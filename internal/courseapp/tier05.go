package courseapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Tier 5 makes an install recoverable, and its five releases differ only in
// what happens between the trial boot and the confirmation.
//
// Tier 3 and Tier 4 requested a permanent upgrade on purpose: the swap
// happened, the image ran, and nothing ever asked whether it worked. Section 6
// fixes that from Tier 5 the application requests BOOT_UPGRADE_TEST and never
// a permanent upgrade, so every install is on trial until the device itself
// decides otherwise.
//
// The fallback path has physically existed since Tier 0, because the course
// pins swap-using-offset in every tier. No tier has ever taken it. T0-W-07 has
// been open since Tier 0 saying exactly that, and this is the tier that closes
// it.
const (
	// The human-readable version imgtool stamps into the image header.
	//
	// It is written here only because releaseSignTier05 below consumes it.
	// Tier 4 declared tier04Version, never wired it to imgtool, and shipped
	// an image whose --version was wrong; an unused Go constant does not
	// fail a build, so the protection is to add the constant and its
	// consumer together.
	tier05Version = "0.5.0+0"

	// The protected MCUboot TLV that carries the source revision.
	//
	// 0x00A0 is the first tag in MCUboot's vendor-reserved xxA0-xxFF range.
	// imgtool puts custom TLVs in the protected area, so the value is covered
	// by the image signature and cannot be rewritten without invalidating the
	// image.
	tier05RevisionTLV = "0x00A0"

	// Every Tier 5 release carries the same security counter, and that is a
	// decision rather than an oversight.
	//
	// These five images exist to test the trial path. A differing counter
	// would let the bootloader's downgrade prevention refuse one of them
	// before its trial ever started, and the tier would be demonstrating
	// Tier 4's control by accident instead of its own. Section 6 allows an
	// equal counter for an ordinary feature release in as many words.
	//
	// It is one above Tier 4's security-fix release, because a device running
	// that release must be able to accept these.
	tier05SecurityCounter = tier04SecurityCounter + 2

	// How long the device has to prove itself healthy. Section 6 fixes 60
	// seconds. It reaches the build as CONFIG_COURSE_HEALTH_GATE_SECONDS,
	// which defaults to the same value, so a build that never sets it is
	// still correct.
	tier05HealthGateSeconds = 60
)

// tier05Variants are the five releases Tier 5 produces.
//
// Four of them do not work, and none of them is hostile. Nobody without the
// Release signing key can produce any of these, so an unhealthy release is the
// manufacturer publishing something broken, which section 11 names beside the
// attacks in its threat list. The device cannot tell a broken release from a
// leaked key, and it recovers from either the same way.
//
// Each needs its own release_id. A prepared release that reuses one the device
// has already seen is shrugged off, and a device carrying on unchanged looks
// exactly like a control working.
var tier05Variants = map[string]firmwareVariant{
	"healthy": {
		releaseID:       "tier-05-healthy",
		label:           "healthy",
		beaconState:     "steady",
		version:         "0.5.0-recoverable",
		imageName:       "tier-05-healthy.bin",
		securityCounter: tier05SecurityCounter,
		trialBehaviour:  "healthy",
	},
	// The crash release is the one that raises the counter, and it is the
	// only one that does.
	//
	// Every other release here carries the same counter so that the trial
	// path is what is being tested rather than Tier 4's downgrade control.
	// This one is deliberately different, because a revert from it goes
	// backwards: the primary slot holds counter 4 and the image being
	// restored holds 3.
	//
	// That is the only arrangement that actually tests section 6's claim
	// that a failed trial can revert without a newer counter making the old
	// image ineligible. MCUboot's check_downgrade_prevention() refuses when
	// the primary counter is strictly greater than the candidate's, so with
	// equal counters it would not fire even if a revert did pass through it.
	// Proving the exemption needs a revert that would otherwise be refused.
	"crash": {
		releaseID:       "tier-05-crash",
		label:           "crash",
		beaconState:     "steady",
		version:         "0.5.1-crash",
		imageName:       "tier-05-crash.bin",
		securityCounter: tier05SecurityCounter + 1,
		trialBehaviour:  "crash",
	},
	"hang": {
		releaseID:       "tier-05-hang",
		label:           "hang",
		beaconState:     "steady",
		version:         "0.5.2-hang",
		imageName:       "tier-05-hang.bin",
		securityCounter: tier05SecurityCounter,
		trialBehaviour:  "hang",
	},
	"fail-health": {
		releaseID:       "tier-05-fail-health",
		label:           "fail-health",
		beaconState:     "steady",
		version:         "0.5.3-fail-health",
		imageName:       "tier-05-fail-health.bin",
		securityCounter: tier05SecurityCounter,
		trialBehaviour:  "fail-health",
	},
	"timeout-health": {
		releaseID:       "tier-05-timeout-health",
		label:           "timeout-health",
		beaconState:     "steady",
		version:         "0.5.4-timeout-health",
		imageName:       "tier-05-timeout-health.bin",
		securityCounter: tier05SecurityCounter,
		trialBehaviour:  "timeout-health",
	},
}

// trialBehaviourSymbols maps a variant's trial behaviour to the Kconfig symbol
// that selects it.
//
// The map is the single place the two vocabularies meet. A behaviour with no
// symbol is a build error rather than a silently healthy image, which is the
// failure that would be hardest to notice: an image that was meant to crash
// and instead confirms looks like the recovery path working.
var trialBehaviourSymbols = map[string]string{
	"healthy":        "CONFIG_COURSE_TRIAL_HEALTHY",
	"crash":          "CONFIG_COURSE_TRIAL_CRASH",
	"hang":           "CONFIG_COURSE_TRIAL_HANG",
	"fail-health":    "CONFIG_COURSE_TRIAL_FAIL_HEALTH",
	"timeout-health": "CONFIG_COURSE_TRIAL_TIMEOUT_HEALTH",
}

func trialBehaviourSymbol(behaviour string) (string, error) {
	if behaviour == "" {
		return "", fmt.Errorf("a Tier 5 variant must name a trial behaviour")
	}
	symbol, ok := trialBehaviourSymbols[behaviour]
	if !ok {
		return "", fmt.Errorf("unknown Tier 5 trial behaviour %q", behaviour)
	}
	return symbol, nil
}

// sourceRevision reports the git revision this build came from, with -dirty
// appended when the working tree has uncommitted changes, exactly as
// git describe --dirty reports it.
//
// A dirty tree gets the suffix rather than a refusal to build. The Learner's
// forked repository will be dirty almost all the time, because editing it is
// the exercise, and refusing to build until they commit is a rule the course
// has no business imposing. The value degrades honestly instead: it says it
// does not identify a commit.
//
// Failure to run git at all is not an error either. A Learner may have
// unpacked the course rather than cloned it, and an image that will not build
// without a git checkout would be a worse outcome than one that says it does
// not know where it came from.
func (a *app) sourceRevision() string {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = a.root
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	revision := strings.TrimSpace(string(out))
	if revision == "" {
		return "unknown"
	}

	// --quiet exits non-zero when there is a difference, which is the
	// question being asked, so a non-nil error here is the answer and not a
	// failure.
	dirty := exec.Command("git", "diff", "--quiet", "HEAD")
	dirty.Dir = a.root
	if dirty.Run() != nil {
		revision += "-dirty"
	}
	return revision
}

func (a *app) tier05BuildDir(variant firmwareVariant) string {
	return filepath.Join(a.zephyrWorkspace(), "build", "tier-05-recovery-"+variant.label)
}

func (a *app) tier05RawImage(variant firmwareVariant) string {
	return filepath.Join(a.tier05BuildDir(variant), "tier-05-recovery", "zephyr", "zephyr.bin")
}

// releaseSignTier05 signs one Tier 5 release and publishes it.
//
// It is Tier 4's sequence with one addition: the source revision goes into a
// protected custom TLV at signing time, so the bootloader can say what it is
// swapping in. After a revert the device is running an image whose Release
// manifest it consumed long ago and no longer holds, and the TLV is the only
// self-description that survives that.
//
// The manifest is Tier 4's, unchanged. Tier 5 changes what the device does
// with an image, not what a release says about itself, and inventing a second
// manifest shape would imply a difference that does not exist.
func (a *app) releaseSignTier05(variantName string) error {
	variant, ok := tier05Variants[variantName]
	if !ok {
		names := make([]string, 0, len(tier05Variants))
		for name := range tier05Variants {
			names = append(names, name)
		}
		sort.Strings(names)
		return fmt.Errorf("unknown Tier 5 release %q; use one of: %s",
			variantName, strings.Join(names, ", "))
	}
	key := a.signingKeyPath("release")
	if _, err := os.Stat(key); err != nil {
		return errors.New("no Release signing key yet; run ./course keys create release first")
	}
	raw := a.tier05RawImage(variant)
	if _, err := os.Stat(raw); err != nil {
		return fmt.Errorf("no Tier 5 %s image to sign; run ./course build firmware --tier 05 --variant %s first",
			variant.label, variant.label)
	}
	out := filepath.Join(a.releaseDir(), variant.imageName)
	if err := os.MkdirAll(a.releaseDir(), 0o700); err != nil {
		return err
	}

	fingerprint, err := a.keyFingerprint(key)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Signing with the release key, fingerprint %s\n", fingerprint)

	revision := a.sourceRevision()
	if err := a.signImage(key, raw, out, strconv.Itoa(variant.securityCounter), tier05Version,
		"--custom-tlv", tier05RevisionTLV, revision); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "+ source revision %s written to protected TLV %s\n",
		revision, tier05RevisionTLV)
	fmt.Fprintln(a.out, "  It is in the protected area, so the signature covers it. It identifies the")
	fmt.Fprintln(a.out, "  build and not the release, and your build will not match a published one.")

	image, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	manifest := a.buildManifest(variant, image, time.Now())
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	manifestFile := a.manifestPath(variant.releaseID)
	if err := os.WriteFile(manifestFile, data, 0o600); err != nil {
		return err
	}

	keyPEM, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	signature, err := signManifest(keyPEM, data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(a.manifestSignaturePath(variant.releaseID), signature, 0o600); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "+ signed %d manifest bytes with ECDSA P-256 over SHA-256\n", len(data))
	fmt.Fprintf(a.out, "  manifest:  %s\n", a.relative(manifestFile))
	fmt.Fprintf(a.out, "  digest:    %s\n", manifest.ImageSHA256)
	fmt.Fprintf(a.out, "  counter:   %d, in the image TLV and in the manifest\n",
		manifest.SecurityCounter)

	release, err := a.publishSigned(variant, out, fingerprint)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: published %s, %d bytes, trial behaviour %s\n",
		variant.releaseID, release["image_size"], variant.trialBehaviour)
	if variant.trialBehaviour != "healthy" {
		fmt.Fprintln(a.out, "This release is correctly signed and genuinely broken. Nobody without the")
		fmt.Fprintln(a.out, "Release signing key could have produced it, so it is the manufacturer")
		fmt.Fprintln(a.out, "publishing something that does not work, which section 11 names beside the")
		fmt.Fprintln(a.out, "attacks. The device cannot tell it from a leaked key and recovers either way.")
	}
	return nil
}

// releaseAssignTier05 offers an already-signed Tier 5 release to the device.
//
// Tier 5 is the first tier with more than one release a Learner needs to hand
// to the board in sequence, and nothing before it needed this. Tier 3 had one
// release. Tier 4 had two, and a fixture that re-assigned an old one to
// demonstrate a replay. Tier 5 has five, four of which exist to be watched
// failing, and a Learner who could only offer whichever release they signed
// most recently could not run the tier at all.
//
// It signs nothing and builds nothing. The release must already exist, and
// every value in the assignment is copied from the release's own signed
// manifest, so this command cannot describe a release as something it is not.
func (a *app) releaseAssignTier05(variantName string) error {
	variant, ok := tier05Variants[variantName]
	if !ok {
		names := make([]string, 0, len(tier05Variants))
		for name := range tier05Variants {
			names = append(names, name)
		}
		sort.Strings(names)
		return fmt.Errorf("unknown Tier 5 release %q; use one of: %s",
			variantName, strings.Join(names, ", "))
	}

	data, err := os.ReadFile(a.manifestPath(variant.releaseID))
	if err != nil {
		return fmt.Errorf("no signed %s release yet; run ./course release sign --tier 05 --variant %s first",
			variant.label, variant.label)
	}
	var manifest releaseManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("the stored %s manifest is unreadable: %w", variant.label, err)
	}

	release := a.assignmentFor(manifest)
	state := filepath.Join(a.root, a.manifest.Paths.State, "ota")
	if err := writeJSON(filepath.Join(state, "current-release.json"), release, 0o600); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "Result: the service now offers %s, version %s, counter %d\n",
		manifest.ReleaseID, manifest.Version, manifest.SecurityCounter)
	fmt.Fprintln(a.out, "Every value above came from that release's own signed manifest. This command")
	fmt.Fprintln(a.out, "signs nothing and changes no stored release.")
	if variant.trialBehaviour != "healthy" {
		fmt.Fprintf(a.out, "This release is built to fail its trial by %s. The device should install it,\n",
			variant.trialBehaviour)
		fmt.Fprintln(a.out, "fail to confirm it, and put the last confirmed image back on its own.")
	}
	return nil
}

// deviceReset restarts the board without reflashing it.
//
// Tier 5 is the first tier that needs this. Everything before it could be
// exercised by publishing a release and waiting; this tier has to interrupt a
// device part way through an operation and see what it does when it comes
// back, which is what section 6's power-cut tests are about.
//
// It pulses RTS, which drives the chip's EN line, while holding DTR
// deasserted. That distinction matters more than it looks. esptool's own reset
// drives both lines and leaves the part in the ROM download loader, boot:0x4,
// where the application never runs and the console stays silent. On a board
// that is supposed to be recovering from an interruption, that is
// indistinguishable from having broken it, and it cost a reflash to diagnose
// the first time.
//
// A reset is not a power cut. It interrupts between operations rather than
// during a flash page write, so it approximates a brown-out without
// reproducing a partial page. The Tier 5 module says so rather than claiming
// the stronger result.
func (a *app) deviceReset() error {
	device, err := a.selectSerialDevice()
	if err != nil {
		return err
	}

	port, err := os.OpenFile(device, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", device, err)
	}
	defer port.Close()

	fd := port.Fd()
	dtr := uint32(syscall.TIOCM_DTR)
	rts := uint32(syscall.TIOCM_RTS)

	// DTR low first, so the part comes up running its application rather
	// than in the ROM loader.
	if err := ioctlSet(fd, syscall.TIOCMBIC, &dtr); err != nil {
		return err
	}
	if err := ioctlSet(fd, syscall.TIOCMBIS, &rts); err != nil {
		return err
	}
	time.Sleep(100 * time.Millisecond)
	if err := ioctlSet(fd, syscall.TIOCMBIC, &rts); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "Result: pulsed RTS on %s\n", a.relative(device))
	fmt.Fprintln(a.out, "The board restarts into its application. Watch it with ./course device logs.")
	fmt.Fprintln(a.out, "This is a reset, not a power cut: it interrupts between operations rather")
	fmt.Fprintln(a.out, "than during a flash page write.")
	return nil
}

func ioctlSet(fd uintptr, request uint, bits *uint32) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request),
		uintptr(unsafe.Pointer(bits)))
	if errno != 0 {
		return fmt.Errorf("ioctl on the serial port failed: %w", errno)
	}
	return nil
}
