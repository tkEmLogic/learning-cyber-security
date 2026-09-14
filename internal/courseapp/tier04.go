package courseapp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tier 4 signs two things with one key.
//
// Tier 3 signed a firmware image, which proves who published it. Tier 4 also
// signs the exact bytes of a Release manifest, which is what lets the device
// decide anything before the image arrives. Section 7 of the specification
// fixes that it is one key: "The offline firmware release-signing key signs
// the MCUboot image and the exact bytes of an immutable release manifest."
//
// The two are checked by different verifiers all the same. MCUboot holds the
// public key for the image, the application holds it for the manifest, and
// section 18 says passing one never counts as evidence for the other.
const (
	tier04Version = "0.4.0+0"

	// The security counter is a property of the release, not of a build flag,
	// so it lives in the variant beside the version. One value feeds both
	// imgtool's --security-counter and the manifest's security_counter field,
	// so the two cannot disagree.
	//
	// It is deliberately not derived from the version. Section 11 names
	// "human-readable versions override the security counter" as this tier's
	// failure criterion.
	tier04SecurityCounter = 1

	// The hardware revision this build asserts it is for. The chip can report
	// its silicon stepping, but nothing on this part reports the product's
	// hardware revision, so it is asserted here and signed rather than read.
	tier04HardwareRevision = 1

	// Five years, which is the support period section 4 fixes for the
	// Reference product.
	tier04SupportYears = 5

	// The channel this build publishes to and the channel the device is
	// configured to follow. One constant, for the same reason the counter is
	// one constant: a device that refused the channel its own build published
	// to would be a puzzle rather than a lesson.
	//
	// Two channels exist, stable and candidate. Nothing here creates the
	// second one; the fixture that publishes to it does.
	tier04Channel = "stable"

	// The channel a hostile manifest can be published to that the device was
	// not configured for. It is the second of the two real channels, not an
	// invented one: the point of the refusal is that a perfectly legitimate
	// channel is still the wrong channel for this device.
	tier04AlternateChannel = "candidate"
)

// tier04Variants are the two good releases Tier 4 produces.
//
// There are two because one is not enough to demonstrate a downgrade. A replay
// needs something to replay past, and the security counter it has to be lower
// than has to be in an image the device is already running.
//
// They are built from the same application source. What differs is the security
// counter, and the counter is the whole subject, so a second application would
// add a five minute build and teach nothing extra. Each is a separate build all
// the same, because CONFIG_COURSE_SECURITY_COUNTER is compiled in: an image
// signed with a counter its own application does not know about would refuse
// releases it should accept.
var tier04Variants = map[string]firmwareVariant{
	"baseline": {
		releaseID:       "tier-04-baseline",
		label:           "baseline",
		beaconState:     "steady",
		version:         "0.4.0-release-policy",
		imageName:       "tier-04-baseline.bin",
		securityCounter: tier04SecurityCounter,
	},
	// The release a downgrade has to get past. Section 11 names raising the
	// counter as what a security fix does, and #69's decision table has two
	// scenarios that raise it, so this is the shape of a real one.
	"security-fix": {
		releaseID:       "tier-04-security-fix",
		label:           "security-fix",
		beaconState:     "fast",
		version:         "0.4.1-security-fix",
		imageName:       "tier-04-security-fix.bin",
		securityCounter: tier04SecurityCounter + 1,
	},
}

// releaseManifest is the Release manifest as it is written to disk.
//
// It is a struct rather than a map so the field order is the order a reader
// wants, and it is marshalled exactly once. Whatever bytes come out are the
// bytes that get signed and the bytes the service must serve back unchanged.
// Re-encoding the same values elsewhere produces different bytes and breaks
// the signature, which is why section 7 verifies the downloaded bytes before
// parsing rather than canonicalising them.
type releaseManifest struct {
	SchemaVersion       int    `json:"schema_version"`
	ReleaseID           string `json:"release_id"`
	Version             string `json:"version"`
	SecurityCounter     int    `json:"security_counter"`
	Channel             string `json:"channel"`
	Board               string `json:"board"`
	HardwareRevisionMin int    `json:"hardware_revision_min"`
	HardwareRevisionMax int    `json:"hardware_revision_max"`
	ImagePath           string `json:"image_path"`
	ImageSize           int    `json:"image_size"`
	ImageSHA256         string `json:"image_sha256"`
	CreatedAt           string `json:"created_at"`
	SupportedUntil      string `json:"supported_until"`
}

// manifestPath and signaturePath are the names the OTA service serves from.
// They sit beside the image in the release directory.
func (a *app) manifestPath(releaseID string) string {
	return filepath.Join(a.releaseDir(), releaseID+".manifest.json")
}

func (a *app) manifestSignaturePath(releaseID string) string {
	return filepath.Join(a.releaseDir(), releaseID+".manifest.sig")
}

// buildManifest describes one release. Nothing here is read from the service,
// and nothing here is negotiable at install time: these are the facts the
// device checks the delivered bytes against.
func (a *app) buildManifest(variant firmwareVariant, image []byte, now time.Time) releaseManifest {
	sum := sha256.Sum256(image)
	return releaseManifest{
		SchemaVersion:   1,
		ReleaseID:       variant.releaseID,
		Version:         variant.version,
		SecurityCounter: variant.securityCounter,
		// A device refuses a manifest for a channel it was not configured for,
		// which is one more thing a mistaken release can get wrong without
		// anybody being an attacker. ./course build firmware writes the same
		// constant into CONFIG_COURSE_RELEASE_CHANNEL.
		Channel:             tier04Channel,
		Board:               a.manifest.Devices["reference_beacon"].Board,
		HardwareRevisionMin: tier04HardwareRevision,
		HardwareRevisionMax: tier04HardwareRevision,
		ImagePath:           variant.imageName,
		ImageSize:           len(image),
		ImageSHA256:         hex.EncodeToString(sum[:]),
		// The device has no clock and cannot check either of these. They are
		// carried and signed so they cannot be edited afterwards, reported in
		// status events, and consumed by Tier 9. Nothing on the device treats
		// them as a condition, and the module says so rather than letting a
		// date field imply a check that does not happen.
		CreatedAt:      now.UTC().Format(time.RFC3339),
		SupportedUntil: now.UTC().AddDate(tier04SupportYears, 0, 0).Format(time.RFC3339),
	}
}

// signManifest signs the exact bytes it is given.
//
// This is the first thing in the course that signs something other than a
// firmware image, so it does not go through imgtool, which is image shaped.
// It is ECDSA P-256 over SHA-256, and the signature is ASN.1 DER in a file of
// its own, which is what "detached" means: the manifest is not modified to
// carry its own signature, because then the bytes being signed would have to
// exclude part of themselves.
func signManifest(keyPEM []byte, data []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("release signing key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse release signing key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("release signing key is not ECDSA")
	}
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}

// writeSigningPublicKeyInc emits the image verification public key for the
// application build, the way writeTrustAnchor emits the Course certificate
// authority.
//
// It writes the bare 65 byte uncompressed EC point, not the SPKI wrapper the
// PEM file holds. The device imports that point directly through PSA, so
// stripping the wrapper here costs the firmware no ASN.1 parser at all and
// keeps CONFIG_MBEDTLS_PEM_PARSE_C off. Research on #65 measured that turning
// PEM parsing on would cost 1696 bytes of .text to do at run time what this
// does for free.
//
// Only the public half is ever read here. No firmware build command names the
// Release signing key, which docs/fixture-safety-contract.md forbids in as
// many words.
func (a *app) writeSigningPublicKeyInc() (string, error) {
	pemBytes, err := os.ReadFile(a.publicKeyPath())
	if err != nil {
		return "", errors.New("no public signing key yet; run ./course keys create release first")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", errors.New("public signing key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse public signing key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("public signing key is not ECDSA")
	}
	point := elliptic.Marshal(key.Curve, key.X, key.Y)

	dir := filepath.Join(a.root, a.manifest.Paths.State, "firmware", "anchor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var out []byte
	out = append(out, "/* Generated by ./course build firmware. Do not edit or commit. */\n"...)
	for i, b := range point {
		if i%12 == 0 {
			out = append(out, "\n\t"...)
		}
		out = append(out, fmt.Sprintf("0x%02x, ", b)...)
	}
	out = append(out, '\n')
	path := filepath.Join(dir, "release_pubkey.inc")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

func (a *app) tier04BuildDir(variant firmwareVariant) string {
	return filepath.Join(a.zephyrWorkspace(), "build", "tier-04-release-policy-"+variant.label)
}

func (a *app) tier04RawImage(variant firmwareVariant) string {
	return filepath.Join(a.tier04BuildDir(variant), "tier-04-release-policy", "zephyr", "zephyr.bin")
}

// releaseSignTier04 signs the image and the manifest, in that order, because
// the manifest describes the signed image and has to be built from its bytes.
//
// It then publishes the release, which is the step Tier 3's releaseSign also
// takes. Until this happens the Update assignment still names a Tier 3 release
// and nothing on the device has anything Tier 4 to fetch a manifest for.
func (a *app) releaseSignTier04(variantName string) error {
	variant, ok := tier04Variants[variantName]
	if !ok {
		names := make([]string, 0, len(tier04Variants))
		for name := range tier04Variants {
			names = append(names, name)
		}
		sort.Strings(names)
		return fmt.Errorf("unknown Tier 4 release %q; use one of: %s", variantName, strings.Join(names, ", "))
	}
	key := a.signingKeyPath("release")
	if _, err := os.Stat(key); err != nil {
		return errors.New("no Release signing key yet; run ./course keys create release first")
	}
	raw := a.tier04RawImage(variant)
	if _, err := os.Stat(raw); err != nil {
		return fmt.Errorf("no Tier 4 %s image to sign; run ./course build firmware --tier 04 --variant %s first",
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

	// The counter goes into the image here and into the manifest below, from
	// the same constant. Section 6 requires the same value in both.
	if err := a.signImage(key, raw, out, strconv.Itoa(variant.securityCounter), tier04Version); err != nil {
		return err
	}

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
	fmt.Fprintf(a.out, "  signature: %s, %d bytes of ASN.1 DER\n",
		a.relative(a.manifestSignaturePath(variant.releaseID)), len(signature))
	fmt.Fprintf(a.out, "  digest:    %s\n", manifest.ImageSHA256)
	fmt.Fprintf(a.out, "  counter:   %d, in the image TLV and in the manifest\n", manifest.SecurityCounter)
	fmt.Fprintln(a.out, "The signature covers these exact bytes. Reformatting the file breaks it,")
	fmt.Fprintln(a.out, "which is why the device verifies the bytes before it parses them.")

	release, err := a.publishSigned(variant, out, fingerprint)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: published %s, %d bytes, counter %d\n",
		variant.releaseID, release["image_size"], manifest.SecurityCounter)
	fmt.Fprintln(a.out, "The Update assignment now names this release. The device reads it only to learn")
	fmt.Fprintln(a.out, "which release it is offered, then fetches the manifest above and verifies that.")
	return nil
}

// ---------------------------------------------------------------------------
// The seven hostile releases
// ---------------------------------------------------------------------------

// hostileManifests are the seven releases the device must refuse, and they are
// not seven of the same thing.
//
// Two of them are forgeries. Anyone can edit a signed manifest, and anyone can
// sign one with a key of their own, so those two are outsider attacks and the
// device throws them out at the signature without parsing a byte.
//
// The other four cannot be forged at all. Nobody without the Release signing
// key can produce a manifest that verifies, so a wrong hardware range, a wrong
// channel, a wrong size and a wrong digest can only exist if the key holder
// signed them. They are the manufacturer publishing something wrong, which the
// specification's Tier 4 threat list names as "incompatible hardware
// assignment" and "version-policy mistakes". They have to be signed with the
// Learner's own key, or the device would refuse them at the signature and
// never reach the check each one exists to demonstrate.
//
// That is the sharp lesson of the tier and the reason the split is printed
// rather than implied: the device cannot tell a mistake from a leaked key, and
// it refuses either way. A signature proves who signed. It never proves they
// should have.
var hostileManifests = []struct {
	name string
	// learnerSigned is true when only the holder of the Release signing key
	// could have produced this manifest.
	learnerSigned bool
	// bootloader is true when the application refuses nothing at all and the
	// only thing that says no is MCUboot, at the next boot.
	bootloader bool
	why        string
	refusedAt  string
}{
	{
		name: "modified", learnerSigned: false,
		why:       "A manifest signed correctly, then edited afterwards, so the bytes no longer match the signature.",
		refusedAt: "check 1, the signature, before anything parses the bytes",
	},
	{
		name: "wrong-key", learnerSigned: false,
		why:       "A manifest signed properly, by a key that is exactly as valid as yours and trusted by nothing.",
		refusedAt: "check 1, the signature, before anything parses the bytes",
	},
	{
		name: "hardware", learnerSigned: true,
		why:       "A hardware revision range that does not include this device.",
		refusedAt: "check 2, hardware compatibility, before any download starts",
	},
	{
		name: "channel", learnerSigned: true,
		why:       "A release channel this device was not configured to follow.",
		refusedAt: "check 4, the release channel, before any download starts",
	},
	{
		name: "size", learnerSigned: true,
		why:       "An image size that is not the number of bytes the service will deliver.",
		refusedAt: "check 5, the declared size, against Content-Length before a byte reaches flash",
	},
	{
		name: "digest", learnerSigned: true,
		why:       "A SHA-256 that is not the digest of the delivered bytes.",
		refusedAt: "check 6, the digest, after the transfer and before any upgrade is requested",
	},
	{
		// The only release in the set that the application accepts.
		//
		// Its manifest is true about everything the application can check: the
		// signature verifies, the hardware matches, the channel matches, the
		// counter is the one this device is already running, and the size and
		// digest describe the delivered bytes exactly. Every check passes and
		// the bytes are written.
		//
		// What it does not describe is the security counter inside the image
		// it points at, which is the older one. The application never sees
		// that counter; it is in the signed image TLV, and MCUboot reads it
		// from the slot at the next boot.
		//
		// This is the only artifact in the course that can show the two
		// verifiers disagreeing, which is what section 18 means by "passing one
		// never counts as evidence for the other". Without it the tier claims
		// two verifiers and can only ever demonstrate one.
		name: "counter-mismatch", learnerSigned: true, bootloader: true,
		why:       "A manifest that is true about everything the application checks, pointing at the image of an older release.",
		refusedAt: "no check in the application at all: every one passes, the bytes are written, and MCUboot refuses the swap at the next boot on the image's own security counter",
	},
}

// hostileReleaseID gives every hostile release an identifier of its own.
//
// This is not cosmetic. The device decides whether to look at a release at all
// by comparing the assignment's identifier against the one it is running, so a
// hostile release that reused the good identifier would be ignored, and a
// Learner would watch a device do nothing and call it a refusal.
func hostileReleaseID(name string) string {
	return "tier-04-hostile-" + name
}

// wrongDigest is the SHA-256 of an image that is not the one being delivered.
//
// It is a real digest of real bytes: the Learner's own image with one byte
// changed. A made up string of hex would fail the same check for the wrong
// reason, and would let someone conclude the device rejects malformed digests
// rather than digests that do not match.
func wrongDigest(image []byte) string {
	other := append([]byte{}, image...)
	other[len(other)/2] ^= 0xff
	sum := sha256.Sum256(other)
	return hex.EncodeToString(sum[:])
}

// deriveHostileManifest makes one hostile manifest out of the Learner's own
// good one. Everything not named here is carried across untouched, including
// created_at, so the difference the fixture prints is exactly the lie.
func deriveHostileManifest(name string, good releaseManifest, image []byte, older *releaseManifest) releaseManifest {
	hostile := good
	hostile.ReleaseID = hostileReleaseID(name)
	switch name {
	case "hardware":
		// A range above this device, not a range with no members. An
		// impossible range would be a malformed manifest; this one is a
		// perfectly sensible release for a board that is not this one.
		hostile.HardwareRevisionMin = tier04HardwareRevision + 1
		hostile.HardwareRevisionMax = tier04HardwareRevision + 2
	case "channel":
		hostile.Channel = tier04AlternateChannel
	case "size":
		// Smaller than the delivery, so Content-Length gives it away before a
		// byte reaches flash. That is the first of the two size checks, and
		// the one that protects the write rather than the upgrade.
		hostile.ImageSize = len(image) - 64
	case "digest":
		hostile.ImageSHA256 = wrongDigest(image)
	case "counter-mismatch":
		// Describe the older image truthfully and keep this release's counter.
		// Nothing the application checks is wrong, so nothing the application
		// checks refuses it.
		if older != nil {
			hostile.ImagePath = older.ImagePath
			hostile.ImageSize = older.ImageSize
			hostile.ImageSHA256 = older.ImageSHA256
		}
	}
	return hostile
}

// releaseHostileTier04 builds the seven manifests the device must refuse.
//
// Every one is derived here, now, from the Learner's own signed release. None
// is committed, so a fork of this repository never carries a ready made attack
// payload. None of them ships a firmware image either: all seven point at an
// image the Learner signed, because what is wrong with them is the signed
// description of it.
func (a *app) releaseHostileTier04() error {
	releases, err := a.goodReleases()
	if err != nil {
		return err
	}
	good := releases[len(releases)-1]
	// The oldest signed release, which is the one carrying the lower counter in
	// its image TLV. counter-mismatch points at that image while describing
	// this one, so it needs a second release to exist. When only one does, that
	// variant is skipped and says why rather than failing the other six: a
	// Learner who has signed one release should still get the six that work.
	var older *releaseManifest
	if len(releases) > 1 {
		older = &releases[0].manifest
	}
	goodManifest, goodBody := good.manifest, good.body
	image, err := os.ReadFile(filepath.Join(a.releaseDir(), goodManifest.ImagePath))
	if err != nil {
		return fmt.Errorf("no image for %s to work from; run ./course release sign --tier 04 first", goodManifest.ReleaseID)
	}
	key := a.signingKeyPath("release")
	keyPEM, err := os.ReadFile(key)
	if err != nil {
		return errors.New("no Release signing key yet; run ./course keys create release first")
	}
	attacker := a.signingKeyPath("attacker")
	attackerPEM, err := os.ReadFile(attacker)
	if err != nil {
		return errors.New("no attacker key yet; run ./course keys create attacker first")
	}
	releaseFingerprint, err := a.keyFingerprint(key)
	if err != nil {
		return err
	}
	attackerFingerprint, err := a.keyFingerprint(attacker)
	if err != nil {
		return err
	}

	fmt.Fprintf(a.out, "Building seven releases your device should refuse, from %s.\n", a.relative(a.manifestPath(goodManifest.ReleaseID)))
	fmt.Fprintf(a.out, "%d bytes of signed manifest, and the image it describes.\n", len(goodBody))
	fmt.Fprintln(a.out, "None of them is shipped with this course, and none of them ships a firmware image.")
	fmt.Fprintln(a.out, "All seven point at an image you signed yourself. What is wrong with them is the description.")
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "Read this before the fingerprints below alarm you.")
	fmt.Fprintln(a.out, "Two of these seven are forgeries: one edited after signing, one signed by another key.")
	fmt.Fprintf(a.out, "The other five are about to be signed with YOUR Release signing key, %s.\n", releaseFingerprint)
	fmt.Fprintln(a.out, "Your key has not leaked. Nobody without it can make a manifest that verifies, so a wrong")
	fmt.Fprintln(a.out, "hardware range, a wrong channel, a wrong size, a wrong digest and a manifest that points")
	fmt.Fprintln(a.out, "at the wrong image can only be signed by")
	fmt.Fprintln(a.out, "whoever holds the key. Those five are the manufacturer publishing something wrong, and")
	fmt.Fprintln(a.out, "they are the only way to reach the checks that run after the signature has passed.")

	for _, variant := range hostileManifests {
		id := hostileReleaseID(variant.name)
		if variant.bootloader && older == nil {
			fmt.Fprintf(a.out, "\n%s: skipped.\n", variant.name)
			fmt.Fprintln(a.out, "  It points at the image of an older release, and only one signed release exists.")
			fmt.Fprintln(a.out, "  Build and sign the second one to get it:")
			fmt.Fprintln(a.out, "    ./course build firmware --tier 04 --variant security-fix")
			fmt.Fprintln(a.out, "    ./course release sign --tier 04 --variant security-fix")
			continue
		}
		hostile := deriveHostileManifest(variant.name, goodManifest, image, older)
		body, err := marshalManifest(hostile)
		if err != nil {
			return err
		}

		fmt.Fprintf(a.out, "\n%s: %s\n", variant.name, variant.why)
		if variant.learnerSigned {
			fmt.Fprintf(a.out, "  kind:       valid signature, and only your key could have produced it\n")
		} else {
			fmt.Fprintf(a.out, "  kind:       invalid signature, and anyone at all could have produced it\n")
		}
		fmt.Fprintf(a.out, "  release_id: %s, its own, so the device has a reason to look\n", id)

		var signature []byte
		switch variant.name {
		case "wrong-key":
			fmt.Fprintf(a.out, "  signing with the attacker key, fingerprint %s\n", attackerFingerprint)
			fmt.Fprintln(a.out, "  as valid as yours, made by the same command, and trusted by nothing")
			signature, err = signManifest(attackerPEM, body)
		case "modified":
			fmt.Fprintf(a.out, "  signing with your release key, fingerprint %s\n", releaseFingerprint)
			signature, err = signManifest(keyPEM, body)
			if err == nil {
				// The edit happens after the signature exists, which is what
				// makes this the tampering case rather than a bad signature:
				// the signature is genuine and the bytes it covers are gone.
				edited := bytes.Replace(body, []byte(goodManifest.ImageSHA256), []byte(wrongDigest(image)), 1)
				if bytes.Equal(edited, body) {
					return errors.New("the good manifest does not carry the digest this edit replaces")
				}
				body = edited
				fmt.Fprintln(a.out, "  then editing image_sha256 in the signed file, and leaving the signature alone")
				fmt.Fprintln(a.out, "  that is what someone substituting an image would have to do")
			}
		default:
			fmt.Fprintf(a.out, "  signing with your release key, fingerprint %s\n", releaseFingerprint)
			signature, err = signManifest(keyPEM, body)
		}
		if err != nil {
			return err
		}

		if err := os.WriteFile(a.manifestPath(id), body, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(a.manifestSignaturePath(id), signature, 0o600); err != nil {
			return err
		}
		for _, line := range manifestDifferences(goodManifest, hostile) {
			fmt.Fprintf(a.out, "  changed:    %s\n", line)
		}
		if variant.name == "modified" {
			fmt.Fprintf(a.out, "  changed:    image_sha256 after signing, %s -> %s\n",
				goodManifest.ImageSHA256, wrongDigest(image))
		}
		fmt.Fprintf(a.out, "  wrote %s, %d bytes, and a %d byte detached signature\n",
			a.relative(a.manifestPath(id)), len(body), len(signature))
		fmt.Fprintf(a.out, "  the device refuses this at %s\n", variant.refusedAt)
	}

	fmt.Fprintln(a.out, "\nResult: seven hostile releases ready, each with its own identifier.")
	fmt.Fprintln(a.out, "Publish one through your own service with:")
	fmt.Fprintln(a.out, "  ./course attack run tier-04/hostile-release --release <name>")
	return nil
}

// marshalManifest is the one place manifest bytes are produced, so the bytes
// that get signed and the bytes that get stored can never come from two
// different encoders.
func marshalManifest(manifest releaseManifest) ([]byte, error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// manifestFields is the manifest in the order a reader wants it, as strings, so
// two manifests can be compared field by field in front of a Learner.
func manifestFields(m releaseManifest) [][2]string {
	return [][2]string{
		{"release_id", m.ReleaseID},
		{"version", m.Version},
		{"security_counter", strconv.Itoa(m.SecurityCounter)},
		{"channel", m.Channel},
		{"board", m.Board},
		{"hardware_revision_min", strconv.Itoa(m.HardwareRevisionMin)},
		{"hardware_revision_max", strconv.Itoa(m.HardwareRevisionMax)},
		{"image_path", m.ImagePath},
		{"image_size", strconv.Itoa(m.ImageSize)},
		{"image_sha256", m.ImageSHA256},
		{"created_at", m.CreatedAt},
		{"supported_until", m.SupportedUntil},
	}
}

// manifestDifferences names every field that differs, so the fixture shows the
// lie instead of asserting there is one.
func manifestDifferences(good, other releaseManifest) []string {
	goodFields := manifestFields(good)
	otherFields := manifestFields(other)
	var lines []string
	for i := range goodFields {
		if goodFields[i][1] != otherFields[i][1] {
			lines = append(lines, fmt.Sprintf("%s, %s -> %s",
				goodFields[i][0], goodFields[i][1], otherFields[i][1]))
		}
	}
	return lines
}

// ---------------------------------------------------------------------------
// Reading what this environment has actually produced
// ---------------------------------------------------------------------------

// loadStoredManifest reads a stored manifest and parses it. It does not verify
// anything, and no caller may treat it as though it had: verification is a
// separate call, on the exact bytes, by design.
func (a *app) loadStoredManifest(releaseID string) (releaseManifest, []byte, error) {
	var manifest releaseManifest
	body, err := os.ReadFile(a.manifestPath(releaseID))
	if err != nil {
		return manifest, nil, fmt.Errorf("no stored manifest for %s", releaseID)
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return manifest, body, fmt.Errorf("the stored manifest for %s is not JSON: %w", releaseID, err)
	}
	return manifest, body, nil
}

// releaseVerifyKey is the public half the application has compiled in. The
// fixtures use it for exactly one thing: to tell the Learner whether a
// signature is good, on the host, before any board is involved.
//
// This is never a stand-in for the device's own check. It proves what the
// fixture published, not what the device did with it.
func (a *app) releaseVerifyKey() (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(a.publicKeyPath())
	if err != nil {
		return nil, errors.New("no public release key yet; run ./course keys create release first")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the public release key is not PEM")
	}
	parsed, err := publicFromPEM(block)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("the public release key is not ECDSA")
	}
	return key, nil
}

// manifestVerifies answers the one question the signature can answer: were
// these exact bytes signed by the holder of this key.
func manifestVerifies(key *ecdsa.PublicKey, body, signature []byte) bool {
	digest := sha256.Sum256(body)
	return ecdsa.VerifyASN1(key, digest[:], signature)
}

// goodRelease is one release this Course environment actually produced, read
// back from its stored files.
type goodRelease struct {
	variant   firmwareVariant
	manifest  releaseManifest
	body      []byte
	signature []byte
}

// goodReleases returns the good Tier 4 releases that exist on disk and whose
// stored signature verifies.
//
// The candidate set is the manifest-owned list of Tier 4 variants and nothing
// else. The hostile manifests live in the same directory and four of them carry
// a perfectly valid signature, so a scan of the directory would happily offer
// one of those to the replay fixture. The safety contract says the replay
// fixture may only name a release this environment actually produced, and this
// is where that is enforced.
func (a *app) goodReleases() ([]goodRelease, error) {
	key, err := a.releaseVerifyKey()
	if err != nil {
		return nil, err
	}
	var found []goodRelease
	for _, variant := range tier04Variants {
		manifest, body, err := a.loadStoredManifest(variant.releaseID)
		if err != nil {
			continue
		}
		signature, err := os.ReadFile(a.manifestSignaturePath(variant.releaseID))
		if err != nil {
			continue
		}
		if manifest.ReleaseID != variant.releaseID || !manifestVerifies(key, body, signature) {
			continue
		}
		found = append(found, goodRelease{variant: variant, manifest: manifest, body: body, signature: signature})
	}
	sort.Slice(found, func(i, j int) bool {
		return found[i].manifest.SecurityCounter < found[j].manifest.SecurityCounter
	})
	return found, nil
}

// newestRelease is the good release with the highest security counter that this
// environment has signed.
//
// The hostile manifests are derived from it rather than from the baseline,
// because the application refuses a manifest whose counter is below its own.
// A hostile release carrying the baseline's counter would be refused at the
// counter check on a device that has already installed a later release, which
// is a real refusal of the wrong thing: the Learner would be shown the
// downgrade control while trying to watch the channel control.
func (a *app) newestRelease() (goodRelease, error) {
	releases, err := a.goodReleases()
	if err != nil {
		return goodRelease{}, err
	}
	if len(releases) == 0 {
		return goodRelease{}, errors.New("no signed Tier 4 release to work from; run ./course release sign --tier 04 first")
	}
	return releases[len(releases)-1], nil
}

// olderRelease picks the release to replay: the highest counter that is still
// strictly lower than the one currently assigned.
//
// Strictly lower, because MCUboot compares security_counter[0] > security_
// counter[1] and accepts an equal counter. A release whose counter merely fails
// to be higher installs, and a fixture built on that would look like the
// control failing.
func olderRelease(releases []goodRelease, currentCounter int) (goodRelease, bool) {
	var best goodRelease
	found := false
	for _, release := range releases {
		if release.manifest.SecurityCounter < currentCounter {
			if !found || release.manifest.SecurityCounter > best.manifest.SecurityCounter {
				best = release
				found = true
			}
		}
	}
	return best, found
}

// assignmentFor turns a signed manifest back into the Update assignment that
// names it. Every value in it comes from the manifest, so the fixture forges
// nothing by publishing it.
func (a *app) assignmentFor(manifest releaseManifest) map[string]any {
	return map[string]any{
		"schema_version": 1, "release_id": manifest.ReleaseID, "version": manifest.Version,
		"board": manifest.Board, "image_path": manifest.ImagePath,
		"image_sha256": manifest.ImageSHA256, "image_size": manifest.ImageSize,
		"mutable": true, "signed": true,
	}
}

// fetchReleaseArtifact asks the service for a stored manifest or its detached
// signature, the way the device does, over the verified connection.
func (a *app) fetchReleaseArtifact(target, releaseID, suffix string) ([]byte, error) {
	client, endpoint := a.serviceClient(target)
	address := endpoint + "/v1/releases/" + url.PathEscape(releaseID) + "/" + suffix
	a.sent(http.MethodGet, address)
	response, err := client.Get(address)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the service returned %s for %s", response.Status, suffix)
	}
	return io.ReadAll(response.Body)
}

// fetchAssignment reads the record that decides what every device installs.
func (a *app) fetchAssignment(target string) (releaseRecord, error) {
	var record releaseRecord
	client, endpoint := a.serviceClient(target)
	address := endpoint + "/v1/releases/current"
	a.sent(http.MethodGet, address)
	response, err := client.Get(address)
	if err != nil {
		return record, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return record, fmt.Errorf("the service returned %s for the current release", response.Status)
	}
	return record, json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&record)
}

// releaseRecord is the Update assignment as the device reads it. Only the
// fields the fixtures use are named; the record has not changed since Tier 0
// and Tier 4 does not change it either.
type releaseRecord struct {
	ReleaseID string `json:"release_id"`
	Version   string `json:"version"`
	ImagePath string `json:"image_path"`
}

// ---------------------------------------------------------------------------
// The fixtures
// ---------------------------------------------------------------------------

// tier04HostileRelease publishes one hostile release through the genuine
// service.
//
// Nothing in this function refuses anything, and that is the point. Every step
// succeeds: the service stores what it is given, serves back exactly the bytes
// it was given, and has no opinion about any of it. The refusal happens on the
// board and the Learner reads it there.
func (a *app) tier04HostileRelease(target string, env environment) (string, string, map[string]string, error) {
	selector := a.selector
	id := hostileReleaseID(selector)
	var described struct {
		learnerSigned bool
		bootloader    bool
		why           string
		refusedAt     string
	}
	for _, variant := range hostileManifests {
		if variant.name == selector {
			described.learnerSigned = variant.learnerSigned
			described.bootloader = variant.bootloader
			described.why = variant.why
			described.refusedAt = variant.refusedAt
		}
	}

	good, err := a.newestRelease()
	if err != nil {
		return "", "", nil, err
	}
	goodManifest := good.manifest
	manifest, body, err := a.loadStoredManifest(id)
	if err != nil {
		return "", "", nil, fmt.Errorf("no %s release yet; run ./course release hostile --tier 04 first", selector)
	}
	signature, err := os.ReadFile(a.manifestSignaturePath(id))
	if err != nil {
		return "", "", nil, fmt.Errorf("no %s signature yet; run ./course release hostile --tier 04 first", selector)
	}
	key, err := a.releaseVerifyKey()
	if err != nil {
		return "", "", nil, err
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	a.step(1, fmt.Sprintf("Take the %s release you built from your own good one.", selector))
	a.note("%s", described.why)
	a.note("%d bytes of manifest, sha256 %s", len(body), digest)
	a.note("Its release identifier is %s, its own. The device compares that against what", id)
	a.note("it is running, so a hostile release that reused %s would simply be ignored.", goodManifest.ReleaseID)
	a.note("Compared against %s, the newest release you have signed:", goodManifest.ReleaseID)
	for _, line := range manifestDifferences(goodManifest, manifest) {
		a.note("  changed: %s", line)
	}
	a.note("image_path is still %s. This publishes no firmware at all.", manifest.ImagePath)

	a.step(2, "Ask who signed it, before anything else asks anything.")
	verified := manifestVerifies(key, body, signature)
	if verified {
		a.got("The signature verifies against your own Release signing key.")
		a.note("This is not a forgery and it could not have been one. Nobody without your key can")
		a.note("produce a manifest that verifies, so this release could only have been signed by")
		a.note("whoever holds it. It is the manufacturer publishing something wrong, not an outsider.")
		a.note("Your key has not leaked. The course signed this with your key deliberately, because")
		a.note("%s", described.refusedAt)
		a.note("never runs on a manifest that failed the signature, so there is no other way to see it.")
		a.note("The device cannot tell this apart from a leaked key, and it refuses either way.")
		a.note("A signature proves who signed. It never proves they should have.")
	} else {
		a.got("The signature does not verify against your Release signing key.")
		a.note("Anyone at all could have produced this one, which is what makes it a forgery.")
		a.note("The device throws it out at %s.", described.refusedAt)
	}
	if described.learnerSigned != verified {
		return "", "", nil, fmt.Errorf("the %s release does not match its declared kind; rebuild it with ./course release hostile --tier 04", selector)
	}

	a.step(3, "Publish it through your own update service.")
	a.note("Not an imposter. The real service, with the certificate your device verifies.")
	a.note("The service stores manifest bytes and serves them back. It never parses one,")
	a.note("never validates one, and holds no key that could sign one.")
	// The same honest bit Tier 3 pointed at, one tier later. The service
	// overwrites signed to false on every PUT and no device has ever read it.
	// From Tier 4 the record is read for one thing only, the release
	// identifier, and everything else about the release comes from the signed
	// manifest. The record stops being believed rather than being changed.
	a.note("This record still claims \"signed\": true. The service refuses to store that claim, and")
	a.note("from Tier 4 the device reads this record only to learn which release it is offered.")
	if err := a.putRelease(target, env, a.assignmentFor(manifest)); err != nil {
		return "", "", nil, err
	}
	a.got("The service now offers %s to every device that asks.", id)

	a.step(4, "Fetch the manifest and its signature back, the way the device will.")
	servedBody, err := a.fetchReleaseArtifact(target, id, "manifest")
	if err != nil {
		return "", "", nil, err
	}
	servedSignature, err := a.fetchReleaseArtifact(target, id, "manifest.sig")
	if err != nil {
		return "", "", nil, err
	}
	if !bytes.Equal(servedBody, body) || !bytes.Equal(servedSignature, signature) {
		return "", "", nil, errors.New("the service did not return the manifest and signature unchanged")
	}
	a.got("%d manifest bytes and %d signature bytes, byte for byte what you published.", len(servedBody), len(servedSignature))
	a.note("Byte for byte matters here. Re-encoding this JSON without changing one value would")
	a.note("break the signature, which is why the service stores bytes rather than a record.")

	a.step(5, "Stop. Nothing here can refuse this release.")
	a.note("Every check Tier 2 added passed. The service is authentic, the connection is private,")
	a.note("the name matched, and the bytes arrived intact.")
	a.note("Tier 3's check would pass too, and that is the part worth sitting with: the image")
	a.note("behind this release is your own correctly signed %s. Tier 3 asks who", manifest.ImagePath)
	a.note("published an image. It has nothing to say about a release that describes it wrongly.")
	if described.bootloader {
		a.note("So will every check the application makes. This one is different from the others:")
		a.note("%s.", described.refusedAt)
		a.note("Expect the application to accept it and say so, expect the write to happen, and")
		a.note("expect the refusal on the reboot after that. One key signed both the manifest and")
		a.note("the image, and the two verifiers still disagree, because they are checking")
		a.note("different things about different bytes.")
	} else {
		a.note("The only thing that can still refuse this is the application on the board, at")
		a.note("%s.", described.refusedAt)
	}
	a.note("Watch it with ./course device logs, and reset the board to make it poll.")

	return fmt.Sprintf("the genuine service published the %s release and served its manifest and signature unchanged; the device outcome is not known to this fixture", selector),
		"The refusal under test is the device's. This fixture records only what it published. Read the board.",
		map[string]string{id + ".manifest.json": digest}, nil
}

// tier04ReplayRelease re-assigns a genuinely signed older release.
//
// It forges nothing. It edits no manifest and no signature. Everything it
// publishes was produced by this Course environment and signed by the Learner's
// own key, and every signature still verifies when the device checks it. That
// is the whole lesson: this is the one attack that survives a perfect
// signature, which is why it is not one of the seven hostile releases.
func (a *app) tier04ReplayRelease(target string, env environment) (string, string, map[string]string, error) {
	key, err := a.releaseVerifyKey()
	if err != nil {
		return "", "", nil, err
	}

	a.step(1, "Read the release the service is offering now.")
	assignment, err := a.fetchAssignment(target)
	if err != nil {
		return "", "", nil, err
	}
	a.got("release_id %s, version %s", assignment.ReleaseID, assignment.Version)

	releases, err := a.goodReleases()
	if err != nil {
		return "", "", nil, err
	}
	var current goodRelease
	for _, release := range releases {
		if release.manifest.ReleaseID == assignment.ReleaseID {
			current = release
		}
	}
	if current.body == nil {
		return "", "", nil, fmt.Errorf(
			"the service is offering %s, which is not a signed Tier 4 release this environment produced; "+
				"a downgrade needs a counter to go backwards from, so publish one first with "+
				"./course release sign --tier 04 --variant security-fix", assignment.ReleaseID)
	}
	a.note("Its manifest is signed by your key and carries security_counter %d.", current.manifest.SecurityCounter)

	a.step(2, "Find an older release this environment actually produced.")
	older, ok := olderRelease(releases, current.manifest.SecurityCounter)
	if !ok {
		var have []string
		for _, release := range releases {
			have = append(have, fmt.Sprintf("%s at counter %d", release.manifest.ReleaseID, release.manifest.SecurityCounter))
		}
		return "", "", nil, fmt.Errorf(
			"no signed release in this environment carries a counter below %d, so there is nothing to replay; "+
				"this environment has: %s. Sign and install the baseline, then sign and install "+
				"./course release sign --tier 04 --variant security-fix, and run this again",
			current.manifest.SecurityCounter, strings.Join(have, ", "))
	}
	a.got("%s, security_counter %d, signed %s", older.manifest.ReleaseID,
		older.manifest.SecurityCounter, older.manifest.CreatedAt)
	if !manifestVerifies(key, older.body, older.signature) {
		return "", "", nil, errors.New("the older release's signature does not verify; this fixture will not publish a release it cannot show is genuine")
	}
	a.note("Its signature verifies. Nothing about this release is forged, edited, or expired,")
	a.note("and this fixture will not touch either file. There is nothing here to detect.")
	a.note("%d is lower than %d, not merely not higher. MCUboot compares counter[0] > counter[1],", older.manifest.SecurityCounter, current.manifest.SecurityCounter)
	a.note("so an equal counter is accepted and only a strictly lower one is a downgrade.")

	a.step(3, "Know what this proves, and what it does not.")
	a.note("Downgrade prevention compares the candidate against the counter in the image already")
	a.note("in the primary slot. Nothing is remembered anywhere else.")
	a.note("MCUboot's check opens with: if there is no security counter in slot 0, allow the swap.")
	a.note("Every image built before Tier 4 carries no counter at all, so a board that is still")
	a.note("running one of those will install this release and the check will never have run.")
	a.note("This fixture cannot see your board. Before you believe anything below, confirm that")
	a.note("your board is running %s and that its boot banner reported", current.manifest.ReleaseID)
	a.note("security_counter %d. If it is not, the install you are about to watch is the", current.manifest.SecurityCounter)
	a.note("migration case succeeding, not the control failing.")

	a.step(4, "Re-assign the older release. Nothing is edited.")
	assignmentBody := a.assignmentFor(older.manifest)
	a.note("Every value in this record comes from the signed manifest you just verified.")
	if err := a.putRelease(target, env, assignmentBody); err != nil {
		return "", "", nil, err
	}
	a.got("The service now offers %s again.", older.manifest.ReleaseID)

	a.step(5, "Fetch the manifest and signature back and prove they are untouched.")
	servedBody, err := a.fetchReleaseArtifact(target, older.manifest.ReleaseID, "manifest")
	if err != nil {
		return "", "", nil, err
	}
	servedSignature, err := a.fetchReleaseArtifact(target, older.manifest.ReleaseID, "manifest.sig")
	if err != nil {
		return "", "", nil, err
	}
	if !bytes.Equal(servedBody, older.body) || !bytes.Equal(servedSignature, older.signature) {
		return "", "", nil, errors.New("the service did not return the stored manifest and signature unchanged")
	}
	if !manifestVerifies(key, servedBody, servedSignature) {
		return "", "", nil, errors.New("the manifest the service served does not verify; it should, because nothing edited it")
	}
	a.got("%d manifest bytes and %d signature bytes, and the signature still verifies.", len(servedBody), len(servedSignature))
	a.note("This is the difference between this fixture and the seven hostile releases. The device will")
	a.note("check this signature and the signature will pass.")

	a.step(6, "Stop. Nothing here can refuse this release.")
	a.note("The signature is perfect, so it cannot be the control. The application compares the")
	a.note("manifest's counter against its own and saves a wasted download, and the bootloader")
	a.note("compares the candidate image's counter against the one in the primary slot. The")
	a.note("bootloader is what actually stops a downgrade; the application's check is a courtesy.")
	a.note("Watch both with ./course device logs, and reset the board to make it poll.")

	sum := sha256.Sum256(older.body)
	return fmt.Sprintf("the genuine service re-assigned %s at security_counter %d, unedited and still verifying, while %s at counter %d was assigned; the device outcome is not known to this fixture",
			older.manifest.ReleaseID, older.manifest.SecurityCounter,
			current.manifest.ReleaseID, current.manifest.SecurityCounter),
		"The refusal under test is the device's, and it is inert unless a counter-carrying image is already in the primary slot. This fixture records only what it published. Read the board.",
		map[string]string{older.manifest.ReleaseID + ".manifest.json": hex.EncodeToString(sum[:])}, nil
}

var tier04Plan = map[string][]string{
	"tier-04/hostile-release": {
		"Take one of the seven hostile releases you built from your own good one.",
		"Say whether its signature verifies, and what that means about who could have made it.",
		"Publish it through your own update service, over the connection the device verifies.",
		"Fetch the manifest and signature back to prove the service serves stored bytes unchanged.",
		"Stop. Nothing on this host can refuse it, and that is the finding.",
	},
	"tier-04/replay-release": {
		"Read the release the service is offering now and find its signed security counter.",
		"Find an older release this environment produced whose counter is strictly lower.",
		"State the precondition: downgrade prevention is inert until a counter-carrying image is primary.",
		"Re-assign the older release, editing no manifest and no signature.",
		"Prove the manifest still verifies, because nothing about it was forged.",
		"Stop. Nothing on this host can refuse it, and that is the finding.",
	},
}

var tier04Proves = map[string][]string{
	"tier-04/hostile-release": {
		"REQ-06 and the Tier 4 threat list: incompatible hardware assignment and version-policy mistakes are refusals, not forgeries.",
		"T3-W-11: five of these seven could only be signed by whoever holds the Release signing key, and the device cannot tell a mistake from a leak.",
		"What a signature does not prove: it says who signed, never that they should have.",
	},
	"tier-04/replay-release": {
		"The one attack a perfect signature does not stop: a genuine older release, replayed.",
		"Section 6: the counter is compared, never remembered, and the comparison lives in flash an attacker can rewrite.",
		"B4 from issue #68: across the transition, before any counter-carrying image is primary, this succeeds.",
	},
}
