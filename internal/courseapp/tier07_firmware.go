package courseapp

// The build half of Tier 7: the one release this tier publishes, and the
// command that signs it.
//
// It lives in its own file rather than beside the Owner credential store,
// because the two halves of Tier 7's tooling answer different questions and
// arrive on different tickets. This one is what #151 needs before it can put
// anything on a board.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// tier07SecurityCounter stays at Tier 6's value, which is Tier 5's.
//
// Section 6 raises a counter only when a release closes a security boundary
// that must not be reopened. Tier 7 does not: it gives the device an
// Operational identity and makes the service demand one, and both of those are
// facts about what the service will serve rather than about what the
// bootloader must refuse to run.
//
// Raising it would also cost the validation this tier depends on. A board that
// has run a counter 4 image can never be put back on a Tier 5 or Tier 6
// release, and re-running the earlier tiers on the same board is how this
// course checks that a new tier did not break an old one.
const tier07SecurityCounter = 3

// tier07Version is what imgtool stamps into the image header.
const tier07Version = "0.7.0+0"

// tier07Variants are the two releases Tier 7 publishes from one source tree.
//
// Tier 6 published two because where an identity comes from was its subject.
// Tier 7's subject is what an identity authorizes, and it takes the per-device
// Factory identity as given: a shared image has nothing it can prove is its
// own, so it has nothing to claim with. The comparison stays Tier 6's, and
// Tier 6 still publishes both halves of it.
//
// The second release exists so that Tier 7 can show an update, and a failed
// one, without leaving Tier 7. An earlier version borrowed a Tier 5 release
// for that, which offered a claimed device an older tier's image: one that
// does not share Tier 7's storage layout, cannot record its own trial on it,
// and so reverted without anyone being told and was offered again without a
// bound (#239). A device in the field is only ever offered its own product's
// releases, and the lab should look like that.
//
// fail-health is a real, correctly signed Tier 7 image that fails one named
// health check on its trial boot. The device downloads it over mutual TLS on
// its Operational identity, installs it on trial, and puts the confirmed image
// back, and the image that comes back reports the revert on the same identity.
var tier07Variants = map[string]firmwareVariant{
	"baseline": {
		releaseID:       "tier-07-operational-identity",
		label:           "baseline",
		beaconState:     "steady",
		version:         "0.7.0-operational-identity",
		imageName:       "tier-07-operational-identity.bin",
		securityCounter: tier07SecurityCounter,
		trialBehaviour:  "healthy",
		identityModel:   "factory",
	},
	"fail-health": {
		releaseID:       "tier-07-fail-health",
		label:           "fail-health",
		beaconState:     "steady",
		version:         "0.7.1-fail-health",
		imageName:       "tier-07-fail-health.bin",
		securityCounter: tier07SecurityCounter,
		trialBehaviour:  "fail-health",
		identityModel:   "factory",
	},
}

func tier07Variant(name string) (firmwareVariant, error) {
	variant, ok := tier07Variants[name]
	if !ok {
		return firmwareVariant{}, fmt.Errorf("unknown Tier 7 release %q; use baseline or fail-health", name)
	}
	return variant, nil
}

func (a *app) tier07BuildDir(variant firmwareVariant) string {
	return filepath.Join(a.zephyrWorkspace(), "build", "tier-07-operational-identity-"+variant.label)
}

func (a *app) tier07RawImage(variant firmwareVariant) string {
	return filepath.Join(a.tier07BuildDir(variant), "tier-07-operational-identity", "zephyr", "zephyr.bin")
}

// releaseSignTier07 signs one Tier 7 release and publishes it.
//
// Tier 6's sequence unchanged, including the source-revision TLV: Tier 7 keeps
// the whole recovery path, and a revert still leaves the device running an
// image whose manifest it consumed long ago.
//
// The image the device ends up running is an ordinary signed release. Nothing
// about the claim is in it. A Learner who reads this command looking for where
// ownership enters the image will not find it, and that is the point: the
// Operational identity arrives over the wire, at run time, from a service, and
// never from a build.
func (a *app) releaseSignTier07(variantName string) error {
	variant, err := tier07Variant(variantName)
	if err != nil {
		return err
	}
	key := a.signingKeyPath("release")
	if _, err := os.Stat(key); err != nil {
		return errors.New("no Release signing key yet; run ./course keys create release first")
	}
	raw := a.tier07RawImage(variant)
	if _, err := os.Stat(raw); err != nil {
		return fmt.Errorf("no Tier 7 image to sign; run ./course build firmware --tier 07 first")
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
	if err := a.signImage(key, raw, out, strconv.Itoa(variant.securityCounter), tier07Version,
		"--custom-tlv", tier05RevisionTLV, revision); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "+ source revision %s written to protected TLV %s\n",
		revision, tier05RevisionTLV)

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
	fmt.Fprintf(a.out, "Result: published %s, %d bytes\n", variant.releaseID, release["image_size"])
	fmt.Fprintln(a.out, "This image holds a Factory identity and no owner. Who owns the device is")
	fmt.Fprintln(a.out, "decided after it is running, by a claim, and it is the service that decides.")
	return nil
}

// releaseAssignTier07 points the service at a Tier 7 release that is already
// signed, so the Learner can go back to baseline after fail-health without
// signing anything again. It is Tier 6's assign with Tier 7's releases.
func (a *app) releaseAssignTier07(variantName string) error {
	variant, err := tier07Variant(variantName)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(a.manifestPath(variant.releaseID))
	if err != nil {
		return fmt.Errorf("no signed %s release yet; run ./course release sign --tier 07 --variant %s first",
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
	return nil
}
