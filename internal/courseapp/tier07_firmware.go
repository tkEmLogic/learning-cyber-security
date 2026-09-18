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

// tier07Variants is one image, and the count is the decision.
//
// Tier 6 published two because where an identity comes from was its subject.
// Tier 7's subject is what an identity authorizes, and it takes the per-device
// Factory identity as given: a shared image has nothing it can prove is its
// own, so it has nothing to claim with. The comparison stays Tier 6's, and
// Tier 6 still publishes both halves of it.
//
// It is still a map with a named variant rather than a bare struct, because
// every path through the build, the signing and the flash takes a variant
// name, and a tier that was special there would be a tier a Learner has to
// hold differently.
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
}

func tier07Variant(name string) (firmwareVariant, error) {
	variant, ok := tier07Variants[name]
	if !ok {
		return firmwareVariant{}, fmt.Errorf("unknown Tier 7 release %q; Tier 7 publishes one, called baseline", name)
	}
	return variant, nil
}

func (a *app) tier07BuildDir(variant firmwareVariant) string {
	return filepath.Join(a.zephyrWorkspace(), "build", "tier-07-operational-identity-"+variant.label)
}

func (a *app) tier07RawImage(variant firmwareVariant) string {
	return filepath.Join(a.tier07BuildDir(variant), "tier-07-operational-identity", "zephyr", "zephyr.bin")
}

// releaseSignTier07 signs Tier 7's one release and publishes it.
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
