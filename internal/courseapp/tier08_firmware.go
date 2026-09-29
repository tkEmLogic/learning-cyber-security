package courseapp

// The build half of Tier 8: the releases this tier publishes, and the
// commands that sign and assign them (#256).
//
// The firmware is firmware/tier-08-credential-lifecycle, Tier 7's application
// with the Operational identity in one of two slots, the Time floor, and every
// refusal read by its check name. It reads a Tier 7 board's storage unchanged,
// so flashing it over a claimed Tier 7 board keeps both identities.

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// tier08SecurityCounter is the first counter raise since Tier 5.
//
// Section 6 raises a counter when a release closes a boundary that must not be
// reopened, and Tier 8 closes one (#206). Tier 5 and Tier 7 both carry 3, and
// both the application policy and MCUboot admit an equal counter, so a Tier 5
// release could reach a claimed Tier 7 board by OTA and erase its identities
// at its first boot. At 4, this image's own policy and its bootloader refuse
// every Tier 5, Tier 6 and Tier 7 release. That is real anti-rollback: the
// storage layout changed, and an older image cannot read it.
//
// The cost Tier 7 declined to pay is paid here on purpose. A board that has
// run this image cannot be put back on an earlier tier by OTA; it takes a
// flash, and the flash guard in flash_guard.go stands in front of that.
const tier08SecurityCounter = 4

// tier08Version is what imgtool stamps into the image header.
const tier08Version = "0.8.0+0"

// tier08Variants are the two releases Tier 8 publishes from one source tree,
// the same pair Tier 7 publishes and for the same reason (#239): a device is
// only ever offered its own product's releases, so the second release is a
// real, correctly signed Tier 8 image that fails one named health check on
// its trial boot. Its manifest still verifies, so it still raises the Time
// floor, whether or not it installs.
var tier08Variants = map[string]firmwareVariant{
	"baseline": {
		releaseID:       "tier-08-credential-lifecycle",
		label:           "baseline",
		beaconState:     "steady",
		version:         "0.8.0-credential-lifecycle",
		imageName:       "tier-08-credential-lifecycle.bin",
		securityCounter: tier08SecurityCounter,
		trialBehaviour:  "healthy",
		identityModel:   "factory",
	},
	"fail-health": {
		releaseID:       "tier-08-fail-health",
		label:           "fail-health",
		beaconState:     "steady",
		version:         "0.8.1-fail-health",
		imageName:       "tier-08-fail-health.bin",
		securityCounter: tier08SecurityCounter,
		trialBehaviour:  "fail-health",
		identityModel:   "factory",
	},
	// time-floor is a lab image, not a product release (#263). It is the
	// baseline built with a Time floor seed the operator sets past the
	// board's own Operational certificate valid_to, so the device refuses that
	// certificate on its own authority. Nothing else differs, and no
	// future-dated manifest is involved: the manifest's created_at is still
	// the moment of signing.
	"time-floor": {
		releaseID:       "tier-08-time-floor",
		label:           "time-floor",
		beaconState:     "steady",
		version:         "0.8.2-time-floor",
		imageName:       "tier-08-time-floor.bin",
		securityCounter: tier08SecurityCounter,
		trialBehaviour:  "healthy",
		identityModel:   "factory",
	},
}

func tier08Variant(name string) (firmwareVariant, error) {
	variant, ok := tier08Variants[name]
	if !ok {
		return firmwareVariant{}, fmt.Errorf("unknown Tier 8 release %q; use baseline, fail-health or time-floor", name)
	}
	return variant, nil
}

func (a *app) tier08BuildDir(variant firmwareVariant) string {
	return filepath.Join(a.zephyrWorkspace(), "build", "tier-08-credential-lifecycle-"+variant.label)
}

func (a *app) tier08RawImage(variant firmwareVariant) string {
	return filepath.Join(a.tier08BuildDir(variant), "tier-08-credential-lifecycle", "zephyr", "zephyr.bin")
}

// tier08TimeFloorSeed is the Time floor's build seed (#217): the moment of
// the build, in the RFC 3339 UTC shape the firmware parses and the manifest's
// created_at already uses. It is compiled into the image, so the image
// signature covers it. Never later than the build, because a floor ahead of
// real time refuses every certificate issued before it and never comes back.
func tier08TimeFloorSeed(now time.Time) string {
	return now.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// withTimeFloorSeed applies --time-floor-seed. Only Tier 8's time-floor
// variant takes one, and it cannot be built without one: a seed ahead of real
// time refuses every certificate issued before it and never comes back, so it
// is never a default and never leaks into a release a board keeps.
func withTimeFloorSeed(variant firmwareVariant, tier, seed string) (firmwareVariant, error) {
	isLab := tier == tier08 && variant.label == "time-floor"
	switch {
	case seed == "" && isLab:
		return variant, errors.New("the time-floor variant needs --time-floor-seed <RFC 3339 UTC>, set past the board's Operational certificate valid_to")
	case seed == "":
		return variant, nil
	case !isLab:
		return variant, errors.New("--time-floor-seed is only for ./course build firmware --tier 08 --variant time-floor")
	}
	at, err := time.Parse(time.RFC3339, seed)
	if err != nil {
		return variant, fmt.Errorf("--time-floor-seed %q is not RFC 3339: %w", seed, err)
	}
	variant.timeFloorSeed = tier08TimeFloorSeed(at)
	return variant, nil
}

// releaseSignTier08 signs one Tier 8 release and publishes it, by Tier 7's
// sequence unchanged.
func (a *app) releaseSignTier08(variantName string) error {
	variant, err := tier08Variant(variantName)
	if err != nil {
		return err
	}
	release, err := a.signTierRelease(tier08, variant, a.tier08RawImage(variant), tier08Version)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: published %s, %d bytes\n", variant.releaseID, release["image_size"])
	fmt.Fprintf(a.out, "Its counter is %d. A device running it refuses every release from Tier 5 to\n",
		variant.securityCounter)
	fmt.Fprintln(a.out, "Tier 7, and its created_at raises the Time floor of every board that verifies it.")
	return nil
}

// releaseAssignTier08 points the service at a Tier 8 release that is already
// signed.
func (a *app) releaseAssignTier08(variantName string) error {
	variant, err := tier08Variant(variantName)
	if err != nil {
		return err
	}
	return a.assignTierRelease(tier08, variant)
}
