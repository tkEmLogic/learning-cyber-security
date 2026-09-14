package courseapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testReleaseKey(t *testing.T) ([]byte, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), &key.PublicKey
}

// The signature covers bytes, not values. This is the whole reason section 7
// verifies the downloaded bytes before parsing instead of canonicalising them,
// and the reason the service must serve a stored manifest back unchanged.
func TestManifestSignatureCoversExactBytesNotValues(t *testing.T) {
	keyPEM, public := testReleaseKey(t)

	manifest := releaseManifest{
		SchemaVersion: 1, ReleaseID: "tier-04-baseline", Version: "0.4.0-release-policy",
		SecurityCounter: 1, Channel: "stable", Board: "esp32c6_devkitc/esp32c6/hpcore",
		HardwareRevisionMin: 1, HardwareRevisionMax: 1,
		ImagePath: "tier-04-baseline.bin", ImageSize: 663611,
		ImageSHA256: "8ad643509ec835b176bd623632be35b6c21db35610ab1d74daca70bd077b69bc",
		CreatedAt:   "2026-09-14T13:20:00Z", SupportedUntil: "2031-09-14T13:20:00Z",
	}

	signed, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	signed = append(signed, '\n')

	signature, err := signManifest(keyPEM, signed)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(public, digest[:], signature) {
		t.Fatal("the signature must verify against the bytes that were signed")
	}

	// Same values, different bytes. A service that parsed the manifest and
	// re-encoded it would produce exactly this, and the device would refuse a
	// release that nobody had tampered with.
	reformatted, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(reformatted) == string(signed) {
		t.Fatal("the reformatted manifest must differ in bytes, or this proves nothing")
	}
	reDigest := sha256.Sum256(reformatted)
	if ecdsa.VerifyASN1(public, reDigest[:], signature) {
		t.Error("reformatting the manifest must break the signature")
	}

	// One value changed, everything else identical.
	tampered := manifest
	tampered.SecurityCounter = 2
	raised, err := json.MarshalIndent(tampered, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raised = append(raised, '\n')
	raisedDigest := sha256.Sum256(raised)
	if ecdsa.VerifyASN1(public, raisedDigest[:], signature) {
		t.Error("raising the security counter must break the signature")
	}
}

// Section 6 requires the same security counter in the signed image TLV and the
// signed manifest. They are the same constant here so they cannot drift, and
// this asserts nobody has split them apart later.
func TestSecurityCounterHasOneSource(t *testing.T) {
	variant := tier04Variants["baseline"]
	if variant.securityCounter != tier04SecurityCounter {
		t.Errorf("variant counter %d should be the tier constant %d",
			variant.securityCounter, tier04SecurityCounter)
	}

	a := &app{}
	a.manifest.Devices = map[string]struct {
		SyntheticID        string   `yaml:"synthetic_id"`
		SpoofID            string   `yaml:"spoof_id"`
		Board              string   `yaml:"board"`
		StableSerialPrefix string   `yaml:"stable_serial_prefix"`
		HardwareRequired   []string `yaml:"hardware_required"`
	}{"reference_beacon": {Board: "esp32c6_devkitc/esp32c6/hpcore"}}
	manifest := a.buildManifest(variant, []byte("firmware"), time.Date(2026, 9, 14, 13, 20, 0, 0, time.UTC))
	if manifest.SecurityCounter != variant.securityCounter {
		t.Errorf("manifest counter %d should equal the variant's %d",
			manifest.SecurityCounter, variant.securityCounter)
	}
}

// Every tier before Tier 4 carries no counter at all, which is what makes
// MCUboot allow the first swap. That is the migration case, not an oversight,
// so it is asserted rather than left to be rediscovered.
func TestTiersBeforeFourCarryNoCounter(t *testing.T) {
	for name, variants := range map[string]map[string]firmwareVariant{
		"tier-00": firmwareVariants, "tier-02": tier02Variants, "tier-03": tier03Variants,
	} {
		for label, variant := range variants {
			if variant.securityCounter != 0 {
				t.Errorf("%s/%s carries counter %d; tiers before Tier 4 carry none",
					name, label, variant.securityCounter)
			}
		}
	}
}

// The default stays Tier 3, so every command a published module prints keeps
// working unchanged.
func TestReleaseSignDefaultsToTierThree(t *testing.T) {
	if got := releaseTierOption(nil); got != "03" {
		t.Errorf("bare release sign should stay Tier 3, got %q", got)
	}
	if got := releaseTierOption([]string{"--tier", "04"}); got != "04" {
		t.Errorf("--tier 04 should select Tier 4, got %q", got)
	}
	if got := releaseTierOption([]string{"--tier", "4"}); got != "04" {
		t.Errorf("--tier 4 should normalize to 04, got %q", got)
	}
}

// Tier 4 builds its own application, the way every tier since Tier 2 has. A
// control added in one tier must never be able to change the firmware a
// published tier describes.
func TestTierFourBuildsItsOwnApplication(t *testing.T) {
	dir, ok := firmwareApps["04"]
	if !ok {
		t.Fatal("Tier 4 has no firmware application")
	}
	if dir == firmwareApps["03"] {
		t.Fatal("Tier 4 must not share Tier 3's application directory")
	}
	for _, name := range []string{
		"CMakeLists.txt", "Kconfig", "prj.conf", "sysbuild.conf",
		"bootloader/mcuboot.conf", "anchor/release_pubkey.inc",
		"src/release_policy.c", "src/release_policy.h",
	} {
		if _, err := os.Stat(filepath.Join("..", "..", dir, name)); err != nil {
			t.Errorf("%s is missing from the Tier 4 application: %v", name, err)
		}
	}
}

// From Tier 3 the bootloader is built separately against the public half of
// the Learner's key, and the image is signed afterwards rather than by the
// build. Tier 4 inherits that whole arrangement.
func TestSignedTiersBuildTheirBootloaderSeparately(t *testing.T) {
	for tier, want := range map[string]bool{"00": false, "02": false, "03": true, "04": true} {
		if got := tierSignsItsOwnImage(tier); got != want {
			t.Errorf("tier %s: separate bootloader build %v, want %v", tier, got, want)
		}
	}
}

// The channel the build publishes to and the channel the device is configured
// to follow are one constant, for the same reason the counter is. A device
// that refused the channel its own build published to would be a puzzle
// rather than a lesson.
func TestReleaseChannelHasOneSource(t *testing.T) {
	a := &app{}
	a.manifest.Devices = map[string]struct {
		SyntheticID        string   `yaml:"synthetic_id"`
		SpoofID            string   `yaml:"spoof_id"`
		Board              string   `yaml:"board"`
		StableSerialPrefix string   `yaml:"stable_serial_prefix"`
		HardwareRequired   []string `yaml:"hardware_required"`
	}{"reference_beacon": {Board: "esp32c6_devkitc/esp32c6/hpcore"}}

	manifest := a.buildManifest(tier04Variants["baseline"], []byte("firmware"),
		time.Date(2026, 9, 14, 13, 20, 0, 0, time.UTC))
	if manifest.Channel != tier04Channel {
		t.Errorf("manifest channel %q should be the tier constant %q",
			manifest.Channel, tier04Channel)
	}

	// The manifest's hardware range has to cover the revision the build
	// asserts, or the device refuses its own release.
	if manifest.HardwareRevisionMin > tier04HardwareRevision ||
		manifest.HardwareRevisionMax < tier04HardwareRevision {
		t.Errorf("manifest hardware range %d..%d does not cover the asserted revision %d",
			manifest.HardwareRevisionMin, manifest.HardwareRevisionMax, tier04HardwareRevision)
	}
}
