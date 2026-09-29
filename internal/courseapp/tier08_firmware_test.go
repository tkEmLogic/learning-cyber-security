package courseapp

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Tier 8 builds its own application, the way every tier since Tier 2 has, and
// the files the tier added are in it.
func TestTierEightBuildsItsOwnApplication(t *testing.T) {
	dir, ok := firmwareApps[tier08]
	if !ok {
		t.Fatal("Tier 8 has no firmware application")
	}
	if dir == firmwareApps["07"] {
		t.Fatal("Tier 8 must not share Tier 7's application directory")
	}
	for _, name := range []string{
		"CMakeLists.txt", "Kconfig", "prj.conf", "sysbuild.conf",
		"bootloader/mcuboot.conf", "anchor/release_pubkey.inc",
		"src/claim.c", "src/identity.c", "src/opaque_tls.c",
		"src/renewal.c", "src/renewal.h", "src/time_floor.c", "src/time_floor.h",
	} {
		if _, err := os.Stat(filepath.Join("..", "..", dir, name)); err != nil {
			t.Errorf("%s is missing from the Tier 8 application: %v", name, err)
		}
	}
}

// Tier 8's bootloader is built separately and its image signed afterwards,
// like every tier from Tier 3, and it publishes two releases of its own.
func TestTierEightSignsItsOwnImage(t *testing.T) {
	if !tierSignsItsOwnImage(tier08) {
		t.Fatal("Tier 8 must build its bootloader separately and sign afterwards")
	}
	if got := variantsForTier(tier08); len(got) != 2 {
		t.Fatalf("Tier 8 publishes two releases, got %d", len(got))
	}
}

// #206: counter 4, above Tier 5's and Tier 7's 3, so this image's own policy
// and its bootloader refuse their releases.
func TestTierEightRaisesTheCounterPastTierSeven(t *testing.T) {
	if tier08SecurityCounter != 4 {
		t.Fatalf("Tier 8 counter is %d, want 4", tier08SecurityCounter)
	}
	if tier08SecurityCounter <= tier07SecurityCounter || tier08SecurityCounter <= tier05SecurityCounter {
		t.Fatal("Tier 8's counter must be above Tier 5's and Tier 7's")
	}
	for name, variant := range tier08Variants {
		if variant.securityCounter != tier08SecurityCounter {
			t.Errorf("Tier 8 %s counter %d, want %d", name, variant.securityCounter, tier08SecurityCounter)
		}
		if variant.identityModel != "factory" {
			t.Errorf("Tier 8 %s identity model %q, want factory", name, variant.identityModel)
		}
	}
}

// Tier 8's second release is its own, never an older tier's (#239).
func TestTierEightFailingReleaseIsItsOwn(t *testing.T) {
	baseline, failing := tier08Variants["baseline"], tier08Variants["fail-health"]
	if !strings.HasPrefix(baseline.releaseID, "tier-08-") || !strings.HasPrefix(failing.releaseID, "tier-08-") {
		t.Fatalf("Tier 8 release ids must be Tier 8's: %q, %q", baseline.releaseID, failing.releaseID)
	}
	if failing.releaseID == baseline.releaseID {
		t.Fatal("fail-health needs its own release id")
	}
	if failing.trialBehaviour != "fail-health" {
		t.Errorf("fail-health trial behaviour is %q", failing.trialBehaviour)
	}
}

// The seed is the RFC 3339 UTC shape time_floor.c parses, and it never
// carries fractional seconds or an offset, both of which the firmware refuses.
func TestTierEightTimeFloorSeedIsWhatTheFirmwareParses(t *testing.T) {
	local := time.FixedZone("CEST", 2*60*60)
	got := tier08TimeFloorSeed(time.Date(2026, 9, 29, 12, 34, 56, 789_000_000, local))
	if got != "2026-09-29T10:34:56Z" {
		t.Fatalf("seed = %q", got)
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`).MatchString(got) {
		t.Fatalf("seed %q is not the 20-character form the firmware accepts", got)
	}
}

// Every firmware command reaches Tier 8's own code now, rather than a refusal
// or an older tier's image. Without a Zephyr workspace or a key each stops
// early, and each says why in Tier 8's terms.
func TestTierEightFirmwareCommandsReachTierEight(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.release([]string{"sign", "--tier", "08", "--variant", "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown Tier 8 release") {
		t.Errorf("release sign --tier 08 with a bad variant = %v", err)
	}
	if err := a.release([]string{"assign", "--tier", "8", "--variant", "baseline"}); err == nil ||
		!strings.Contains(err.Error(), "--tier 08 --variant baseline") {
		t.Errorf("release assign --tier 8 before signing = %v", err)
	}
	if err := a.release([]string{"sign", "--tier", "tier-08", "--variant", "baseline"}); err == nil ||
		!strings.Contains(err.Error(), "Release signing key") && !strings.Contains(err.Error(), "Tier 8 image") {
		t.Errorf("release sign --tier 08 without a key or an image = %v", err)
	}
	if err := a.buildFirmware([]string{"--tier", "08", "--variant", "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown firmware variant") {
		t.Errorf("build firmware --tier 08 with a bad variant = %v", err)
	}
	if err := a.deviceFlash([]string{"--tier", "08", "--variant", "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown firmware variant") {
		t.Errorf("device flash --tier 08 with a bad variant = %v", err)
	}
}
