package courseapp

import (
	"os"
	"path/filepath"
	"testing"
)

// Tier 7 builds its own application, the way every tier since Tier 2 has. A
// control added in one tier must never be able to change the firmware a
// published tier describes.
//
// This is Tier 4's test with Tier 7's file list, and it exists because the
// absence of this map entry is what blocked the board validation: a firmware
// tree nothing can build through ./course is a firmware tree nobody can flash.
func TestTierSevenBuildsItsOwnApplication(t *testing.T) {
	dir, ok := firmwareApps["07"]
	if !ok {
		t.Fatal("Tier 7 has no firmware application")
	}
	if dir == firmwareApps["06"] {
		t.Fatal("Tier 7 must not share Tier 6's application directory")
	}
	for _, name := range []string{
		"CMakeLists.txt", "Kconfig", "prj.conf", "sysbuild.conf",
		"bootloader/mcuboot.conf", "anchor/release_pubkey.inc",
		"src/claim.c", "src/claim.h", "src/identity.c", "src/opaque_tls.c",
	} {
		if _, err := os.Stat(filepath.Join("..", "..", dir, name)); err != nil {
			t.Errorf("%s is missing from the Tier 7 application: %v", name, err)
		}
	}
}

// Tier 7's bootloader is built separately against the public half of the
// Learner's key, and its image is signed afterwards. Every tier from Tier 3 on
// has that property, so a new tier that quietly lacked it would publish an
// image the board refuses for a reason nobody could see from the console.
func TestTierSevenSignsItsOwnImage(t *testing.T) {
	if !tierSignsItsOwnImage("07") {
		t.Fatal("Tier 7 must build its bootloader separately and sign afterwards")
	}
	if got := variantsForTier("07"); len(got) != 2 {
		t.Fatalf("Tier 7 publishes two releases, got %d", len(got))
	}
}

// The counter stays at Tier 6's value, and that is a decision rather than an
// oversight. Raising it would make every Tier 5 and Tier 6 release
// uninstallable on a board that has run Tier 7, and re-running an earlier tier
// on the same board is how this course checks a new tier broke nothing.
func TestTierSevenCarriesTierSixesCounter(t *testing.T) {
	for name, variant := range tier07Variants {
		if variant.securityCounter != tier06SecurityCounter {
			t.Errorf("Tier 7 %s counter %d should still be Tier 6's %d", name, variant.securityCounter, tier06SecurityCounter)
		}
	}
}

// Tier 7 shows an update and a failed one with its own releases, never an
// earlier tier's (#239). The failing release has to be a distinct release
// carrying the same identity model, or the device would either shrug it off as
// the release it already runs or lose its identity to a different layout.
func TestTierSevenFailingReleaseIsItsOwn(t *testing.T) {
	baseline, failing := tier07Variants["baseline"], tier07Variants["fail-health"]
	if failing.releaseID == "" || failing.releaseID == baseline.releaseID {
		t.Fatalf("fail-health needs its own release id, got %q", failing.releaseID)
	}
	if failing.trialBehaviour != "fail-health" {
		t.Errorf("fail-health trial behaviour is %q", failing.trialBehaviour)
	}
	if failing.identityModel != baseline.identityModel {
		t.Errorf("fail-health identity model %q differs from baseline %q", failing.identityModel, baseline.identityModel)
	}
}

// Tier 7 carries the factory identity and nothing else. The generated fragment
// is what says so to the build, so the variant has to name the model the same
// way Tier 6's factory image does.
func TestTierSevenCarriesTheFactoryIdentity(t *testing.T) {
	variant := tier07Variants["baseline"]
	if variant.identityModel != "factory" {
		t.Fatalf("Tier 7 identity model is %q, want factory", variant.identityModel)
	}
	symbol, err := identityModelSymbol(variant.identityModel)
	if err != nil {
		t.Fatalf("Tier 7's identity model has no Kconfig symbol: %v", err)
	}
	if symbol != "CONFIG_COURSE_IDENTITY_FACTORY" {
		t.Errorf("Tier 7 should configure CONFIG_COURSE_IDENTITY_FACTORY, got %s", symbol)
	}
}
