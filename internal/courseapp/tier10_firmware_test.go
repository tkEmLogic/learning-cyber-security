package courseapp

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tier 10 builds its own application, Tier 9's remediation behaviour as a
// committed tree, with the handover material beside it.
func TestTierTenBuildsItsOwnApplication(t *testing.T) {
	dir, ok := firmwareApps[tier10]
	if !ok {
		t.Fatal("Tier 10 has no firmware application")
	}
	if dir == firmwareApps[tier09] {
		t.Fatal("Tier 10 must not share Tier 9's application directory")
	}
	for _, name := range []string{
		"CMakeLists.txt", "Kconfig", "prj.conf", "sysbuild.conf",
		"src/main.c", "src/health_gate.c",
		"patches.yml", "patches/tf-psa-crypto/cve-2026-50583.patch",
		"handover/teammate-candidate.patch",
	} {
		if _, err := os.Stat(filepath.Join("..", "..", dir, name)); err != nil {
			t.Errorf("%s is missing from the Tier 10 application: %v", name, err)
		}
	}
}

// The corrected tree carries the remediation behaviour: the support listener is
// compiled out and the TF-PSA-Crypto backport is on. Neither defect is in the
// committed source; both live only in the handover patch.
func TestTierTenCorrectedTreeHasNoDefect(t *testing.T) {
	root := filepath.Join("..", "..", firmwareApps[tier10])
	prj, err := os.ReadFile(filepath.Join(root, "prj.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(prj), "CONFIG_COURSE_SUPPORT_LISTENER=y") {
		t.Error("the corrected tree must not enable the support listener; that is the handover patch's defect")
	}
	if !strings.Contains(string(prj), "CONFIG_COURSE_TF_PSA_CRYPTO_BACKPORT=y") {
		t.Error("both Tier 10 variants carry the backport, so the corrected tree sets it")
	}
	main, err := os.ReadFile(filepath.Join(root, "src", "main.c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), "#define BEACON_PERIOD_SECONDS 1\n") {
		t.Error("the corrected tree's beacon period must be the healthy one; the long period is the handover patch's defect")
	}
	// The corrected tree brings networking up after the health gate, so network
	// loss cannot fail the gate (section 6). The handover patch is what moves it
	// before the gate.
	gate := strings.Index(string(main), "confirm_or_revert();")
	net := strings.Index(string(main), "bring_up_network_and_listener(address")
	if gate < 0 || net < 0 || net < gate {
		t.Error("the corrected tree must bring networking up after the health gate")
	}
}

// The handover patch carries exactly the two settled defects, in separate
// hunks, and never a built-in fault arm or a line that says the fault is
// deliberate (symptoms only, #287).
func TestTierTenHandoverPatchHasTheTwoDefects(t *testing.T) {
	patch, err := os.ReadFile(filepath.Join("..", "..", firmwareApps[tier10], "handover", "teammate-candidate.patch"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(patch)
	if !strings.Contains(body, "+CONFIG_COURSE_SUPPORT_LISTENER=y") {
		t.Error("the handover patch must bring the support listener back")
	}
	if !strings.Contains(body, "+#define BEACON_PERIOD_SECONDS 90") {
		t.Error("the handover patch must lengthen the beacon period past the health window")
	}
	if !strings.Contains(body, "+\tonline = bring_up_network_and_listener(address, sizeof(address));") {
		t.Error("the handover patch must start networking and the listener before the gate")
	}
	for _, forbidden := range []string{"TRIAL_TIMEOUT_HEALTH", "TRIAL_FAIL_HEALTH", "deliberately"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the handover patch must be symptoms-only, but mentions %q", forbidden)
		}
	}
	// Two defects, separate hunks: the patch spans two files and at least three
	// hunks (prj.conf enable, main.c beacon, main.c reorder).
	if hunks := strings.Count(body, "\n@@ "); hunks < 3 {
		t.Errorf("expected the two defects in separate hunks, found %d hunks", hunks)
	}
}

// The counters climb: the candidate at 7 above Tier 9's 6, and the corrected at
// 8 one above the candidate, so the corrected release leaves the candidate
// behind on the ordinary release path (#287).
func TestTierTenCountersClimb(t *testing.T) {
	if !tierSignsItsOwnImage(tier10) {
		t.Fatal("Tier 10 must build its bootloader separately and sign afterwards")
	}
	candidate := tier10Variants["candidate"]
	corrected := tier10Variants["corrected"]
	if candidate.securityCounter != 7 {
		t.Errorf("candidate counter %d, want 7", candidate.securityCounter)
	}
	if corrected.securityCounter != candidate.securityCounter+1 {
		t.Errorf("corrected counter %d must be one above the candidate's %d", corrected.securityCounter, candidate.securityCounter)
	}
	if candidate.releaseID == corrected.releaseID {
		t.Error("the two releases must have different ids, or a device refuses the second as already-confirmed")
	}
	for label := range tier10Variants {
		if tier10Versions[label] == "" {
			t.Errorf("variant %s has no imgtool version", label)
		}
	}
}

// Only the candidate carries the handover patch, and both variants carry the
// backport. The candidate is the lower counter, so the corrected one wins.
func TestTierTenVariantFlags(t *testing.T) {
	candidate := tier10Variants["candidate"]
	corrected := tier10Variants["corrected"]
	if !candidate.handoverPatch || !candidate.westPatches {
		t.Errorf("candidate = handover %v, patch %v; want true, true", candidate.handoverPatch, candidate.westPatches)
	}
	if corrected.handoverPatch || !corrected.westPatches {
		t.Errorf("corrected = handover %v, patch %v; want false, true", corrected.handoverPatch, corrected.westPatches)
	}
	if candidate.imageName == corrected.imageName {
		t.Error("the two releases must not share an image name")
	}
	if candidate.securityCounter >= corrected.securityCounter {
		t.Error("the candidate must sit below the corrected release")
	}
}

// The patch list names the backport by the digest the file actually has, so a
// changed patch is refused by west patch rather than applied.
func TestTierTenPatchListMatchesThePatch(t *testing.T) {
	root := filepath.Join("..", "..", firmwareApps[tier10])
	list, err := os.ReadFile(filepath.Join(root, "patches.yml"))
	if err != nil {
		t.Fatal(err)
	}
	patch, err := os.ReadFile(filepath.Join(root, "patches", "tf-psa-crypto", "cve-2026-50583.patch"))
	if err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(patch))
	if !strings.Contains(string(list), "sha256sum: "+sum) {
		t.Errorf("patches.yml does not name the patch's sha256 %s", sum)
	}
	if !strings.Contains(string(list), "module: "+tier09PatchedModule) {
		t.Errorf("patches.yml does not target %s", tier09PatchedModule)
	}
}

func TestTierTenFirmwareCommandsReachTierTen(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.release([]string{"sign", "--tier", "10", "--variant", "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown Tier 10 release") {
		t.Errorf("release sign --tier 10 with a bad variant = %v", err)
	}
	if err := a.release([]string{"assign", "--tier", "10", "--variant", "corrected"}); err == nil ||
		!strings.Contains(err.Error(), "--tier 10 --variant corrected") {
		t.Errorf("release assign --tier 10 before signing = %v", err)
	}
	if err := a.release([]string{"test", "--tier", "10", "--variant", "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown Tier 10 release") {
		t.Errorf("release test --tier 10 with a bad variant = %v", err)
	}
	if err := a.release([]string{"approve", "--tier", "10", "--variant", "nope", "--approver", "teammate"}); err == nil ||
		!strings.Contains(err.Error(), "unknown Tier 10 release") {
		t.Errorf("release approve --tier 10 with a bad variant = %v", err)
	}
	if err := a.buildFirmware([]string{"--tier", "10", "--variant", "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown firmware variant") {
		t.Errorf("build firmware --tier 10 with a bad variant = %v", err)
	}
	if err := a.deviceFlash([]string{"--tier", "10", "--variant", "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown firmware variant") {
		t.Errorf("device flash --tier 10 with a bad variant = %v", err)
	}
}

// rollout start accepts Tier 10's variants, which #288 found it did not.
func TestTierTenRolloutStartAcceptsTierTen(t *testing.T) {
	a, _ := provisioningApp(t)
	// An unknown Tier 10 variant is rejected by name, which proves the tier is
	// routed to tier10Variant rather than refused as not-Tier-9.
	err := a.rollout([]string{"start", "--tier", "10", "--variant", "nope", "--canary", "beacon-01", "--actor", "teammate"})
	if err == nil || !strings.Contains(err.Error(), "unknown Tier 10 release") {
		t.Errorf("rollout start --tier 10 with a bad variant = %v", err)
	}
	// A good variant gets past option parsing and variant lookup, and fails only
	// when it cannot find a signed manifest (no build in this unit test).
	err = a.rollout([]string{"start", "--tier", "10", "--variant", "candidate", "--canary", "beacon-01", "--actor", "teammate"})
	if err == nil || !strings.Contains(err.Error(), "no signed candidate release") {
		t.Errorf("rollout start --tier 10 --variant candidate before signing = %v", err)
	}
}
