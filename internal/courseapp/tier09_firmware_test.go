package courseapp

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tier 9 builds its own application, and the files the tier added are in it.
func TestTierNineBuildsItsOwnApplication(t *testing.T) {
	dir, ok := firmwareApps[tier09]
	if !ok {
		t.Fatal("Tier 9 has no firmware application")
	}
	if dir == firmwareApps[tier08] {
		t.Fatal("Tier 9 must not share Tier 8's application directory")
	}
	for _, name := range []string{
		"CMakeLists.txt", "Kconfig", "prj.conf", "sysbuild.conf",
		"src/support_listener.c", "src/support_listener.h",
		"src/time_floor.c", "src/renewal.c",
		"patches.yml", "patches/tf-psa-crypto/cve-2026-50583.patch",
	} {
		if _, err := os.Stat(filepath.Join("..", "..", dir, name)); err != nil {
			t.Errorf("%s is missing from the Tier 9 application: %v", name, err)
		}
	}
}

// The remediation is one counter above the release it replaces, and both are
// above Tier 8, so the ordinary release path is what leaves the vulnerable
// version behind (section 7).
func TestTierNineCountersClimb(t *testing.T) {
	if !tierSignsItsOwnImage(tier09) {
		t.Fatal("Tier 9 must build its bootloader separately and sign afterwards")
	}
	listener := tier09Variants["support-listener"]
	remediation := tier09Variants["remediation"]
	if listener.securityCounter <= tier08SecurityCounter {
		t.Errorf("support-listener counter %d must be above Tier 8's %d", listener.securityCounter, tier08SecurityCounter)
	}
	if remediation.securityCounter != listener.securityCounter+1 {
		t.Errorf("remediation counter %d must be one above %d", remediation.securityCounter, listener.securityCounter)
	}
	if listener.releaseID == remediation.releaseID {
		t.Error("the two releases must have different ids, or a device refuses the second as already-confirmed")
	}
	for label := range tier09Variants {
		if tier09Versions[label] == "" {
			t.Errorf("variant %s has no imgtool version", label)
		}
	}
}

// Only the support-listener release compiles in the listener, and only the
// remediation carries the patch. Neither may carry both, and the generated
// configuration spells both lines for both, so a stale value cannot leak.
func TestTierNineVariantsDifferInListenerAndPatch(t *testing.T) {
	listener := tier09Variants["support-listener"]
	remediation := tier09Variants["remediation"]
	if !listener.supportListener || listener.westPatches {
		t.Errorf("support-listener = listener %v, patch %v; want true, false", listener.supportListener, listener.westPatches)
	}
	if remediation.supportListener || !remediation.westPatches {
		t.Errorf("remediation = listener %v, patch %v; want false, true", remediation.supportListener, remediation.westPatches)
	}
	if listener.imageName == remediation.imageName {
		t.Error("the two releases must not share an image name")
	}
}

// The patch list names the patch file by the digest the file actually has,
// so a changed patch is refused by west patch rather than applied.
func TestTierNinePatchListMatchesThePatch(t *testing.T) {
	root := filepath.Join("..", "..", firmwareApps[tier09])
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

func TestTierNineFirmwareCommandsReachTierNine(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.release([]string{"sign", "--tier", "09", "--variant", "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown Tier 9 release") {
		t.Errorf("release sign --tier 09 with a bad variant = %v", err)
	}
	if err := a.release([]string{"assign", "--tier", "9", "--variant", "remediation"}); err == nil ||
		!strings.Contains(err.Error(), "--tier 09 --variant remediation") {
		t.Errorf("release assign --tier 9 before signing = %v", err)
	}
	if err := a.buildFirmware([]string{"--tier", "09", "--variant", "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown firmware variant") {
		t.Errorf("build firmware --tier 09 with a bad variant = %v", err)
	}
	if err := a.deviceFlash([]string{"--tier", "09", "--variant", "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown firmware variant") {
		t.Errorf("device flash --tier 09 with a bad variant = %v", err)
	}
}
