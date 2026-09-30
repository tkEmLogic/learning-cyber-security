package courseapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A module is in an image when a source under it was compiled, and a module
// the build could only see is not: that is how the bootloader's west spdx
// output came to list Mbed TLS it never compiles (#266).
func TestCompiledFilesCountsOnlyCompiledSources(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "compile_commands.json")
	if err := os.WriteFile(db, []byte(`[
		{"file": "/ws/zephyr/kernel/sched.c"},
		{"file": "/ws/zephyr/kernel/thread.c"},
		{"file": "/ws/bootloader/mcuboot/ext/tinycrypt/lib/source/ecc.c"},
		{"file": "/ws/zephyrish/not-zephyr.c"}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	counts, err := compiledFiles(db, map[string]string{
		"zephyr":    "/ws/zephyr",
		"mcuboot":   "/ws/bootloader/mcuboot",
		"tinycrypt": "/ws/bootloader/mcuboot/ext/tinycrypt",
		"mbedtls":   "/ws/modules/crypto/mbedtls",
	})
	if err != nil {
		t.Fatal(err)
	}
	if counts["zephyr"] != 2 {
		t.Errorf("zephyr = %d, want 2; a sibling directory with a shared prefix must not count", counts["zephyr"])
	}
	if counts["tinycrypt"] != 1 || counts["mcuboot"] != 1 {
		t.Errorf("tinycrypt = %d, mcuboot = %d; a vendored library counts as itself and inside its vendor", counts["tinycrypt"], counts["mcuboot"])
	}
	if counts["mbedtls"] != 0 {
		t.Errorf("mbedtls = %d; nothing under it was compiled", counts["mbedtls"])
	}
}

// Only the Espressif libraries module.yml lists for this SoC count as linked
// blobs, each with its recorded hash and the commit it was fetched from.
func TestLinkedBlobsReadsModuleYML(t *testing.T) {
	dir := t.TempDir()
	ninja := filepath.Join(dir, "build.ninja")
	module := filepath.Join(dir, "module.yml")
	if err := os.WriteFile(ninja, []byte("LINK_FLAGS = -L/ws/modules/hal/espressif/zephyr/blobs/lib/esp32c6 -lnet80211 -lgcc -lpp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, []byte(`blobs:
  - path: lib/esp32c6/libnet80211.a
    sha256: aaaa
    url: https://github.com/espressif/esp32-wifi-lib/raw/b9bc45aa8e98d53f8999f220a92286d9a57d4c1b/esp32c6/libnet80211.a
  - path: lib/esp32c6/libpp.a
    sha256: bbbb
    url: https://github.com/espressif/esp32-wifi-lib/raw/b9bc45aa8e98d53f8999f220a92286d9a57d4c1b/esp32c6/libpp.a
  - path: lib/esp32/libpp.a
    sha256: cccc
    url: https://github.com/espressif/esp32-wifi-lib/raw/b9bc45aa8e98d53f8999f220a92286d9a57d4c1b/esp32/libpp.a
`), 0o600); err != nil {
		t.Fatal(err)
	}
	blobs, err := linkedBlobs(ninja, module, "esp32c6")
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 2 || blobs[0].SHA256 != "aaaa" || blobs[1].SHA256 != "bbbb" {
		t.Fatalf("blobs = %+v, want net80211 and pp for esp32c6 only", blobs)
	}
	component := blobComponent(blobs[0])
	if component.Version != "b9bc45aa8e98d53f8999f220a92286d9a57d4c1b" ||
		component.PURL != "pkg:github/espressif/esp32-wifi-lib@b9bc45aa8e98d53f8999f220a92286d9a57d4c1b#esp32c6/libnet80211.a" {
		t.Errorf("blob component = version %q purl %q", component.Version, component.PURL)
	}
	if component.CPE != "" {
		t.Error("a closed-source blob has no CPE, and the SBOM must not invent one")
	}
}

func TestVersionReaders(t *testing.T) {
	dir := t.TempDir()
	version := filepath.Join(dir, "VERSION")
	_ = os.WriteFile(version, []byte("VERSION_MAJOR = 4\nVERSION_MINOR = 4\nPATCHLEVEL = 2\nVERSION_TWEAK = 0\n"), 0o600)
	if got, err := versionFromZephyrFile(version); err != nil || got != "4.4.2" {
		t.Errorf("versionFromZephyrFile = %q, %v", got, err)
	}
	header := filepath.Join(dir, "build_info.h")
	_ = os.WriteFile(header, []byte("#define TF_PSA_CRYPTO_VERSION_STRING         \"1.1.0\"\n"), 0o600)
	if got, err := versionFromDefine(header, "TF_PSA_CRYPTO_VERSION_STRING"); err != nil || got != "1.1.0" {
		t.Errorf("versionFromDefine = %q, %v", got, err)
	}
}

// The serial is derived from what is described, so describing the same image
// twice gives the same serial, and a different image a different one.
func TestBOMSerialIsStableAndVersionFive(t *testing.T) {
	a, b, c := bomSerial("x"), bomSerial("x"), bomSerial("y")
	if a != b || a == c {
		t.Errorf("serials %s %s %s", a, b, c)
	}
	if !strings.HasPrefix(a, "urn:uuid:") || a[9+14] != '5' {
		t.Errorf("serial %s is not a version-5-shaped UUID URN", a)
	}
}

// Approval refuses locally, and sends nothing, when a link is missing or no
// approver is named.
func TestReleaseApproveRefusesLocally(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.release([]string{"approve", "--tier", "09", "--variant", "support-listener"}); err == nil ||
		!strings.Contains(err.Error(), "--approver") {
		t.Errorf("approve without an approver = %v", err)
	}
	if err := a.release([]string{"approve", "--tier", "09", "--variant", "support-listener", "--approver", "x"}); err == nil ||
		!strings.Contains(err.Error(), "refused locally") {
		t.Errorf("approve with nothing signed = %v", err)
	}
	if err := a.release([]string{"approve", "--tier", "08", "--variant", "baseline", "--approver", "x"}); err == nil ||
		!strings.Contains(err.Error(), "Tier 9") {
		t.Errorf("approve outside Tier 9 = %v", err)
	}
}
