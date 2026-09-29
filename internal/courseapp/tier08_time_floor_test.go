package courseapp

// E-8-11 (#262). The verdict comes from the firmware's own Time floor, built
// for native_sim, so the test that proves the row needs the Zephyr workspace.
// It is TestE811OnNativeSim, and it runs only when COURSE_NATIVE_SIM=1 is set:
//
//	COURSE_NATIVE_SIM=1 ZEPHYR_WORKSPACE=/opt/zephyr-workspace \
//	    go test ./internal/courseapp -run TestE811OnNativeSim -v
//
// The rest run everywhere. They check what the runner generates and how it
// behaves around the build, and none of them decides whether a certificate
// expired: that is the firmware's to decide.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var incByte = regexp.MustCompile(`0x([0-9a-f]{2})`)

// readInc reads back the bytes one generated .inc file holds.
func readInc(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for _, m := range incByte.FindAllStringSubmatch(string(data), -1) {
		b, err := strconv.ParseUint(m[1], 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, byte(b))
	}
	return out
}

// The inputs are what the row says they are: a far-future manifest the
// compiled-in key verifies, the same bytes under a key it does not, and two
// 90-day certificates that the far-future date outlives and the seed does not.
func TestE811InputsAreOneRunsThrowawayMaterial(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	inputs, err := writeTimeFloorInputs(dir, now)
	if err != nil {
		t.Fatal(err)
	}

	point := readInc(t, dir, "release_pubkey.inc")
	if len(point) != 65 || point[0] != 0x04 {
		t.Fatalf("release_pubkey.inc is %d bytes, want an uncompressed P-256 point", len(point))
	}
	far := readInc(t, dir, "far_manifest.inc")
	digest := sha256.Sum256(far)
	if !ecdsa.VerifyASN1(inputs.publicKey, digest[:], readInc(t, dir, "far_manifest_sig.inc")) {
		t.Fatal("the far-future manifest does not verify under the compiled-in key")
	}
	if ecdsa.VerifyASN1(inputs.publicKey, digest[:], readInc(t, dir, "untrusted_manifest_sig.inc")) {
		t.Fatal("the untrusted signature verifies under the compiled-in key")
	}
	ordinary := readInc(t, dir, "ordinary_manifest.inc")
	ordinaryDigest := sha256.Sum256(ordinary)
	if !ecdsa.VerifyASN1(inputs.publicKey, ordinaryDigest[:], readInc(t, dir, "ordinary_manifest_sig.inc")) {
		t.Fatal("the ordinary manifest does not verify under the compiled-in key")
	}

	var manifest releaseManifest
	if err := json.Unmarshal(far, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ReleaseID != timeFloorFarRelease || manifest.CreatedAt != inputs.farDate {
		t.Fatalf("far manifest %+v", manifest)
	}
	if err := json.Unmarshal(ordinary, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.CreatedAt != now.Format(time.RFC3339) {
		t.Fatalf("the ordinary manifest is dated %s, want now", manifest.CreatedAt)
	}

	for _, name := range []string{"operational_cert.inc", "recovered_cert.inc"} {
		cert, err := x509.ParseCertificate(readInc(t, dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !cert.NotAfter.After(now) || cert.NotAfter.Sub(cert.NotBefore) != timeFloorCertificateDays*24*time.Hour {
			t.Fatalf("%s is valid %s to %s", name, cert.NotBefore, cert.NotAfter)
		}
		farDate, _ := time.Parse(time.RFC3339, inputs.farDate)
		if !cert.NotAfter.Before(farDate) {
			t.Fatalf("%s outlives the far-future date", name)
		}
	}
	if inputs.seed != now.Format(time.RFC3339) {
		t.Fatalf("seed %s, want the run's own time", inputs.seed)
	}
	fragment, err := os.ReadFile(filepath.Join(dir, "host.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fragment), `CONFIG_COURSE_TIME_FLOOR_SEED="`+inputs.seed+`"`) {
		t.Fatalf("host.conf does not carry the seed:\n%s", fragment)
	}

	// No private half is written anywhere.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
		if bytes.Contains(data, []byte("PRIVATE KEY")) {
			t.Fatalf("%s holds a private key", entry.Name())
		}
	}

	// Two runs never share a key.
	again, err := writeTimeFloorInputs(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	if again.publicKey.Equal(inputs.publicKey) {
		t.Fatal("two runs generated the same release key")
	}
}

// The dry run needs no service, no marker, no workspace and no board, and it
// says it reaches none of them.
func TestE811DryRunTouchesNothing(t *testing.T) {
	root := testRepository(t)
	t.Setenv("ZEPHYR_WORKSPACE", filepath.Join(root, "no-workspace"))
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--repo", root, "service", "bypass", "e-8-11"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, want := range []string{
		"Target: none. This row opens no socket",
		"Observed on: host",
		"never your Release signing key",
		"Result: dry run only",
		"Execute: ./course service bypass e-8-11 --execute e-8-11",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("dry run lacks %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "Marker matched") {
		t.Fatal("the local row fetched the marker")
	}
	if _, err := os.Stat(filepath.Join(root, "artifacts")); err == nil {
		t.Fatal("the dry run wrote evidence")
	}
}

// Execute takes the exact identifier, and without a Zephyr workspace it says
// what it needs and records a failed run rather than a result.
func TestE811WithoutAWorkspaceSaysWhatItNeeds(t *testing.T) {
	root := testRepository(t)
	t.Setenv("ZEPHYR_WORKSPACE", filepath.Join(root, "no-workspace"))
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--repo", root, "service", "bypass", "e-8-11", "--execute", "e-8-10"}, &stdout, &stderr); code == 0 {
		t.Fatal("a mismatched --execute ran the row")
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--repo", root, "service", "bypass", "e-8-11", "--execute", "e-8-11"}, &stdout, &stderr); code == 0 {
		t.Fatalf("E-8-11 passed with no workspace:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "native_sim") {
		t.Fatalf("the failure does not say what it needs: %s", stderr.String())
	}
	records, _ := filepath.Glob(filepath.Join(root, "artifacts", "generated", "attacks", "tier-08", "e-8-11", "*.json"))
	if len(records) != 1 {
		t.Fatalf("%d evidence records, want 1", len(records))
	}
	data, err := os.ReadFile(records[0])
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record["result"] != "failed" || record["observed_on"] != witnessHost || record["release_signing_key_used"] != false {
		t.Fatalf("evidence %v", record)
	}
}

// The row is a local one, labelled host, and reachable from the listing.
func TestE811IsALocalHostRow(t *testing.T) {
	row, ok := lookupBypassRow("e-8-11")
	if !ok {
		t.Fatal("no E-8-11 row")
	}
	if row.local == nil || row.run != nil || row.forges || row.witness != witnessHost {
		t.Fatalf("E-8-11 %+v", row)
	}
}

// The reader refuses a transcript that lacks any one of the firmware's
// verdict lines. It decides nothing itself; this checks it cannot be
// satisfied by less than the whole demonstration.
func TestE811VerdictNeedsEveryLine(t *testing.T) {
	inputs := timeFloorInputs{
		farDate:   "2046-09-29T12:00:00Z",
		validTo:   "2026-12-28T12:00:00Z",
		recovered: "2026-12-28T12:00:01Z",
	}
	first := strings.Join([]string{
		"host.present operational certificate presented, 382 bytes",
		"release.refused check=manifest-signature",
		"host.present operational certificate presented, 382 bytes",
		"time.floor raised to 2046-09-29T12:00:00Z by the signed created_at of release tier-08-far-future-host",
		"time.floor expired valid_to=2026-12-28T12:00:00Z floor=2046-09-29T12:00:00Z",
		"host.present operational certificate refused err=-EKEYEXPIRED",
	}, "\n")
	second := strings.Join([]string{
		"time.floor 2046-09-29T12:00:00Z, set by release tier-08-far-future-host",
		"time.floor expired valid_to=2026-12-28T12:00:01Z floor=2046-09-29T12:00:00Z",
		"time.floor stays at 2046-09-29T12:00:00Z; release tier-08-ordinary-host was created at 2026-09-29T12:00:00Z, which is not later",
		"host.present operational certificate refused err=-EKEYEXPIRED",
	}, "\n")
	if err := checkTimeFloorVerdict(inputs, first, second); err != nil {
		t.Fatalf("the whole demonstration was refused: %v", err)
	}
	for i, line := range strings.Split(first, "\n") {
		cut := strings.Replace(first, line, "", 1)
		if err := checkTimeFloorVerdict(inputs, cut, second); err == nil {
			t.Errorf("first boot without line %d was accepted", i)
		}
	}
	for i, line := range strings.Split(second, "\n") {
		cut := strings.Replace(second, line, "", 1)
		if err := checkTimeFloorVerdict(inputs, first, cut); err == nil {
			t.Errorf("second boot without line %d was accepted", i)
		}
	}
}

// The row itself, against the firmware's own code. Needs the Zephyr
// workspace; see the top of this file.
func TestE811OnNativeSim(t *testing.T) {
	if os.Getenv("COURSE_NATIVE_SIM") != "1" {
		t.Skip("set COURSE_NATIVE_SIM=1 and ZEPHYR_WORKSPACE to build the Time floor for native_sim")
	}
	root := testRepository(t)
	source, err := filepath.Abs(filepath.Join("..", "..", "firmware"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, filepath.Join(root, "firmware")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--repo", root, "service", "bypass", "e-8-11", "--execute", "e-8-11"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s\n%s", code, stderr.String(), stdout.String())
	}
	t.Log(stdout.String())
}
