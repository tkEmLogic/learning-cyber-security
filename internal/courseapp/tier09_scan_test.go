package courseapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// The real scanners never run here: their results depend on multi-gigabyte
// databases and belong in a manual check. These tests cover what the course
// itself decides: the pins, the refusals, the paths and the SBOM's shape.

// testScanApp is a repository with the real course.yml and the committed Go
// vulnerability database, and a user cache in a temporary directory.
func testScanApp(t *testing.T) (*app, *bytes.Buffer) {
	t.Helper()
	root := testRepository(t)
	s := loadScanning(t, "../..")
	source := filepath.Join("..", "..", s.Govulncheck.Database.Path)
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, s.Govulncheck.Database.Path)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	var out bytes.Buffer
	a, err := load(root, &out, &out)
	if err != nil {
		t.Fatal(err)
	}
	return a, &out
}

func loadScanning(t *testing.T, root string) scanningManifest {
	t.Helper()
	a, err := load(root, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.scanning()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The pins are the ones the research checked, and the Go database committed
// to the repository is the one course.yml pins.
func TestScanningPinsMatchTheResearch(t *testing.T) {
	s := loadScanning(t, "../..")
	if s.Grype.Version != "v0.119.0" || s.Govulncheck.Version != "v1.8.0" {
		t.Errorf("scanner pins are grype %s and govulncheck %s", s.Grype.Version, s.Govulncheck.Version)
	}
	if s.GoToolchain != "go1.24.0" {
		t.Errorf("the service must be scanned as it shipped, with go1.24.0, not %s", s.GoToolchain)
	}
	if !strings.HasSuffix(s.Grype.Database.URL, "/"+s.Grype.Database.Name) {
		t.Errorf("the grype URL %s does not name the pinned archive %s", s.Grype.Database.URL, s.Grype.Database.Name)
	}
	if err := verifyPinnedFile(filepath.Join("..", "..", s.Govulncheck.Database.Path), s.Govulncheck.Database); err != nil {
		t.Errorf("the committed Go vulnerability database does not match its pin: %v", err)
	}
}

// go.mod has no toolchain line. Adding one is the Learner's Tier 9 fix, and
// a toolchain line already there would take away the finding (#272).
func TestGoModHasNoToolchainLine(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "toolchain") {
			t.Fatalf("go.mod has %q; the toolchain line is the Learner's fix, not the starting point", line)
		}
	}
}

func TestVerifyPinnedFileRefusesSizeAndChecksum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive")
	content := []byte("pinned bytes")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	good := pinnedFile{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(content))}
	if err := verifyPinnedFile(path, good); err != nil {
		t.Fatalf("the right file was refused: %v", err)
	}
	wrongSize := good
	wrongSize.Size++
	if err := verifyPinnedFile(path, wrongSize); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Errorf("a file of the wrong size was accepted: %v", err)
	}
	wrongSum := good
	wrongSum.SHA256 = strings.Repeat("0", 64)
	if err := verifyPinnedFile(path, wrongSum); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Errorf("a file with the wrong checksum was accepted: %v", err)
	}
}

// A corrupt archive is refused before import. The test puts no grype on
// PATH, so reaching the import step would fail with a different message.
func TestScanSetupRefusesACorruptArchiveBeforeImport(t *testing.T) {
	a, out := testScanApp(t)
	t.Setenv("PATH", t.TempDir())
	// The pinned size is shrunk in this copy of course.yml, so the test need
	// not write 182 MB. The archive then has the right size and the wrong
	// bytes, and only the checksum can catch it.
	manifest := filepath.Join(a.root, "course.yml")
	data, _ := os.ReadFile(manifest)
	shrunk := strings.Replace(string(data), "size: 182413359", "size: 16", 1)
	if shrunk == string(data) {
		t.Fatal("the grype archive size pin was not found in course.yml")
	}
	if err := os.WriteFile(manifest, []byte(shrunk), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := a.scanning()
	corrupt := filepath.Join(t.TempDir(), s.Grype.Database.Name)
	if err := os.WriteFile(corrupt, make([]byte, s.Grype.Database.Size), 0o600); err != nil {
		t.Fatal(err)
	}
	err := a.scanSetup([]string{"--archive", corrupt})
	if err == nil || !strings.Contains(err.Error(), "not imported") || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("a corrupt archive was not refused on its checksum: %v", err)
	}
	if strings.Contains(out.String(), "grype db import") {
		t.Fatal("grype db import was reached with a corrupt archive")
	}
	cache, _ := a.scanCacheDir(s)
	if _, err := os.Stat(filepath.Join(cache, pinnedGrypeDir)); !os.IsNotExist(err) {
		t.Fatalf("the pinned database directory exists after a refused archive: %v", err)
	}
	// The Go database was verified and unpacked before the refusal.
	if _, ok := readImportRecord(filepath.Join(cache, goVulnDBDir)); !ok {
		t.Fatal("the Go vulnerability database was not unpacked")
	}
	if _, err := os.Stat(filepath.Join(cache, goVulnDBDir, "index", "db.json")); err != nil {
		t.Fatalf("the unpacked Go database has no index: %v", err)
	}
}

// A committed Go database that a Learner has edited is refused on use.
func TestEditedGoDatabaseIsRefused(t *testing.T) {
	a, _ := testScanApp(t)
	s, _ := a.scanning()
	path := filepath.Join(a.root, s.Govulncheck.Database.Path)
	data, _ := os.ReadFile(path)
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cache, _ := a.scanCacheDir(s)
	if _, err := a.ensureGoVulnDB(s, cache); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("an edited Go database was accepted: %v", err)
	}
}

// Scanning refuses to run on a database that setup did not import, so no scan
// can silently fall back to whatever grype finds in its default cache.
func TestPinnedScanRefusesWithoutImport(t *testing.T) {
	a, _ := testScanApp(t)
	s, _ := a.scanning()
	if _, err := a.pinnedGrypeDB(s); err == nil || !strings.Contains(err.Error(), "scan setup") {
		t.Fatalf("a missing import was not refused: %v", err)
	}
	cache, _ := a.scanCacheDir(s)
	dir := filepath.Join(cache, pinnedGrypeDir)
	if err := writeJSON(filepath.Join(dir, importStamp), importRecord{"older.tar.zst", strings.Repeat("a", 64), time.Now()}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.pinnedGrypeDB(s); err == nil {
		t.Fatal("a different imported snapshot was accepted as the pinned one")
	}
}

func TestScannerEnvironmentIsOffline(t *testing.T) {
	env := strings.Join(scannerEnv("/cache/grype-db"), " ")
	for _, want := range []string{"GRYPE_DB_CACHE_DIR=/cache/grype-db", "GRYPE_DB_AUTO_UPDATE=false",
		"GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_DB_VALIDATE_AGE=false"} {
		if !strings.Contains(env, want) {
			t.Errorf("the pinned grype environment lacks %s", want)
		}
	}
	if strings.Contains(strings.Join(liveScannerEnv("/cache/live"), " "), "grype-db ") {
		t.Error("the live environment must use its own cache directory")
	}
}

func TestParseScanFirmwareArgs(t *testing.T) {
	good := [][]string{
		{"--sbom", "x.cdx.json"},
		{"--sbom", "x.cdx.json", "--vex", "v.json", "--live"},
		{"--tier", "09", "--variant", "remediation"},
		{"--tier", "9", "--variant", "support-listener"},
	}
	for _, args := range good {
		if _, err := parseScanFirmwareArgs(args); err != nil {
			t.Errorf("%v was refused: %v", args, err)
		}
	}
	bad := [][]string{
		{},
		{"--sbom"},
		{"--sbom", "x", "--tier", "09", "--variant", "remediation"},
		{"--tier", "09"},
		{"--variant", "remediation"},
		{"--tier", "08", "--variant", "remediation"},
		{"--sbom", "x", "--unknown", "y"},
	}
	for _, args := range bad {
		if _, err := parseScanFirmwareArgs(args); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	options, _ := parseScanFirmwareArgs([]string{"--tier", "tier-9", "--variant", "remediation"})
	if options.tier != tier09 {
		t.Errorf("tier-9 normalized to %q", options.tier)
	}
}

func TestParseScanSetupAndServiceArgs(t *testing.T) {
	if archive, err := parseScanSetupArgs([]string{"--archive", "db.tar.zst"}); err != nil || archive != "db.tar.zst" {
		t.Errorf("--archive gave %q, %v", archive, err)
	}
	for _, args := range [][]string{{"--archive"}, {"--url", "x"}} {
		if _, err := parseScanSetupArgs(args); err == nil {
			t.Errorf("setup %v was accepted", args)
		}
	}
	if live, err := parseScanServiceArgs([]string{"--live"}); err != nil || !live {
		t.Errorf("--live gave %v, %v", live, err)
	}
	if _, err := parseScanServiceArgs([]string{"--vex"}); err == nil {
		t.Error("an unknown service option was accepted")
	}
	a, _ := testScanApp(t)
	if err := a.scan([]string{"everything"}); err == nil {
		t.Error("an unknown scan command was accepted")
	}
}

// A Tier 9 release resolves to the SBOM name the OTA service's approval check
// looks for, and results sit beside the SBOM under a name that cannot
// collide with it, pinned or live.
func TestScanPathResolution(t *testing.T) {
	a, _ := testScanApp(t)
	for variant, id := range map[string]string{"support-listener": "tier-09-support-listener", "remediation": "tier-09-remediation"} {
		path, err := a.firmwareSBOMPath(variant)
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(a.root, "artifacts", "generated", "releases", id+".firmware.cdx.json")
		if path != want {
			t.Errorf("%s resolved to %s, want %s", variant, path, want)
		}
	}
	if _, err := a.firmwareSBOMPath("baseline"); err == nil {
		t.Error("a release Tier 9 does not build was resolved")
	}
	cases := map[string]string{
		"/r/tier-09-remediation.firmware.cdx.json": "/r/tier-09-remediation.firmware.grype.json",
		"/r/ota-service.cdx.json":                  "/r/ota-service.grype.json",
		"/r/plain.json":                            "/r/plain.grype.json",
	}
	for sbom, want := range cases {
		if got := scanResultPath(sbom, "grype", false); got != want {
			t.Errorf("result for %s is %s, want %s", sbom, got, want)
		}
	}
	if got := scanResultPath("/r/ota-service.cdx.json", "grype", true); got != "/r/ota-service.grype-live.json" {
		t.Errorf("live result is %s", got)
	}
}

func TestSummarizeGovulncheckCountsEachLevelOnce(t *testing.T) {
	stream := `{"config":{"go_version":"go1.24.0","db_last_modified":"2026-09-28T16:43:40Z"}}
{"finding":{"osv":"GO-A","trace":[{"module":"stdlib","package":"net/http"}]}}
{"finding":{"osv":"GO-A","trace":[{"module":"stdlib","package":"net/http","function":"Get"},{"function":"main"}]}}
{"finding":{"osv":"GO-B","trace":[{"module":"stdlib","package":"crypto/x509"}]}}
{"finding":{"osv":"GO-C","trace":[{"module":"stdlib"}]}}
{"osv":{"id":"GO-A"}}
`
	summary, err := summarizeGovulncheck([]byte(stream))
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Reachable) != 1 || summary.Reachable[0] != "GO-A" || summary.Imported != 1 || summary.Required != 1 {
		t.Errorf("summary is %+v", summary)
	}
	if summary.GoVersion != "go1.24.0" || summary.DBLastModified != "2026-09-28T16:43:40Z" {
		t.Errorf("config not read: %+v", summary)
	}
	if _, err := summarizeGovulncheck([]byte("{not json")); err == nil {
		t.Error("broken govulncheck output was accepted")
	}
}

func testBuildInfo() *debug.BuildInfo {
	return &debug.BuildInfo{
		GoVersion: "go1.24.0",
		Path:      "github.com/tkEmLogic/learning-cyber-security/services/ota/cmd/ota",
		Main:      debug.Module{Path: "github.com/tkEmLogic/learning-cyber-security", Version: "v0.0.0-20261001000000-0123456789ab+dirty"},
		Deps: []*debug.Module{
			{Path: "gopkg.in/yaml.v3", Version: "v3.0.1", Sum: "h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA="},
		},
		Settings: []debug.BuildSetting{
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			{Key: "vcs.modified", Value: "true"},
			{Key: "GOOS", Value: "linux"},
		},
	}
}

// The SBOM is valid CycloneDX 1.6 JSON with the standard library spelled the
// way grype matches it, a bom-ref on every component, and both hashes of the
// binary.
func TestServiceBOMShape(t *testing.T) {
	hashes := []cdxHash{{"SHA-256", strings.Repeat("a", 64)}, {"SHA-512", strings.Repeat("b", 128)}}
	bom, err := serviceBOM(testBuildInfo(), hashes, "1.0", "urn:uuid:test", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("the SBOM is not valid JSON: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.6" {
		t.Fatalf("format %v, spec %v", doc["bomFormat"], doc["specVersion"])
	}
	metadata := doc["metadata"].(map[string]any)
	if metadata["timestamp"] != "2026-10-01T00:00:00Z" {
		t.Errorf("timestamp %v", metadata["timestamp"])
	}
	tools := metadata["tools"].(map[string]any)["components"].([]any)
	if tools[0].(map[string]any)["name"] != "course" {
		t.Errorf("the tool is %v, not the course", tools[0])
	}

	main := bom.Metadata.Component
	if main.PURL != "pkg:golang/github.com/tkEmLogic/learning-cyber-security@v0.0.0-20261001000000-0123456789ab%2Bdirty#services/ota/cmd/ota" {
		t.Errorf("main purl %s", main.PURL)
	}
	if len(main.Hashes) != 2 || main.Hashes[0].Alg != "SHA-256" || main.Hashes[1].Alg != "SHA-512" {
		t.Errorf("main hashes %+v", main.Hashes)
	}
	properties := map[string]string{}
	for _, p := range main.Properties {
		properties[p.Name] = p.Value
	}
	if properties["go:build:vcs.revision"] != "0123456789abcdef0123456789abcdef01234567" || properties["go:build:vcs.modified"] != "true" {
		t.Errorf("vcs properties %v", properties)
	}

	if len(bom.Components) != 2 {
		t.Fatalf("components %+v", bom.Components)
	}
	stdlib := bom.Components[0]
	if stdlib.PURL != "pkg:golang/stdlib@1.24.0" || stdlib.Version != "1.24.0" {
		t.Errorf("stdlib is %s version %s; grype matches pkg:golang/stdlib@1.24.0", stdlib.PURL, stdlib.Version)
	}
	if stdlib.CPE != "cpe:2.3:a:golang:go:1.24.0:*:*:*:*:*:*:*" {
		t.Errorf("stdlib cpe %s", stdlib.CPE)
	}
	yaml := bom.Components[1]
	if yaml.PURL != "pkg:golang/gopkg.in/yaml.v3@v3.0.1" || len(yaml.Hashes) != 0 {
		t.Errorf("dependency %+v; the h1: sum is not a file hash and must not be presented as one", yaml)
	}

	refs := map[string]bool{main.BOMRef: true}
	for _, c := range append(bom.Components, bom.Metadata.Tools.Components...) {
		if c.BOMRef == "" {
			t.Errorf("%s has no bom-ref", c.Name)
		}
		if refs[c.BOMRef] {
			t.Errorf("bom-ref %s is not unique", c.BOMRef)
		}
		refs[c.BOMRef] = true
	}
	if bom.Dependencies[0].Ref != main.BOMRef || len(bom.Dependencies[0].DependsOn) != 2 {
		t.Errorf("dependencies %+v", bom.Dependencies)
	}
}

func TestServiceBOMRefusesABinaryWithoutBuildInformation(t *testing.T) {
	if _, err := serviceBOM(&debug.BuildInfo{}, nil, "1.0", "urn:uuid:x", time.Now()); err == nil {
		t.Error("an empty build information was turned into an SBOM")
	}
}

// A binary stamped with another clone's revision is refused; one with no
// revision at all is not.
func TestCheckBuildRevision(t *testing.T) {
	info := testBuildInfo()
	if err := checkBuildRevision(info, "0123456789abcdef0123456789abcdef01234567"); err != nil {
		t.Errorf("the matching revision was refused: %v", err)
	}
	if err := checkBuildRevision(info, "fedcba9876543210fedcba9876543210fedcba98"); err == nil {
		t.Error("a binary from another revision was accepted")
	}
	if err := checkBuildRevision(&debug.BuildInfo{}, "fedcba9876543210fedcba9876543210fedcba98"); err != nil {
		t.Errorf("a binary with no revision was refused: %v", err)
	}
}

func TestSBOMServiceTakesNoOptions(t *testing.T) {
	a, _ := testScanApp(t)
	if err := a.sbomService([]string{"--output", "x"}); err == nil {
		t.Error("an option was accepted")
	}
}

// A toolchain line in go.mod is what ships, so it overrides the pin; with no
// line the pin reproduces the service as it shipped.
func TestGoModToolchainOverridesThePin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	_ = os.WriteFile(path, []byte("module x\n\ngo 1.24\n"), 0o600)
	if got := goModToolchain(path); got != "" {
		t.Errorf("no toolchain line = %q, want empty", got)
	}
	_ = os.WriteFile(path, []byte("module x\n\ngo 1.24\n\ntoolchain go1.26.8\n"), 0o600)
	if got := goModToolchain(path); got != "go1.26.8" {
		t.Errorf("toolchain line = %q, want go1.26.8", got)
	}
}
