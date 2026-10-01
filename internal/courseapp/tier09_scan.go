package courseapp

// The scanning half of Tier 9 (#277): `./course scan setup|firmware|service`.
//
// Every scan runs offline against a database pinned in course.yml, so every
// Learner sees the same matches whatever day they scan. A match list is only
// true as of its database date, and the Learner's triage is graded against the
// pinned list. `--live` runs the same scan against today's database for the
// optional comparison in #272, and says clearly that it is not the pinned
// result.
//
// grype scans SBOMs, the firmware's and the service's. govulncheck scans the
// service's source, because only govulncheck can tell a reachable Go
// vulnerability from one that is merely linked in.

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// scanningManifest is the `scanning:` block of course.yml.
type scanningManifest struct {
	Cache       string `yaml:"cache"`
	GoToolchain string `yaml:"go_toolchain"`
	Grype       struct {
		Version  string     `yaml:"version"`
		Database pinnedFile `yaml:"database"`
	} `yaml:"grype"`
	Govulncheck struct {
		Version  string     `yaml:"version"`
		Database pinnedFile `yaml:"database"`
	} `yaml:"govulncheck"`
}

// pinnedFile is one downloaded input the course trusts only by its checksum.
// Name is the grype archive's file name; Path is where a committed file lives
// in the repository. A pin has one or the other.
type pinnedFile struct {
	Name     string `yaml:"name"`
	Path     string `yaml:"path"`
	URL      string `yaml:"url"`
	SHA256   string `yaml:"sha256"`
	Size     int64  `yaml:"size"`
	Built    string `yaml:"built"`
	Modified string `yaml:"modified"`
}

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// scanning reads the `scanning:` block. It reads course.yml again rather than
// adding a field to the shared manifest type, so the scanning pins stay in
// this file and the rest of the course never depends on them.
func (a *app) scanning() (scanningManifest, error) {
	data, err := os.ReadFile(filepath.Join(a.root, "course.yml"))
	if err != nil {
		return scanningManifest{}, err
	}
	var document struct {
		Scanning scanningManifest `yaml:"scanning"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return scanningManifest{}, fmt.Errorf("course.yml: %w", err)
	}
	s := document.Scanning
	if s.Cache == "" || filepath.IsAbs(s.Cache) || strings.Contains(s.Cache, "..") {
		return s, errors.New("course.yml scanning.cache must be a relative directory under the user cache")
	}
	if !strings.HasPrefix(s.GoToolchain, "go1.") {
		return s, errors.New("course.yml scanning.go_toolchain must name a Go release, such as go1.24.0")
	}
	// The pin reproduces the service as it shipped, on any machine, while
	// go.mod names no toolchain. Once go.mod does, that toolchain is what
	// ships, so it is what the SBOM and the scans describe. That is how the
	// Learner's Tier 9 fix, a toolchain line, shows up as fixed.
	if toolchain := goModToolchain(filepath.Join(a.root, "go.mod")); toolchain != "" {
		s.GoToolchain = toolchain
	}
	if s.Grype.Version == "" || s.Govulncheck.Version == "" {
		return s, errors.New("course.yml must pin the grype and govulncheck versions")
	}
	for label, pin := range map[string]pinnedFile{"grype": s.Grype.Database, "govulncheck": s.Govulncheck.Database} {
		if !sha256Pattern.MatchString(pin.SHA256) || pin.Size <= 0 || pin.URL == "" {
			return s, fmt.Errorf("course.yml scanning.%s.database needs a url, a lower-case sha256 and a size", label)
		}
	}
	if name := s.Grype.Database.Name; name == "" || filepath.Base(name) != name {
		return s, errors.New("course.yml scanning.grype.database.name must be a plain file name")
	}
	if s.Govulncheck.Database.Path == "" {
		return s, errors.New("course.yml scanning.govulncheck.database.path must name the committed database")
	}
	return s, nil
}

// scanCacheDir is where downloads and imported databases live. It is outside
// the repository: see the comment on `cache:` in course.yml.
func (a *app) scanCacheDir(s scanningManifest) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no user cache directory for the scan databases: %w", err)
	}
	return filepath.Join(base, s.Cache), nil
}

// Directory names under the cache. The live grype database has its own
// directory so that a live run can never overwrite the pinned one.
const (
	pinnedGrypeDir = "grype-db"
	liveGrypeDir   = "grype-db-live"
	goVulnDBDir    = "go-vulndb"
	importStamp    = "course-import.json"
)

// sbomDir is where the service SBOM and its scan results are written.
func (a *app) sbomDir() string {
	return filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "sbom")
}

// verifyPinnedFile refuses a file whose size or SHA-256 differs from its pin.
// It is called before anything reads the file's contents, so a truncated
// download or a substituted archive never reaches `grype db import`.
func verifyPinnedFile(path string, pin pinnedFile) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != pin.Size {
		return fmt.Errorf("%s is %d bytes, but course.yml pins %d; it is not the pinned database", path, info.Size(), pin.Size)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != pin.SHA256 {
		return fmt.Errorf("%s has sha256 %s, but course.yml pins %s; it is not the pinned database", path, got, pin.SHA256)
	}
	return nil
}

// scannerEnv is the environment for every pinned grype run. All three are
// needed. Without the first two grype goes to the network. Without the third
// it refuses a database more than five days old, so every Learner's pinned
// scan would start failing five days after the snapshot was built.
func scannerEnv(dbDir string) []string {
	return []string{
		"GRYPE_DB_CACHE_DIR=" + dbDir,
		"GRYPE_DB_AUTO_UPDATE=false",
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
		"GRYPE_DB_VALIDATE_AGE=false",
	}
}

// liveScannerEnv lets grype fetch today's database into its own directory.
func liveScannerEnv(dbDir string) []string {
	return []string{
		"GRYPE_DB_CACHE_DIR=" + dbDir,
		"GRYPE_DB_AUTO_UPDATE=true",
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
	}
}

// requireScanner finds a scanner on PATH and refuses any version but the
// pinned one. The same database matches differently under a different
// scanner version, so a mismatch would give a Learner a list the answer key
// does not describe. The version is read from the binary's build information,
// which needs no network, unlike `govulncheck -version`.
func requireScanner(name, version string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s is not installed; the dev container provides %s %s (.devcontainer/Dockerfile)", name, name, version)
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read the version of %s: %w", path, err)
	}
	if info.Main.Version != version {
		return "", fmt.Errorf("%s is %s %s, but course.yml pins %s; a different scanner version gives a different match list",
			path, name, info.Main.Version, version)
	}
	return path, nil
}

// importRecord is written beside an imported database. A scan reads it to
// prove that the database in the cache is the pinned one, and setup reads it
// to skip a three-gigabyte import that has already been done.
type importRecord struct {
	Name       string    `json:"name"`
	SHA256     string    `json:"sha256"`
	ImportedAt time.Time `json:"imported_at"`
}

func readImportRecord(dir string) (importRecord, bool) {
	var record importRecord
	if err := readJSON(filepath.Join(dir, importStamp), &record); err != nil {
		return record, false
	}
	return record, true
}

func (a *app) scan(args []string) error {
	if len(args) == 0 {
		return errors.New("scan requires setup, firmware, or service")
	}
	switch args[0] {
	case "setup":
		return a.scanSetup(args[1:])
	case "firmware":
		return a.scanFirmware(args[1:])
	case "service":
		return a.scanService(args[1:])
	default:
		return fmt.Errorf("unknown scan command %q; use setup, firmware, or service", args[0])
	}
}

func parseScanSetupArgs(args []string) (string, error) {
	archive := ""
	for len(args) > 0 {
		if len(args) < 2 {
			return "", fmt.Errorf("option %s requires a value", args[0])
		}
		switch args[0] {
		case "--archive":
			archive = args[1]
		default:
			return "", fmt.Errorf("unknown scan setup option %s", args[0])
		}
		args = args[2:]
	}
	return archive, nil
}

// scanSetup verifies and imports both pinned databases. It is the only scan
// step that may use the network, and only to fetch what is missing: the grype
// archive, and the go1.24.0 toolchain the service is built and scanned with.
func (a *app) scanSetup(args []string) error {
	archive, err := parseScanSetupArgs(args)
	if err != nil {
		return err
	}
	s, err := a.scanning()
	if err != nil {
		return err
	}
	cache, err := a.scanCacheDir(s)
	if err != nil {
		return err
	}
	a.context("pinned vulnerability databases in " + cache)
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return err
	}

	a.step(1, "Unpack the pinned Go vulnerability database")
	goDB, err := a.ensureGoVulnDB(s, cache)
	if err != nil {
		return err
	}
	a.note("%s, modified %s", goDB, s.Govulncheck.Database.Modified)

	a.step(2, "Verify the pinned grype database archive")
	pin := s.Grype.Database
	if archive == "" {
		archive = filepath.Join(cache, pin.Name)
		if _, err := os.Stat(archive); errors.Is(err, os.ErrNotExist) {
			if err := a.download(pin.URL, archive); err != nil {
				return err
			}
		}
	}
	fmt.Fprintf(a.out, "+ sha256sum %s\n", archive)
	if err := verifyPinnedFile(archive, pin); err != nil {
		return fmt.Errorf("%w; it was not imported", err)
	}
	a.note("sha256 %s, %d bytes, as course.yml pins", pin.SHA256, pin.Size)

	a.step(3, "Import it where only the course looks")
	grype, err := requireScanner("grype", s.Grype.Version)
	if err != nil {
		return err
	}
	dbDir := filepath.Join(cache, pinnedGrypeDir)
	if record, ok := readImportRecord(dbDir); ok && record.SHA256 == pin.SHA256 {
		a.note("already imported on %s", record.ImportedAt.Format(time.RFC3339))
	} else {
		// A half-finished earlier import, or a different snapshot, is removed
		// first, so the directory only ever holds the pinned database.
		if err := os.RemoveAll(dbDir); err != nil {
			return err
		}
		if err := os.MkdirAll(dbDir, 0o700); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "+ GRYPE_DB_CACHE_DIR=%s grype db import %s\n", dbDir, archive)
		if err := runAttachedEnv(a.root, a.out, a.errOut, scannerEnv(dbDir), grype, "db", "import", archive); err != nil {
			return fmt.Errorf("grype db import: %w", err)
		}
		if err := writeJSON(filepath.Join(dbDir, importStamp), importRecord{pin.Name, pin.SHA256, time.Now().UTC()}, 0o600); err != nil {
			return err
		}
	}
	fmt.Fprintf(a.out, "+ GRYPE_DB_CACHE_DIR=%s grype db status\n", dbDir)
	if err := runAttachedEnv(a.root, a.out, a.errOut, scannerEnv(dbDir), grype, "db", "status"); err != nil {
		return fmt.Errorf("grype db status: %w", err)
	}

	a.step(4, "Fetch the Go toolchain the service shipped with")
	fmt.Fprintf(a.out, "+ GOTOOLCHAIN=%s go version\n", s.GoToolchain)
	if err := runAttachedEnv(a.root, a.out, a.errOut, []string{"GOTOOLCHAIN=" + s.GoToolchain}, "go", "version"); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "Result: grype database built %s and Go database modified %s are ready; scans need no network\n",
		pin.Built, s.Govulncheck.Database.Modified)
	fmt.Fprintln(a.out, "Next: ./course sbom service, then ./course scan service")
	return nil
}

// download fetches url to path through a temporary name, so an interrupted
// download never leaves a file that looks complete. The caller verifies it.
func (a *app) download(url, path string) error {
	fmt.Fprintf(a.out, "+ curl -fL -o %s %s\n", path, url)
	// A client of its own: the course client's five-second timeout is for
	// talking to the local service, not for 182 MB.
	client := &http.Client{Timeout: 30 * time.Minute}
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s; download it yourself and run ./course scan setup --archive <file>", url, response.Status)
	}
	partial := path + ".part"
	file, err := os.OpenFile(partial, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, response.Body); err != nil {
		file.Close()
		os.Remove(partial)
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(partial, path)
}

// ensureGoVulnDB verifies the committed Go vulnerability database and unpacks
// it into the cache, unless the same snapshot is already there. It is checked
// on every use, not only at setup, because it is a file in a repository a
// Learner edits.
func (a *app) ensureGoVulnDB(s scanningManifest, cache string) (string, error) {
	pin := s.Govulncheck.Database
	archive := filepath.Join(a.root, pin.Path)
	if err := verifyPinnedFile(archive, pin); err != nil {
		return "", err
	}
	dir := filepath.Join(cache, goVulnDBDir)
	if record, ok := readImportRecord(dir); ok && record.SHA256 == pin.SHA256 {
		return dir, nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	fmt.Fprintf(a.out, "+ unzip -d %s %s\n", dir, pin.Path)
	if err := unzipInto(archive, dir); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if err := writeJSON(filepath.Join(dir, importStamp), importRecord{filepath.Base(pin.Path), pin.SHA256, time.Now().UTC()}, 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

// unzipInto extracts regular files only, and refuses any entry that would land
// outside dir. The checksum already pins the archive; this is so that the
// function stays safe if it is ever pointed at anything else.
func unzipInto(archive, dir string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, entry := range reader.File {
		target := filepath.Join(dir, filepath.FromSlash(entry.Name))
		if !strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) {
			return fmt.Errorf("%s: entry %q leaves the target directory", archive, entry.Name)
		}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if !entry.Mode().IsRegular() {
			return fmt.Errorf("%s: entry %q is not a regular file", archive, entry.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		source, err := entry.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			source.Close()
			return err
		}
		_, copyErr := io.Copy(out, source)
		source.Close()
		if err := out.Close(); err != nil {
			return err
		}
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

// pinnedGrypeDB returns the pinned database directory, and refuses when setup
// has not imported the pinned snapshot there.
func (a *app) pinnedGrypeDB(s scanningManifest) (string, error) {
	cache, err := a.scanCacheDir(s)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cache, pinnedGrypeDir)
	record, ok := readImportRecord(dir)
	if !ok || record.SHA256 != s.Grype.Database.SHA256 {
		return "", errors.New("the pinned grype database is not imported; run ./course scan setup")
	}
	return dir, nil
}

type scanFirmwareOptions struct {
	sbom    string
	tier    string
	variant string
	vex     string
	live    bool
}

func parseScanFirmwareArgs(args []string) (scanFirmwareOptions, error) {
	var options scanFirmwareOptions
	for len(args) > 0 {
		if args[0] == "--live" {
			options.live = true
			args = args[1:]
			continue
		}
		if len(args) < 2 {
			return options, fmt.Errorf("option %s requires a value", args[0])
		}
		switch args[0] {
		case "--sbom":
			options.sbom = args[1]
		case "--tier":
			options.tier = normalizeTier(args[1])
		case "--variant":
			options.variant = args[1]
		case "--vex":
			options.vex = args[1]
		default:
			return options, fmt.Errorf("unknown scan firmware option %s", args[0])
		}
		args = args[2:]
	}
	byRelease := options.tier != "" || options.variant != ""
	switch {
	case options.sbom != "" && byRelease:
		return options, errors.New("give either --sbom or --tier with --variant, not both")
	case options.sbom == "" && !byRelease:
		return options, errors.New("scan firmware requires --sbom <file>, or --tier 09 --variant <release>")
	case byRelease && (options.tier == "" || options.variant == ""):
		return options, errors.New("--tier and --variant must be given together")
	case byRelease && options.tier != tier09:
		return options, fmt.Errorf("only Tier 9 releases carry an SBOM, not tier %s", options.tier)
	}
	return options, nil
}

// firmwareSBOMPath resolves a Tier 9 release to the SBOM the release store
// keeps beside its image, under the name the OTA service's approval check
// expects (services/ota/approval.go).
func (a *app) firmwareSBOMPath(variant string) (string, error) {
	v, err := tier09Variant(variant)
	if err != nil {
		return "", err
	}
	return filepath.Join(a.root, "artifacts", "generated", "releases", v.releaseID+".firmware.cdx.json"), nil
}

// scanResultPath names a scan result after the SBOM it came from, in the same
// directory: tier-09-remediation.firmware.cdx.json gives
// tier-09-remediation.firmware.grype.json. A live result gets its own name, so
// it can never be mistaken for, or overwrite, the pinned one.
func scanResultPath(sbom, tool string, live bool) string {
	base := strings.TrimSuffix(strings.TrimSuffix(sbom, ".json"), ".cdx")
	if live {
		tool += "-live"
	}
	return base + "." + tool + ".json"
}

func (a *app) scanFirmware(args []string) error {
	options, err := parseScanFirmwareArgs(args)
	if err != nil {
		return err
	}
	sbom := options.sbom
	if sbom == "" {
		if sbom, err = a.firmwareSBOMPath(options.variant); err != nil {
			return err
		}
	}
	if sbom, err = filepath.Abs(sbom); err != nil {
		return err
	}
	a.context("firmware SBOM " + a.relative(sbom))
	return a.grypeSBOM(sbom, options.vex, options.live)
}

// grypeSBOM scans one SBOM, writes grype's JSON beside it, and prints a
// short table.
func (a *app) grypeSBOM(sbom, vex string, live bool) error {
	if _, err := os.Stat(sbom); err != nil {
		return fmt.Errorf("no SBOM at %s: %w", sbom, err)
	}
	s, err := a.scanning()
	if err != nil {
		return err
	}
	grype, err := requireScanner("grype", s.Grype.Version)
	if err != nil {
		return err
	}
	var env []string
	if live {
		cache, err := a.scanCacheDir(s)
		if err != nil {
			return err
		}
		dbDir := filepath.Join(cache, liveGrypeDir)
		env = liveScannerEnv(dbDir)
		fmt.Fprintln(a.out, "LIVE: today's database, not the pinned one. This result is not the one the triage is graded against.")
		fmt.Fprintf(a.out, "+ GRYPE_DB_CACHE_DIR=%s grype db update\n", dbDir)
		if err := runAttachedEnv(a.root, a.out, a.errOut, env, grype, "db", "update"); err != nil {
			return fmt.Errorf("grype db update: %w", err)
		}
	} else {
		dbDir, err := a.pinnedGrypeDB(s)
		if err != nil {
			return err
		}
		env = scannerEnv(dbDir)
	}
	result := scanResultPath(sbom, "grype", live)
	command := []string{"sbom:" + sbom, "-o", "json", "--file", result}
	if vex != "" {
		if _, err := os.Stat(vex); err != nil {
			return fmt.Errorf("no VEX document at %s: %w", vex, err)
		}
		command = append(command, "--vex", vex)
	}
	fmt.Fprintf(a.out, "+ grype %s\n", strings.Join(command, " "))
	if err := runAttachedEnv(a.root, io.Discard, a.errOut, env, grype, command...); err != nil {
		return fmt.Errorf("grype: %w", err)
	}
	var report grypeReport
	if err := readJSON(result, &report); err != nil {
		return err
	}
	a.printGrypeReport(report)
	fmt.Fprintf(a.out, "Output: %s\n", a.relative(result))
	if live {
		fmt.Fprintln(a.out, "Result: LIVE scan, not the pinned result; mark anything new or changed as under investigation")
	} else {
		fmt.Fprintf(a.out, "Result: %d matches against the pinned grype database built %s\n", len(report.Matches), s.Grype.Database.Built)
	}
	return nil
}

// grypeReport is the part of grype's JSON the summary reads.
type grypeReport struct {
	Matches        []grypeMatch `json:"matches"`
	IgnoredMatches []grypeMatch `json:"ignoredMatches"`
}

type grypeMatch struct {
	Vulnerability struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Fix      struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
	} `json:"vulnerability"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"artifact"`
}

var severityOrder = map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4}

func severityRank(severity string) int {
	if rank, ok := severityOrder[severity]; ok {
		return rank
	}
	return len(severityOrder)
}

func (a *app) printGrypeReport(report grypeReport) {
	matches := append([]grypeMatch(nil), report.Matches...)
	sort.SliceStable(matches, func(i, j int) bool {
		ri, rj := severityRank(matches[i].Vulnerability.Severity), severityRank(matches[j].Vulnerability.Severity)
		if ri != rj {
			return ri < rj
		}
		return matches[i].Vulnerability.ID < matches[j].Vulnerability.ID
	})
	counts := map[string]int{}
	fmt.Fprintf(a.out, "%-20s  %-10s  %-24s  %-12s  %s\n", "VULNERABILITY", "SEVERITY", "COMPONENT", "VERSION", "FIXED IN")
	for _, match := range matches {
		counts[match.Vulnerability.Severity]++
		fixed := strings.Join(match.Vulnerability.Fix.Versions, ", ")
		if fixed == "" {
			fixed = "(" + match.Vulnerability.Fix.State + ")"
		}
		fmt.Fprintf(a.out, "%-20s  %-10s  %-24s  %-12s  %s\n", match.Vulnerability.ID, match.Vulnerability.Severity,
			match.Artifact.Name, match.Artifact.Version, fixed)
	}
	var parts []string
	for _, severity := range []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"} {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], severity))
		}
	}
	fmt.Fprintf(a.out, "Matches: %d (%s)\n", len(report.Matches), strings.Join(parts, ", "))
	if len(report.IgnoredMatches) > 0 {
		fmt.Fprintf(a.out, "Suppressed by VEX: %d, listed under ignoredMatches in the output\n", len(report.IgnoredMatches))
	}
}

func parseScanServiceArgs(args []string) (bool, error) {
	live := false
	for _, arg := range args {
		switch arg {
		case "--live":
			live = true
		default:
			return false, fmt.Errorf("unknown scan service option %s", arg)
		}
	}
	return live, nil
}

// Output names for the service. They are fixed, because the service has one
// SBOM and the module refers to these files by name.
const (
	serviceSBOMName  = "ota-service.cdx.json"
	serviceScanBase  = "ota-service.govulncheck"
	servicePackages  = "./services/ota/..."
	liveGoVulnSuffix = "-live"
)

// scanService runs govulncheck on the service's source and grype on its SBOM.
// Both views are kept: grype's is what a customer's scanner sees from the
// SBOM, and govulncheck's says which of those matches the code can reach.
func (a *app) scanService(args []string) error {
	live, err := parseScanServiceArgs(args)
	if err != nil {
		return err
	}
	s, err := a.scanning()
	if err != nil {
		return err
	}
	a.context("OTA service source and SBOM")
	sbom := filepath.Join(a.sbomDir(), serviceSBOMName)
	if _, err := os.Stat(sbom); err != nil {
		return fmt.Errorf("no service SBOM at %s; run ./course sbom service first", a.relative(sbom))
	}
	govulncheck, err := requireScanner("govulncheck", s.Govulncheck.Version)
	if err != nil {
		return err
	}
	if !live {
		// Checked before govulncheck runs, so a half-finished setup is found
		// before the first result is written rather than after.
		if _, err := a.pinnedGrypeDB(s); err != nil {
			return err
		}
	}

	a.step(1, "Scan the service source for reachable Go vulnerabilities")
	var dbArgs []string
	base := filepath.Join(a.sbomDir(), serviceScanBase)
	if live {
		fmt.Fprintln(a.out, "LIVE: today's Go vulnerability database, not the pinned one. This result is not the one the triage is graded against.")
		base += liveGoVulnSuffix
	} else {
		cache, err := a.scanCacheDir(s)
		if err != nil {
			return err
		}
		goDB, err := a.ensureGoVulnDB(s, cache)
		if err != nil {
			return err
		}
		dbArgs = []string{"-db", "file://" + filepath.ToSlash(goDB)}
	}
	// GOTOOLCHAIN makes govulncheck see the standard library the service
	// shipped with. On a host with a newer Go it would otherwise scan that
	// Go's standard library and report nothing, which is the wrong answer.
	env := []string{"GOTOOLCHAIN=" + s.GoToolchain}
	scanPath, vexPath := base+".json", base+".openvex.json"
	if err := os.MkdirAll(a.sbomDir(), 0o700); err != nil {
		return err
	}
	for _, run := range []struct {
		format string
		path   string
	}{{"json", scanPath}, {"openvex", vexPath}} {
		command := append(append([]string{}, dbArgs...), "-format", run.format, servicePackages)
		fmt.Fprintf(a.out, "+ GOTOOLCHAIN=%s govulncheck %s > %s\n", s.GoToolchain, strings.Join(command, " "), a.relative(run.path))
		var stdout bytes.Buffer
		if err := runAttachedEnv(a.root, &stdout, a.errOut, env, govulncheck, command...); err != nil {
			return fmt.Errorf("govulncheck: %w", err)
		}
		if err := os.WriteFile(run.path, stdout.Bytes(), 0o600); err != nil {
			return err
		}
	}
	data, err := os.ReadFile(scanPath)
	if err != nil {
		return err
	}
	summary, err := summarizeGovulncheck(data)
	if err != nil {
		return err
	}
	a.note("scanned with %s against the database modified %s", summary.GoVersion, summary.DBLastModified)
	a.note("%d vulnerabilities reachable from the service's code, %d more in imported packages but not called, %d more in required modules only",
		len(summary.Reachable), summary.Imported, summary.Required)
	fmt.Fprintf(a.out, "Output: %s and %s\n", a.relative(scanPath), a.relative(vexPath))

	a.step(2, "Scan the service SBOM as a customer's scanner would")
	if err := a.grypeSBOM(sbom, "", live); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: %d of the SBOM's matches are reachable from the code; that difference is what reachability analysis is for\n",
		len(summary.Reachable))
	return nil
}

// govulncheckSummary counts govulncheck's findings at its three levels. A
// finding whose first trace frame names a function is reachable: the code
// calls a vulnerable symbol. One naming only a package is imported but not
// called, and one naming only a module is required but not imported.
type govulncheckSummary struct {
	GoVersion      string
	DBLastModified string
	Reachable      []string
	Imported       int
	Required       int
}

func summarizeGovulncheck(data []byte) (govulncheckSummary, error) {
	var summary govulncheckSummary
	type frame struct {
		Module   string `json:"module"`
		Package  string `json:"package"`
		Function string `json:"function"`
	}
	type message struct {
		Config *struct {
			GoVersion      string `json:"go_version"`
			DBLastModified string `json:"db_last_modified"`
		} `json:"config"`
		Finding *struct {
			OSV   string  `json:"osv"`
			Trace []frame `json:"trace"`
		} `json:"finding"`
	}
	level := map[string]int{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var m message
		if err := decoder.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return summary, fmt.Errorf("govulncheck output: %w", err)
		}
		if m.Config != nil {
			summary.GoVersion = m.Config.GoVersion
			summary.DBLastModified = m.Config.DBLastModified
		}
		if m.Finding == nil || len(m.Finding.Trace) == 0 {
			continue
		}
		// 3 is reachable, 2 imported, 1 required; an OSV entry counts once,
		// at the deepest level any of its findings reached.
		first := m.Finding.Trace[0]
		depth := 1
		if first.Function != "" {
			depth = 3
		} else if first.Package != "" {
			depth = 2
		}
		if depth > level[m.Finding.OSV] {
			level[m.Finding.OSV] = depth
		}
	}
	for id, depth := range level {
		switch depth {
		case 3:
			summary.Reachable = append(summary.Reachable, id)
		case 2:
			summary.Imported++
		default:
			summary.Required++
		}
	}
	sort.Strings(summary.Reachable)
	return summary, nil
}

// goModToolchain returns the toolchain directive in go.mod, or "" when there
// is none or the file cannot be read.
func goModToolchain(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "toolchain" && strings.HasPrefix(fields[1], "go1.") {
			return fields[1]
		}
	}
	return ""
}
