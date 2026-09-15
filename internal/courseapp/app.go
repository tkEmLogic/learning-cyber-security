package courseapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

type manifest struct {
	SchemaVersion int `yaml:"schema_version"`
	Course        struct {
		ID                        string `yaml:"id"`
		Version                   string `yaml:"version"`
		EnvironmentMarkerTTLHours int    `yaml:"environment_marker_ttl_hours"`
	} `yaml:"course"`
	Runtime struct {
		BindDefault          string `yaml:"bind_default"`
		PrivateBindAllowed   bool   `yaml:"private_bind_allowed"`
		OTAPort              int    `yaml:"ota_port"`
		TLSPort              int    `yaml:"ota_tls_port"`
		ImpersonationPort    int    `yaml:"impersonation_port"`
		ImpersonationTLSPort int    `yaml:"impersonation_tls_port"`
	} `yaml:"runtime"`
	Paths struct {
		State              string   `yaml:"state"`
		Secrets            string   `yaml:"secrets"`
		Build              string   `yaml:"build"`
		GeneratedArtifacts string   `yaml:"generated_artifacts"`
		LearnerEvidence    string   `yaml:"learner_evidence"`
		CleanupAllowlist   []string `yaml:"cleanup_allowlist"`
	} `yaml:"paths"`
	Services map[string]struct {
		Bind   string `yaml:"bind"`
		Port   int    `yaml:"port"`
		Health string `yaml:"health"`
		Marker string `yaml:"marker"`
	} `yaml:"services"`
	Devices map[string]struct {
		SyntheticID        string   `yaml:"synthetic_id"`
		SpoofID            string   `yaml:"spoof_id"`
		Board              string   `yaml:"board"`
		StableSerialPrefix string   `yaml:"stable_serial_prefix"`
		HardwareRequired   []string `yaml:"hardware_required"`
	} `yaml:"devices"`
	Fixtures map[string]fixture `yaml:"fixtures"`
	Safety   struct {
		SyntheticDataOnly         bool   `yaml:"synthetic_data_only"`
		MarkerRequired            bool   `yaml:"marker_required"`
		MarkerPath                string `yaml:"marker_path"`
		DryRunDefault             bool   `yaml:"dry_run_default"`
		ExecuteIdentifierRequired bool   `yaml:"execute_identifier_required"`
		RefuseAfterFailedReset    bool   `yaml:"refuse_after_failed_reset"`
		CleanupConfirmation       string `yaml:"cleanup_confirmation"`
	} `yaml:"safety"`
	Checkpoints struct {
		PublicationOwnerIssue int    `yaml:"publication_owner_issue"`
		PublicationStatus     string `yaml:"publication_status"`
	} `yaml:"checkpoints"`
	Verification map[string]struct {
		Command       []string          `yaml:"command"`
		Receipt       string            `yaml:"receipt"`
		RevisionBound bool              `yaml:"revision_bound"`
		Hardware      map[string]string `yaml:"hardware"`
	} `yaml:"verification"`
	Tiers map[string]tier `yaml:"tiers"`
}

type tier struct {
	Title                 string   `yaml:"title"`
	Kind                  string   `yaml:"kind"`
	Track                 string   `yaml:"track"`
	Status                string   `yaml:"status"`
	StartCheckpoint       string   `yaml:"start_checkpoint"`
	CompleteCheckpoint    string   `yaml:"complete_checkpoint"`
	Module                string   `yaml:"module"`
	Prerequisites         []string `yaml:"prerequisites"`
	ContinueSameWorkspace bool     `yaml:"continue_same_workspace"`
	Fixtures              []string `yaml:"fixtures"`
}

type fixture struct {
	Tier             string   `yaml:"tier"`
	Target           string   `yaml:"target"`
	Interface        string   `yaml:"interface"`
	ExpectedEffect   string   `yaml:"expected_effect"`
	Changes          []string `yaml:"changes"`
	Reset            string   `yaml:"reset"`
	HardwareRequired bool     `yaml:"hardware_required"`

	// Images are the hostile firmware images a fixture may publish, keyed by
	// the selector a Learner types. The selector is an allowlisted manifest
	// value like every other mutable input, never a path from the command
	// line. See docs/fixture-safety-contract.md.
	Images map[string]string `yaml:"images"`

	// Releases are the hostile release identifiers a fixture may publish,
	// keyed the same way. Tier 4 needs its own field because what it
	// publishes is a signed Release manifest and not an image at all, and a
	// map called images holding release identifiers would be a lie in the
	// manifest. The guardrail is identical: the selector is allowlisted here,
	// never supplied as a path.
	Releases map[string]string `yaml:"releases"`

	// Image is the single built image a Tier 6 fixture reads the compiled-in
	// credential out of, and PhantomIDs is the bounded list of
	// never-manufactured identifiers the clone may register. Both are
	// allowlisted here, never supplied on the command line: the image so that
	// extraction is not a way to read any file, and the identifiers so that an
	// unbounded loop appending to the manufacturing record is not mistaken for
	// a demonstration of scale. See docs/fixture-safety-contract.md, "Tier 6
	// fixtures".
	Image      string   `yaml:"image"`
	PhantomIDs []string `yaml:"phantom_ids"`
}

// selectors returns the allowlist a fixture's selector must come from, and the
// option name that chooses it. A fixture has at most one of the two.
func (f fixture) selectors() (map[string]string, string) {
	if len(f.Releases) > 0 {
		return f.Releases, "--release"
	}
	return f.Images, "--image"
}

// maxFixtureHoldSeconds bounds how long a fixture may leave the Course
// environment in its insecure state. The environment is disposable, but it
// should never be left that way by accident.
const maxFixtureHoldSeconds = 600

type environment struct {
	SchemaVersion int       `json:"schema_version"`
	CourseID      string    `json:"course_id"`
	EnvironmentID string    `json:"environment_id"`
	Tier          string    `json:"tier"`
	SyntheticData bool      `json:"synthetic_data"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type app struct {
	root     string
	manifest manifest
	out      io.Writer
	errOut   io.Writer
	client   *http.Client

	// selector is the manifest key of the hostile artifact the running fixture
	// was asked to publish: an image in Tier 3, a signed Release manifest in
	// Tier 4. It is set by the attack runner after the key has been checked
	// against the manifest, never taken as a path.
	selector string
}

func Run(args []string, out, errOut io.Writer) int {
	root, args, err := parseRoot(args)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	a, err := load(root, out, errOut)
	if err != nil {
		fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if len(args) == 0 {
		a.usage(errOut)
		return 2
	}
	if err := a.dispatch(args); err != nil {
		fmt.Fprintln(errOut, "refused:", err)
		return 1
	}
	return 0
}

func parseRoot(args []string) (string, []string, error) {
	root := "."
	if len(args) >= 2 && args[0] == "--repo" {
		root = args[1]
		args = args[2:]
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", nil, err
	}
	return absolute, args, nil
}

func load(root string, out, errOut io.Writer) (*app, error) {
	data, err := os.ReadFile(filepath.Join(root, "course.yml"))
	if err != nil {
		return nil, err
	}
	var m manifest
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&m); err != nil {
		return nil, fmt.Errorf("course.yml: %w", err)
	}
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	return &app{
		root:     root,
		manifest: m,
		out:      out,
		errOut:   errOut,
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func validateManifest(m manifest) error {
	if m.SchemaVersion != 1 || m.Course.ID != "learning-cyber-security" || m.Course.Version == "" {
		return errors.New("course.yml has an unsupported identity or schema version")
	}
	if m.Runtime.OTAPort == 0 || m.Runtime.BindDefault == "" {
		return errors.New("course.yml must define the OTA port and default bind address")
	}
	if len(m.Paths.CleanupAllowlist) != 4 || m.Safety.CleanupConfirmation == "" {
		return errors.New("course.yml cleanup contract is incomplete")
	}
	t0, ok := m.Tiers["00"]
	if !ok || t0.Status != "implemented" || len(t0.Fixtures) != 4 {
		return errors.New("course.yml must implement Tier 0 with four fixtures")
	}
	for _, id := range []string{"tier-00/plaintext-inspection", "tier-00/device-id-spoofing", "tier-00/service-impersonation", "tier-00/altered-image"} {
		if _, ok := m.Fixtures[id]; !ok {
			return fmt.Errorf("course.yml is missing fixture %s", id)
		}
	}
	for _, id := range []string{"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "A", "B"} {
		if _, ok := m.Tiers[id]; !ok {
			return fmt.Errorf("course.yml is missing planned tier %s", id)
		}
	}
	return nil
}

func (a *app) dispatch(args []string) error {
	switch args[0] {
	case "doctor":
		return a.doctor()
	case "setup":
		return a.setup(args[1:])
	case "tier":
		return a.tier(args[1:])
	case "build":
		return a.build(args[1:])
	case "service":
		return a.service(args[1:])
	case "device":
		return a.device(args[1:])
	case "keys":
		return a.keys(args[1:])
	case "release":
		return a.release(args[1:])
	case "provision":
		return a.provision(args[1:])
	case "attack":
		return a.attack(args[1:])
	case "verify":
		return a.verify(args[1:])
	case "evidence":
		return a.evidence(args[1:])
	case "clean":
		return a.clean(args[1:])
	case "validate":
		return a.validateRepository()
	default:
		a.usage(a.errOut)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func (a *app) usage(w io.Writer) {
	fmt.Fprintln(w, "usage: ./course doctor|setup|tier|build|service|device|keys|release|provision|attack|verify|evidence|clean")
}

func (a *app) context(target string) {
	fmt.Fprintf(a.out, "Context: course %s, Tier 00, target %s\n", a.manifest.Course.Version, target)
}

func (a *app) doctor() error {
	a.context("host")
	required := [][]string{{"git", "--version"}, {"go", "version"}, {"curl", "--version"}}
	problems := 0
	for _, probe := range required {
		fmt.Fprintf(a.out, "+ %s\n", strings.Join(probe, " "))
		if err := runProbe(a.root, probe); err != nil {
			fmt.Fprintf(a.out, "  missing: %v\n", err)
			problems++
		} else {
			fmt.Fprintln(a.out, "  available")
		}
	}
	python := "python3"
	venvPython := filepath.Join(a.root, a.manifest.Paths.Build, "python", "bin", "python")
	if info, err := os.Stat(venvPython); err == nil && info.Mode().IsRegular() {
		python = venvPython
	}
	fmt.Fprintf(a.out, "+ %s -c \"import jsonschema, yaml\"\n", python)
	if err := runProbe(a.root, []string{python, "-c", "import jsonschema, yaml"}); err != nil {
		fmt.Fprintln(a.out, "  missing: Python packages from requirements.txt are unavailable")
		fmt.Fprintln(a.out, "  install: python3 -m venv build/python && build/python/bin/pip install -r requirements.txt")
		problems++
	} else {
		fmt.Fprintln(a.out, "  available")
	}
	fmt.Fprintln(a.out, "+ find /dev/serial/by-id -maxdepth 1 -type l")
	if entries, _ := filepath.Glob("/dev/serial/by-id/*"); len(entries) == 0 {
		fmt.Fprintln(a.out, "  hardware: pending, no stable ESP32-C6 serial path detected")
	} else {
		for _, entry := range entries {
			fmt.Fprintf(a.out, "  candidate: %s\n", entry)
		}
		fmt.Fprintln(a.out, "  hardware: pending, serial candidates do not prove that an ESP32-C6 is connected")
	}
	if problems != 0 {
		return fmt.Errorf("%d required host checks failed", problems)
	}
	fmt.Fprintln(a.out, "Result: the course toolchain is available")
	fmt.Fprintln(a.out, "Next: ./course setup")
	return nil
}

func (a *app) setup(args []string) error {
	options, err := parseSetupArgs(args)
	if err != nil {
		return err
	}
	bind := options.bind
	a.context("generated local Course environment")
	if err := validateBind(bind); err != nil {
		return err
	}
	for _, path := range []string{a.manifest.Paths.State, a.manifest.Paths.Secrets, a.manifest.Paths.Build, a.manifest.Paths.GeneratedArtifacts} {
		fmt.Fprintf(a.out, "+ mkdir -p %s\n", path)
		if err := os.MkdirAll(filepath.Join(a.root, path), 0o700); err != nil {
			return err
		}
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	env := environment{1, a.manifest.Course.ID, id, "00", true, now, now.Add(time.Duration(a.manifest.Course.EnvironmentMarkerTTLHours) * time.Hour)}
	if err := writeJSON(filepath.Join(a.root, a.manifest.Safety.MarkerPath), env, 0o600); err != nil {
		return err
	}
	// COURSE_ADVERTISED_HOST is the address the Reference product uses to reach
	// the service, which is this container's published port on the host. The
	// service process itself always listens on every address inside the
	// container, so the two are not the same value.
	serviceEnv := fmt.Sprintf("COURSE_ENVIRONMENT_ID=%s\nCOURSE_ADVERTISED_HOST=%s\nCOURSE_PORT=%d\n", id, bind, a.manifest.Runtime.OTAPort)
	if err := os.WriteFile(filepath.Join(a.root, a.manifest.Paths.State, "service.env"), []byte(serviceEnv), 0o600); err != nil {
		return err
	}
	otaState := filepath.Join(a.root, a.manifest.Paths.State, "ota")
	releaseDir := filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "releases")
	if err := os.MkdirAll(otaState, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(releaseDir, 0o700); err != nil {
		return err
	}
	image := []byte("COURSE SYNTHETIC FIRMWARE\nTier 00\nstate=steady\n")
	imagePath := filepath.Join(releaseDir, "tier-00-baseline.bin")
	if err := os.WriteFile(imagePath, image, 0o600); err != nil {
		return err
	}
	sum := sha256.Sum256(image)
	release := map[string]any{
		"schema_version": 1, "release_id": "tier-00-baseline", "version": "0.0.0-insecure",
		"board": "esp32c6_devkitc/esp32c6/hpcore", "image_path": filepath.Base(imagePath),
		"image_sha256": hex.EncodeToString(sum[:]), "image_size": len(image), "mutable": true, "signed": false,
	}
	for _, name := range []string{"seed-release.json", "current-release.json"} {
		if err := writeJSON(filepath.Join(otaState, name), release, 0o600); err != nil {
			return err
		}
	}
	deviceConfig := map[string]any{"schema_version": 1, "device_id": a.manifest.Devices["reference_beacon"].SyntheticID, "ota_url": fmt.Sprintf("http://%s:%d", bind, a.manifest.Runtime.OTAPort)}
	if err := writeJSON(filepath.Join(a.root, a.manifest.Paths.State, "device-config.json"), deviceConfig, 0o600); err != nil {
		return err
	}
	if err := a.writeWiFiSecret(options.wifiSSID, options.wifiPSK); err != nil {
		return err
	}
	if err := a.writeCertificates(options.replaceCA); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: created synthetic Tier 0 environment %s\n", id)
	fmt.Fprintf(a.out, "State: %s, %s\n", a.manifest.Paths.State, a.manifest.Paths.GeneratedArtifacts)
	if isLoopback(bind) {
		fmt.Fprintln(a.out, "Note: the service is advertised on loopback, so a physical board cannot reach it.")
		fmt.Fprintln(a.out, "Note: run setup again with --bind <this host's private address> for hardware work.")
	}
	fmt.Fprintln(a.out, "Next: ./course service start")
	return nil
}

// writeWiFiSecret keeps the course Wi-Fi passphrase in the ignored secrets
// directory. Tier 0 compiles it into the firmware image, which the Weakness
// ledger records, but it never belongs in Git.
func (a *app) writeWiFiSecret(ssid, psk string) error {
	path := filepath.Join(a.root, a.manifest.Paths.Secrets, "wifi.conf")
	if ssid == "" {
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintf(a.out, "Kept: existing %s\n", path)
			return nil
		}
		ssid, psk = "", ""
	}
	body := fmt.Sprintf(`# Local course Wi-Fi network for the ESP32-C6 Reference product.
#
# Generated by ./course setup. Git ignores this directory. Never commit it.
#
# The network must be 2.4 GHz WPA2-PSK, on the same Layer 2 network as the
# host that runs ./course service start, with client isolation switched off.
#
# Set both values with:
#   ./course setup --wifi-ssid <name> --wifi-psk <passphrase>
CONFIG_COURSE_WIFI_SSID=%q
CONFIG_COURSE_WIFI_PSK=%q
`, ssid, psk)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return err
	}
	if ssid == "" {
		fmt.Fprintf(a.out, "Wrote: %s with no network yet\n", path)
	} else {
		fmt.Fprintf(a.out, "Wrote: %s for network %q\n", path, ssid)
	}
	return nil
}

// writeTrustAnchor turns the Course certificate authority into a C byte list
// the firmware build compiles in, the same way the Wi-Fi credentials are
// compiled in. The generated file lives in generated state, never in the
// application directory, so the repository stays free of Course environment
// material.
func (a *app) writeTrustAnchor() (string, error) {
	der, err := os.ReadFile(filepath.Join(a.pkiDir(), coursepki.CourseCADER))
	if err != nil {
		return "", errors.New("run ./course setup before building firmware that verifies a service")
	}
	dir := filepath.Join(a.root, a.manifest.Paths.State, "firmware", "anchor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var builder strings.Builder
	builder.WriteString("/* Generated by ./course build firmware. Do not edit or commit. */\n")
	for i, b := range der {
		if i%12 == 0 {
			builder.WriteString("\n\t")
		}
		fmt.Fprintf(&builder, "0x%02x, ", b)
	}
	builder.WriteString("\n")
	path := filepath.Join(dir, "course_ca_der.inc")
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

// pkiDir is where every generated key and certificate lives. It is inside the
// ignored secrets directory and nothing ever copies material out of it.
func (a *app) pkiDir() string {
	return filepath.Join(a.root, a.manifest.Paths.Secrets, "pki")
}

// writeCertificates generates the Course certificate authority and everything
// it signs.
//
// Replacing an existing authority is refused unless the Learner asks for it by
// name. The trust anchor is compiled into the firmware image, so a new
// authority leaves a flashed board trusting material that no longer exists, and
// the raw symptom is a handshake failure that looks like a broken network.
func (a *app) writeCertificates(replace bool) error {
	dir := a.pkiDir()
	if coursepki.Exists(dir) && !replace {
		fingerprint, err := coursepki.AnchorFingerprint(dir)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.out, "Kept: existing Course certificate authority %s in %s\n",
			fingerprint, filepath.Join(a.manifest.Paths.Secrets, "pki"))
		fmt.Fprintln(a.out, "Note: replacing it needs --replace-certificate-authority, and every flashed board must be built and flashed again.")
		return nil
	}
	if err := coursepki.Generate(dir); err != nil {
		return err
	}
	fingerprint, err := coursepki.AnchorFingerprint(dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Wrote: Course certificate authority %s in %s\n",
		fingerprint, filepath.Join(a.manifest.Paths.Secrets, "pki"))
	fmt.Fprintf(a.out, "Wrote: service certificate for %s, and the two certificates the Tier 2 bypass tests need\n",
		coursepki.ServiceName)
	return nil
}

func isLoopback(bind string) bool {
	address := net.ParseIP(bind)
	return address != nil && address.IsLoopback()
}

type setupOptions struct {
	bind      string
	wifiSSID  string
	wifiPSK   string
	replaceCA bool
}

func parseSetupArgs(args []string) (setupOptions, error) {
	options := setupOptions{bind: "127.0.0.1"}
	for len(args) > 0 {
		if args[0] == "--replace-certificate-authority" {
			options.replaceCA = true
			args = args[1:]
			continue
		}
		if len(args) < 2 {
			return options, fmt.Errorf("option %s requires a value", args[0])
		}
		switch args[0] {
		case "--bind":
			options.bind = args[1]
		case "--wifi-ssid":
			options.wifiSSID = args[1]
		case "--wifi-psk":
			options.wifiPSK = args[1]
		default:
			return options, fmt.Errorf("unknown setup option %s", args[0])
		}
		args = args[2:]
	}
	if (options.wifiSSID == "") != (options.wifiPSK == "") {
		return options, errors.New("--wifi-ssid and --wifi-psk must be given together")
	}
	if options.wifiPSK != "" && (len(options.wifiPSK) < 8 || len(options.wifiPSK) > 63) {
		return options, errors.New("--wifi-psk must be a WPA2 passphrase of 8 to 63 characters")
	}
	return options, nil
}

func (a *app) tier(args []string) error {
	if len(args) == 0 {
		return errors.New("tier requires list, status, start, or diff")
	}
	switch args[0] {
	case "list":
		ids := sortedTierIDs(a.manifest.Tiers)
		a.context("tier manifest")
		for _, id := range ids {
			t := a.manifest.Tiers[id]
			fmt.Fprintf(a.out, "%s  %-11s  %s", id, strings.ToUpper(t.Status), t.Title)
			if len(t.Prerequisites) > 0 {
				fmt.Fprintf(a.out, "  prerequisites: %s", strings.Join(t.Prerequisites, ","))
			}
			fmt.Fprintln(a.out)
		}
		return nil
	case "status":
		a.context("Course workspace")
		var state map[string]any
		if err := readJSON(filepath.Join(a.root, a.manifest.Paths.State, "workspace.json"), &state); err != nil {
			fmt.Fprintln(a.out, "Result: this checkout is not a generated Course workspace")
		} else {
			data, _ := json.MarshalIndent(state, "", "  ")
			fmt.Fprintln(a.out, string(data))
		}
		fmt.Fprintf(a.out, "+ git status --short --branch\n")
		return runAttached(a.root, a.out, a.errOut, "git", "status", "--short", "--branch")
	case "start":
		return a.tierStart(args[1:])
	case "diff":
		return a.tierDiff(args[1:])
	default:
		return fmt.Errorf("unknown tier command %q", args[0])
	}
}

func (a *app) tierStart(args []string) error {
	if len(args) == 0 {
		return errors.New("tier start requires an identifier")
	}
	id := normalizeTier(args[0])
	t, ok := a.manifest.Tiers[id]
	if !ok {
		return fmt.Errorf("unknown tier %s", id)
	}
	if t.Status != "implemented" {
		return fmt.Errorf("Tier %s is %s and unavailable", id, t.Status)
	}
	workspace := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--workspace" && i+1 < len(args) {
			workspace = args[i+1]
			i++
		} else {
			return fmt.Errorf("unknown tier start option %s", args[i])
		}
	}
	if id != "00" && t.ContinueSameWorkspace {
		return errors.New("Tier 1 continues in the Tier 0 Course workspace on the same branch; there is no separate workspace to start")
	}
	if workspace == "" {
		workspace = filepath.Join(filepath.Dir(a.root), "learning-cyber-security-course")
	}
	if dirty, err := gitOutput(a.root, "status", "--porcelain"); err != nil || strings.TrimSpace(dirty) != "" {
		return errors.New("the controller checkout must be clean")
	}
	if err := runProbe(a.root, []string{"git", "rev-parse", "--verify", "refs/tags/" + t.StartCheckpoint}); err != nil {
		return fmt.Errorf("checkpoint %s is not published; issue #%d owns checkpoint publication", t.StartCheckpoint, a.manifest.Checkpoints.PublicationOwnerIssue)
	}
	branch := "learner/tier-" + strings.ToLower(id)
	fmt.Fprintf(a.out, "+ git worktree add -b %s %s %s\n", branch, workspace, t.StartCheckpoint)
	if err := runAttached(a.root, a.out, a.errOut, "git", "worktree", "add", "-b", branch, workspace, t.StartCheckpoint); err != nil {
		return err
	}
	state := map[string]any{"schema_version": 1, "tier": id, "controller_repository": a.root, "start_checkpoint": t.StartCheckpoint, "created_at": time.Now().UTC()}
	stateDir := filepath.Join(workspace, a.manifest.Paths.State)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(stateDir, "workspace.json"), state, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: Course workspace created at %s\nModule: %s\n", workspace, t.Module)
	return nil
}

func (a *app) tierDiff(args []string) error {
	if len(args) == 0 {
		return errors.New("tier diff requires an identifier")
	}
	id := normalizeTier(args[0])
	t, ok := a.manifest.Tiers[id]
	if !ok {
		return fmt.Errorf("unknown tier %s", id)
	}
	if runProbe(a.root, []string{"git", "rev-parse", "--verify", "refs/tags/" + t.StartCheckpoint}) != nil {
		return fmt.Errorf("checkpoint %s is pending publication by issue #%d", t.StartCheckpoint, a.manifest.Checkpoints.PublicationOwnerIssue)
	}
	fmt.Fprintf(a.out, "+ git diff %s...HEAD\n", t.StartCheckpoint)
	return runAttached(a.root, a.out, a.errOut, "git", "--no-pager", "diff", t.StartCheckpoint+"...HEAD")
}

func (a *app) build(args []string) error {
	component := "all"
	if len(args) > 0 {
		component = args[0]
	}
	a.context(component)
	switch component {
	case "all":
		fmt.Fprintln(a.out, "+ go build ./tools/course ./services/ota/cmd/ota")
		if err := runAttached(a.root, a.out, a.errOut, "go", "build", "./tools/course", "./services/ota/cmd/ota"); err != nil {
			return err
		}
		fmt.Fprintln(a.out, "+ ./scripts/build-zephyr-baseline.sh")
		return runAttached(a.root, a.out, a.errOut, "./scripts/build-zephyr-baseline.sh")
	case "host", "service", "helper":
		fmt.Fprintln(a.out, "+ go build ./tools/course ./services/ota/cmd/ota")
		return runAttached(a.root, a.out, a.errOut, "go", "build", "./tools/course", "./services/ota/cmd/ota")
	case "firmware":
		return a.buildFirmware(args[1:])
	default:
		return fmt.Errorf("unknown component %q", component)
	}
}

// firmwareVariant describes one buildable image. The Reference product ships
// as two: the baseline the Learner flashes, and the altered image the
// altered-image fixture publishes to show that Tier 0 accepts any image the
// service offers.
type firmwareVariant struct {
	releaseID   string
	label       string
	beaconState string
	version     string
	imageName   string
	// securityCounter is zero for every tier before Tier 4, which is exactly
	// what those images carry: no counter TLV at all. MCUboot treats an image
	// with no counter in the primary slot as permission to swap, so this being
	// unset is not a default, it is the migration case.
	securityCounter int
	// trialBehaviour is empty for every tier before Tier 5, which has no
	// trial boot to behave during. From Tier 5 it names one of the five
	// arms of the COURSE_TRIAL_BEHAVIOUR choice, and it is the only thing
	// that differs between the five images that tier publishes.
	trialBehaviour string
	// identityModel is empty for every tier before Tier 6, which has one
	// identity and no choice about it. From Tier 6 it names one of the two
	// arms of the COURSE_IDENTITY choice, and it is the only thing that
	// differs between the two images that tier publishes.
	identityModel string
}

var firmwareVariants = map[string]firmwareVariant{
	"baseline": {
		releaseID:   "tier-00-baseline",
		label:       "baseline",
		beaconState: "steady",
		version:     "0.0.0-insecure",
		imageName:   "tier-00-baseline.bin",
	},
	"altered": {
		releaseID:   "tier-00-altered",
		label:       "altered",
		beaconState: "fast",
		version:     "0.0.0-altered",
		imageName:   "tier-00-altered.bin",
	},
}

// tier02Variants are the same images built from the Tier 2 application, which
// verifies the service before it reads anything from it.
var tier02Variants = map[string]firmwareVariant{
	"baseline": {
		releaseID:   "tier-02-baseline",
		label:       "baseline",
		beaconState: "steady",
		version:     "0.2.0-authenticated",
		imageName:   "tier-02-baseline.bin",
	},
}

// tier03Variants are built from the Tier 3 application, whose bootloader
// refuses an image that does not verify against the key compiled into it.
//
// The image name carries no "signed" marker on purpose. A release is either one
// the device will run or one it will refuse, and the name is not what decides.
var tier03Variants = map[string]firmwareVariant{
	"baseline": {
		releaseID:   "tier-03-baseline",
		label:       "baseline",
		beaconState: "steady",
		version:     "0.3.0-signed",
		imageName:   "tier-03-baseline.bin",
	},
}

// firmwareApps maps a tier to the application directory that builds it. Each
// tier owns its own application, so a control added in one tier can never
// change the firmware a published tier describes.
var firmwareApps = map[string]string{
	"00": "firmware/reference-product-baseline",
	"02": "firmware/tier-02-authenticated-service",
	"03": "firmware/tier-03-signed-images",
	"04": "firmware/tier-04-release-policy",
	"05": "firmware/tier-05-recovery",
	"06": "firmware/tier-06-factory-identity",
}

// tierSignsItsOwnImage names the tiers whose bootloader is built separately
// against the public half of the Learner's key, and whose image is therefore
// signed afterwards rather than by the build.
//
// Written as a set rather than as a comparison against "03" and "04" because
// the property is "this tier's bootloader checks who published an image", and
// every tier from Tier 3 on has it.
func tierSignsItsOwnImage(tier string) bool {
	return tier == "03" || tier == "04" || tier == "05" || tier == "06"
}

func variantsForTier(tier string) map[string]firmwareVariant {
	switch tier {
	case "02":
		return tier02Variants
	case "03":
		return tier03Variants
	case "04":
		return tier04Variants
	case "05":
		return tier05Variants
	case "06":
		return tier06Variants
	default:
		return firmwareVariants
	}
}

func (a *app) buildFirmware(args []string) error {
	name := "baseline"
	tier := "00"
	for len(args) > 0 {
		if len(args) < 2 {
			return fmt.Errorf("option %s requires a value", args[0])
		}
		switch args[0] {
		case "--variant":
			name = args[1]
		case "--tier":
			tier = normalizeTier(args[1])
		default:
			return fmt.Errorf("unknown firmware option %s", args[0])
		}
		args = args[2:]
	}
	variants := variantsForTier(tier)
	variant, ok := variants[name]
	if !ok {
		return fmt.Errorf("unknown firmware variant %q for tier %s", name, tier)
	}
	appDir, ok := firmwareApps[tier]
	if !ok {
		return fmt.Errorf("tier %s has no firmware application", tier)
	}

	confPath, host, err := a.writeFirmwareConfig(variant, tier)
	if err != nil {
		return err
	}

	// Zephyr build trees are large third-party output, so they stay in the
	// external workspace beside the toolchain, not in the repository.
	buildDir := filepath.Join(a.zephyrWorkspace(), "build", filepath.Base(appDir)+"-"+variant.label)
	buildEnv := []string{"COURSE_FIRMWARE_CONF=" + confPath, "ZEPHYR_BUILD_DIR=" + buildDir}
	printed := buildEnv
	if tier != "00" {
		buildEnv = append(buildEnv, "COURSE_FIRMWARE_APP="+appDir)
		anchorDir, err := a.writeTrustAnchor()
		if err != nil {
			return err
		}
		buildEnv = append(buildEnv, "COURSE_CA_INC_DIR="+anchorDir)
		printed = buildEnv
	}
	// From Tier 3 the bootloader is built separately, against the public half
	// of the Learner's key. The build never sees anything that could sign.
	if tierSignsItsOwnImage(tier) {
		if _, err := os.Stat(a.publicKeyPath()); err != nil {
			return errors.New("no public signing key yet; run ./course keys create release first")
		}
		buildEnv = append(buildEnv, "COURSE_SIGNING_PUBKEY="+a.publicKeyPath())
		printed = buildEnv
	}
	// Tier 4 compiles the same public key into the application as well, so it
	// can verify a Release manifest. It is a separate variable from the trust
	// anchor because it answers a separate question: the anchor says which
	// service to talk to, this says whose release metadata to believe.
	if tier == "04" || tier == "05" || tier == "06" {
		keyDir, err := a.writeSigningPublicKeyInc()
		if err != nil {
			return err
		}
		buildEnv = append(buildEnv, "COURSE_RELEASE_KEY_INC_DIR="+keyDir)
		printed = buildEnv
	}
	// Tier 6's shared variant, and nothing else, compiles in the fleet's
	// private key. This is the one deliberate exception to the rule that a
	// firmware build command never names a private key, and it is bounded to
	// this one throwaway credential: see the Tier 6 section of
	// docs/fixture-safety-contract.md.
	//
	// The variable is set for the shared variant only, so the factory build
	// does not have the key on its include path at all.
	if tier == "06" && variant.identityModel == "shared" {
		sharedDir, err := a.writeSharedIdentityInc()
		if err != nil {
			return err
		}
		buildEnv = append(buildEnv, "COURSE_SHARED_IDENTITY_INC_DIR="+sharedDir)
		printed = buildEnv
		fmt.Fprintln(a.out, "Note: this build compiles the fleet's private key into the image. That is")
		fmt.Fprintln(a.out, "Note: what Tier 6 is about, and it is the only build in the course that does it.")
	}
	fmt.Fprintf(a.out, "+ %s ./scripts/build-zephyr-baseline.sh\n", strings.Join(printed, " "))
	if err := runAttachedEnv(a.root, a.out, a.errOut, buildEnv,
		"./scripts/build-zephyr-baseline.sh"); err != nil {
		return err
	}

	// Tier 3 and Tier 4 stop here. The image exists and it is unsigned, which
	// is not a release: the device will refuse it. Signing is the Learner's own
	// step, with the private key, on an image the build has already let go of.
	if tierSignsItsOwnImage(tier) {
		fmt.Fprintf(a.out, "Result: built an unsigned Tier %s image in %s\n",
			strings.TrimLeft(tier, "0"), buildDir)
		fmt.Fprintln(a.out, "Nothing has been published. This image is unsigned, so the bootloader would refuse it.")
		fmt.Fprintln(a.out, "Sign and publish it yourself with:")
		if tier == "04" {
			fmt.Fprintf(a.out, "  ./course release sign%s\n", signCommandSuffix(tier, variant))
			fmt.Fprintln(a.out, "That step signs the image and the Release manifest with the same key,")
			fmt.Fprintf(a.out, "puts security counter %d in both, and publishes the release.\n", variant.securityCounter)
		} else {
			// signCommandSuffix, not a bare "./course release sign".
			// The bare form signs Tier 3, so for Tier 5 and Tier 6 the
			// hint named a command that would sign the wrong image. It
			// returns "" for Tier 3, so Tier 3's published output is
			// unchanged, and Tier 4 keeps its own branch above.
			fmt.Fprintf(a.out, "  ./course release sign%s\n", signCommandSuffix(tier, variant))
		}
		return nil
	}

	release, err := a.publishFirmwareImage(variant, buildDir, filepath.Base(appDir))
	if err != nil {
		return err
	}

	fmt.Fprintf(a.out, "Result: built %s release %s, %d bytes\n",
		variant.label, variant.releaseID, release["image_size"])
	if isLoopback(host) {
		fmt.Fprintln(a.out, "Note: this image points at a loopback address and cannot reach the service from a board.")
		fmt.Fprintln(a.out, "Note: run ./course setup --bind <this host's private address> and build again.")
	}
	return nil
}

// writeFirmwareConfig turns the generated Course environment into one Kconfig
// fragment for the Zephyr build. The passphrase is read from the ignored
// secrets directory and never printed.
func (a *app) writeFirmwareConfig(variant firmwareVariant, tier string) (string, string, error) {
	var config struct {
		OTAURL string `json:"ota_url"`
	}
	configPath := filepath.Join(a.root, a.manifest.Paths.State, "device-config.json")
	if err := readJSON(configPath, &config); err != nil {
		return "", "", errors.New("run ./course setup before building firmware")
	}
	target, err := url.Parse(config.OTAURL)
	if err != nil {
		return "", "", fmt.Errorf("generated device configuration holds an unusable OTA address: %w", err)
	}
	host := target.Hostname()
	port := target.Port()
	if port == "" {
		port = strconv.Itoa(a.manifest.Runtime.OTAPort)
	}
	if net.ParseIP(host) == nil {
		return "", "", fmt.Errorf("the OTA address must be a literal IP address, not %q", host)
	}

	ssid, psk, err := a.readWiFiSecret()
	if err != nil {
		return "", "", err
	}
	if ssid == "" {
		fmt.Fprintln(a.errOut, "Warning: no course Wi-Fi network is configured, so this image stays offline.")
		fmt.Fprintln(a.errOut, "Warning: run ./course setup --wifi-ssid <name> --wifi-psk <passphrase>.")
	}

	dir := filepath.Join(a.root, a.manifest.Paths.State, "firmware")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	body := fmt.Sprintf(`# Generated by ./course build firmware --tier %s --variant %s. Do not edit or commit.
CONFIG_COURSE_WIFI_SSID=%q
CONFIG_COURSE_WIFI_PSK=%q
CONFIG_COURSE_OTA_HOST=%q
CONFIG_COURSE_OTA_PORT=%s
CONFIG_COURSE_DEVICE_ID=%q
CONFIG_COURSE_RELEASE_ID=%q
CONFIG_COURSE_IMAGE_LABEL=%q
CONFIG_COURSE_BEACON_STATE=%q
`, tier, variant.label, ssid, psk, host, port,
		a.manifest.Devices["reference_beacon"].SyntheticID,
		variant.releaseID, variant.label, variant.beaconState)

	// A tier that verifies a service also needs the name to require and the
	// fingerprint of the anchor it was built with, so the board can print the
	// fingerprint at boot and a stale anchor diagnoses itself.
	if tier != "00" {
		anchor, err := coursepki.AnchorFingerprint(a.pkiDir())
		if err != nil {
			return "", "", errors.New("run ./course setup before building firmware that verifies a service")
		}
		body += fmt.Sprintf(`CONFIG_COURSE_OTA_SERVICE_NAME=%q
CONFIG_COURSE_OTA_TLS_PORT=%d
CONFIG_COURSE_TRUST_ANCHOR_FINGERPRINT=%q
`, coursepki.ServiceName, a.manifest.Runtime.TLSPort, anchor)
	}

	// From Tier 3 the board also reports which image verification key its
	// build trusted. The application cannot see what the bootloader holds, so
	// this is a claim about the build; main.c says so on the line beneath it.
	if tierSignsItsOwnImage(tier) {
		fingerprint, err := a.keyFingerprint(a.publicKeyPath())
		if err != nil {
			return "", "", errors.New("run ./course keys create release before building signed firmware")
		}
		body += fmt.Sprintf("CONFIG_COURSE_SIGNING_KEY_FINGERPRINT=%q\n", fingerprint)
	}

	// Tier 4 decides what to install from signed metadata, so the build has to
	// state the three facts that decision is made against.
	//
	// The counter comes from the variant, which is the same constant that
	// reaches imgtool's --security-counter and the manifest's security_counter
	// field. One value, three places, and no way for them to disagree: an
	// application that refused a release its own image TLV would have accepted
	// would be a bug nobody could see from the console.
	//
	// The hardware revision is asserted here and nowhere read. The channel is
	// a policy choice, not a property of the device.
	if tier == "04" || tier == "05" || tier == "06" {
		body += fmt.Sprintf(`CONFIG_COURSE_SECURITY_COUNTER=%d
CONFIG_COURSE_HARDWARE_REVISION=%d
CONFIG_COURSE_RELEASE_CHANNEL=%q
`, variant.securityCounter, tier04HardwareRevision, tier04Channel)
	}

	// Tier 5 adds the two facts that are about this build rather than about
	// the release it carries.
	//
	// The trial behaviour selects one arm of the Kconfig choice, which is the
	// only difference between the five images this tier publishes.
	//
	// The source revision travels twice: here, so the application can print
	// what it is running, and in a protected MCUboot TLV at tag 0x00A0 that
	// imgtool writes at signing time, so the bootloader can say what it is
	// swapping in. Both copies are covered by the image signature. It
	// identifies the build and not the release, and a Learner's own build
	// carries their hash and will usually be dirty.
	if tier == "05" || tier == "06" {
		symbol, err := trialBehaviourSymbol(variant.trialBehaviour)
		if err != nil {
			return "", "", err
		}
		body += fmt.Sprintf("%s=y\n", symbol)
		body += fmt.Sprintf("CONFIG_COURSE_HEALTH_GATE_SECONDS=%d\n", tier05HealthGateSeconds)
		body += fmt.Sprintf("CONFIG_COURSE_SOURCE_REVISION=%q\n", a.sourceRevision())
	}

	// Tier 6 selects which identity this image carries. There are two arms and
	// deliberately no third that falls back from one to the other: "failed
	// enrollment silently falls back to shared identity" is a stated failure
	// criterion in section 11.
	if tier == "06" {
		symbol, err := identityModelSymbol(variant.identityModel)
		if err != nil {
			return "", "", err
		}
		body += fmt.Sprintf("%s=y\n", symbol)
	}

	// The filename carries the tier as well as the variant. Tier 0 and Tier 2
	// both have a variant called "baseline", and a shared path meant the last
	// build won: building Tier 2 and then flashing Tier 0 re-configured the
	// Tier 0 image against Tier 2's file and died on the TLS symbols Tier 0
	// does not define.
	path := filepath.Join(dir, "tier-"+tier+"-"+variant.label+".conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", "", err
	}
	fmt.Fprintf(a.out, "Generated: %s for %s:%s, network %q\n",
		path, host, port, ssid)
	return path, host, nil
}

// zephyrWorkspace mirrors the default in scripts/build-zephyr-baseline.sh so
// the helper knows where the build wrote its image.
func (a *app) zephyrWorkspace() string {
	if workspace := os.Getenv("ZEPHYR_WORKSPACE"); workspace != "" {
		return workspace
	}
	return filepath.Join(filepath.Dir(a.root), "zephyr-v4.4.2")
}

func (a *app) readWiFiSecret() (string, string, error) {
	path := filepath.Join(a.root, a.manifest.Paths.Secrets, "wifi.conf")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return values["CONFIG_COURSE_WIFI_SSID"], values["CONFIG_COURSE_WIFI_PSK"], nil
}

// publishFirmwareImage copies the MCUboot-wrapped image into the release
// directory and records it. The baseline build also becomes the seed the OTA
// service serves, so a fixture reset returns the device to it.
func (a *app) publishFirmwareImage(variant firmwareVariant, buildDir, appName string) (map[string]any, error) {
	source := filepath.Join(buildDir, appName, "zephyr", "zephyr.signed.bin")
	image, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("the build produced no MCUboot image: %w", err)
	}
	releaseDir := filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "releases")
	if err := os.MkdirAll(releaseDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(releaseDir, variant.imageName), image, 0o600); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(image)
	release := map[string]any{
		"schema_version": 1, "release_id": variant.releaseID, "version": variant.version,
		"board": a.manifest.Devices["reference_beacon"].Board, "image_path": variant.imageName,
		"image_sha256": hex.EncodeToString(sum[:]), "image_size": len(image),
		"mutable": true, "signed": false,
	}
	otaState := filepath.Join(a.root, a.manifest.Paths.State, "ota")
	if err := os.MkdirAll(otaState, 0o700); err != nil {
		return nil, err
	}
	names := []string{"built-" + variant.label + ".json"}
	if variant.label == "baseline" {
		names = append(names, "seed-release.json", "current-release.json")
	}
	for _, name := range names {
		if err := writeJSON(filepath.Join(otaState, name), release, 0o600); err != nil {
			return nil, err
		}
	}
	return release, nil
}

// service manages the OTA service as a plain process inside the dev
// container. The container publishes the port to the host, so a physical
// ESP32-C6 reaches the service over the host's private address while this
// process only ever listens inside the container.
func (a *app) service(args []string) error {
	if len(args) == 0 {
		return errors.New("service requires start, stop, or status")
	}
	switch args[0] {
	case "start":
		https := false
		present := ""
		rangeBehaviour := ""
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--https":
				https = true
			case "--present":
				if i+1 >= len(args) {
					return errors.New("--present requires service, untrusted, or wrong-name")
				}
				present = args[i+1]
				i++
			case "--range":
				if i+1 >= len(args) {
					return errors.New("--range requires ignore or interrupt:<bytes>")
				}
				rangeBehaviour = args[i+1]
				i++
			default:
				return fmt.Errorf("unknown service start option %s", args[i])
			}
		}
		if present != "" && !https {
			return errors.New("--present applies only with --https")
		}
		if err := checkRangeBehaviour(rangeBehaviour); err != nil {
			return err
		}
		return a.serviceStart(https, present, rangeBehaviour)
	case "stop":
		return a.serviceStop()
	case "status":
		return a.serviceStatus()
	case "certificate":
		return a.serviceCertificate()
	default:
		return fmt.Errorf("unknown service command %q", args[0])
	}
}

func (a *app) servicePIDPath() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "ota.pid")
}

func (a *app) serviceLogPath() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "ota.log")
}

// runningService returns the supervised process when it is still alive. A
// stale PID file is removed, because a container restart leaves one behind.
func (a *app) runningService() (*os.Process, bool) {
	data, err := os.ReadFile(a.servicePIDPath())
	if err != nil {
		return nil, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		os.Remove(a.servicePIDPath())
		return nil, false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(a.servicePIDPath())
		return nil, false
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		os.Remove(a.servicePIDPath())
		return nil, false
	}
	return process, true
}

// serviceModePath records which transport the running service uses, so status
// can report it without guessing.
func (a *app) serviceModePath() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "service-mode")
}

func (a *app) serviceMode() string {
	data, err := os.ReadFile(a.serviceModePath())
	if err != nil {
		return "http"
	}
	return strings.TrimSpace(string(data))
}

// presentedCertificate maps the name a Learner types to the material the
// service will hold.
//
// The two wrong ones exist so the device can be watched refusing them. They are
// the only way to test the device's half of this control, because the check
// runs on the device and nothing on the host can stand in for it.
var presentedCertificate = map[string][2]string{
	"service":    {coursepki.ServiceCert, coursepki.ServiceKey},
	"untrusted":  {coursepki.UntrustedCert, coursepki.UntrustedKey},
	"wrong-name": {coursepki.WrongNameCert, coursepki.WrongNameKey},
}

// checkRangeBehaviour rejects a misspelled misbehaviour rather than starting a
// service that quietly behaves correctly.
//
// A Learner who typed the option expects the service to answer badly. A
// service that silently answered well would look like the device's control
// working, which is the failure this whole family of options exists to avoid.
func checkRangeBehaviour(behaviour string) error {
	if behaviour == "" || behaviour == "ignore" {
		return nil
	}
	if rest, found := strings.CutPrefix(behaviour, "interrupt:"); found {
		if n, err := strconv.Atoi(rest); err == nil && n > 0 {
			return nil
		}
	}
	return fmt.Errorf("unknown --range value %q; use ignore or interrupt:<bytes>", behaviour)
}

func (a *app) serviceStart(https bool, present string, rangeBehaviour string) error {
	if _, running := a.runningService(); running {
		return errors.New("the OTA service is already running; run ./course service stop first")
	}
	settings, err := a.serviceSettings()
	if err != nil {
		return err
	}
	binary := filepath.Join(a.root, a.manifest.Paths.Build, "ota")
	build := []string{"go", "build", "-o", binary, "./services/ota/cmd/ota"}
	fmt.Fprintf(a.out, "+ %s\n", strings.Join(build, " "))
	if err := runAttached(a.root, a.out, a.errOut, build[0], build[1:]...); err != nil {
		return err
	}
	log, err := os.OpenFile(a.serviceLogPath(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer log.Close()
	arguments := []string{}
	if https {
		if !coursepki.Exists(a.pkiDir()) {
			return errors.New("no Course certificate authority exists; run ./course setup first")
		}
		arguments = append(arguments, "--https")
		if present == "" {
			present = "service"
		}
		if present != "service" {
			fmt.Fprintf(a.out, "This service will present the %s certificate on purpose, so a device can be watched refusing it.\n", present)
			fmt.Fprintln(a.out, "Nothing that verifies correctly will talk to it. Start it again without --present to return to normal.")
		}
	}
	fmt.Fprintf(a.out, "+ %s %s\n", binary, strings.Join(arguments, " "))
	command := exec.Command(binary, arguments...)
	command.Dir = a.root
	command.Stdout = log
	command.Stderr = log
	// The service listens on every address inside the container. The container
	// publishes the port, so this wildcard never reaches the host network by
	// itself. COURSE_ALLOW_CONTAINER_WILDCARD tells the service that is
	// deliberate rather than a misconfigured bind.
	command.Env = append(os.Environ(),
		"COURSE_ID="+a.manifest.Course.ID,
		"COURSE_TIER=00",
		"COURSE_ENVIRONMENT_ID="+settings.environmentID,
		"COURSE_BIND=0.0.0.0",
		"COURSE_ALLOW_CONTAINER_WILDCARD=1",
		"COURSE_PORT="+settings.port,
		"COURSE_STATE_DIR="+filepath.Join(a.root, a.manifest.Paths.State, "ota"),
		"COURSE_RELEASE_DIR="+filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "releases"),
		"COURSE_RANGE_BEHAVIOUR="+rangeBehaviour,
	)
	if https {
		material, ok := presentedCertificate[present]
		if !ok {
			return fmt.Errorf("unknown certificate %q; use service, untrusted, or wrong-name", present)
		}
		command.Env = append(command.Env,
			"COURSE_TLS_PORT="+strconv.Itoa(a.manifest.Runtime.TLSPort),
			"COURSE_TLS_CERT="+filepath.Join(a.pkiDir(), material[0]),
			"COURSE_TLS_KEY="+filepath.Join(a.pkiDir(), material[1]),
			"COURSE_SERVICE_NAME="+coursepki.ServiceName,
		)
	}
	mode := "http"
	if https {
		mode = "https"
	}
	if err := os.WriteFile(a.serviceModePath(), []byte(mode), 0o600); err != nil {
		return err
	}
	// A new process group keeps the service alive after ./course exits and
	// lets stop signal the whole group.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return err
	}
	if err := os.WriteFile(a.servicePIDPath(), []byte(strconv.Itoa(command.Process.Pid)), 0o600); err != nil {
		return err
	}
	go command.Wait()
	target := a.serviceURL()
	for i := 0; i < 40; i++ {
		if response, err := a.client.Get(target + "/health"); err == nil && response.StatusCode == http.StatusOK {
			response.Body.Close()
			fmt.Fprintln(a.out, "Result: OTA service is healthy")
			if https {
				fmt.Fprintf(a.out, "Release records, firmware, and events: https://%s:%d\n",
					coursepki.ServiceName, a.manifest.Runtime.TLSPort)
				fmt.Fprintf(a.out, "Health and the Course environment marker stay on http://%s:%s\n",
					settings.advertised, settings.port)
				fmt.Fprintln(a.out, "Next: ./course service certificate")
				return nil
			}
			fmt.Fprintf(a.out, "Reachable by the Reference product at %s\n", a.advertisedURL(settings))
			fmt.Fprintln(a.out, "Next: ./course attack list")
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	a.serviceStop()
	return fmt.Errorf("OTA service did not become healthy, see %s", a.serviceLogPath())
}

func (a *app) serviceStop() error {
	process, running := a.runningService()
	if !running {
		fmt.Fprintln(a.out, "Result: the OTA service is not running")
		return nil
	}
	fmt.Fprintf(a.out, "+ kill %d\n", process.Pid)
	if err := syscall.Kill(-process.Pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	for i := 0; i < 40; i++ {
		if _, still := a.runningService(); !still {
			os.Remove(a.servicePIDPath())
			fmt.Fprintln(a.out, "Result: the OTA service stopped")
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	syscall.Kill(-process.Pid, syscall.SIGKILL)
	os.Remove(a.servicePIDPath())
	fmt.Fprintln(a.out, "Result: the OTA service was forced to stop")
	return nil
}

func (a *app) serviceStatus() error {
	settings, err := a.serviceSettings()
	if err != nil {
		return err
	}
	process, running := a.runningService()
	if !running {
		return errors.New("the OTA service is not running; run ./course service start")
	}
	fmt.Fprintf(a.out, "Process: ota running as pid %d\n", process.Pid)
	target := a.serviceURL()
	fmt.Fprintf(a.out, "+ curl --fail %s/health\n", target)
	response, err := a.client.Get(target + "/health")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned %s", response.Status)
	}
	fmt.Fprintln(a.out, "Result: OTA service is healthy")
	if a.serviceMode() == "https" {
		fmt.Fprintf(a.out, "Transport: release records, firmware, and events on TLS port %d, presenting %s\n",
			a.manifest.Runtime.TLSPort, coursepki.ServiceName)
		fmt.Fprintln(a.out, "Transport: health and the Course environment marker stay on plain HTTP")
		return nil
	}
	fmt.Fprintf(a.out, "Transport: plain HTTP, every endpoint readable by anyone on this network\n")
	fmt.Fprintf(a.out, "Reachable by the Reference product at %s\n", a.advertisedURL(settings))
	return nil
}

// serviceCertificate shows a Learner what the service presents, and what the
// device will compare it against. It reports what the certificate claims. It
// does not say whether anything trusts it, because that is the device's
// decision and the whole subject of the tier.
func (a *app) serviceCertificate() error {
	dir := a.pkiDir()
	if !coursepki.Exists(dir) {
		return errors.New("no Course certificate authority exists; run ./course setup first")
	}
	anchor, err := coursepki.AnchorFingerprint(dir)
	if err != nil {
		return err
	}
	a.context("generated certificate material")

	fmt.Fprintln(a.out, "The Course certificate authority. Generated for this Course environment, and nothing else trusts it:")
	description, err := coursepki.Describe(filepath.Join(dir, coursepki.CourseCACert))
	if err != nil {
		return err
	}
	fmt.Fprint(a.out, description)
	fmt.Fprintf(a.out, "\nThis fingerprint is compiled into the Tier 2 firmware as its trust anchor: %s\n", anchor)
	fmt.Fprintln(a.out, "The board prints the same value at boot. If the two differ, the board was built against a different Course environment.")

	fmt.Fprintln(a.out, "\nThe certificate the service presents:")
	description, err = coursepki.Describe(filepath.Join(dir, coursepki.ServiceCert))
	if err != nil {
		return err
	}
	fmt.Fprint(a.out, description)
	fmt.Fprintf(a.out, "\nNote the DNS name and the empty IP address list. The device connects to a literal address and then requires the certificate to carry the name %s.\n", coursepki.ServiceName)
	fmt.Fprintln(a.out, "The name is never looked up. There is no resolver on the device. It is the value the certificate is compared against.")

	fmt.Fprintln(a.out, "\nThe two certificates the bypass tests use:")
	for _, entry := range []struct {
		file string
		why  string
	}{
		{coursepki.UntrustedCert, "correct name, issued by an authority the device does not trust"},
		{coursepki.WrongNameCert, "issued by the trusted authority, wrong name"},
	} {
		fmt.Fprintf(a.out, "\n%s, %s:\n", entry.file, entry.why)
		description, err = coursepki.Describe(filepath.Join(dir, entry.file))
		if err != nil {
			return err
		}
		fmt.Fprint(a.out, description)
	}
	fmt.Fprintf(a.out, "\nEvery private key stays in %s. Git ignores it. Never commit it.\n",
		filepath.Join(a.manifest.Paths.Secrets, "pki"))
	return nil
}

func (a *app) device(args []string) error {
	if len(args) == 0 {
		return errors.New("device requires flash, logs, status, dump, reset, update, or recover")
	}
	switch args[0] {
	case "flash":
		return a.deviceFlash(args[1:])
	case "logs":
		return a.deviceLogs()
	case "dump":
		return a.deviceDump(args[1:])
	case "reset":
		return a.deviceReset()
	case "status":
		return a.deviceStatus()
	case "update":
		fmt.Fprintln(a.out, "The device drives its own update. It reports status, reads the update")
		fmt.Fprintln(a.out, "assignment, and installs any release the service names:")
		fmt.Fprintln(a.out, "+ GET /v1/releases/current")
		fmt.Fprintln(a.out, "+ GET /v1/firmware/{name}")
		fmt.Fprintln(a.out, "+ POST /v1/devices/{device_id}/events")
		fmt.Fprintln(a.out, "Change the assignment with ./course attack run tier-00/altered-image.")
		fmt.Fprintln(a.out, "Watch the result with ./course device logs.")
		return nil
	case "recover":
		return errors.New("Tier 0 has no recovery path: the swap is permanent and there is no test boot; reflash with ./course device flash")
	default:
		return fmt.Errorf("unknown device command %q", args[0])
	}
}

// selectSerialDevice returns the one stable serial path for an attached
// board. It refuses to guess when several are present, because flashing the
// wrong device is not recoverable from inside this tool.
func (a *app) selectSerialDevice() (string, error) {
	dev := a.manifest.Devices["reference_beacon"]
	entries, err := os.ReadDir(dev.StableSerialPrefix)
	if err != nil {
		return a.fallbackSerialDevice(dev.StableSerialPrefix)
	}
	var found []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(strings.ToLower(name), "espressif") && strings.HasSuffix(name, "-if00") {
			found = append(found, filepath.Join(dev.StableSerialPrefix, name))
		}
	}
	sort.Strings(found)
	switch len(found) {
	case 0:
		return a.fallbackSerialDevice(dev.StableSerialPrefix)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("%d Espressif serial devices are attached; detach all but the course board", len(found))
	}
}

// fallbackSerialDevice covers a container that has the raw device node but not
// the stable by-id tree. It still refuses to guess between several boards.
func (a *app) fallbackSerialDevice(prefix string) (string, error) {
	matches, err := filepath.Glob("/dev/ttyACM*")
	if err != nil || len(matches) == 0 {
		return "", fmt.Errorf("no board is attached under %s; hardware steps stay pending", prefix)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("%d serial devices are attached and %s is unavailable; detach all but the course board", len(matches), prefix)
	}
	fmt.Fprintf(a.errOut, "Warning: %s is unavailable, so %s was selected instead.\n", prefix, matches[0])
	fmt.Fprintln(a.errOut, "Warning: that path is not stable across reconnections.")
	return matches[0], nil
}

func (a *app) deviceFlash(args []string) error {
	name := "baseline"
	tier := "00"
	for len(args) > 0 {
		if len(args) < 2 {
			return fmt.Errorf("option %s requires a value", args[0])
		}
		switch args[0] {
		case "--variant":
			name = args[1]
		case "--tier":
			tier = normalizeTier(args[1])
		default:
			return fmt.Errorf("unknown flash option %s", args[0])
		}
		args = args[2:]
	}
	variants := variantsForTier(tier)
	variant, ok := variants[name]
	if !ok {
		return fmt.Errorf("unknown firmware variant %q for tier %s", name, tier)
	}
	appDir, ok := firmwareApps[tier]
	if !ok {
		return fmt.Errorf("tier %s has no firmware application", tier)
	}

	device, err := a.selectSerialDevice()
	if err != nil {
		return err
	}
	buildDir := filepath.Join(a.zephyrWorkspace(), "build", filepath.Base(appDir)+"-"+variant.label)
	if _, err := os.Stat(filepath.Join(buildDir, "domains.yaml")); err != nil {
		return fmt.Errorf("no sysbuild output for the tier %s %s image; run ./course build firmware --tier %s --variant %s first", tier, variant.label, tier, variant.label)
	}

	// From Tier 3 the two images come from two builds, so west flash cannot
	// place them: it would write the bootloader sysbuild produced, which does
	// not verify anything, and the unsigned application beside it.
	if tierSignsItsOwnImage(tier) {
		return a.flashSignedRelease(device, buildDir, variant, tier)
	}

	workspace := a.zephyrWorkspace()
	west := filepath.Join(workspace, ".venv", "bin", "west")
	fmt.Fprintf(a.out, "+ %s flash -d %s --esp-device %s\n", west, buildDir, device)
	fmt.Fprintln(a.out, "This writes MCUboot and the application to normal flash only.")
	fmt.Fprintln(a.out, "It runs no eFuse, secure boot, or flash encryption command.")
	// west flash shells out to esptool, which lives in the workspace virtual
	// environment rather than on the system path.
	return runAttachedFrom(a.root, workspace, a.out, a.errOut,
		[]string{
			"ZEPHYR_BASE=" + filepath.Join(workspace, "zephyr"),
			"PATH=" + filepath.Join(workspace, ".venv", "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		},
		west, "flash", "-d", buildDir, "--esp-device", device)
}

func (a *app) deviceLogs() error {
	device, err := a.selectSerialDevice()
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "+ python3 -m serial.tools.miniterm %s 115200\n", device)
	fmt.Fprintln(a.out, "Leave with Ctrl-] and reset the board to see the boot banner.")
	python := filepath.Join(a.zephyrWorkspace(), ".venv", "bin", "python")
	if _, err := os.Stat(python); err != nil {
		python = "python3"
	}
	return runAttached(a.root, a.out, a.errOut, python, "-m", "serial.tools.miniterm", device, "115200")
}

func (a *app) attack(args []string) error {
	if len(args) == 0 {
		return errors.New("attack requires list, run, or reset")
	}
	switch args[0] {
	case "list":
		ids := make([]string, 0, len(a.manifest.Fixtures))
		for id := range a.manifest.Fixtures {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fixture := a.manifest.Fixtures[id]
			fmt.Fprintf(a.out, "%s\n  expected: %s\n  hardware required: %t\n", id, fixture.ExpectedEffect, fixture.HardwareRequired)
		}
		return nil
	case "run":
		return a.attackRun(args[1:])
	case "reset":
		if len(args) != 2 {
			return errors.New("attack reset requires one fixture identifier")
		}
		return a.resetFixture(args[1])
	default:
		return fmt.Errorf("unknown attack command %q", args[0])
	}
}

func (a *app) attackRun(args []string) error {
	if len(args) == 0 {
		return errors.New("attack run requires a fixture identifier")
	}
	id := args[0]
	f, ok := a.manifest.Fixtures[id]
	if !ok {
		return fmt.Errorf("unknown fixture %q", id)
	}
	executeID := ""
	target := f.Target
	selectedInterface := f.Interface
	interfaceSpecified := false
	hold := 0
	selected := ""
	allowed, option := f.selectors()
	target = a.serviceURL()
	for i := 1; i < len(args); i++ {
		if i+1 >= len(args) {
			return fmt.Errorf("option %s requires a value", args[i])
		}
		switch args[i] {
		case "--execute":
			executeID = args[i+1]
		case "--target":
			target = args[i+1]
		case "--interface":
			selectedInterface = args[i+1]
			interfaceSpecified = true
		case "--image", "--release":
			if len(allowed) == 0 {
				return fmt.Errorf("%s takes no %s", id, args[i])
			}
			if args[i] != option {
				return fmt.Errorf("%s selects its artifact with %s, not %s", id, option, args[i])
			}
			selected = args[i+1]
		case "--hold":
			seconds, err := strconv.Atoi(args[i+1])
			if err != nil || seconds < 0 || seconds > maxFixtureHoldSeconds {
				return fmt.Errorf("--hold must be between 0 and %d seconds", maxFixtureHoldSeconds)
			}
			hold = seconds
		default:
			return fmt.Errorf("unknown attack option %s", args[i])
		}
		i++
	}
	if err := validateTarget(target); err != nil {
		return err
	}
	if selectedInterface == "" {
		return errors.New("an explicit interface is required")
	}
	if err := validateSelectedInterface(target, selectedInterface, interfaceSpecified); err != nil {
		return err
	}
	// The artifact is chosen from the manifest, never supplied as a path. A
	// fixture that accepted a filename would be a way to make the course serve
	// arbitrary bytes to a board.
	if len(allowed) > 0 {
		if selected == "" {
			names := make([]string, 0, len(allowed))
			for name := range allowed {
				names = append(names, name)
			}
			sort.Strings(names)
			return fmt.Errorf("%s needs %s, one of: %s", id, option, strings.Join(names, ", "))
		}
		if _, ok := allowed[selected]; !ok {
			return fmt.Errorf("unknown %s %q for %s", strings.TrimPrefix(option, "--"), selected, id)
		}
	}
	if _, err := os.Stat(a.fixtureBlockPath(id)); err == nil {
		return fmt.Errorf("fixture is blocked after a failed reset; run %s", f.Reset)
	}
	env, fingerprint, err := a.matchMarker(target)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Fixture: %s\nTarget: %s\nInterface: %s\n", id, target, selectedInterface)
	fmt.Fprintf(a.out, "Marker matched: course_id=%s environment_id=%s tier=%s synthetic_data=%t\n", env.CourseID, env.EnvironmentID, env.Tier, env.SyntheticData)
	fmt.Fprintf(a.out, "Expected insecure effect: %s\nChanges: %s\nReset: %s\n", f.ExpectedEffect, strings.Join(f.Changes, ", "), f.Reset)
	plans := fixturePlan
	proofs := fixtureProves
	if strings.HasPrefix(id, "tier-02/") {
		plans = tier02Plan
		proofs = tier02Proves
	}
	if strings.HasPrefix(id, "tier-03/") {
		plans = tier03Plan
		proofs = tier03Proves
	}
	if strings.HasPrefix(id, "tier-04/") {
		plans = tier04Plan
		proofs = tier04Proves
	}
	if strings.HasPrefix(id, "tier-06/") {
		plans = tier06Plan
		proofs = tier06Proves
	}
	if plan, ok := plans[id]; ok {
		fmt.Fprintln(a.out, "Plan:")
		for i, line := range plan {
			fmt.Fprintf(a.out, "  %d. %s\n", i+1, line)
		}
	}
	if proves, ok := proofs[id]; ok {
		fmt.Fprintln(a.out, "Weaknesses this demonstrates:")
		for _, line := range proves {
			fmt.Fprintf(a.out, "  %s\n", line)
		}
	}
	if executeID == "" {
		fmt.Fprintln(a.out, "Result: dry run only")
		fmt.Fprintf(a.out, "Execute: %s\n", a.fixtureCommand(id, selected))
		return nil
	}
	if executeID != id {
		return errors.New("--execute value must exactly match the fixture identifier")
	}
	if hold > 0 && !f.HardwareRequired {
		return fmt.Errorf("--hold applies only to a fixture that needs hardware; %s does not", id)
	}
	start := time.Now().UTC()
	a.selector = selected
	observed, limitation, artifactHashes, runErr := a.executeFixture(id, target, env)
	// A device polls on its own schedule. Without a hold, the reset below
	// restores the baseline release before any board can read the insecure
	// one, so the hardware effect could never be observed.
	if hold > 0 && runErr == nil {
		fmt.Fprintf(a.out, "Holding the insecure state for %d seconds so an attached device can poll.\n", hold)
		fmt.Fprintf(a.out, "Watch it with ./course device logs in another terminal.\n")
		time.Sleep(time.Duration(hold) * time.Second)
	}
	resetErr := a.resetFixtureState(id, target, env)
	result := "passed"
	resetResult := "passed"
	if runErr != nil {
		result = "failed"
	}
	if resetErr != nil {
		result = "failed"
		resetResult = "failed"
		_ = os.MkdirAll(filepath.Dir(a.fixtureBlockPath(id)), 0o700)
		_ = writeJSON(a.fixtureBlockPath(id), map[string]any{"fixture": id, "failed_at": time.Now().UTC(), "reason": resetErr.Error()}, 0o600)
	}
	record := map[string]any{
		"schema_version": 1, "fixture_id": id, "marker_fingerprint": fingerprint,
		"target": target, "selected_interface": selectedInterface, "started_at": start,
		"ended_at": time.Now().UTC(), "command": a.fixtureCommand(id, selected), "selector": selected,
		"expected_effect": f.ExpectedEffect, "observed_effect": observed, "result": result,
		"reset_result": resetResult, "artifact_hashes": artifactHashes, "hardware_limitation": limitation,
	}
	evidencePath, evidenceErr := a.writeAttackEvidence(id, record)
	if evidenceErr != nil {
		return evidenceErr
	}
	fmt.Fprintf(a.out, "Evidence: %s\nReset result: %s\n", evidencePath, resetResult)
	if resetErr != nil {
		return fmt.Errorf("automatic reset failed: %v; run %s", resetErr, f.Reset)
	}
	if runErr != nil {
		return runErr
	}
	fmt.Fprintf(a.out, "Result: %s\n", observed)
	return nil
}

// An attack a Learner cannot see teaches nothing. These helpers narrate a
// fixture as it runs: every request it sends, every answer it gets back, and
// what each one means. The Result line at the end is the summary, not the
// lesson.

func (a *app) step(number int, what string) {
	fmt.Fprintf(a.out, "\nStep %d. %s\n", number, what)
}

func (a *app) sent(method, target string) {
	fmt.Fprintf(a.out, "  -> %s %s\n", method, target)
}

func (a *app) sentBody(label string, value any) {
	fmt.Fprintf(a.out, "     %s\n", label)
	a.showJSON(value)
}

func (a *app) got(format string, args ...any) {
	fmt.Fprintf(a.out, "  <- %s\n", fmt.Sprintf(format, args...))
}

func (a *app) note(format string, args ...any) {
	fmt.Fprintf(a.out, "     %s\n", fmt.Sprintf(format, args...))
}

func (a *app) showJSON(value any) {
	data, err := json.MarshalIndent(value, "     ", "  ")
	if err != nil {
		return
	}
	fmt.Fprintf(a.out, "     %s\n", string(data))
}

// showBytes shows what the image looks like on the wire. Text content is
// printed as text; a compiled image is printed as hex, because a screen of
// dots teaches nothing. Either way the point is that it is readable at all.
func (a *app) showBytes(body []byte) {
	const preview = 64
	shown := body
	truncated := false
	if len(shown) > preview {
		shown, truncated = shown[:preview], true
	}
	printable := 0
	for _, c := range shown {
		if c == '\n' || c == '\t' || (c >= 32 && c <= 126) {
			printable++
		}
	}
	suffix := ""
	if truncated {
		suffix = " ..."
	}
	if len(shown) > 0 && printable*10 >= len(shown)*9 {
		text := strings.ReplaceAll(string(shown), "\n", "\\n")
		fmt.Fprintf(a.out, "     first %d bytes as text: %s%s\n", len(shown), text, suffix)
		return
	}
	fmt.Fprintf(a.out, "     first %d bytes as hex: %s%s\n", len(shown), hex.EncodeToString(shown), suffix)
	fmt.Fprintln(a.out, "     A compiled image, sent in the clear. Readable, copyable, and modifiable in transit.")
}

// fixtureProves links each fixture to the Weakness ledger identifiers it
// demonstrates, so the Learner never has to guess which row to fill in.
var tier02Proves = map[string][]string{
	"tier-02/plaintext-inspection": {
		"T0-W-01  HTTP has no confidentiality. Closed for release data by this tier. The marker stays readable by design.",
	},
	"tier-02/service-impersonation": {
		"T0-W-03  The device trusted an unauthenticated service. Closed by this tier.",
	},
	"tier-02/name-mismatch": {
		"T0-W-03  The device trusted an unauthenticated service. This shows the second half of the check.",
	},
}

var tier02Plan = map[string][]string{
	"tier-02/plaintext-inspection": {
		"Ask the plain HTTP port for the release record, as Tier 0 did, and show it is no longer there.",
		"Ask the TLS port with the trust anchor and the required name, and read the record.",
		"Ask the TLS port by address without the name, and watch it refused.",
		"Record the bytes on the wire, if the container allows capture.",
	},
	"tier-02/service-impersonation": {
		"Start a manifest-owned imposter holding a certificate for the right name from the wrong authority.",
		"Point the generated device configuration at it.",
		"Ask it for a release, checking the certificate the way the device does, and watch it refused.",
		"Show the certificate it was holding.",
	},
	"tier-02/name-mismatch": {
		"Serve a certificate genuinely issued by the trusted authority, for another name.",
		"Connect requiring the name the device requires, and watch it refused.",
		"Notice that the chain check passed and the name check did not.",
	},
}

var fixtureProves = map[string][]string{
	"tier-00/plaintext-inspection": {
		"T0-W-01  HTTP has no confidentiality. Everything above was readable by anyone on this network.",
	},
	"tier-00/device-id-spoofing": {
		"T0-W-02  The service trusts the device identifier inside the request body, not the sender.",
	},
	"tier-00/service-impersonation": {
		"T0-W-03  The device trusts any service that answers at the configured address.",
	},
	"tier-00/altered-image": {
		"T0-W-04  MCUboot accepts an unsigned image, so the device will run whatever arrives.",
		"T0-W-05  The release record is mutable, so anyone who can write it chooses the firmware.",
	},
}

// fixturePlan is what a dry run shows: the steps the fixture would take, in
// order, before the Learner commits to running it.
var fixturePlan = map[string][]string{
	"tier-00/plaintext-inspection": {
		"Ask the service which firmware release it is currently handing out.",
		"Download that firmware image and read its bytes.",
	},
	"tier-00/device-id-spoofing": {
		"Post a status event to one device's endpoint, naming a different device inside the body.",
		"Check which identifier the service recorded.",
	},
	"tier-00/service-impersonation": {
		"Start a second HTTP service that copies this course environment marker.",
		"Rewrite the generated device configuration to point at it.",
		"Ask the device's configured address for a release, and see whose answer comes back.",
	},
	"tier-00/altered-image": {
		"Build or reuse an altered, unsigned firmware image.",
		"Overwrite the current release record so the service hands out the altered image.",
		"Download the image again and confirm the service delivered the altered bytes.",
	},
}

func (a *app) executeFixture(id, target string, env environment) (string, string, map[string]string, error) {
	switch id {
	case "tier-06/clone-shared-identity":
		return a.cloneSharedIdentity(env)
	case "tier-00/plaintext-inspection":
		a.step(1, "Ask the service which firmware release it is handing out.")
		a.note("No credential is sent, because the service asks for none.")
		var release map[string]any
		a.sent(http.MethodGet, target+"/v1/releases/current")
		if err := a.getJSON(target+"/v1/releases/current", &release); err != nil {
			return "", "", nil, err
		}
		a.got("200 OK, and the whole record came back readable:")
		a.showJSON(release)
		a.note("This is plain HTTP. Anyone who can see this network sees exactly these fields.")
		name, _ := release["image_path"].(string)

		a.step(2, "Download the firmware image that record names.")
		a.sent(http.MethodGet, target+"/v1/firmware/"+url.PathEscape(name))
		response, err := a.client.Get(target + "/v1/firmware/" + url.PathEscape(name))
		if err != nil {
			return "", "", nil, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			return "", "", nil, err
		}
		if response.StatusCode != http.StatusOK || len(body) == 0 {
			return "", "", nil, errors.New("firmware bytes were not readable")
		}
		sum := sha256.Sum256(body)
		a.got("%d OK, %d bytes of firmware, with no encryption of any kind.", response.StatusCode, len(body))
		a.showBytes(body)
		a.note("sha256: %s", hex.EncodeToString(sum[:]))
		a.note("Nothing proved who asked for this image, and nothing proves who built it.")
		return fmt.Sprintf("plaintext release version %v and %d firmware bytes were readable", release["version"], len(body)), "", map[string]string{name: "sha256:" + hex.EncodeToString(sum[:])}, nil
	case "tier-00/device-id-spoofing":
		dev := a.manifest.Devices["reference_beacon"]
		a.step(1, "Report a machine state, but lie about which device is reporting.")
		a.note("The address names %s. The body claims to be %s.", dev.SyntheticID, dev.SpoofID)
		a.note("A real device would have to prove which one it is. Nothing here asks it to.")
		event := map[string]any{"device_id": dev.SpoofID, "event_type": "status.observed", "boot_id": "synthetic-boot", "event_sequence": 1, "firmware_version": "0.0.0-insecure", "security_counter": 0, "machine_state": "fast", "result": "synthetic", "reason_code": "fixture"}
		data, _ := json.Marshal(event)
		a.sent(http.MethodPost, target+"/v1/devices/"+url.PathEscape(dev.SyntheticID)+"/events")
		a.sentBody("with this body:", event)
		request, _ := http.NewRequest(http.MethodPost, target+"/v1/devices/"+url.PathEscape(dev.SyntheticID)+"/events", bytes.NewReader(data))
		request.Header.Set("Content-Type", "application/json")
		response, err := a.client.Do(request)
		if err != nil {
			return "", "", nil, err
		}
		defer response.Body.Close()
		var result map[string]any
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			return "", "", nil, err
		}
		if response.StatusCode != http.StatusAccepted || result["accepted_device_id"] != dev.SpoofID {
			return "", "", nil, errors.New("service did not demonstrate body device_id trust")
		}

		a.step(2, "Read back which device the service believes reported.")
		a.got("%d Accepted, and the service recorded this:", response.StatusCode)
		a.showJSON(result)
		a.note("It stored %s, the identifier from the body, not %s from the address.", dev.SpoofID, dev.SyntheticID)
		a.note("One device just wrote history for another, and the audit record now lies.")
		return "service accepted the spoofed manifest-owned device identifier", "", map[string]string{}, nil
	case "tier-00/service-impersonation":
		return a.runImpersonation(env, target)
	case "tier-02/plaintext-inspection":
		return a.runTier02PlaintextInspection(env, target)
	case "tier-02/service-impersonation":
		return a.runTier02Impersonation(env, target)
	case "tier-02/name-mismatch":
		return a.runTier02NameMismatch(env, target)
	case "tier-03/hostile-image":
		return a.tier03HostileImage(target, env)
	case "tier-04/hostile-release":
		return a.tier04HostileRelease(target, env)
	case "tier-04/replay-release":
		return a.tier04ReplayRelease(target, env)
	case "tier-00/altered-image":
		a.step(1, "Take an altered, unsigned firmware image.")
		release, image, runnable, err := a.alteredImageRelease()
		if err != nil {
			return "", "", nil, err
		}
		name := release["image_path"].(string)
		sum := sha256.Sum256(image)
		if runnable {
			a.note("Using the real altered image you built with ./course build firmware --variant altered.")
		} else {
			a.note("Using a placeholder image. It cannot run on a board, but the service treats it the same.")
		}
		a.note("It is not signed. Nothing in it says who made it.")
		a.showBytes(image)
		a.note("sha256: %s", hex.EncodeToString(sum[:]))

		a.step(2, "Overwrite the record that decides which firmware every device installs.")
		a.note("The record is mutable and the service does not ask who is changing it.")
		data, _ := json.Marshal(release)
		a.sent(http.MethodPut, target+"/v1/releases/current")
		a.sentBody("replacing the current release with:", release)
		request, _ := http.NewRequest(http.MethodPut, target+"/v1/releases/current", bytes.NewReader(data))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Course-Environment-ID", env.EnvironmentID)
		response, err := a.client.Do(request)
		if err != nil {
			return "", "", nil, err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return "", "", nil, fmt.Errorf("mutable release update returned %s", response.Status)
		}
		a.got("%d OK. The service now hands out the altered image to every device that asks.", response.StatusCode)

		a.step(3, "Download it back, the way a device would.")
		a.sent(http.MethodGet, target+"/v1/firmware/"+name)
		response, err = a.client.Get(target + "/v1/firmware/" + name)
		if err != nil {
			return "", "", nil, err
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil || !bytes.Equal(body, image) {
			return "", "", nil, errors.New("altered image was not delivered unchanged")
		}
		a.got("%d OK, %d bytes, byte for byte the altered image.", response.StatusCode, len(body))
		a.note("A device receiving this has no way to tell it apart from a genuine release.")
		if runnable {
			return "altered unsigned image was built for the board and delivered by the service",
				"device acceptance needs a flashed ESP32-C6 that can reach this service",
				map[string]string{name: "sha256:" + hex.EncodeToString(sum[:])}, nil
		}
		return "altered unsigned placeholder image was generated and delivered by the service",
			"the placeholder image cannot run on a board; build one with ./course build firmware --variant altered",
			map[string]string{name: "sha256:" + hex.EncodeToString(sum[:])}, nil
	default:
		return "", "", nil, errors.New("fixture implementation unavailable")
	}
}

// alteredImageRelease prefers the MCUboot image built by
// `./course build firmware --variant altered`, because only a real image lets
// a board demonstrate that Tier 0 runs whatever the service offers. A host
// without the Zephyr toolchain still gets a placeholder, so the fixture keeps
// working in CI and on hosts with no board.
func (a *app) alteredImageRelease() (map[string]any, []byte, bool, error) {
	releaseDir := filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "releases")
	variant := firmwareVariants["altered"]

	var built map[string]any
	builtPath := filepath.Join(a.root, a.manifest.Paths.State, "ota", "built-altered.json")
	if err := readJSON(builtPath, &built); err == nil {
		image, err := os.ReadFile(filepath.Join(releaseDir, variant.imageName))
		if err == nil {
			return built, image, true, nil
		}
	}

	image := []byte("COURSE SYNTHETIC ALTERED FIRMWARE\nTier 00\nstate=fast\n")
	if err := os.WriteFile(filepath.Join(releaseDir, variant.imageName), image, 0o600); err != nil {
		return nil, nil, false, err
	}
	sum := sha256.Sum256(image)
	release := map[string]any{
		"schema_version": 1, "release_id": variant.releaseID, "version": variant.version,
		"board": a.manifest.Devices["reference_beacon"].Board, "image_path": variant.imageName,
		"image_sha256": hex.EncodeToString(sum[:]), "image_size": len(image),
		"mutable": true, "signed": false,
	}
	return release, image, false, nil
}

func (a *app) runImpersonation(env environment, target string) (string, string, map[string]string, error) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return "", "", nil, err
	}
	host := targetURL.Hostname()
	if host == "localhost" {
		host = "127.0.0.1"
	}
	bind := net.JoinHostPort(host, strconv.Itoa(a.manifest.Runtime.ImpersonationPort))
	listener, err := net.Listen("tcp", bind)
	if err != nil {
		return "", "", nil, fmt.Errorf("start manifest-owned impersonation service: %w", err)
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/course-environment", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(env)
	})
	mux.HandleFunc("/v1/releases/current", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"release_id": "impersonated", "version": "0.0.0-hostile", "signed": false})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer server.Shutdown(context.Background())
	impersonationURL := "http://" + bind
	a.step(1, "Start a second service that pretends to be the update service.")
	a.note("Listening on %s. It serves the same endpoints and copies this environment marker.", impersonationURL)
	if _, _, err := a.matchMarker(impersonationURL); err != nil {
		return "", "", nil, err
	}
	a.got("The imposter answers the marker check convincingly enough for the course tooling.")

	a.step(2, "Point the device configuration at the imposter.")
	configPath := filepath.Join(a.root, a.manifest.Paths.State, "device-config.json")
	var config map[string]any
	if err := readJSON(configPath, &config); err != nil {
		return "", "", nil, err
	}
	a.note("Was: ota_url = %v", config["ota_url"])
	config["ota_url"] = impersonationURL
	a.note("Now: ota_url = %v", impersonationURL)
	a.note("In Tier 0 this address is the entire basis for trust. Whoever answers it, wins.")
	if err := writeJSON(configPath, config, 0o600); err != nil {
		return "", "", nil, err
	}

	a.step(3, "Ask for a release, exactly as the device would.")
	a.sent(http.MethodGet, impersonationURL+"/v1/releases/current")
	var release map[string]any
	if err := a.getJSON(impersonationURL+"/v1/releases/current", &release); err != nil {
		return "", "", nil, err
	}
	if release["release_id"] != "impersonated" {
		return "", "", nil, errors.New("generated device configuration did not accept impersonation service")
	}
	a.got("The answer came from the imposter, and it looks like any other release:")
	a.showJSON(release)
	a.note("No certificate, no key, no name was ever checked. The real service was never contacted.")
	return "marker-matching HTTP service impersonation supplied a hostile mutable release record", "", map[string]string{}, nil
}

func (a *app) resetFixture(id string) error {
	f, ok := a.manifest.Fixtures[id]
	if !ok {
		return fmt.Errorf("unknown fixture %q", id)
	}
	env, _, err := a.matchMarker(f.Target)
	if err != nil {
		return err
	}
	if err := a.resetFixtureState(id, f.Target, env); err != nil {
		return err
	}
	_ = os.Remove(a.fixtureBlockPath(id))
	fmt.Fprintf(a.out, "Result: reset %s to the Tier 0 seed\n", id)
	return nil
}

func (a *app) resetFixtureState(id, target string, env environment) error {
	// The clone fixture touches no service. Its reset appends to the
	// append-only manufacturing record rather than asking the service to
	// restore a seed, so it returns before the service reset below.
	if id == "tier-06/clone-shared-identity" {
		return a.resetClone()
	}
	// Tier 2 moved the lab endpoints behind TLS, so the reset goes there and
	// verifies the certificate like everything else. The marker check that
	// authorised this run stayed in the clear; the reset is data, and data
	// travels the way the tier says data travels.
	resetURL := target + "/v1/lab/reset"
	client := a.client
	if fixtureUsesTLS(id) {
		pool, err := a.trustAnchorPool()
		if err != nil {
			return err
		}
		client = a.verifyingClient(pool, coursepki.ServiceName, a.tlsAddress(target))
		resetURL = "https://" + coursepki.ServiceName + ":" + strconv.Itoa(a.manifest.Runtime.TLSPort) + "/v1/lab/reset"
	}
	request, _ := http.NewRequest(http.MethodPost, resetURL, nil)
	request.Header.Set("X-Course-Environment-ID", env.EnvironmentID)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("service reset returned %s", response.Status)
	}
	if id == "tier-00/service-impersonation" || id == "tier-02/service-impersonation" {
		config := map[string]any{"schema_version": 1, "device_id": a.manifest.Devices["reference_beacon"].SyntheticID, "ota_url": target}
		if err := writeJSON(filepath.Join(a.root, a.manifest.Paths.State, "device-config.json"), config, 0o600); err != nil {
			return err
		}
	}
	if id == "tier-00/altered-image" {
		// A built altered image is a build output, not fixture state, so it
		// survives the reset and the Learner can rerun the fixture without
		// another firmware build. Reset still returns the service to the
		// baseline release, which is what the device installs next.
		var built map[string]any
		builtPath := filepath.Join(a.root, a.manifest.Paths.State, "ota", "built-altered.json")
		if err := readJSON(builtPath, &built); err == nil {
			return nil
		}
		if err := os.Remove(filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "releases", "tier-00-altered.bin")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (a *app) matchMarker(target string) (environment, string, error) {
	var expected environment
	if err := readJSON(filepath.Join(a.root, a.manifest.Safety.MarkerPath), &expected); err != nil {
		return expected, "", errors.New("run ./course setup before using fixtures")
	}
	if time.Now().UTC().After(expected.ExpiresAt) {
		return expected, "", errors.New("Course environment marker expired; run setup again")
	}
	var actual environment
	if err := a.getJSON(strings.TrimRight(target, "/")+"/.well-known/course-environment", &actual); err != nil {
		return actual, "", fmt.Errorf("marker handshake failed: %w", err)
	}
	if expected.CourseID != actual.CourseID || expected.EnvironmentID != actual.EnvironmentID || expected.Tier != actual.Tier || !expected.SyntheticData || !actual.SyntheticData {
		return actual, "", errors.New("Course environment marker mismatch")
	}
	data, _ := json.Marshal(expected)
	sum := sha256.Sum256(data)
	return actual, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (a *app) getJSON(address string, value any) error {
	response, err := a.client.Get(address)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", address, response.Status)
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		return errors.New("marker or service response is not JSON")
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(value)
}

func (a *app) writeAttackEvidence(id string, record map[string]any) (string, error) {
	runID := time.Now().UTC().Format("20060102T150405.000000000Z")
	path := filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "attacks", filepath.FromSlash(id), runID+".json")
	if err := writeJSON(path, record, 0o600); err != nil {
		return "", err
	}
	relative, _ := filepath.Rel(a.root, path)
	return relative, nil
}

func (a *app) fixtureBlockPath(id string) string {
	slug := strings.ReplaceAll(id, "/", "--")
	return filepath.Join(a.root, a.manifest.Paths.State, "fixture-blocks", slug+".json")
}

func (a *app) verify(args []string) error {
	if len(args) != 1 {
		return errors.New("verify requires one tier identifier")
	}
	id := normalizeTier(args[0])
	t, ok := a.manifest.Tiers[id]
	if !ok {
		return fmt.Errorf("unknown tier %s", id)
	}
	if t.Status != "implemented" {
		return fmt.Errorf("Tier %s is %s and unavailable", id, t.Status)
	}
	dirty, err := gitOutput(a.root, "status", "--porcelain")
	if err != nil {
		return err
	}
	if strings.TrimSpace(dirty) != "" {
		return errors.New("verification receipt requires a clean Git revision")
	}
	fmt.Fprintln(a.out, "+ ./scripts/verify-tier-00.sh")
	if err := runAttached(a.root, a.out, a.errOut, "./scripts/verify-tier-00.sh"); err != nil {
		return err
	}
	revision, err := gitOutput(a.root, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	manifestData, err := os.ReadFile(filepath.Join(a.root, "course.yml"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(manifestData)
	receipt := map[string]any{
		"schema_version": 1, "course_version": a.manifest.Course.Version, "tier": id,
		"start_checkpoint": t.StartCheckpoint, "verified_revision": strings.TrimSpace(revision),
		"manifest_digest": "sha256:" + hex.EncodeToString(digest[:]), "result": "passed",
		"completed_at": time.Now().UTC(), "hardware": a.hardwareStatus(id),
	}
	path := filepath.Join(a.root, a.manifest.Paths.State, "receipts", "tier-"+strings.ToLower(id)+".json")
	if err := writeJSON(path, receipt, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: Tier %s host verification passed\nReceipt: %s\n", id, path)
	return nil
}

// hardwareStatus reports what the course claims about physical behavior for
// one tier. course.yml owns these values, so a receipt, the verification
// script, and the course material cannot drift apart.
func (a *app) hardwareStatus(id string) map[string]string {
	status := a.manifest.Verification["tier_"+strings.ToLower(id)].Hardware
	if status == nil {
		return map[string]string{}
	}
	return status
}

// deviceStatus prints every hardware claim the course makes, tier by tier.
//
// It used to print Tier 0's rows only, while the Tier 2 module already told a
// Learner to run it to see "which hardware results the course currently
// claims". A command that answers a question about the whole course with one
// tier's answer is worse than one that refuses to answer.
func (a *app) deviceStatus() error {
	tiers := make([]string, 0, len(a.manifest.Verification))
	for key := range a.manifest.Verification {
		tiers = append(tiers, key)
	}
	sort.Strings(tiers)

	printed := 0
	for _, key := range tiers {
		status := a.manifest.Verification[key].Hardware
		if len(status) == 0 {
			continue
		}
		names := make([]string, 0, len(status))
		for name := range status {
			names = append(names, name)
		}
		sort.Strings(names)
		if printed > 0 {
			fmt.Fprintln(a.out)
		}
		fmt.Fprintf(a.out, "Tier %s\n", strings.TrimPrefix(key, "tier_"))
		for _, name := range names {
			fmt.Fprintf(a.out, "  %s: %s\n", strings.ReplaceAll(name, "_", " "), status[name])
		}
		printed++
	}
	if printed == 0 {
		fmt.Fprintln(a.out, "No hardware claim is recorded for any tier.")
		return nil
	}
	fmt.Fprintln(a.out, "\nA result that is not validated is not a claim. A skipped check never supports one.")
	return nil
}

func (a *app) evidence(args []string) error {
	if len(args) != 1 {
		return errors.New("evidence requires context or check")
	}
	switch args[0] {
	case "context":
		env, fingerprint, revision, err := a.currentEvidenceContext()
		if err != nil {
			return err
		}
		fmt.Fprintf(a.out, "Source revision: %s\nEnvironment ID: %s\nMarker fingerprint: %s\n", revision, env.EnvironmentID, fingerprint)
		fmt.Fprintln(a.out, "Fixture evidence:")
		for _, fixture := range a.manifest.Tiers["00"].Fixtures {
			matches, _ := filepath.Glob(filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "attacks", filepath.FromSlash(fixture), "*.json"))
			sort.Strings(matches)
			if len(matches) == 0 {
				fmt.Fprintf(a.out, "  %s: pending\n", fixture)
				continue
			}
			relative, _ := filepath.Rel(a.root, matches[len(matches)-1])
			fmt.Fprintf(a.out, "  %s: %s\n", fixture, relative)
		}
		return nil
	case "check":
		return a.validateLearnerEvidence()
	default:
		return fmt.Errorf("unknown evidence command %q", args[0])
	}
}

func (a *app) validateRepository() error {
	if err := validateManifest(a.manifest); err != nil {
		return err
	}
	for _, path := range []string{
		"evidence/schemas/course-manifest.schema.json",
		"evidence/schemas/tier-00-evidence.schema.json",
		"course-material/index.md",
		"course-material/tiers/tier-00-unsecured/index.md",
		"course-material/tiers/tier-01-threat-model/index.md",
		"course-material/tiers/tier-01-threat-model/answers.md",
		"course-material/tiers/tier-02-authenticated-https/index.md",
	} {
		if _, err := os.Stat(filepath.Join(a.root, path)); err != nil {
			return fmt.Errorf("required path missing: %s", path)
		}
	}
	fmt.Fprintln(a.out, "Result: course.yml and the required Tier 0, Tier 1, and Tier 2 repository paths are valid")
	return a.validateBundledEvidence()
}

func (a *app) validateBundledEvidence() error {
	roots := []string{"evidence/templates/tier-00", "evidence/examples/tier-00"}
	required := map[string]bool{"baseline-architecture": false, "http-exchange": false, "accepted-image-record": false, "absent-controls": false}
	for _, root := range roots {
		entries, err := filepath.Glob(filepath.Join(a.root, root, "*.json"))
		if err != nil || len(entries) != 4 {
			return fmt.Errorf("%s must contain four JSON records", root)
		}
		for _, path := range entries {
			var record map[string]any
			if err := readJSON(path, &record); err != nil {
				return err
			}
			for _, field := range []string{"schema_version", "artifact_id", "artifact_type", "owner", "reviewer", "scope", "revision", "status", "created_at", "last_reviewed_at", "source_revision", "environment", "limitations", "content"} {
				if _, ok := record[field]; !ok {
					return fmt.Errorf("%s is missing %s", path, field)
				}
			}
			if id, ok := record["artifact_type"].(string); ok {
				required[id] = true
			}
		}
	}
	for id, found := range required {
		if !found {
			return fmt.Errorf("evidence artifact type %s is missing", id)
		}
	}
	fmt.Fprintln(a.out, "Result: Tier 0 evidence templates and generated examples satisfy required metadata")
	return nil
}

func (a *app) validateLearnerEvidence() error {
	root := filepath.Join(a.root, a.manifest.Paths.LearnerEvidence, "tier-00")
	entries, err := filepath.Glob(filepath.Join(root, "*.json"))
	if err != nil || len(entries) != 4 {
		return errors.New("evidence/learner/tier-00 must contain the four completed Tier 0 JSON records")
	}

	env, expectedFingerprint, expectedRevision, err := a.currentEvidenceContext()
	if err != nil {
		return err
	}

	required := map[string]bool{"baseline-architecture": false, "http-exchange": false, "accepted-image-record": false, "absent-controls": false}
	for _, path := range entries {
		var record map[string]any
		if err := readJSON(path, &record); err != nil {
			return err
		}
		artifactType, _ := record["artifact_type"].(string)
		if _, ok := required[artifactType]; !ok {
			return fmt.Errorf("%s has unsupported artifact_type %q", path, artifactType)
		}
		if required[artifactType] {
			return fmt.Errorf("Learner evidence contains duplicate artifact_type %s", artifactType)
		}
		required[artifactType] = true
		status, _ := record["status"].(string)
		if status == "" || status == "template" || status == "example" {
			return fmt.Errorf("%s must have a completed Learner status", path)
		}
		if value, _ := record["created_at"].(string); value == "" {
			return fmt.Errorf("%s must set created_at", path)
		}
		if value, _ := record["source_revision"].(string); value != expectedRevision {
			return fmt.Errorf("%s source_revision must match HEAD %s", path, expectedRevision)
		}
		recordEnv, ok := record["environment"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s must contain environment metadata", path)
		}
		if value, _ := recordEnv["environment_id"].(string); value != env.EnvironmentID {
			return fmt.Errorf("%s environment_id must match the current Course environment", path)
		}
		if value, _ := recordEnv["marker_fingerprint"].(string); value != expectedFingerprint {
			return fmt.Errorf("%s marker_fingerprint must match the current Course environment", path)
		}
		content, ok := record["content"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s must contain evidence content", path)
		}
		if err := validateLearnerEvidenceContent(path, artifactType, status, record, content); err != nil {
			return err
		}
	}
	for id, found := range required {
		if !found {
			return fmt.Errorf("Learner evidence artifact type %s is missing", id)
		}
	}
	for _, fixture := range a.manifest.Tiers["00"].Fixtures {
		matches, _ := filepath.Glob(filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "attacks", filepath.FromSlash(fixture), "*.json"))
		if len(matches) == 0 {
			return fmt.Errorf("run fixture %s with --execute before checking evidence", fixture)
		}
	}
	fmt.Fprintln(a.out, "Result: Learner Tier 0 evidence is complete and bound to the current revision and Course environment")
	return nil
}

func (a *app) currentEvidenceContext() (environment, string, string, error) {
	var env environment
	if err := readJSON(filepath.Join(a.root, a.manifest.Safety.MarkerPath), &env); err != nil {
		return env, "", "", errors.New("run ./course setup before using Learner evidence")
	}
	envData, _ := json.Marshal(env)
	envDigest := sha256.Sum256(envData)
	fingerprint := "sha256:" + hex.EncodeToString(envDigest[:])
	revision, err := gitOutput(a.root, "rev-parse", "HEAD")
	if err != nil {
		return env, "", "", err
	}
	return env, fingerprint, strings.TrimSpace(revision), nil
}

func validateLearnerEvidenceContent(path, artifactType, status string, record, content map[string]any) error {
	requireString := func(key string) error {
		if value, _ := content[key].(string); strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s content.%s must be set", path, key)
		}
		return nil
	}
	requireList := func(key string) error {
		if value, _ := content[key].([]any); len(value) == 0 {
			return fmt.Errorf("%s content.%s must contain at least one item", path, key)
		}
		return nil
	}
	switch artifactType {
	case "baseline-architecture":
		for _, key := range []string{"components", "data_flows", "trust_boundaries"} {
			if err := requireList(key); err != nil {
				return err
			}
		}
		return requireString("notes")
	case "http-exchange":
		for _, key := range []string{"request_line", "response_status", "fixture_evidence_path"} {
			if err := requireString(key); err != nil {
				return err
			}
		}
		if err := requireList("readable_fields"); err != nil {
			return err
		}
		if readable, _ := content["firmware_bytes_readable"].(bool); !readable {
			return fmt.Errorf("%s content.firmware_bytes_readable must record the Tier 0 observation", path)
		}
	case "accepted-image-record":
		for _, key := range []string{"image_sha256", "service_delivery", "mcuboot_mode", "device_flash", "device_boot", "wifi_association", "http_exchange", "ota_download", "altered_image_execution", "led_behavior", "serial_record"} {
			if err := requireString(key); err != nil {
				return err
			}
		}
		if status == "pending" {
			for _, key := range []string{"device_flash", "device_boot", "wifi_association", "http_exchange", "ota_download", "altered_image_execution", "led_behavior", "serial_record"} {
				if content[key] != "pending" {
					return fmt.Errorf("%s content.%s must stay pending when the artifact status is pending", path, key)
				}
			}
			if limitations, _ := record["limitations"].([]any); len(limitations) == 0 {
				return fmt.Errorf("%s must explain the pending hardware limitation", path)
			}
		}
	case "absent-controls":
		for _, key := range []string{"absent", "observed_effects", "next_tier_questions"} {
			if err := requireList(key); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *app) clean(args []string) error {
	confirmation := ""
	if len(args) == 2 && args[0] == "--confirm" {
		confirmation = args[1]
	} else if len(args) != 0 {
		return errors.New("usage: ./course clean --confirm 'REMOVE COURSE GENERATED STATE'")
	}
	a.context("generated state cleanup")
	var existing []string
	for _, relative := range a.manifest.Paths.CleanupAllowlist {
		path := filepath.Join(a.root, relative)
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, relative)
		}
	}
	fmt.Fprintf(a.out, "Allowlist: %s\n", strings.Join(a.manifest.Paths.CleanupAllowlist, ", "))
	fmt.Fprintf(a.out, "Existing targets: %s\n", strings.Join(existing, ", "))
	if confirmation != a.manifest.Safety.CleanupConfirmation {
		return fmt.Errorf("typed confirmation required: %s", a.manifest.Safety.CleanupConfirmation)
	}
	if response, err := a.client.Get(a.serviceURL() + "/health"); err == nil {
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			return errors.New("the OTA service is still healthy; run ./course service stop before cleanup")
		}
	}
	for _, relative := range existing {
		clean := filepath.Clean(relative)
		if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") || !contains(a.manifest.Paths.CleanupAllowlist, clean) {
			return fmt.Errorf("unsafe cleanup path %q", relative)
		}
		fmt.Fprintf(a.out, "+ rm -rf -- %s\n", clean)
		if err := os.RemoveAll(filepath.Join(a.root, clean)); err != nil {
			return err
		}
	}
	fmt.Fprintln(a.out, "Result: only manifest-allowlisted generated state was removed")
	return nil
}

type serviceSettings struct {
	environmentID string
	advertised    string
	port          string
}

func (a *app) serviceSettings() (serviceSettings, error) {
	data, err := os.ReadFile(filepath.Join(a.root, a.manifest.Paths.State, "service.env"))
	if err != nil {
		return serviceSettings{}, errors.New("run ./course setup first")
	}
	settings := serviceSettings{advertised: a.manifest.Runtime.BindDefault, port: strconv.Itoa(a.manifest.Runtime.OTAPort)}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "COURSE_ENVIRONMENT_ID":
			settings.environmentID = value
		case "COURSE_ADVERTISED_HOST":
			settings.advertised = value
		case "COURSE_PORT":
			settings.port = value
		}
	}
	return settings, nil
}

// serviceURL is how ./course itself reaches the service. The service runs in
// the same container, so this is always loopback. It is not the address the
// Reference product uses.
func (a *app) serviceURL() string {
	port := strconv.Itoa(a.manifest.Runtime.OTAPort)
	if settings, err := a.serviceSettings(); err == nil {
		port = settings.port
	}
	return "http://" + net.JoinHostPort("127.0.0.1", port)
}

// advertisedURL is the address a physical board uses: this container's
// published port on the host, as chosen by ./course setup --bind.
func (a *app) advertisedURL(settings serviceSettings) string {
	return "http://" + net.JoinHostPort(settings.advertised, settings.port)
}

func validateBind(value string) error {
	if value == "localhost" {
		return nil
	}
	ip := net.ParseIP(value)
	if ip == nil || !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return errors.New("bind address must be loopback or a literal private or link-local address")
	}
	return nil
}

func validateTarget(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("target must be one literal HTTP origin")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("target must not include a path")
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("DNS names other than localhost are refused")
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("wildcard, broadcast, and multicast targets are refused")
	}
	if !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return errors.New("target must be loopback, RFC 1918, IPv6 unique-local, or IPv6 link-local")
	}
	return nil
}

func validateSelectedInterface(rawTarget, selected string, explicitlySelected bool) error {
	u, err := url.Parse(rawTarget)
	if err != nil {
		return err
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		if selected != "loopback" && selected != "lo" {
			return errors.New("loopback target must use the loopback interface")
		}
		return nil
	}
	if !explicitlySelected {
		return errors.New("a non-loopback target requires --interface with the selected local interface")
	}
	iface, err := net.InterfaceByName(selected)
	if err != nil {
		return fmt.Errorf("selected interface %q is unavailable", selected)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("inspect selected interface %q: %w", selected, err)
	}
	for _, address := range addresses {
		addressIP, _, err := net.ParseCIDR(address.String())
		if err == nil && addressIP.Equal(ip) {
			return nil
		}
	}
	return fmt.Errorf("target address %s is not assigned to selected interface %s", ip, selected)
}

func runProbe(dir string, command []string) error {
	if len(command) == 0 {
		return errors.New("empty command")
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func runAttached(dir string, stdout, stderr io.Writer, name string, args ...string) error {
	return runAttachedEnv(dir, stdout, stderr, nil, name, args...)
}

func runAttachedEnv(dir string, stdout, stderr io.Writer, env []string, name string, args ...string) error {
	return runAttachedFrom(dir, dir, stdout, stderr, env, name, args...)
}

// runAttachedFrom runs a command in workDir while keeping temporary files
// under the repository. west subcommands such as flash only work inside the
// Zephyr workspace, which is not the repository.
func runAttachedFrom(root, workDir string, stdout, stderr io.Writer, env []string, name string, args ...string) error {
	tmpDir := filepath.Join(root, "build", "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return err
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = workDir
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = append(append(os.Environ(), "TMPDIR="+tmpDir), env...)
	return cmd.Run()
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func randomID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	data[6] = (data[6] & 0x0f) | 0x40
	data[8] = (data[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[0:4], data[4:6], data[6:8], data[8:10], data[10:16]), nil
}

func writeJSON(path string, value any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), mode)
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func sortedTierIDs(tiers map[string]tier) []string {
	order := []string{"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "A", "B"}
	var result []string
	for _, id := range order {
		if _, ok := tiers[id]; ok {
			result = append(result, id)
		}
	}
	return result
}

func normalizeTier(value string) string {
	value = strings.TrimPrefix(strings.ToUpper(value), "TIER-")
	if number, err := strconv.Atoi(value); err == nil {
		return fmt.Sprintf("%02d", number)
	}
	return value
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// identityModelSymbol maps a variant's identity model to its Kconfig symbol.
//
// A map rather than string building, so a typo is a build failure here rather
// than a silently misconfigured image. Tier 5 learned this the hard way with
// its trial behaviours.
func identityModelSymbol(model string) (string, error) {
	symbols := map[string]string{
		"shared":  "CONFIG_COURSE_IDENTITY_SHARED",
		"factory": "CONFIG_COURSE_IDENTITY_FACTORY",
	}
	symbol, ok := symbols[model]
	if !ok {
		return "", fmt.Errorf("unknown identity model %q", model)
	}
	return symbol, nil
}
