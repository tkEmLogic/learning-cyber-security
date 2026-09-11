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
	"time"

	"gopkg.in/yaml.v3"
)

type manifest struct {
	SchemaVersion int `yaml:"schema_version"`
	Course        struct {
		ID                        string `yaml:"id"`
		Version                   string `yaml:"version"`
		EnvironmentMarkerTTLHours int    `yaml:"environment_marker_ttl_hours"`
	} `yaml:"course"`
	Runtime struct {
		Selection          string `yaml:"selection"`
		BindDefault        string `yaml:"bind_default"`
		PrivateBindAllowed bool   `yaml:"private_bind_allowed"`
		OTAPort            int    `yaml:"ota_port"`
		ImpersonationPort  int    `yaml:"impersonation_port"`
		Compose            struct {
			File    string              `yaml:"file"`
			Choices map[string][]string `yaml:"choices"`
			Probes  map[string][]string `yaml:"probes"`
		} `yaml:"compose"`
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
		Bind        string `yaml:"bind"`
		Port        int    `yaml:"port"`
		ComposeFile string `yaml:"compose_file"`
		Health      string `yaml:"health"`
		Marker      string `yaml:"marker"`
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
}

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
	if m.Runtime.Selection != "explicit_if_ambiguous" {
		return errors.New("course.yml must require explicit runtime selection when ambiguous")
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
	fmt.Fprintln(w, "usage: ./course doctor|setup|tier|build|service|device|attack|verify|evidence|clean")
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
	available := a.availableRuntimes()
	for _, runtime := range []string{"docker", "podman"} {
		probe := a.manifest.Runtime.Compose.Probes[runtime]
		command := append(append([]string{}, a.manifest.Runtime.Compose.Choices[runtime]...), "version")
		fmt.Fprintf(a.out, "+ %s && %s\n", strings.Join(probe, " "), strings.Join(command, " "))
		fmt.Fprintf(a.out, "  qualifies: %t\n", contains(available, runtime))
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
	if len(available) > 1 {
		fmt.Fprintln(a.out, "Result: both runtimes qualify; setup requires --runtime docker or --runtime podman")
	} else if len(available) == 1 {
		fmt.Fprintf(a.out, "Result: runtime %s qualifies\n", available[0])
	} else {
		problems++
		fmt.Fprintln(a.out, "Result: no compose runtime qualifies")
	}
	if problems != 0 {
		return fmt.Errorf("%d required host checks failed", problems)
	}
	fmt.Fprintln(a.out, "Next: ./course setup --runtime <docker|podman>")
	return nil
}

func (a *app) setup(args []string) error {
	runtime, bind, err := parseSetupArgs(args)
	if err != nil {
		return err
	}
	a.context("generated local Course environment")
	available := a.availableRuntimes()
	if runtime == "" {
		if len(available) == 0 {
			return errors.New("no Docker or Podman compose runtime qualifies")
		}
		if len(available) > 1 {
			return errors.New("both Docker and Podman qualify; choose --runtime docker or --runtime podman")
		}
		runtime = available[0]
	}
	if !contains(available, runtime) {
		return fmt.Errorf("runtime %q does not qualify", runtime)
	}
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
	runtimeState := map[string]any{"schema_version": 1, "runtime": runtime, "compose_command": a.manifest.Runtime.Compose.Choices[runtime]}
	if err := writeJSON(filepath.Join(a.root, a.manifest.Paths.State, "runtime.json"), runtimeState, 0o600); err != nil {
		return err
	}
	serviceEnv := fmt.Sprintf("COURSE_ENVIRONMENT_ID=%s\nCOURSE_BIND=%s\nCOURSE_PORT=%d\n", id, bind, a.manifest.Runtime.OTAPort)
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
	fmt.Fprintf(a.out, "Result: created synthetic Tier 0 environment %s\n", id)
	fmt.Fprintf(a.out, "State: %s, %s\n", a.manifest.Paths.State, a.manifest.Paths.GeneratedArtifacts)
	fmt.Fprintln(a.out, "Next: ./course service start")
	return nil
}

func parseSetupArgs(args []string) (string, string, error) {
	runtime := ""
	bind := "127.0.0.1"
	for len(args) > 0 {
		if len(args) < 2 {
			return "", "", fmt.Errorf("option %s requires a value", args[0])
		}
		switch args[0] {
		case "--runtime":
			runtime = args[1]
		case "--bind":
			bind = args[1]
		default:
			return "", "", fmt.Errorf("unknown setup option %s", args[0])
		}
		args = args[2:]
	}
	if runtime != "" && runtime != "docker" && runtime != "podman" {
		return "", "", errors.New("--runtime must be docker or podman")
	}
	return runtime, bind, nil
}

func (a *app) availableRuntimes() []string {
	var available []string
	for _, name := range []string{"docker", "podman"} {
		if runProbe(a.root, a.manifest.Runtime.Compose.Probes[name]) != nil {
			continue
		}
		command := append(append([]string{}, a.manifest.Runtime.Compose.Choices[name]...), "version")
		if runProbe(a.root, command) == nil {
			available = append(available, name)
		}
	}
	return available
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
		return errors.New("Tier 1 will continue in the Tier 0 Course workspace when Tier 1 is implemented")
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
		fmt.Fprintln(a.out, "+ ./scripts/build-zephyr-baseline.sh")
		return runAttached(a.root, a.out, a.errOut, "./scripts/build-zephyr-baseline.sh")
	default:
		return fmt.Errorf("unknown component %q", component)
	}
}

func (a *app) service(args []string) error {
	if len(args) == 0 {
		return errors.New("service requires start, stop, or status")
	}
	runtime, err := a.runtimeState()
	if err != nil {
		return err
	}
	compose := a.manifest.Runtime.Compose.Choices[runtime]
	base := append(append([]string{}, compose...), "--env-file", filepath.Join(a.root, a.manifest.Paths.State, "service.env"), "-f", filepath.Join(a.root, a.manifest.Runtime.Compose.File))
	switch args[0] {
	case "start":
		command := append(base, "up", "-d", "--build")
		fmt.Fprintf(a.out, "+ %s\n", strings.Join(command, " "))
		if err := runAttached(a.root, a.out, a.errOut, command[0], command[1:]...); err != nil {
			return err
		}
		target, err := a.serviceURL()
		if err != nil {
			return err
		}
		for i := 0; i < 20; i++ {
			if response, err := a.client.Get(target + "/health"); err == nil && response.StatusCode == http.StatusOK {
				response.Body.Close()
				fmt.Fprintln(a.out, "Result: OTA service is healthy")
				fmt.Fprintln(a.out, "Next: ./course attack list")
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return errors.New("OTA service did not become healthy")
	case "stop":
		command := append(base, "down", "--remove-orphans")
		fmt.Fprintf(a.out, "+ %s\n", strings.Join(command, " "))
		return runAttached(a.root, a.out, a.errOut, command[0], command[1:]...)
	case "status":
		command := append(base, "ps")
		fmt.Fprintf(a.out, "+ %s\n", strings.Join(command, " "))
		if err := runAttached(a.root, a.out, a.errOut, command[0], command[1:]...); err != nil {
			return err
		}
		target, err := a.serviceURL()
		if err != nil {
			return err
		}
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
		return nil
	default:
		return fmt.Errorf("unknown service command %q", args[0])
	}
}

func (a *app) device(args []string) error {
	if len(args) == 0 {
		return errors.New("device requires flash, logs, update, or recover")
	}
	dev := a.manifest.Devices["reference_beacon"]
	switch args[0] {
	case "flash":
		fmt.Fprintf(a.out, "+ west flash -d \"$ZEPHYR_BUILD_DIR\" --dev-id /dev/serial/by-id/<selected-esp32c6>\n")
	case "logs":
		fmt.Fprintln(a.out, "+ python3 -m serial.tools.miniterm /dev/serial/by-id/<selected-esp32c6> 115200")
	case "update":
		fmt.Fprintln(a.out, "+ device HTTP client: GET /v1/releases/current, GET /v1/releases/{id}/manifest, GET /v1/firmware/{name}")
	case "recover":
		fmt.Fprintln(a.out, "+ west flash -d \"$ZEPHYR_BUILD_DIR\" --recover is not enabled in Tier 0")
	default:
		return fmt.Errorf("unknown device command %q", args[0])
	}
	return fmt.Errorf("%s requires a physical ESP32-C6 selected by a stable %s path; hardware validation is pending", args[0], dev.StableSerialPrefix)
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
	if serviceTarget, err := a.serviceURL(); err == nil {
		target = serviceTarget
	}
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
	if executeID == "" {
		fmt.Fprintln(a.out, "Result: dry run only")
		fmt.Fprintf(a.out, "Execute: ./course attack run %s --execute %s\n", id, id)
		return nil
	}
	if executeID != id {
		return errors.New("--execute value must exactly match the fixture identifier")
	}
	start := time.Now().UTC()
	observed, limitation, artifactHashes, runErr := a.executeFixture(id, target, env)
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
		"ended_at": time.Now().UTC(), "command": fmt.Sprintf("./course attack run %s --execute %s", id, id),
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

func (a *app) executeFixture(id, target string, env environment) (string, string, map[string]string, error) {
	switch id {
	case "tier-00/plaintext-inspection":
		var release map[string]any
		if err := a.getJSON(target+"/v1/releases/current", &release); err != nil {
			return "", "", nil, err
		}
		name, _ := release["image_path"].(string)
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
		return fmt.Sprintf("plaintext release version %v and %d firmware bytes were readable", release["version"], len(body)), "", map[string]string{name: "sha256:" + hex.EncodeToString(sum[:])}, nil
	case "tier-00/device-id-spoofing":
		dev := a.manifest.Devices["reference_beacon"]
		event := map[string]any{"device_id": dev.SpoofID, "event_type": "status.observed", "boot_id": "synthetic-boot", "event_sequence": 1, "firmware_version": "0.0.0-insecure", "security_counter": 0, "machine_state": "fast", "result": "synthetic", "reason_code": "fixture"}
		data, _ := json.Marshal(event)
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
		return "service accepted the spoofed manifest-owned device identifier", "", map[string]string{}, nil
	case "tier-00/service-impersonation":
		return a.runImpersonation(env, target)
	case "tier-00/altered-image":
		releaseDir := filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "releases")
		image := []byte("COURSE SYNTHETIC ALTERED FIRMWARE\nTier 00\nstate=fast\n")
		name := "tier-00-altered.bin"
		if err := os.WriteFile(filepath.Join(releaseDir, name), image, 0o600); err != nil {
			return "", "", nil, err
		}
		sum := sha256.Sum256(image)
		release := map[string]any{"schema_version": 1, "release_id": "tier-00-altered", "version": "0.0.0-altered", "board": "esp32c6_devkitc/esp32c6/hpcore", "image_path": name, "image_sha256": hex.EncodeToString(sum[:]), "image_size": len(image), "mutable": true, "signed": false}
		data, _ := json.Marshal(release)
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
		response, err = a.client.Get(target + "/v1/firmware/" + name)
		if err != nil {
			return "", "", nil, err
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil || !bytes.Equal(body, image) {
			return "", "", nil, errors.New("altered image was not delivered unchanged")
		}
		return "altered unsigned image was generated and delivered by the service", "physical ESP32-C6 acceptance and execution remain pending", map[string]string{name: "sha256:" + hex.EncodeToString(sum[:])}, nil
	default:
		return "", "", nil, errors.New("fixture implementation unavailable")
	}
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
	if _, _, err := a.matchMarker(impersonationURL); err != nil {
		return "", "", nil, err
	}
	configPath := filepath.Join(a.root, a.manifest.Paths.State, "device-config.json")
	var config map[string]any
	if err := readJSON(configPath, &config); err != nil {
		return "", "", nil, err
	}
	config["ota_url"] = impersonationURL
	if err := writeJSON(configPath, config, 0o600); err != nil {
		return "", "", nil, err
	}
	var release map[string]any
	if err := a.getJSON(impersonationURL+"/v1/releases/current", &release); err != nil {
		return "", "", nil, err
	}
	if release["release_id"] != "impersonated" {
		return "", "", nil, errors.New("generated device configuration did not accept impersonation service")
	}
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
	request, _ := http.NewRequest(http.MethodPost, target+"/v1/lab/reset", nil)
	request.Header.Set("X-Course-Environment-ID", env.EnvironmentID)
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("service reset returned %s", response.Status)
	}
	if id == "tier-00/service-impersonation" {
		config := map[string]any{"schema_version": 1, "device_id": a.manifest.Devices["reference_beacon"].SyntheticID, "ota_url": target}
		if err := writeJSON(filepath.Join(a.root, a.manifest.Paths.State, "device-config.json"), config, 0o600); err != nil {
			return err
		}
	}
	if id == "tier-00/altered-image" {
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
		"completed_at": time.Now().UTC(), "hardware": map[string]string{"flash": "pending", "serial": "pending", "altered_image_execution": "pending"},
	}
	path := filepath.Join(a.root, a.manifest.Paths.State, "receipts", "tier-"+strings.ToLower(id)+".json")
	if err := writeJSON(path, receipt, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: Tier %s host verification passed\nReceipt: %s\n", id, path)
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
		"course-material/tiers/tier-00-unsecured/index.md",
		"course-material/tiers/tier-00-unsecured/weakness-ledger.md",
	} {
		if _, err := os.Stat(filepath.Join(a.root, path)); err != nil {
			return fmt.Errorf("required path missing: %s", path)
		}
	}
	fmt.Fprintln(a.out, "Result: course.yml and required Tier 0 repository paths are valid")
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
		for _, key := range []string{"image_sha256", "service_delivery", "mcuboot_mode", "device_flash", "device_boot", "led_behavior", "serial_record"} {
			if err := requireString(key); err != nil {
				return err
			}
		}
		if status == "pending" {
			for _, key := range []string{"device_flash", "device_boot", "led_behavior", "serial_record"} {
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
	if target, err := a.serviceURL(); err == nil {
		if response, err := a.client.Get(target + "/health"); err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return errors.New("the OTA service is still healthy; run ./course service stop before cleanup")
			}
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

func (a *app) runtimeState() (string, error) {
	var state struct {
		Runtime string `json:"runtime"`
	}
	if err := readJSON(filepath.Join(a.root, a.manifest.Paths.State, "runtime.json"), &state); err != nil {
		return "", errors.New("run ./course setup before service commands")
	}
	if _, ok := a.manifest.Runtime.Compose.Choices[state.Runtime]; !ok {
		return "", errors.New("generated runtime selection is invalid")
	}
	return state.Runtime, nil
}

func (a *app) serviceURL() (string, error) {
	data, err := os.ReadFile(filepath.Join(a.root, a.manifest.Paths.State, "service.env"))
	if err != nil {
		return "", errors.New("run ./course setup first")
	}
	bind := "127.0.0.1"
	port := strconv.Itoa(a.manifest.Runtime.OTAPort)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "COURSE_BIND":
			bind = value
		case "COURSE_PORT":
			port = value
		}
	}
	return "http://" + net.JoinHostPort(bind, port), nil
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
	tmpDir := filepath.Join(dir, "build", "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return err
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = append(os.Environ(), "TMPDIR="+tmpDir)
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
