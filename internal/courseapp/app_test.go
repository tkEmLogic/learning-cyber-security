package courseapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/services/ota"
)

func TestTierListShowsPlannedUnavailableTiers(t *testing.T) {
	root := testRepository(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--repo", root, "tier", "list"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "00  IMPLEMENTED") || !strings.Contains(stdout.String(), "01  IMPLEMENTED") || !strings.Contains(stdout.String(), "02  PLANNED") || !strings.Contains(stdout.String(), "B  PLANNED") {
		t.Fatalf("unexpected tier list:\n%s", stdout.String())
	}
}

func TestTargetGuardrails(t *testing.T) {
	allowed := []string{"http://127.0.0.1:8080", "http://localhost:8080", "http://10.2.3.4:8080", "http://[fd00::1]:8080"}
	for _, target := range allowed {
		if err := validateTarget(target); err != nil {
			t.Errorf("allowed target %s rejected: %v", target, err)
		}
	}
	refused := []string{"https://127.0.0.1", "http://example.com", "http://0.0.0.0:8080", "http://224.0.0.1", "http://127.0.0.1:8080/path", "http://127.0.0.1:8080?scan=1"}
	for _, target := range refused {
		if err := validateTarget(target); err == nil {
			t.Errorf("unsafe target %s accepted", target)
		}
	}
}

func TestNonLoopbackRequiresMatchingSelectedInterface(t *testing.T) {
	if err := validateSelectedInterface("http://10.2.3.4:8080", "loopback", false); err == nil {
		t.Fatal("non-loopback target did not require explicit interface selection")
	}
	if err := validateSelectedInterface("http://127.0.0.1:8080", "eth0", true); err == nil {
		t.Fatal("loopback target accepted a non-loopback interface")
	}
}

func TestDryRunAndHostFixtures(t *testing.T) {
	root := testRepository(t)
	stateDir := filepath.Join(root, ".course-state", "ota")
	releaseDir := filepath.Join(root, "artifacts", "generated", "releases")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(releaseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	image := []byte("synthetic baseline firmware")
	if err := os.WriteFile(filepath.Join(releaseDir, "tier-00-baseline.bin"), image, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(image)
	release := map[string]any{"schema_version": 1, "release_id": "tier-00-baseline", "version": "0.0.0-insecure", "board": "esp32c6_devkitc/esp32c6/hpcore", "image_path": "tier-00-baseline.bin", "image_sha256": hex.EncodeToString(sum[:]), "image_size": len(image), "mutable": true, "signed": false}
	writeJSON(filepath.Join(stateDir, "seed-release.json"), release, 0o600)
	writeJSON(filepath.Join(stateDir, "current-release.json"), release, 0o600)
	env := environment{1, "learning-cyber-security", "fixture-test", "00", true, time.Now().UTC(), time.Now().UTC().Add(time.Hour)}
	writeJSON(filepath.Join(root, ".course-state", "environment.json"), env, 0o600)
	writeJSON(filepath.Join(root, ".course-state", "device-config.json"), map[string]any{"ota_url": "unset"}, 0o600)
	service, err := ota.New(ota.Config{
		CourseID:      "learning-cyber-security",
		EnvironmentID: "fixture-test",
		Tier:          "00",
		StateDir:      stateDir,
		ReleaseDir:    releaseDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.Handler())
	defer server.Close()

	fixtures := []string{
		"tier-00/plaintext-inspection",
		"tier-00/device-id-spoofing",
		"tier-00/service-impersonation",
		"tier-00/altered-image",
	}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run([]string{"--repo", root, "attack", "run", fixture, "--target", server.URL}, &stdout, &stderr)
			if code != 0 || !strings.Contains(stdout.String(), "dry run only") {
				t.Fatalf("dry run code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			stdout.Reset()
			stderr.Reset()
			code = Run([]string{"--repo", root, "attack", "run", fixture, "--target", server.URL, "--execute", "wrong-fixture"}, &stdout, &stderr)
			if code == 0 || !strings.Contains(stderr.String(), "exactly match") {
				t.Fatalf("wrong execute identifier was not refused: code=%d stderr=%s", code, stderr.String())
			}
			stdout.Reset()
			stderr.Reset()
			code = Run([]string{"--repo", root, "attack", "run", fixture, "--target", server.URL, "--execute", fixture}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("execute code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), "Reset result: passed") {
				t.Fatalf("missing reset result:\n%s", stdout.String())
			}
		})
	}
}

func TestFixtureRefusesAfterFailedResetMarker(t *testing.T) {
	root := testRepository(t)
	block := filepath.Join(root, ".course-state", "fixture-blocks", "tier-00--plaintext-inspection.json")
	if err := os.MkdirAll(filepath.Dir(block), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(block, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"--repo", root, "attack", "run", "tier-00/plaintext-inspection",
		"--target", "http://127.0.0.1:8080",
		"--execute", "tier-00/plaintext-inspection",
	}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "blocked after a failed reset") {
		t.Fatalf("blocked fixture was not refused: code=%d stderr=%s", code, stderr.String())
	}
}

func TestExecuteIdentifierAndCleanupRefuseUnsafeInput(t *testing.T) {
	root := testRepository(t)
	if err := os.MkdirAll(filepath.Join(root, "build", "keep"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--repo", root, "clean", "--confirm", "wrong phrase"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("clean accepted wrong confirmation")
	}
	if _, err := os.Stat(filepath.Join(root, "build", "keep")); err != nil {
		t.Fatal("clean removed data after refusal")
	}
}

func TestCleanupRefusesWhileServiceIsHealthy(t *testing.T) {
	root := testRepository(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	host, port, _ := strings.Cut(strings.TrimPrefix(server.URL, "http://"), ":")
	if err := os.MkdirAll(filepath.Join(root, ".course-state"), 0o700); err != nil {
		t.Fatal(err)
	}
	serviceEnv := "COURSE_ADVERTISED_HOST=" + host + "\nCOURSE_PORT=" + port + "\n"
	if err := os.WriteFile(filepath.Join(root, ".course-state", "service.env"), []byte(serviceEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "build", "keep"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--repo", root, "clean", "--confirm", "REMOVE COURSE GENERATED STATE"}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "service stop") {
		t.Fatalf("clean did not refuse a healthy service: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "build", "keep")); err != nil {
		t.Fatal("clean removed data while the service was healthy")
	}
}

func TestEvidenceCheckRejectsMissingLearnerRecords(t *testing.T) {
	root := testRepository(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--repo", root, "evidence", "check"}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "four completed Tier 0 JSON records") {
		t.Fatalf("missing Learner evidence was not rejected: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestEvidenceCheckAcceptsCompletedPendingHardwareRecords(t *testing.T) {
	root := testRepository(t)
	initializeGitRepository(t, root)
	env := environment{1, "learning-cyber-security", "evidence-test", "00", true, time.Now().UTC(), time.Now().UTC().Add(time.Hour)}
	writeJSON(filepath.Join(root, ".course-state", "environment.json"), env, 0o600)
	envData, _ := json.Marshal(env)
	envDigest := sha256.Sum256(envData)
	fingerprint := "sha256:" + hex.EncodeToString(envDigest[:])
	revisionBytes, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	revision := strings.TrimSpace(string(revisionBytes))

	records := map[string]map[string]any{
		"baseline-architecture": {
			"components": []any{"device", "service"}, "data_flows": []any{"HTTP"},
			"trust_boundaries": []any{"local network"}, "notes": "No authenticated boundary.",
		},
		"http-exchange": {
			"request_line": "GET /v1/releases/current HTTP/1.1", "response_status": "200 OK",
			"readable_fields": []any{"version"}, "firmware_bytes_readable": true,
			"fixture_evidence_path": "artifacts/generated/attacks/tier-00/plaintext-inspection/run.json",
		},
		"accepted-image-record": {
			"image_sha256": "sha256:synthetic", "service_delivery": "observed in host fixture",
			"mcuboot_mode": "unsigned", "device_flash": "pending", "device_boot": "pending",
			"wifi_association": "pending", "http_exchange": "pending",
			"ota_download": "pending", "altered_image_execution": "pending",
			"led_behavior": "pending", "serial_record": "pending",
		},
		"absent-controls": {
			"absent": []any{"TLS"}, "observed_effects": []any{"plaintext readable"},
			"next_tier_questions": []any{"Which asset is exposed?"},
		},
	}
	for artifactType, content := range records {
		status := "observed"
		limitations := []any{}
		if artifactType == "accepted-image-record" {
			status = "pending"
			limitations = []any{"No physical ESP32-C6 was available."}
		}
		record := map[string]any{
			"schema_version": 1, "artifact_id": "test-" + artifactType, "artifact_type": artifactType,
			"owner": "Learner", "reviewer": nil, "scope": "tier-00", "revision": 1, "status": status,
			"created_at": time.Now().UTC().Format(time.RFC3339), "last_reviewed_at": nil,
			"source_revision": revision,
			"environment": map[string]any{
				"course_id": "learning-cyber-security", "tier": "00", "synthetic_data": true,
				"environment_id": env.EnvironmentID, "marker_fingerprint": fingerprint,
			},
			"limitations": limitations, "content": content,
		}
		writeJSON(filepath.Join(root, "evidence", "learner", "tier-00", artifactType+".json"), record, 0o600)
	}
	for _, fixture := range []string{
		"tier-00/plaintext-inspection",
		"tier-00/device-id-spoofing",
		"tier-00/service-impersonation",
		"tier-00/altered-image",
	} {
		writeJSON(filepath.Join(root, "artifacts", "generated", "attacks", fixture, "run.json"), map[string]any{"result": "passed"}, 0o600)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"--repo", root, "evidence", "check"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "bound to the current revision") {
		t.Fatalf("completed Learner evidence failed: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func testRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	sourceRoot := filepath.Clean(filepath.Join("..", ".."))
	data, err := os.ReadFile(filepath.Join(sourceRoot, "course.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "course.yml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func initializeGitRepository(t *testing.T, root string) {
	t.Helper()
	commands := [][]string{
		{"init", "--quiet"},
		{"add", "course.yml"},
		{"-c", "user.name=Course Test", "-c", "user.email=course-test@example.invalid", "commit", "--quiet", "-m", "test"},
	}
	for _, args := range commands {
		command := exec.Command("git", append([]string{"-C", root}, args...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
}

func TestEnvironmentJSONShape(t *testing.T) {
	value := environment{1, "learning-cyber-security", "id", "00", true, time.Now(), time.Now().Add(time.Hour)}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"synthetic_data":true`)) {
		t.Fatalf("unexpected environment JSON: %s", data)
	}
}
