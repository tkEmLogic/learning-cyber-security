package courseapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
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
	if !strings.Contains(stdout.String(), "00  IMPLEMENTED") || !strings.Contains(stdout.String(), "01  PLANNED") || !strings.Contains(stdout.String(), "B  PLANNED") {
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
