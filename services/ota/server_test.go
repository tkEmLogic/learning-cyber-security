package ota

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTierZeroProtocolAndInsecureEffects(t *testing.T) {
	state := t.TempDir()
	releases := t.TempDir()
	image := []byte("synthetic firmware bytes")
	if err := os.WriteFile(filepath.Join(releases, "baseline.bin"), image, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(image)
	release := Release{
		SchemaVersion: 1,
		ReleaseID:     "baseline",
		Version:       "0.0.0-insecure",
		Board:         "esp32c6_devkitc/esp32c6/hpcore",
		ImagePath:     "baseline.bin",
		ImageSHA256:   hex.EncodeToString(sum[:]),
		ImageSize:     int64(len(image)),
		Mutable:       true,
		Signed:        false,
	}
	writeTestJSON(t, filepath.Join(state, "seed-release.json"), release)
	writeTestJSON(t, filepath.Join(state, "current-release.json"), release)
	server, err := New(Config{
		CourseID:      "learning-cyber-security",
		EnvironmentID: "test-environment",
		Tier:          "00",
		StateDir:      state,
		ReleaseDir:    releases,
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	response, err := http.Get(httpServer.URL + "/.well-known/course-environment")
	if err != nil {
		t.Fatal(err)
	}
	var marker map[string]any
	if err := json.NewDecoder(response.Body).Decode(&marker); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if marker["environment_id"] != "test-environment" || marker["synthetic_data"] != true {
		t.Fatalf("unexpected marker: %#v", marker)
	}

	event := `{"device_id":"beacon-development-clone","event_type":"status.observed"}`
	response, err = http.Post(httpServer.URL+"/v1/devices/beacon-development-shared/events", "application/json", strings.NewReader(event))
	if err != nil {
		t.Fatal(err)
	}
	var accepted map[string]any
	if err := json.NewDecoder(response.Body).Decode(&accepted); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted || accepted["accepted_device_id"] != "beacon-development-clone" {
		t.Fatalf("Tier 0 did not trust the spoofed body identifier: %#v", accepted)
	}

	request, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/v1/firmware/baseline.bin", nil)
	request.Header.Set("Range", "bytes=0-8")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusPartialContent {
		t.Fatalf("range request status = %s", response.Status)
	}
	response.Body.Close()

	altered := []byte("altered synthetic firmware")
	if err := os.WriteFile(filepath.Join(releases, "altered.bin"), altered, 0o600); err != nil {
		t.Fatal(err)
	}
	alteredSum := sha256.Sum256(altered)
	changed := Release{1, "altered", "0.0.0-altered", release.Board, "altered.bin", hex.EncodeToString(alteredSum[:]), int64(len(altered)), true, false}
	data, _ := json.Marshal(changed)
	request, _ = http.NewRequest(http.MethodPut, httpServer.URL+"/v1/releases/current", bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Course-Environment-ID", "test-environment")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("mutable release status = %s", response.Status)
	}
	response.Body.Close()

	request, _ = http.NewRequest(http.MethodPost, httpServer.URL+"/v1/lab/reset", nil)
	request.Header.Set("X-Course-Environment-ID", "test-environment")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reset status = %s", response.Status)
	}
	response.Body.Close()

	var restored Release
	data, err = os.ReadFile(filepath.Join(state, "current-release.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.ReleaseID != "baseline" {
		t.Fatalf("reset restored %q, want baseline", restored.ReleaseID)
	}
	if _, err := os.Stat(filepath.Join(state, "events.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("reset left events file, err=%v", err)
	}
}

func TestMutationRequiresCourseMarker(t *testing.T) {
	state := t.TempDir()
	releases := t.TempDir()
	if err := os.WriteFile(filepath.Join(releases, "baseline.bin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	release := Release{1, "baseline", "0", "board", "baseline.bin", "", 1, true, false}
	writeTestJSON(t, filepath.Join(state, "seed-release.json"), release)
	writeTestJSON(t, filepath.Join(state, "current-release.json"), release)
	server, err := New(Config{
		CourseID:      "learning-cyber-security",
		EnvironmentID: "expected",
		Tier:          "00",
		StateDir:      state,
		ReleaseDir:    releases,
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	data, _ := json.Marshal(release)
	request, _ := http.NewRequest(http.MethodPut, httpServer.URL+"/v1/releases/current", bytes.NewReader(data))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation without marker status = %s", response.Status)
	}
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The marker must stay reachable in the clear in every tier, because a safety
// check cannot depend on the control it is used to test. The data endpoints
// must leave the plain listener and say where they went.
func TestPublicHandlerKeepsTheMarkerAndMovesTheData(t *testing.T) {
	server := newTestServer(t)

	for _, path := range []string{"/health", "/.well-known/course-environment"} {
		recorder := httptest.NewRecorder()
		server.PublicHandler(8443, "ota.course.example").ServeHTTP(
			recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("%s on the plain listener = %d, want 200", path, recorder.Code)
		}
	}

	recorder := httptest.NewRecorder()
	server.PublicHandler(8443, "ota.course.example").ServeHTTP(
		recorder, httptest.NewRequest(http.MethodGet, "/v1/releases/current", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("release record on the plain listener = %d, want 404", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "ota.course.example:8443") {
		t.Fatalf("the refusal must say where the endpoint went, got %s", recorder.Body.String())
	}
}

func TestDataHandlerDoesNotServeTheMarker(t *testing.T) {
	server := newTestServer(t)
	recorder := httptest.NewRecorder()
	server.DataHandler().ServeHTTP(
		recorder, httptest.NewRequest(http.MethodGet, "/.well-known/course-environment", nil))
	if recorder.Code == http.StatusOK {
		t.Fatal("the marker must not be served behind TLS; the fixtures read it in the clear")
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	server, err := New(Config{
		CourseID:      "learning-cyber-security",
		EnvironmentID: "test-environment",
		Tier:          "02",
		StateDir:      t.TempDir(),
		ReleaseDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}
