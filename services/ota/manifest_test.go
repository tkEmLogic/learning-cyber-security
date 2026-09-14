package ota

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// storedManifest is written with formatting no Go encoder would ever produce:
// tab indentation, a key order that is not the struct's and not alphabetical,
// and a trailing newline. That is the point. A real manifest is whatever bytes
// the signer signed, and the service has no opinion about how they look.
const storedManifest = `{
	"schema_version": 1,
	"release_id": "tier-04-baseline",
	"version": "0.4.0-release-policy",
	"security_counter": 1,
	"channel": "stable",
	"board": "esp32c6_devkitc/esp32c6/hpcore",
	"hardware_revision_min": 1,
	"hardware_revision_max": 1,
	"image_path": "tier-04-baseline.bin",
	"image_size": 663611,
	"image_sha256": "8ad643509ec835b176bd623632be35b6c21db35610ab1d74daca70bd077b69bc",
	"created_at": "2026-09-14T13:20:00Z",
	"supported_until": "2031-09-14T00:00:00Z"
}
`

// TestManifestBytesSurviveTheServiceUnchanged is the test this whole split
// exists for.
//
// It signs the exact stored bytes with an ECDSA P-256 key, serves them, and
// verifies the signature against what came back off the wire. If anything on
// the path parsed the manifest and re-encoded it, the bytes would differ and
// the signature would fail, which is exactly what the old handler did by
// re-marshalling the Go struct.
func TestManifestBytesSurviveTheServiceUnchanged(t *testing.T) {
	server, releases := newManifestTestServer(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stored := []byte(storedManifest)
	digest := sha256.Sum256(stored)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	writeReleaseFile(t, releases, "tier-04-baseline.manifest.json", stored)
	writeReleaseFile(t, releases, "tier-04-baseline.manifest.sig", signature)

	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	served := getBytes(t, httpServer.URL+"/v1/releases/tier-04-baseline/manifest", http.StatusOK)
	if !bytes.Equal(served, stored) {
		t.Fatalf("served manifest is not the stored manifest\nstored: %q\nserved: %q", stored, served)
	}

	servedSignature := getBytes(t, httpServer.URL+"/v1/releases/tier-04-baseline/manifest.sig", http.StatusOK)
	if !bytes.Equal(servedSignature, signature) {
		t.Fatal("served signature is not the stored signature")
	}

	servedDigest := sha256.Sum256(served)
	if !ecdsa.VerifyASN1(&key.PublicKey, servedDigest[:], servedSignature) {
		t.Fatal("the signature does not verify against the bytes the service served")
	}

	// And the negative half: re-encoding the same values, changing nothing a
	// reader would call a value, produces different bytes and a signature that
	// no longer verifies. This is what the endpoint used to do.
	var parsed map[string]any
	if err := json.Unmarshal(stored, &parsed); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reencoded, stored) {
		t.Fatal("the re-encoded manifest must differ, or this test proves nothing")
	}
	reencodedDigest := sha256.Sum256(reencoded)
	if ecdsa.VerifyASN1(&key.PublicKey, reencodedDigest[:], signature) {
		t.Fatal("re-encoded manifest still verified; the signature is not covering the bytes")
	}
}

// The signature must be findable from the manifest response, because the device
// fetches both and has nothing else to go on.
func TestManifestResponsePointsAtItsSignature(t *testing.T) {
	server, releases := newManifestTestServer(t)
	writeReleaseFile(t, releases, "tier-04-baseline.manifest.json", []byte(storedManifest))

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder,
		httptest.NewRequest(http.MethodGet, "/v1/releases/tier-04-baseline/manifest", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("manifest status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("X-Course-Manifest-Signature"); got != "/v1/releases/tier-04-baseline/manifest.sig" {
		t.Fatalf("manifest signature header = %q", got)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("manifest content type = %q", got)
	}
}

// Range requests work on the manifest for the same reason they work on
// firmware: both are served straight from the file by http.ServeContent.
func TestManifestSupportsRangeRequests(t *testing.T) {
	server, releases := newManifestTestServer(t)
	stored := []byte(storedManifest)
	writeReleaseFile(t, releases, "tier-04-baseline.manifest.json", stored)

	request := httptest.NewRequest(http.MethodGet, "/v1/releases/tier-04-baseline/manifest", nil)
	request.Header.Set("Range", "bytes=0-9")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPartialContent {
		t.Fatalf("range status = %d, want 206", recorder.Code)
	}
	if !bytes.Equal(recorder.Body.Bytes(), stored[:10]) {
		t.Fatalf("range body = %q", recorder.Body.Bytes())
	}
}

// A release with no stored manifest is a 404 that says so. The service does not
// invent one, because it cannot: it does not hold the Release signing key.
func TestMissingManifestExplainsItself(t *testing.T) {
	server, _ := newManifestTestServer(t)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder,
		httptest.NewRequest(http.MethodGet, "/v1/releases/tier-04-nothing-here/manifest", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing manifest status = %d, want 404", recorder.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["release_id"] != "tier-04-nothing-here" || body["error"] == nil {
		t.Fatalf("missing manifest body = %#v", body)
	}
}

// A release identifier is a name, never a path. The router already refuses a
// slash inside the segment; `..` it would happily pass through.
func TestReleaseIDCannotWalkOutOfTheReleaseDirectory(t *testing.T) {
	server, releases := newManifestTestServer(t)
	outside := filepath.Join(filepath.Dir(releases), "secret.manifest.json")
	if err := os.WriteFile(outside, []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"..", "..secret", "a..b", "tier%2004", "tier%2F04"} {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder,
			httptest.NewRequest(http.MethodGet, "/v1/releases/"+id+"/manifest", nil))
		if recorder.Code == http.StatusOK {
			t.Errorf("release_id %q was served", id)
		}
	}
}

// The Update assignment is a separate object and its wire shape is frozen.
// Tiers 0, 2 and 3 are published and describe this record exactly, and
// decodeJSON refuses unknown fields, so an added field breaks both the reading
// and the writing half of every one of those tiers. This test is the guard.
func TestUpdateAssignmentWireShapeIsUnchanged(t *testing.T) {
	server, releases := newManifestTestServer(t)
	image := []byte("synthetic firmware bytes")
	writeReleaseFile(t, releases, "baseline.bin", image)
	release := Release{
		SchemaVersion: 1,
		ReleaseID:     "baseline",
		Version:       "0.0.0-insecure",
		Board:         "esp32c6_devkitc/esp32c6/hpcore",
		ImagePath:     "baseline.bin",
		ImageSHA256:   "f28a01",
		ImageSize:     int64(len(image)),
		Mutable:       true,
		Signed:        false,
	}
	writeTestJSON(t, filepath.Join(server.cfg.StateDir, "current-release.json"), release)

	// A stored manifest for this release must not leak into the assignment.
	writeReleaseFile(t, releases, "baseline.manifest.json", []byte(storedManifest))
	writeReleaseFile(t, releases, "baseline.manifest.sig", []byte{0x30, 0x00})

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder,
		httptest.NewRequest(http.MethodGet, "/v1/releases/current", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("assignment status = %d", recorder.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"schema_version", "release_id", "version", "board",
		"image_path", "image_sha256", "image_size", "mutable", "signed",
	}
	if len(body) != len(want) {
		t.Fatalf("the Update assignment gained or lost a field: %#v", body)
	}
	for _, field := range want {
		if _, ok := body[field]; !ok {
			t.Errorf("the Update assignment lost %q, which a published tier quotes", field)
		}
	}
}

func newManifestTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	releases := filepath.Join(t.TempDir(), "releases")
	if err := os.MkdirAll(releases, 0o700); err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		CourseID:      "learning-cyber-security",
		EnvironmentID: "test-environment",
		Tier:          "04",
		StateDir:      t.TempDir(),
		ReleaseDir:    releases,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, releases
}

func writeReleaseFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func getBytes(t *testing.T, url string, wantStatus int) []byte {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		t.Fatalf("GET %s = %s, want %d", url, response.Status, wantStatus)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
