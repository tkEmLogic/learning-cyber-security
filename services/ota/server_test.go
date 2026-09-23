package ota

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

// newRangeServer builds a service that answers firmware downloads badly on
// purpose, with one release already published.
func newRangeServer(t *testing.T, behaviour string, image []byte) *Server {
	t.Helper()
	stateDir := t.TempDir()
	releaseDir := t.TempDir()
	server, err := New(Config{
		CourseID:       "learning-cyber-security",
		EnvironmentID:  "test-environment",
		Tier:           "05",
		StateDir:       stateDir,
		ReleaseDir:     releaseDir,
		RangeBehaviour: behaviour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "tier-05-healthy.bin"), image, 0o600); err != nil {
		t.Fatal(err)
	}
	release := Release{
		SchemaVersion: 1,
		ReleaseID:     "tier-05-healthy",
		Version:       "0.5.0-recoverable",
		Board:         "esp32c6_devkitc",
		ImagePath:     "tier-05-healthy.bin",
		ImageSize:     int64(len(image)),
	}
	data, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "current-release.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return server
}

// A correctly behaving service honours Range, which is what makes an ordinary
// resume work. This is the baseline the two misbehaviours are measured against.
func TestFirmwareHonoursRangeByDefault(t *testing.T) {
	image := bytes.Repeat([]byte{0xa5}, 4096)
	srv := httptest.NewServer(newRangeServer(t, "", image).Handler())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/firmware/tier-05-healthy.bin", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=1024-")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 3072 {
		t.Fatalf("body = %d bytes, want 3072", len(body))
	}
}

// The failure a device is most likely to get wrong: the whole body, with a
// 200, in answer to a request for part of it. A client that looks only at
// whether bytes arrived appends this to what it already has.
func TestFirmwareCanIgnoreRange(t *testing.T) {
	image := bytes.Repeat([]byte{0xa5}, 4096)
	srv := httptest.NewServer(newRangeServer(t, "ignore", image).Handler())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/firmware/tier-05-healthy.bin", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=1024-")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: the point of this mode is that it looks like success",
			response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != len(image) {
		t.Fatalf("body = %d bytes, want the whole %d byte image", len(body), len(image))
	}
}

// A genuine partial transfer: the headers promise the whole image and the
// connection dies part way through. This is what the device has to resume
// from, and it is deliberately different from a short file, which would be a
// size mismatch and would be refused rather than resumed.
func TestFirmwareCanBeInterrupted(t *testing.T) {
	image := bytes.Repeat([]byte{0xa5}, 4096)
	srv := httptest.NewServer(newRangeServer(t, "interrupt:1024", image).Handler())
	defer srv.Close()

	response, err := http.Get(srv.URL + "/v1/firmware/tier-05-healthy.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.ContentLength != int64(len(image)) {
		t.Fatalf("Content-Length = %d, want the full %d: the client must be told the whole "+
			"image is coming and then not receive it", response.ContentLength, len(image))
	}
	body, readErr := io.ReadAll(response.Body)
	if readErr == nil {
		t.Fatal("reading the body succeeded; the connection should have been dropped")
	}
	if len(body) > 1024 {
		t.Fatalf("received %d bytes, want no more than the 1024 byte limit", len(body))
	}
}

// Tier 7's device listener, and the thing every one of these tests asserts:
// the check name.
//
// A status is not a reason. Six distinct refusals are six identical 403s to
// anything reading only status codes, which is a true property of real systems
// and a Weakness ledger row in its own right. The firmware branches on `check`
// and so does every test below, because a test that asserts only the status
// has not tested what it claims to.

type testAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestAuthority(t *testing.T, name string) testAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testAuthority{cert: cert, key: key}
}

// issue mints one client certificate. The serial, the owner scope and the
// validity window are all callers' choices, because that is exactly the power
// the attack fixture has once it holds the Operational CA signing key.
func (a testAuthority) issue(t *testing.T, serial int64, deviceID, ownerScope string,
	notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject := pkix.Name{
		CommonName:   deviceID,
		Organization: []string{"Learning Cyber Security course, synthetic"},
	}
	if ownerScope != "" {
		subject.OrganizationalUnit = []string{ownerScope}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, key.Public(), a.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// mutualFixture is one service with mutual TLS on, both authorities, and a
// manufacturing record the test writes lines into.
type mutualFixture struct {
	server       *Server
	manufacturer testAuthority
	operational  testAuthority
	stateDir     string
	provisionDir string
	pkiDir       string
}

func newMutualFixture(t *testing.T) *mutualFixture {
	t.Helper()
	state := t.TempDir()
	releases := t.TempDir()
	provisioning := t.TempDir()
	manufacturer := newTestAuthority(t, "Learning Cyber Security Manufacturer Device CA")
	operational := newTestAuthority(t, "Learning Cyber Security Operational Device CA")

	image := []byte("synthetic firmware bytes")
	if err := os.WriteFile(filepath.Join(releases, "baseline.bin"), image, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(image)
	writeTestJSON(t, filepath.Join(state, "current-release.json"), Release{
		SchemaVersion: 1,
		ReleaseID:     "baseline",
		Version:       "0.7.0-operational",
		Board:         "esp32c6_devkitc/esp32c6/hpcore",
		ImagePath:     "baseline.bin",
		ImageSHA256:   hex.EncodeToString(sum[:]),
		ImageSize:     int64(len(image)),
	})

	// The signing material the service issues Operational certificates from.
	// It is a directory the service is handed, exactly as the running service
	// is handed COURSE_PKI_DIR, so a test issues through the same path a
	// Learner does.
	pki := t.TempDir()
	writeAuthorityFiles(t, pki, operational)

	server, err := New(Config{
		CourseID:      "learning-cyber-security",
		EnvironmentID: "test-environment",
		Tier:          "07",
		StateDir:      state,
		ReleaseDir:    releases,
		MutualTLS: &MutualTLS{
			ManufacturerCA:  manufacturer.cert,
			OperationalCA:   operational.cert,
			ProvisioningDir: provisioning,
			PKIDir:          pki,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &mutualFixture{
		server:       server,
		manufacturer: manufacturer,
		operational:  operational,
		stateDir:     state,
		provisionDir: provisioning,
		pkiDir:       pki,
	}
}

// writeAuthorityFiles writes an authority to disk under the host side's file
// names, which are the names the service reads.
func writeAuthorityFiles(t *testing.T, dir string, authority testAuthority) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(authority.key)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		operationalCACertFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.cert.Raw}),
		operationalCAKeyFile:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// claim writes the record line that issue #146's operator half will write:
// this device now belongs to this owner, and this is the serial it was issued.
func (f *mutualFixture) claim(t *testing.T, deviceID, owner string, serial int64) {
	t.Helper()
	f.appendRecord(t, "records.jsonl", map[string]any{
		"kind":               "claim",
		"recorded_at":        time.Now().UTC().Format(time.RFC3339Nano),
		"device_id":          deviceID,
		"owner_id":           owner,
		"lifecycle_state":    "claimed",
		"certificate_serial": strconv.FormatInt(serial, 10),
	})
}

func (f *mutualFixture) revoke(t *testing.T, serial int64) {
	t.Helper()
	f.appendRecord(t, "revoked.jsonl", map[string]any{
		"certificate_serial": strconv.FormatInt(serial, 10),
		"revoked_at":         time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (f *mutualFixture) appendRecord(t *testing.T, name string, row map[string]any) {
	t.Helper()
	line, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(f.provisionDir, name),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
}

// present builds a request that arrived on a connection carrying one verified
// client certificate. The chain is what the handler reads the role out of.
func present(t *testing.T, ca testAuthority, leaf *x509.Certificate,
	method, target, body string) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf, ca.cert}},
	}
	return request
}

// refusalOf runs one request against the device listener and reads the refusal
// out of the answer.
func (f *mutualFixture) refusalOf(t *testing.T, request *http.Request) (int, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	f.server.DeviceHandler().ServeHTTP(recorder, request)
	var body map[string]any
	if recorder.Body.Len() > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("answer was not JSON: %s", recorder.Body.String())
		}
	}
	return recorder.Code, body
}

func assertRefusal(t *testing.T, status int, body map[string]any, check string) {
	t.Helper()
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: every authorization refusal in this tier is 403", status)
	}
	if body["check"] != check {
		t.Fatalf("check = %v, want %q", body["check"], check)
	}
	if reason, _ := body["reason"].(string); reason == "" {
		t.Fatalf("refused at %s with no reason; the check names the property, the reason says what the caller holds", check)
	}
}

// A Factory identity at the ordinary download endpoint. Section 8 restricts
// the Factory identity to claiming and controlled recovery, and this is the
// half of that restriction the tier's success criteria name.
func TestFactoryIdentityIsRefusedAtTheDownloadEndpoint(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	factory, _ := f.manufacturer.issue(t, 4001, "beacon-remfg-206ef1170d64", "",
		now.Add(-time.Hour), now.Add(time.Hour))

	status, body := f.refusalOf(t, present(t, f.manufacturer, factory,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, status, body, CheckIdentityOperational)

	// Before certificate-active has passed, the subject is only what the
	// certificate says about itself.
	if _, present := body["device_id"]; present {
		t.Fatalf("a refusal made before the certificate was accepted must not assert a device_id: %#v", body)
	}
}

// And the other half, which #136 left out and #137 put back: an Operational
// certificate at the claim endpoint. A certificate is a role, not a ranking.
func TestOperationalIdentityIsRefusedAtTheClaimEndpoint(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	operational, _ := f.operational.issue(t, 7001, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7001)

	status, body := f.refusalOf(t, present(t, f.operational, operational, http.MethodPost,
		"https://ota.course.example/v1/devices/beacon-remfg-206ef1170d64/claim", `{"nonce":"x"}`))
	assertRefusal(t, status, body, CheckIdentityFactory)
}

// certificate-active, clause 1. The device cannot evaluate a validity window
// at all, so the service's clock is the only enforcer in the course.
func TestExpiredOperationalCertificateIsRefused(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	expired, _ := f.operational.issue(t, 7002, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-200*24*time.Hour), now.Add(-24*time.Hour))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7002)

	status, body := f.refusalOf(t, present(t, f.operational, expired,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, status, body, CheckCertificateActive)
	if !strings.Contains(body["reason"].(string), "expired") {
		t.Fatalf("reason must say which clause refused: %v", body["reason"])
	}
}

// certificate-active, clause 2. Revoked, and not yet expired: the certificate
// is refused although nothing in it has run out.
func TestRevokedCertificateIsRefusedThoughUnexpired(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	cert, _ := f.operational.issue(t, 7003, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7003)
	f.revoke(t, 7003)

	status, body := f.refusalOf(t, present(t, f.operational, cert,
		http.MethodGet, "https://ota.course.example/v1/firmware/baseline.bin", ""))
	assertRefusal(t, status, body, CheckCertificateActive)
	if !strings.Contains(body["reason"].(string), "revoked") {
		t.Fatalf("reason must say which clause refused: %v", body["reason"])
	}
}

// certificate-active, clause 3. Genuinely signed by the Operational CA, and
// the service has no record of issuing it: a CA signature is not an
// authorization, the record is.
func TestCertificateTheServiceNeverIssuedIsRefused(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	forged, _ := f.operational.issue(t, 9999, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7004)

	status, body := f.refusalOf(t, present(t, f.operational, forged,
		http.MethodGet, "https://ota.course.example/v1/releases/baseline/manifest", ""))
	assertRefusal(t, status, body, CheckCertificateActive)
	if !strings.Contains(body["reason"].(string), "no record of issuing") {
		t.Fatalf("reason must say which clause refused: %v", body["reason"])
	}
}

// device-claimed, reachable only because clause 3 joins on any claim record
// rather than this device's. A forged certificate carrying a recorded serial
// and the common name of a device that was never claimed.
func TestUnclaimedDeviceIsRefused(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	f.claim(t, "beacon-bypass-e7-01", "rival-labs", 7005)
	forged, _ := f.operational.issue(t, 7005, "beacon-never-claimed", "rival-labs",
		now.Add(-time.Hour), now.Add(90*24*time.Hour))

	status, body := f.refusalOf(t, present(t, f.operational, forged,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, status, body, CheckDeviceClaimed)
	if body["device_id"] != "beacon-never-claimed" {
		t.Fatalf("device_id = %v; the certificate has been accepted by now, so the refusal may name it", body["device_id"])
	}
}

// ownership-context: owner B's certificate against a device in owner A's
// context. Unreachable honestly under first-come ownership, which is why the
// fixture forges it.
func TestWrongOwnerScopeIsRefused(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7006)
	forged, _ := f.operational.issue(t, 7006, "beacon-remfg-206ef1170d64", "rival-labs",
		now.Add(-time.Hour), now.Add(90*24*time.Hour))

	status, body := f.refusalOf(t, present(t, f.operational, forged,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, status, body, CheckOwnershipContext)

	// Specific about what the caller holds, silent about the record.
	reason := body["reason"].(string)
	if !strings.Contains(reason, "rival-labs") {
		t.Fatalf("reason must name the scope the caller presented: %q", reason)
	}
	if strings.Contains(reason, "northwind") {
		t.Fatalf("reason names the current owner, which is the one thing the refuser could not otherwise learn: %q", reason)
	}
}

// identifier-consistent, path half. Today's service never compares the path
// value at all.
func TestEventPathIdentifierMustMatchTheCertificate(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	cert, _ := f.operational.issue(t, 7007, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7007)

	status, body := f.refusalOf(t, present(t, f.operational, cert, http.MethodPost,
		"https://ota.course.example/v1/devices/beacon-development-clone/events",
		`{"device_id":"beacon-development-clone","event_type":"status.observed"}`))
	assertRefusal(t, status, body, CheckIdentifierConsistent)
}

// identifier-consistent, body half. Tier 0 recorded "tier_00_trust":
// "body_device_id" and believed whatever the body said.
func TestEventBodyIdentifierMustMatchTheCertificate(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	cert, _ := f.operational.issue(t, 7008, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7008)

	status, body := f.refusalOf(t, present(t, f.operational, cert, http.MethodPost,
		"https://ota.course.example/v1/devices/beacon-remfg-206ef1170d64/events",
		`{"device_id":"beacon-development-clone","event_type":"status.observed"}`))
	assertRefusal(t, status, body, CheckIdentifierConsistent)
	if body["device_id"] != "beacon-remfg-206ef1170d64" {
		t.Fatalf("device_id = %v, want the certificate's, never the body's", body["device_id"])
	}
}

// The one identity that gets through, on the two routes that carry a second
// identifier and on one that does not.
func TestValidOperationalIdentityIsServed(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	cert, _ := f.operational.issue(t, 7009, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7009)

	recorder := httptest.NewRecorder()
	f.server.DeviceHandler().ServeHTTP(recorder, present(t, f.operational, cert,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("assignment = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	f.server.DeviceHandler().ServeHTTP(recorder, present(t, f.operational, cert, http.MethodPost,
		"https://ota.course.example/v1/devices/beacon-remfg-206ef1170d64/events",
		`{"device_id":"beacon-remfg-206ef1170d64","event_type":"status.observed"}`))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("event = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	var accepted map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted["accepted_from"] != "client_certificate" {
		t.Fatalf("the service must say which identity it believed: %#v", accepted)
	}
	if _, warned := accepted["warning"]; warned {
		t.Fatalf("Tier 0's warning is about trusting the body, and the body is no longer what is trusted: %#v", accepted)
	}

	stored := readEventLines(t, filepath.Join(f.stateDir, "events.jsonl"))
	if len(stored) != 1 {
		t.Fatalf("stored %d event lines, want 1", len(stored))
	}
	if stored[0]["accepted_from"] != "client_certificate" || stored[0]["certificate_device_id"] != "beacon-remfg-206ef1170d64" {
		t.Fatalf("the record must say which value the service believed and why: %#v", stored[0])
	}
	if _, old := stored[0]["tier_00_trust"]; old {
		t.Fatalf("the Tier 0 provenance must not be written behind mutual TLS: %#v", stored[0])
	}
}

// Every refusal lands in the service's own events.jsonl, tagged with the
// source that distinguishes a service-authored row from a device-authored
// one. That trail is the tier's "authorization tests" lab artifact, and it is
// what makes it a grep rather than a screenshot.
func TestRefusalsAreRecordedInTheServiceEventLog(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	factory, _ := f.manufacturer.issue(t, 4002, "beacon-remfg-206ef1170d64", "",
		now.Add(-time.Hour), now.Add(time.Hour))

	status, _ := f.refusalOf(t, present(t, f.manufacturer, factory,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}

	rows := readEventLines(t, filepath.Join(f.stateDir, "events.jsonl"))
	if len(rows) != 1 {
		t.Fatalf("recorded %d rows, want 1", len(rows))
	}
	row := rows[0]
	if row["source"] != "service" || row["check"] != CheckIdentityOperational {
		t.Fatalf("refusal row = %#v", row)
	}
	if row["certificate_serial"] != "4002" || row["certificate_subject"] != "beacon-remfg-206ef1170d64" {
		t.Fatalf("the service's own trail keeps what the wire body withholds: %#v", row)
	}
	if _, asserted := row["device_id"]; asserted {
		t.Fatalf("the row must record what was presented, not assert an established device: %#v", row)
	}
}

func readEventLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	return rows
}

// The one refusal in the tier with no check name at all.
//
// A client certificate from an authority outside the pool never reaches a
// handler: the handshake ends the connection, so there is no status, no body,
// no check, and nothing in events.jsonl. That asymmetry is the tier's clearest
// demonstration that a refusal's usefulness depends on which layer refuses.
func TestForeignIssuerFailsAtTheHandshakeWithNoCheckName(t *testing.T) {
	f := newMutualFixture(t)
	foreign := newTestAuthority(t, "Learning Cyber Security Untrusted CA")
	now := time.Now()
	leaf, key := foreign.issue(t, 1, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(time.Hour))

	response, err := f.overTheWire(t, leaf, key, "/v1/releases/current")
	if err == nil {
		response.Body.Close()
		t.Fatalf("the handshake accepted a foreign issuer, status %s", response.Status)
	}
	if _, err := os.Stat(filepath.Join(f.stateDir, "events.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("a handshake failure must leave no row behind, err=%v", err)
	}
}

// An expired certificate from a known authority must reach a handler, and be
// refused at certificate-active with a check name.
//
// This runs over a real handshake rather than a synthesized r.TLS, because a
// synthesized one cannot see the defect this test exists for.
// tls.RequireAndVerifyClientCert runs x509.Verify, which judges the validity
// window, so the listener used to refuse an expired Operational certificate
// during the handshake — with no status, no body and no check, exactly like a
// foreign issuer. Clause 1 of certificate-active was unreachable over the
// wire, and the device could not tell "your certificate ran out" from "I have
// never heard of your authority". Both rows now exist and they differ.
func TestExpiredCertificateIsRefusedByACheckAndNotByTheHandshake(t *testing.T) {
	f := newMutualFixture(t)
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7101)
	now := time.Now()
	expired, key := f.operational.issue(t, 7101, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-200*24*time.Hour), now.Add(-24*time.Hour))

	response, err := f.overTheWire(t, expired, key, "/v1/releases/current")
	if err != nil {
		t.Fatalf("the handshake refused an expired certificate, so no check could name it: %v", err)
	}
	defer response.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden || body["check"] != CheckCertificateActive {
		t.Fatalf("status %d check %v, want 403 %s", response.StatusCode, body["check"], CheckCertificateActive)
	}
	if reason, _ := body["reason"].(string); !strings.Contains(reason, "expired") {
		t.Fatalf("reason = %q, want it to say the certificate expired", reason)
	}
}

// overTheWire runs one request against a real device listener, configured
// exactly as cmd/ota configures it, and presents one client certificate.
func (f *mutualFixture) overTheWire(t *testing.T, leaf *x509.Certificate,
	key *ecdsa.PrivateKey, path string) (*http.Response, error) {
	t.Helper()
	listener := httptest.NewUnstartedServer(f.server.DeviceHandler())
	listener.TLS = &tls.Config{
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: f.server.cfg.MutualTLS.VerifyClientCertificate,
	}
	listener.StartTLS()
	t.Cleanup(listener.Close)

	client := listener.Client()
	transport := client.Transport.(*http.Transport)
	// Sent whatever the server says it will accept, so the refusal is the
	// server rejecting the certificate rather than the client declining to
	// offer it.
	transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}, nil
	}
	return client.Get(listener.URL + path)
}

// The safety check must never depend on the control it tests. The marker stays
// on the plain listener, is not redirected, and is served by neither of the
// two TLS listeners.
func TestTheMarkerIsServedOnlyOnThePlainListener(t *testing.T) {
	f := newMutualFixture(t)

	for name, handler := range map[string]http.Handler{
		"device":   f.server.DeviceHandler(),
		"operator": f.server.OperatorHandler(),
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(
			http.MethodGet, "/.well-known/course-environment", nil))
		if recorder.Code == http.StatusOK {
			t.Fatalf("the %s listener served the marker; a fixture holding a CA key could forge that check", name)
		}
	}

	for _, path := range []string{"/health", "/.well-known/course-environment"} {
		recorder := httptest.NewRecorder()
		f.server.SplitPublicHandler(8443, 8444, "ota.course.example").ServeHTTP(
			recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s on the plain listener = %d, want 200", path, recorder.Code)
		}
	}
}

// The plain listener sorts the moved routes by which listener now serves them,
// which is the split stated where a Learner meets it first.
func TestSplitPublicHandlerNamesTheRightListener(t *testing.T) {
	f := newMutualFixture(t)
	handler := f.server.SplitPublicHandler(8443, 8444, "ota.course.example")

	for path, want := range map[string]string{
		"/v1/firmware/baseline.bin": "ota.course.example:8443",
		"/v1/lab/reset":             "ota.course.example:8444",
	} {
		method := http.MethodGet
		if path == "/v1/lab/reset" {
			method = http.MethodPost
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s on the plain listener = %d, want 404", path, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), want) {
			t.Fatalf("%s must be sent to %s, got %s", path, want, recorder.Body.String())
		}
	}
}

// The lab controls authorize a lab, not a person: they keep the Course
// environment marker header they have always had, and they do not take the
// Owner credential.
func TestOperatorListenerKeepsTheLabControlsOnTheMarkerHeader(t *testing.T) {
	f := newMutualFixture(t)
	handler := f.server.OperatorHandler()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/lab/reset", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("lab reset without the marker = %d, want 403", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/releases/current", nil)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("the lab bench must be able to read back what it just set: %d", recorder.Code)
	}
}

// stubOwners stands in for issue #146's Owner credential store. It exists to
// prove the seam: the listener asks, the store answers, and a refusal from the
// store is the only 401 in the tier.
type stubOwners struct {
	owner  string
	secret string
}

func (s stubOwners) VerifyOwner(credential string) (string, *Refusal) {
	if credential != s.secret {
		return "", &Refusal{
			Check:  CheckOwnerCredentialKnown,
			Reason: "no Owner credential in the store matches the one presented",
		}
	}
	return s.owner, nil
}

func TestOperatorClaimSitsBehindTheOwnerCredential(t *testing.T) {
	f := newMutualFixture(t)

	// A service built with mutual TLS now has a store of its own, so the
	// unbuilt answer has to be asked for. It stays asserted because the branch
	// is still live: a caller may pass its own verifier, and one that passes
	// none at all must be told the route exists rather than be sent looking
	// for a typo.
	f.server.cfg.OwnerCredentials = nil
	recorder := httptest.NewRecorder()
	f.server.OperatorHandler().ServeHTTP(recorder,
		httptest.NewRequest(http.MethodPost, "/v1/claim", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unbuilt claim route = %d, want 503", recorder.Code)
	}

	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	var seen string
	f.server.cfg.Claim.Operator = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = OwnerFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/claim", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer wrong")
	f.server.OperatorHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("a credential the store does not know = %d, want 401", recorder.Code)
	}
	var refusal map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &refusal); err != nil {
		t.Fatal(err)
	}
	if refusal["check"] != CheckOwnerCredentialKnown {
		t.Fatalf("check = %v, want %q", refusal["check"], CheckOwnerCredentialKnown)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/v1/claim", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer correct-horse")
	f.server.OperatorHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("a known credential = %d, want 200", recorder.Code)
	}
	if seen != "northwind" {
		t.Fatalf("the handler must be handed the owner the credential belongs to, got %q", seen)
	}
}

// With --mutual-tls off, every byte the service emits is what it emits today.
//
// This is a hard constraint rather than a courtesy. The Tier 2 module quotes
// the plain listener's refusal body verbatim, down to the port in moved_to,
// and the Tier 0 module quotes the event answer down to its warning. Tiers 0
// to 6 run the service exactly as they always did.
func TestWithoutMutualTLSEveryAnswerIsUnchanged(t *testing.T) {
	state := t.TempDir()
	releases := t.TempDir()
	if err := os.WriteFile(filepath.Join(releases, "baseline.bin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	release := Release{1, "baseline", "0", "board", "baseline.bin", "", 1, true, false}
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
	if server.cfg.MutualTLS != nil {
		t.Fatal("mutual TLS must be off unless the Learner turned it on")
	}

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost,
		"/v1/devices/beacon-development-shared/events",
		strings.NewReader(`{"device_id":"beacon-development-clone","event_type":"status.observed"}`)))
	const wantEvent = `{"accepted":true,"accepted_device_id":"beacon-development-clone","warning":"Tier 0 trusts the JSON body device_id"}` + "\n"
	if recorder.Body.String() != wantEvent {
		t.Fatalf("the Tier 0 event answer changed:\n got %s\nwant %s", recorder.Body.String(), wantEvent)
	}

	stored := readEventLines(t, filepath.Join(state, "events.jsonl"))
	if len(stored) != 1 || stored[0]["tier_00_trust"] != "body_device_id" {
		t.Fatalf("the Tier 0 record changed: %#v", stored)
	}
	if _, added := stored[0]["accepted_from"]; added {
		t.Fatalf("a field Tier 0 never wrote appeared in its record: %#v", stored[0])
	}

	recorder = httptest.NewRecorder()
	server.PublicHandler(8443, "ota.course.example").ServeHTTP(recorder,
		httptest.NewRequest(http.MethodGet, "/v1/releases/current", nil))
	const wantMoved = `{"error":"this endpoint is no longer served over plain HTTP","moved_to":"https://ota.course.example:8443","still_here":["/health","/.well-known/course-environment"],"why":"Tier 2 moved release records, firmware, and events to an authenticated, encrypted connection","why_still_here":"the Course environment marker is a fail-closed targeting check, not a credential, and it must not depend on the control it is used to test"}` + "\n"
	if recorder.Body.String() != wantMoved {
		t.Fatalf("the Tier 2 redirect body changed:\n got %s\nwant %s", recorder.Body.String(), wantMoved)
	}
}
