package courseapp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// fakeDevice stands in for the ESP32-C6 so the station can be exercised before
// any board exists.
//
// It does what the firmware will do and nothing else: generate a P-256 key,
// build a certification request carrying the Bootstrap credential inside the
// signed structure, and sign it with the key it is claiming. Building the
// station against this first is deliberate. A station that can only be driven
// through firmware cannot be debugged when the firmware is also new.
type fakeDevice struct {
	key *ecdsa.PrivateKey
}

func newFakeDevice(t *testing.T) *fakeDevice {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeDevice{key: key}
}

func (d *fakeDevice) request(t *testing.T, deviceID, credential string) []byte {
	t.Helper()
	value, err := MarshalCredentialExtension(credential)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: deviceID},
		ExtraExtensions: []pkix.Extension{{
			Id:    CredentialExtensionOID(),
			Value: value,
		}},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, d.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func provisioningApp(t *testing.T) (*app, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	out := &bytes.Buffer{}
	a := &app{root: root, out: out, errOut: out}
	a.manifest.Paths.State = ".course-state"
	a.manifest.Paths.Secrets = ".course-secrets"
	if err := coursepki.GenerateDeviceCA(a.deviceCADir()); err != nil {
		t.Fatal(err)
	}
	return a, out
}

// credentialFor mints one and digs the printed secret back out, which is the
// only place it ever exists. The store keeps a verifier.
func credentialFor(t *testing.T, a *app, out *bytes.Buffer, deviceID string) string {
	t.Helper()
	before := out.Len()
	if err := a.issueCredential(deviceID); err != nil {
		t.Fatal(err)
	}
	printed := out.String()[before:]
	for _, line := range strings.Split(printed, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && !strings.Contains(line, " ") {
			return line
		}
	}
	t.Fatalf("no credential was printed in:\n%s", printed)
	return ""
}

func TestEnrollmentIssuesACertificateAndConsumesTheCredential(t *testing.T) {
	a, out := provisioningApp(t)
	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, "beacon-aabbccddeeff")

	outcome, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-aabbccddeeff",
		CSRDer:   device.request(t, "beacon-aabbccddeeff", credential),
	}, credential)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Issued {
		t.Fatalf("expected a certificate, got refusal %s: %s", outcome.Check, outcome.Reason)
	}

	issued, err := x509.ParseCertificate(outcome.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Subject.CommonName != "beacon-aabbccddeeff" {
		t.Fatalf("certificate names %q", issued.Subject.CommonName)
	}
	// The certificate must carry the key the device proved it holds, not one the
	// station chose.
	if !device.key.PublicKey.Equal(issued.PublicKey) {
		t.Fatal("the issued certificate does not carry the device's own public key")
	}
}

// E-6-01. The refusal this whole tier builds toward.
func TestAConsumedCredentialCannotEnrollASecondTime(t *testing.T) {
	a, out := provisioningApp(t)
	credential := credentialFor(t, a, out, "beacon-aabbccddeeff")

	first := newFakeDevice(t)
	if _, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-aabbccddeeff",
		CSRDer:   first.request(t, "beacon-aabbccddeeff", credential),
	}, credential); err != nil {
		t.Fatal(err)
	}

	// A different device, the same credential. This is the clone.
	clone := newFakeDevice(t)
	outcome, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-aabbccddeeff",
		CSRDer:   clone.request(t, "beacon-aabbccddeeff", credential),
	}, credential)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Issued {
		t.Fatal("a consumed Bootstrap credential enrolled a second device")
	}
	// The refusal must name which check ran and what it compared, not just fail.
	if outcome.Check != "credential-unconsumed" {
		t.Fatalf("refused at %q, want credential-unconsumed: %s", outcome.Check, outcome.Reason)
	}
	if !strings.Contains(outcome.Reason, "was consumed at") {
		t.Fatalf("refusal does not say when it was consumed: %s", outcome.Reason)
	}
}

// E-6-02, the backstop: a fresh credential cannot take over an identifier that
// already holds a certificate.
func TestASecondCredentialCannotTakeOverAnEnrolledIdentifier(t *testing.T) {
	a, out := provisioningApp(t)

	first := credentialFor(t, a, out, "beacon-aabbccddeeff")
	genuine := newFakeDevice(t)
	if _, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-aabbccddeeff",
		CSRDer:   genuine.request(t, "beacon-aabbccddeeff", first),
	}, first); err != nil {
		t.Fatal(err)
	}

	second := credentialFor(t, a, out, "beacon-aabbccddeeff")
	clone := newFakeDevice(t)
	outcome, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-aabbccddeeff",
		CSRDer:   clone.request(t, "beacon-aabbccddeeff", second),
	}, second)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Issued {
		t.Fatal("a second certificate was issued for an identifier that already holds one")
	}
	if outcome.Check != "identifier-unused" {
		t.Fatalf("refused at %q, want identifier-unused: %s", outcome.Check, outcome.Reason)
	}
}

// E-6-03. Proof of possession: a request for a key you do not hold.
func TestARequestNotSignedByItsOwnKeyIsRefused(t *testing.T) {
	a, out := provisioningApp(t)
	credential := credentialFor(t, a, out, "beacon-aabbccddeeff")

	device := newFakeDevice(t)
	der := device.request(t, "beacon-aabbccddeeff", credential)
	// Corrupt the signature, leaving the request otherwise intact. This is what
	// a request built around somebody else's public key looks like to the
	// station: everything parses and nothing verifies.
	der[len(der)-1] ^= 0xff

	outcome, err := a.enroll(enrollmentRequest{DeviceID: "beacon-aabbccddeeff", CSRDer: der}, credential)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Issued {
		t.Fatal("a request that does not verify was issued a certificate")
	}
	if outcome.Check != "proof-of-possession" {
		t.Fatalf("refused at %q, want proof-of-possession", outcome.Check)
	}
}

// The credential must be bound to the key, not merely presented beside it.
func TestACredentialLiftedOntoAnotherKeyIsRefused(t *testing.T) {
	a, out := provisioningApp(t)
	credential := credentialFor(t, a, out, "beacon-aabbccddeeff")

	// A clone that holds a valid credential but signs a request carrying a
	// different one. The station compares what is inside the signature against
	// what it was handed.
	clone := newFakeDevice(t)
	outcome, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-aabbccddeeff",
		CSRDer:   clone.request(t, "beacon-aabbccddeeff", "not-the-credential-that-was-issued"),
	}, credential)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Issued {
		t.Fatal("a request carrying the wrong credential was issued a certificate")
	}
	if outcome.Check != "credential-binding" {
		t.Fatalf("refused at %q, want credential-binding: %s", outcome.Check, outcome.Reason)
	}
}

func TestAnUnknownCredentialIsRefused(t *testing.T) {
	a, _ := provisioningApp(t)
	device := newFakeDevice(t)
	credential := strings.Repeat("ab", 32)

	outcome, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-aabbccddeeff",
		CSRDer:   device.request(t, "beacon-aabbccddeeff", credential),
	}, credential)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Issued {
		t.Fatal("a credential that was never issued enrolled a device")
	}
	if outcome.Check != "credential-known" {
		t.Fatalf("refused at %q, want credential-known", outcome.Check)
	}
}

// Section 11 makes this a stated failure criterion for the tier, so it is
// enforced rather than reviewed.
func TestTheManufacturingRecordNeverHoldsPrivateKeyMaterial(t *testing.T) {
	a, out := provisioningApp(t)
	credential := credentialFor(t, a, out, "beacon-aabbccddeeff")
	device := newFakeDevice(t)
	if _, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-aabbccddeeff",
		CSRDer:   device.request(t, "beacon-aabbccddeeff", credential),
	}, credential); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(a.provisionRecordPath())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{"PRIVATE KEY", "privateKey", credential} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("the manufacturing record contains %q", forbidden)
		}
	}
	// It must hold the verifier, though, or there is nothing to check against.
	if !strings.Contains(text, verifierFor(credential)) {
		t.Fatal("the manufacturing record does not hold the credential verifier")
	}
}

// The store is append only, and a refusal is recorded as carefully as a
// success. Section 8 requires every provisioning attempt and state change to be
// recorded.
func TestRefusalsAreRecordedNotDiscarded(t *testing.T) {
	a, _ := provisioningApp(t)
	device := newFakeDevice(t)
	credential := strings.Repeat("cd", 32)
	if _, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-aabbccddeeff",
		CSRDer:   device.request(t, "beacon-aabbccddeeff", credential),
	}, credential); err != nil {
		t.Fatal(err)
	}
	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Result != "refused" {
		t.Fatalf("expected one refused record, got %+v", records)
	}
	if !strings.Contains(records[0].Detail, "credential-known") {
		t.Fatalf("the record does not name the check that refused: %q", records[0].Detail)
	}
}

// A device identifier reaches a certificate subject, so it is held to a shape.
func TestDeviceIdentifiersAreValidated(t *testing.T) {
	for _, bad := range []string{"", "../escape", "Beacon-Upper", "beacon aabb", strings.Repeat("a", 65)} {
		if err := validateDeviceID(bad); err == nil {
			t.Fatalf("accepted device identifier %q", bad)
		}
	}
	if err := validateDeviceID("beacon-404cca5ea9fc"); err != nil {
		t.Fatalf("rejected a good identifier: %v", err)
	}
}

func TestTheDeviceCARefusesToReplaceItself(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if err := coursepki.GenerateDeviceCA(dir); err != nil {
		t.Fatal(err)
	}
	if err := coursepki.GenerateDeviceCA(dir); err == nil {
		t.Fatal("the device CA replaced itself silently")
	}
}

// The device CA is a different authority from the Course CA, and the course
// says so repeatedly. Check it is actually true.
func TestTheDeviceCAIsNotTheCourseCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if err := coursepki.Generate(dir); err != nil {
		t.Fatal(err)
	}
	if err := coursepki.GenerateDeviceCA(dir); err != nil {
		t.Fatal(err)
	}
	deviceCA, _, err := coursepki.LoadDeviceCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	courseRaw, err := os.ReadFile(filepath.Join(dir, coursepki.CourseCADER))
	if err != nil {
		t.Fatal(err)
	}
	courseCA, err := x509.ParseCertificate(courseRaw)
	if err != nil {
		t.Fatal(err)
	}
	if deviceCA.Subject.CommonName == courseCA.Subject.CommonName {
		t.Fatal("the device CA and the Course CA share a subject")
	}
	if bytes.Equal(deviceCA.RawSubjectPublicKeyInfo, courseCA.RawSubjectPublicKeyInfo) {
		t.Fatal("the device CA and the Course CA share a key")
	}
}

// The invariant to check the implementation against: nothing ever leaves the
// station that the record does not already contain.
//
// The ordering everyone writes first is issue, send, then mark consumed, and it
// produces the worst possible artefact: a certificate that exists in the field
// and in no record. Here the record is written before the certificate is
// returned, so a station that cannot record cannot issue either.
func TestAStationThatCannotRecordDoesNotIssue(t *testing.T) {
	a, out := provisioningApp(t)
	credential := credentialFor(t, a, out, "beacon-aabbccddeeff")
	device := newFakeDevice(t)

	// Make the record impossible to append to.
	//
	// A permissions bit would not do: the verification container runs as root,
	// which ignores them, and the first version of this test passed on the host
	// and failed in the container for exactly that reason. Replacing the file
	// with a directory is a failure nothing can bypass.
	if err := os.Remove(a.provisionRecordPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(a.provisionRecordPath(), 0o700); err != nil {
		t.Fatal(err)
	}

	outcome, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-aabbccddeeff",
		CSRDer:   device.request(t, "beacon-aabbccddeeff", credential),
	}, credential)
	if err == nil {
		t.Fatal("enrollment succeeded although the record could not be written")
	}
	if outcome.Issued || outcome.CertDER != nil {
		t.Fatal("a certificate was returned although nothing could be recorded")
	}
}
