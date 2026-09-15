package courseapp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

// The before state. The same proof of possession, asking a question every
// device in the fleet knows the answer to.
func TestSharedRegistrationAcceptsAnythingHoldingTheFleetKey(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := coursepki.GenerateSharedIdentity(a.deviceCADir()); err != nil {
		t.Fatal(err)
	}
	certDER, key, err := coursepki.LoadSharedIdentity(a.deviceCADir())
	if err != nil {
		t.Fatal(err)
	}

	sign := func() ([]byte, []byte) {
		nonce, err := sharedRegistrationNonce()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(nonce)
		signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return nonce, signature
	}

	// The Learner's own board.
	nonce, signature := sign()
	first, err := a.registerShared("beacon-development-shared", certDER, nonce, signature)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Issued {
		t.Fatalf("the genuine device was refused: %s", first.Reason)
	}

	// The clone, on the host, holding the same extracted key. Nothing
	// distinguishes it, which is the entire point of the tier.
	nonce, signature = sign()
	second, err := a.registerShared("beacon-development-shared", certDER, nonce, signature)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Issued {
		t.Fatalf("the clone was refused before hardening: %s", second.Reason)
	}

	// Two records, one fingerprint. This is the screen that teaches the tier.
	if first.CertFingerprint != second.CertFingerprint {
		t.Fatal("the clone somehow presented a different certificate")
	}
	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	issued := 0
	for _, record := range records {
		if record.Kind == recordEnrollment && record.Result == "issued" {
			issued++
			if record.CertFingerprint != first.CertFingerprint {
				t.Fatal("a record carries a different fingerprint")
			}
		}
	}
	if issued != 2 {
		t.Fatalf("expected two registrations sharing one fingerprint, got %d", issued)
	}
}

// Even before hardening the proof is real: holding the certificate is not
// enough, you have to hold the key.
func TestSharedRegistrationStillNeedsTheKey(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := coursepki.GenerateSharedIdentity(a.deviceCADir()); err != nil {
		t.Fatal(err)
	}
	certDER, _, err := coursepki.LoadSharedIdentity(a.deviceCADir())
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := sharedRegistrationNonce()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(nonce)
	signature, err := ecdsa.SignASN1(rand.Reader, other, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := a.registerShared("beacon-development-shared", certDER, nonce, signature)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Issued {
		t.Fatal("registration succeeded with a signature from the wrong key")
	}
	if outcome.Check != "proof-of-possession" {
		t.Fatalf("refused at %q, want proof-of-possession", outcome.Check)
	}
}

// buildSharedImageStub writes a fake "image": a blob with the fleet's SEC1
// private key and its certificate embedded in it, surrounded by noise, so
// extraction has something to search that looks like a firmware image rather
// than a key file. It returns the shared cert DER for the test to compare
// against.
func buildSharedImageStub(t *testing.T, a *app) []byte {
	t.Helper()
	if err := coursepki.GenerateSharedIdentity(a.deviceCADir()); err != nil {
		t.Fatal(err)
	}
	certDER, key, err := coursepki.LoadSharedIdentity(a.deviceCADir())
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// Noise, then the key, more noise, then the certificate, more noise. The
	// order is deliberately key-before-cert and not adjacent, so the test
	// proves the certificate is found by matching the key rather than by
	// sitting next to it.
	noise := make([]byte, 4096)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	var image []byte
	image = append(image, noise...)
	image = append(image, keyDER...)
	image = append(image, noise...)
	image = append(image, certDER...)
	image = append(image, noise...)

	dir := filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "releases")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tier-06-shared-identity.bin"), image, 0o600); err != nil {
		t.Fatal(err)
	}
	return certDER
}

func TestExtractionFindsTheFleetKeyAndCertificateInAnImage(t *testing.T) {
	a, _ := provisioningApp(t)
	a.manifest.Paths.GeneratedArtifacts = "artifacts/generated"
	a.manifest.Fixtures = map[string]fixture{
		"tier-06/clone-shared-identity": {Image: "tier-06-shared-identity.bin"},
	}
	certDER := buildSharedImageStub(t, a)

	image, err := os.ReadFile(func() string { p, _ := a.sharedImagePath(); return p }())
	if err != nil {
		t.Fatal(err)
	}
	foundCert, key, offset, err := extractSharedIdentity(image)
	if err != nil {
		t.Fatal(err)
	}
	if offset < 0 || key == nil {
		t.Fatal("the key was not located")
	}
	if !bytes.Equal(foundCert, certDER) {
		t.Fatal("the certificate found by matching the key is not the fleet certificate")
	}
	// The public half of the extracted key must be the certificate's key, which
	// is the whole basis for using it to impersonate the fleet.
	cert, err := x509.ParseCertificate(foundCert)
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("the extracted key does not match the certificate")
	}
}

// The extraction command must refuse a Learner-supplied path. A command that
// read any named file would be a general-purpose key-recovery tool.
func TestExtractionRefusesASuppliedPath(t *testing.T) {
	a, _ := provisioningApp(t)
	err := a.provisionExtract([]string{"--image", "/etc/shadow"})
	if err == nil || !strings.Contains(err.Error(), "takes no path") {
		t.Fatalf("expected a refusal of the supplied path, got %v", err)
	}
}

// The clone registers a duplicate and phantoms under one credential, and its
// reset appends rather than deletes.
func TestCloneRegistersDuplicatesAndPhantomsThenResetAppends(t *testing.T) {
	a, _ := provisioningApp(t)
	a.manifest.Paths.GeneratedArtifacts = "artifacts/generated"
	a.manifest.Fixtures = map[string]fixture{
		"tier-06/clone-shared-identity": {
			Image:      "tier-06-shared-identity.bin",
			PhantomIDs: []string{"beacon-phantom-0001", "beacon-phantom-0002"},
		},
	}
	certDER := buildSharedImageStub(t, a)
	fingerprint := certFingerprint(certDER)

	// A real device registers first, so the clone has an identity to take over.
	_, key, err := coursepki.LoadSharedIdentity(a.deviceCADir())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.cloneRegister("beacon-development-shared", certDER, key); err != nil {
		t.Fatal(err)
	}

	observed, limitation, hashes, err := a.cloneSharedIdentity(environment{})
	if err != nil {
		t.Fatal(err)
	}
	if limitation != "" {
		t.Fatalf("the clone runs on the host and claims nothing about a board, got limitation %q", limitation)
	}
	if hashes["shared-identity-certificate"] != fingerprint {
		t.Fatal("the evidence does not carry the shared certificate fingerprint")
	}
	if !strings.Contains(observed, "no board") {
		t.Fatalf("observed effect should say no board was involved: %q", observed)
	}

	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	shared, phantom, resets := 0, 0, 0
	for _, r := range records {
		switch {
		case r.Kind == recordEnrollment && r.DeviceID == "beacon-development-shared" && r.Result == "issued":
			shared++
			if r.CertFingerprint != fingerprint {
				t.Fatal("a shared entry carries a different fingerprint")
			}
		case r.Kind == recordEnrollment && strings.HasPrefix(r.DeviceID, "beacon-phantom-") && r.Result == "issued":
			phantom++
		case r.Kind == recordFixtureReset:
			resets++
		}
	}
	// Two entries under one identifier: the real registration and the clone's.
	if shared != 2 {
		t.Fatalf("expected 2 shared-identifier entries, got %d", shared)
	}
	if phantom != 2 {
		t.Fatalf("expected 2 phantom entries, got %d", phantom)
	}

	// Reset appends and never deletes.
	before := len(records)
	if err := a.resetClone(); err != nil {
		t.Fatal(err)
	}
	after, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != before+1 {
		t.Fatalf("reset should append exactly one record, went from %d to %d", before, len(after))
	}
	if after[len(after)-1].Kind != recordFixtureReset {
		t.Fatal("the appended record is not a fixture_reset")
	}
	if resets != 0 {
		t.Fatal("no fixture_reset should have existed before reset was called")
	}
}

// The clone refuses when no device has registered with the credential yet,
// rather than inventing an identifier to take over.
func TestCloneRefusesWithNothingToTakeOver(t *testing.T) {
	a, _ := provisioningApp(t)
	a.manifest.Paths.GeneratedArtifacts = "artifacts/generated"
	a.manifest.Fixtures = map[string]fixture{
		"tier-06/clone-shared-identity": {Image: "tier-06-shared-identity.bin"},
	}
	buildSharedImageStub(t, a)
	_, _, _, err := a.cloneSharedIdentity(environment{})
	if err == nil || !strings.Contains(err.Error(), "no device has registered") {
		t.Fatalf("expected a refusal with nothing to take over, got %v", err)
	}
}
