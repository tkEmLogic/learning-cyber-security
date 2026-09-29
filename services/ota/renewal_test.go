package ota

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

const renewalDevice = "beacon-remfg-206ef1170d64"

// csrFor is a certification request for a key the caller chose, so a test can
// ask for a renewal onto a key that was already certified.
func csrFor(t *testing.T, key *ecdsa.PrivateKey, deviceID string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: deviceID},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func freshKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// issuedFor is an Operational certificate issued `age` ago with `lifetime` to
// live from its issue, backdated for skew the way the service backdates one.
func (f *mutualFixture) issuedFor(t *testing.T, serial int64, age, lifetime time.Duration) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	issued := time.Now().Add(-age)
	return f.operational.issue(t, serial, renewalDevice, "northwind",
		issued.Add(-operationalSkew), issued.Add(lifetime))
}

// assignment polls the assignment as a device and reads the whole answer.
func (f *mutualFixture) assignment(t *testing.T, cert *x509.Certificate) map[string]any {
	t.Helper()
	status, body := f.refusalOf(t, present(t, f.operational, cert, http.MethodGet,
		"https://ota.course.example/v1/releases/current", ""))
	if status != http.StatusOK {
		t.Fatalf("assignment = %d %#v, want 200", status, body)
	}
	return body
}

// renewal submits one renewal on the connection carrying cert.
func (f *mutualFixture) renewal(t *testing.T, cert *x509.Certificate, csr string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"csr": csr})
	if err != nil {
		t.Fatal(err)
	}
	return f.refusalOf(t, present(t, f.operational, cert, http.MethodPost,
		"https://ota.course.example/v1/devices/"+renewalDevice+"/renewal", string(body)))
}

func renewedCertificate(t *testing.T, body map[string]any) *x509.Certificate {
	t.Helper()
	text, _ := body["certificate"].(string)
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		t.Fatalf("the renewal answer carries no certificate: %#v", body)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func revokedLines(t *testing.T, f *mutualFixture) []map[string]any {
	t.Helper()
	return readEventLines(t, filepath.Join(f.provisionDir, "revoked.jsonl"))
}

// The flag is measured against each certificate's own window, less the hour
// NotBefore is backdated for skew, and it is absent unless it is true.
func TestTheAssignmentCarriesRenewOnlyWhenDue(t *testing.T) {
	cases := []struct {
		name          string
		age, lifetime time.Duration
		due           bool
	}{
		{"a new ninety-day certificate", 0, OperationalLifetime, false},
		{"fifty-nine days into ninety", 59 * 24 * time.Hour, OperationalLifetime, false},
		{"sixty-one days into ninety", 61 * 24 * time.Hour, OperationalLifetime, true},
		// A third of the 65-minute window would be due at once; a third of the
		// five-minute lifetime is not due for 3m20s.
		{"one minute into five", time.Minute, 5 * time.Minute, false},
		{"four minutes into five", 4 * time.Minute, 5 * time.Minute, true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newMutualFixture(t)
			serial := int64(8100 + i)
			cert, _ := f.issuedFor(t, serial, c.age, c.lifetime)
			f.claim(t, renewalDevice, "northwind", serial)

			body := f.assignment(t, cert)
			renew, has := body["renew"]
			if c.due && renew != true {
				t.Fatalf("renew = %v, want true: %#v", renew, body)
			}
			if !c.due && has {
				t.Fatalf("a certificate that is not due must get the Tier 7 answer, with no renew field: %#v", body)
			}
		})
	}
}

// The operator listener's copy of the assignment never carries the flag.
func TestTheOperatorAssignmentNeverCarriesRenew(t *testing.T) {
	f := newMutualFixture(t)
	recorder := httptest.NewRecorder()
	f.server.OperatorHandler().ServeHTTP(recorder,
		httptest.NewRequest(http.MethodGet, "/v1/releases/current", nil))
	if strings.Contains(recorder.Body.String(), "renew") {
		t.Fatalf("the operator assignment carries renew: %s", recorder.Body.String())
	}
}

// An unsolicited renewal is refused at renewal-due, and nothing is issued.
func TestAnUnsolicitedRenewalIsRefusedAtRenewalDue(t *testing.T) {
	f := newMutualFixture(t)
	cert, _ := f.issuedFor(t, 8201, time.Hour, OperationalLifetime)
	f.claim(t, renewalDevice, "northwind", 8201)

	status, body := f.renewal(t, cert, certificationRequest(t, renewalDevice))
	assertRefusal(t, status, body, CheckRenewalDue)
	if body["device_id"] != renewalDevice {
		t.Fatalf("renewal-due runs after the device id is trusted, so it names it: %#v", body)
	}
	if rows := recordsOfKind(t, f, lifecycle.KindRenewal); len(rows) != 0 {
		t.Fatalf("a refused renewal wrote %d renewal records", len(rows))
	}
}

// The whole forced renewal: the Owner asks, the assignment says renew, the
// device renews on its current identity, both certificates are accepted until
// the new one is used, and the first use retires the old one as superseded,
// in that order.
func TestAForcedRenewalOverlapsUntilTheNewCertificateIsUsed(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	old, _ := f.issuedFor(t, 8301, time.Hour, OperationalLifetime)
	f.claim(t, renewalDevice, "northwind", 8301)

	if _, has := f.assignment(t, old)["renew"]; has {
		t.Fatal("a new certificate is not due before the Owner asks")
	}
	status, answer := f.operatorPost(t,
		"/v1/devices/"+renewalDevice+"/renewal-request", "correct-horse", "")
	if status != http.StatusOK || answer["result"] != "requested" {
		t.Fatalf("renewal request = %d %#v, want 200 requested", status, answer)
	}
	if f.assignment(t, old)["renew"] != true {
		t.Fatal("the Owner's request did not set renew on the assignment")
	}

	status, body := f.renewal(t, old, certificationRequest(t, renewalDevice))
	if status != http.StatusOK || body["result"] != "renewed" {
		t.Fatalf("renewal = %d %#v, want 200 renewed", status, body)
	}
	renewed := renewedCertificate(t, body)
	if renewed.Subject.CommonName != renewalDevice || renewed.Subject.OrganizationalUnit[0] != "northwind" {
		t.Fatalf("renewed subject = %v, want the same device and owner", renewed.Subject)
	}
	if got := renewed.NotAfter.Sub(renewed.NotBefore); got != OperationalLifetime+operationalSkew {
		t.Fatalf("renewed window = %s, want the Operational lifetime plus skew", got)
	}

	rows := recordsOfKind(t, f, lifecycle.KindRenewal)
	if len(rows) != 1 {
		t.Fatalf("wrote %d renewal records, want 1", len(rows))
	}
	row := rows[0]
	if row["renewed_from_serial"] != "8301" || row["certificate_serial"] != renewed.SerialNumber.String() ||
		row["certificate_public_key"] != fingerprintOf(renewed.RawSubjectPublicKeyInfo) ||
		row["owner_id"] != "northwind" || row["lifecycle_state"] != lifecycle.Active {
		t.Fatalf("renewal record = %#v", row)
	}
	if recordsOfKind(t, f, lifecycle.KindClaim)[0]["certificate_serial"] != "8301" ||
		len(recordsOfKind(t, f, lifecycle.KindClaim)) != 1 {
		t.Fatal("a renewal must not write a second claim line")
	}

	// The overlap: the old certificate still works, and the new one is not due.
	if code := f.serve(t, present(t, f.operational, old, http.MethodGet,
		"https://ota.course.example/v1/releases/current", "")); code != http.StatusOK {
		t.Fatalf("the old certificate before the new one is used = %d, want 200", code)
	}
	if len(f.server.revokedSerials()) != 0 {
		t.Fatal("the old certificate was retired before the new one was used")
	}
	if _, has := f.assignment(t, renewed)["renew"]; has {
		t.Fatal("the renewed certificate was issued after the request, so it is not due")
	}

	// The first use of the new certificate is the activation, and it retires
	// the old one. The assignment poll above was that use.
	activations := recordsOfKind(t, f, lifecycle.KindActivation)
	var activatedAt string
	for _, activation := range activations {
		if activation["certificate_serial"] == renewed.SerialNumber.String() {
			activatedAt, _ = activation["recorded_at"].(string)
		}
	}
	if activatedAt == "" {
		t.Fatalf("no activation record for the renewed serial: %#v", activations)
	}
	lines := revokedLines(t, f)
	if len(lines) != 1 || lines[0]["certificate_serial"] != "8301" ||
		lines[0]["reason"] != ReasonSuperseded || lines[0]["role"] != RoleOperational {
		t.Fatalf("revoked.jsonl = %#v, want one superseded line for 8301", lines)
	}
	activated, _ := time.Parse(time.RFC3339Nano, activatedAt)
	retired, _ := time.Parse(time.RFC3339Nano, lines[0]["revoked_at"].(string))
	if retired.Before(activated) {
		t.Fatalf("the old serial was retired at %s, before the new one was used at %s", retired, activated)
	}

	status, refusal := f.refusalOf(t, present(t, f.operational, old, http.MethodGet,
		"https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, status, refusal, CheckCertificateActive)
	if code := f.serve(t, present(t, f.operational, renewed, http.MethodGet,
		"https://ota.course.example/v1/releases/current", "")); code != http.StatusOK {
		t.Fatalf("the renewed certificate = %d, want 200", code)
	}
	if got := f.server.provisioningState().devices[renewalDevice].State; got != lifecycle.Active {
		t.Fatalf("renewal moves no state; the device is %q, want active", got)
	}
}

// A certificate that reaches a third of its life is due without anyone asking.
func TestALateCertificateRenewsWithoutARequest(t *testing.T) {
	f := newMutualFixture(t)
	old, _ := f.issuedFor(t, 8401, 61*24*time.Hour, OperationalLifetime)
	f.claim(t, renewalDevice, "northwind", 8401)

	status, body := f.renewal(t, old, certificationRequest(t, renewalDevice))
	if status != http.StatusOK || body["result"] != "renewed" {
		t.Fatalf("renewal = %d %#v, want 200 renewed", status, body)
	}
}

// key-unused, three ways: the key on the connection, a key an earlier claim
// certified for this device, and the Factory key its enrollment certified.
func TestAReusedKeyIsRefusedAtKeyUnused(t *testing.T) {
	f := newMutualFixture(t)
	factory, earlier := freshKey(t), freshKey(t)
	spkiOf := func(key *ecdsa.PrivateKey) string {
		spki, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		return fingerprintOf(spki)
	}
	f.appendRecord(t, "records.jsonl", map[string]any{
		"kind":                   "enrollment",
		"device_id":              renewalDevice,
		"result":                 "issued",
		"certificate_serial":     "4501",
		"certificate_public_key": spkiOf(factory),
	})
	old, oldKey := f.issuedFor(t, 8501, 61*24*time.Hour, OperationalLifetime)
	f.appendRecord(t, "records.jsonl", map[string]any{
		"kind":                   "claim",
		"device_id":              renewalDevice,
		"owner_id":               "northwind",
		"certificate_serial":     "8501",
		"certificate_public_key": spkiOf(earlier),
	})

	for name, key := range map[string]*ecdsa.PrivateKey{
		"the key on the connection": oldKey,
		"a key a claim certified":   earlier,
		"the Factory key":           factory,
	} {
		status, body := f.renewal(t, old, csrFor(t, key, renewalDevice))
		if body["check"] != CheckKeyUnused {
			t.Fatalf("%s: check = %v, want %s", name, body["check"], CheckKeyUnused)
		}
		assertRefusal(t, status, body, CheckKeyUnused)
	}
	if rows := recordsOfKind(t, f, lifecycle.KindRenewal); len(rows) != 0 {
		t.Fatalf("a refused renewal wrote %d renewal records", len(rows))
	}
}

// A lost response followed by a retry: the candidate the device never used is
// retired as superseded by the next renewal, so a device has at most two
// Operational certificates the service accepts.
func TestARetryRetiresTheUnusedCandidate(t *testing.T) {
	f := newMutualFixture(t)
	old, _ := f.issuedFor(t, 8601, 61*24*time.Hour, OperationalLifetime)
	f.claim(t, renewalDevice, "northwind", 8601)

	_, first := f.renewal(t, old, certificationRequest(t, renewalDevice))
	lost := renewedCertificate(t, first)
	status, second := f.renewal(t, old, certificationRequest(t, renewalDevice))
	if status != http.StatusOK {
		t.Fatalf("retry = %d %#v, want 200", status, second)
	}
	kept := renewedCertificate(t, second)

	superseded, _ := second["superseded_serials"].([]any)
	if len(superseded) != 1 || superseded[0] != lost.SerialNumber.String() {
		t.Fatalf("superseded_serials = %#v, want the lost candidate", second["superseded_serials"])
	}
	status, refusal := f.refusalOf(t, present(t, f.operational, lost, http.MethodGet,
		"https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, status, refusal, CheckCertificateActive)

	accepted := 0
	for _, cert := range []*x509.Certificate{old, lost, kept} {
		if f.server.certificateActive(identityOf(t, f, cert), f.server.provisioningState()) == nil {
			accepted++
		}
	}
	if accepted != 2 {
		t.Fatalf("%d accepted Operational serials, want at most two", accepted)
	}
}

// identityOf reads a certificate the way the device listener does.
func identityOf(t *testing.T, f *mutualFixture, cert *x509.Certificate) DeviceIdentity {
	t.Helper()
	identity, ok := f.server.cfg.MutualTLS.identityFrom(present(t, f.operational, cert, http.MethodGet, "/", ""))
	if !ok {
		t.Fatal("the certificate does not read as a device identity")
	}
	return identity
}

// The renewal route runs the ordinary record checks: a revoked device cannot
// renew, and a certification request naming another device is refused.
func TestTheRenewalRouteRunsTheRecordChecks(t *testing.T) {
	f := newMutualFixture(t)
	old, _ := f.issuedFor(t, 8701, 61*24*time.Hour, OperationalLifetime)
	f.claim(t, renewalDevice, "northwind", 8701)

	status, body := f.renewal(t, old, certificationRequest(t, "beacon-neighbour-000000000000"))
	assertRefusal(t, status, body, CheckIdentifierConsistent)

	f.revokeDeviceRecord(t, renewalDevice, "northwind")
	status, body = f.renewal(t, old, certificationRequest(t, renewalDevice))
	assertRefusal(t, status, body, CheckDeviceUnrevoked)
}

// The Owner's request is gated by owner-of-record, sits behind the Owner
// credential, and asking twice writes one line.
func TestTheRenewalRequestIsTheOwnersAlone(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "contoso", secret: "contoso-key"}
	f.claim(t, renewalDevice, "northwind", 8801)
	target := "/v1/devices/" + renewalDevice + "/renewal-request"

	status, body := f.operatorPost(t, target, "contoso-key", "")
	if status != http.StatusForbidden || body["check"] != CheckOwnerOfRecord {
		t.Fatalf("another owner = %d %#v, want 403 owner-of-record", status, body)
	}
	if strings.Contains(body["reason"].(string), "northwind") {
		t.Fatalf("owner-of-record must not name the owner: %v", body["reason"])
	}
	status, body = f.operatorPost(t, target, "", "")
	if status != http.StatusUnauthorized || body["check"] != CheckOwnerCredentialKnown {
		t.Fatalf("no credential = %d %#v, want 401 owner-credential-known", status, body)
	}

	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	for _, want := range []string{"requested", "already-requested"} {
		status, body = f.operatorPost(t, target, "correct-horse", "")
		if status != http.StatusOK || body["result"] != want {
			t.Fatalf("request = %d %#v, want 200 %s", status, body, want)
		}
	}
	if rows := recordsOfKind(t, f, KindRenewalRequest); len(rows) != 1 {
		t.Fatalf("asking twice wrote %d renewal requests, want 1", len(rows))
	}
	if got := f.server.provisioningState().devices[renewalDevice].State; got != lifecycle.Claimed {
		t.Fatalf("a renewal request moves no state; the device is %q", got)
	}

	f.revokeDeviceRecord(t, renewalDevice, "northwind")
	status, body = f.operatorPost(t, target, "correct-horse", "")
	if status != http.StatusForbidden || body["check"] != CheckDeviceUnrevoked {
		t.Fatalf("a revoked device = %d %#v, want 403 device-unrevoked", status, body)
	}
}

// A renewed certificate is the Owner's to revoke, as a claimed one is.
func TestTheOwnerCanRevokeARenewedCertificate(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	old, _ := f.issuedFor(t, 8901, 61*24*time.Hour, OperationalLifetime)
	f.claim(t, renewalDevice, "northwind", 8901)
	_, body := f.renewal(t, old, certificationRequest(t, renewalDevice))
	renewed := renewedCertificate(t, body)

	status, answer := f.operatorPost(t, "/v1/certificates/"+renewed.SerialNumber.String()+"/revoke",
		"correct-horse", revokeReason)
	if status != http.StatusOK || answer["result"] != "revoked" {
		t.Fatalf("revoking the renewed certificate = %d %#v, want 200 revoked", status, answer)
	}
}
