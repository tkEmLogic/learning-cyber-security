package ota

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The nonce a board would print: fifteen bytes as twenty-four Crockford base32
// characters, in six groups of four.
const testNonce = "K7X2-9QW4-M3TR-8B5N-P6VD-3JZC"

const otherNonce = "1234-5678-9ABC-DEFG-HJKM-NPQR"

// addOwner writes one line of the Owner credential store, holding a verifier
// and never the credential.
func (f *mutualFixture) addOwner(t *testing.T, owner, credential string, expires time.Time) {
	t.Helper()
	f.appendRecord(t, "owners.jsonl", map[string]any{
		"kind":                "owner_credential_issued",
		"recorded_at":         time.Now().UTC().Format(time.RFC3339Nano),
		"owner_id":            owner,
		"credential_id":       fmt.Sprintf("%s-%d", owner, expires.UnixNano()),
		"credential_verifier": ownerVerifierFor(credential),
		"credential_expires":  expires.UTC().Format(time.RFC3339),
	})
}

// certificationRequest is what the device generates beside its nonce: a
// request for the Operational key it just made, naming itself.
func certificationRequest(t *testing.T, deviceID string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: deviceID},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// deviceHalf submits or re-sends the device half on a connection carrying the
// device's Factory certificate.
func (f *mutualFixture) deviceHalf(t *testing.T, factory *x509.Certificate,
	deviceID, nonce, csr string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"nonce": nonce, "csr": csr})
	if err != nil {
		t.Fatal(err)
	}
	request := present(t, f.manufacturer, factory, http.MethodPost,
		"https://ota.course.example/v1/devices/"+deviceID+"/claim", string(body))
	return f.refusalOf(t, request)
}

// operatorHalf submits the operator half on the server-authenticated listener,
// with the Owner credential as a bearer token and never in the body.
func (f *mutualFixture) operatorHalf(t *testing.T, credential, deviceID, nonce string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"device_id": deviceID, "nonce": nonce})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/claim", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer "+credential)
	recorder := httptest.NewRecorder()
	f.server.OperatorHandler().ServeHTTP(recorder, request)
	var answer map[string]any
	if recorder.Body.Len() > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
			t.Fatalf("answer was not JSON: %s", recorder.Body.String())
		}
	}
	return recorder.Code, answer
}

// claimable is one unclaimed device with a Factory identity, an owner holding
// a live credential, and no waiting.
func (f *mutualFixture) claimable(t *testing.T, deviceID, owner, credential string) *x509.Certificate {
	t.Helper()
	now := time.Now()
	factory, _ := f.manufacturer.issue(t, 7001, deviceID, "", now.Add(-time.Hour), now.Add(time.Hour))
	f.addOwner(t, owner, credential, now.Add(90*24*time.Hour))
	f.server.claimSleep = func(time.Duration) {}
	return factory
}

// The claim needs both halves, and the device collects its certificate on the
// same POST it opened the window with.
func TestBothHalvesTogetherIssueAnOwnerScopedCertificate(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	csr := certificationRequest(t, device)

	status, answer := f.deviceHalf(t, factory, device, testNonce, csr)
	if status != http.StatusOK || answer["result"] != "pending" {
		t.Fatalf("device half = %d %v, want 200 pending", status, answer)
	}
	// Pending carries no check. The device's rule is that a body with a check
	// is terminal and stops the poll dead.
	if _, found := answer["check"]; found {
		t.Fatalf("pending must carry no check field: %v", answer)
	}

	// A poll before the operator half lands is still pending, and the service
	// keeps the request from the first arrival.
	status, answer = f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))
	if status != http.StatusOK || answer["result"] != "pending" {
		t.Fatalf("poll = %d %v, want 200 pending", status, answer)
	}

	status, answer = f.operatorHalf(t, "owner-secret", device, testNonce)
	if status != http.StatusOK || answer["result"] != "claimed" {
		t.Fatalf("operator half = %d %v, want 200 claimed", status, answer)
	}
	if answer["lifecycle_state"] != "claimed" {
		t.Fatalf("lifecycle_state = %v, want claimed", answer["lifecycle_state"])
	}

	status, answer = f.deviceHalf(t, factory, device, testNonce, csr)
	if status != http.StatusOK || answer["result"] != "issued" {
		t.Fatalf("collecting poll = %d %v, want 200 issued", status, answer)
	}
	block, _ := pem.Decode([]byte(answer["certificate"].(string)))
	if block == nil {
		t.Fatal("the issued certificate is not PEM")
	}
	issued, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Subject.CommonName != device {
		t.Fatalf("subject common name = %q, want %q", issued.Subject.CommonName, device)
	}
	if len(issued.Subject.OrganizationalUnit) != 1 || issued.Subject.OrganizationalUnit[0] != "northwind" {
		t.Fatalf("owner scope = %v, want [northwind]", issued.Subject.OrganizationalUnit)
	}
	if err := issued.CheckSignatureFrom(f.operational.cert); err != nil {
		t.Fatalf("the issued certificate does not chain to the Operational CA: %v", err)
	}
	// Ninety days, not the Factory identity's ten years.
	if days := issued.NotAfter.Sub(issued.NotBefore).Hours() / 24; days < 89 || days > 92 {
		t.Fatalf("lifetime = %.0f days, want about 90", days)
	}

	// The device record moved to claimed, by appending rather than by editing.
	record := lastClaimRecord(t, f)
	if record["lifecycle_state"] != "claimed" {
		t.Fatalf("record lifecycle_state = %v, want claimed", record["lifecycle_state"])
	}
	if record["owner_id"] != "northwind" || record["device_id"] != device {
		t.Fatalf("claim record names the wrong pair: %v", record)
	}
	if record["certificate_serial"] != issued.SerialNumber.String() {
		t.Fatalf("record serial = %v, want %s", record["certificate_serial"], issued.SerialNumber)
	}
	// The nonce is kept as a verifier and never as itself.
	if got, _ := record["claim_nonce_verifier"].(string); !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("claim_nonce_verifier = %q, want a sha256 verifier", got)
	}
}

// Everything the claim writes, in both stores, holds a verifier or a
// fingerprint and never a secret.
func TestNoClaimSecretIsEverWritten(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fd"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))
	f.operatorHalf(t, "owner-secret", device, testNonce)

	for _, path := range []string{
		filepath.Join(f.provisionDir, "records.jsonl"),
		filepath.Join(f.stateDir, "events.jsonl"),
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"K7X29QW4M3TR8B5NP6VD3JZC", testNonce, "owner-secret", "PRIVATE KEY"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("%s holds %q; a record may hold a verifier or a fingerprint and nothing else",
					filepath.Base(path), secret)
			}
		}
	}
}

// The certification request's subject is identifier-consistent's third source
// on this route. A device asking for a certificate for its neighbour is
// refused by the same rule as one naming a neighbour in a path.
func TestTheCertificationRequestMustNameTheSameDevice(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")

	status, body := f.deviceHalf(t, factory, device, testNonce,
		certificationRequest(t, "beacon-claim-404cca5ea9ff"))
	assertRefusal(t, status, body, CheckIdentifierConsistent)
	if body["device_id"] != device {
		t.Fatalf("device_id = %v, want %q: certificate-active has passed by here", body["device_id"], device)
	}
}

// The device half strictly precedes the operator half. Nothing is parked for a
// device that never called.
func TestAnOperatorHalfWithNoDeviceHalfIsRefused(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	f.claimable(t, device, "northwind", "owner-secret")

	status, body := f.operatorHalf(t, "owner-secret", device, testNonce)
	assertRefusal(t, status, body, CheckClaimWindowOpen)
	// The service has established nothing about the device the caller named.
	if _, found := body["device_id"]; found {
		t.Fatalf("claim-window-open must not echo an unestablished device: %v", body)
	}
}

// The service is the only party that decides a claim is expired.
func TestAnExpiredClaimWindowIsRefused(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))

	later := time.Now().Add(ClaimWindowLifetime + time.Minute)
	f.server.cfg.MutualTLS.Now = func() time.Time { return later }

	status, body := f.operatorHalf(t, "owner-secret", device, testNonce)
	assertRefusal(t, status, body, CheckClaimWindowOpen)
}

// Four backed-off attempts, and only a wrong nonce spends one.
func TestOnlyNonceMatchSpendsAnAttemptAndFourClosesTheWindow(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	var delays []time.Duration
	f.server.claimSleep = func(d time.Duration) { delays = append(delays, d) }
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))

	for attempt := 1; attempt <= claimAttemptBudget; attempt++ {
		status, body := f.operatorHalf(t, "owner-secret", device, otherNonce)
		assertRefusal(t, status, body, CheckNonceMatch)
	}
	// Nothing on the first wrong nonce — one typo is not an attack — then two,
	// four and eight seconds. The zero is absent rather than recorded, because
	// the handler only sleeps when there is something to sleep for. This is the
	// same 0, 2, 4, 8 the device half uses for its submissions.
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}
	if len(delays) != len(want) {
		t.Fatalf("delays = %v, want %v", delays, want)
	}
	for i := range want {
		if delays[i] != want[i] {
			t.Fatalf("delays = %v, want %v", delays, want)
		}
	}

	// The budget is spent, so the window is gone: the right nonce now finds no
	// window rather than a fifth attempt.
	status, body := f.operatorHalf(t, "owner-secret", device, testNonce)
	assertRefusal(t, status, body, CheckClaimWindowOpen)
}

// Refusals other than nonce-match must not spend an attempt, or an attacker
// closes a Learner's window without ever guessing.
func TestARefusalThatIsNotNonceMatchSpendsNothing(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))

	// An unknown credential never reaches the window at all.
	for i := 0; i < 10; i++ {
		status, body := f.operatorHalf(t, "not-a-credential", device, otherNonce)
		if status != http.StatusUnauthorized || body["check"] != CheckOwnerCredentialKnown {
			t.Fatalf("attempt %d = %d %v, want 401 owner-credential-known", i, status, body)
		}
	}
	// A wrong device names no window of this one's.
	f.operatorHalf(t, "owner-secret", "beacon-claim-404cca5ea9ff", testNonce)

	status, answer := f.operatorHalf(t, "owner-secret", device, testNonce)
	if status != http.StatusOK || answer["result"] != "claimed" {
		t.Fatalf("the window must still be open and unspent: %d %v", status, answer)
	}
}

// The load-bearing order. A replayed nonce against a device that is genuinely
// owned must refuse at nonce-unspent, not at device-unowned.
//
// Putting device-unowned first is the obvious order and it is wrong: it would
// make every replayed nonce on a claimed board answer already-owned, and
// "replayed claim nonce" is a named success criterion the board has to be able
// to earn on its own rather than borrow from the fixture.
func TestAReplayedNonceOnAnOwnedDeviceRefusesAtNonceUnspent(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))
	if status, answer := f.operatorHalf(t, "owner-secret", device, testNonce); status != http.StatusOK {
		t.Fatalf("the first claim must succeed: %d %v", status, answer)
	}

	// The device is now owned and the nonce is now spent. Both are true, and
	// the order decides which one the caller is told.
	status, body := f.operatorHalf(t, "owner-secret", device, testNonce)
	assertRefusal(t, status, body, CheckNonceUnspent)
	if body["check"] == CheckDeviceUnowned {
		t.Fatal("device-unowned ran before nonce-unspent; the order is load-bearing")
	}
}

// Replayed stays distinct from no open claim window across a restart, because
// the window is memory and the fact that a nonce was spent is not.
func TestASpentNonceIsStillSpentAfterARestart(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))
	f.operatorHalf(t, "owner-secret", device, testNonce)

	// A restart keeps the directories and loses the windows. The handlers are
	// rebuilt rather than carried over, because a handler bound to the old
	// server would be the old server.
	config := f.server.cfg
	config.Claim = ClaimHandlers{}
	config.OwnerCredentials = nil
	restarted, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	restarted.claimSleep = func(time.Duration) {}
	f.server = restarted

	status, body := f.operatorHalf(t, "owner-secret", device, testNonce)
	assertRefusal(t, status, body, CheckNonceUnspent)

	// A nonce nobody ever presented is a different answer.
	status, body = f.operatorHalf(t, "owner-secret", device, otherNonce)
	assertRefusal(t, status, body, CheckClaimWindowOpen)
}

// Wrong-owner is refused from the record, because the device named no owner
// when it opened its window. First come, and the refusal never says who.
func TestASecondOwnerIsRefusedAtDeviceUnowned(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.addOwner(t, "rival-labs", "rival-secret", time.Now().Add(90*24*time.Hour))
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))
	f.operatorHalf(t, "owner-secret", device, testNonce)

	// A second press generates a fresh window on an already-claimed device,
	// which is how the board earns this refusal itself.
	f.deviceHalf(t, factory, device, otherNonce, certificationRequest(t, device))
	status, body := f.operatorHalf(t, "rival-secret", device, otherNonce)
	assertRefusal(t, status, body, CheckDeviceUnowned)
	if reason, _ := body["reason"].(string); strings.Contains(reason, "northwind") {
		t.Fatalf("a wrong-owner refusal must not name the current owner: %q", reason)
	}
}

// A second physical action supersedes: two live nonces for one device would be
// two ways in.
func TestASecondWindowSupersedesTheFirst(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))
	f.deviceHalf(t, factory, device, otherNonce, certificationRequest(t, device))

	status, body := f.operatorHalf(t, "owner-secret", device, testNonce)
	assertRefusal(t, status, body, CheckNonceMatch)

	if status, answer := f.operatorHalf(t, "owner-secret", device, otherNonce); status != http.StatusOK {
		t.Fatalf("the superseding window must be the live one: %d %v", status, answer)
	}
}

// The window's whole trail is in the service's own event log.
func TestTheClaimWindowTrailIsRecorded(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))
	f.operatorHalf(t, "owner-secret", device, otherNonce)
	f.operatorHalf(t, "owner-secret", device, testNonce)

	want := map[string]bool{"opened": false, "refused": false, "nonce_spent": false, "issued": false}
	for _, row := range readEventLines(t, filepath.Join(f.stateDir, "events.jsonl")) {
		if row["source"] != "service" {
			continue
		}
		if event, ok := row["claim_event"].(string); ok {
			if _, wanted := want[event]; wanted {
				want[event] = true
			}
		}
	}
	for event, found := range want {
		if !found {
			t.Fatalf("the window trail has no %q row", event)
		}
	}
}

// A malformed request is not an authorization decision and must not borrow an
// authorization check's name.
func TestAMalformedClaimAnswersFourHundredWithNoCheck(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")

	for _, body := range []string{
		`{"nonce":"not-a-nonce","csr":"` + strings.ReplaceAll(certificationRequest(t, device), "\n", `\n`) + `"}`,
		`{"nonce":"` + testNonce + `","csr":"not a request"}`,
		`{`,
	} {
		request := present(t, f.manufacturer, factory, http.MethodPost,
			"https://ota.course.example/v1/devices/"+device+"/claim", body)
		recorder := httptest.NewRecorder()
		f.server.DeviceHandler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body %q = %d, want 400", body, recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), `"check"`) {
			t.Fatalf("a 400 must carry no check name: %s", recorder.Body.String())
		}
	}
}

// A person transcribing a nonce may drop the grouping or use lower case. The
// confusable-free alphabet only pays if both spellings hash the same.
func TestANonceIsCanonicalisedBeforeItIsHashed(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))

	if status, answer := f.operatorHalf(t, "owner-secret", device,
		strings.ToLower(strings.ReplaceAll(testNonce, "-", " "))); status != http.StatusOK {
		t.Fatalf("a regrouped, lower-case nonce must match: %d %v", status, answer)
	}
}

// The three Owner credential checks, each 401, in their published order.
func TestTheThreeOwnerCredentialChecks(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	f.claimable(t, device, "northwind", "owner-secret")
	f.addOwner(t, "stale-owner", "expired-secret", time.Now().Add(-time.Hour))

	cases := []struct {
		name       string
		credential string
		check      string
	}{
		{"no credential at all", "", CheckOwnerCredentialKnown},
		{"a credential nobody holds", "invented", CheckOwnerCredentialKnown},
		{"a credential past its ninety days", "expired-secret", CheckOwnerCredentialValid},
	}
	for _, testCase := range cases {
		status, body := f.operatorHalf(t, testCase.credential, device, testNonce)
		if status != http.StatusUnauthorized {
			t.Fatalf("%s = %d, want 401: not knowing who is asking is not an authorization refusal",
				testCase.name, status)
		}
		if body["check"] != testCase.check {
			t.Fatalf("%s = %v, want %q", testCase.name, body["check"], testCase.check)
		}
	}

	// Re-minting supersedes: the older credential stops matching.
	f.addOwner(t, "northwind", "second-secret", time.Now().Add(90*24*time.Hour))
	status, body := f.operatorHalf(t, "owner-secret", device, testNonce)
	if status != http.StatusUnauthorized || body["check"] != CheckOwnerCredentialCurrent {
		t.Fatalf("a superseded credential = %d %v, want 401 owner-credential-current", status, body)
	}
	if status, body := f.operatorHalf(t, "second-secret", device, testNonce); body["check"] != CheckClaimWindowOpen {
		t.Fatalf("the current credential must authenticate: %d %v", status, body)
	}
}

// The store is read live, so an owner minted after the service started
// authenticates without a restart.
func TestTheOwnerStoreIsReadLive(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	f.server.claimSleep = func(time.Duration) {}
	status, body := f.operatorHalf(t, "late-secret", device, testNonce)
	if status != http.StatusUnauthorized || body["check"] != CheckOwnerCredentialKnown {
		t.Fatalf("before minting = %d %v, want 401 owner-credential-known", status, body)
	}
	f.addOwner(t, "northwind", "late-secret", time.Now().Add(90*24*time.Hour))
	status, body = f.operatorHalf(t, "late-secret", device, testNonce)
	if body["check"] != CheckClaimWindowOpen {
		t.Fatalf("after minting = %d %v, want the claim checks rather than a credential one", status, body)
	}
}

// What the claim issued is what the ordinary endpoints accept.
//
// This is the join the tier rests on: certificate-active clause 3 and
// device-claimed both read the record the claim itself wrote, so a device that
// has just been claimed can download with the certificate it just collected,
// and nothing had to be seeded by hand to make that true.
func TestTheIssuedCertificateIsServedOnTheOrdinaryEndpoints(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-404cca5ea9fc"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))
	f.operatorHalf(t, "owner-secret", device, testNonce)
	_, answer := f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))

	block, _ := pem.Decode([]byte(answer["certificate"].(string)))
	issued, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	f.server.DeviceHandler().ServeHTTP(recorder, present(t, f.operational, issued,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("the certificate this service just issued = %d, want 200: %s",
			recorder.Code, recorder.Body.String())
	}

	// And the Factory identity that opened the claim is still refused there.
	recorder = httptest.NewRecorder()
	f.server.DeviceHandler().ServeHTTP(recorder, present(t, f.manufacturer, factory,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("the Factory identity = %d, want 403", recorder.Code)
	}
}

func lastClaimRecord(t *testing.T, f *mutualFixture) map[string]any {
	t.Helper()
	var last map[string]any
	for _, row := range readEventLines(t, filepath.Join(f.provisionDir, "records.jsonl")) {
		if row["kind"] == "claim" {
			last = row
		}
	}
	if last == nil {
		t.Fatal("no claim record was written")
	}
	return last
}
