package ota

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// revokeDeviceRecord writes the revocation line the service's own endpoint
// writes: this device is stopped. The derivation reads it and device-unrevoked
// enforces it.
func (f *mutualFixture) revokeDeviceRecord(t *testing.T, deviceID, owner string) {
	t.Helper()
	f.appendRecord(t, "records.jsonl", map[string]any{
		"kind":            "revocation",
		"recorded_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"device_id":       deviceID,
		"owner_id":        owner,
		"reason":          ReasonKeyCompromise,
		"lifecycle_state": "revoked",
	})
}

// operatorPost runs one request against the operator listener, which
// authenticates the bearer credential and not a client certificate.
func (f *mutualFixture) operatorPost(t *testing.T, target, credential, body string) (int, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	f.server.OperatorHandler().ServeHTTP(recorder, request)
	var answer map[string]any
	if recorder.Body.Len() > 0 {
		_ = json.Unmarshal(recorder.Body.Bytes(), &answer)
	}
	return recorder.Code, answer
}

const revokeReason = `{"reason":"` + ReasonKeyCompromise + `"}`

// device-unrevoked, on an ordinary Operational route. A revoked device is told
// it is revoked and not that its certificate ran out, so the fleet can tell the
// two apart.
func TestRevokedDeviceIsRefusedAtDeviceUnrevoked(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	cert, _ := f.operational.issue(t, 7101, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(OperationalLifetime))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7101)
	f.revokeDeviceRecord(t, "beacon-remfg-206ef1170d64", "northwind")

	status, body := f.refusalOf(t, present(t, f.operational, cert,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, status, body, CheckDeviceUnrevoked)
	if body["device_id"] != "beacon-remfg-206ef1170d64" {
		t.Fatalf("device-unrevoked runs after the device id is trusted, so it names it: %#v", body)
	}
}

// device-unrevoked on the claim endpoint. This is what closes re-claim: a
// revoked device presenting its Factory identity to claim afresh is refused at
// device-unrevoked, not let through by device-unowned. Only a remanufacture is
// the way back.
func TestRevokedDeviceIsRefusedAtTheClaimEndpoint(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	factory, _ := f.manufacturer.issue(t, 4101, "beacon-remfg-206ef1170d64", "",
		now.Add(-time.Hour), now.Add(time.Hour))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7102)
	f.revokeDeviceRecord(t, "beacon-remfg-206ef1170d64", "northwind")

	status, body := f.refusalOf(t, present(t, f.manufacturer, factory, http.MethodPost,
		"https://ota.course.example/v1/devices/beacon-remfg-206ef1170d64/claim", `{"nonce":"x"}`))
	assertRefusal(t, status, body, CheckDeviceUnrevoked)
}

// A Factory serial in revoked.jsonl is refused at the claim endpoint by clause
// 2 of certificate-active, which does not care about role. This is the
// enforcement the manufacturer's provision revoke relies on: it is already
// here, and Tier 8 only owes it an operation and this test.
func TestRevokedFactorySerialIsRefusedAtTheClaimEndpoint(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	factory, _ := f.manufacturer.issue(t, 4102, "beacon-remfg-206ef1170d64", "",
		now.Add(-time.Hour), now.Add(time.Hour))
	f.revoke(t, 4102)

	status, body := f.refusalOf(t, present(t, f.manufacturer, factory, http.MethodPost,
		"https://ota.course.example/v1/devices/beacon-remfg-206ef1170d64/claim", `{"nonce":"x"}`))
	assertRefusal(t, status, body, CheckCertificateActive)
	if !strings.Contains(body["reason"].(string), "revoked") {
		t.Fatalf("a revoked Factory serial is refused at clause 2: %v", body["reason"])
	}
}

// The Owner revokes their own Operational certificate through the service, and
// the certificate is then refused at certificate-active. Nothing was copied
// into the device's record: it is the certificate that is stopped, not the
// device, which is why the device can still recover through its Factory
// identity.
func TestOwnerRevokesTheirOwnCertificate(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	now := time.Now()
	cert, _ := f.operational.issue(t, 7103, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(OperationalLifetime))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7103)

	status, body := f.operatorPost(t,
		"/v1/certificates/7103/revoke", "correct-horse", revokeReason)
	if status != http.StatusOK {
		t.Fatalf("revoke = %d, want 200: %#v", status, body)
	}
	if body["result"] != "revoked" || body["reason"] != ReasonKeyCompromise {
		t.Fatalf("revoke answer = %#v", body)
	}

	rstatus, rbody := f.refusalOf(t, present(t, f.operational, cert,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, rstatus, rbody, CheckCertificateActive)
	if !strings.Contains(rbody["reason"].(string), "revoked") {
		t.Fatalf("the revoked certificate must be refused at clause 2: %v", rbody["reason"])
	}
	// The device itself is untouched: no revocation record, so device-unrevoked
	// does not fire for it.
	if got := f.server.provisioningState().devices["beacon-remfg-206ef1170d64"].State; got == "revoked" {
		t.Fatal("revoking a certificate must not revoke the device")
	}
}

// Revoking a certificate the caller does not own is refused at owner-of-record,
// and the refusal names neither the owner nor whether the serial exists.
func TestCertificateRevocationRefusesAnotherOwnerAtOwnerOfRecord(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "contoso", secret: "contoso-key"}
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7104)

	status, body := f.operatorPost(t,
		"/v1/certificates/7104/revoke", "contoso-key", revokeReason)
	if status != http.StatusForbidden || body["check"] != CheckOwnerOfRecord {
		t.Fatalf("wrong owner = %d %#v, want 403 owner-of-record", status, body)
	}
	if strings.Contains(body["reason"].(string), "northwind") {
		t.Fatalf("owner-of-record must not name the owner: %v", body["reason"])
	}
}

// A reason outside the CRLReason set is a 400, before anything is written.
func TestCertificateRevocationRejectsAnUnknownReason(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7105)

	status, _ := f.operatorPost(t,
		"/v1/certificates/7105/revoke", "correct-horse", `{"reason":"becauseISaidSo"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("an unknown reason = %d, want 400", status)
	}
	if revoked := f.server.revokedSerials()["7105"]; revoked {
		t.Fatal("a 400 must write nothing")
	}
}

// The Owner revokes their own device through the service. A revocation record
// is written, the derivation moves the device to revoked, and device-unrevoked
// then refuses it.
func TestOwnerRevokesTheirOwnDevice(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	now := time.Now()
	cert, _ := f.operational.issue(t, 7106, "beacon-remfg-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(OperationalLifetime))
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7106)

	status, body := f.operatorPost(t,
		"/v1/devices/beacon-remfg-206ef1170d64/revoke", "correct-horse", revokeReason)
	if status != http.StatusOK {
		t.Fatalf("revoke device = %d, want 200: %#v", status, body)
	}
	if body["lifecycle_state"] != "revoked" {
		t.Fatalf("revoke device answer = %#v", body)
	}
	if got := f.server.provisioningState().devices["beacon-remfg-206ef1170d64"].State; got != "revoked" {
		t.Fatalf("device state = %q, want revoked", got)
	}

	rstatus, rbody := f.refusalOf(t, present(t, f.operational, cert,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, rstatus, rbody, CheckDeviceUnrevoked)
}

// Revoking a device the caller does not own is refused at owner-of-record.
func TestDeviceRevocationRefusesAnotherOwnerAtOwnerOfRecord(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "contoso", secret: "contoso-key"}
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7107)

	status, body := f.operatorPost(t,
		"/v1/devices/beacon-remfg-206ef1170d64/revoke", "contoso-key", revokeReason)
	if status != http.StatusForbidden || body["check"] != CheckOwnerOfRecord {
		t.Fatalf("wrong owner = %d %#v, want 403 owner-of-record", status, body)
	}
}

// An unowned device cannot be revoked by anyone: there is no owner of record to
// be, so the same owner-of-record refusal answers.
func TestDeviceRevocationRefusesAnUnownedDeviceAtOwnerOfRecord(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}

	status, body := f.operatorPost(t,
		"/v1/devices/beacon-remfg-206ef1170d64/revoke", "correct-horse", revokeReason)
	if status != http.StatusForbidden || body["check"] != CheckOwnerOfRecord {
		t.Fatalf("unowned device = %d %#v, want 403 owner-of-record", status, body)
	}
}

// A reason outside the CRLReason set is a 400, and nothing is appended.
func TestDeviceRevocationRejectsAnUnknownReason(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7108)

	status, _ := f.operatorPost(t,
		"/v1/devices/beacon-remfg-206ef1170d64/revoke", "correct-horse", `{"reason":"nope"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("an unknown reason = %d, want 400", status)
	}
	if got := f.server.provisioningState().devices["beacon-remfg-206ef1170d64"].State; got == "revoked" {
		t.Fatal("a 400 must write no revocation record")
	}
}

// Both revocation routes sit behind the Owner credential, like the claim
// approval: no bearer token is the tier's one 401.
func TestRevocationRoutesSitBehindTheOwnerCredential(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	for _, target := range []string{
		"/v1/certificates/7109/revoke",
		"/v1/devices/beacon-remfg-206ef1170d64/revoke",
	} {
		status, body := f.operatorPost(t, target, "", revokeReason)
		if status != http.StatusUnauthorized || body["check"] != CheckOwnerCredentialKnown {
			t.Fatalf("%s with no credential = %d %#v, want 401 owner-credential-known", target, status, body)
		}
	}
}

// The idempotence of the one-way operation: asking twice does not write a
// second line.
func TestCertificateRevocationIsIdempotent(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	f.claim(t, "beacon-remfg-206ef1170d64", "northwind", 7110)

	for i := 0; i < 2; i++ {
		status, _ := f.operatorPost(t,
			"/v1/certificates/7110/revoke", "correct-horse", revokeReason)
		if status != http.StatusOK {
			t.Fatalf("revoke %d = %d, want 200", i, status)
		}
	}
	lines := readEventLines(t, f.provisionDir+"/revoked.jsonl")
	revocations := 0
	for _, line := range lines {
		if line["certificate_serial"] == strconv.Itoa(7110) {
			revocations++
		}
	}
	if revocations != 1 {
		t.Fatalf("a one-way operation wrote %d lines, want 1", revocations)
	}
}
