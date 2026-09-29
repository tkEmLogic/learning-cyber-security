package ota

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const recoveryDevice = "beacon-recover-206ef1170d64"

const thirdNonce = "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01"

// collected reads the certificate a device's collecting poll carries.
func collected(t *testing.T, answer map[string]any) *x509.Certificate {
	t.Helper()
	text, _ := answer["certificate"].(string)
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		t.Fatalf("no certificate in the poll answer: %v", answer)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// claimedThroughTheService runs a whole Tier 7 claim and returns the Factory
// certificate that opened it and the Operational certificate it issued.
func (f *mutualFixture) claimedThroughTheService(t *testing.T, deviceID, owner, credential string) (
	*x509.Certificate, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	factory, _ := f.manufacturer.issue(t, 4201, deviceID, "", now.Add(-time.Hour), now.Add(3*time.Hour))
	f.addOwner(t, owner, credential, now.Add(90*24*time.Hour))
	f.server.claimSleep = func(time.Duration) {}
	csr := certificationRequest(t, deviceID)
	if status, answer := f.deviceHalf(t, factory, deviceID, testNonce, csr); status != http.StatusOK {
		t.Fatalf("device half = %d %v", status, answer)
	}
	if status, answer := f.operatorHalf(t, credential, deviceID, testNonce); status != http.StatusOK ||
		answer["result"] != "claimed" {
		t.Fatalf("operator half = %d %v, want 200 claimed", status, answer)
	}
	_, answer := f.deviceHalf(t, factory, deviceID, testNonce, csr)
	return factory, collected(t, answer)
}

func (f *mutualFixture) recover(t *testing.T, deviceID, credential, body string) (int, map[string]any) {
	t.Helper()
	return f.operatorPost(t, "/v1/devices/"+deviceID+"/recover", credential, body)
}

// The whole recovery, by the owner of record. The authorization revokes the
// old certificate as superseded, the unchanged Tier 7 claim then issues a new
// one to the same owner, and the lifecycle state does not move.
func TestTheOwnerOfRecordRecoversALostOperationalIdentity(t *testing.T) {
	f := newMutualFixture(t)
	factory, old := f.claimedThroughTheService(t, recoveryDevice, "northwind", "owner-secret")
	oldSerial := old.SerialNumber.String()

	status, answer := f.recover(t, recoveryDevice, "owner-secret", "")
	if status != http.StatusOK || answer["result"] != "authorized" {
		t.Fatalf("recover = %d %v, want 200 authorized", status, answer)
	}
	if revoked, _ := answer["revoked_certificate_serials"].([]any); len(revoked) != 1 || revoked[0] != oldSerial {
		t.Fatalf("revoked = %v, want [%s]", answer["revoked_certificate_serials"], oldSerial)
	}

	// The old certificate goes through the Owner's revocation machinery: a
	// revoked.jsonl line with the superseded reason, refused at clause 2.
	lines := readEventLines(t, filepath.Join(f.provisionDir, "revoked.jsonl"))
	if len(lines) != 1 || lines[0]["certificate_serial"] != oldSerial ||
		lines[0]["reason"] != ReasonSuperseded || lines[0]["role"] != RoleOperational ||
		lines[0]["by"] != "northwind" {
		t.Fatalf("revoked.jsonl = %v", lines)
	}
	rstatus, rbody := f.refusalOf(t, present(t, f.operational, old,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, rstatus, rbody, CheckCertificateActive)

	authorizations := recordsOfKind(t, f, "recovery_authorization")
	if len(authorizations) != 1 {
		t.Fatalf("recovery_authorization records = %d, want 1", len(authorizations))
	}
	authorization := authorizations[0]
	if authorization["owner_id"] != "northwind" || authorization["expires_at"] == nil ||
		authorization["lifecycle_state"] != "claimed" {
		t.Fatalf("authorization record = %v", authorization)
	}

	// The device half is the Tier 7 claim, word for word.
	csr := certificationRequest(t, recoveryDevice)
	if status, answer := f.deviceHalf(t, factory, recoveryDevice, otherNonce, csr); status != http.StatusOK ||
		answer["result"] != "pending" {
		t.Fatalf("device half = %d %v, want 200 pending", status, answer)
	}
	if !hasClaimEventDetail(t, f, "claim window opened by an owned device under a recovery authorization") {
		t.Fatal("the service must record that an owned device opened a window for a recovery")
	}
	status, answer = f.operatorHalf(t, "owner-secret", recoveryDevice, otherNonce)
	if status != http.StatusOK || answer["result"] != "recovered" || answer["lifecycle_state"] != "claimed" {
		t.Fatalf("operator half = %d %v, want 200 recovered, still claimed", status, answer)
	}
	status, answer = f.deviceHalf(t, factory, recoveryDevice, otherNonce, csr)
	if status != http.StatusOK || answer["result"] != "issued" {
		t.Fatalf("collecting poll = %d %v, want 200 issued", status, answer)
	}
	fresh := collected(t, answer)
	if fresh.SerialNumber.String() == oldSerial {
		t.Fatal("recovery must issue a new certificate")
	}
	if fresh.Subject.OrganizationalUnit[0] != "northwind" {
		t.Fatalf("owner scope = %v, want northwind", fresh.Subject.OrganizationalUnit)
	}

	// A recovery record, not a claim record, spending the authorization.
	recoveries := recordsOfKind(t, f, "recovery")
	if len(recoveries) != 1 {
		t.Fatalf("recovery records = %d, want 1", len(recoveries))
	}
	if recoveries[0]["recovery_authorization"] != authorization["recovery_authorization"] ||
		recoveries[0]["certificate_serial"] != fresh.SerialNumber.String() ||
		recoveries[0]["certificate_fingerprint"] == nil || recoveries[0]["lifecycle_state"] != "claimed" {
		t.Fatalf("recovery record = %v", recoveries[0])
	}
	if claims := recordsOfKind(t, f, "claim"); len(claims) != 1 {
		t.Fatalf("claim records = %d, want 1: recovery is not a second claim", len(claims))
	}

	// The new certificate passes clause 3 and every check after it, and its
	// first use is an ordinary activation.
	if code := f.serve(t, present(t, f.operational, fresh,
		http.MethodGet, "https://ota.course.example/v1/releases/current", "")); code != http.StatusOK {
		t.Fatalf("the recovered certificate = %d, want 200", code)
	}
	if got := f.server.provisioningState().devices[recoveryDevice]; got.State != "active" ||
		got.Owner != "northwind" {
		t.Fatalf("after first use: %#v, want active under northwind", got)
	}

	// Single use: the next press by the same owner is an owned device again.
	f.deviceHalf(t, factory, recoveryDevice, thirdNonce, certificationRequest(t, recoveryDevice))
	status, answer = f.operatorHalf(t, "owner-secret", recoveryDevice, thirdNonce)
	assertRefusal(t, status, answer, CheckDeviceUnowned)
}

// A recovery authorization is the owner of record's alone. Another owner is
// refused at owner-of-record, nothing is revoked and nothing is recorded, and
// the refusal does not say who the owner is.
func TestRecoveryIsRefusedToAnotherOwnerAtOwnerOfRecord(t *testing.T) {
	f := newMutualFixture(t)
	_, old := f.claimedThroughTheService(t, recoveryDevice, "northwind", "owner-secret")
	f.addOwner(t, "contoso", "contoso-secret", time.Now().Add(24*time.Hour))

	status, answer := f.recover(t, recoveryDevice, "contoso-secret", "")
	assertRefusal(t, status, answer, CheckOwnerOfRecord)
	if strings.Contains(answer["reason"].(string), "northwind") {
		t.Fatalf("owner-of-record must not name the owner: %v", answer["reason"])
	}
	if f.server.revokedSerials()[old.SerialNumber.String()] {
		t.Fatal("a refused recovery must revoke nothing")
	}
	if rows := recordsOfKind(t, f, "recovery_authorization"); len(rows) != 0 {
		t.Fatalf("a refused recovery wrote %d authorizations", len(rows))
	}

	// An unowned device has no owner of record to be.
	status, answer = f.recover(t, "beacon-nobody-206ef1170d64", "contoso-secret", "")
	assertRefusal(t, status, answer, CheckOwnerOfRecord)
}

// Another owner cannot ride the owner's authorization: at the claim it is
// still an owned device, refused at device-unowned.
func TestAnotherOwnerCannotSpendTheOwnersAuthorization(t *testing.T) {
	f := newMutualFixture(t)
	factory, _ := f.claimedThroughTheService(t, recoveryDevice, "northwind", "owner-secret")
	f.addOwner(t, "contoso", "contoso-secret", time.Now().Add(24*time.Hour))
	if status, answer := f.recover(t, recoveryDevice, "owner-secret", ""); status != http.StatusOK {
		t.Fatalf("recover = %d %v", status, answer)
	}
	f.deviceHalf(t, factory, recoveryDevice, otherNonce, certificationRequest(t, recoveryDevice))
	status, answer := f.operatorHalf(t, "contoso-secret", recoveryDevice, otherNonce)
	assertRefusal(t, status, answer, CheckDeviceUnowned)
	if rows := recordsOfKind(t, f, "recovery"); len(rows) != 0 {
		t.Fatal("another owner's approval must not spend the authorization")
	}
}

// Without an authorization an owned device's claim is refused as it always
// was, with one clause pointing its owner at claim recover. The device half is
// still accepted, because the device cannot know it lost anything, and the
// service records the sign of a lost Operational identity.
func TestAnOwnedDeviceWithoutAnAuthorizationIsRefusedAtDeviceUnowned(t *testing.T) {
	f := newMutualFixture(t)
	factory, _ := f.claimedThroughTheService(t, recoveryDevice, "northwind", "owner-secret")

	status, answer := f.deviceHalf(t, factory, recoveryDevice, otherNonce, certificationRequest(t, recoveryDevice))
	if status != http.StatusOK || answer["result"] != "pending" {
		t.Fatalf("device half = %d %v, want 200 pending", status, answer)
	}
	if !hasClaimEventDetail(t, f, "claim window opened by an owned device") {
		t.Fatal("an owned device opening a window must be recorded")
	}
	status, answer = f.operatorHalf(t, "owner-secret", recoveryDevice, otherNonce)
	assertRefusal(t, status, answer, CheckDeviceUnowned)
	if !strings.Contains(answer["reason"].(string), "./course claim recover") {
		t.Fatalf("device-unowned must point an owner at claim recover: %v", answer["reason"])
	}
}

// The authorization lives one hour on the service clock. After that the claim
// is an owned device again, and running recover a second time revokes
// nothing new.
func TestARecoveryAuthorizationExpiresAfterAnHour(t *testing.T) {
	f := newMutualFixture(t)
	factory, _ := f.claimedThroughTheService(t, recoveryDevice, "northwind", "owner-secret")
	if status, answer := f.recover(t, recoveryDevice, "owner-secret", ""); status != http.StatusOK {
		t.Fatalf("recover = %d %v", status, answer)
	}

	later := time.Now().Add(RecoveryAuthorizationLifetime + time.Minute)
	f.server.cfg.MutualTLS.Now = func() time.Time { return later }
	f.deviceHalf(t, factory, recoveryDevice, otherNonce, certificationRequest(t, recoveryDevice))
	status, answer := f.operatorHalf(t, "owner-secret", recoveryDevice, otherNonce)
	assertRefusal(t, status, answer, CheckDeviceUnowned)

	status, answer = f.recover(t, recoveryDevice, "owner-secret", "")
	if status != http.StatusOK || answer["result"] != "authorized" {
		t.Fatalf("second recover = %d %v, want 200 authorized", status, answer)
	}
	if revoked, _ := answer["revoked_certificate_serials"].([]any); len(revoked) != 0 {
		t.Fatalf("a second recover revoked %v, want nothing new", revoked)
	}
	if lines := readEventLines(t, filepath.Join(f.provisionDir, "revoked.jsonl")); len(lines) != 1 {
		t.Fatalf("revoked.jsonl has %d lines, want 1", len(lines))
	}
}

// One live authorization at a time: asking again while it is live answers the
// same one and writes nothing.
func TestALiveAuthorizationIsNotWrittenTwice(t *testing.T) {
	f := newMutualFixture(t)
	f.claimedThroughTheService(t, recoveryDevice, "northwind", "owner-secret")
	_, first := f.recover(t, recoveryDevice, "owner-secret", "")
	status, second := f.recover(t, recoveryDevice, "owner-secret", "")
	if status != http.StatusOK || second["result"] != "already-authorized" ||
		second["recovery_authorization"] != first["recovery_authorization"] {
		t.Fatalf("second recover = %d %v, want the first authorization back", status, second)
	}
	if rows := recordsOfKind(t, f, "recovery_authorization"); len(rows) != 1 {
		t.Fatalf("authorizations = %d, want 1", len(rows))
	}
}

// keyCompromise is for a board the owner thinks was stolen; anything outside
// the two recovery reasons is a 400 that writes nothing.
func TestRecoveryReasons(t *testing.T) {
	f := newMutualFixture(t)
	_, old := f.claimedThroughTheService(t, recoveryDevice, "northwind", "owner-secret")

	if status, _ := f.recover(t, recoveryDevice, "owner-secret", `{"reason":"privilegeWithdrawn"}`); status != http.StatusBadRequest {
		t.Fatalf("an out-of-set reason = %d, want 400", status)
	}
	if f.server.revokedSerials()[old.SerialNumber.String()] {
		t.Fatal("a 400 must revoke nothing")
	}
	status, answer := f.recover(t, recoveryDevice, "owner-secret", `{"reason":"keyCompromise"}`)
	if status != http.StatusOK || answer["reason"] != ReasonKeyCompromise {
		t.Fatalf("recover with keyCompromise = %d %v", status, answer)
	}
	lines := readEventLines(t, filepath.Join(f.provisionDir, "revoked.jsonl"))
	if len(lines) != 1 || lines[0]["reason"] != ReasonKeyCompromise {
		t.Fatalf("revoked.jsonl = %v", lines)
	}
}

// A revoked device cannot be recovered: this is where the two revocations
// differ. It is refused at device-unrevoked on the authorization, and on the
// claim route whatever the log says.
func TestARevokedDeviceIsRefusedRecoveryAtDeviceUnrevoked(t *testing.T) {
	f := newMutualFixture(t)
	factory, _ := f.claimedThroughTheService(t, recoveryDevice, "northwind", "owner-secret")
	f.revokeDeviceRecord(t, recoveryDevice, "northwind")

	status, answer := f.recover(t, recoveryDevice, "owner-secret", "")
	assertRefusal(t, status, answer, CheckDeviceUnrevoked)
	if rows := recordsOfKind(t, f, "recovery_authorization"); len(rows) != 0 {
		t.Fatal("a revoked device must get no authorization")
	}
	status, answer = f.deviceHalf(t, factory, recoveryDevice, otherNonce, certificationRequest(t, recoveryDevice))
	assertRefusal(t, status, answer, CheckDeviceUnrevoked)
}

// After a certificate revocation, by contrast, recovery succeeds: it stops a
// credential and not a device.
func TestRecoveryAfterACertificateRevocationSucceeds(t *testing.T) {
	f := newMutualFixture(t)
	factory, old := f.claimedThroughTheService(t, recoveryDevice, "northwind", "owner-secret")
	if status, answer := f.operatorPost(t, "/v1/certificates/"+old.SerialNumber.String()+"/revoke",
		"owner-secret", revokeReason); status != http.StatusOK {
		t.Fatalf("revoke certificate = %d %v", status, answer)
	}
	status, answer := f.recover(t, recoveryDevice, "owner-secret", "")
	if status != http.StatusOK {
		t.Fatalf("recover = %d %v", status, answer)
	}
	if revoked, _ := answer["revoked_certificate_serials"].([]any); len(revoked) != 0 {
		t.Fatalf("already revoked, so nothing new: %v", revoked)
	}
	f.deviceHalf(t, factory, recoveryDevice, otherNonce, certificationRequest(t, recoveryDevice))
	status, answer = f.operatorHalf(t, "owner-secret", recoveryDevice, otherNonce)
	if status != http.StatusOK || answer["result"] != "recovered" {
		t.Fatalf("operator half = %d %v, want 200 recovered", status, answer)
	}
}

// A decommissioned device cannot be recovered. A decommission clears the owner
// of record, so device-in-service runs before owner-of-record here.
func TestADecommissionedDeviceIsRefusedRecoveryAtDeviceInService(t *testing.T) {
	f := newMutualFixture(t)
	f.claimedThroughTheService(t, recoveryDevice, "northwind", "owner-secret")
	f.appendRecord(t, "records.jsonl", map[string]any{
		"kind":            "decommission",
		"recorded_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"device_id":       recoveryDevice,
		"lifecycle_state": "decommissioned",
	})
	status, answer := f.recover(t, recoveryDevice, "owner-secret", "")
	assertRefusal(t, status, answer, CheckDeviceInService)
	if rows := recordsOfKind(t, f, "recovery_authorization"); len(rows) != 0 {
		t.Fatal("a decommissioned device must get no authorization")
	}
}

// The recovery route sits behind the Owner credential like every Owner
// workflow.
func TestTheRecoveryRouteSitsBehindTheOwnerCredential(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	status, answer := f.recover(t, recoveryDevice, "", "")
	if status != http.StatusUnauthorized || answer["check"] != CheckOwnerCredentialKnown {
		t.Fatalf("no credential = %d %v, want 401 owner-credential-known", status, answer)
	}
}

func hasClaimEventDetail(t *testing.T, f *mutualFixture, detail string) bool {
	t.Helper()
	for _, row := range readEventLines(t, filepath.Join(f.stateDir, "events.jsonl")) {
		if row["claim_event"] == "opened" && row["detail"] == detail {
			return true
		}
	}
	return false
}
