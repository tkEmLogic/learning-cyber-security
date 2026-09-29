package ota

import (
	"crypto/x509"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const transferDevice = "beacon-transfer-206ef1170d64"

func (f *mutualFixture) transfer(t *testing.T, deviceID, credential string) (int, map[string]any) {
	t.Helper()
	return f.operatorPost(t, "/v1/devices/"+deviceID+"/transfer", credential, "")
}

// The whole Ownership transfer. The owner of record gives the device up, which
// revokes its certificate as privilegeWithdrawn and leaves it transferred; the
// old certificate is refused at certificate-active; a new owner claims it with
// the unchanged Tier 7 press and is issued a certificate in their own scope.
func TestTheOwnerOfRecordTransfersADeviceAndANewOwnerClaimsIt(t *testing.T) {
	f := newMutualFixture(t)
	factory, old := f.claimedThroughTheService(t, transferDevice, "northwind", "owner-secret")
	oldSerial := old.SerialNumber.String()
	if code := f.serve(t, present(t, f.operational, old,
		http.MethodGet, "https://ota.course.example/v1/releases/current", "")); code != http.StatusOK {
		t.Fatalf("the old certificate before the transfer = %d, want 200", code)
	}
	f.addOwner(t, "contoso", "contoso-secret", time.Now().Add(24*time.Hour))

	// Before the transfer the new owner is refused at device-unowned, and the
	// reason points at owner transfer without naming the owner.
	f.deviceHalf(t, factory, transferDevice, otherNonce, certificationRequest(t, transferDevice))
	status, answer := f.operatorHalf(t, "contoso-secret", transferDevice, otherNonce)
	assertRefusal(t, status, answer, CheckDeviceUnowned)
	if reason := answer["reason"].(string); !strings.Contains(reason, "./course owner transfer") ||
		strings.Contains(reason, "northwind") {
		t.Fatalf("device-unowned must point at owner transfer and not name the owner: %v", reason)
	}

	status, answer = f.transfer(t, transferDevice, "owner-secret")
	if status != http.StatusOK || answer["result"] != "transferred" ||
		answer["lifecycle_state"] != "transferred" || answer["reason"] != ReasonPrivilegeWithdrawn {
		t.Fatalf("transfer = %d %v, want 200 transferred", status, answer)
	}
	if revoked, _ := answer["revoked_certificate_serials"].([]any); len(revoked) != 1 || revoked[0] != oldSerial {
		t.Fatalf("revoked = %v, want [%s]", answer["revoked_certificate_serials"], oldSerial)
	}

	// Through the Owner's revocation machinery: one revoked.jsonl line.
	lines := readEventLines(t, filepath.Join(f.provisionDir, "revoked.jsonl"))
	if len(lines) != 1 || lines[0]["certificate_serial"] != oldSerial ||
		lines[0]["reason"] != ReasonPrivilegeWithdrawn || lines[0]["role"] != RoleOperational ||
		lines[0]["by"] != "northwind" {
		t.Fatalf("revoked.jsonl = %v", lines)
	}
	transfers := recordsOfKind(t, f, "transfer")
	if len(transfers) != 1 || transfers[0]["owner_id"] != "northwind" ||
		transfers[0]["lifecycle_state"] != "transferred" ||
		transfers[0]["revocation_reason"] != ReasonPrivilegeWithdrawn {
		t.Fatalf("transfer records = %v", transfers)
	}
	if _, voided := transfers[0]["voided_recovery_authorization"]; voided {
		t.Fatal("no authorization was open, so none may be named as voided")
	}
	if got := f.server.provisioningState().devices[transferDevice]; got.State != "transferred" ||
		got.Owned() || got.Owner != "" {
		t.Fatalf("after the transfer: %#v, want transferred and owned by no one", got)
	}

	// The window the new owner opened before the transfer was closed by it, so
	// the new owner presses again.
	status, answer = f.operatorHalf(t, "contoso-secret", transferDevice, otherNonce)
	assertRefusal(t, status, answer, CheckClaimWindowOpen)

	// A transferred device is refused at certificate-active until it is
	// claimed again, on every Operational route.
	for _, target := range []string{
		"https://ota.course.example/v1/releases/current",
		"https://ota.course.example/v1/firmware/ota-demo.signed.bin",
	} {
		rstatus, rbody := f.refusalOf(t, present(t, f.operational, old, http.MethodGet, target, ""))
		assertRefusal(t, rstatus, rbody, CheckCertificateActive)
	}

	// The second act is the Tier 7 claim, word for word.
	csr := certificationRequest(t, transferDevice)
	if status, answer := f.deviceHalf(t, factory, transferDevice, thirdNonce, csr); status != http.StatusOK ||
		answer["result"] != "pending" {
		t.Fatalf("device half = %d %v, want 200 pending", status, answer)
	}
	status, answer = f.operatorHalf(t, "contoso-secret", transferDevice, thirdNonce)
	if status != http.StatusOK || answer["result"] != "claimed" || answer["lifecycle_state"] != "claimed" ||
		answer["owner_id"] != "contoso" {
		t.Fatalf("new owner's claim = %d %v, want 200 claimed by contoso", status, answer)
	}
	_, answer = f.deviceHalf(t, factory, transferDevice, thirdNonce, csr)
	fresh := collected(t, answer)
	if fresh.SerialNumber.String() == oldSerial || fresh.Subject.OrganizationalUnit[0] != "contoso" {
		t.Fatalf("new certificate serial %s scope %v, want a new serial in contoso",
			fresh.SerialNumber, fresh.Subject.OrganizationalUnit)
	}
	if code := f.serve(t, present(t, f.operational, fresh,
		http.MethodGet, "https://ota.course.example/v1/releases/current", "")); code != http.StatusOK {
		t.Fatalf("the new owner's certificate = %d, want 200", code)
	}
	if got := f.server.provisioningState().devices[transferDevice]; got.State != "active" ||
		got.Owner != "contoso" {
		t.Fatalf("after the new owner's first use: %#v, want active under contoso", got)
	}

	// The old certificate stays refused after the new claim.
	rstatus, rbody := f.refusalOf(t, present(t, f.operational, old,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, rstatus, rbody, CheckCertificateActive)
}

// Only the owner of record can give a device up. Another owner, and anyone
// naming a device never claimed, are refused at owner-of-record; nothing is
// revoked and nothing is recorded, and the refusal names no owner.
func TestATransferByAnyoneButTheOwnerOfRecordIsRefused(t *testing.T) {
	f := newMutualFixture(t)
	_, old := f.claimedThroughTheService(t, transferDevice, "northwind", "owner-secret")
	f.addOwner(t, "contoso", "contoso-secret", time.Now().Add(24*time.Hour))

	status, answer := f.transfer(t, transferDevice, "contoso-secret")
	assertRefusal(t, status, answer, CheckOwnerOfRecord)
	if strings.Contains(answer["reason"].(string), "northwind") {
		t.Fatalf("owner-of-record must not name the owner: %v", answer["reason"])
	}
	status, answer = f.transfer(t, "beacon-nobody-206ef1170d64", "contoso-secret")
	assertRefusal(t, status, answer, CheckOwnerOfRecord)

	if f.server.revokedSerials()[old.SerialNumber.String()] {
		t.Fatal("a refused transfer must revoke nothing")
	}
	if rows := recordsOfKind(t, f, "transfer"); len(rows) != 0 {
		t.Fatalf("a refused transfer wrote %d records", len(rows))
	}
	if got := f.server.provisioningState().devices[transferDevice]; got.State != "claimed" {
		t.Fatalf("state = %q, want claimed", got.State)
	}
}

// Once the device is given up, the old owner is nobody's owner of record: a
// second transfer, a device revocation, a certificate revocation and a
// recovery are all refused at owner-of-record.
func TestTheOldOwnerIsRefusedEverythingAfterTheTransfer(t *testing.T) {
	f := newMutualFixture(t)
	_, old := f.claimedThroughTheService(t, transferDevice, "northwind", "owner-secret")
	if status, answer := f.transfer(t, transferDevice, "owner-secret"); status != http.StatusOK {
		t.Fatalf("transfer = %d %v", status, answer)
	}
	for name, target := range map[string]string{
		"transfer again":      "/v1/devices/" + transferDevice + "/transfer",
		"revoke the device":   "/v1/devices/" + transferDevice + "/revoke",
		"revoke the old cert": "/v1/certificates/" + old.SerialNumber.String() + "/revoke",
		"recover":             "/v1/devices/" + transferDevice + "/recover",
	} {
		t.Run(name, func(t *testing.T) {
			body := ""
			if strings.HasSuffix(target, "/revoke") {
				body = revokeReason
			}
			status, answer := f.operatorPost(t, target, "owner-secret", body)
			assertRefusal(t, status, answer, CheckOwnerOfRecord)
		})
	}
	if rows := recordsOfKind(t, f, "transfer"); len(rows) != 1 {
		t.Fatalf("transfer records = %d, want 1", len(rows))
	}
}

// A revoked device cannot be transferred, and a decommissioned one cannot
// either. device-in-service runs before owner-of-record, because a
// decommission clears the owner, and device-unrevoked after it.
func TestAStoppedDeviceCannotBeTransferred(t *testing.T) {
	f := newMutualFixture(t)
	f.claimedThroughTheService(t, transferDevice, "northwind", "owner-secret")
	f.revokeDeviceRecord(t, transferDevice, "northwind")
	status, answer := f.transfer(t, transferDevice, "owner-secret")
	assertRefusal(t, status, answer, CheckDeviceUnrevoked)

	f.decommission(t, transferDevice)
	status, answer = f.transfer(t, transferDevice, "owner-secret")
	assertRefusal(t, status, answer, CheckDeviceInService)

	if rows := recordsOfKind(t, f, "transfer"); len(rows) != 0 {
		t.Fatalf("a refused transfer wrote %d records", len(rows))
	}
}

// A transfer voids an open Recovery authorization and names it. Even when the
// old owner later claims the device back as a new owner, the voided
// authorization never lets a press through as a recovery.
func TestATransferVoidsAnOpenRecoveryAuthorization(t *testing.T) {
	f := newMutualFixture(t)
	factory, _ := f.claimedThroughTheService(t, transferDevice, "northwind", "owner-secret")
	_, authorized := f.recover(t, transferDevice, "owner-secret", "")
	id := authorized["recovery_authorization"]

	status, answer := f.transfer(t, transferDevice, "owner-secret")
	if status != http.StatusOK || answer["voided_recovery_authorization"] != id {
		t.Fatalf("transfer = %d %v, want the open authorization %v voided", status, answer, id)
	}
	if revoked, _ := answer["revoked_certificate_serials"].([]any); len(revoked) != 0 {
		t.Fatalf("recovery had revoked the certificate already, so nothing new: %v", revoked)
	}
	if transfers := recordsOfKind(t, f, "transfer"); transfers[0]["voided_recovery_authorization"] != id {
		t.Fatalf("the transfer record must name the voided authorization: %v", transfers[0])
	}
	if _, found := f.server.liveRecoveryAuthorization(transferDevice, "northwind", time.Now()); found {
		t.Fatal("a voided authorization is still live")
	}

	// The old owner claims the device back, as anyone may, with a new press.
	f.deviceHalf(t, factory, transferDevice, otherNonce, certificationRequest(t, transferDevice))
	if status, answer := f.operatorHalf(t, "owner-secret", transferDevice, otherNonce); status != http.StatusOK ||
		answer["result"] != "claimed" {
		t.Fatalf("claim back = %d %v, want 200 claimed", status, answer)
	}
	// And the next press is an owned device again, not a recovery.
	f.deviceHalf(t, factory, transferDevice, thirdNonce, certificationRequest(t, transferDevice))
	status, answer = f.operatorHalf(t, "owner-secret", transferDevice, thirdNonce)
	assertRefusal(t, status, answer, CheckDeviceUnowned)
	if rows := recordsOfKind(t, f, "recovery"); len(rows) != 0 {
		t.Fatal("a voided authorization was spent")
	}
}

// The transfer route sits behind the Owner credential like every Owner
// workflow.
func TestTheTransferRouteSitsBehindTheOwnerCredential(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	status, answer := f.transfer(t, transferDevice, "")
	if status != http.StatusUnauthorized || answer["check"] != CheckOwnerCredentialKnown {
		t.Fatalf("no credential = %d %v, want 401 owner-credential-known", status, answer)
	}
}

// A claim window that was open when the device was stopped cannot bring it
// back. Approving it after a device revocation is refused at device-unrevoked,
// and after a decommission at device-in-service; no claim record is written,
// the state does not move, and the window is closed.
func TestAWindowOpenBeforeTheDeviceWasStoppedCannotBeApproved(t *testing.T) {
	cases := map[string]struct {
		stop  func(t *testing.T, f *mutualFixture)
		check string
		state string
	}{
		"revoked through the Owner's route": {
			stop: func(t *testing.T, f *mutualFixture) {
				if status, answer := f.operatorPost(t, "/v1/devices/"+transferDevice+"/revoke",
					"owner-secret", revokeReason); status != http.StatusOK {
					t.Fatalf("revoke = %d %v", status, answer)
				}
			},
			check: CheckDeviceUnrevoked, state: "revoked",
		},
		"decommissioned by the station": {
			stop:  func(t *testing.T, f *mutualFixture) { f.decommission(t, transferDevice) },
			check: CheckDeviceInService, state: "decommissioned",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newMutualFixture(t)
			factory, _ := f.claimedThroughTheService(t, transferDevice, "northwind", "owner-secret")
			if status, answer := f.recover(t, transferDevice, "owner-secret", ""); status != http.StatusOK {
				t.Fatalf("recover = %d %v", status, answer)
			}
			f.deviceHalf(t, factory, transferDevice, otherNonce, certificationRequest(t, transferDevice))
			c.stop(t, f)

			status, answer := f.operatorHalf(t, "owner-secret", transferDevice, otherNonce)
			assertRefusal(t, status, answer, c.check)
			if claims, recoveries := recordsOfKind(t, f, "claim"), recordsOfKind(t, f, "recovery"); len(claims) != 1 ||
				len(recoveries) != 0 {
				t.Fatalf("claim records %d, recovery records %d; want the first claim only", len(claims), len(recoveries))
			}
			if got := f.server.provisioningState().devices[transferDevice].State; got != c.state {
				t.Fatalf("state = %q, want %q", got, c.state)
			}
			status, answer = f.operatorHalf(t, "owner-secret", transferDevice, otherNonce)
			assertRefusal(t, status, answer, CheckClaimWindowOpen)
		})
	}
}

// The same window on a device that was never claimed, then decommissioned:
// before this check it was approved as a first claim.
func TestAWindowOnAnUnclaimedDeviceIsRefusedAfterADecommission(t *testing.T) {
	f := newMutualFixture(t)
	factory := f.claimable(t, transferDevice, "northwind", "owner-secret")
	f.deviceHalf(t, factory, transferDevice, testNonce, certificationRequest(t, transferDevice))
	f.decommission(t, transferDevice)
	status, answer := f.operatorHalf(t, "owner-secret", transferDevice, testNonce)
	assertRefusal(t, status, answer, CheckDeviceInService)
	if rows := recordsOfKind(t, f, "claim"); len(rows) != 0 {
		t.Fatalf("a decommissioned device was claimed: %v", rows)
	}
}

// The Owner's two revocation routes refuse a retired device at
// device-in-service and a revoked one at device-unrevoked, as every Owner
// operation on a device does.
func TestTheRevocationRoutesRefuseAStoppedDevice(t *testing.T) {
	type attempt struct{ name, target string }
	for _, c := range []struct {
		name  string
		stop  func(t *testing.T, f *mutualFixture)
		check string
	}{
		{"revoked", func(t *testing.T, f *mutualFixture) { f.revokeDeviceRecord(t, transferDevice, "northwind") },
			CheckDeviceUnrevoked},
		{"decommissioned", func(t *testing.T, f *mutualFixture) { f.decommission(t, transferDevice) },
			CheckDeviceInService},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newMutualFixture(t)
			_, old := f.claimedThroughTheService(t, transferDevice, "northwind", "owner-secret")
			c.stop(t, f)
			for _, a := range []attempt{
				{"certificate", "/v1/certificates/" + old.SerialNumber.String() + "/revoke"},
				{"device", "/v1/devices/" + transferDevice + "/revoke"},
			} {
				status, answer := f.operatorPost(t, a.target, "owner-secret", revokeReason)
				if status != http.StatusForbidden || answer["check"] != c.check {
					t.Fatalf("revoke %s of a %s device = %d %v, want 403 %s", a.name, c.name, status, answer, c.check)
				}
			}
			if f.server.revokedSerials()[old.SerialNumber.String()] {
				t.Fatal("a refused revocation must revoke nothing")
			}
			if rows := recordsOfKind(t, f, "revocation"); c.name == "decommissioned" && len(rows) != 0 {
				t.Fatalf("a refused revocation wrote %d records", len(rows))
			}
		})
	}
}

// During a renewal overlap the device holds two Operational certificates, and
// a transfer revokes both: the old owner keeps neither.
func TestATransferDuringARenewalOverlapRevokesBothCertificates(t *testing.T) {
	f := newMutualFixture(t)
	f.server.cfg.OwnerCredentials = stubOwners{owner: "northwind", secret: "correct-horse"}
	cert, _ := f.issuedFor(t, 8201, 61*24*time.Hour, OperationalLifetime)
	f.claim(t, renewalDevice, "northwind", 8201)
	status, body := f.renewal(t, cert, csrFor(t, freshKey(t), renewalDevice))
	if status != http.StatusOK {
		t.Fatalf("renewal = %d %v", status, body)
	}
	next := renewedCertificate(t, body)

	status, answer := f.transfer(t, renewalDevice, "correct-horse")
	if status != http.StatusOK {
		t.Fatalf("transfer = %d %v", status, answer)
	}
	for _, c := range []*x509.Certificate{cert, next} {
		if !f.server.revokedSerials()[c.SerialNumber.String()] {
			t.Fatalf("serial %s survived the transfer", c.SerialNumber)
		}
		rstatus, rbody := f.refusalOf(t, present(t, f.operational, c,
			http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
		assertRefusal(t, rstatus, rbody, CheckCertificateActive)
	}
}
