package courseapp

import (
	"net/http"
	"strings"
	"testing"

	"github.com/tkEmLogic/learning-cyber-security/services/ota"
)

// The station spells the service's request kind again rather than importing
// the service, so the two spellings are pinned together here.
func TestTheStationSpellsTheRenewalRequestKindAsTheServiceDoes(t *testing.T) {
	if recordRenewalRequest != ota.KindRenewalRequest {
		t.Fatalf("station %q, service %q", recordRenewalRequest, ota.KindRenewalRequest)
	}
}

// claim renew needs a device and a credential before anything is sent.
func TestClaimRenewNeedsADeviceAndACredential(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.claim([]string{"renew", "--credential", "deadbeef"}); err == nil {
		t.Fatal("claim renew without --device was accepted")
	}
	if err := a.claim([]string{"renew", "--device", "beacon-aabbccddeeff"}); err == nil ||
		!strings.Contains(err.Error(), "--credential") {
		t.Fatalf("claim renew without --credential = %v", err)
	}
}

// A refusal is narrated by its check name, and the command fails.
func TestClaimRenewNarratesARefusalByItsCheck(t *testing.T) {
	a, out := provisioningApp(t)
	err := a.narrateRenewalRequest(http.StatusForbidden,
		[]byte(`{"check":"owner-of-record","reason":"you are not the owner of record for this device"}`))
	if err == nil || !strings.Contains(err.Error(), "owner-of-record") {
		t.Fatalf("a refusal = %v, want an error naming owner-of-record", err)
	}
	if !strings.Contains(out.String(), "refused at check owner-of-record") {
		t.Fatalf("the refusal is not narrated by its check:\n%s", out.String())
	}
}

// A success says the renewal is due now, and what happens next.
func TestClaimRenewNarratesASuccess(t *testing.T) {
	a, out := provisioningApp(t)
	if err := a.narrateRenewalRequest(http.StatusOK,
		[]byte(`{"result":"requested","device_id":"beacon-aabbccddeeff","renew":true}`)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"renew: true", "superseded", "Result: renewal is due now for beacon-aabbccddeeff"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("the success narration lacks %q:\n%s", want, out.String())
		}
	}
}

// The record view shows a renewal and a renewal request.
func TestTheRecordViewShowsARenewal(t *testing.T) {
	a, out := provisioningApp(t)
	device := "beacon-aabbccddeeff"
	for _, line := range []provisionRecord{
		{Kind: recordEnrollment, DeviceID: device, Result: "issued"},
		{Kind: recordClaim, DeviceID: device, OwnerID: "northwind", CertSerial: "99"},
		{Kind: recordRenewalRequest, DeviceID: device, OwnerID: "northwind", Station: "course-ota-service"},
		{Kind: recordRenewal, DeviceID: device, OwnerID: "northwind", CertSerial: "100",
			RenewedFrom: "99", CertPublicKey: "sha256:abc", Station: "course-ota-service"},
	} {
		if err := a.writeRecord(line); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	if err := a.provisionShowRecord(nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"renewal requested by northwind", "renewed operational certificate 99 as 100, lifecycle claimed"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("the record view lacks %q:\n%s", want, out.String())
		}
	}
}
