package ota

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

func recordsOfKind(t *testing.T, f *mutualFixture, kind string) []map[string]any {
	t.Helper()
	var rows []map[string]any
	for _, row := range readEventLines(t, filepath.Join(f.provisionDir, "records.jsonl")) {
		if row["kind"] == kind {
			rows = append(rows, row)
		}
	}
	return rows
}

func (f *mutualFixture) serve(t *testing.T, request *http.Request) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	f.server.DeviceHandler().ServeHTTP(recorder, request)
	return recorder.Code
}

// The first use of an Operational certificate appends one activation record
// carrying its serial, and that record is what makes the device active. Every
// later use writes nothing.
func TestTheFirstUseOfACertificateActivatesTheDevice(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	device := "beacon-remfg-206ef1170d64"
	cert, _ := f.operational.issue(t, 7009, device, "northwind", now.Add(-time.Hour), now.Add(time.Hour))
	f.claim(t, device, "northwind", 7009)

	if got := f.server.provisioningState().devices[device].State; got != lifecycle.Claimed {
		t.Fatalf("before first use the device is %q, want %q", got, lifecycle.Claimed)
	}
	for range 3 {
		if code := f.serve(t, present(t, f.operational, cert, http.MethodGet,
			"https://ota.course.example/v1/releases/current", "")); code != http.StatusOK {
			t.Fatalf("assignment = %d, want 200", code)
		}
	}

	rows := recordsOfKind(t, f, lifecycle.KindActivation)
	if len(rows) != 1 {
		t.Fatalf("wrote %d activation records for three uses of one certificate, want 1", len(rows))
	}
	row := rows[0]
	if row["device_id"] != device || row["owner_id"] != "northwind" || row["certificate_serial"] != "7009" {
		t.Fatalf("activation record = %#v", row)
	}
	if row["lifecycle_state"] != lifecycle.Active {
		t.Fatalf("stored lifecycle_state = %v, want %q", row["lifecycle_state"], lifecycle.Active)
	}
	if got := f.server.provisioningState().devices[device].State; got != lifecycle.Active {
		t.Fatalf("after first use the device is %q, want %q", got, lifecycle.Active)
	}
}

// A refused request is not a use, and activates nothing.
func TestARefusedRequestActivatesNothing(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	device := "beacon-remfg-206ef1170d64"
	cert, _ := f.operational.issue(t, 7010, device, "contoso", now.Add(-time.Hour), now.Add(time.Hour))
	f.claim(t, device, "northwind", 7010)

	status, body := f.refusalOf(t, present(t, f.operational, cert, http.MethodGet,
		"https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, status, body, CheckOwnershipContext)
	if rows := recordsOfKind(t, f, lifecycle.KindActivation); len(rows) != 0 {
		t.Fatalf("a refused request wrote %d activation records", len(rows))
	}
	if got := f.server.provisioningState().devices[device].State; got != lifecycle.Claimed {
		t.Fatalf("the device is %q, want %q", got, lifecycle.Claimed)
	}
}

// A certificate this device was never issued can pass every check, because
// clause 3 of certificate-active joins on any claim record. It is still not a
// use of this device's Operational identity, so it activates nothing.
func TestASerialIssuedToAnotherDeviceActivatesNothing(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	device := "beacon-remfg-206ef1170d64"
	f.claim(t, "beacon-donor", "northwind", 7011)
	f.claim(t, device, "northwind", 7012)
	forged, _ := f.operational.issue(t, 7011, device, "northwind", now.Add(-time.Hour), now.Add(time.Hour))

	if code := f.serve(t, present(t, f.operational, forged, http.MethodGet,
		"https://ota.course.example/v1/releases/current", "")); code != http.StatusOK {
		t.Fatalf("assignment = %d, want 200", code)
	}
	if rows := recordsOfKind(t, f, lifecycle.KindActivation); len(rows) != 0 {
		t.Fatalf("a serial issued to another device wrote an activation: %#v", rows)
	}
}

// The claim the service writes stores the derivation's answer, not a literal.
func TestTheClaimRecordStoresTheDerivedState(t *testing.T) {
	f := newMutualFixture(t)
	device := "beacon-claim-206ef1170d64"
	factory := f.claimable(t, device, "northwind", "owner-secret")
	f.deviceHalf(t, factory, device, testNonce, certificationRequest(t, device))
	status, answer := f.operatorHalf(t, "owner-secret", device, testNonce)
	if status != http.StatusOK {
		t.Fatalf("operator half = %d: %#v", status, answer)
	}
	record := lastClaimRecord(t, f)
	derived := f.server.provisioningState().devices[device].State
	if record["lifecycle_state"] != derived || answer["lifecycle_state"] != derived || derived != lifecycle.Claimed {
		t.Fatalf("stored %v, answered %v, derived %q; all three must be %q",
			record["lifecycle_state"], answer["lifecycle_state"], derived, lifecycle.Claimed)
	}
}

// The device-event success path records the serial, spelled as the refusal
// path spells it, so one grep follows one certificate through both outcomes.
func TestADeviceEventRecordsTheCertificateSerial(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	device := "beacon-remfg-206ef1170d64"
	cert, _ := f.operational.issue(t, 7013, device, "northwind", now.Add(-time.Hour), now.Add(time.Hour))
	f.claim(t, device, "northwind", 7013)

	if code := f.serve(t, present(t, f.operational, cert, http.MethodPost,
		"https://ota.course.example/v1/devices/"+device+"/events",
		`{"device_id":"`+device+`","event_type":"status.observed"}`)); code != http.StatusAccepted {
		t.Fatalf("event = %d, want 202", code)
	}
	stored := readEventLines(t, filepath.Join(f.stateDir, "events.jsonl"))
	if len(stored) != 1 || stored[0]["certificate_serial"] != "7013" {
		t.Fatalf("the accepted event must carry the certificate serial: %#v", stored)
	}
}
