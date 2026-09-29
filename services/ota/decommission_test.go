package ota

import (
	"net/http"
	"testing"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// decommission writes the record the provisioning station's
// `./course provision decommission` appends. No serial is revoked, on purpose:
// certificate-active runs first, so revoking the serial as well would refuse
// the certificate before device-in-service could name the real reason.
func (f *mutualFixture) decommission(t *testing.T, deviceID string) {
	t.Helper()
	f.appendRecord(t, "records.jsonl", map[string]any{
		"kind":            "decommission",
		"recorded_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"device_id":       deviceID,
		"lifecycle_state": "decommissioned",
	})
}

func (f *mutualFixture) remanufacture(t *testing.T, deviceID string) {
	t.Helper()
	f.appendRecord(t, "records.jsonl", map[string]any{
		"kind":            "remanufacture",
		"recorded_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"device_id":       deviceID,
		"lifecycle_state": "manufactured",
	})
}

// device-in-service on a device route. A claimed, decommissioned device brings
// its Operational certificate to the download endpoint and is refused, though
// the certificate itself is unexpired, unrevoked and on record.
func TestDecommissionedDeviceIsRefusedAtTheDownloadEndpoint(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	cert, _ := f.operational.issue(t, 8101, "beacon-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(OperationalLifetime))
	f.claim(t, "beacon-206ef1170d64", "northwind", 8101)
	f.decommission(t, "beacon-206ef1170d64")

	status, body := f.refusalOf(t, present(t, f.operational, cert,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, status, body, CheckDeviceInService)

	// device-in-service runs after certificate-active, so the refusal may name
	// the device it has already accepted.
	if body["device_id"] != "beacon-206ef1170d64" {
		t.Fatalf("device_id = %v; device-in-service runs after certificate-active and may name the device", body["device_id"])
	}
}

// device-in-service on the claim route too, which no other device check
// reaches. The Factory certificate is refused although claim is the one route a
// Factory identity is otherwise allowed on.
func TestDecommissionedDeviceIsRefusedAtTheClaimEndpoint(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	factory, _ := f.manufacturer.issue(t, 8102, "beacon-206ef1170d64", "",
		now.Add(-time.Hour), now.Add(time.Hour))
	f.decommission(t, "beacon-206ef1170d64")

	status, body := f.refusalOf(t, present(t, f.manufacturer, factory, http.MethodPost,
		"https://ota.course.example/v1/devices/beacon-206ef1170d64/claim", `{"nonce":"x"}`))
	assertRefusal(t, status, body, CheckDeviceInService)
}

// The certificate serial is deliberately not revoked, so certificate-active
// passes and device-in-service is the check that fires. Were the serial in
// revoked.jsonl, this would refuse at certificate-active and the new check
// would be unreachable over the wire.
func TestDecommissioningLeavesTheSerialUnrevoked(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	cert, _ := f.operational.issue(t, 8103, "beacon-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(OperationalLifetime))
	f.claim(t, "beacon-206ef1170d64", "northwind", 8103)
	f.decommission(t, "beacon-206ef1170d64")

	if f.server.revokedSerials()["8103"] {
		t.Fatal("decommissioning must not revoke the certificate serial")
	}
	_, body := f.refusalOf(t, present(t, f.operational, cert,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	if body["check"] != CheckDeviceInService {
		t.Fatalf("check = %v, want device-in-service to be the reachable refusal", body["check"])
	}
}

// A remanufacture record lifts the decommissioning: the device is back to
// manufactured, so device-in-service no longer fires. It is then refused at
// device-claimed like any other unclaimed device, which is the correct next
// gate and shows the earlier refusal is gone.
func TestRemanufactureReturnsTheDeviceToService(t *testing.T) {
	f := newMutualFixture(t)
	now := time.Now()
	cert, _ := f.operational.issue(t, 8104, "beacon-206ef1170d64", "northwind",
		now.Add(-time.Hour), now.Add(OperationalLifetime))
	f.claim(t, "beacon-206ef1170d64", "northwind", 8104)
	f.decommission(t, "beacon-206ef1170d64")
	f.remanufacture(t, "beacon-206ef1170d64")

	if got := f.server.provisioningState().devices["beacon-206ef1170d64"].State; got != lifecycle.Manufactured {
		t.Fatalf("state after remanufacture = %q, want manufactured", got)
	}
	status, body := f.refusalOf(t, present(t, f.operational, cert,
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	assertRefusal(t, status, body, CheckDeviceClaimed)
}
