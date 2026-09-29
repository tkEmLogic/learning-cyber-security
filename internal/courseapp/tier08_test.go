package courseapp

import (
	"strings"
	"testing"
)

// The station fills in lifecycle_state from the derivation, whatever the
// caller put there, and a line that moves no state stores none.
func TestTheStationStoresTheDerivedState(t *testing.T) {
	a, _ := provisioningApp(t)
	device := "beacon-aabbccddeeff"
	lines := []provisionRecord{
		{Kind: recordCredentialIssued, DeviceID: device, Result: "issued"},
		{Kind: recordEnrollment, DeviceID: device, Result: "issued", Lifecycle: LifecycleActive},
		{Kind: recordClaim, DeviceID: device, OwnerID: "northwind", CertSerial: "99"},
		{Kind: recordActivation, DeviceID: device, OwnerID: "northwind", CertSerial: "99"},
		{Kind: recordActivation, DeviceID: device, OwnerID: "northwind", CertSerial: "98"},
	}
	for _, line := range lines {
		if err := a.writeRecord(line); err != nil {
			t.Fatal(err)
		}
	}
	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"", LifecycleManufactured, LifecycleClaimed, LifecycleActive, LifecycleActive}
	for i, record := range records {
		if record.Lifecycle != want[i] {
			t.Errorf("line %d (%s) stored %q, want %q", i, record.Kind, record.Lifecycle, want[i])
		}
	}
}

// The service's activation line reads as one in the station's record view.
func TestTheRecordViewShowsAnActivation(t *testing.T) {
	a, out := provisioningApp(t)
	device := "beacon-aabbccddeeff"
	for _, line := range []provisionRecord{
		{Kind: recordEnrollment, DeviceID: device, Result: "issued"},
		{Kind: recordClaim, DeviceID: device, OwnerID: "northwind", CertSerial: "99"},
		{Kind: recordActivation, DeviceID: device, OwnerID: "northwind", CertSerial: "99", Station: "course-ota-service"},
	} {
		if err := a.writeRecord(line); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	if err := a.provisionShowRecord(nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "first used operational certificate 99, lifecycle active") {
		t.Fatalf("the record view does not show the activation:\n%s", out.String())
	}
}
