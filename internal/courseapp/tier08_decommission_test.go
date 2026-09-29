package courseapp

import (
	"bytes"
	"strings"
	"testing"
)

// enrollDevice mints a Bootstrap credential and drives one enrolment through
// the transport-free station, the way the fixtures do, so a test can reach the
// state after an enrolment without a board.
func enrollDevice(t *testing.T, a *app, out *bytes.Buffer, deviceID string) enrollmentOutcome {
	t.Helper()
	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, deviceID)
	outcome, err := a.enroll(enrollmentRequest{
		DeviceID: deviceID,
		CSRDer:   device.request(t, deviceID, credential),
	}, credential)
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func countRecords(t *testing.T, a *app, kind string) int {
	t.Helper()
	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, record := range records {
		if record.Kind == kind {
			n++
		}
	}
	return n
}

// boardOf keys a board by its MAC suffix, so two identifiers minted for one
// board resolve to one unit.
func TestBoardOfKeysByTheMACSuffix(t *testing.T) {
	for _, id := range []string{
		"beacon-206ef1170d64",
		"beacon-t08-206ef1170d64",
		"beacon-remfg-206ef1170d64",
	} {
		if got := boardOf(id); got != "206ef1170d64" {
			t.Fatalf("boardOf(%q) = %q, want the shared MAC suffix", id, got)
		}
	}
	// A name that is not a MAC keys to itself, so it can only match its own
	// records.
	if got := boardOf("beacon-development-shared"); got != "beacon-development-shared" {
		t.Fatalf("boardOf of a non-MAC name = %q, want itself", got)
	}
}

// hardware-in-service, old identifier: the decommissioned board brings its own
// name and an old credential, and is refused before the credential is even
// looked up.
func TestHardwareInServiceRefusesTheSameIdentifier(t *testing.T) {
	a, out := provisioningApp(t)
	if outcome := enrollDevice(t, a, out, "beacon-206ef1170d64"); !outcome.Issued {
		t.Fatalf("first enrolment refused at %s: %s", outcome.Check, outcome.Reason)
	}
	if err := a.provisionDecommission([]string{"--device", "beacon-206ef1170d64"}); err != nil {
		t.Fatal(err)
	}

	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, "beacon-206ef1170d64")
	outcome, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-206ef1170d64",
		CSRDer:   device.request(t, "beacon-206ef1170d64", credential),
	}, credential)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Issued || outcome.Check != "hardware-in-service" {
		t.Fatalf("re-enrolment = issued:%v check:%s, want a refusal at hardware-in-service", outcome.Issued, outcome.Check)
	}
}

// hardware-in-service, new identifier, same MAC: a fresh credential and a
// brand-new name do not get a decommissioned board back in, because the board
// is keyed by its MAC suffix, not by the identifier.
func TestHardwareInServiceRefusesANewIdentifierOnTheSameBoard(t *testing.T) {
	a, out := provisioningApp(t)
	if outcome := enrollDevice(t, a, out, "beacon-206ef1170d64"); !outcome.Issued {
		t.Fatalf("first enrolment refused at %s: %s", outcome.Check, outcome.Reason)
	}
	if err := a.provisionDecommission([]string{"--device", "beacon-206ef1170d64"}); err != nil {
		t.Fatal(err)
	}

	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, "beacon-t08-206ef1170d64")
	outcome, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-t08-206ef1170d64",
		CSRDer:   device.request(t, "beacon-t08-206ef1170d64", credential),
	}, credential)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Issued || outcome.Check != "hardware-in-service" {
		t.Fatalf("new-name enrolment = issued:%v check:%s, want a refusal at hardware-in-service", outcome.Issued, outcome.Check)
	}
}

// Remanufacture is the one way back. After it, a new identifier with the board's
// MAC suffix enrols, and the old identifier stays retired.
func TestRemanufactureLetsANewIdentifierEnrol(t *testing.T) {
	a, out := provisioningApp(t)
	if outcome := enrollDevice(t, a, out, "beacon-206ef1170d64"); !outcome.Issued {
		t.Fatalf("first enrolment refused at %s: %s", outcome.Check, outcome.Reason)
	}
	if err := a.provisionDecommission([]string{"--device", "beacon-206ef1170d64"}); err != nil {
		t.Fatal(err)
	}
	if err := a.provisionRemanufacture([]string{
		"--device", "beacon-206ef1170d64", "--reason", "returned board, wiped and re-manufactured",
	}); err != nil {
		t.Fatal(err)
	}

	outcome := enrollDevice(t, a, out, "beacon-t08-206ef1170d64")
	if !outcome.Issued {
		t.Fatalf("enrolment after remanufacture refused at %s: %s", outcome.Check, outcome.Reason)
	}

	// The old identifier stays retired: it already holds a certificate, so it
	// is refused at identifier-unused rather than let back in.
	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, "beacon-206ef1170d64")
	retired, err := a.enroll(enrollmentRequest{
		DeviceID: "beacon-206ef1170d64",
		CSRDer:   device.request(t, "beacon-206ef1170d64", credential),
	}, credential)
	if err != nil {
		t.Fatal(err)
	}
	if retired.Issued || retired.Check != "identifier-unused" {
		t.Fatalf("old identifier = issued:%v check:%s, want it kept retired at identifier-unused", retired.Issued, retired.Check)
	}
}

// Factory loss is observed, not refused: a board that re-enrols under a new
// name while an earlier claim of its still stands is let in, and the station
// records which identity was lost.
func TestFactoryLossIsObservedOnReEnrolment(t *testing.T) {
	a, out := provisioningApp(t)
	if outcome := enrollDevice(t, a, out, "beacon-206ef1170d64"); !outcome.Issued {
		t.Fatalf("first enrolment refused at %s: %s", outcome.Check, outcome.Reason)
	}
	// The OTA service would write this claim; here the station stands in for it
	// so the board has a live, owned identity to lose.
	if err := a.writeRecord(provisionRecord{
		Kind:       recordClaim,
		DeviceID:   "beacon-206ef1170d64",
		OwnerID:    "northwind",
		CertSerial: "9001",
	}); err != nil {
		t.Fatal(err)
	}

	outcome := enrollDevice(t, a, out, "beacon-t08-206ef1170d64")
	if !outcome.Issued {
		t.Fatalf("re-enrolment must be allowed, got refusal at %s: %s", outcome.Check, outcome.Reason)
	}

	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		if record.Kind == recordFactoryLoss {
			found = true
			if record.Replaced != "beacon-206ef1170d64" {
				t.Fatalf("factory_loss names replaced %q, want the lost identity", record.Replaced)
			}
			if record.DeviceID != "beacon-t08-206ef1170d64" {
				t.Fatalf("factory_loss device_id %q, want the re-enrolled identity", record.DeviceID)
			}
		}
	}
	if !found {
		t.Fatal("no factory_loss observation was recorded on re-enrolment")
	}
}

// A first, clean enrolment raises no observation, and neither does a re-enrol
// on a board whose earlier identity was never claimed: factory_loss keys on an
// owned identity, which is the signature of an owner left confused.
func TestFactoryLossIsNotRaisedWithoutAnOwnedIdentity(t *testing.T) {
	a, out := provisioningApp(t)
	if outcome := enrollDevice(t, a, out, "beacon-206ef1170d64"); !outcome.Issued {
		t.Fatalf("first enrolment refused at %s: %s", outcome.Check, outcome.Reason)
	}
	// Re-enrol under a new name with no claim on record for the board.
	if outcome := enrollDevice(t, a, out, "beacon-t08-206ef1170d64"); !outcome.Issued {
		t.Fatalf("re-enrolment refused at %s: %s", outcome.Check, outcome.Reason)
	}
	if n := countRecords(t, a, recordFactoryLoss); n != 0 {
		t.Fatalf("factory_loss recorded %d times without an owned identity, want 0", n)
	}
}

// A second decommission is refused at device-in-service, and one decommission
// record is the whole of it.
func TestSecondDecommissionIsRefusedAtDeviceInService(t *testing.T) {
	a, out := provisioningApp(t)
	if outcome := enrollDevice(t, a, out, "beacon-206ef1170d64"); !outcome.Issued {
		t.Fatalf("first enrolment refused at %s: %s", outcome.Check, outcome.Reason)
	}
	if err := a.provisionDecommission([]string{"--device", "beacon-206ef1170d64"}); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	if err := a.provisionDecommission([]string{"--device", "beacon-206ef1170d64"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Refused at check device-in-service") {
		t.Fatalf("second decommission did not report device-in-service:\n%s", out.String())
	}
	if n := countRecords(t, a, recordDecommission); n != 1 {
		t.Fatalf("decommission records = %d, want exactly one", n)
	}
}

// Decommissioning a board the station never manufactured is a typo, not a
// lifecycle event, and is refused before any record is written.
func TestDecommissionRequiresAKnownBoard(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.provisionDecommission([]string{"--device", "beacon-000000000000"}); err == nil {
		t.Fatal("decommissioning an unknown board must be refused")
	}
	if n := countRecords(t, a, recordDecommission); n != 0 {
		t.Fatalf("decommission records = %d, want none written for an unknown board", n)
	}
}
