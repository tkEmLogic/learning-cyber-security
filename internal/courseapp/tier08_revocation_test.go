package courseapp

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The manufacturer's block searches enrollment records, where Factory serials
// live. This is the lookup Tier 8 owes: ./course claim revoke searches claim
// records and cannot name a Factory serial, so a claim record for the serial
// does not satisfy provision revoke, and an enrollment record does.
func TestProvisionRevokeSearchesEnrollmentRecords(t *testing.T) {
	a, out := provisioningApp(t)

	// A claim record for the serial is the wrong store: the manufacturer's
	// block does not find a Factory serial in a claim record.
	if err := a.writeRecord(provisionRecord{
		Kind: recordClaim, DeviceID: "beacon-aabbccddeeff", OwnerID: "northwind",
		Lifecycle: LifecycleClaimed, CertSerial: "5551",
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.provisionRevoke([]string{"--serial", "5551", "--reason", crlReasonKeyCompromise}); err == nil {
		t.Fatal("a claim serial was accepted; the manufacturer's block must search enrollment records")
	}

	// An enrollment record for the serial is the right store.
	if err := a.writeRecord(provisionRecord{
		Kind: recordEnrollment, DeviceID: "beacon-aabbccddeeff",
		Lifecycle: LifecycleManufactured, CertSerial: "4001",
		CertFingerprint: "sha256:abc", Result: "issued",
	}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := a.provisionRevoke([]string{"--serial", "4001", "--reason", crlReasonKeyCompromise}); err != nil {
		t.Fatal(err)
	}
	revoked, err := a.revokedSerials()
	if err != nil {
		t.Fatal(err)
	}
	if !revoked["4001"] {
		t.Fatal("the Factory serial was not written to the revocation file")
	}
	if !strings.Contains(out.String(), "beacon-aabbccddeeff") {
		t.Fatalf("the command must show the enrollment it blocked:\n%s", out.String())
	}

	// The line is the richer Tier 8 shape.
	line := lastRevokedLine(t, a)
	if line.CertSerial != "4001" || line.Role != "factory" ||
		line.Reason != crlReasonKeyCompromise || line.By != "manufacturer" || line.Revoked == "" {
		t.Fatalf("the revocation line is not the richer Tier 8 shape: %#v", line)
	}
}

// The manufacturer may block a Factory identity only for keyCompromise.
func TestProvisionRevokeRejectsOtherReasons(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.writeRecord(provisionRecord{
		Kind: recordEnrollment, DeviceID: "beacon-aabbccddeeff",
		CertSerial: "4002", Result: "issued",
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.provisionRevoke([]string{"--serial", "4002", "--reason", crlReasonCessationOfOperation}); err == nil {
		t.Fatal("cessationOfOperation was accepted for a Factory block")
	}
	revoked, _ := a.revokedSerials()
	if revoked["4002"] {
		t.Fatal("a refused reason must write nothing")
	}
}

// Blocking a Factory identity is one-way, and asking twice writes no second
// line.
func TestProvisionRevokeIsIdempotent(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.writeRecord(provisionRecord{
		Kind: recordEnrollment, DeviceID: "beacon-aabbccddeeff",
		CertSerial: "4003", Result: "issued",
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := a.provisionRevoke([]string{"--serial", "4003", "--reason", crlReasonKeyCompromise}); err != nil {
			t.Fatal(err)
		}
	}
	if got := countRevoked(t, a, "4003"); got != 1 {
		t.Fatalf("a one-way block wrote %d lines, want 1", got)
	}
}

// The owner revoke commands validate the reason against the CRLReason set
// before any request is built, so a bad reason never reaches the wire.
func TestOwnerRevokeRejectsAnUnknownReasonOffline(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.ownerRevoke([]string{"certificate", "--serial", "7001",
		"--reason", "becauseISaidSo", "--credential", "deadbeef"}); err == nil {
		t.Fatal("an unknown reason was accepted for owner revoke certificate")
	}
	if err := a.ownerRevoke([]string{"device", "--device", "beacon-aabbccddeeff",
		"--reason", "nope", "--credential", "deadbeef"}); err == nil {
		t.Fatal("an unknown reason was accepted for owner revoke device")
	}
}

// An unknown owner revoke target is a usage error, not a silent fall-through.
func TestOwnerRevokeRejectsAnUnknownTarget(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.ownerRevoke([]string{"everything", "--reason", crlReasonKeyCompromise}); err == nil {
		t.Fatal("an unknown target was accepted")
	}
}

func lastRevokedLine(t *testing.T, a *app) tier08RevocationLine {
	t.Helper()
	raw, err := os.ReadFile(a.revokedPath())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var line tier08RevocationLine
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &line); err != nil {
		t.Fatal(err)
	}
	return line
}

func countRevoked(t *testing.T, a *app, serial string) int {
	t.Helper()
	raw, err := os.ReadFile(a.revokedPath())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var line tier08RevocationLine
		if err := json.Unmarshal([]byte(l), &line); err != nil {
			t.Fatal(err)
		}
		if line.CertSerial == serial {
			count++
		}
	}
	return count
}
