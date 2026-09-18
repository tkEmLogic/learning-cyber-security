package courseapp

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// ownerCredentialFor mints one and digs the printed secret back out, which is
// the only place it ever exists.
func ownerCredentialFor(t *testing.T, a *app, out *bytes.Buffer, slug string) string {
	t.Helper()
	before := out.Len()
	if err := a.ownerNew([]string{"--name", slug}); err != nil {
		t.Fatal(err)
	}
	printed := out.String()[before:]
	for _, line := range strings.Split(printed, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && !strings.Contains(line, " ") {
			return line
		}
	}
	t.Fatalf("no credential was printed in:\n%s", printed)
	return ""
}

func TestOwnerStoreKeepsAVerifierAndNeverTheCredential(t *testing.T) {
	a, out := provisioningApp(t)
	credential := ownerCredentialFor(t, a, out, "northwind")

	records, err := a.readOwnerRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("owner store holds %d records, want 1", len(records))
	}
	if records[0].CredentialVerifier != verifierFor(credential) {
		t.Fatal("the store must hold the verifier of the credential it printed")
	}
	if strings.Contains(strings.Join([]string{
		records[0].CredentialVerifier, records[0].CredentialID,
	}, " "), credential) {
		t.Fatal("the credential itself reached the store")
	}
	expires, err := time.Parse(time.RFC3339, records[0].CredentialExpires)
	if err != nil {
		t.Fatal(err)
	}
	// Ninety days, because nothing consumes an Owner credential and a lifetime
	// is the only bound it has.
	if days := time.Until(expires).Hours() / 24; days < 89 || days > 91 {
		t.Fatalf("lifetime = %.0f days, want 90", days)
	}
}

// Re-minting supersedes rather than resets. A lost credential must not brick
// the lab, and replacement is not revocation.
func TestReMintingAnOwnerSupersedesTheOlderCredential(t *testing.T) {
	a, out := provisioningApp(t)
	first := ownerCredentialFor(t, a, out, "northwind")
	second := ownerCredentialFor(t, a, out, "northwind")
	if first == second {
		t.Fatal("two mints produced one credential")
	}

	records, err := a.readOwnerRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("owner store holds %d records, want 2: the store is append only", len(records))
	}
	current, ok := currentOwnerRecord(records, "northwind")
	if !ok || current.CredentialVerifier != verifierFor(second) {
		t.Fatal("the later credential must be the one that authenticates")
	}

	if live, err := a.ownerCredentialIsCurrent("northwind", second); err != nil || !live {
		t.Fatalf("the current credential is not current: %v %v", live, err)
	}
	if live, err := a.ownerCredentialIsCurrent("northwind", first); err != nil || live {
		t.Fatalf("the superseded credential still verifies: %v %v", live, err)
	}
	// What makes an idempotent mint possible for the attack fixture.
	if live, err := a.ownerCredentialIsCurrent("rival-labs", second); err != nil || live {
		t.Fatalf("a credential verified as the wrong owner: %v %v", live, err)
	}
}

func TestOwnerNamesAreSlugs(t *testing.T) {
	a, _ := provisioningApp(t)
	for _, name := range []string{"", "Northwind", "north wind", "../escape"} {
		if err := a.ownerNew([]string{"--name", name}); err == nil {
			t.Fatalf("owner name %q was accepted", name)
		}
	}
}

// The revoke command is a lab control, not a general revocation tool a tier
// early: it takes a serial this environment can show a claim record for, and
// nothing else.
func TestRevokeTakesOnlyASerialThisEnvironmentIssued(t *testing.T) {
	a, out := provisioningApp(t)
	if err := a.claimRevoke([]string{"--serial", "12345"}); err == nil {
		t.Fatal("a serial with no claim record was accepted")
	}

	if err := a.writeRecord(provisionRecord{
		Kind:            recordClaim,
		DeviceID:        "beacon-aabbccddeeff",
		OwnerID:         "northwind",
		Lifecycle:       LifecycleClaimed,
		CertSerial:      "12345",
		CertFingerprint: "sha256:abc",
	}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := a.claimRevoke([]string{"--serial", "12345"}); err != nil {
		t.Fatal(err)
	}
	revoked, err := a.revokedSerials()
	if err != nil {
		t.Fatal(err)
	}
	if !revoked["12345"] {
		t.Fatal("the serial was not written to the revocation file")
	}
	if !strings.Contains(out.String(), "beacon-aabbccddeeff") {
		t.Fatalf("the command must show the record it revoked against:\n%s", out.String())
	}

	// Revoking twice is not an error and does not write a second line.
	if err := a.claimRevoke([]string{"--serial", "12345"}); err != nil {
		t.Fatal(err)
	}
}

// The claim record is the first thing in the course to carry a lifecycle state
// other than manufactured, and it arrives by appending.
func TestTheClaimRecordMovesTheDeviceToClaimed(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.writeRecord(provisionRecord{
		Kind:      recordEnrollment,
		DeviceID:  "beacon-aabbccddeeff",
		Lifecycle: LifecycleManufactured,
		Result:    "issued",
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.writeRecord(provisionRecord{
		Kind:       recordClaim,
		DeviceID:   "beacon-aabbccddeeff",
		OwnerID:    "northwind",
		Lifecycle:  LifecycleClaimed,
		CertSerial: "99",
	}); err != nil {
		t.Fatal(err)
	}
	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("the record holds %d lines, want 2: state is derived, never edited", len(records))
	}
	if records[0].Lifecycle != LifecycleManufactured || records[1].Lifecycle != LifecycleClaimed {
		t.Fatalf("replaying the log must show manufactured then claimed, got %q then %q",
			records[0].Lifecycle, records[1].Lifecycle)
	}
}
