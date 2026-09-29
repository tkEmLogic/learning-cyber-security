package courseapp

import (
	"strings"
	"testing"
)

// The device identifiers are borrowed from the Tier 7 fixture's bounded list;
// each test has its own Course environment, so nothing is shared.
//
// claimForTest runs a whole claim through the real service: the device half
// from the fixture's synthetic device, the operator half from claim approve.
func claimForTest(t *testing.T, f *bypassFixture, deviceID, credential string) {
	t.Helper()
	nonce := openAWindow(t, f, deviceID)
	if err := f.app.claim([]string{"approve",
		"--device", deviceID, "--nonce", nonce, "--credential", credential}); err != nil {
		t.Fatalf("approve: %v\n%s", err, f.out.String())
	}
}

// The owner of record authorizes a recovery, and the next claim of the same
// device by the same owner is a recovery rather than a refusal.
func TestClaimRecoverByTheOwnerOfRecordLetsOneClaimThrough(t *testing.T) {
	f := approveFixture(t)
	const deviceID = "beacon-bypass-e7-06"
	credential, _, err := f.app.mintOwner("field-owner")
	if err != nil {
		t.Fatal(err)
	}
	claimForTest(t, f, deviceID, credential)

	f.out.Reset()
	if err := f.app.claim([]string{"recover", "--device", deviceID, "--credential", credential}); err != nil {
		t.Fatalf("recover: %v\n%s", err, f.out.String())
	}
	output := f.out.String()
	if !strings.Contains(output, `"reason":"superseded"`) {
		t.Fatalf("recover must default to superseded:\n%s", output)
	}
	if !strings.Contains(output, "Result: recovery of "+deviceID+" is authorized") {
		t.Fatalf("no result line:\n%s", output)
	}
	if strings.Contains(output, credential) {
		t.Fatalf("the credential was printed:\n%s", output)
	}

	nonce := openAWindow(t, f, deviceID)
	f.out.Reset()
	if err := f.app.claim([]string{"approve",
		"--device", deviceID, "--nonce", nonce, "--credential", credential}); err != nil {
		t.Fatalf("approve after recover: %v\n%s", err, f.out.String())
	}
	if !strings.Contains(f.out.String(), "Result: "+deviceID+" is recovered for field-owner") {
		t.Fatalf("the approval was not a recovery:\n%s", f.out.String())
	}
}

// Another owner is refused at owner-of-record, by name.
func TestClaimRecoverByAnotherOwnerIsRefusedAtOwnerOfRecord(t *testing.T) {
	f := approveFixture(t)
	const deviceID = "beacon-bypass-e7-07"
	owner, _, err := f.app.mintOwner("field-owner")
	if err != nil {
		t.Fatal(err)
	}
	claimForTest(t, f, deviceID, owner)
	other, _, err := f.app.mintOwner("other-owner")
	if err != nil {
		t.Fatal(err)
	}

	f.out.Reset()
	err = f.app.claim([]string{"recover", "--device", deviceID, "--credential", other})
	if err == nil || !strings.Contains(err.Error(), "owner-of-record") {
		t.Fatalf("recover by another owner = %v, want a refusal at owner-of-record\n%s", err, f.out.String())
	}
	if !strings.Contains(f.out.String(), "refused at check owner-of-record") {
		t.Fatalf("the refusal did not name its check:\n%s", f.out.String())
	}
}

// Only superseded and keyCompromise are recovery reasons, and anything else is
// refused before a request is built.
func TestClaimRecoverRejectsAnUnknownReasonOffline(t *testing.T) {
	a, _ := provisioningApp(t)
	err := a.claim([]string{"recover", "--device", "beacon-aabbccddeeff",
		"--credential", "00", "--reason", crlReasonPrivilegeWithdrawn})
	if err == nil || !strings.Contains(err.Error(), "not accepted for a recovery") {
		t.Fatalf("an out-of-set reason = %v", err)
	}
}
