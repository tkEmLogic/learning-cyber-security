package courseapp

import (
	"strings"
	"testing"
)

// The owner of record gives the device up, the old owner is refused if they
// try again, and a second owner then claims it with the ordinary approve.
func TestOwnerTransferThenASecondOwnerClaims(t *testing.T) {
	f := approveFixture(t)
	const deviceID = "beacon-bypass-e7-06"
	first, _, err := f.app.mintOwner("field-owner")
	if err != nil {
		t.Fatal(err)
	}
	claimForTest(t, f, deviceID, first)

	f.out.Reset()
	if err := f.app.owner([]string{"transfer", "--device", deviceID, "--credential", first}); err != nil {
		t.Fatalf("transfer: %v\n%s", err, f.out.String())
	}
	output := f.out.String()
	for _, want := range []string{
		"reason: privilegeWithdrawn",
		"result:                 transferred",
		"Result: device " + deviceID + " is transferred",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("transfer output lacks %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, first) {
		t.Fatalf("the credential was printed:\n%s", output)
	}

	f.out.Reset()
	err = f.app.owner([]string{"transfer", "--device", deviceID, "--credential", first})
	if err == nil || !strings.Contains(f.out.String(), "refused at check owner-of-record") {
		t.Fatalf("a second transfer by the old owner = %v, want owner-of-record\n%s", err, f.out.String())
	}

	second, _, err := f.app.mintOwner("second-owner")
	if err != nil {
		t.Fatal(err)
	}
	nonce := openAWindow(t, f, deviceID)
	f.out.Reset()
	if err := f.app.claim([]string{"approve",
		"--device", deviceID, "--nonce", nonce, "--credential", second}); err != nil {
		t.Fatalf("approve by the second owner: %v\n%s", err, f.out.String())
	}
	if !strings.Contains(f.out.String(), "Result: "+deviceID+" is claimed by second-owner") {
		t.Fatalf("the second owner's approval was not a claim:\n%s", f.out.String())
	}
}

// Another owner cannot give a device up.
func TestOwnerTransferByAnotherOwnerIsRefusedAtOwnerOfRecord(t *testing.T) {
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
	err = f.app.owner([]string{"transfer", "--device", deviceID, "--credential", other})
	if err == nil || !strings.Contains(err.Error(), "owner-of-record") {
		t.Fatalf("transfer by another owner = %v, want owner-of-record\n%s", err, f.out.String())
	}
}

// The credential is required, and its absence is caught before any request.
func TestOwnerTransferNeedsACredential(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.owner([]string{"transfer", "--device", "beacon-aabbccddeeff"}); err == nil ||
		!strings.Contains(err.Error(), "--credential is required") {
		t.Fatalf("no credential = %v", err)
	}
}
