package courseapp

// `./course claim approve` is the operator half of the claim, and the only
// command in this course that speaks for a person.
//
// The property worth a test is what the command does not do: it sends no
// owner field, and there is no flag for one. The owner on the answer came from
// the credential the service verified. A command that let a caller name an
// owner would teach the opposite of the tier.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
)

// openAWindow drives the device half only, leaving a claim window waiting for
// an operator. It uses the fixture's synthetic device because the real one is
// a board, and the device half is not what these tests are about.
func openAWindow(t *testing.T, f *bypassFixture, deviceID string) string {
	t.Helper()
	adversary, err := f.app.newTier07Adversary("approve-test")
	if err != nil {
		t.Fatal(err)
	}
	device, err := adversary.ensureEnrolled(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := operationalRequest(deviceID, key)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := newClaimNonce()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := adversary.asDevice(device.FactoryCertificate, device.FactoryKey,
		http.MethodPost, "/v1/devices/"+deviceID+"/claim",
		map[string]any{"nonce": nonce, "csr": csr})
	if err != nil {
		t.Fatal(err)
	}
	if opened.refused() {
		t.Fatalf("the device half was refused at %s: %s", opened.Check, opened.Reason)
	}
	return nonce
}

// approveFixture points the command at the test listeners. Only the operator
// port can be unknown until a listener is bound; everything else the command
// reads is this repository's own manifest.
func approveFixture(t *testing.T) *bypassFixture {
	t.Helper()
	f := newBypassFixture(t)
	f.app.manifest.Runtime.OperatorTLSPort = f.app.manifest.Bypass[tier07BypassKey].OperatorPort
	return f
}

func TestApproveNamesNoOwnerAndTheServiceDerivesOneFromTheCredential(t *testing.T) {
	f := approveFixture(t)
	const deviceID = "beacon-bypass-e7-03"
	nonce := openAWindow(t, f, deviceID)

	credential, _, err := f.app.mintOwner("field-owner")
	if err != nil {
		t.Fatal(err)
	}
	f.out.Reset()
	if err := f.app.claim([]string{"approve",
		"--device", deviceID, "--nonce", nonce, "--credential", credential}); err != nil {
		t.Fatalf("approve: %v\n%s", err, f.out.String())
	}
	output := f.out.String()

	if strings.Contains(output, `"owner`) || strings.Contains(output, "--owner") {
		t.Fatalf("the request named an owner, which is the one thing it may not do:\n%s", output)
	}
	if !strings.Contains(output, "owner:           field-owner") {
		t.Fatalf("the answer did not carry the owner the credential belongs to:\n%s", output)
	}
	if !strings.Contains(output, "Result: "+deviceID+" is claimed by field-owner") {
		t.Fatalf("no result line:\n%s", output)
	}
	if strings.Contains(output, credential) {
		t.Fatalf("the credential was printed:\n%s", output)
	}
}

func TestApproveReportsARefusalByItsCheckNameAndNotItsStatus(t *testing.T) {
	f := approveFixture(t)
	credential, _, err := f.app.mintOwner("field-owner")
	if err != nil {
		t.Fatal(err)
	}
	f.out.Reset()
	err = f.app.claim([]string{"approve",
		"--device", "beacon-bypass-e7-04", "--nonce", "ABCD-EFGH-JKMN-PQRS-TVWX-YZ23",
		"--credential", credential})
	if err == nil {
		t.Fatal("a claim with no open window was not reported as a failure")
	}
	output := f.out.String()
	if !strings.Contains(output, "refused at check claim-window-open") {
		t.Fatalf("the refusal did not name its check:\n%s", output)
	}
	if !strings.Contains(err.Error(), "claim-window-open") {
		t.Fatalf("the error did not name the check: %v", err)
	}
}

func TestApproveIsRefusedWhenTheCredentialIsNotAnOwners(t *testing.T) {
	f := approveFixture(t)
	const deviceID = "beacon-bypass-e7-05"
	nonce := openAWindow(t, f, deviceID)

	f.out.Reset()
	err := f.app.claim([]string{"approve",
		"--device", deviceID, "--nonce", nonce,
		"--credential", "0000000000000000000000000000000000000000000000000000000000000000"})
	if err == nil {
		t.Fatal("an unknown credential was accepted")
	}
	if !strings.Contains(f.out.String(), "refused at check owner-credential-known") {
		t.Fatalf("the refusal did not name the authentication check:\n%s", f.out.String())
	}
}
