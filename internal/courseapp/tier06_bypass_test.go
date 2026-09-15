package courseapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// Each host-witnessed bypass must be refused, and refused at the check the
// section 11 table names. A refusal at a different check has not tested the row.

func TestBypassReplayConsumedIsRefused(t *testing.T) {
	a, out := provisioningApp(t)
	if err := a.bypassReplayConsumed(); err != nil {
		t.Fatalf("E-6-01: %v", err)
	}
	if !strings.Contains(out.String(), "refused at credential-unconsumed") {
		t.Fatalf("E-6-01 did not refuse at credential-unconsumed:\n%s", out.String())
	}
}

func TestBypassIdentifierReuseIsRefused(t *testing.T) {
	a, out := provisioningApp(t)
	if err := a.bypassIdentifierReuse(); err != nil {
		t.Fatalf("E-6-02: %v", err)
	}
	if !strings.Contains(out.String(), "refused at identifier-unused") {
		t.Fatalf("E-6-02 did not refuse at identifier-unused:\n%s", out.String())
	}
}

func TestBypassBadProofOfPossessionIsRefused(t *testing.T) {
	a, out := provisioningApp(t)
	if err := a.bypassBadProofOfPossession(); err != nil {
		t.Fatalf("E-6-03: %v", err)
	}
	if !strings.Contains(out.String(), "refused at proof-of-possession") {
		t.Fatalf("E-6-03 did not refuse at proof-of-possession:\n%s", out.String())
	}
}

// A request presenting one key and signed by another must fail proof of
// possession, which is the whole basis for E-6-03.
func TestBadProofOfPossessionRequestFailsSignatureCheck(t *testing.T) {
	der, err := badProofOfPossessionRequest("beacon-bypass-e6-03", strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("the crafted request should still parse: %v", err)
	}
	if err := csr.CheckSignature(); err == nil {
		t.Fatal("the crafted request verified, so it does not present a key whose private half is unheld")
	}
}

// writeFakeReleaseKey writes an EC key pair where the signing paths expect the
// Release key, without going through imgtool. E-6-06 only needs a key that is
// not a device identity and is trusted as the release anchor.
func writeFakeReleaseKey(t *testing.T, a *app) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(a.signingDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.signingKeyPath("release"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(a.publicKeyPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.publicKeyPath(), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBypassKeySeparationRefusesTheReleaseKey(t *testing.T) {
	a, out := provisioningApp(t)
	writeFakeReleaseKey(t, a)
	if err := a.bypassKeySeparation(); err != nil {
		t.Fatalf("E-6-06: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "refused at credential-carried") {
		t.Fatalf("E-6-06 half two did not refuse at credential-carried:\n%s", got)
	}
	if !strings.Contains(got, "refuses the") {
		t.Fatalf("E-6-06 half one did not show the identity key's firmware signature refused:\n%s", got)
	}
}

func TestBypassClonedSharedCredentialIsRefused(t *testing.T) {
	a, out := provisioningApp(t)
	if err := coursepki.GenerateSharedIdentity(a.pkiDir()); err != nil {
		t.Fatal(err)
	}
	if err := a.bypassClonedSharedCredential(); err != nil {
		t.Fatalf("E-6-07: %v", err)
	}
	if !strings.Contains(out.String(), "refused at credential-carried") {
		t.Fatalf("E-6-07 did not refuse at credential-carried:\n%s", out.String())
	}
}
