package coursepki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The fourth authority, and the guard that keeps it from being replaced.
func TestOperationalCARefusesToReplaceItself(t *testing.T) {
	dir := t.TempDir()
	if OperationalCAExists(dir) {
		t.Fatal("an empty directory reports an authority")
	}
	if err := GenerateOperationalCA(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range OperationalCAFiles() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
	}
	before, err := os.ReadFile(filepath.Join(dir, OperationalCACert))
	if err != nil {
		t.Fatal(err)
	}
	if err := GenerateOperationalCA(dir); err == nil {
		t.Fatal("the authority was replaced silently")
	}
	after, err := os.ReadFile(filepath.Join(dir, OperationalCACert))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the refusal still rewrote the authority")
	}

	ca, _, err := LoadOperationalCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Subject.CommonName != OperationalCAName {
		t.Fatalf("subject = %q, want %q", ca.Subject.CommonName, OperationalCAName)
	}
	// A fourth authority, not a second name for the third one.
	if ca.Subject.CommonName == DeviceCAName {
		t.Fatal("the operational authority is the manufacturer authority")
	}
}

// An Operational certificate is a Factory certificate with a different issuer
// and the owner slug in the subject organizational unit.
func TestOperationalCertificateCarriesTheOwnerAndNinetyDays(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateOperationalCA(dir); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := IssueOperationalCertificate(dir, "beacon-aabbccddeeff", "northwind", key.Public())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Subject.CommonName != "beacon-aabbccddeeff" {
		t.Fatalf("common name = %q", issued.Subject.CommonName)
	}
	if len(issued.Subject.OrganizationalUnit) != 1 || issued.Subject.OrganizationalUnit[0] != "northwind" {
		t.Fatalf("organizational unit = %v, want [northwind]", issued.Subject.OrganizationalUnit)
	}
	if len(issued.ExtKeyUsage) != 1 || issued.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("extended key usage = %v, want client authentication only", issued.ExtKeyUsage)
	}
	if len(issued.DNSNames) != 0 {
		t.Fatal("an Operational identity is a client and carries no subject alternative name")
	}
	if issued.IsCA {
		t.Fatal("an Operational leaf is not an authority")
	}
	days := issued.NotAfter.Sub(issued.NotBefore).Hours() / 24
	if days < 90 || days > 91 {
		t.Fatalf("lifetime = %.0f days, want 90 against the Factory identity's ten years", days)
	}

	ca, _, err := LoadOperationalCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := issued.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("the leaf does not chain to the operational authority: %v", err)
	}
}

// The fixture's variant chooses a serial and a validity window, and nothing
// else.
func TestTheForgeableVariantChoosesOnlySerialAndWindow(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateOperationalCA(dir); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opened := time.Now().UTC().Add(-200 * 24 * time.Hour)
	expired := time.Now().UTC().Add(-time.Hour)
	der, err := IssueOperationalCertificateAs(dir, "beacon-aabbccddeeff", "rival-labs",
		key.Public(), big.NewInt(4242), opened, expired)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if issued.SerialNumber.Int64() != 4242 {
		t.Fatalf("serial = %s, want 4242", issued.SerialNumber)
	}
	if !issued.NotAfter.Before(time.Now()) {
		t.Fatal("the chosen expiry was ignored")
	}
	// An expired certificate, not a malformed one: the window has to open
	// before it closes or the row demonstrates a broken issuer.
	if !issued.NotBefore.Before(issued.NotAfter) {
		t.Fatalf("NotBefore %s is not before NotAfter %s", issued.NotBefore, issued.NotAfter)
	}
	if issued.IsCA || issued.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Fatal("the forgeable variant must not be able to make an authority")
	}
	if _, err := IssueOperationalCertificateAs(dir, "beacon-aabbccddeeff", "rival-labs",
		key.Public(), nil, opened, expired); err == nil {
		t.Fatal("a certificate with no serial was issued")
	}
}
