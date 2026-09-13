package coursepki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateProducesAVerifiableChainAndTwoFailingOnes(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(dir); err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(dir, CourseCACert))
	if err != nil {
		t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("the Course certificate authority is not usable as a trust anchor")
	}

	cases := []struct {
		file    string
		name    string
		wantErr bool
		why     string
	}{
		{ServiceCert, ServiceName, false, "the service certificate must verify against the course authority under its own name"},
		{UntrustedCert, ServiceName, true, "a certificate from another authority must fail, even with the right name"},
		{WrongNameCert, ServiceName, true, "a certificate from the course authority must fail under a name it does not carry"},
	}
	for _, test := range cases {
		data, err := os.ReadFile(filepath.Join(dir, test.file))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(data)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		_, err = cert.Verify(x509.VerifyOptions{DNSName: test.name, Roots: pool})
		if test.wantErr && err == nil {
			t.Errorf("%s verified but should not have: %s", test.file, test.why)
		}
		if !test.wantErr && err != nil {
			t.Errorf("%s failed to verify: %s (%v)", test.file, test.why, err)
		}
	}
}

// The service certificate deliberately carries no iPAddress SAN, so a tool
// that connects by address without stating the name fails. That failure is the
// mistake Tier 2 is about, and it has to keep happening.
func TestServiceCertificateCarriesNoAddress(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ServiceCert))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.IPAddresses) != 0 {
		t.Fatalf("service certificate carries %d IP addresses; it must carry none", len(cert.IPAddresses))
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != ServiceName {
		t.Fatalf("service certificate names = %v, want [%s]", cert.DNSNames, ServiceName)
	}
}

func TestExistsReportsAGeneratedAuthority(t *testing.T) {
	dir := t.TempDir()
	if Exists(dir) {
		t.Fatal("an empty directory must not look like a Course certificate authority")
	}
	if err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	if !Exists(dir) {
		t.Fatal("a generated authority must be found, so setup can refuse to replace it")
	}
}
