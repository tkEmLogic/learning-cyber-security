// Package coursepki generates the disposable certificate material for one
// Course environment.
//
// Every key here is thrown away with the Course environment that owns it. None
// of it is a production asset, and none of it ever leaves .course-secrets/.
//
// The material is generated once, at setup, rather than on demand by a
// fixture. A fixture's job is to be pointed at a target, and it should not
// also be a certificate factory.
package coursepki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ServiceName is the name the Reference product checks a certificate against.
//
// The .example top-level domain is reserved by RFC 2606, so this name can
// never resolve on the public internet and cannot be mistaken for a real
// service. It is never resolved at all: the device connects to a literal
// address and passes this name to the TLS layer as the value to verify.
const ServiceName = "ota.course.example"

// MismatchName is the name on the deliberately wrong certificate. It is
// issued by the trusted authority, so the only thing wrong with it is the
// name, which is what the bypass test needs to isolate.
const MismatchName = "ota-not-this-one.course.example"

// Lifetime is deliberately long.
//
// The Reference product is built without CONFIG_MBEDTLS_HAVE_TIME_DATE, so it
// parses notBefore and notAfter and never compares them. Host tools do compare
// them. A short lifetime would therefore break curl and the fixtures while the
// device carried on happily, which is a confusing failure with no lesson
// attached at Tier 2. Renewal is Tier 8.
const Lifetime = 10 * 365 * 24 * time.Hour

// Material names every file in the generated set.
type Material struct {
	Dir string
}

// Names of the generated files. The names state their role, because a Learner
// is expected to read this directory rather than take it on trust.
const (
	CourseCACert    = "course-ca.crt.pem"
	CourseCAKey     = "course-ca.key.pem"
	CourseCADER     = "course-ca.der"
	ServiceCert     = "service.crt.pem"
	ServiceKey      = "service.key.pem"
	UntrustedCACert = "untrusted-ca.crt.pem"
	UntrustedCAKey  = "untrusted-ca.key.pem"
	UntrustedCert   = "untrusted-service.crt.pem"
	UntrustedKey    = "untrusted-service.key.pem"
	WrongNameCert   = "wrong-name.crt.pem"
	WrongNameKey    = "wrong-name.key.pem"
)

// GeneratedFiles lists every file Generate writes, so callers can check the
// set without knowing how it is built.
func GeneratedFiles() []string {
	return []string{
		CourseCACert, CourseCAKey, CourseCADER,
		ServiceCert, ServiceKey,
		UntrustedCACert, UntrustedCAKey,
		UntrustedCert, UntrustedKey,
		WrongNameCert, WrongNameKey,
	}
}

// Exists reports whether a Course certificate authority is already present.
//
// Setup refuses to replace one silently. The trust anchor is compiled into the
// firmware image, so replacing the authority leaves every flashed board
// trusting material that no longer exists, and the raw symptom is a handshake
// failure with no obvious cause.
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, CourseCACert))
	return err == nil
}

// Generate writes the whole set: the Course certificate authority, the Service
// certificate it signs, and the two certificates the Tier 2 bypass tests need.
func Generate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	courseCA, courseCAKey, err := newAuthority("Learning Cyber Security Course CA")
	if err != nil {
		return err
	}
	untrustedCA, untrustedCAKey, err := newAuthority("Learning Cyber Security Untrusted CA")
	if err != nil {
		return err
	}

	// The real service certificate. It carries a dNSName SAN and deliberately
	// no iPAddress SAN, so a tool that connects by address without stating the
	// name fails. That failure is the mistake Tier 2 is about.
	service, serviceKey, err := newLeaf(ServiceName, courseCA, courseCAKey)
	if err != nil {
		return err
	}
	// Correctly formed, correct name, issued by an authority the device does
	// not trust. Isolates chain validation.
	untrusted, untrustedKey, err := newLeaf(ServiceName, untrustedCA, untrustedCAKey)
	if err != nil {
		return err
	}
	// Issued by the trusted authority, wrong name. Isolates name validation.
	wrongName, wrongNameKey, err := newLeaf(MismatchName, courseCA, courseCAKey)
	if err != nil {
		return err
	}

	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{CourseCACert, certPEM(courseCA), 0o600},
		{CourseCAKey, keyPEM(courseCAKey), 0o600},
		{CourseCADER, courseCA, 0o600},
		{ServiceCert, certPEM(service), 0o600},
		{ServiceKey, keyPEM(serviceKey), 0o600},
		{UntrustedCACert, certPEM(untrustedCA), 0o600},
		{UntrustedCAKey, keyPEM(untrustedCAKey), 0o600},
		{UntrustedCert, certPEM(untrusted), 0o600},
		{UntrustedKey, keyPEM(untrustedKey), 0o600},
		{WrongNameCert, certPEM(wrongName), 0o600},
		{WrongNameKey, keyPEM(wrongNameKey), 0o600},
	}
	for _, file := range files {
		if file.data == nil {
			return fmt.Errorf("failed to encode %s", file.name)
		}
		if err := os.WriteFile(filepath.Join(dir, file.name), file.data, file.mode); err != nil {
			return err
		}
	}
	return nil
}

// newAuthority returns a self-signed CA certificate in DER form and its key.
//
// One root signs the service certificate directly. There is no intermediate,
// because Tier 2 already introduces four new ideas and key hierarchy is Tier
// 3's subject, where it carries real weight.
func newAuthority(commonName string) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Learning Cyber Security course, synthetic"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(Lifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

// newLeaf issues a server certificate for one name.
func newLeaf(name string, caDER []byte, caKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error) {
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name, Organization: []string{"Learning Cyber Security course, synthetic"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(Lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		return nil, errors.New("generated a zero certificate serial")
	}
	return serial, nil
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// Describe returns a human-readable account of one certificate file, for the
// command that shows a Learner what the service is presenting. It reports what
// the certificate claims, not whether anything trusts it.
func Describe(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("%s is not PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	names := "none"
	if len(cert.DNSNames) > 0 {
		names = fmt.Sprintf("%v", cert.DNSNames)
	}
	addresses := "none"
	if len(cert.IPAddresses) > 0 {
		addresses = fmt.Sprintf("%v", cert.IPAddresses)
	}
	return fmt.Sprintf(""+
		"  Subject:      %s\n"+
		"  Issuer:       %s\n"+
		"  DNS names:    %s\n"+
		"  IP addresses: %s\n"+
		"  Valid from:   %s\n"+
		"  Valid until:  %s\n"+
		"  Key:          %s\n"+
		"  Fingerprint:  %s\n",
		cert.Subject.CommonName, cert.Issuer.CommonName, names, addresses,
		cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339),
		cert.PublicKeyAlgorithm, Fingerprint(cert.Raw)), nil
}

// Fingerprint is the value the Reference product prints at boot for its own
// trust anchor, so a stale anchor diagnoses itself instead of looking like a
// broken network.
func Fingerprint(der []byte) string {
	return fingerprint(der)
}

// AnchorFingerprint returns the fingerprint of the Course certificate
// authority in a directory.
func AnchorFingerprint(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, CourseCADER))
	if err != nil {
		return "", err
	}
	return fingerprint(data), nil
}

// fingerprint is the first eight bytes of the SHA-256 of the DER, formatted
// the way the course formats the Course environment marker fingerprint. It is
// short enough to compare by eye across a serial console and a terminal, which
// is the only comparison it is ever used for.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}
