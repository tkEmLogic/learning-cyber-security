package coursepki

// The operational device certificate authority.
//
// This is the fourth authority in the course and the second that signs device
// identities. It exists because the Factory identity and the Operational
// identity answer different questions: the first says which board this is, the
// second says which board this is and who owns it today. Signing both with one
// authority would make the issuer useless as a role, and the issuer is exactly
// what the OTA service reads a role out of.
//
// It is self-signed, like the other three. An intermediate under the
// manufacturer authority would say the manufacturer stands behind every
// ownership decision a customer makes, which is the opposite of what a device
// handover means.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Operational authority file names, following the same naming rule as the rest
// of this package: the name states the role.
const (
	OperationalCACert = "operational-ca.crt.pem"
	OperationalCAKey  = "operational-ca.key.pem"
	OperationalCADER  = "operational-ca.der"
)

// OperationalCAName is the subject of the operational device authority.
//
// It says "Operational Device CA" against the manufacturer's "Manufacturer
// Device CA", so a Learner reading a chain can tell which of the two device
// authorities signed what without reading a serial number.
const OperationalCAName = "Learning Cyber Security Operational Device CA"

// OperationalLifetime is how long an Operational certificate is valid.
//
// Ninety days against the Factory identity's ten years, and the contrast is
// the teaching. A Factory identity is issued once on a production line and has
// to outlive the product's support period; an Operational identity says who
// owns the device today, which is a fact that expires. It is beside
// FactoryLifetime so both numbers are readable in one screen.
//
// Ninety days is enforceable here in a way a short Tier 2 lifetime would not
// be, because the device cannot evaluate a validity window at all: the OTA
// service's certificate-active check is the only enforcer in the course. There
// is no renewal. That is Tier 8, and an expired Operational certificate is
// Tier 8's opening argument.
const OperationalLifetime = 90 * 24 * time.Hour

// OperationalCAFiles lists every file GenerateOperationalCA writes.
func OperationalCAFiles() []string {
	return []string{OperationalCACert, OperationalCAKey, OperationalCADER}
}

// OperationalCAExists reports whether the operational device authority is present.
func OperationalCAExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, OperationalCACert))
	return err == nil
}

// GenerateOperationalCA writes the operational device authority.
//
// It refuses to replace an existing one, for the same reason GenerateDeviceCA
// does: every Operational certificate already issued chains to it, and the
// OTA service verifies client certificates against it. Replacing it silently
// would lock every claimed device out of its own update service, and the
// symptom would appear a long way from the cause.
func GenerateOperationalCA(dir string) error {
	if OperationalCAExists(dir) {
		return errors.New("an operational device CA already exists")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	der, key, err := newAuthority(OperationalCAName)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, OperationalCACert), certPEM(der), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, OperationalCAKey), keyPEM(key), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, OperationalCADER), der, 0o600)
}

// LoadOperationalCA reads the authority back for signing.
func LoadOperationalCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBytes, err := os.ReadFile(filepath.Join(dir, OperationalCACert))
	if err != nil {
		return nil, nil, fmt.Errorf("no operational device CA: %w", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("operational CA certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := os.ReadFile(filepath.Join(dir, OperationalCAKey))
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, nil, errors.New("operational CA key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// IssueOperationalCertificate signs an Operational identity for one device
// under one owner.
//
// An Operational certificate is a Factory certificate with a different issuer
// and the owner slug in the subject organizational unit. Nothing marks it
// "operational": the issuer is the role, and a second signal is a fact that
// can disagree with the chain.
//
// The public key comes from the device's own certification request, and
// nothing here has ever seen the private half.
//
// The OTA service does not call this. It is handed a directory and signs from
// it itself, because nothing under services/ depends on internal/. This is the
// host side's copy of the same leaf, for the attack fixture and for Tier 8.
func IssueOperationalCertificate(dir, deviceID, ownerSlug string, publicKey any) ([]byte, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	return IssueOperationalCertificateAs(dir, deviceID, ownerSlug, publicKey,
		serial, time.Now().UTC().Add(OperationalLifetime))
}

// IssueOperationalCertificateAs is the same leaf with the serial and the
// expiry chosen by the caller.
//
// It exists for the attack fixture, and it is deliberately the smallest
// widening that the fixture's rows need: a certificate carrying a serial the
// service has a record of, or one whose validity window has already closed.
// Both are certificates a leaked CA key can make, and the tier's argument is
// that a CA signature is not an authorization.
//
// What it may sign is bounded by docs/fixture-safety-contract.md: an
// Operational leaf for a device identifier this Course environment holds a
// record for, and nothing else. It cannot make an authority, because it sets
// no basic constraints and no certificate-sign key usage.
func IssueOperationalCertificateAs(dir, deviceID, ownerSlug string, publicKey any,
	serial *big.Int, notAfter time.Time) ([]byte, error) {
	ca, caKey, err := LoadOperationalCA(dir)
	if err != nil {
		return nil, err
	}
	if serial == nil {
		return nil, errors.New("an operational certificate needs a serial number")
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      operationalSubject(deviceID, ownerSlug),
		NotBefore:    time.Now().UTC().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Client authentication only, as the Factory identity. An Operational
		// identity is never a server, and it carries no SAN for the same
		// reason: a SAN answers "which server am I talking to".
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
}

// operationalSubject is subjectFor with the owner slug added.
//
// The organizational unit is the ownership context: what the certificate says
// about who owns this device. What the manufacturing record says is a separate
// fact, and ownership-context is the check that the two agree.
func operationalSubject(deviceID, ownerSlug string) pkix.Name {
	name := subjectFor(deviceID)
	if ownerSlug != "" {
		name.OrganizationalUnit = []string{ownerSlug}
	}
	return name
}
