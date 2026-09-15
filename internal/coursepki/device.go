package coursepki

// The manufacturer device certificate authority.
//
// Section 8 of docs/course-specification.md requires three distinct trust
// relationships, and this is the first of them: an authority that signs Factory
// identities and is trusted by the enrollment service. It is deliberately not
// the Course certificate authority in pki.go, which signs the OTA service's own
// TLS certificate and is trusted by devices for a completely different purpose.
//
// Keeping them apart is the point. A course that signed device identities with
// the same authority that signs the server would teach that a certificate
// authority is a thing you have one of, and section 8 spends a whole subsection
// saying otherwise.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Device authority file names, following the same naming rule as the rest of
// this package: the name states the role, because a Learner is expected to read
// this directory rather than take it on trust.
const (
	DeviceCACert = "device-ca.crt.pem"
	DeviceCAKey  = "device-ca.key.pem"
	DeviceCADER  = "device-ca.der"
)

// DeviceCAName is the subject of the manufacturer device authority.
//
// It says "Device CA" rather than repeating the course name alone, so that a
// Learner reading a certificate chain can tell at a glance which of the two
// authorities signed what.
const DeviceCAName = "Learning Cyber Security Manufacturer Device CA"

// DeviceCAFiles lists every file GenerateDeviceCA writes.
func DeviceCAFiles() []string {
	return []string{DeviceCACert, DeviceCAKey, DeviceCADER}
}

// DeviceCAExists reports whether the manufacturer device authority is present.
func DeviceCAExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, DeviceCACert))
	return err == nil
}

// GenerateDeviceCA writes the manufacturer device authority.
//
// It refuses to replace an existing one. Every Factory certificate already
// issued chains to it, so replacing it silently would strand every provisioned
// board with an identity nothing can verify, and the symptom would be a
// verification failure a long way from the cause.
func GenerateDeviceCA(dir string) error {
	if DeviceCAExists(dir) {
		return errors.New("a manufacturer device CA already exists")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	der, key, err := newAuthority(DeviceCAName)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, DeviceCACert), certPEM(der), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, DeviceCAKey), keyPEM(key), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, DeviceCADER), der, 0o600)
}

// LoadDeviceCA reads the authority back for signing.
func LoadDeviceCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBytes, err := os.ReadFile(filepath.Join(dir, DeviceCACert))
	if err != nil {
		return nil, nil, fmt.Errorf("no manufacturer device CA: %w", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("device CA certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := os.ReadFile(filepath.Join(dir, DeviceCAKey))
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, nil, errors.New("device CA key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// FactoryLifetime is how long a Factory certificate is valid.
//
// Section 8 calls the Factory identity long lived but explicitly not permanent,
// and the course's support period is five years, so this is deliberately longer
// than that and deliberately finite. A certificate with no expiry would teach
// that an identity can be issued and then forgotten about.
const FactoryLifetime = 10 * 365 * 24 * time.Hour

// IssueFactoryCertificate signs a Factory identity for one device.
//
// The public key comes from the device's own certification request. Nothing in
// this function has ever seen the private half, which is the property section
// 11 states as a failure criterion if it is broken: the backend must not store
// the private key.
func IssueFactoryCertificate(dir, deviceID string, publicKey any) ([]byte, error) {
	ca, caKey, err := LoadDeviceCA(dir)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subjectFor(deviceID),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(FactoryLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Client authentication only. A Factory identity is never a server, and
		// section 8 keeps it out of the ordinary firmware download path
		// entirely, so nothing here grants it more than it needs.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
}

// subjectFor puts the device identifier in the certificate subject.
//
// The identifier is assigned by the station and lives here, so the device can
// read its own identifier back out of its certificate rather than holding it
// separately. One source of truth, settled on issue #114.
func subjectFor(deviceID string) pkix.Name {
	return pkix.Name{
		CommonName:   deviceID,
		Organization: []string{"Learning Cyber Security course, synthetic"},
	}
}
