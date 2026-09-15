// Tier 6 section 11 bypass runners.
//
// #115 settled seven rows, E-6-01 to E-6-07. Five of them are refusals the
// provisioning station makes on the host, and the station controls that make
// them already live in enroll() and registerShared(). What was missing was a
// way to trigger each one reproducibly, so a Learner sees the refusal rather
// than reads that it would happen. These runners craft the request the station
// is meant to refuse and show the refusal it makes.
//
// Each runner is self-contained: it mints whatever credential it needs and uses
// throwaway beacon-bypass-* identifiers, so the outcome does not depend on any
// earlier record state. A refused attempt is written to the append-only record
// like any other, which is the honest behaviour: the manufacturing record shows
// what was tried, not only what succeeded.
//
// E-6-04 (export refused on the device) and E-6-05 (the key read back out of a
// flash dump) are not here: they are the two rows that need the board, and they
// run through ./course provision export and ./course device dump.

package courseapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// ecdsaWithSHA256 is the signature algorithm every request in this course uses.
var ecdsaWithSHA256OID = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

// hostDevice is a device that exists only on the host. It does what the board's
// firmware does for these bypasses: hold a P-256 key and build a certification
// request carrying a Bootstrap credential inside the signed structure. The
// station cannot tell it from a real one, which is the point of E-6-01 and
// E-6-02: neither is a board bug, both are the station accepting or refusing a
// request on its own record.
type hostDevice struct {
	key *ecdsa.PrivateKey
}

func newHostDevice() (*hostDevice, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &hostDevice{key: key}, nil
}

func (d *hostDevice) request(deviceID, credential string) ([]byte, error) {
	value, err := MarshalCredentialExtension(credential)
	if err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: deviceID},
		ExtraExtensions: []pkix.Extension{{
			Id:    CredentialExtensionOID(),
			Value: value,
		}},
	}
	return x509.CreateCertificateRequest(rand.Reader, template, d.key)
}

func (a *app) provisionBypass(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ./course provision bypass e-6-01|e-6-02|e-6-03|e-6-06|e-6-07")
	}
	switch strings.ToLower(args[0]) {
	case "e-6-01":
		return a.bypassReplayConsumed()
	case "e-6-02":
		return a.bypassIdentifierReuse()
	case "e-6-03":
		return a.bypassBadProofOfPossession()
	case "e-6-06":
		return a.bypassKeySeparation()
	case "e-6-07":
		return a.bypassClonedSharedCredential()
	default:
		return fmt.Errorf("unknown bypass %q; the host-witnessed rows are e-6-01, e-6-02, e-6-03, e-6-06 and e-6-07", args[0])
	}
}

func (a *app) enrollHost(deviceID, credential string, csr []byte) (enrollmentOutcome, error) {
	return a.enroll(enrollmentRequest{
		DeviceID:         deviceID,
		HardwareRevision: strconv.Itoa(tier04HardwareRevision),
		CSRDer:           csr,
	}, credential)
}

// reportRefusal prints a station refusal and fails if the station did not
// refuse, or refused at a different check than the row expects. A bypass that
// refuses for the wrong reason has not tested what it claims to.
func (a *app) reportRefusal(id string, outcome enrollmentOutcome, wantCheck string) error {
	if outcome.Issued {
		return fmt.Errorf("%s did not refuse: the station issued a certificate", id)
	}
	fmt.Fprintf(a.out, "  refused at check %s\n", outcome.Check)
	fmt.Fprintf(a.out, "  %s\n", outcome.Reason)
	if outcome.Check != wantCheck {
		return fmt.Errorf("%s refused at %q, expected %q", id, outcome.Check, wantCheck)
	}
	fmt.Fprintf(a.out, "\nResult: %s refused at %s, as the tier requires\n", id, wantCheck)
	return nil
}

// E-6-01. A consumed Bootstrap credential presented again.
func (a *app) bypassReplayConsumed() error {
	const device = "beacon-bypass-e6-01"
	fmt.Fprintln(a.out, "E-6-01: replay a consumed Bootstrap credential")

	credential, _, err := a.mintCredential(device)
	if err != nil {
		return err
	}
	dev, err := newHostDevice()
	if err != nil {
		return err
	}
	csr, err := dev.request(device, credential)
	if err != nil {
		return err
	}
	first, err := a.enrollHost(device, credential, csr)
	if err != nil {
		return err
	}
	if !first.Issued {
		return fmt.Errorf("the setup enrollment was refused at %s: %s", first.Check, first.Reason)
	}
	fmt.Fprintf(a.out, "  the credential was consumed once, certificate %s\n", first.CertSerial)
	fmt.Fprintln(a.out, "  now the same credential is presented a second time")

	replay, err := dev.request(device, credential)
	if err != nil {
		return err
	}
	outcome, err := a.enrollHost(device, credential, replay)
	if err != nil {
		return err
	}
	return a.reportRefusal("E-6-01", outcome, "credential-unconsumed")
}

// E-6-02. A second device under an identifier that already holds a certificate.
func (a *app) bypassIdentifierReuse() error {
	const device = "beacon-bypass-e6-02"
	fmt.Fprintln(a.out, "E-6-02: enroll a second device under an identifier that already holds a certificate")

	first, _, err := a.mintCredential(device)
	if err != nil {
		return err
	}
	dev1, err := newHostDevice()
	if err != nil {
		return err
	}
	csr1, err := dev1.request(device, first)
	if err != nil {
		return err
	}
	issued, err := a.enrollHost(device, first, csr1)
	if err != nil {
		return err
	}
	if !issued.Issued {
		return fmt.Errorf("the setup enrollment was refused at %s: %s", issued.Check, issued.Reason)
	}
	fmt.Fprintf(a.out, "  %s now holds certificate %s\n", device, issued.CertSerial)
	fmt.Fprintln(a.out, "  a second device, with its own key and a fresh credential, claims the same identifier")

	second, _, err := a.mintCredential(device)
	if err != nil {
		return err
	}
	dev2, err := newHostDevice()
	if err != nil {
		return err
	}
	csr2, err := dev2.request(device, second)
	if err != nil {
		return err
	}
	outcome, err := a.enrollHost(device, second, csr2)
	if err != nil {
		return err
	}
	return a.reportRefusal("E-6-02", outcome, "identifier-unused")
}

// E-6-03. A certification request for a public key whose private half is not
// held. The request presents one key and is signed by another, so the proof of
// possession that ties the two together does not verify.
func (a *app) bypassBadProofOfPossession() error {
	const device = "beacon-bypass-e6-03"
	fmt.Fprintln(a.out, "E-6-03: submit a request for a public key whose private half you do not hold")

	credential, _, err := a.mintCredential(device)
	if err != nil {
		return err
	}
	csr, err := badProofOfPossessionRequest(device, credential)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, "  the request presents one key and is signed by another")
	outcome, err := a.enrollHost(device, credential, csr)
	if err != nil {
		return err
	}
	return a.reportRefusal("E-6-03", outcome, "proof-of-possession")
}

// badProofOfPossessionRequest builds a certification request that presents the
// public key `wanted` but is signed by `held`, a different key. CheckSignature
// verifies the signature against the presented key, so it fails: this is the
// request an attacker who has someone else's public key but not their private
// key could produce, and no more.
func badProofOfPossessionRequest(deviceID, credential string) ([]byte, error) {
	held, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	wanted, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	value, err := MarshalCredentialExtension(credential)
	if err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: deviceID},
		ExtraExtensions: []pkix.Extension{{
			Id:    CredentialExtensionOID(),
			Value: value,
		}},
	}
	// A structurally valid request presenting `wanted`.
	wantedDER, err := x509.CreateCertificateRequest(rand.Reader, template, wanted)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificateRequest(wantedDER)
	if err != nil {
		return nil, err
	}
	// Re-sign that request's body with `held`, a key we do hold but is not the
	// one presented, and reassemble. The signature no longer belongs to the
	// presented key.
	digest := sha256.Sum256(parsed.RawTBSCertificateRequest)
	signature, err := ecdsa.SignASN1(rand.Reader, held, digest[:])
	if err != nil {
		return nil, err
	}
	var reassembled struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	reassembled.TBS = asn1.RawValue{FullBytes: parsed.RawTBSCertificateRequest}
	reassembled.Algorithm = pkix.AlgorithmIdentifier{Algorithm: ecdsaWithSHA256OID}
	reassembled.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	return asn1.Marshal(reassembled)
}

// requestWithoutCredential builds a certification request that proves possession
// of a key but carries no Bootstrap credential. It is what an attacker who holds
// a key with no place in the manufacturing model can produce: the Release
// signing key (E-6-06) or the cloned shared credential (E-6-07). The hardened
// factory station enrolls only a device that carries a Bootstrap credential, so
// it refuses this at credential-carried whatever key signed it.
func requestWithoutCredential(deviceID string, key *ecdsa.PrivateKey) ([]byte, error) {
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: deviceID}}
	return x509.CreateCertificateRequest(rand.Reader, template, key)
}

func loadECPrivateKeyPEM(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not PEM", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an ECDSA key", path)
	}
	return key, nil
}

func loadECPublicKeyPEM(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not PEM", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an ECDSA public key", path)
	}
	return key, nil
}

// E-6-06. A key used outside its role. T3-W-11 requires the device identity key
// to be separate from every firmware signing and boot key, and this shows both
// halves: the identity key cannot sign firmware the release trust anchor
// accepts, and the Release signing key cannot enroll.
func (a *app) bypassKeySeparation() error {
	fmt.Fprintln(a.out, "E-6-06: use a key outside its role (T3-W-11 key separation)")

	releasePub, err := loadECPublicKeyPEM(a.publicKeyPath())
	if err != nil {
		return fmt.Errorf("no Release public key; run ./course keys create release first: %w", err)
	}
	releaseKey, err := loadECPrivateKeyPEM(a.signingKeyPath("release"))
	if err != nil {
		return fmt.Errorf("no Release signing key; run ./course keys create release first: %w", err)
	}

	// Half one: the device identity key signs firmware.
	identity, err := newHostDevice()
	if err != nil {
		return err
	}
	body := []byte("a firmware manifest the device tries to sign with its own identity key")
	digest := sha256.Sum256(body)
	identitySig, err := ecdsa.SignASN1(rand.Reader, identity.key, digest[:])
	if err != nil {
		return err
	}
	releaseSig, err := ecdsa.SignASN1(rand.Reader, releaseKey, digest[:])
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, "  half one: the device identity key signs a firmware manifest")
	if manifestVerifies(releasePub, body, identitySig) {
		return errors.New("E-6-06: a manifest signed by the device identity key verified against the release key")
	}
	if !manifestVerifies(releasePub, body, releaseSig) {
		return errors.New("E-6-06: the release key's own signature did not verify, so the comparison proves nothing")
	}
	fmt.Fprintln(a.out, "  the release trust anchor verifies the release key's signature and refuses the")
	fmt.Fprintln(a.out, "  identity key's over the same bytes. A device cannot sign firmware for the fleet.")

	// Half two: the Release signing key enrolls.
	fmt.Fprintln(a.out, "  half two: the Release signing key is offered to the station as a device")
	csr, err := requestWithoutCredential("beacon-bypass-e6-06", releaseKey)
	if err != nil {
		return err
	}
	outcome, err := a.enrollHost("beacon-bypass-e6-06", "", csr)
	if err != nil {
		return err
	}
	return a.reportRefusal("E-6-06", outcome, "credential-carried")
}

// E-6-07. The cloned shared credential presented to the hardened station. The
// clone holds the fleet key and can prove it, but the factory station enrolls
// only a device carrying a Bootstrap credential, which the shared model never
// issued. Possession of the fleet key buys nothing here: that is what hardening
// changed.
func (a *app) bypassClonedSharedCredential() error {
	fmt.Fprintln(a.out, "E-6-07: present the cloned shared credential to the hardened station")

	if !coursepki.SharedIdentityExists(a.pkiDir()) {
		return errors.New("no shared identity to clone; run ./course keys create shared-identity first")
	}
	_, key, err := coursepki.LoadSharedIdentity(a.pkiDir())
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, "  the clone holds the fleet key and proves possession of it")
	fmt.Fprintln(a.out, "  the factory station enrolls a per-device Bootstrap credential, not a fleet key")
	csr, err := requestWithoutCredential("beacon-bypass-e6-07", key)
	if err != nil {
		return err
	}
	outcome, err := a.enrollHost("beacon-bypass-e6-07", "", csr)
	if err != nil {
		return err
	}
	return a.reportRefusal("E-6-07", outcome, "credential-carried")
}
