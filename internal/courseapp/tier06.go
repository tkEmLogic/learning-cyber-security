package courseapp

// Tier 6 replaces one shared identity with a per-device Factory identity. This
// file holds the host half: the Bootstrap credential store, the provisioning
// station, and the manufacturing record.
//
// The shape is settled on issues #105, #112, #113 and #114.
//
// Two roles, two commands, on purpose. `credential new` plays the manufacturer's
// IT department: it mints a credential and keeps only a verifier. `enroll` plays
// the station on the line: it hands the credential to the device, checks what
// comes back, and issues a certificate. In a single-station lab the same person
// runs both, and the module says so rather than pretending the separation is
// stronger than it is. What Tier 6 actually demonstrates is the one-use
// property, and that is real however the credential was delivered.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"encoding/asn1"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// Lifecycle states from section 8.
//
// All six are written down even though Tier 6 can only ever reach the first.
// An enum with one value teaches that lifecycle state is a boolean, and section
// 8 spends a subsection saying it is not. Tier 7 reaches claimed, Tier 8 the
// rest.
const (
	LifecycleManufactured   = "manufactured"
	LifecycleClaimed        = "claimed"
	LifecycleActive         = "active"
	LifecycleTransferred    = "transferred"
	LifecycleRevoked        = "revoked"
	LifecycleDecommissioned = "decommissioned"
)

// Record kinds in the append-only log.
const (
	recordCredentialIssued = "credential_issued"
	recordEnrollment       = "enrollment"
	recordDelivery         = "delivery_confirmed"
	recordRemanufacture    = "remanufacture"
	recordFixtureReset     = "fixture_reset"
)

// provisionRecord is one line of the manufacturing record.
//
// The store is append only, so state is derived by replaying the log rather
// than by editing a row. That is what makes "atomically marks the Bootstrap
// credential consumed" achievable in a command rather than a daemon: one
// O_APPEND write of one line is the whole state change, and there is no window
// in which a credential is spent but the certificate is unrecorded.
//
// It never contains private key material. Section 11 states that as a failure
// criterion for this tier, and writeRecord enforces it rather than trusting
// callers.
type provisionRecord struct {
	Kind      string `json:"kind"`
	Recorded  string `json:"recorded_at"`
	DeviceID  string `json:"device_id"`
	Station   string `json:"station,omitempty"`
	Lifecycle string `json:"lifecycle_state,omitempty"`

	// Hardware revision, from section 8's field list.
	HardwareRevision string `json:"hardware_revision,omitempty"`

	// Bootstrap credential state, stored as a verifier rather than plaintext.
	CredentialID       string `json:"credential_id,omitempty"`
	CredentialVerifier string `json:"credential_verifier,omitempty"`
	CredentialExpires  string `json:"credential_expires,omitempty"`
	ConsumedCredential string `json:"consumed_credential,omitempty"`

	// Factory certificate, public material only.
	CertSerial      string `json:"certificate_serial,omitempty"`
	CertFingerprint string `json:"certificate_fingerprint,omitempty"`
	CertPublicKey   string `json:"certificate_public_key,omitempty"`

	Result string `json:"result,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// credentialLifetime is how long a Bootstrap credential may be used.
//
// Section 8 calls for a short validity period. Short here means long enough to
// walk to the bench and plug in a board, and nothing like long enough to be a
// standing key.
const credentialLifetime = 24 * time.Hour

func (a *app) provisionDir() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "provisioning")
}

func (a *app) provisionRecordPath() string {
	return filepath.Join(a.provisionDir(), "records.jsonl")
}

func (a *app) deviceCADir() string {
	return filepath.Join(a.root, a.manifest.Paths.Secrets, "pki")
}

func (a *app) provision(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ./course provision credential|enroll|register|extract|record")
	}
	switch args[0] {
	case "credential":
		return a.provisionCredential(args[1:])
	case "enroll":
		return a.provisionEnroll(args[1:])
	case "register":
		return a.provisionRegister(args[1:])
	case "extract":
		return a.provisionExtract(args[1:])
	case "record":
		return a.provisionShowRecord(args[1:])
	default:
		return fmt.Errorf("unknown provision command %q; use credential, enroll, register, extract or record", args[0])
	}
}

func (a *app) provisionCredential(args []string) error {
	if len(args) < 2 || args[0] != "new" {
		return errors.New("usage: ./course provision credential new --device <id>")
	}
	deviceID, err := flagValue(args[1:], "--device")
	if err != nil {
		return err
	}
	return a.issueCredential(deviceID)
}

// issueCredential mints one Bootstrap credential and keeps only its verifier.
//
// Section 8: unique, high entropy, limited to one device, the Factory
// enrollment purpose, a short validity period, and one successful use. The
// first four are properties of this record; the fifth is enforced at enrollment
// by replaying the log.
func (a *app) issueCredential(deviceID string) error {
	if err := validateDeviceID(deviceID); err != nil {
		return err
	}
	if err := os.MkdirAll(a.provisionDir(), 0o700); err != nil {
		return err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	credential := hex.EncodeToString(secret)
	credentialID, err := randomID()
	if err != nil {
		return err
	}
	expires := time.Now().UTC().Add(credentialLifetime)

	record := provisionRecord{
		Kind:               recordCredentialIssued,
		DeviceID:           deviceID,
		CredentialID:       credentialID,
		CredentialVerifier: verifierFor(credential),
		CredentialExpires:  expires.Format(time.RFC3339),
		Lifecycle:          LifecycleManufactured,
		Result:             "issued",
	}
	if err := a.writeRecord(record); err != nil {
		return err
	}

	fmt.Fprintln(a.out, "Minting one Bootstrap credential. This command is the manufacturer's")
	fmt.Fprintln(a.out, "IT department, not the provisioning station: it keeps only a verifier.")
	fmt.Fprintf(a.out, "  device:      %s\n", deviceID)
	fmt.Fprintf(a.out, "  credential:  %s\n", credentialID)
	fmt.Fprintf(a.out, "  verifier:    %s\n", record.CredentialVerifier)
	fmt.Fprintf(a.out, "  expires:     %s\n", record.CredentialExpires)
	fmt.Fprintf(a.out, "  recorded in: %s\n", a.relative(a.provisionRecordPath()))
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "The credential itself is printed once and never stored. If you lose it,")
	fmt.Fprintln(a.out, "mint another: that is a remanufacturing act and it appends a new record.")
	fmt.Fprintf(a.out, "\n  %s\n\n", credential)
	fmt.Fprintf(a.out, "Result: one credential for %s, valid until %s\n", deviceID, record.CredentialExpires)
	return nil
}

// verifierFor is what the store keeps instead of the credential.
//
// A hash, not the credential and not an HMAC key. Section 8 requires the
// service to store only the verifier needed to check it, and a symmetric
// construction would put a live secret in the store: stealing it would then let
// an attacker enroll every device whose credential is still unconsumed. Issue
// #112 records why this beat the HMAC alternative, and what was given up.
func verifierFor(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// validateDeviceID keeps a Learner-supplied identifier from becoming a path.
//
// The identifier reaches a file name and a certificate subject, so it is held
// to the shape the course generates: the beacon prefix and a lower-case hex MAC.
func validateDeviceID(id string) error {
	if id == "" {
		return errors.New("a device identifier is required")
	}
	if len(id) > 64 {
		return errors.New("device identifier is too long")
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return fmt.Errorf("device identifier %q may hold only lower-case letters, digits and hyphens", id)
		}
	}
	return nil
}

func flagValue(args []string, name string) (string, error) {
	for i, arg := range args {
		if arg == name && i+1 < len(args) {
			return args[i+1], nil
		}
		if strings.HasPrefix(arg, name+"=") {
			return strings.TrimPrefix(arg, name+"="), nil
		}
	}
	return "", fmt.Errorf("missing %s", name)
}

// writeRecord appends one line, and refuses to write private key material.
//
// The refusal is here rather than in a review checklist because section 11
// makes "the backend stores the private key" a stated failure criterion for
// this tier, and a criterion with no enforcement point is a wish.
func (a *app) writeRecord(record provisionRecord) error {
	record.Recorded = time.Now().UTC().Format(time.RFC3339Nano)
	if record.Station == "" {
		record.Station = "course-provisioning-station"
	}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if looksLikePrivateKey(string(line)) {
		return errors.New("refusing to write a manufacturing record that contains private key material")
	}
	if err := os.MkdirAll(a.provisionDir(), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(a.provisionRecordPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(line, '\n'))
	return err
}

func looksLikePrivateKey(s string) bool {
	for _, marker := range []string{"PRIVATE KEY", "BEGIN EC PARAMETERS", "privateKey"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func (a *app) readRecords() ([]provisionRecord, error) {
	raw, err := os.ReadFile(a.provisionRecordPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []provisionRecord
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record provisionRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("manufacturing record is corrupt: %w", err)
		}
		records = append(records, record)
	}
	return records, nil
}

// credentialState replays the log to answer the only two questions enrollment
// asks: is there a live credential matching what the device sent, and does this
// identifier already hold a Factory certificate.
type credentialState struct {
	matched   *provisionRecord
	consumed  *provisionRecord
	certifier *provisionRecord
}

func (a *app) credentialStateFor(deviceID, credential string) (credentialState, error) {
	records, err := a.readRecords()
	if err != nil {
		return credentialState{}, err
	}
	verifier := verifierFor(credential)
	var state credentialState
	for i := range records {
		record := records[i]
		switch record.Kind {
		case recordCredentialIssued:
			if record.CredentialVerifier == verifier && record.DeviceID == deviceID {
				state.matched = &records[i]
			}
		case recordEnrollment:
			if record.Result != "issued" {
				continue
			}
			if record.DeviceID == deviceID {
				state.certifier = &records[i]
			}
			if state.matched != nil && record.ConsumedCredential == state.matched.CredentialID {
				state.consumed = &records[i]
			}
		}
	}
	// A credential consumed for this device is found on a second pass, because
	// the enrollment that consumed it may be logged before the loop has seen
	// the issuance line it refers to.
	if state.matched != nil && state.consumed == nil {
		for i := range records {
			if records[i].Kind == recordEnrollment &&
				records[i].Result == "issued" &&
				records[i].ConsumedCredential == state.matched.CredentialID {
				state.consumed = &records[i]
				break
			}
		}
	}
	return state, nil
}

// enrollmentRequest is what the device sends over the provisioning shell.
type enrollmentRequest struct {
	DeviceID         string
	HardwareRevision string
	// CSRDer is the device's certification request, carrying the credential in
	// an extension so that it is covered by the request's own self-signature.
	CSRDer []byte
}

// enrollmentOutcome is what the station decided, and why.
type enrollmentOutcome struct {
	Issued          bool
	Check           string
	Reason          string
	CertDER         []byte
	CertFingerprint string
	CertSerial      string
}

// enroll is the station. It is deliberately transport-free so that it can be
// exercised against a fake device before a board exists: a station that can
// only be driven through firmware cannot be debugged when the firmware is also
// new.
func (a *app) enroll(request enrollmentRequest, credential string) (enrollmentOutcome, error) {
	if err := validateDeviceID(request.DeviceID); err != nil {
		return enrollmentOutcome{}, err
	}
	csr, err := x509.ParseCertificateRequest(request.CSRDer)
	if err != nil {
		return enrollmentOutcome{}, fmt.Errorf("certification request will not parse: %w", err)
	}

	// Proof of possession. The request is self-signed with the private key whose
	// public half it carries, so a request for a key the sender does not hold
	// cannot be produced. This is E-6-03.
	if err := csr.CheckSignature(); err != nil {
		outcome := enrollmentOutcome{
			Check:  "proof-of-possession",
			Reason: "the certification request is not signed by the key it presents",
		}
		return outcome, a.recordRefusal(request, outcome)
	}

	// The credential must be inside the signed request, not merely alongside it,
	// or a stolen valid credential could be paired with somebody else's key.
	carried, err := credentialFromCSR(csr)
	if err != nil {
		outcome := enrollmentOutcome{Check: "credential-carried", Reason: err.Error()}
		return outcome, a.recordRefusal(request, outcome)
	}
	if carried != credential {
		outcome := enrollmentOutcome{
			Check:  "credential-binding",
			Reason: "the credential inside the signed request is not the one the station was given",
		}
		return outcome, a.recordRefusal(request, outcome)
	}

	state, err := a.credentialStateFor(request.DeviceID, credential)
	if err != nil {
		return enrollmentOutcome{}, err
	}
	if state.matched == nil {
		outcome := enrollmentOutcome{
			Check:  "credential-known",
			Reason: fmt.Sprintf("no Bootstrap credential was ever issued for %s matching this verifier", request.DeviceID),
		}
		return outcome, a.recordRefusal(request, outcome)
	}
	// Refusal one of two: a consumed credential presented again. E-6-01.
	if state.consumed != nil {
		outcome := enrollmentOutcome{
			Check: "credential-unconsumed",
			Reason: fmt.Sprintf("credential %s was consumed at %s by certificate %s",
				state.matched.CredentialID, state.consumed.Recorded, state.consumed.CertSerial),
		}
		return outcome, a.recordRefusal(request, outcome)
	}
	if expires, perr := time.Parse(time.RFC3339, state.matched.CredentialExpires); perr == nil {
		if time.Now().UTC().After(expires) {
			outcome := enrollmentOutcome{
				Check:  "credential-valid",
				Reason: fmt.Sprintf("credential %s expired at %s", state.matched.CredentialID, state.matched.CredentialExpires),
			}
			return outcome, a.recordRefusal(request, outcome)
		}
	}
	// Refusal two of two: an identifier that already holds a certificate. E-6-02.
	if state.certifier != nil {
		outcome := enrollmentOutcome{
			Check: "identifier-unused",
			Reason: fmt.Sprintf("%s already holds Factory certificate %s, fingerprint %s",
				request.DeviceID, state.certifier.CertSerial, state.certifier.CertFingerprint),
		}
		return outcome, a.recordRefusal(request, outcome)
	}

	der, err := coursepki.IssueFactoryCertificate(a.deviceCADir(), request.DeviceID, csr.PublicKey)
	if err != nil {
		return enrollmentOutcome{}, err
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return enrollmentOutcome{}, err
	}
	fingerprint := certFingerprint(der)

	// One append: the certificate is recorded and the credential is consumed in
	// the same line, before anything is sent to the device. Nothing ever leaves
	// the station that the record does not already contain.
	record := provisionRecord{
		Kind:               recordEnrollment,
		DeviceID:           request.DeviceID,
		HardwareRevision:   request.HardwareRevision,
		Lifecycle:          LifecycleManufactured,
		ConsumedCredential: state.matched.CredentialID,
		CertSerial:         issued.SerialNumber.String(),
		CertFingerprint:    fingerprint,
		CertPublicKey:      publicKeyFingerprint(csr.RawSubjectPublicKeyInfo),
		Result:             "issued",
	}
	if err := a.writeRecord(record); err != nil {
		return enrollmentOutcome{}, err
	}

	return enrollmentOutcome{
		Issued:          true,
		Check:           "issued",
		CertDER:         der,
		CertFingerprint: fingerprint,
		CertSerial:      issued.SerialNumber.String(),
	}, nil
}

func (a *app) recordRefusal(request enrollmentRequest, outcome enrollmentOutcome) error {
	return a.writeRecord(provisionRecord{
		Kind:             recordEnrollment,
		DeviceID:         request.DeviceID,
		HardwareRevision: request.HardwareRevision,
		Result:           "refused",
		Detail:           outcome.Check + ": " + outcome.Reason,
	})
}

func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func publicKeyFingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (a *app) provisionShowRecord(args []string) error {
	records, err := a.readRecords()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Fprintln(a.out, "The manufacturing record is empty. Nothing has been provisioned yet.")
		return nil
	}
	want := ""
	if len(args) > 0 {
		if value, ferr := flagValue(args, "--device"); ferr == nil {
			want = value
		}
	}
	fmt.Fprintf(a.out, "Manufacturing record: %s\n", a.relative(a.provisionRecordPath()))
	fmt.Fprintln(a.out, "It is append only. Nothing below is ever edited or removed, including")
	fmt.Fprintln(a.out, "entries a clone put there.")
	fmt.Fprintln(a.out)
	shown := 0
	for _, record := range records {
		if want != "" && record.DeviceID != want {
			continue
		}
		shown++
		fmt.Fprintf(a.out, "%s  %-18s %s\n", record.Recorded, record.Kind, record.DeviceID)
		switch record.Kind {
		case recordCredentialIssued:
			fmt.Fprintf(a.out, "    credential %s, verifier %s, expires %s\n",
				record.CredentialID, short(record.CredentialVerifier), record.CredentialExpires)
		case recordEnrollment:
			if record.Result == "issued" {
				fmt.Fprintf(a.out, "    issued certificate %s, fingerprint %s\n", record.CertSerial, short(record.CertFingerprint))
				if record.ConsumedCredential == "" {
					// The shared model has no Bootstrap credential to
					// consume, and printing an empty one read as a
					// missing value rather than as the absence this
					// tier is arguing about.
					fmt.Fprintf(a.out, "    no Bootstrap credential was required, lifecycle %s\n", record.Lifecycle)
				} else {
					fmt.Fprintf(a.out, "    consumed credential %s, lifecycle %s\n", record.ConsumedCredential, record.Lifecycle)
				}
			} else {
				fmt.Fprintf(a.out, "    refused: %s\n", record.Detail)
			}
		}
	}
	fmt.Fprintf(a.out, "\nResult: %d record(s)\n", shown)
	return nil
}

func short(fingerprint string) string {
	if len(fingerprint) <= 23 {
		return fingerprint
	}
	return fingerprint[:23] + "..."
}

// courseCredentialOID carries the Bootstrap credential inside the certification
// request.
//
// It is a synthetic identifier under a private enterprise arc that belongs to
// nobody. The course invents it for the same reason Tier 5 invented a custom
// image TLV tag: the value has to live somewhere the signature covers, and no
// standard attribute means what this one means.
//
// Putting it here rather than beside the request is the whole point. A
// credential sent alongside a request can be lifted and paired with somebody
// else's key. A credential inside the CertificationRequestInfo is covered by
// the request's own self-signature, so the credential and the key it authorizes
// cannot be separated. Settled on issue #112.
var courseCredentialOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 6, 1}

// credentialFromCSR reads the credential the device put inside its request.
func credentialFromCSR(csr *x509.CertificateRequest) (string, error) {
	for _, extension := range csr.Extensions {
		if extension.Id.Equal(courseCredentialOID) {
			var value string
			if _, err := asn1.Unmarshal(extension.Value, &value); err != nil {
				return "", errors.New("the credential extension will not decode")
			}
			return value, nil
		}
	}
	for _, extension := range csr.ExtraExtensions {
		if extension.Id.Equal(courseCredentialOID) {
			var value string
			if _, err := asn1.Unmarshal(extension.Value, &value); err != nil {
				return "", errors.New("the credential extension will not decode")
			}
			return value, nil
		}
	}
	return "", errors.New("the certification request carries no Bootstrap credential")
}

// MarshalCredentialExtension builds the extension a device puts in its request.
//
// It lives here rather than in a test so that the firmware's encoder has one
// definition to agree with, and so the fake device used by the station's tests
// is exercising the same bytes the board will send.
func MarshalCredentialExtension(credential string) ([]byte, error) {
	return asn1.Marshal(credential)
}

// CredentialExtensionOID exposes the OID for the same reason.
func CredentialExtensionOID() asn1.ObjectIdentifier {
	return courseCredentialOID
}

// tier06SecurityCounter is the counter Tier 6's releases carry.
//
// It stays at Tier 5's value. Section 6 says a security counter is increased
// only when a release closes a security boundary that must not be reopened,
// and Tier 6 closes none: T0-W-02 moves to reduced rather than closed, because
// the device gains an identity that nothing yet requires it to present.
// Raising it here would also make every Tier 5 release uninstallable, which is
// a cost with nothing bought.
const tier06SecurityCounter = 3

// tier06Variants are the two images Tier 6 publishes from one source tree.
//
// They differ in where the device's identity comes from, which is the whole
// subject of the tier, so the difference a Learner reads is one Kconfig
// conditional rather than a diff between two directories.
//
// There is deliberately no third variant that generates a key when it can and
// uses the shared identity when it cannot.
var tier06Variants = map[string]firmwareVariant{
	"shared": {
		releaseID:       "tier-06-shared-identity",
		label:           "shared",
		beaconState:     "steady",
		version:         "0.6.0-shared-identity",
		imageName:       "tier-06-shared-identity.bin",
		securityCounter: tier06SecurityCounter,
		trialBehaviour:  "healthy",
		identityModel:   "shared",
	},
	"factory": {
		releaseID:       "tier-06-factory-identity",
		label:           "factory",
		beaconState:     "steady",
		version:         "0.6.0-factory-identity",
		imageName:       "tier-06-factory-identity.bin",
		securityCounter: tier06SecurityCounter,
		trialBehaviour:  "healthy",
		identityModel:   "factory",
	},
}

// registerShared is the station before hardening.
//
// It accepts anything that can prove possession of the fleet's one private key
// and appends a manufacturing record for it. There is no Bootstrap credential
// to check, because in the shared model there is none: possession of the
// compiled-in key is simultaneously the identity and the authorization to be
// registered. That is what section 11 means by a reusable default credential
// remaining active.
//
// The proof is real. The station issues a nonce, the device signs it with the
// key its certificate carries, and the station verifies that signature against
// that certificate. Nothing here is weaker than the hardened path: it is the
// same proof of possession, asking a question whose answer every device in the
// fleet knows.
func (a *app) registerShared(deviceID string, certDER []byte, nonce, signature []byte) (enrollmentOutcome, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return enrollmentOutcome{}, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return enrollmentOutcome{}, fmt.Errorf("certificate will not parse: %w", err)
	}
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return enrollmentOutcome{}, errors.New("the certificate does not carry an ECDSA key")
	}
	digest := sha256.Sum256(nonce)
	if !ecdsa.VerifyASN1(public, digest[:], signature) {
		outcome := enrollmentOutcome{
			Check:  "proof-of-possession",
			Reason: "the nonce signature does not verify against the presented certificate",
		}
		return outcome, a.recordRefusal(enrollmentRequest{DeviceID: deviceID}, outcome)
	}

	fingerprint := certFingerprint(certDER)
	record := provisionRecord{
		Kind:            recordEnrollment,
		DeviceID:        deviceID,
		Lifecycle:       LifecycleManufactured,
		CertSerial:      cert.SerialNumber.String(),
		CertFingerprint: fingerprint,
		CertPublicKey:   publicKeyFingerprint(cert.RawSubjectPublicKeyInfo),
		Result:          "issued",
		Detail:          "registered against the shared development identity, no Bootstrap credential was required",
	}
	if err := a.writeRecord(record); err != nil {
		return enrollmentOutcome{}, err
	}
	return enrollmentOutcome{
		Issued:          true,
		Check:           "registered",
		CertFingerprint: fingerprint,
		CertSerial:      cert.SerialNumber.String(),
	}, nil
}

// sharedRegistrationNonce is what the station asks the device to sign.
func sharedRegistrationNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// tier06Version is the human-readable version imgtool stamps into both Tier 6
// images.
//
// One value for both, as Tier 5 used one for all five. The two images differ
// in where their identity comes from, not in what they are as a release, and
// a version that implied otherwise would invite a Learner to read the identity
// model out of the header instead of out of the boot banner.
//
// Declared beside its consumer. Tier 4 declared tier04Version, never wired it
// to imgtool, and shipped an image whose --version was wrong, because an
// unused Go constant does not fail a build.
const tier06Version = "0.6.0+0"

func (a *app) tier06BuildDir(variant firmwareVariant) string {
	return filepath.Join(a.zephyrWorkspace(), "build", "tier-06-factory-identity-"+variant.label)
}

func (a *app) tier06RawImage(variant firmwareVariant) string {
	return filepath.Join(a.tier06BuildDir(variant), "tier-06-factory-identity", "zephyr", "zephyr.bin")
}

func tier06Variant(name string) (firmwareVariant, error) {
	variant, ok := tier06Variants[name]
	if ok {
		return variant, nil
	}
	names := make([]string, 0, len(tier06Variants))
	for key := range tier06Variants {
		names = append(names, key)
	}
	sort.Strings(names)
	return firmwareVariant{}, fmt.Errorf("unknown Tier 6 release %q; use one of: %s",
		name, strings.Join(names, ", "))
}

// releaseSignTier06 signs one Tier 6 release and publishes it.
//
// It is Tier 5's sequence unchanged, including the source-revision TLV: Tier 6
// keeps the whole recovery path and a revert still leaves the device running
// an image whose manifest it consumed long ago.
//
// Both images carry security counter 3, the same value Tier 5's releases
// carry. Section 6 raises a counter only when a release closes a security
// boundary that must not be reopened, and Tier 6 closes none: T0-W-02 moves to
// reduced rather than closed, because the device gains an identity that
// nothing yet requires it to present.
func (a *app) releaseSignTier06(variantName string) error {
	variant, err := tier06Variant(variantName)
	if err != nil {
		return err
	}
	key := a.signingKeyPath("release")
	if _, err := os.Stat(key); err != nil {
		return errors.New("no Release signing key yet; run ./course keys create release first")
	}
	raw := a.tier06RawImage(variant)
	if _, err := os.Stat(raw); err != nil {
		return fmt.Errorf("no Tier 6 %s image to sign; run ./course build firmware --tier 06 --variant %s first",
			variant.label, variant.label)
	}
	out := filepath.Join(a.releaseDir(), variant.imageName)
	if err := os.MkdirAll(a.releaseDir(), 0o700); err != nil {
		return err
	}

	fingerprint, err := a.keyFingerprint(key)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Signing with the release key, fingerprint %s\n", fingerprint)

	revision := a.sourceRevision()
	if err := a.signImage(key, raw, out, strconv.Itoa(variant.securityCounter), tier06Version,
		"--custom-tlv", tier05RevisionTLV, revision); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "+ source revision %s written to protected TLV %s\n",
		revision, tier05RevisionTLV)

	image, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	manifest := a.buildManifest(variant, image, time.Now())
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	manifestFile := a.manifestPath(variant.releaseID)
	if err := os.WriteFile(manifestFile, data, 0o600); err != nil {
		return err
	}

	keyPEM, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	signature, err := signManifest(keyPEM, data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(a.manifestSignaturePath(variant.releaseID), signature, 0o600); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "+ signed %d manifest bytes with ECDSA P-256 over SHA-256\n", len(data))
	fmt.Fprintf(a.out, "  manifest:  %s\n", a.relative(manifestFile))
	fmt.Fprintf(a.out, "  digest:    %s\n", manifest.ImageSHA256)
	fmt.Fprintf(a.out, "  counter:   %d, in the image TLV and in the manifest\n",
		manifest.SecurityCounter)

	release, err := a.publishSigned(variant, out, fingerprint)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: published %s, %d bytes, identity model %s\n",
		variant.releaseID, release["image_size"], variant.identityModel)
	if variant.identityModel == "shared" {
		fmt.Fprintln(a.out, "This image carries the fleet's one private key. Every board flashed with it")
		fmt.Fprintln(a.out, "is the same device, and anyone holding the image holds the credential.")
	}
	return nil
}

// releaseAssignTier06 offers an already-signed Tier 6 release to the device.
//
// Tier 5's command, for Tier 5's reason: publishing a release re-assigns it,
// and Tier 6 has two releases a Learner hands to the board in sequence. It
// signs nothing and builds nothing, and every value in the assignment is
// copied from the release's own signed manifest.
func (a *app) releaseAssignTier06(variantName string) error {
	variant, err := tier06Variant(variantName)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(a.manifestPath(variant.releaseID))
	if err != nil {
		return fmt.Errorf("no signed %s release yet; run ./course release sign --tier 06 --variant %s first",
			variant.label, variant.label)
	}
	var manifest releaseManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("the stored %s manifest is unreadable: %w", variant.label, err)
	}

	release := a.assignmentFor(manifest)
	state := filepath.Join(a.root, a.manifest.Paths.State, "ota")
	if err := writeJSON(filepath.Join(state, "current-release.json"), release, 0o600); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "Result: the service now offers %s, version %s, counter %d\n",
		manifest.ReleaseID, manifest.Version, manifest.SecurityCounter)
	fmt.Fprintln(a.out, "Every value above came from that release's own signed manifest. This command")
	fmt.Fprintln(a.out, "signs nothing and changes no stored release.")
	return nil
}

// writeSharedIdentityInc compiles the fleet's identity into the shared image.
//
// This is the one place in the whole course where a private key reaches a
// firmware build, and it is deliberate. A credential a Learner cannot extract
// from their own image cannot teach why shared credentials fail, so the tier
// gives them one to extract. The bound is written into the Tier 6 section of
// docs/fixture-safety-contract.md: this credential only, generated locally,
// never committed, and never used to sign anything a device would trust.
//
// It is written into its own directory rather than the shared anchor
// directory, and the environment variable naming that directory is set only
// for the shared variant. The factory build therefore never has the key on its
// include path at all, which is a stronger statement than "it does not include
// it".
//
// The key goes in as the SEC1 ECPrivateKey structure rather than as a bare
// scalar. That is what a real image would carry, and it is what makes the
// extraction command teachable: the structure has a fixed seven byte prefix
// that can be searched for and explained, where thirty-two anonymous bytes
// could only be found by already knowing where they were.
func (a *app) writeSharedIdentityInc() (string, error) {
	certDER, key, err := coursepki.LoadSharedIdentity(a.pkiDir())
	if err != nil {
		return "", errors.New("no shared development identity yet; run ./course keys create shared-identity first")
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}

	dir := filepath.Join(a.root, a.manifest.Paths.State, "firmware", "shared-identity")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := writeIncFile(dir, "shared_identity_key.inc", keyDER); err != nil {
		return "", err
	}
	if err := writeIncFile(dir, "shared_identity_cert.inc", certDER); err != nil {
		return "", err
	}
	return dir, nil
}

// writeIncFile emits one C byte list, the way writeTrustAnchor does.
func writeIncFile(dir, name string, data []byte) error {
	var builder strings.Builder
	builder.WriteString("/* Generated by ./course build firmware. Do not edit or commit. */\n")
	for i, b := range data {
		if i%12 == 0 {
			builder.WriteString("\n\t")
		}
		fmt.Fprintf(&builder, "0x%02x, ", b)
	}
	builder.WriteString("\n")
	return os.WriteFile(filepath.Join(dir, name), []byte(builder.String()), 0o600)
}

// provisionRegister is the before state, driven over the console.
//
// The station issues a nonce, the shared image signs it with the credential
// compiled into it, and the station checks that signature against the
// certificate the image also carries. It verifies. What the station cannot
// tell, and what the whole tier is about, is which board answered: every image
// built this way knows the same answer.
func (a *app) provisionRegister(args []string) error {
	deviceID, _ := flagValue(args, "--device")

	console, err := a.openConsole()
	if err != nil {
		return err
	}
	defer console.Close()

	nonce, err := sharedRegistrationNonce()
	if err != nil {
		return err
	}

	fmt.Fprintln(a.out, "Registering a device against the provisioning station.")
	fmt.Fprintln(a.out, "This is the fleet before hardening, so there is no Bootstrap credential")
	fmt.Fprintln(a.out, "to present. Possession of the compiled-in key is both the identity and")
	fmt.Fprintln(a.out, "the authorization to be registered.")
	fmt.Fprintf(a.out, "\n  station nonce: %x\n", nonce)
	fmt.Fprintln(a.out, "  asking the board to sign it over the console")

	if err := console.send(fmt.Sprintf("provision register %x", nonce)); err != nil {
		return err
	}
	certDER, err := console.readChunked("provision.cert", 20*time.Second)
	if err != nil {
		return fmt.Errorf("the board did not return a certificate: %w", err)
	}
	signature, err := console.readChunked("provision.sig", 20*time.Second)
	if err != nil {
		return fmt.Errorf("the board did not return a signature: %w", err)
	}
	fmt.Fprintf(a.out, "  board returned a %d byte certificate and a %d byte signature\n",
		len(certDER), len(signature))

	// The identifier defaults to the one inside the certificate the board
	// presented, so an honest registration records what the device actually
	// claims. The clone fixture overrides it, which is exactly the abuse.
	if deviceID == "" {
		parsed, perr := x509.ParseCertificate(certDER)
		if perr != nil {
			return fmt.Errorf("the certificate the board sent will not parse: %w", perr)
		}
		deviceID = parsed.Subject.CommonName
		fmt.Fprintf(a.out, "  identifier taken from the certificate subject: %s\n", deviceID)
	} else {
		fmt.Fprintf(a.out, "  identifier supplied on the command line: %s\n", deviceID)
	}

	outcome, err := a.registerShared(deviceID, certDER, nonce, signature)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out)
	if !outcome.Issued {
		fmt.Fprintf(a.out, "Refused at check %s: %s\n", outcome.Check, outcome.Reason)
		return nil
	}
	fmt.Fprintln(a.out, "The signature verified against the certificate the board presented, so")
	fmt.Fprintln(a.out, "the board does hold that private key. Nothing here establishes which")
	fmt.Fprintln(a.out, "board it is.")
	fmt.Fprintf(a.out, "  certificate: %s\n", outcome.CertSerial)
	fmt.Fprintf(a.out, "  fingerprint: %s\n", outcome.CertFingerprint)
	fmt.Fprintf(a.out, "  recorded in: %s\n", a.relative(a.provisionRecordPath()))
	fmt.Fprintf(a.out, "\nResult: %s registered against the shared development identity\n", deviceID)
	return nil
}

// provisionEnroll is the hardened path, driven over the same console.
//
// Two acts by two roles. ./course provision credential new played the
// manufacturer's IT department and kept only a verifier; this is the station on
// the line, which hands the credential to the device, checks what comes back,
// and issues a certificate.
func (a *app) provisionEnroll(args []string) error {
	deviceID, err := flagValue(args, "--device")
	if err != nil {
		return errors.New("usage: ./course provision enroll --device <id> --credential <hex>")
	}
	credential, err := flagValue(args, "--credential")
	if err != nil {
		return errors.New("usage: ./course provision enroll --device <id> --credential <hex>")
	}
	if err := validateDeviceID(deviceID); err != nil {
		return err
	}

	console, err := a.openConsole()
	if err != nil {
		return err
	}
	defer console.Close()

	fmt.Fprintf(a.out, "Enrolling %s over the board's console.\n", deviceID)
	fmt.Fprintln(a.out, "The credential goes over the cable, not over the network. A Bootstrap")
	fmt.Fprintln(a.out, "credential delivered through the device's normal network traffic would")
	fmt.Fprintln(a.out, "not be the separate channel section 8 asks for.")
	fmt.Fprintln(a.out, "\n  handing the credential to the device and asking for a request")

	if err := console.send("provision request " + credential); err != nil {
		return err
	}
	csrDER, err := console.readChunked("provision.csr", 30*time.Second)
	if err != nil {
		return fmt.Errorf("the board did not return a certification request: %w", err)
	}
	fmt.Fprintf(a.out, "  board returned a %d byte certification request\n", len(csrDER))
	fmt.Fprintln(a.out, "  it is signed by the key the board generated, and the credential is")
	fmt.Fprintln(a.out, "  inside that signature rather than beside it")

	outcome, err := a.enroll(enrollmentRequest{
		DeviceID:         deviceID,
		HardwareRevision: strconv.Itoa(tier04HardwareRevision),
		CSRDer:           csrDER,
	}, credential)
	if err != nil {
		return err
	}
	if !outcome.Issued {
		fmt.Fprintln(a.out)
		fmt.Fprintf(a.out, "Refused at check %s\n", outcome.Check)
		fmt.Fprintf(a.out, "  %s\n", outcome.Reason)
		fmt.Fprintf(a.out, "  the refusal is recorded in %s\n", a.relative(a.provisionRecordPath()))
		fmt.Fprintln(a.out, "\nNothing was sent to the board. It still holds its key and no certificate.")
		return nil
	}

	fmt.Fprintln(a.out, "\n  the station issued a certificate and consumed the credential in one")
	fmt.Fprintln(a.out, "  append, before anything was sent to the board, so nothing leaves here")
	fmt.Fprintln(a.out, "  that the record does not already contain")
	fmt.Fprintf(a.out, "  certificate: %s\n", outcome.CertSerial)
	fmt.Fprintf(a.out, "  fingerprint: %s\n", outcome.CertFingerprint)
	fmt.Fprintln(a.out, "\n  returning it to the board")

	if err := console.sendChunked("provision certificate", outcome.CertDER); err != nil {
		return err
	}
	lines, err := console.collect(20*time.Second, func(line string) bool {
		return strings.Contains(line, "provision.certificate stored") ||
			strings.Contains(line, "provision.certificate refused") ||
			strings.Contains(line, "provision.certificate got")
	})
	if err != nil {
		return fmt.Errorf("the board did not confirm the certificate: %w", err)
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "provision.") || strings.HasPrefix(line, "identity.") {
			fmt.Fprintf(a.out, "  board: %s\n", line)
		}
	}
	fmt.Fprintf(a.out, "\nResult: %s holds a Factory identity, fingerprint %s\n",
		deviceID, outcome.CertFingerprint)
	fmt.Fprintln(a.out, "Read the board, not this line: ./course provision record --device "+deviceID)
	fmt.Fprintln(a.out, "shows what the station stored, which is the half a device cannot fake.")
	return nil
}

// The shared development identity, as it sits inside a built shared image.
//
// The key is a SEC1 ECPrivateKey. For P-256 that structure is a fixed 121
// bytes and begins with SEQUENCE (0x77 content bytes), INTEGER 1, then an
// OCTET STRING of 32 bytes: 30 77 02 01 01 04 20. That seven byte prefix is
// what ./course provision extract searches for, and it is why the key is
// compiled in as the whole structure rather than a bare scalar: a Learner can
// be shown a prefix to look for and told what it means, where thirty-two
// anonymous bytes could only be found by already knowing where they were.
var sec1P256Prefix = []byte{0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20}

const sec1P256Len = 121

// sharedImagePath is the built shared image the credential is extracted from.
//
// It is named by the manifest, never supplied on the command line. A command
// that read any file a Learner named would be a general-purpose key-recovery
// tool wearing a course label, which docs/fixture-safety-contract.md exists to
// keep out of the course.
func (a *app) sharedImagePath() (string, error) {
	f, ok := a.manifest.Fixtures["tier-06/clone-shared-identity"]
	if !ok || f.Image == "" {
		return "", errors.New("no shared image is named in course.yml")
	}
	return filepath.Join(a.releaseDir(), f.Image), nil
}

// extractSharedIdentity finds the fleet key and certificate inside a built
// shared image.
//
// Both are recoverable, and that is the lesson: everything the fleet identity
// is made of travels in every image built the same way. The key is found by
// its SEC1 prefix; the certificate is found by scanning for a DER SEQUENCE that
// parses as a certificate whose public key is the one the private key implies,
// which ties the two together rather than trusting their adjacency in the
// image.
func extractSharedIdentity(image []byte) (certDER []byte, key *ecdsa.PrivateKey, keyOffset int, err error) {
	keyOffset = -1
	for i := 0; i+sec1P256Len <= len(image); i++ {
		if !bytesEqual(image[i:i+len(sec1P256Prefix)], sec1P256Prefix) {
			continue
		}
		candidate, perr := x509.ParseECPrivateKey(image[i : i+sec1P256Len])
		if perr != nil {
			continue
		}
		key = candidate
		keyOffset = i
		break
	}
	if key == nil {
		return nil, nil, -1, errors.New("no SEC1 P-256 private key is present in this image")
	}

	// Find the certificate that belongs to this key. A DER certificate begins
	// with a SEQUENCE whose length is two bytes (0x30 0x82 hi lo), which is
	// true of every certificate this course issues, so the scan is cheap.
	for i := 0; i+4 <= len(image); i++ {
		if image[i] != 0x30 || image[i+1] != 0x82 {
			continue
		}
		length := int(image[i+2])<<8 | int(image[i+3])
		end := i + 4 + length
		if end > len(image) {
			continue
		}
		cert, perr := x509.ParseCertificate(image[i:end])
		if perr != nil {
			continue
		}
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.X.Cmp(key.PublicKey.X) != 0 || pub.Y.Cmp(key.PublicKey.Y) != 0 {
			continue
		}
		return image[i:end], key, keyOffset, nil
	}
	return nil, key, keyOffset, errors.New("the private key is present but its certificate is not")
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// provisionExtract reads the fleet credential out of the Learner's own built
// shared image and reports it.
//
// It is an ordinary command and not a fixture. It has no target, opens no
// socket, and changes nothing, so the marker handshake and a reset would guard
// nothing while implying a check happened. It prints a fingerprint and never
// the key, and the narration is the point: a command that printed
// "Result: key extracted" would teach nothing.
func (a *app) provisionExtract(args []string) error {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--image") || strings.HasPrefix(arg, "--file") || strings.HasPrefix(arg, "--path") {
			return errors.New("extraction takes no path; the image it reads is named in course.yml, on purpose")
		}
	}

	path, err := a.sharedImagePath()
	if err != nil {
		return err
	}
	image, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no built shared image at %s; run ./course build firmware --tier 06 --variant shared first",
			a.relative(path))
	}

	fmt.Fprintf(a.out, "Reading the shared image you built: %s (%d bytes)\n", a.relative(path), len(image))
	fmt.Fprintln(a.out, "This is a firmware image, not a secret store. It is the same file you would")
	fmt.Fprintln(a.out, "flash to a board, and anyone who has the image has everything in it.")
	fmt.Fprintln(a.out)
	fmt.Fprintf(a.out, "Searching for a SEC1 P-256 private key, which begins %x.\n", sec1P256Prefix)

	certDER, key, offset, err := extractSharedIdentity(image)
	if err != nil {
		return err
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)

	fmt.Fprintf(a.out, "Found it at offset 0x%x. The next %d bytes are the fleet's private key.\n", offset, len(keyDER))
	fmt.Fprintln(a.out, "That is the whole credential. In the shared model there is no separate")
	fmt.Fprintln(a.out, "Bootstrap credential: holding this key is both the identity and the")
	fmt.Fprintln(a.out, "authorization to enroll, which is what makes it worth copying.")
	fmt.Fprintln(a.out)

	point := elliptic.Marshal(key.Curve, key.PublicKey.X, key.PublicKey.Y)
	fmt.Fprintf(a.out, "  public key fingerprint:  %s\n", "sha256:"+hex.EncodeToString(sha256Of(point)))
	fmt.Fprintf(a.out, "  certificate fingerprint: %s\n", certFingerprint(certDER))
	cert, _ := x509.ParseCertificate(certDER)
	if cert != nil {
		fmt.Fprintf(a.out, "  certificate subject:     %s\n", cert.Subject.CommonName)
	}
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "The private key itself is not printed, and it never needs to be. The")
	fmt.Fprintln(a.out, "fingerprint is enough to prove it is here, and the clone fixture reads the")
	fmt.Fprintln(a.out, "same bytes to act as this identity without a board:")
	fmt.Fprintln(a.out, "  ./course attack run tier-06/clone-shared-identity")
	fmt.Fprintln(a.out)
	fmt.Fprintf(a.out, "Result: the fleet private key was extracted from your own image, fingerprint %s\n",
		certFingerprint(certDER))
	return nil
}

func sha256Of(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// tier06Plan and tier06Proves are what the clone's dry run shows.
var tier06Plan = map[string][]string{
	"tier-06/clone-shared-identity": {
		"Extract the fleet credential from your own built shared image, on the host.",
		"Find a device already registered with that credential in the manufacturing record.",
		"Register a second time under that same identifier, and watch the station accept it.",
		"Register several devices that were never manufactured, under the same one credential.",
		"Show the record: many entries, one certificate fingerprint, no board involved.",
	},
}

var tier06Proves = map[string][]string{
	"tier-06/clone-shared-identity": {
		"One extracted shared credential impersonates every device. It is the threat named against this tier, and it is why a per-device Factory identity (SC-06) replaces the shared one.",
		"The provisioning station accepts a proof of possession without asking which device offered it, because in the shared model every device offers the same one.",
	},
}

// cloneSharedIdentity is the Tier 6 attack fixture.
//
// It reads the fleet credential out of the Learner's own built shared image and
// acts as the fleet against the provisioning station, entirely on the host. No
// board is involved, and that is the lesson rather than a compromise forced by
// owning one board: a copied credential does not need the hardware it was
// copied from.
//
// It shows the mechanism, not a verdict. Every request it makes and every
// answer it gets is narrated, because the station's acceptance is the whole
// point and a fixture that printed "clone succeeded" would teach nothing.
func (a *app) cloneSharedIdentity(env environment) (string, string, map[string]string, error) {
	path, err := a.sharedImagePath()
	if err != nil {
		return "", "", nil, err
	}
	image, err := os.ReadFile(path)
	if err != nil {
		return "", "", nil, fmt.Errorf("no built shared image at %s; run ./course build firmware --tier 06 --variant shared first",
			a.relative(path))
	}
	certDER, key, offset, err := extractSharedIdentity(image)
	if err != nil {
		return "", "", nil, err
	}
	fingerprint := certFingerprint(certDER)

	a.step(1, "Extract the fleet credential from your own shared image.")
	a.note("Read %s on the host, no board attached.", a.relative(path))
	a.got("found the SEC1 private key at offset 0x%x and the matching certificate", offset)
	a.note("certificate fingerprint %s", fingerprint)
	a.note("This is the same key ./course provision extract reports. Here it is used, not just named.")

	// The identifier to take over is read from the record, never from the
	// command line, so the clone can only impersonate a device this Course
	// environment actually registered with this credential.
	records, err := a.readRecords()
	if err != nil {
		return "", "", nil, err
	}
	takeover := ""
	for i := range records {
		if records[i].Kind == recordEnrollment && records[i].Result == "issued" &&
			records[i].CertFingerprint == fingerprint {
			takeover = records[i].DeviceID
			break
		}
	}
	if takeover == "" {
		return "", "", nil, errors.New(
			"no device has registered with this credential yet; run ./course provision register first, " +
				"so the clone has an existing identity to take over")
	}

	a.step(2, "Register a second time under an identifier the record already holds.")
	a.note("The record already has %s, registered with this credential.", takeover)
	a.note("A real device could only prove this key once, because it is the only one that holds it.")
	a.note("The clone holds it too, so it proves it again, for a device that is already enrolled.")
	if err := a.cloneRegister(takeover, certDER, key); err != nil {
		return "", "", nil, err
	}
	a.got("the station accepted it. There are now two entries for %s, both %s.", takeover, fingerprint)
	a.note("Nothing distinguished the clone's proof from the real device's. Both hold the same key.")

	a.step(3, "Register devices that were never manufactured.")
	f := a.manifest.Fixtures["tier-06/clone-shared-identity"]
	a.note("These identifiers name no board. The credential is all the station checks, and it is one credential.")
	for _, phantom := range f.PhantomIDs {
		if err := a.cloneRegister(phantom, certDER, key); err != nil {
			return "", "", nil, err
		}
		a.got("registered %s, a device that does not exist, under %s", phantom, fingerprint)
	}

	total := 1 + len(f.PhantomIDs)
	a.step(4, "Read the manufacturing record back.")
	a.note("Run ./course provision record to see it: %d new entries this fixture wrote,", total)
	a.note("every one of them carrying the one fingerprint %s.", fingerprint)
	a.note("The station cannot tell any of them apart, because in the shared model there is")
	a.note("nothing to tell apart. That is what the per-device Factory identity fixes.")

	observed := fmt.Sprintf("one duplicate under %s and %d never-manufactured devices registered under one fingerprint %s, from the host with no board",
		takeover, len(f.PhantomIDs), fingerprint)
	return observed, "", map[string]string{"shared-identity-certificate": fingerprint}, nil
}

// cloneRegister signs a station nonce with the extracted key and registers.
//
// It is what a device does during shared registration, except that both halves
// run on the host: the station issues the nonce and the "device" answers it
// with a key that came out of a file rather than off a board. registerShared is
// the same station code path ./course provision register drives, so the clone
// is not a weaker imitation of the attack, it is the attack.
func (a *app) cloneRegister(deviceID string, certDER []byte, key *ecdsa.PrivateKey) error {
	nonce, err := sharedRegistrationNonce()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(nonce)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return err
	}
	a.sent("station", "nonce "+hex.EncodeToString(nonce[:8])+"... to "+deviceID)
	outcome, err := a.registerShared(deviceID, certDER, nonce, signature)
	if err != nil {
		return err
	}
	if !outcome.Issued {
		return fmt.Errorf("the station refused %s at check %s: %s", deviceID, outcome.Check, outcome.Reason)
	}
	return nil
}

// resetClone is the clone fixture's reset, and it appends rather than deletes.
//
// The manufacturing record is append only by design: a credential is consumed
// and a certificate recorded in one write, so nothing ever leaves the station
// that the record does not already contain. A reset that deleted the clone's
// entries would make the store mutable and quietly break that guarantee for the
// sake of tidying up after a fixture, so reset writes one fixture_reset entry
// and the phantom devices stay in the record forever.
//
// That is the finding, not a limitation of the tooling. A cloned credential's
// damage to a manufacturing record is not reversible by the party who discovers
// it. A Learner who wants the record empty again discards the whole Course
// environment, which is an environment reset and not something a fixture may do.
func (a *app) resetClone() error {
	return a.writeRecord(provisionRecord{
		Kind:   recordFixtureReset,
		Result: "reset",
		Detail: "tier-06/clone-shared-identity reset: the record is append only, so the clone's entries remain above this line. Reset restores the station's operational state, not the record.",
	})
}
