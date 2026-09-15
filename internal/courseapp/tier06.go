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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		return errors.New("usage: ./course provision credential|enroll|record|reset")
	}
	switch args[0] {
	case "credential":
		return a.provisionCredential(args[1:])
	case "record":
		return a.provisionShowRecord(args[1:])
	default:
		return fmt.Errorf("unknown provision command %q; use credential, enroll, record or reset", args[0])
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
				fmt.Fprintf(a.out, "    consumed credential %s, lifecycle %s\n", record.ConsumedCredential, record.Lifecycle)
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
