package courseapp

// Tier 7 replaces the Factory identity's authority with an owner's. This file
// holds the host half: the Owner credential store, and the one lab control
// that marks a certificate revoked.
//
// The claim itself is not here, and that is the tier's shape rather than an
// omission. Tier 6's provisioning station is a command on a bench, so the
// command is the authority. Tier 7's claim is a two-party transition between a
// device holding a Factory identity and a person holding an Owner credential,
// and collapsing it into one local write against shared state would leave the
// two parties as one. The OTA service owns the claim; these commands mint the
// credential a person presents to it and read the record it writes.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// ownerCredentialLifetime is how long an Owner credential may be used.
//
// Nothing consumes an Owner credential, so a bound has to come from somewhere
// other than use. Ninety days: long enough that a Learner returning after a
// break is not locked out of their own lab, short enough that the check exists
// and is visible rather than being the standing secret this tier argues
// against.
//
// The contrast with Tier 6's twenty-four hours is the teaching. A Bootstrap
// credential dies on first successful use and only has to survive the walk to
// the bench. An Owner credential is reusable, so its bound is a lifetime.
const ownerCredentialLifetime = 90 * 24 * time.Hour

// ownerRecordKind is the only kind in the owner store today.
const ownerRecordKind = "owner_credential_issued"

// ownerRecord is one line of `.course-state/provisioning/owners.jsonl`.
//
// A separate file beside records.jsonl rather than rows in it, because that
// store is keyed per device and an owner is not a device: mixing them would
// make readRecords replay entries carrying no device_id.
//
// The field names are Tier 6's, deliberately. A credential is a credential in
// both tiers, and a Learner who has read one store should not have to learn a
// second spelling to read the other.
type ownerRecord struct {
	Kind               string `json:"kind"`
	Recorded           string `json:"recorded_at"`
	OwnerID            string `json:"owner_id"`
	CredentialID       string `json:"credential_id,omitempty"`
	CredentialVerifier string `json:"credential_verifier,omitempty"`
	CredentialExpires  string `json:"credential_expires,omitempty"`
	Result             string `json:"result,omitempty"`
}

func (a *app) ownerStorePath() string {
	return filepath.Join(a.provisionDir(), "owners.jsonl")
}

func (a *app) revokedPath() string {
	return filepath.Join(a.provisionDir(), "revoked.jsonl")
}

func (a *app) owner(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ./course owner new --name <slug>|list")
	}
	switch args[0] {
	case "new":
		return a.ownerNew(args[1:])
	case "list":
		return a.ownerList()
	default:
		return fmt.Errorf("unknown owner command %q; use new or list", args[0])
	}
}

func (a *app) ownerNew(args []string) error {
	slug, err := flagValue(args, "--name")
	if err != nil {
		return err
	}
	credential, record, err := a.mintOwner(slug)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Minting one Owner credential. It authorizes a person, not a device, so")
	fmt.Fprintln(a.out, "it never rides the mutual-TLS listener: you present it as a bearer token")
	fmt.Fprintln(a.out, "on the operator port, and the store keeps only a verifier.")
	fmt.Fprintf(a.out, "  owner:       %s\n", record.OwnerID)
	fmt.Fprintf(a.out, "  credential:  %s\n", record.CredentialID)
	fmt.Fprintf(a.out, "  verifier:    %s\n", record.CredentialVerifier)
	fmt.Fprintf(a.out, "  expires:     %s\n", record.CredentialExpires)
	fmt.Fprintf(a.out, "  recorded in: %s\n", a.relative(a.ownerStorePath()))
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "The credential itself is printed once and never stored. Run this command")
	fmt.Fprintln(a.out, "again for the same owner and the new credential supersedes this one: the")
	fmt.Fprintln(a.out, "old one stops matching. That is replacement, not revocation, and the")
	fmt.Fprintln(a.out, "difference is what Tier 8 is for.")
	fmt.Fprintf(a.out, "\n  %s\n\n", credential)
	fmt.Fprintln(a.out, "Do not choose a credential of your own instead. This one is 256 random")
	fmt.Fprintln(a.out, "bits, which is the whole reason the store may hash it once and quickly.")
	fmt.Fprintf(a.out, "Result: owner %s holds one credential, valid until %s\n",
		record.OwnerID, record.CredentialExpires)
	return nil
}

// mintOwner appends one Owner credential and returns the secret.
//
// The secret exists only here and in the caller. The attack fixture calls this
// directly, because it needs the credential to authenticate as its adversary
// owner and be refused at an authorization check rather than an authentication
// one.
func (a *app) mintOwner(slug string) (credential string, record ownerRecord, err error) {
	if err := validateOwnerID(slug); err != nil {
		return "", ownerRecord{}, err
	}
	if err := os.MkdirAll(a.provisionDir(), 0o700); err != nil {
		return "", ownerRecord{}, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", ownerRecord{}, err
	}
	credential = hex.EncodeToString(secret)
	credentialID, err := randomID()
	if err != nil {
		return "", ownerRecord{}, err
	}
	record = ownerRecord{
		Kind:               ownerRecordKind,
		OwnerID:            slug,
		CredentialID:       credentialID,
		CredentialVerifier: verifierFor(credential),
		CredentialExpires:  time.Now().UTC().Add(ownerCredentialLifetime).Format(time.RFC3339),
		Result:             "issued",
	}
	if err := a.writeOwnerRecord(record); err != nil {
		return "", ownerRecord{}, err
	}
	return credential, record, nil
}

// ownerCredentialIsCurrent answers the one question a caller holding a stored
// credential can ask without minting a new one: does this secret still
// authenticate as this owner.
//
// It is what makes "mint idempotently" possible for the attack fixture, which
// holds its adversary owner's credential in its own state. A fixture that
// minted on every run would leave a trail of superseded entries in a store the
// Learner is asked to read.
func (a *app) ownerCredentialIsCurrent(slug, credential string) (bool, error) {
	records, err := a.readOwnerRecords()
	if err != nil {
		return false, err
	}
	current, ok := currentOwnerRecord(records, slug)
	if !ok {
		return false, nil
	}
	if current.CredentialVerifier != verifierFor(credential) {
		return false, nil
	}
	expires, err := time.Parse(time.RFC3339, current.CredentialExpires)
	if err != nil {
		return false, nil
	}
	return time.Now().UTC().Before(expires), nil
}

func (a *app) ownerList() error {
	records, err := a.readOwnerRecords()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Fprintln(a.out, "No owners yet. Make one with ./course owner new --name <slug>")
		return nil
	}
	fmt.Fprintf(a.out, "Owner store: %s\n", a.relative(a.ownerStorePath()))
	fmt.Fprintln(a.out, "It is append only. A second credential for the same owner supersedes the")
	fmt.Fprintln(a.out, "first; nothing is edited or removed.")
	fmt.Fprintln(a.out)
	seen := map[string]bool{}
	for _, record := range records {
		state := "superseded"
		if current, ok := currentOwnerRecord(records, record.OwnerID); ok &&
			current.CredentialID == record.CredentialID {
			state = "current"
			seen[record.OwnerID] = true
		}
		fmt.Fprintf(a.out, "%s  %-12s %s\n", record.Recorded, record.OwnerID, state)
		fmt.Fprintf(a.out, "    credential %s, verifier %s, expires %s\n",
			record.CredentialID, short(record.CredentialVerifier), record.CredentialExpires)
	}
	fmt.Fprintf(a.out, "\nResult: %d owner(s) with a current credential\n", len(seen))
	return nil
}

// currentOwnerRecord is the owner store replayed: the last entry for an owner
// is the one that authenticates, exactly as the manufacturing record derives
// credential state rather than editing a row.
func currentOwnerRecord(records []ownerRecord, slug string) (ownerRecord, bool) {
	var current ownerRecord
	found := false
	for _, record := range records {
		if record.Kind == ownerRecordKind && record.OwnerID == slug {
			current = record
			found = true
		}
	}
	return current, found
}

func (a *app) readOwnerRecords() ([]ownerRecord, error) {
	raw, err := os.ReadFile(a.ownerStorePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []ownerRecord
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record ownerRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("owner store is corrupt: %w", err)
		}
		records = append(records, record)
	}
	return records, nil
}

// writeOwnerRecord appends one line, and refuses to write private key material
// or anything that looks like a credential rather than a verifier.
//
// The guard is writeRecord's, for the same reason: a store that must hold only
// verifiers needs an enforcement point rather than a convention.
func (a *app) writeOwnerRecord(record ownerRecord) error {
	record.Recorded = time.Now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if looksLikePrivateKey(string(line)) {
		return errors.New("refusing to write an owner record that contains private key material")
	}
	if record.CredentialVerifier != "" && !strings.HasPrefix(record.CredentialVerifier, "sha256:") {
		return errors.New("refusing to write an owner record whose credential is not a verifier")
	}
	if err := os.MkdirAll(a.provisionDir(), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(a.ownerStorePath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(line, '\n'))
	return err
}

// validateOwnerID keeps an owner slug safe as a path component and readable in
// a certificate subject.
//
// The character rules are validateDeviceID's. An owner has no display name: the
// slug is the identifier, it is what the Operational certificate carries in its
// organizational unit, and one name is one fewer thing that can disagree.
func validateOwnerID(slug string) error {
	if slug == "" {
		return errors.New("an owner name is required")
	}
	if len(slug) > 64 {
		return errors.New("owner name is too long")
	}
	for _, r := range slug {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return fmt.Errorf("owner name %q may hold only lower-case letters, digits and hyphens", slug)
		}
	}
	return nil
}

func (a *app) claim(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ./course claim approve --device <id> --nonce <nonce> --credential <hex>|revoke --serial <certificate serial>")
	}
	switch args[0] {
	case "approve":
		return a.claimApprove(args[1:])
	case "revoke":
		return a.claimRevoke(args[1:])
	default:
		return fmt.Errorf("unknown claim command %q; use approve or revoke", args[0])
	}
}

// claimApprove is the operator half of the claim, and the only command in this
// course that speaks for a person rather than for a device or a station.
//
// It takes no --owner flag, and the absence is the teaching. The service
// derives the owner from the credential it verified, because a field the
// caller fills in is not an authentication. There is nowhere in this exchange
// for a caller to say who they are.
//
// It also never touches `.course-state` itself. Tier 6's station was a command
// doing one append, so the command was the authority. Here the authority is
// the service, and this command is one of the two parties talking to it.
func (a *app) claimApprove(args []string) error {
	deviceID, err := flagValue(args, "--device")
	if err != nil {
		return err
	}
	nonce, err := flagValue(args, "--nonce")
	if err != nil {
		return err
	}
	credential, err := flagValue(args, "--credential")
	if err != nil {
		return errors.New("--credential is required; it is the Owner credential ./course owner new printed once")
	}
	if strings.TrimSpace(credential) == "" {
		return errors.New("--credential is empty")
	}

	pool, err := a.trustAnchorPool()
	if err != nil {
		return err
	}
	port := a.manifest.Runtime.OperatorTLSPort
	address := net.JoinHostPort(hostOf(a.serviceURL()), strconv.Itoa(port))
	base := "https://" + coursepki.ServiceName + ":" + strconv.Itoa(port)
	client := a.verifyingClient(pool, coursepki.ServiceName, address)

	fmt.Fprintln(a.out, "Approving a claim as the person who owns this device.")
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "An Owner credential authorizes a person, so it cannot ride the listener")
	fmt.Fprintln(a.out, "the device uses. That listener demands a client certificate during the")
	fmt.Fprintln(a.out, "handshake, before any header is read, and a person holds no device")
	fmt.Fprintln(a.out, "certificate. The credential goes to the operator listener instead, as a")
	fmt.Fprintln(a.out, "bearer token, over a connection that authenticates the server only.")
	fmt.Fprintf(a.out, "  operator listener: %s\n", base)
	fmt.Fprintf(a.out, "  device named:      %s\n", deviceID)
	fmt.Fprintf(a.out, "  nonce presented:   %s\n", nonce)
	fmt.Fprintln(a.out, "  owner named:       nothing. This command sends no owner field, and there")
	fmt.Fprintln(a.out, "                     is no flag for one. The service derives the owner from")
	fmt.Fprintln(a.out, "                     the credential it verified.")
	fmt.Fprintln(a.out)

	body, err := json.Marshal(map[string]string{"device_id": deviceID, "nonce": nonce})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, base+"/v1/claim", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)

	fmt.Fprintf(a.out, "+ POST %s/v1/claim\n", base)
	fmt.Fprintln(a.out, "  Authorization: Bearer <the credential, not printed>")
	fmt.Fprintf(a.out, "  -> %s\n", body)

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("the operator listener could not be reached at %s: %w; start the service with ./course service start --https --mutual-tls", address, err)
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "  <- %d %s\n", response.StatusCode, http.StatusText(response.StatusCode))

	if response.StatusCode != http.StatusOK {
		var refusal struct {
			Check  string `json:"check"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(answer, &refusal); err != nil || refusal.Check == "" {
			fmt.Fprintf(a.out, "     %s\n", strings.TrimSpace(string(answer)))
			return fmt.Errorf("the operator half was refused with status %d", response.StatusCode)
		}
		fmt.Fprintf(a.out, "     refused at check %s\n", refusal.Check)
		fmt.Fprintf(a.out, "     reason: %s\n", refusal.Reason)
		fmt.Fprintln(a.out)
		fmt.Fprintln(a.out, "The check name says which property did not hold, and the status does not.")
		fmt.Fprintln(a.out, "Every authorization refusal in this tier answers 403, so reading the status")
		fmt.Fprintln(a.out, "alone would tell you nothing about what went wrong.")
		fmt.Fprintf(a.out, "Result: the operator half was refused at %s\n", refusal.Check)
		return fmt.Errorf("refused at check %s", refusal.Check)
	}

	var issued struct {
		Result      string `json:"result"`
		DeviceID    string `json:"device_id"`
		OwnerID     string `json:"owner_id"`
		State       string `json:"lifecycle_state"`
		Serial      string `json:"certificate_serial"`
		Fingerprint string `json:"certificate_fingerprint"`
		NotAfter    string `json:"not_after"`
	}
	if err := json.Unmarshal(answer, &issued); err != nil {
		return fmt.Errorf("the operator listener answered 200 with a body this command cannot read: %w", err)
	}
	fmt.Fprintf(a.out, "     result:          %s\n", issued.Result)
	fmt.Fprintf(a.out, "     device:          %s\n", issued.DeviceID)
	fmt.Fprintf(a.out, "     owner:           %s\n", issued.OwnerID)
	fmt.Fprintf(a.out, "     lifecycle state: %s\n", issued.State)
	fmt.Fprintf(a.out, "     serial:          %s\n", issued.Serial)
	fmt.Fprintf(a.out, "     fingerprint:     %s\n", issued.Fingerprint)
	fmt.Fprintf(a.out, "     not after:       %s\n", issued.NotAfter)
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "The owner on that line was never sent. It came from the credential.")
	fmt.Fprintln(a.out, "The certificate is now waiting in the open claim window, and the device")
	fmt.Fprintln(a.out, "collects it on its next poll. Nothing was sent to the device from here:")
	fmt.Fprintln(a.out, "the two halves never meet except inside the service.")
	fmt.Fprintf(a.out, "Result: %s is claimed by %s, certificate %s\n",
		issued.DeviceID, issued.OwnerID, short(issued.Fingerprint))
	return nil
}

// revocationRecord is one line of revoked.jsonl.
//
// The file is the service's whole authority on clause 2 of certificate-active.
// There is no CRL and no OCSP responder in this course: when the verifier is
// also the issuer it finds out what it withdrew by looking at its own record,
// and every real complication in CRLs comes from the day those two are
// different machines.
type revocationRecord struct {
	CertSerial string `json:"certificate_serial"`
	Revoked    string `json:"revoked_at"`
}

// claimRevoke marks one certificate revoked.
//
// It is a lab control rather than an operator workflow: Tier 8 owns revocation
// as something an owner does, and Tier 7 owns only the file the service reads.
// It takes nothing but a serial, and only a serial this Course environment can
// show a claim record for, so it cannot become a general revocation tool a tier
// early.
func (a *app) claimRevoke(args []string) error {
	serial, err := flagValue(args, "--serial")
	if err != nil {
		return err
	}
	records, err := a.readRecords()
	if err != nil {
		return err
	}
	var issued *provisionRecord
	for i := range records {
		if records[i].Kind == recordClaim && records[i].CertSerial == serial {
			issued = &records[i]
		}
	}
	if issued == nil {
		return fmt.Errorf("no claim record in %s carries certificate serial %s; this command revokes only a certificate this environment issued",
			a.relative(a.provisionRecordPath()), serial)
	}
	already, err := a.revokedSerials()
	if err != nil {
		return err
	}
	if already[serial] {
		fmt.Fprintf(a.out, "Certificate serial %s is already marked revoked.\n", serial)
		return nil
	}
	if err := os.MkdirAll(a.provisionDir(), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(revocationRecord{
		CertSerial: serial,
		Revoked:    time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(a.revokedPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Marking one Operational certificate revoked. The update service reads this")
	fmt.Fprintln(a.out, "file live, so the next request presenting that certificate is refused at")
	fmt.Fprintln(a.out, "certificate-active. The device is never told: it holds no revocation client")
	fmt.Fprintln(a.out, "in any tier, because a device that cannot check a date cannot check a list.")
	fmt.Fprintf(a.out, "  device:      %s\n", issued.DeviceID)
	fmt.Fprintf(a.out, "  owner:       %s\n", issued.OwnerID)
	fmt.Fprintf(a.out, "  serial:      %s\n", serial)
	fmt.Fprintf(a.out, "  fingerprint: %s\n", short(issued.CertFingerprint))
	fmt.Fprintf(a.out, "  recorded in: %s\n", a.relative(a.revokedPath()))
	fmt.Fprintf(a.out, "Result: certificate serial %s is revoked\n", serial)
	return nil
}

func (a *app) revokedSerials() (map[string]bool, error) {
	revoked := map[string]bool{}
	raw, err := os.ReadFile(a.revokedPath())
	if errors.Is(err, os.ErrNotExist) {
		return revoked, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record revocationRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("revocation file is corrupt: %w", err)
		}
		revoked[record.CertSerial] = true
	}
	return revoked, nil
}
