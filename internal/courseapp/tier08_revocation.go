package courseapp

// Tier 8's revocation commands, the host half.
//
// Two are the Owner's and one is the manufacturer's, and they reach two
// different places for the reason the two mechanisms are kept apart. The Owner
// revokes a certificate or a device through the OTA service, over the operator
// listener, presenting the Owner credential as a bearer token: the service is
// the only writer of the Owner's revocations. The manufacturer blocks a Factory
// identity from the station, writing revoked.jsonl directly as the station
// writes enrollment records, because there is no owner and no service in the
// manufacturer's world.
//
// The lab control ./course claim revoke stays exactly as Tier 7 left it. It
// still runs the published Tier 7 module, and it searches claim records; the
// manufacturer's block searches enrollment records, which is where Factory
// serials live, and that is the lookup Tier 8 owes the enforcement clause 2
// already carries.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// CRLReason names, from RFC 5280. Spelled on this side of the service boundary
// too, because the store the manufacturer writes and the request the Owner
// sends both name a reason and one JSON value may not mean two things.
const (
	crlReasonKeyCompromise        = "keyCompromise"
	crlReasonPrivilegeWithdrawn   = "privilegeWithdrawn"
	crlReasonCessationOfOperation = "cessationOfOperation"
)

// ownerRevocationReasons is the set the Owner may give. The manufacturer may
// give only keyCompromise: blocking a Factory identity is the answer to a
// compromised board, not to a withdrawal or a retirement, which are the Owner's
// vocabulary for a certificate.
var ownerRevocationReasons = map[string]bool{
	crlReasonKeyCompromise:        true,
	crlReasonPrivilegeWithdrawn:   true,
	crlReasonCessationOfOperation: true,
}

// tier08RevocationLine is the richer revoked.jsonl line Tier 8 writes: the
// serial the service reads for clause 2, and the role, reason, time and author
// that make the file legible as evidence rather than a bare blocklist. It is a
// superset of Tier 7's two-field line, so the service and the Tier 7 reader,
// which both read only certificate_serial, are unaffected.
type tier08RevocationLine struct {
	CertSerial string `json:"certificate_serial"`
	Role       string `json:"role"`
	Reason     string `json:"reason"`
	Revoked    string `json:"revoked_at"`
	By         string `json:"by"`
}

// ownerRevoke is the owner revoke dispatcher: certificate or device.
func (a *app) ownerRevoke(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ./course owner revoke certificate --serial <serial> --reason <CRLReason> --credential <hex>|device --device <id> --reason <CRLReason> --credential <hex>")
	}
	switch args[0] {
	case "certificate":
		return a.ownerRevokeCertificate(args[1:])
	case "device":
		return a.ownerRevokeDevice(args[1:])
	default:
		return fmt.Errorf("unknown owner revoke target %q; use certificate or device", args[0])
	}
}

// ownerRevokeCertificate stops one Operational certificate the caller owns. It
// stops a credential and not a device: the device can still recover through its
// Factory identity.
func (a *app) ownerRevokeCertificate(args []string) error {
	serial, err := flagValue(args, "--serial")
	if err != nil {
		return err
	}
	reason, credential, err := ownerRevokeFlags(args)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Revoking one Operational certificate. This stops the credential, not the")
	fmt.Fprintln(a.out, "device: a device whose certificate is revoked can still recover through its")
	fmt.Fprintln(a.out, "Factory identity. It is one-way, and nothing you can send cancels it.")
	fmt.Fprintf(a.out, "  serial: %s\n", serial)
	fmt.Fprintf(a.out, "  reason: %s\n", reason)
	fmt.Fprintln(a.out)
	return a.ownerRevokeRequest("/v1/certificates/"+serial+"/revoke", credential, reason)
}

// ownerRevokeDevice stops one device the caller owns. It is refused on every
// route, claim and recovery included, and only a remanufacture leaves the
// state.
func (a *app) ownerRevokeDevice(args []string) error {
	deviceID, err := flagValue(args, "--device")
	if err != nil {
		return err
	}
	reason, credential, err := ownerRevokeFlags(args)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Revoking one device. This stops the device itself: it can neither use nor")
	fmt.Fprintln(a.out, "obtain an Operational identity, and it is refused on every route including")
	fmt.Fprintln(a.out, "claim and recovery. It is one-way, and only a remanufacture leaves it.")
	fmt.Fprintf(a.out, "  device: %s\n", deviceID)
	fmt.Fprintf(a.out, "  reason: %s\n", reason)
	fmt.Fprintln(a.out)
	return a.ownerRevokeRequest("/v1/devices/"+deviceID+"/revoke", credential, reason)
}

// ownerRevokeFlags reads the two flags both owner revocations share, and checks
// the reason against the Owner's set here so an out-of-set value is refused
// before a request is built, with the same message the service would answer.
func ownerRevokeFlags(args []string) (reason, credential string, err error) {
	reason, err = flagValue(args, "--reason")
	if err != nil {
		return "", "", err
	}
	if !ownerRevocationReasons[reason] {
		return "", "", fmt.Errorf("reason %q is not an accepted CRLReason; use %s, %s or %s",
			reason, crlReasonKeyCompromise, crlReasonPrivilegeWithdrawn, crlReasonCessationOfOperation)
	}
	credential, err = flagValue(args, "--credential")
	if err != nil {
		return "", "", errors.New("--credential is required; it is the Owner credential ./course owner new printed once")
	}
	if strings.TrimSpace(credential) == "" {
		return "", "", errors.New("--credential is empty")
	}
	return reason, credential, nil
}

// ownerRevokeRequest sends one revocation to the operator listener and narrates
// the answer, exactly as claim approve does: the credential authorizes a
// person, so it rides the operator port as a bearer token and never the device
// listener.
func (a *app) ownerRevokeRequest(path, credential, reason string) error {
	pool, err := a.trustAnchorPool()
	if err != nil {
		return err
	}
	port := a.manifest.Runtime.OperatorTLSPort
	address := net.JoinHostPort(hostOf(a.serviceURL()), strconv.Itoa(port))
	base := "https://" + coursepki.ServiceName + ":" + strconv.Itoa(port)
	client := a.verifyingClient(pool, coursepki.ServiceName, address)

	body, err := json.Marshal(map[string]string{"reason": reason})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)

	fmt.Fprintf(a.out, "+ POST %s%s\n", base, path)
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
			return fmt.Errorf("the revocation was refused with status %d", response.StatusCode)
		}
		fmt.Fprintf(a.out, "     refused at check %s\n", refusal.Check)
		fmt.Fprintf(a.out, "     reason: %s\n", refusal.Reason)
		fmt.Fprintln(a.out)
		fmt.Fprintln(a.out, "The check name says which property did not hold, and the status does not.")
		fmt.Fprintf(a.out, "Result: the revocation was refused at %s\n", refusal.Check)
		return fmt.Errorf("refused at check %s", refusal.Check)
	}

	var done struct {
		Result     string `json:"result"`
		CertSerial string `json:"certificate_serial"`
		DeviceID   string `json:"device_id"`
		State      string `json:"lifecycle_state"`
		Reason     string `json:"reason"`
	}
	if err := json.Unmarshal(answer, &done); err != nil {
		return fmt.Errorf("the operator listener answered 200 with a body this command cannot read: %w", err)
	}
	if done.CertSerial != "" {
		fmt.Fprintf(a.out, "     result: %s\n", done.Result)
		fmt.Fprintf(a.out, "     serial: %s\n", done.CertSerial)
		fmt.Fprintf(a.out, "Result: certificate serial %s is %s\n", done.CertSerial, done.Result)
		return nil
	}
	fmt.Fprintf(a.out, "     result:          %s\n", done.Result)
	fmt.Fprintf(a.out, "     device:          %s\n", done.DeviceID)
	if done.State != "" {
		fmt.Fprintf(a.out, "     lifecycle state: %s\n", done.State)
	}
	fmt.Fprintf(a.out, "Result: device %s is %s\n", done.DeviceID, done.Result)
	return nil
}

// provisionRevoke blocks one Factory identity from the station.
//
// This is the manufacturer's operation, and it closes the recovery door: the
// Factory identity is what recovery needs, so a blocked Factory identity leaves
// only authorized re-provisioning. That is the point rather than a bug, and it
// is one-way: remanufacture, a new Factory key under a new serial, is the way
// out.
//
// It searches enrollment records, where Factory serials live. The Tier 7 lab
// control ./course claim revoke searches claim records and so cannot name a
// Factory serial at all; this is the lookup Tier 8 owes the enforcement.
func (a *app) provisionRevoke(args []string) error {
	serial, err := flagValue(args, "--serial")
	if err != nil {
		return err
	}
	reason, err := flagValue(args, "--reason")
	if err != nil {
		return err
	}
	if reason != crlReasonKeyCompromise {
		return fmt.Errorf("the manufacturer may block a Factory identity only for %s; %q is not accepted",
			crlReasonKeyCompromise, reason)
	}
	records, err := a.readRecords()
	if err != nil {
		return err
	}
	var enrolled *provisionRecord
	for i := range records {
		if records[i].Kind == recordEnrollment && records[i].Result == "issued" &&
			records[i].CertSerial == serial {
			enrolled = &records[i]
		}
	}
	if enrolled == nil {
		return fmt.Errorf("no enrollment record in %s carries Factory certificate serial %s; this command blocks a Factory identity, and Factory serials live in enrollment records",
			a.relative(a.provisionRecordPath()), serial)
	}
	already, err := a.revokedSerials()
	if err != nil {
		return err
	}
	if already[serial] {
		fmt.Fprintf(a.out, "Factory certificate serial %s is already revoked.\n", serial)
		return nil
	}
	if err := os.MkdirAll(a.provisionDir(), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(tier08RevocationLine{
		CertSerial: serial,
		Role:       "factory",
		Reason:     reason,
		Revoked:    time.Now().UTC().Format(time.RFC3339Nano),
		By:         "manufacturer",
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
	fmt.Fprintln(a.out, "Blocking one Factory identity. The update service reads this file live, so")
	fmt.Fprintln(a.out, "the next request presenting that Factory certificate is refused at")
	fmt.Fprintln(a.out, "certificate-active on every route, the claim endpoint included, because")
	fmt.Fprintln(a.out, "clause 2 does not care which authority signed the certificate.")
	fmt.Fprintf(a.out, "  device:      %s\n", enrolled.DeviceID)
	fmt.Fprintf(a.out, "  serial:      %s\n", serial)
	fmt.Fprintf(a.out, "  fingerprint: %s\n", short(enrolled.CertFingerprint))
	fmt.Fprintf(a.out, "  reason:      %s\n", reason)
	fmt.Fprintf(a.out, "  recorded in: %s\n", a.relative(a.revokedPath()))
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "This closes the recovery door: recovery needs the Factory identity. It is")
	fmt.Fprintln(a.out, "one-way, and remanufacture, a new Factory key under a new serial, is the")
	fmt.Fprintln(a.out, "manufacturer's way out.")
	fmt.Fprintf(a.out, "Result: Factory certificate serial %s is revoked\n", serial)
	return nil
}
