package ota

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// Tier 8's revocations, the Owner's half. Both are operator workflows behind
// the Owner credential, and the service is the only writer of them: a person
// asks the service to stop a certificate or a device, and the service records
// it where the enforcement already reads.
//
// The two are kept apart on purpose. Certificate revocation stops one
// credential, so a device whose Operational certificate is revoked can still
// recover through its Factory identity; it is written to revoked.jsonl and
// enforced by clause 2 of certificate-active. Device revocation stops the
// device itself, so it is refused on every route including claim and recovery;
// it is a lifecycle transition, so ADR 0003 puts it in records.jsonl as a
// revocation record and the derivation reads it. Neither copies the other's
// facts: the check name tells the Learner which thing was stopped.
//
// The manufacturer's revocation of a Factory identity is not here. It writes
// directly from the station, as the station writes enrollment records, so it
// lives in internal/courseapp. The enforcement it relies on already exists:
// clause 2 does not care about role, so a Factory serial in revoked.jsonl is
// refused on every route the moment it is written.

// CRLReason names, from RFC 5280. The course uses the enum's spelling on the
// wire, because a name a Learner can read is the whole point of naming the
// reason; there is no numeric form anywhere.
const (
	ReasonKeyCompromise        = "keyCompromise"
	ReasonPrivilegeWithdrawn   = "privilegeWithdrawn"
	ReasonCessationOfOperation = "cessationOfOperation"
)

// ownerRevocationReasons is the fixed set an Owner may give. A reason from a
// closed vocabulary is what lets the fleet tell a key compromise from a
// decommissioning later; anything outside it is a 400. Transfer and
// decommissioning reuse privilegeWithdrawn and cessationOfOperation when they
// revoke a certificate.
var ownerRevocationReasons = map[string]bool{
	ReasonKeyCompromise:        true,
	ReasonPrivilegeWithdrawn:   true,
	ReasonCessationOfOperation: true,
}

// revokeCertificate stops one Operational certificate the caller owns, at
// POST /v1/certificates/{serial}/revoke.
//
// The record is the authority on whose certificate this is, not the caller: a
// serial the service has no claim record for, or one issued to another owner,
// is refused at owner-of-record without saying which. It is one-way; there is
// no route that writes a line cancelling this one.
func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	owner, ok := OwnerFrom(r.Context())
	if !ok {
		http.Error(w, "no authenticated owner on this request", http.StatusInternalServerError)
		return
	}
	serial := r.PathValue("serial")
	if serial == "" {
		http.Error(w, "a certificate serial is required in the path", http.StatusBadRequest)
		return
	}
	reason, err := ownerRevocationReason(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	state := s.provisioningState()
	certOwner, deviceID, found := operationalCertOwner(state, serial)
	device := state.devices[deviceID]
	notYours := !found || certOwner != owner || device.Owner != owner
	if found && device.State == lifecycle.Decommissioned {
		// The device checks every Owner operation runs, in the same order; see
		// ownerRouteRefusal. device-in-service first, because a decommission
		// clears the owner of record and owner-of-record would hide it.
		notYours = false
	}
	if notYours {
		// owner-of-record: silent about who the owner is, and about whether the
		// serial was ever issued at all. The caller learns only that it is not
		// an Operational certificate they own. The claim record naming the
		// caller is not enough: the device must still be theirs, so an owner who
		// gave a device up in a transfer cannot reach its old certificates.
		s.Refuse(w, r, http.StatusForbidden, Refusal{
			Check:  CheckOwnerOfRecord,
			Reason: fmt.Sprintf("certificate serial %s is not an Operational certificate you own", serial),
		})
		return
	}
	if refusal := ownerRouteRefusal(deviceID, device, owner, "revoked"); refusal != nil {
		s.Refuse(w, r, http.StatusForbidden, *refusal)
		return
	}
	if s.revokedSerials()[serial] {
		// One-way and idempotent: re-asking does not append a second line.
		writeJSON(w, http.StatusOK, map[string]any{
			"result":             "already-revoked",
			"certificate_serial": serial,
			"device_id":          deviceID,
		})
		return
	}
	if err := s.appendRevokedSerial(serial, RoleOperational, reason, owner); err != nil {
		http.Error(w, "the revocation could not be recorded: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":             "revoked",
		"certificate_serial": serial,
		"role":               RoleOperational,
		"reason":             reason,
		"device_id":          deviceID,
		"by":                 owner,
	})
}

// revokeDevice stops one device the caller owns, at
// POST /v1/devices/{device_id}/revoke.
//
// It appends a revocation record and the derivation moves the device to
// revoked, where device-unrevoked refuses it on every route. It is held under
// claimMu, like the claim and the activation, so the line it writes is derived
// from the log as it stands when the line is written. It is one-way; only a
// remanufacture leaves the state.
func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	owner, ok := OwnerFrom(r.Context())
	if !ok {
		http.Error(w, "no authenticated owner on this request", http.StatusInternalServerError)
		return
	}
	deviceID := r.PathValue("device_id")
	if deviceID == "" {
		http.Error(w, "a device identifier is required in the path", http.StatusBadRequest)
		return
	}
	reason, err := ownerRevocationReason(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	state := s.provisioningState()
	device := state.devices[deviceID]
	// device-in-service, owner-of-record, device-unrevoked. An unowned device
	// and one owned by somebody else are one owner-of-record answer, naming
	// neither the owner nor whether the device exists beyond the identifier the
	// caller already sent. A device revoked already is refused at
	// device-unrevoked rather than answered as a success: it is the one fact
	// the owner is asking about, and it already has a check name.
	if refusal := ownerRouteRefusal(deviceID, device, owner, "revoked"); refusal != nil {
		s.Refuse(w, r, http.StatusForbidden, *refusal)
		return
	}
	next := lifecycle.Record{Kind: lifecycle.KindRevocation, DeviceID: deviceID, OwnerID: owner}
	record := map[string]any{
		"kind":            lifecycle.KindRevocation,
		"recorded_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"station":         "course-ota-service",
		"device_id":       deviceID,
		"owner_id":        owner,
		"reason":          reason,
		"revoked_by":      owner,
		"lifecycle_state": lifecycle.StateAfter(state.records, next),
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		http.Error(w, "the revocation could not be recorded: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":          "revoked",
		"device_id":       deviceID,
		"reason":          reason,
		"lifecycle_state": lifecycle.Revoked,
		"by":              owner,
	})
}

// operationalCertOwner is who a serial's issuing record names as its owner, and
// the device it was issued to. A recovered or renewed certificate is the
// Owner's to revoke as much as a claimed one is. Serials are unique, so at most
// one claim, recovery or renewal record carries any of them.
func operationalCertOwner(state provisioningState, serial string) (owner, deviceID string, found bool) {
	issued, found := state.issuances[serial]
	if !found {
		return "", "", false
	}
	return issued.ownerID, issued.deviceID, true
}

// ownerRevocationReason reads and validates the reason a revocation body
// carries. A missing or out-of-set reason is a 400: the reason is a required
// value from the CRLReason set, not free text.
func ownerRevocationReason(body io.Reader) (string, error) {
	var fields struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSON(body, &fields); err != nil {
		return "", err
	}
	if fields.Reason == "" {
		return "", errors.New("a reason is required, from the CRLReason set: keyCompromise, privilegeWithdrawn, cessationOfOperation")
	}
	if !ownerRevocationReasons[fields.Reason] {
		return "", fmt.Errorf("reason %q is not an accepted CRLReason; use keyCompromise, privilegeWithdrawn or cessationOfOperation", fields.Reason)
	}
	return fields.Reason, nil
}

// appendRevokedSerial writes one richer line of revoked.jsonl: the serial the
// service reads for clause 2, plus the role, reason, time and author that make
// the file legible as evidence rather than a bare blocklist.
//
// The refusal guard appendProvisioningRecord carries is unnecessary here: no
// field this line holds is key material. It takes s.mu, the mutex the event
// log takes, so two writers append whole lines.
func (s *Server) appendRevokedSerial(serial, role, reason, by string) error {
	row := map[string]any{
		"certificate_serial": serial,
		"role":               role,
		"reason":             reason,
		"revoked_at":         time.Now().UTC().Format(time.RFC3339Nano),
		"by":                 by,
	}
	line, err := json.Marshal(row)
	if err != nil {
		return err
	}
	dir := s.cfg.MutualTLS.ProvisioningDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(filepath.Join(dir, "revoked.jsonl"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(line, '\n'))
	return err
}
