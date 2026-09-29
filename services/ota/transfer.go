package ota

import (
	"net/http"
	"sort"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// An Ownership transfer is two acts, and this is the first.
//
// The owner of record gives the device up: ./course owner transfer revokes the
// device's Operational certificates as privilegeWithdrawn, voids any open
// Recovery authorization, and writes a transfer line. The derivation then
// rests the device in transferred, owned by no one, and it stays there until
// the second act, which is the unchanged Tier 7 claim by whoever holds the
// board and presses its button. Step 4 of matchAndIssue passes that claim
// because the device is not owned, and nothing else about the claim changes.
//
// It follows the pattern recovery set: an act recorded before the press, then
// the ordinary claim. The old owner's consent is required and the release is
// open. The transfer names no recipient, because the press binds the device to
// the person holding it, and a new owner cannot force a transfer, because
// letting possession override the owner would be the universal recovery path
// #214 refused.
//
// A transferred device cannot reach the OTA service at all. Its certificates
// are in revoked.jsonl, so clause 2 of certificate-active refuses them on every
// route, and the Factory identity reaches only the claim route. That is also
// why no transferred check exists: the certificate is what the old owner still
// holds, and certificate-active already names what is wrong with it.

// transferDevice is POST /v1/devices/{device_id}/transfer, behind the Owner
// credential.
//
// It is held under claimMu, like the claim and the recovery authorization, so
// the line it writes is derived from the log as it stands and a claim window
// cannot be matched halfway through it. The request has no body: the CRLReason
// is always privilegeWithdrawn, because a transfer withdraws the old owner's
// privilege and says nothing about the key.
func (s *Server) transferDevice(w http.ResponseWriter, r *http.Request) {
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

	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	state := s.provisioningState()
	device := state.devices[deviceID]
	if refusal := ownerRouteRefusal(deviceID, device, owner, "transferred"); refusal != nil {
		s.Refuse(w, r, http.StatusForbidden, *refusal)
		return
	}

	// Every Operational certificate the device holds under this owner that is
	// not revoked already: usually one, two during a renewal overlap. Each goes
	// through the Owner's revocation machinery, so the old owner's certificate
	// is refused at certificate-active the moment this answers.
	already := s.revokedSerials()
	var revoked []string
	for serial := range device.Operational {
		if !already[serial] {
			revoked = append(revoked, serial)
		}
	}
	sort.Strings(revoked)
	for _, serial := range revoked {
		if err := s.appendRevokedSerial(serial, RoleOperational, ReasonPrivilegeWithdrawn, owner); err != nil {
			http.Error(w, "the old certificate could not be revoked, so nothing was transferred: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
	}
	if revoked == nil {
		revoked = []string{}
	}

	// A transfer voids an open Recovery authorization and names it, so the log
	// never holds a live authorization for somebody who is not the owner.
	now := s.cfg.MutualTLS.now()
	voided := ""
	if live, found := s.liveRecoveryAuthorization(deviceID, owner, now); found {
		voided = live.ID
	}

	record := map[string]any{
		"kind":                        lifecycle.KindTransfer,
		"recorded_at":                 time.Now().UTC().Format(time.RFC3339Nano),
		"station":                     "course-ota-service",
		"device_id":                   deviceID,
		"owner_id":                    owner,
		"revoked_certificate_serials": revoked,
		"revocation_reason":           ReasonPrivilegeWithdrawn,
		"lifecycle_state": lifecycle.StateAfter(state.records, lifecycle.Record{
			Kind: lifecycle.KindTransfer, DeviceID: deviceID, OwnerID: owner,
		}),
	}
	if voided != "" {
		record["voided_recovery_authorization"] = voided
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		http.Error(w, "the transfer could not be recorded: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// A claim window the device opened before the transfer was opened while
	// somebody owned it. It closes here, so the new owner's claim starts with a
	// press made after the device was given up.
	if window := s.claimWindows[deviceID]; window != nil {
		s.recordClaimEvent(deviceID, "closed", window.nonceVerifier,
			"the device was given up in an ownership transfer")
		delete(s.claimWindows, deviceID)
	}

	answer := map[string]any{
		"result":                      "transferred",
		"device_id":                   deviceID,
		"revoked_certificate_serials": revoked,
		"reason":                      ReasonPrivilegeWithdrawn,
		"lifecycle_state":             lifecycle.Transferred,
		"by":                          owner,
	}
	if voided != "" {
		answer["voided_recovery_authorization"] = voided
	}
	writeJSON(w, http.StatusOK, answer)
}

// ownerRouteRefusal is the three checks every Owner operation on a device runs,
// in the order recovery settled: device-in-service, owner-of-record,
// device-unrevoked. what is the past participle the reasons use, such as
// "revoked" or "transferred"; the owner-of-record reason needs none, because it
// is the same answer whatever was asked.
//
// device-in-service runs first because a decommission clears the owner of
// record, so behind owner-of-record it could never fire. The cost is that any
// authenticated owner learns a device is retired, which is less than
// device-unowned already tells them. device-unrevoked runs after
// owner-of-record because a revoked device keeps its owner, so only that owner
// is told it is revoked. owner-of-record is silent about who the owner is, and
// an unowned device and one owned by somebody else are one answer.
func ownerRouteRefusal(deviceID string, device lifecycle.Device, owner, what string) *Refusal {
	if device.State == lifecycle.Decommissioned {
		return &Refusal{
			Check:    CheckDeviceInService,
			Reason:   "this device is decommissioned, and a decommissioned device cannot be " + what + " until it is remanufactured",
			DeviceID: deviceID,
		}
	}
	if device.Owner == "" || device.Owner != owner {
		return &Refusal{
			Check:    CheckOwnerOfRecord,
			Reason:   "you are not the owner of record for this device",
			DeviceID: deviceID,
		}
	}
	if device.State == lifecycle.Revoked {
		return &Refusal{
			Check:    CheckDeviceUnrevoked,
			Reason:   "this device is revoked, and a revoked device cannot be " + what + " until it is remanufactured",
			DeviceID: deviceID,
		}
	}
	return nil
}
