package ota

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// Recovery is the Tier 7 claim with one check replaced, not a second protocol.
//
// The press, the Claim nonce, the device half and the poll are unchanged, and
// the firmware does not know it is recovering. What changes is step 4 of
// matchAndIssue: a device that is already owned passes when its owner of record
// holds an unspent Recovery authorization for it, and is refused at
// device-unowned otherwise, as it always was.
//
// The authorization is a recorded act before the press. The owner runs
// ./course claim recover, the service revokes the device's current Operational
// certificates and writes a recovery_authorization line, and for one hour the
// owner's next claim of that device is a recovery. Nothing stops the owner
// acting alone, and that is correct: authority belongs to the owner, and the
// press is the second party. There is no recovery-authorized check, because a
// missing authorization is exactly "the device is owned", and one fact keeps
// one name.
//
// Neither kind moves a lifecycle state. A device that lost its key is still
// claimed or active as far as the log knows, which is ADR 0003's point: the
// log records what a device may do, not what it is holding.

// RecoveryAuthorizationLifetime is how long an authorization waits for the
// press, on the service clock. Once it expires it is gone, and the owner runs
// claim recover again, which revokes nothing new.
const RecoveryAuthorizationLifetime = time.Hour

// ReasonSuperseded is the CRLReason a recovery revokes the old certificate
// with by default: the identity is lost and a new one replaces it.
const ReasonSuperseded = "superseded"

// recoveryRevocationReasons is what a recovery may give. keyCompromise is for
// an owner who thinks the board was stolen rather than merely corrupted.
var recoveryRevocationReasons = map[string]bool{
	ReasonSuperseded:    true,
	ReasonKeyCompromise: true,
}

// recoveryAuthorization is one recovery_authorization line, as the service
// reads it back.
type recoveryAuthorization struct {
	ID       string
	DeviceID string
	OwnerID  string
	Expires  time.Time
	Revoked  []string
}

// authorizeRecovery is POST /v1/devices/{device_id}/recover, behind the Owner
// credential.
//
// It is held under claimMu, like the claim itself, so the authorization the
// operator half reads is never half written. The revocation goes through the
// same revoked.jsonl line the Owner's certificate revocation writes, so clause
// 2 of certificate-active refuses the old certificate the moment this answers.
func (s *Server) authorizeRecovery(w http.ResponseWriter, r *http.Request) {
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
	reason, err := recoveryReason(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	state := s.provisioningState()
	device := state.devices[deviceID]

	// device-in-service runs first here, and not beside device-unrevoked as on
	// the device listener. A decommission clears the owner of record, so
	// behind owner-of-record it could never fire. The cost is that any
	// authenticated owner learns a device is retired, which is less than
	// device-unowned already tells them.
	if device.State == lifecycle.Decommissioned {
		s.Refuse(w, r, http.StatusForbidden, Refusal{
			Check:    CheckDeviceInService,
			Reason:   "this device is decommissioned, and a decommissioned device cannot be recovered until it is remanufactured",
			DeviceID: deviceID,
		})
		return
	}
	if device.Owner == "" || device.Owner != owner {
		// owner-of-record, with the same silence the revocations keep: an
		// unowned device and one owned by somebody else are one answer.
		s.Refuse(w, r, http.StatusForbidden, Refusal{
			Check:    CheckOwnerOfRecord,
			Reason:   "you are not the owner of record for this device, and only the owner of record may authorize a recovery",
			DeviceID: deviceID,
		})
		return
	}
	// device-unrevoked, after owner-of-record: a revoked device keeps its
	// owner, so only that owner is told it is revoked. Recovery is where the
	// two revocations differ. A revoked certificate is what recovery replaces;
	// a revoked device is refused here and again on the claim route, and only
	// a remanufacture is the way out.
	if device.State == lifecycle.Revoked {
		s.Refuse(w, r, http.StatusForbidden, Refusal{
			Check:    CheckDeviceUnrevoked,
			Reason:   "this device is revoked, and a revoked device cannot be recovered until it is remanufactured",
			DeviceID: deviceID,
		})
		return
	}

	now := s.cfg.MutualTLS.now()
	if live, found := s.liveRecoveryAuthorization(deviceID, owner, now); found {
		// One authorization at a time. A second while the first is live would
		// be two ways in for one press.
		writeJSON(w, http.StatusOK, map[string]any{
			"result":                      "already-authorized",
			"device_id":                   deviceID,
			"recovery_authorization":      live.ID,
			"revoked_certificate_serials": live.Revoked,
			"expires_at":                  live.Expires.UTC().Format(time.RFC3339),
		})
		return
	}

	// Revoke every Operational certificate the device holds under this owner
	// that is not revoked already. Usually that is one; after a renewal it may
	// be two, and a lost identity leaves neither trustworthy. Running recover
	// again after an authorization expired finds them revoked and revokes
	// nothing new.
	already := s.revokedSerials()
	var revoked []string
	for serial := range device.Operational {
		if !already[serial] {
			revoked = append(revoked, serial)
		}
	}
	sort.Strings(revoked)
	for _, serial := range revoked {
		if err := s.appendRevokedSerial(serial, RoleOperational, reason, owner); err != nil {
			http.Error(w, "the old certificate could not be revoked, so nothing was authorized: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
	}

	id, err := newRecoveryAuthorizationID()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	expires := now.Add(RecoveryAuthorizationLifetime)
	if revoked == nil {
		revoked = []string{}
	}
	record := map[string]any{
		"kind":                        lifecycle.KindRecoveryAuthorization,
		"recorded_at":                 time.Now().UTC().Format(time.RFC3339Nano),
		"station":                     "course-ota-service",
		"device_id":                   deviceID,
		"owner_id":                    owner,
		"recovery_authorization":      id,
		"revoked_certificate_serials": revoked,
		"revocation_reason":           reason,
		"expires_at":                  expires.UTC().Format(time.RFC3339Nano),
		"lifecycle_state": lifecycle.StateAfter(state.records, lifecycle.Record{
			Kind: lifecycle.KindRecoveryAuthorization, DeviceID: deviceID, OwnerID: owner,
		}),
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		http.Error(w, "the recovery authorization could not be recorded: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":                      "authorized",
		"device_id":                   deviceID,
		"recovery_authorization":      id,
		"revoked_certificate_serials": revoked,
		"reason":                      reason,
		"expires_at":                  expires.UTC().Format(time.RFC3339),
		"lifecycle_state":             device.State,
	})
}

// liveRecoveryAuthorization is the newest authorization this owner gave for
// this device that no recovery has spent and the service clock has not
// expired. The caller holds claimMu.
func (s *Server) liveRecoveryAuthorization(deviceID, owner string, now time.Time) (recoveryAuthorization, bool) {
	var authorizations []recoveryAuthorization
	spent := map[string]bool{}
	forEachJSONLine(filepath.Join(s.cfg.MutualTLS.ProvisioningDir, "records.jsonl"), func(line []byte) {
		var row struct {
			Kind          string   `json:"kind"`
			DeviceID      string   `json:"device_id"`
			OwnerID       string   `json:"owner_id"`
			Authorization string   `json:"recovery_authorization"`
			Expires       string   `json:"expires_at"`
			Revoked       []string `json:"revoked_certificate_serials"`
		}
		if err := json.Unmarshal(line, &row); err != nil || row.Authorization == "" {
			return
		}
		switch row.Kind {
		case lifecycle.KindRecovery:
			spent[row.Authorization] = true
		case lifecycle.KindRecoveryAuthorization:
			expires, err := time.Parse(time.RFC3339Nano, row.Expires)
			if err != nil {
				return
			}
			authorizations = append(authorizations, recoveryAuthorization{
				ID: row.Authorization, DeviceID: row.DeviceID, OwnerID: row.OwnerID,
				Expires: expires, Revoked: row.Revoked,
			})
		}
	})
	for i := len(authorizations) - 1; i >= 0; i-- {
		candidate := authorizations[i]
		if candidate.DeviceID == deviceID && candidate.OwnerID == owner &&
			!spent[candidate.ID] && now.Before(candidate.Expires) {
			return candidate, true
		}
	}
	return recoveryAuthorization{}, false
}

// recoveryReason reads the optional reason. An empty body, or one with no
// reason, means superseded; anything outside the recovery set is a 400.
func recoveryReason(body io.Reader) (string, error) {
	if body == nil {
		return ReasonSuperseded, nil
	}
	raw, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return ReasonSuperseded, nil
	}
	var fields struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSON(strings.NewReader(string(raw)), &fields); err != nil {
		return "", err
	}
	if fields.Reason == "" {
		return ReasonSuperseded, nil
	}
	if !recoveryRevocationReasons[fields.Reason] {
		return "", fmt.Errorf("reason %q is not accepted for a recovery; use %s, or %s for a board you think was stolen",
			fields.Reason, ReasonSuperseded, ReasonKeyCompromise)
	}
	return fields.Reason, nil
}

func newRecoveryAuthorizationID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("no randomness for a recovery authorization identifier")
	}
	return "recovery-" + hex.EncodeToString(raw[:]), nil
}
