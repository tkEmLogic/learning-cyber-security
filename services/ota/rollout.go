package ota

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// Tier 9's rollouts, pause and withdrawal, the service's half.
//
// Every device polls the same route, GET /v1/releases/current, and until now
// every device got the same answer. From here the answer is worked out per
// device, at poll time, from the append-only events in records.jsonl:
//
//   - a device no open rollout covers gets the Fleet baseline, which is the
//     record PUT /v1/releases/current sets and which it normally already runs;
//   - a device a rollout covers gets the rollout's release. The Canary group is
//     covered from the start, every other claimed, active device from the
//     advance, and a device the service has already served the release to
//     stays covered through a pause, so a download it began can resume.
//
// There is no "no assignment" answer on the wire. A Tier 8 board treats an
// empty assignment as an error, so a device outside every rollout gets the
// baseline and refuses it as already-confirmed, as it does today. The shape
// of the answer does not change at all: a Tier 8 board cannot tell a rollout
// is happening unless it is in one.
//
// There is no mutable per-device file. What a device is offered is derived
// from the log, the way its lifecycle state already is, so the log is the one
// place that says why a device got what it got.
//
// Only one rollout is open at a time, so each device has exactly one target.
// Withdrawal closes a rollout and its release is never served again. The fix
// is a separate rollout of a newer release, and until it reaches a device that
// runs the withdrawn release, that device is offered the baseline and refuses
// it as a rollback. That gap is the "fix not yet available" state.
//
// Every action here is a manufacturer's, on the operator listener, behind the
// listener boundary and the marker header like the baseline PUT. None is under
// Owner scope. The actor is a stated field and nothing authenticates it, which
// is T9-W-37: an unauthorised pause or withdrawal is an availability attack.

// The operator-listener routes this tier adds, in one place, so the module and
// `./course` can be written from this list.
//
//	POST /v1/rollouts
//	    {"release": <Release>, "canary_device_ids": ["..."], "actor": "..."}
//	    Starts a rollout of the release record to the named Canary group. The
//	    record is the same shape PUT /v1/releases/current takes, because the
//	    service never parses a Release manifest and so cannot build one.
//	GET  /v1/rollouts/current
//	    Reads back the rollout state the log derives, so a command that just
//	    changed it can show what it changed.
//	POST /v1/rollouts/current/advance   {"actor": "..."}
//	    Offers the release to every other claimed, active device.
//	POST /v1/rollouts/current/pause     {"actor": "..."}
//	POST /v1/rollouts/current/resume    {"actor": "..."}
//	POST /v1/rollouts/current/complete  {"actor": "..."}
//	    Closes an advanced rollout by making its release the Fleet baseline.
//	POST /v1/releases/{release_id}/withdraw  {"reason": "...", "actor": "..."}
//	    The reason is the vulnerability record's identifier.
//	POST /v1/releases/{release_id}/approve   {"image_path": "...", "actor": "..."}
//	    See approval.go.
//
// Refusals use the Refusal shape and answer 409. A request without the marker
// header is 403, and a malformed one 400, exactly as on the baseline PUT.
const (
	RouteRolloutStart    = "POST /v1/rollouts"
	RouteRolloutCurrent  = "GET /v1/rollouts/current"
	RouteRolloutAdvance  = "POST /v1/rollouts/current/advance"
	RouteRolloutPause    = "POST /v1/rollouts/current/pause"
	RouteRolloutResume   = "POST /v1/rollouts/current/resume"
	RouteRolloutComplete = "POST /v1/rollouts/current/complete"
	RouteReleaseWithdraw = "POST /v1/releases/{release_id}/withdraw"
	RouteReleaseApprove  = "POST /v1/releases/{release_id}/approve"
)

// The event kinds this tier appends to records.jsonl. None of them moves a
// device's lifecycle state, so they live here and not in internal/lifecycle.
// Only rollout.served carries a device_id, and lifecycle.Derive passes over a
// kind it does not know.
const (
	KindRolloutStarted   = "rollout.started"
	KindRolloutAdvanced  = "rollout.advanced"
	KindRolloutPaused    = "rollout.paused"
	KindRolloutResumed   = "rollout.resumed"
	KindRolloutCompleted = "rollout.completed"
	KindReleaseWithdrawn = "release.withdrawn"
	KindReleaseApproved  = "release.approved"

	// KindRolloutServed is the service's own fact that it offered a rollout's
	// release to one device. It is what a pause keeps serving, and it is the
	// service's observation rather than something the device reports, so a
	// device cannot talk its way into or out of a paused rollout.
	KindRolloutServed = "rollout.served"
)

// Tier 9's checks. Each answers 409: every one is the log or the release store
// disagreeing with the request, and none is about who is asking.
const (
	// CheckReleaseApproved holds when the release has an approval record and
	// every artifact it links is unchanged. It runs at rollout start, advance,
	// resume and complete, and on the baseline PUT when the service runs with
	// release approval on (Tier 9).
	CheckReleaseApproved = "release-approved"

	// CheckReleaseWithdrawn holds when the release has not been withdrawn. A
	// withdrawn release keeps its approval, and withdrawal still wins.
	CheckReleaseWithdrawn = "release-withdrawn"

	// CheckNoOpenRollout holds when no rollout is open. A rollout start needs
	// it, because each device has exactly one target, and so does the baseline
	// PUT, because moving the baseline under an open rollout changes what
	// every device outside it is offered.
	CheckNoOpenRollout = "no-open-rollout"

	// CheckRolloutOpen holds when a rollout is open, for the steps that act on
	// one.
	CheckRolloutOpen = "rollout-open"

	// CheckRolloutRunning holds when the open rollout is not paused. Advance
	// and complete need it: a pause is a decision to stop, and moving on from
	// it is what resume is for.
	CheckRolloutRunning = "rollout-running"

	// CheckRolloutAdvanced holds when the open rollout has reached the whole
	// fleet. Complete needs it, so the baseline never skips the canary review.
	CheckRolloutAdvanced = "rollout-advanced"

	// CheckNotFleetBaseline holds when the release being withdrawn is not the
	// Fleet baseline. The baseline is what every device outside a rollout is
	// offered, and there is no empty answer to fall back to, so it moves
	// first, by a rollout of its replacement.
	CheckNotFleetBaseline = "not-fleet-baseline"

	// The approval's own three. See approval.go.
	CheckFirstApproval           = "first-approval"
	CheckReleaseArtifactsPresent = "release-artifacts-present"
	CheckBuildTreeClean          = "build-tree-clean"
)

// The two stages of a rollout.
const (
	stageCanary = "canary"
	stageFleet  = "fleet"
)

// rollout is the one open rollout, as the log derives it.
type rollout struct {
	release Release
	canary  map[string]bool
	stage   string
	paused  bool
	served  map[string]bool
	actor   string
}

// rolloutState is the rollout and approval events, replayed.
type rolloutState struct {
	open      *rollout
	approvals map[string]map[string]approvedArtifact
	withdrawn map[string]bool
}

// rolloutLine is what the service reads of one rollout or approval line. The
// provisioning station reads the same file and ignores every field here it
// does not know, which is why none of these reuses a station field name with a
// different type.
type rolloutLine struct {
	Kind            string                      `json:"kind"`
	ReleaseID       string                      `json:"release_id"`
	Release         *Release                    `json:"release"`
	CanaryDeviceIDs []string                    `json:"canary_device_ids"`
	DeviceID        string                      `json:"device_id"`
	Actor           string                      `json:"actor"`
	Artifacts       map[string]approvedArtifact `json:"artifacts"`
}

// rolloutState replays records.jsonl for the events this tier writes.
//
// A line that does not fit the state it arrives in moves nothing, as in
// internal/lifecycle: an advance with no open rollout, a served line for a
// release that is not the open rollout's, a second approval. The log is append
// only and has more than one writer, so it may hold such lines, and none of
// them can open a second rollout or unwithdraw a release.
func (s *Server) rolloutState() rolloutState {
	state := rolloutState{
		approvals: map[string]map[string]approvedArtifact{},
		withdrawn: map[string]bool{},
	}
	if s.cfg.MutualTLS == nil {
		return state
	}
	forEachJSONLine(filepath.Join(s.cfg.MutualTLS.ProvisioningDir, "records.jsonl"), func(raw []byte) {
		var line rolloutLine
		if err := json.Unmarshal(raw, &line); err != nil {
			return
		}
		open := state.open
		matches := open != nil && line.ReleaseID == open.release.ReleaseID
		switch line.Kind {
		case KindReleaseApproved:
			if _, seen := state.approvals[line.ReleaseID]; !seen && line.ReleaseID != "" {
				state.approvals[line.ReleaseID] = line.Artifacts
			}
		case KindRolloutStarted:
			if open != nil || line.Release == nil || line.Release.ReleaseID != line.ReleaseID ||
				state.withdrawn[line.ReleaseID] {
				return
			}
			canary := map[string]bool{}
			for _, id := range line.CanaryDeviceIDs {
				canary[id] = true
			}
			state.open = &rollout{
				release: *line.Release,
				canary:  canary,
				stage:   stageCanary,
				served:  map[string]bool{},
				actor:   line.Actor,
			}
		case KindRolloutAdvanced:
			if matches {
				open.stage = stageFleet
			}
		case KindRolloutPaused:
			if matches {
				open.paused = true
			}
		case KindRolloutResumed:
			if matches {
				open.paused = false
			}
		case KindRolloutServed:
			if matches && line.DeviceID != "" {
				open.served[line.DeviceID] = true
			}
		case KindRolloutCompleted:
			if matches {
				state.open = nil
			}
		case KindReleaseWithdrawn:
			if line.ReleaseID == "" {
				return
			}
			state.withdrawn[line.ReleaseID] = true
			if matches {
				state.open = nil
			}
		}
	})
	return state
}

// offers says whether the open rollout offers its release to this device. The
// served clause comes first, so a pause never takes back what it already gave.
func (o *rollout) offers(deviceID string, device lifecycle.Device) bool {
	switch {
	case o.served[deviceID]:
		return true
	case o.paused:
		return false
	case o.canary[deviceID]:
		return true
	case o.stage == stageFleet:
		return device.State == lifecycle.Active
	}
	return false
}

// assignmentFor is one device's Update assignment: the open rollout's release
// if the rollout offers it to this device, and the Fleet baseline otherwise.
// The second result says whether it came from the rollout.
func (s *Server) assignmentFor(deviceID string) (Release, bool, error) {
	baseline, err := s.loadRelease()
	if err != nil {
		return baseline, false, err
	}
	open := s.rolloutState().open
	if open == nil {
		return baseline, false, nil
	}
	device := s.provisioningState().devices[deviceID]
	if !open.offers(deviceID, device) {
		return baseline, false, nil
	}
	return open.release, true, nil
}

// recordServed appends the rollout.served line the first time the service
// offers a rollout's release to a device. Like the activation line, it is
// guarded by the log read again under claimMu, so two polls racing write one
// line, and a line that cannot be written is logged rather than refused: the
// next poll tries again.
func (s *Server) recordServed(deviceID string, release Release) {
	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	open := s.rolloutState().open
	if open == nil || open.release.ReleaseID != release.ReleaseID || open.served[deviceID] {
		return
	}
	record := map[string]any{
		"kind":        KindRolloutServed,
		"recorded_at": time.Now().UTC().Format(time.RFC3339Nano),
		"station":     serviceStation,
		"release_id":  release.ReleaseID,
		"device_id":   deviceID,
		"stage":       open.stage,
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		log.Printf("release %s was served to %s but that could not be recorded: %v", release.ReleaseID, deviceID, err)
	}
}

// deviceFirmware is GET /v1/firmware/{name} on the device listener. It serves
// the image of the device's own assignment, so a canary device can download
// the release it was offered and no device can download one it was not. A
// withdrawn release is never any device's assignment, so its image is never
// served again either.
func (s *Server) deviceFirmware(w http.ResponseWriter, r *http.Request) {
	identity, ok := DeviceFrom(r.Context())
	if !ok {
		s.firmware(w, r)
		return
	}
	release, _, err := s.assignmentFor(identity.DeviceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.serveFirmware(w, r, release)
}

// rolloutRoutes are this tier's operator-listener routes. See the list above.
func (s *Server) rolloutRoutes() []deviceRoute {
	return []deviceRoute{
		{pattern: RouteRolloutStart, handler: http.HandlerFunc(s.startRollout)},
		{pattern: RouteRolloutCurrent, handler: http.HandlerFunc(s.currentRollout)},
		{pattern: RouteRolloutAdvance, handler: s.rolloutStep(KindRolloutAdvanced)},
		{pattern: RouteRolloutPause, handler: s.rolloutStep(KindRolloutPaused)},
		{pattern: RouteRolloutResume, handler: s.rolloutStep(KindRolloutResumed)},
		{pattern: RouteRolloutComplete, handler: s.rolloutStep(KindRolloutCompleted)},
		{pattern: RouteReleaseWithdraw, handler: http.HandlerFunc(s.withdrawRelease)},
		{pattern: RouteReleaseApprove, handler: http.HandlerFunc(s.approveRelease)},
	}
}

// startRollout is POST /v1/rollouts.
func (s *Server) startRollout(w http.ResponseWriter, r *http.Request) {
	if !s.markerHeaderMatches(r) {
		http.Error(w, "course environment marker mismatch", http.StatusForbidden)
		return
	}
	var request struct {
		Release         Release  `json:"release"`
		CanaryDeviceIDs []string `json:"canary_device_ids"`
		Actor           string   `json:"actor"`
	}
	if err := decodeJSON(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	release := request.Release
	if err := s.validateRelease(release); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !validReleaseID(release.ReleaseID) {
		http.Error(w, "invalid release_id", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Actor) == "" {
		http.Error(w, "actor is required: a rollout says who started it", http.StatusBadRequest)
		return
	}
	canary, err := canaryGroup(request.CanaryDeviceIDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The same two values the baseline PUT forces, so a release record means
	// the same thing whichever route offered it.
	release.Mutable = true
	release.Signed = false

	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	state := s.rolloutState()
	if state.open != nil {
		s.Refuse(w, r, http.StatusConflict, Refusal{
			Check: CheckNoOpenRollout,
			Reason: fmt.Sprintf("the rollout of release %s is still open, and one rollout is open at a time; complete or withdraw it first",
				state.open.release.ReleaseID),
		})
		return
	}
	if state.withdrawn[release.ReleaseID] {
		s.Refuse(w, r, http.StatusConflict, withdrawnRefusal(release.ReleaseID))
		return
	}
	if refusal := s.releaseApproved(state, release); refusal != nil {
		s.Refuse(w, r, http.StatusConflict, *refusal)
		return
	}
	record := map[string]any{
		"kind":              KindRolloutStarted,
		"recorded_at":       time.Now().UTC().Format(time.RFC3339Nano),
		"station":           serviceStation,
		"release_id":        release.ReleaseID,
		"release":           release,
		"canary_device_ids": canary,
		"actor":             request.Actor,
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		http.Error(w, "the rollout could not be recorded, so it did not start: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":            "started",
		"release_id":        release.ReleaseID,
		"stage":             stageCanary,
		"canary_device_ids": canary,
		"actor":             request.Actor,
	})
}

// canaryGroup checks the list a rollout names. It is never empty, because a
// rollout with no canary would reach the fleet with nothing to review, and it
// is sorted and without repeats, so the recorded group reads the same however
// it was typed.
func canaryGroup(ids []string) ([]string, error) {
	seen := map[string]bool{}
	var group []string
	for _, id := range ids {
		if !validReleaseID(id) {
			return nil, fmt.Errorf("canary device id %q is not a device identifier", id)
		}
		if !seen[id] {
			seen[id] = true
			group = append(group, id)
		}
	}
	if len(group) == 0 {
		return nil, fmt.Errorf("canary_device_ids is required: a rollout names its Canary group")
	}
	sort.Strings(group)
	return group, nil
}

// rolloutStep serves advance, pause, resume and complete, which are one shape:
// an actor, a step on the open rollout, one line in the log.
//
// Asking for the state the rollout is already in writes nothing and says so,
// the way a second renewal request does, so a repeated command is not a second
// fact. Advance, resume and complete check the approval's digests again first,
// because each one offers the release to devices that have not had it yet.
func (s *Server) rolloutStep(kind string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.markerHeaderMatches(r) {
			http.Error(w, "course environment marker mismatch", http.StatusForbidden)
			return
		}
		var request struct {
			Actor string `json:"actor"`
		}
		if err := decodeJSON(r.Body, &request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(request.Actor) == "" {
			http.Error(w, "actor is required: every rollout step says who took it", http.StatusBadRequest)
			return
		}

		s.claimMu.Lock()
		defer s.claimMu.Unlock()

		state := s.rolloutState()
		open := state.open
		if open == nil {
			s.Refuse(w, r, http.StatusConflict, Refusal{
				Check:  CheckRolloutOpen,
				Reason: "no rollout is open; start one with POST /v1/rollouts",
			})
			return
		}
		releaseID := open.release.ReleaseID
		already := ""
		switch kind {
		case KindRolloutAdvanced:
			if open.paused {
				s.Refuse(w, r, http.StatusConflict, Refusal{
					Check:  CheckRolloutRunning,
					Reason: fmt.Sprintf("the rollout of release %s is paused; resume it before advancing", releaseID),
				})
				return
			}
			if open.stage == stageFleet {
				already = "already-advanced"
			}
		case KindRolloutPaused:
			if open.paused {
				already = "already-paused"
			}
		case KindRolloutResumed:
			if !open.paused {
				already = "already-running"
			}
		case KindRolloutCompleted:
			if open.paused {
				s.Refuse(w, r, http.StatusConflict, Refusal{
					Check:  CheckRolloutRunning,
					Reason: fmt.Sprintf("the rollout of release %s is paused; resume it before completing", releaseID),
				})
				return
			}
			if open.stage != stageFleet {
				s.Refuse(w, r, http.StatusConflict, Refusal{
					Check:  CheckRolloutAdvanced,
					Reason: fmt.Sprintf("the rollout of release %s has reached only its Canary group; advance it before completing", releaseID),
				})
				return
			}
		}
		if already != "" {
			writeJSON(w, http.StatusOK, map[string]any{"result": already, "release_id": releaseID})
			return
		}
		if kind != KindRolloutPaused {
			if refusal := s.releaseApproved(state, open.release); refusal != nil {
				s.Refuse(w, r, http.StatusConflict, *refusal)
				return
			}
		}
		// Complete moves the baseline before it closes the rollout. If the
		// line then fails, the rollout is still open over a baseline that is
		// already its release, and a retry finishes it. The other order could
		// close the rollout over the old baseline and offer the fleet a
		// rollback.
		if kind == KindRolloutCompleted {
			if err := s.saveRelease(open.release); err != nil {
				http.Error(w, "the Fleet baseline could not be moved, so the rollout stays open: "+err.Error(),
					http.StatusInternalServerError)
				return
			}
		}
		record := map[string]any{
			"kind":        kind,
			"recorded_at": time.Now().UTC().Format(time.RFC3339Nano),
			"station":     serviceStation,
			"release_id":  releaseID,
			"actor":       request.Actor,
		}
		if err := s.appendProvisioningRecord(record); err != nil {
			http.Error(w, "the rollout step could not be recorded, so it did not happen: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"result":     strings.TrimPrefix(kind, "rollout."),
			"release_id": releaseID,
			"actor":      request.Actor,
		})
	})
}

// withdrawRelease is POST /v1/releases/{release_id}/withdraw.
//
// It closes the rollout if the release is the open rollout's, and it marks the
// release as never to be served again whether or not one was open. It does not
// start the fix: that is a separate rollout, because the fix is a separate
// release with its own approval.
func (s *Server) withdrawRelease(w http.ResponseWriter, r *http.Request) {
	if !s.markerHeaderMatches(r) {
		http.Error(w, "course environment marker mismatch", http.StatusForbidden)
		return
	}
	releaseID := r.PathValue("release_id")
	if !validReleaseID(releaseID) {
		http.Error(w, "invalid release_id", http.StatusBadRequest)
		return
	}
	var request struct {
		Reason string `json:"reason"`
		Actor  string `json:"actor"`
	}
	if err := decodeJSON(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Reason) == "" {
		http.Error(w, "reason is required: a withdrawal names the vulnerability record it answers", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Actor) == "" {
		http.Error(w, "actor is required: a withdrawal says who withdrew", http.StatusBadRequest)
		return
	}

	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	state := s.rolloutState()
	if state.withdrawn[releaseID] {
		writeJSON(w, http.StatusOK, map[string]any{"result": "already-withdrawn", "release_id": releaseID})
		return
	}
	if baseline, err := s.loadRelease(); err == nil && baseline.ReleaseID == releaseID {
		s.Refuse(w, r, http.StatusConflict, Refusal{
			Check: CheckNotFleetBaseline,
			Reason: fmt.Sprintf("release %s is the Fleet baseline, which every device outside a rollout is offered; roll out its replacement and complete that rollout first",
				releaseID),
		})
		return
	}
	closes := state.open != nil && state.open.release.ReleaseID == releaseID
	record := map[string]any{
		"kind":           KindReleaseWithdrawn,
		"recorded_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"station":        serviceStation,
		"release_id":     releaseID,
		"reason":         request.Reason,
		"actor":          request.Actor,
		"rollout_closed": closes,
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		http.Error(w, "the withdrawal could not be recorded, so the release is still offered: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":         "withdrawn",
		"release_id":     releaseID,
		"reason":         request.Reason,
		"actor":          request.Actor,
		"rollout_closed": closes,
	})
}

// currentRollout is GET /v1/rollouts/current: the state the log derives, for
// the lab bench to read back. It changes nothing, so it does not need the
// marker header, like the operator copy of GET /v1/releases/current.
func (s *Server) currentRollout(w http.ResponseWriter, _ *http.Request) {
	state := s.rolloutState()
	approved := sortedKeys(state.approvals)
	withdrawn := sortedKeys(state.withdrawn)
	if state.open == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"open":                  false,
			"approved_release_ids":  approved,
			"withdrawn_release_ids": withdrawn,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"open":                  true,
		"release_id":            state.open.release.ReleaseID,
		"release":               state.open.release,
		"stage":                 state.open.stage,
		"paused":                state.open.paused,
		"canary_device_ids":     sortedKeys(state.open.canary),
		"served_device_ids":     sortedKeys(state.open.served),
		"started_by":            state.open.actor,
		"approved_release_ids":  approved,
		"withdrawn_release_ids": withdrawn,
	})
}

// baselineRefusal is what the baseline PUT asks of the rollout state when the
// service runs with mutual TLS. Without it there is no log to ask, and Tiers 0
// to 6 are unchanged.
//
// It must be called under claimMu, so a rollout cannot start between the check
// and the write.
func (s *Server) baselineRefusal(release Release) *Refusal {
	if s.cfg.MutualTLS == nil {
		return nil
	}
	state := s.rolloutState()
	if state.open != nil {
		return &Refusal{
			Check: CheckNoOpenRollout,
			Reason: fmt.Sprintf("the rollout of release %s is open, and the Fleet baseline does not move under an open rollout; complete or withdraw it first",
				state.open.release.ReleaseID),
		}
	}
	if state.withdrawn[release.ReleaseID] {
		refusal := withdrawnRefusal(release.ReleaseID)
		return &refusal
	}
	// From Tier 9 only, so the PUT is not an unapproved side door. Tiers 7
	// and 8 run without release approval and keep the PUT they have.
	if s.cfg.ReleaseApproval {
		return s.releaseApproved(state, release)
	}
	return nil
}

func withdrawnRefusal(releaseID string) Refusal {
	return Refusal{
		Check:  CheckReleaseWithdrawn,
		Reason: fmt.Sprintf("release %s has been withdrawn, and a withdrawn release is never offered again", releaseID),
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
