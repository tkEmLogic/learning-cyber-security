package ota

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// Tier 8's renewal, the service's half.
//
// Renewal replaces a device's Operational identity with one on a new key,
// before the old one expires, for the same owner. The current Operational
// identity authenticates it, so it is the one identity operation with no
// person in it, and that is deliberate: the Factory identity is not a fallback
// here, although RFC 7030 section 3.3.2 would allow one.
//
// The service holds the whole schedule. It is the only enforcer of expiry,
// through certificate-active, so it is also the only party that says when a
// renewal is due: the assignment a device polls gains `renew`, and a renewal
// the service did not ask for is refused at renewal-due. The device never
// reasons about dates to decide this, and its Time floor is not a trigger,
// because a floor that moves only when someone publishes a release is a
// trigger a Learner can catch lying.
//
// The overlap has one owner too. It runs from the issue of the new
// certificate to the first request the service accepts on it, which is the
// activation record, and on that record the service revokes the old serial as
// superseded. The proof is the service's observation and not the device's
// claim. If the new certificate is never used, the old one works until its own
// NotAfter, so there is no new timer: at worst the window is the old
// certificate's remaining lifetime, which is RFC 8739's price for an overlap.
//
// A failed renewal writes no record of its own. The refusal trail already
// records every refused attempt with its serial and its check, and the device
// keeps the identity it had.

// Tier 8's two renewal checks. Both answer 403, and both run in the renewal
// handler after every route check has passed, because both are questions about
// this renewal rather than about the connection.
const (
	// CheckRenewalDue holds when the service has asked this certificate to
	// renew: a third or less of its own lifetime is left, or the Owner asked
	// with ./course claim renew after it was issued. An unsolicited renewal is
	// refused here, which makes the schedule a control and not advice.
	CheckRenewalDue = "renewal-due"

	// CheckKeyUnused holds when the public key in the request has never been
	// certified for this device, Factory key included. It is section 8's "a
	// new key pair" as a control: in RFC 7030's words this is a rekey, and a
	// renewal onto a key the device already had is refused rather than
	// quietly reissued.
	CheckKeyUnused = "key-unused"
)

// KindRenewalRequest is the Owner's request that a device renew now. It moves
// no lifecycle state, so it lives here and not in internal/lifecycle: it only
// sets `renew` for the certificates issued before it.
const KindRenewalRequest = "renewal_request"

// renewalDueAt is when a third of a certificate's own lifetime is left.
//
// It is measured against the certificate's own window and not against
// OperationalLifetime, so a deliberately short-lived certificate is due at a
// third of its own life and not never. The window is the lifetime plus the
// hour NotBefore is backdated for skew, and that hour is subtracted first: a
// five-minute certificate has a 65-minute window, and a third of that is more
// than its whole life.
func renewalDueAt(identity DeviceIdentity) time.Time {
	issued := identity.NotBefore.Add(operationalSkew)
	lifetime := identity.NotAfter.Sub(issued)
	if lifetime < 0 {
		lifetime = 0
	}
	return identity.NotAfter.Add(-lifetime / 3)
}

// renewalDue is the `renew` flag: the one answer the assignment and
// renewal-due both read, so the flag and the check cannot disagree.
func (s *Server) renewalDue(identity DeviceIdentity, state provisioningState) bool {
	if !s.cfg.MutualTLS.now().Before(renewalDueAt(identity)) {
		return true
	}
	return renewalRequested(state, identity)
}

// renewalRequested says whether the Owner asked for a renewal after this
// certificate was issued. A request applies to every certificate issued before
// it and to none issued after it, so the certificate a renewal issues is not
// itself due, and a retry on the old certificate after a lost response still
// is.
func renewalRequested(state provisioningState, identity DeviceIdentity) bool {
	issued, ok := state.issuances[identity.Serial]
	if !ok || issued.deviceID != identity.DeviceID {
		return false
	}
	for _, record := range state.records[issued.index+1:] {
		if record.Kind == KindRenewalRequest && record.DeviceID == identity.DeviceID {
			return true
		}
	}
	return false
}

// deviceAssignment is the assignment a device polls, GET /v1/releases/current
// on the device listener. It is the release record, and `renew` when renewal is
// due for the certificate that asked.
//
// The field is written only when it is true. An assignment that is not due is
// byte for byte what Tier 7 serves, and a Tier 7 board, which has never heard
// of the field, reads the same answer it always has. The operator listener's
// copy of this route never carries it: there is no certificate there to be due.
//
// The release record is the Fleet baseline unless a Tier 9 rollout covers this
// device, and then it is the rollout's release, in the same shape. The first
// time a rollout's release is offered to a device the service records that it
// served it, which is what a pause keeps serving. See rollout.go.
func (s *Server) deviceAssignment(w http.ResponseWriter, r *http.Request) {
	identity, ok := DeviceFrom(r.Context())
	var release Release
	var err error
	if ok {
		var fromRollout bool
		release, fromRollout, err = s.assignmentFor(identity.DeviceID)
		if err == nil && fromRollout {
			s.recordServed(identity.DeviceID, release)
		}
	} else {
		release, err = s.loadRelease()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !ok || !s.renewalDue(identity, s.provisioningState()) {
		writeJSON(w, http.StatusOK, release)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Release
		Renew bool `json:"renew"`
	}{release, true})
}

// renewalHandler is POST /v1/devices/{device_id}/renewal.
//
// identity-operational, certificate-active, identifier-consistent against the
// path, device-unrevoked, device-claimed and ownership-context have already run,
// so the request was made by a current, owned, unrevoked Operational identity.
// That already names the revoked and other-owner refusals, and it is why a
// stolen Operational key gains persistence from renewal and not a new owner.
//
// The new public key travels in a certification request, as it does in a
// claim, so the device proves it holds the new private key. The request's
// subject is the third source identifier-consistent compares, by the claim's
// rule.
func (s *Server) renewalHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := DeviceFrom(r.Context())
	leaf := presentedLeaf(r)
	if !ok || leaf == nil {
		http.Error(w, "no verified client certificate on this connection", http.StatusInternalServerError)
		return
	}
	var submission struct {
		CSR string `json:"csr"`
	}
	if err := decodeJSON(r.Body, &submission); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	request, err := parseCertificationRequest(submission.CSR)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := request.CheckSignature(); err != nil {
		http.Error(w, "the certification request does not verify against its own public key",
			http.StatusBadRequest)
		return
	}
	if request.Subject.CommonName != identity.DeviceID {
		s.Refuse(w, r, http.StatusForbidden, Refusal{
			Check: CheckIdentifierConsistent,
			Reason: fmt.Sprintf("the certificate presented names %s and the certification request names %s; one request names one device",
				identity.DeviceID, request.Subject.CommonName),
			DeviceID: identity.DeviceID,
		})
		return
	}

	outcome := s.renew(identity, leaf, request)
	if outcome.refusal != nil {
		s.Refuse(w, r, outcome.status, *outcome.refusal)
		return
	}
	writeJSON(w, outcome.status, outcome.body)
}

// renew holds claimMu across the whole transition, like the claim: check,
// retire any unused candidate, issue, record. Every line the service appends to
// records.jsonl is derived from the log as it stands when the line is written.
func (s *Server) renew(identity DeviceIdentity, leaf *x509.Certificate,
	request *x509.CertificateRequest) claimOutcome {
	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	state := s.provisioningState()
	deviceID := identity.DeviceID
	device := state.devices[deviceID]

	// 1. renewal-due. It is silent about nothing the caller does not hold: the
	// time is its own certificate's.
	if !s.renewalDue(identity, state) {
		return claimOutcome{status: http.StatusForbidden, refusal: &Refusal{
			Check: CheckRenewalDue,
			Reason: fmt.Sprintf("renewal is not due for certificate serial %s: it is due at %s by service clock, and the owner has not asked for one sooner",
				identity.Serial, renewalDueAt(identity).UTC().Format(time.RFC3339)),
			DeviceID: deviceID,
		}}
	}

	// 2. key-unused. The certificate on the connection is compared as well as
	// the record, so a renewal onto the very key it is presenting is refused
	// even where the record carries no fingerprint for it.
	key := fingerprintOf(request.RawSubjectPublicKeyInfo)
	if key == fingerprintOf(leaf.RawSubjectPublicKeyInfo) || state.certifiedKeys[deviceID][key] {
		return claimOutcome{status: http.StatusForbidden, refusal: &Refusal{
			Check:    CheckKeyUnused,
			Reason:   fmt.Sprintf("public key %s has already been certified for this device; a renewal needs a new key pair", key),
			DeviceID: deviceID,
		}}
	}

	// At most two accepted Operational serials per device. A candidate an
	// earlier renewal issued and the device never used is retired before a new
	// one exists, so a lost response followed by a retry leaves no certificate
	// that stays valid for its whole life unseen. It is retired first, so a
	// failure after this point leaves fewer live certificates and never more.
	revoked := s.revokedSerials()
	var superseded []string
	for serial, issued := range state.issuances {
		if issued.kind != lifecycle.KindRenewal || issued.deviceID != deviceID ||
			serial == identity.Serial || !device.Operational[serial] ||
			device.Activated[serial] || revoked[serial] {
			continue
		}
		if err := s.appendRevokedSerial(serial, RoleOperational, ReasonSuperseded, serviceStation); err != nil {
			return claimOutcome{status: http.StatusInternalServerError, body: map[string]any{
				"error": "an unused Renewal candidate could not be retired, so nothing was issued: " + err.Error(),
			}}
		}
		superseded = append(superseded, serial)
	}

	der, certificate, err := s.issueOperational(deviceID, device.Owner, request.PublicKey, OperationalLifetime)
	if err != nil {
		return claimOutcome{status: http.StatusInternalServerError, body: map[string]any{
			"error": "the operational authority could not sign this renewal: " + err.Error(),
		}}
	}
	serial := certificate.SerialNumber.String()
	fingerprint := fingerprintOf(der)
	stateAfter := lifecycle.StateAfter(state.records, lifecycle.Record{
		Kind: lifecycle.KindRenewal, DeviceID: deviceID, OwnerID: device.Owner, CertSerial: serial,
	})
	record := map[string]any{
		"kind":                    lifecycle.KindRenewal,
		"recorded_at":             time.Now().UTC().Format(time.RFC3339Nano),
		"station":                 serviceStation,
		"device_id":               deviceID,
		"owner_id":                device.Owner,
		"lifecycle_state":         stateAfter,
		"renewed_from_serial":     identity.Serial,
		"certificate_serial":      serial,
		"certificate_fingerprint": fingerprint,
		"certificate_public_key":  key,
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		return claimOutcome{status: http.StatusInternalServerError, body: map[string]any{
			"error": "the renewal could not be recorded, so nothing was issued: " + err.Error(),
		}}
	}

	body := map[string]any{
		"result":                  "renewed",
		"device_id":               deviceID,
		"owner_id":                device.Owner,
		"lifecycle_state":         stateAfter,
		"renewed_from_serial":     identity.Serial,
		"certificate":             string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"certificate_serial":      serial,
		"certificate_fingerprint": fingerprint,
		"not_after":               certificate.NotAfter.UTC().Format(time.RFC3339),
	}
	if len(superseded) > 0 {
		sort.Strings(superseded)
		body["superseded_serials"] = superseded
	}
	return claimOutcome{status: http.StatusOK, body: body}
}

// retireRenewed revokes, as superseded, the certificate a renewal replaced,
// once the renewed certificate has been used. It is called with the activation
// line for the renewed serial already written, and under claimMu, so the
// superseded line is always later than the activation that justifies it.
//
// This is the gate section 8 asks for: the old certificate is revoked only
// after the new identity is proved to work, and the proof is the service's own
// activation record. Nothing else writes a superseded line for a replaced
// certificate. A line that cannot be written is logged and does not refuse the
// request, for the reason the activation line does not; the old certificate
// then lives to its own NotAfter, which is the overlap's stated worst case.
func (s *Server) retireRenewed(state provisioningState, serial string) {
	issued, ok := state.issuances[serial]
	if !ok || issued.kind != lifecycle.KindRenewal || issued.renewedFrom == "" {
		return
	}
	if s.revokedSerials()[issued.renewedFrom] {
		return
	}
	if err := s.appendRevokedSerial(issued.renewedFrom, RoleOperational, ReasonSuperseded, serviceStation); err != nil {
		log.Printf("certificate %s was not retired after %s was first used: %v", issued.renewedFrom, serial, err)
	}
}

// requestRenewal is the Owner's POST /v1/devices/{device_id}/renewal-request,
// behind the Owner credential on the operator listener. It sets `renew` now
// for every certificate the device holds, rather than waiting for a third of
// the lifetime, by appending a renewal_request line.
//
// It is gated by owner-of-record, exactly as the Owner's revocations are. A
// decommissioned device is told so at device-in-service and a revoked one at
// device-unrevoked: neither can ever renew, so asking would be a request that
// can never be served.
func (s *Server) requestRenewal(w http.ResponseWriter, r *http.Request) {
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
	// device-in-service first, as on the Recovery authorization: a
	// decommission clears the owner of record, so behind owner-of-record it
	// could never fire.
	if device.State == lifecycle.Decommissioned {
		s.Refuse(w, r, http.StatusForbidden, Refusal{
			Check:    CheckDeviceInService,
			Reason:   "this device is decommissioned, and a decommissioned device cannot renew until it is remanufactured",
			DeviceID: deviceID,
		})
		return
	}
	if device.Owner == "" || device.Owner != owner {
		s.Refuse(w, r, http.StatusForbidden, Refusal{
			Check:    CheckOwnerOfRecord,
			Reason:   "you are not the owner of record for this device",
			DeviceID: deviceID,
		})
		return
	}
	if device.State == lifecycle.Revoked {
		s.Refuse(w, r, http.StatusForbidden, Refusal{
			Check:    CheckDeviceUnrevoked,
			Reason:   "this device is revoked, and a revoked device cannot renew until it is remanufactured",
			DeviceID: deviceID,
		})
		return
	}
	if pendingRenewalRequest(state, deviceID) {
		writeJSON(w, http.StatusOK, map[string]any{
			"result":    "already-requested",
			"device_id": deviceID,
			"renew":     true,
		})
		return
	}
	record := map[string]any{
		"kind":         KindRenewalRequest,
		"recorded_at":  time.Now().UTC().Format(time.RFC3339Nano),
		"station":      serviceStation,
		"device_id":    deviceID,
		"owner_id":     owner,
		"requested_by": owner,
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		http.Error(w, "the renewal request could not be recorded: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":    "requested",
		"device_id": deviceID,
		"renew":     true,
		"by":        owner,
	})
}

// pendingRenewalRequest says whether a renewal request already stands for the
// latest certificate this device was issued, so asking twice writes one line.
func pendingRenewalRequest(state provisioningState, deviceID string) bool {
	latest := -1
	for _, issued := range state.issuances {
		if issued.deviceID == deviceID && issued.index > latest {
			latest = issued.index
		}
	}
	if latest < 0 {
		return false
	}
	for _, record := range state.records[latest+1:] {
		if record.Kind == KindRenewalRequest && record.DeviceID == deviceID {
			return true
		}
	}
	return false
}

// serviceStation is how the service signs the lines it writes.
const serviceStation = "course-ota-service"
