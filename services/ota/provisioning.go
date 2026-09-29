package ota

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// The service reads the device lifecycle record live, and appends to it in two
// places only.
//
// `.course-state/provisioning` is the host CLI's territory: the provisioning
// station enrols a device there. From Tier 7 the service appends the `claim`
// line that ownership is derived from, and from Tier 8 the `activation` line
// that makes a device active, the `renewal` line that issues a device its next
// Operational certificate, and the Owner's `renewal_request`. Everything else
// here crosses that boundary read only, on the requests that need it.
//
// Nothing here unmarshals the whole record shape. The station owns that shape
// and adds fields to it; the service reads the few values the derivation needs
// and ignores everything else, so a field added on the other side of the
// boundary can never turn a device's request into a 400.

// revocationRecord is one line of `revoked.jsonl`, the file a minimal host
// command writes and the service reads as its authority on clause 2 of
// certificate-active. The course builds no CRL and no OCSP responder: when the
// verifier is also the issuer, it finds out by looking at its own record, and
// every real complication in CRLs comes from the day those two are different
// machines.
type revocationRecord struct {
	CertSerial string `json:"certificate_serial"`
}

// provisioningState is the whole log, replayed.
//
// State is derived rather than edited, by the one derivation in
// internal/lifecycle that the station uses too. The `lifecycle_state` field on
// a line is a copy written for a reader; nothing here reads it.
type provisioningState struct {
	records []lifecycle.Record
	devices map[string]lifecycle.Device

	// serials is every serial that appears in any claim or renewal record,
	// which is what clause 3 of certificate-active joins on.
	//
	// Any claim record, not this device's. The narrower form could never be
	// wrong and could never be useful: an unclaimed device has no claim record
	// at all, so every certificate surviving a per-device clause 3 would
	// belong to a claimed device and device-claimed could never fire. The
	// wider join leaves device-claimed reachable, and identifier-consistent
	// and device-claimed between them re-tighten what it stops enforcing. The
	// sentence survives either way — a CA signature is not an authorization,
	// the record is — and it gains a second beside it: the record binds a
	// serial, and a serial is not a certificate.
	//
	// A renewal record issues a serial exactly as a claim record does, so it
	// joins the same set. Without that case a renewed certificate is refused
	// at clause 3 as one the service never issued.
	serials map[string]bool

	// issuances is every issuing line, claim or renewal, by the serial it
	// issued. It is what renewal reads: whose certificate a serial is, where
	// in the log it was issued, which key it certified, and which serial a
	// renewal replaced.
	issuances map[string]issuance

	// certifiedKeys is, per device, the fingerprint of every public key any
	// line has recorded certifying for it: the Factory key at enrollment and
	// every Operational key since. key-unused refuses a renewal onto any of
	// them, which is what makes section 8's "a new key pair" a control.
	certifiedKeys map[string]map[string]bool
}

// issuance is one line that issued an Operational certificate.
type issuance struct {
	kind     string
	deviceID string
	ownerID  string

	// index is the line's position in the log. A renewal_request applies to
	// the serials issued before it and to none issued after it.
	index int

	// publicKey is the fingerprint of the certified SubjectPublicKeyInfo,
	// which is what key-unused compares.
	publicKey string

	// renewedFrom is the serial a renewal replaced; empty on a claim.
	renewedFrom string
}

// provisioningLine is what the service reads of one record line: the fields the
// derivation reads, and the three renewal needs that move no state.
type provisioningLine struct {
	lifecycle.Record
	PublicKey   string `json:"certificate_public_key"`
	RenewedFrom string `json:"renewed_from_serial"`
}

func (s *Server) provisioningState() provisioningState {
	lines := s.readProvisioningLines()
	records := make([]lifecycle.Record, len(lines))
	for i, line := range lines {
		records[i] = line.Record
	}
	state := provisioningState{
		records:       records,
		devices:       lifecycle.Derive(records),
		serials:       map[string]bool{},
		issuances:     map[string]issuance{},
		certifiedKeys: map[string]map[string]bool{},
	}
	for i, line := range lines {
		certifies := line.Kind == lifecycle.KindClaim || line.Kind == lifecycle.KindRenewal ||
			(line.Kind == lifecycle.KindEnrollment && line.Result == "issued")
		if certifies && line.DeviceID != "" && line.PublicKey != "" {
			if state.certifiedKeys[line.DeviceID] == nil {
				state.certifiedKeys[line.DeviceID] = map[string]bool{}
			}
			state.certifiedKeys[line.DeviceID][line.PublicKey] = true
		}
		switch line.Kind {
		case lifecycle.KindClaim, lifecycle.KindRenewal:
		default:
			continue
		}
		if line.DeviceID == "" || line.CertSerial == "" {
			continue
		}
		state.serials[line.CertSerial] = true
		state.issuances[line.CertSerial] = issuance{
			kind:        line.Kind,
			deviceID:    line.DeviceID,
			ownerID:     line.OwnerID,
			index:       i,
			publicKey:   line.PublicKey,
			renewedFrom: line.RenewedFrom,
		}
	}
	return state
}

func (s *Server) readProvisioningLines() []provisioningLine {
	var lines []provisioningLine
	forEachJSONLine(filepath.Join(s.cfg.MutualTLS.ProvisioningDir, "records.jsonl"), func(raw []byte) {
		var line provisioningLine
		if err := json.Unmarshal(raw, &line); err == nil {
			lines = append(lines, line)
		}
	})
	return lines
}

// revokedSerials reads the revocation file. A missing file means nothing has
// been revoked, which is the state every environment starts in.
func (s *Server) revokedSerials() map[string]bool {
	revoked := map[string]bool{}
	forEachJSONLine(filepath.Join(s.cfg.MutualTLS.ProvisioningDir, "revoked.jsonl"), func(line []byte) {
		var record revocationRecord
		if err := json.Unmarshal(line, &record); err == nil && record.CertSerial != "" {
			revoked[record.CertSerial] = true
		}
	})
	return revoked
}

// forEachJSONLine reads an append-only JSON Lines file, skipping what it
// cannot parse. A half-written final line is a normal state for a file another
// process appends to, and it must not take the service down.
func forEachJSONLine(path string, visit func([]byte)) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		visit(line)
	}
}
