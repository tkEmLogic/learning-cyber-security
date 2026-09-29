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
// that makes a device active. Everything else here crosses that boundary read
// only, on the requests that need it.
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

	// serials is every serial that appears in any claim record, which is what
	// clause 3 of certificate-active joins on.
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
	serials map[string]bool
}

func (s *Server) provisioningState() provisioningState {
	records := s.readProvisioningRecords()
	state := provisioningState{
		records: records,
		devices: lifecycle.Derive(records),
		serials: map[string]bool{},
	}
	for _, record := range records {
		if record.Kind == lifecycle.KindClaim && record.DeviceID != "" && record.CertSerial != "" {
			state.serials[record.CertSerial] = true
		}
	}
	return state
}

func (s *Server) readProvisioningRecords() []lifecycle.Record {
	var records []lifecycle.Record
	forEachJSONLine(filepath.Join(s.cfg.MutualTLS.ProvisioningDir, "records.jsonl"), func(line []byte) {
		var record lifecycle.Record
		if err := json.Unmarshal(line, &record); err == nil {
			records = append(records, record)
		}
	})
	return records
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
