package ota

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
)

// The service reads the manufacturing record; it never writes it.
//
// `.course-state/provisioning` is the host CLI's territory: the provisioning
// station enrols a device there and issue #146's claim writes the `claim` line
// that ownership is derived from. This file is the only place the service
// crosses that boundary, and it crosses it read only, live, on the requests
// that need it.
//
// Nothing here unmarshals the whole record shape. The station owns that shape
// and adds fields to it; the service reads the four values three checks need
// and ignores everything else, so a field added on the other side of the
// boundary can never turn a device's request into a 400.

// Record kinds this package cares about. The station writes several more.
const (
	recordKindClaim         = "claim"
	recordKindRemanufacture = "remanufacture"
)

// provisioningRecord is the subset of one manufacturing record line the
// service reads.
type provisioningRecord struct {
	Kind       string `json:"kind"`
	DeviceID   string `json:"device_id"`
	OwnerID    string `json:"owner_id"`
	CertSerial string `json:"certificate_serial"`
}

// revocationRecord is one line of `revoked.jsonl`, the file a minimal host
// command writes and the service reads as its authority on clause 2 of
// certificate-active. The course builds no CRL and no OCSP responder: when the
// verifier is also the issuer, it finds out by looking at its own record, and
// every real complication in CRLs comes from the day those two are different
// machines.
type revocationRecord struct {
	CertSerial string `json:"certificate_serial"`
}

// claimState is what replaying the record log says about one device.
type claimState struct {
	owner   string
	claimed bool
}

// provisioningState is the whole log, replayed.
//
// State is derived rather than edited, exactly as the station derives
// credential state today. A `claim` line claims a device and names its owner;
// a `remanufacture` line takes it back to manufactured, which is what makes
// the Tier 6 erase path the only escape from an expired Operational identity.
type provisioningState struct {
	devices map[string]claimState

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
	state := provisioningState{
		devices: map[string]claimState{},
		serials: map[string]bool{},
	}
	for _, record := range s.readProvisioningRecords() {
		switch record.Kind {
		case recordKindClaim:
			if record.DeviceID == "" {
				continue
			}
			state.devices[record.DeviceID] = claimState{owner: record.OwnerID, claimed: true}
			if record.CertSerial != "" {
				state.serials[record.CertSerial] = true
			}
		case recordKindRemanufacture:
			delete(state.devices, record.DeviceID)
		}
	}
	return state
}

func (s *Server) readProvisioningRecords() []provisioningRecord {
	var records []provisioningRecord
	forEachJSONLine(filepath.Join(s.cfg.MutualTLS.ProvisioningDir, "records.jsonl"), func(line []byte) {
		var record provisioningRecord
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
