package ota

import (
	"log"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// recordActivation appends the `activation` line the first time a device uses
// an Operational certificate, which is what makes the device active.
//
// `claimed` is already taken by the moment the certificate is issued, so
// `active` means used rather than issued, and a use is a request that every
// check on an Operational route has let through. The line carries the serial,
// which is what lets it be written once per certificate rather than once per
// device, and what gives renewal a record that the new identity works.
//
// It is guarded by the derived state, read again under claimMu, so two
// requests racing on the first use write one line between them and every
// later request writes nothing.
//
// A line that cannot be written does not refuse the request. The device has
// passed every check, and turning an unwritable record into a refusal would
// make the log an authorization input it is not. The next request tries again,
// because the derivation still says the activation is owed.
func (s *Server) recordActivation(identity DeviceIdentity) {
	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	state := s.provisioningState()
	device := state.devices[identity.DeviceID]
	if !device.Owned() || !device.Operational[identity.Serial] || device.Activated[identity.Serial] {
		return
	}
	next := lifecycle.Record{
		Kind:       lifecycle.KindActivation,
		DeviceID:   identity.DeviceID,
		OwnerID:    device.Owner,
		CertSerial: identity.Serial,
	}
	record := map[string]any{
		"kind":               lifecycle.KindActivation,
		"recorded_at":        time.Now().UTC().Format(time.RFC3339Nano),
		"station":            "course-ota-service",
		"device_id":          identity.DeviceID,
		"owner_id":           device.Owner,
		"lifecycle_state":    lifecycle.StateAfter(state.records, next),
		"certificate_serial": identity.Serial,
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		log.Printf("the activation of certificate %s could not be recorded: %v", identity.Serial, err)
		return
	}
	// The first use of a renewed certificate is the proof that the new
	// identity works, so the certificate it replaced is retired now, and only
	// now.
	s.retireRenewed(state, identity.Serial)
}
