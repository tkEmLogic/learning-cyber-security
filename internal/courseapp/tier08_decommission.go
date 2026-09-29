package courseapp

// Tier 8 adds the manufacturer's two board-level commands to the provisioning
// station: decommission retires a board for good, and remanufacture is the one
// way back. The unit is the board, not the identifier — the service's record is
// what stops re-entry, and the device's erase is part of the procedure but is
// never the authority (decision #216).
//
// The board is keyed by the MAC suffix of its identifier, the convention
// validateDeviceID's comment already states. Two identifiers on one board
// (say beacon-206ef1170d64 and a later beacon-t08-206ef1170d64) share that
// suffix, so a decommissioning follows the hardware across a change of name and
// a new identifier on a decommissioned board is refused at hardware-in-service.
//
// Nothing is deleted. decommission and remanufacture append one line each to
// the same append-only record the station and the OTA service already share,
// and internal/lifecycle derives decommissioned and manufactured from them.

import (
	"errors"
	"fmt"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// boardOf is the hardware key: the twelve-hex-character MAC suffix the course
// names every board after. An identifier that does not end in a MAC (the
// synthetic and phantom names from earlier tiers) keys to itself, so it can
// only ever match its own records, which is the conservative reading of "keyed
// by their suffix as written".
func boardOf(deviceID string) string {
	end := len(deviceID)
	start := end
	for start > 0 && isLowerHex(deviceID[start-1]) {
		start--
	}
	tail := deviceID[start:end]
	if len(tail) >= 12 {
		return tail[len(tail)-12:]
	}
	return deviceID
}

func isLowerHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}

// boardDecommissioned replays the board-level records for one board. The last
// of its decommission and remanufacture lines wins: a decommission takes it out
// of service, and a remanufacture is the only thing that puts it back.
func boardDecommissioned(records []provisionRecord, board string) bool {
	decommissioned := false
	for _, record := range records {
		if boardOf(record.DeviceID) != board {
			continue
		}
		switch record.Kind {
		case recordDecommission:
			decommissioned = true
		case recordRemanufacture:
			decommissioned = false
		}
	}
	return decommissioned
}

// boardEnrolled reports whether any identifier on this board ever received a
// Factory certificate. A command that retires or remanufactures a board the
// station never manufactured is a typo, not a lifecycle event.
func boardEnrolled(records []provisionRecord, board string) bool {
	for _, record := range records {
		if record.Kind == recordEnrollment && record.Result == "issued" &&
			boardOf(record.DeviceID) == board {
			return true
		}
	}
	return false
}

// lostIdentity names an owned identity on this board other than the one now
// enrolling, if there is one. That is the signature of an unrecorded Factory
// identity loss: the board re-enrols under a new name while an earlier claim
// still stands and no decommission or remanufacture explains the gap. The most
// recently recorded such identity is the one named.
//
// It keys on ownership (claimed or active) rather than on any live state on
// purpose: a remanufacture returns the old identifier to manufactured, so a
// board that came back through the recorded path leaves no owned identity
// behind and raises no observation, while an accidental erase of a claimed
// board does.
func lostIdentity(records []provisionRecord, board, enrolling string) string {
	devices := lifecycle.Derive(lifecycleRecords(records))
	lost := ""
	for _, record := range records {
		if record.DeviceID == enrolling || boardOf(record.DeviceID) != board {
			continue
		}
		if devices[record.DeviceID].Owned() {
			lost = record.DeviceID
		}
	}
	return lost
}

func lifecycleRecords(records []provisionRecord) []lifecycle.Record {
	derived := make([]lifecycle.Record, 0, len(records))
	for _, record := range records {
		derived = append(derived, record.lifecycleRecord())
	}
	return derived
}

// appendFactoryLoss writes the factory_loss observation if this board carried a
// live identity under another name. It is called once, right after a successful
// enrolment.
func (a *app) appendFactoryLoss(enrolling string) error {
	records, err := a.readRecords()
	if err != nil {
		return err
	}
	board := boardOf(enrolling)
	lost := lostIdentity(records, board, enrolling)
	if lost == "" {
		return nil
	}
	return a.writeRecord(provisionRecord{
		Kind:     recordFactoryLoss,
		DeviceID: enrolling,
		Board:    board,
		Replaced: lost,
		Detail: fmt.Sprintf("board re-enrolled as %s while %s was still live; the earlier Factory identity was lost with no decommission or remanufacture on record",
			enrolling, lost),
	})
}

// provisionDecommission retires a board for good. It runs from any state, but a
// board already out of service is refused at device-in-service, because one
// decommission record is the whole of it.
func (a *app) provisionDecommission(args []string) error {
	deviceID, err := flagValue(args, "--device")
	if err != nil {
		return errors.New("usage: ./course provision decommission --device <id>")
	}
	if err := validateDeviceID(deviceID); err != nil {
		return err
	}
	records, err := a.readRecords()
	if err != nil {
		return err
	}
	board := boardOf(deviceID)
	if !boardEnrolled(records, board) {
		return fmt.Errorf("no board is enrolled as %s; decommissioning retires a board the station manufactured", deviceID)
	}

	fmt.Fprintf(a.out, "Decommissioning the board keyed by %s, named here %s.\n", board, deviceID)
	fmt.Fprintln(a.out, "The manufacturer retires the board for good. The authority is this record,")
	fmt.Fprintln(a.out, "not the device: erasing the board is part of the procedure, but what stops")
	fmt.Fprintln(a.out, "re-entry is the line written here, and only remanufacture lifts it.")

	if boardDecommissioned(records, board) {
		fmt.Fprintln(a.out)
		fmt.Fprintln(a.out, "Refused at check device-in-service")
		fmt.Fprintf(a.out, "  the board keyed by %s is already decommissioned; one record is enough\n", board)
		fmt.Fprintln(a.out, "  Nothing was written. Use ./course provision remanufacture to bring it back.")
		return nil
	}

	if err := a.writeRecord(provisionRecord{
		Kind:     recordDecommission,
		DeviceID: deviceID,
		Board:    board,
	}); err != nil {
		return err
	}

	fmt.Fprintln(a.out, "\n  no certificate serial was revoked: certificate-active runs before")
	fmt.Fprintln(a.out, "  device-in-service, so revoking the serials would refuse the certificate")
	fmt.Fprintln(a.out, "  before the new check could name the real reason.")
	fmt.Fprintf(a.out, "\nResult: the board is decommissioned. Every route is now refused for it,\n")
	fmt.Fprintf(a.out, "on the service at device-in-service and at the station at hardware-in-service.\n")
	fmt.Fprintf(a.out, "It is recorded in %s\n", a.relative(a.provisionRecordPath()))
	return nil
}

// provisionRemanufacture is the one way back, from decommissioned or from any
// other state. It writes the remanufacture record the OTA service already reads
// and returns the board to manufactured, so a new identifier with this MAC
// suffix may enrol. The old identifier stays retired.
func (a *app) provisionRemanufacture(args []string) error {
	deviceID, err := flagValue(args, "--device")
	if err != nil {
		return errors.New("usage: ./course provision remanufacture --device <old-id> --reason <text>")
	}
	reason, err := flagValue(args, "--reason")
	if err != nil {
		return errors.New("usage: ./course provision remanufacture --device <old-id> --reason <text>")
	}
	if err := validateDeviceID(deviceID); err != nil {
		return err
	}
	records, err := a.readRecords()
	if err != nil {
		return err
	}
	board := boardOf(deviceID)
	if !boardEnrolled(records, board) {
		return fmt.Errorf("no board is enrolled as %s; remanufacture returns a board the station manufactured", deviceID)
	}

	fmt.Fprintf(a.out, "Remanufacturing the board keyed by %s, named here %s.\n", board, deviceID)
	fmt.Fprintf(a.out, "  reason: %s\n", reason)

	if err := a.writeRecord(provisionRecord{
		Kind:     recordRemanufacture,
		DeviceID: deviceID,
		Board:    board,
		Reason:   reason,
	}); err != nil {
		return err
	}

	fmt.Fprintln(a.out, "\n  the board returns to manufactured. The manufacturer is vouching for the")
	fmt.Fprintln(a.out, "  board again, not lifting a block its owner could lift.")
	fmt.Fprintf(a.out, "\nResult: enrol a new identifier with the suffix %s to bring the board back\n", board)
	fmt.Fprintf(a.out, "into service. The old identifier %s stays retired.\n", deviceID)
	fmt.Fprintf(a.out, "It is recorded in %s\n", a.relative(a.provisionRecordPath()))
	return nil
}
