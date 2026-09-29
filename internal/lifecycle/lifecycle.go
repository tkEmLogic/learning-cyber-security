// Package lifecycle derives a device's lifecycle state from the provisioning
// record.
//
// The record is the state and the `lifecycle_state` field on a line is a copy
// of it, as docs/adr/0003-device-lifecycle-state-is-derived.md settles. A
// single current-state field in an append-only log would be a read-modify-write,
// and Tier 6 bought its atomicity by making one O_APPEND write the whole state
// change. So the state is replayed from the kinds of the lines, and a writer
// that fills in the field asks this package what the log will say once its line
// is on it. The field and the derivation cannot disagree, because they are the
// same function.
//
// Both writers of records.jsonl, the provisioning station and the OTA service,
// read the log through this package, so there is one derivation and not two
// that happen to agree today.
package lifecycle

// The six states section 8 names. Tier 6 reaches the first, Tier 7 the second,
// and Tier 8 the rest.
const (
	Manufactured   = "manufactured"
	Claimed        = "claimed"
	Active         = "active"
	Transferred    = "transferred"
	Revoked        = "revoked"
	Decommissioned = "decommissioned"
)

// The record kinds that move a device's state. The log holds others, such as
// credential issuance and the Owner credential lines, and they move nothing.
const (
	KindEnrollment    = "enrollment"
	KindClaim         = "claim"
	KindRemanufacture = "remanufacture"

	// KindRevocation stops one device. It is the Owner's act, written once, and
	// one-way: nothing but a remanufacture leaves the state it moves a device
	// into. It stops a device rather than a credential, which is why it lives
	// here and a revoked certificate serial lives in revoked.jsonl.
	KindRevocation = "revocation"

	// KindActivation is appended once per Operational certificate, the first
	// time the device uses it. It is what makes a device active: `claimed`
	// already means the certificate was issued, so `active` means it was used,
	// and that is the name renewal needs for section 8's "proves the new
	// identity works".
	KindActivation = "activation"

	// KindDecommission retires a board for good: it moves the device to
	// decommissioned from any state, and only a later remanufacture record on
	// the same board lifts it. No certificate serial is revoked, so the
	// service's device-in-service check stays reachable over the wire.
	KindDecommission = "decommission"

	// KindRecovery replaces a lost Operational identity for the owner of
	// record. It adds the new certificate's serial to the device and moves no
	// state: a device that lost its key is still claimed or active as far as
	// the log knows, because the log records what a device may do and not what
	// it is holding.
	KindRecovery = "recovery"

	// KindRecoveryAuthorization is the owner's recorded statement that the
	// Operational identity is lost, written before the press. It moves nothing
	// here; the service reads it to let one recovery through.
	KindRecoveryAuthorization = "recovery_authorization"

	// KindTransfer is the first act of an Ownership transfer: the owner of
	// record gives the device up. It moves an owned device to transferred,
	// owned by no one, and the device rests there until the second act, an
	// ordinary claim by whoever holds it. Issue #205 called the state
	// transient; #215 narrowed it to a resting state, because the two acts are
	// done by two people and nothing makes the second one follow at once.
	KindTransfer = "transfer"
)

// Record is the subset of one record line the derivation reads. Every writer
// adds fields of its own, and none of them can change a state.
type Record struct {
	Kind       string `json:"kind"`
	DeviceID   string `json:"device_id"`
	OwnerID    string `json:"owner_id"`
	CertSerial string `json:"certificate_serial"`
	Result     string `json:"result"`
}

// Device is what replaying the log says about one device identifier.
type Device struct {
	State string

	// Owner is the owner of record while the device is claimed or active, and
	// stays on a revoked device. A transferred device has none: it was given up.
	Owner string

	// Operational is every Operational certificate serial issued to this
	// device under its current owner, and Activated is the ones it has used.
	// They are what lets an activation be written once per certificate rather
	// than once per device.
	Operational map[string]bool
	Activated   map[string]bool
}

// Owned says whether the device has an owner of record, which is what the
// service's device-claimed and device-unowned checks ask.
func (d Device) Owned() bool {
	return d.State == Claimed || d.State == Active
}

// Derive replays the whole log.
//
// A line that does not describe a transition from the state its device is in
// moves nothing. That covers a refused enrollment, and an activation for a
// serial the device was never issued or has already used: the log may hold
// such lines, because it is append only and more than one process writes it,
// but none of them can put a device somewhere the table in ADR 0003 does not
// reach.
func Derive(records []Record) map[string]Device {
	devices := map[string]Device{}
	for _, record := range records {
		apply(devices, record)
	}
	return devices
}

// StateAfter is the value a writer puts in the `lifecycle_state` field of the
// line it is about to append: the state the log will derive for that device
// once the line is on it.
func StateAfter(records []Record, next Record) string {
	return Derive(append(append([]Record(nil), records...), next))[next.DeviceID].State
}

func apply(devices map[string]Device, record Record) {
	if record.DeviceID == "" {
		return
	}
	device, known := devices[record.DeviceID]
	switch record.Kind {
	case KindEnrollment:
		if record.Result != "issued" {
			return
		}
		devices[record.DeviceID] = Device{State: Manufactured}
	case KindClaim:
		// A claim is a new owner and a new certificate, so it starts the
		// device's certificate history afresh. Nothing the device used under
		// an earlier claim makes it active under this one.
		device = Device{
			State:       Claimed,
			Owner:       record.OwnerID,
			Operational: map[string]bool{},
			Activated:   map[string]bool{},
		}
		if record.CertSerial != "" {
			device.Operational[record.CertSerial] = true
		}
		devices[record.DeviceID] = device
	case KindActivation:
		if !known || !device.Owned() || !device.Operational[record.CertSerial] ||
			device.Activated[record.CertSerial] {
			return
		}
		device.State = Active
		device.Activated[record.CertSerial] = true
		devices[record.DeviceID] = device
	case KindRecovery:
		// A new certificate for the same owner, and nothing else. A recovery
		// for a device that has no owner, or for somebody who is not its
		// owner, moves nothing, like every other line that does not describe
		// a transition from where the device is.
		if !known || !device.Owned() || record.OwnerID != device.Owner || record.CertSerial == "" {
			return
		}
		device.Operational[record.CertSerial] = true
		devices[record.DeviceID] = device
	case KindTransfer:
		// Only the owner of record gives a device up, so a transfer for a device
		// nobody owns, or one naming somebody else, moves nothing. The owner and
		// the certificate history go with it: the transfer revoked those
		// certificates, and the next claim starts a history of its own.
		if !known || !device.Owned() || record.OwnerID != device.Owner {
			return
		}
		devices[record.DeviceID] = Device{State: Transferred}
	case KindRevocation:
		// One-way, and the only exit is a remanufacture below. The owner and the
		// certificate history stay, because owner-of-record still has to
		// recognise whose device was stopped; a revocation for a device the log
		// has never seen moves nothing, like every other line here.
		if !known {
			return
		}
		device.State = Revoked
		devices[record.DeviceID] = device
	case KindDecommission:
		// From any state, and the record is the whole authority. Replayed
		// after it, a remanufacture line returns the device to manufactured,
		// so the two kinds together are the only way in and the only way out.
		devices[record.DeviceID] = Device{State: Decommissioned}
	case KindRemanufacture:
		devices[record.DeviceID] = Device{State: Manufactured}
	}
}
