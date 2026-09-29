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

	// KindRenewal issues a device its next Operational certificate, on a new
	// key, for the same owner. It moves no state: ADR 0003 puts renewal inside
	// the active self-loop, because an overlap is two certificates and one
	// device. It is a kind of its own and not a second claim line, because a
	// claim starts a new owner's certificate history and a renewal continues
	// the current one.
	KindRenewal = "renewal"
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

	// Owner is the owner of record while the device is claimed or active.
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
	case KindRenewal:
		// The new serial joins the current owner's certificates, so its first
		// use can be recorded as an activation. A renewal for a device with no
		// owner, or naming another owner, adds nothing.
		if !known || !device.Owned() || record.OwnerID != device.Owner || record.CertSerial == "" {
			return
		}
		device.Operational[record.CertSerial] = true
		devices[record.DeviceID] = device
	case KindActivation:
		if !known || !device.Owned() || !device.Operational[record.CertSerial] ||
			device.Activated[record.CertSerial] {
			return
		}
		device.State = Active
		device.Activated[record.CertSerial] = true
		devices[record.DeviceID] = device
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
	case KindRemanufacture:
		devices[record.DeviceID] = Device{State: Manufactured}
	}
}
