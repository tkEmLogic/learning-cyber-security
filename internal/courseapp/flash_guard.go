package courseapp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// The guard on ./course device flash that #206 decided and #241 built.
//
// Flashing never writes the storage partition. The damage comes from the first
// boot: a Tier 5 image mounts its own three-sector NVS instance at the first
// byte of the partition, on top of the eight-sector instance the settings
// subsystem owns from Tier 6, and depending on where that instance's write
// sector is, the mount erases sectors that hold the Factory and Operational
// identities. Nothing records the loss, and the service still believes the
// device is claimed.
//
// So before an image from a tier below 06 is written, the board is asked. The
// host records are never consulted: they cannot say which board is plugged in,
// identifiers end in the MAC by convention only, and one MAC already carries
// several stale claimed records.

// The Secure Storage entries that make a board enrolled. its/2/601 holds the
// Factory identity's key from Tier 6, its/2/701 the Operational identity's key
// from Tier 7. The ITS store writes them through settings, which stores the
// name in clear as its own NVS entry.
var identityEntryNames = []string{"its/2/601", "its/2/701"}

// The settings subsystem's NVS instance on this board: CONFIG_SETTINGS_NVS
// with its default of eight sectors, one 4 KiB flash page each, starting at the
// first byte of the storage partition.
const (
	settingsSectorSize  = 4096
	settingsSectorCount = 8
	nvsATESize          = 8

	// Zephyr's settings NVS backend keeps a name counter at 0x8000, stores each
	// name at an id above it, and stores the value 0x4000 ids further on.
	settingsNameCountID  = 0x8000
	settingsNameIDOffset = 0x4000
	nvsSpecialID         = 0xffff
)

// storageIdentity is what the storage partition says about the identities on
// the board.
type storageIdentity struct {
	// Entries are the identity entries a settings instance holds live: the
	// newest write of the name is not a deletion, and neither is the newest
	// write of its value.
	Entries []string
	// Residue is true when an identity entry's name appears somewhere in the
	// partition but no live entry holds it: a deleted or unreachable record.
	// The board cannot use it, so it does not refuse a flash on its own.
	Residue bool
}

func (s storageIdentity) enrolled() bool { return len(s.Entries) > 0 }

type nvsEntry struct {
	length int
	data   []byte
}

// inspectStorage reads a dump of the storage partition the way Zephyr's NVS
// would at mount, and reports which identity entries the settings instance
// holds. It is a pure function over the bytes so the refusal can be tested
// without a board.
func inspectStorage(dump []byte) storageIdentity {
	latest := latestNVSEntries(dump)

	var result storageIdentity
	for _, name := range identityEntryNames {
		if nameEntryLive(latest, name) {
			result.Entries = append(result.Entries, name)
		} else if bytes.Contains(dump, []byte(name)) {
			result.Residue = true
		}
	}
	return result
}

func nameEntryLive(latest map[uint16]nvsEntry, name string) bool {
	for id, entry := range latest {
		if id <= settingsNameCountID || id >= settingsNameCountID+settingsNameIDOffset {
			continue
		}
		if entry.length == 0 || string(entry.data) != name {
			continue
		}
		if value, ok := latest[id+settingsNameIDOffset]; ok && value.length > 0 {
			return true
		}
	}
	return false
}

// latestNVSEntries walks the sectors from oldest to newest and keeps the last
// write of each id, which is the value NVS would return for it.
func latestNVSEntries(dump []byte) map[uint16]nvsEntry {
	latest := map[uint16]nvsEntry{}
	if len(dump) < settingsSectorSize*settingsSectorCount {
		return latest
	}
	sector := func(i int) []byte {
		return dump[i*settingsSectorSize : (i+1)*settingsSectorSize]
	}
	closed := func(i int) bool {
		s := sector(i)
		return !erased(s[settingsSectorSize-nvsATESize:])
	}

	// The write sector is the open sector that follows a closed one. NVS keeps
	// the sector after it erased for garbage collection, so the ring read from
	// the sector after the write sector round to the write sector is oldest to
	// newest.
	write := 0
	for i := 0; i < settingsSectorCount; i++ {
		if closed(i) && !closed((i+1)%settingsSectorCount) {
			write = (i + 1) % settingsSectorCount
			break
		}
	}
	for step := 1; step <= settingsSectorCount; step++ {
		for _, ate := range sectorEntries(sector((write + step) % settingsSectorCount)) {
			latest[ate.id] = ate.entry
		}
	}
	return latest
}

type nvsATE struct {
	id    uint16
	entry nvsEntry
}

// sectorEntries returns a sector's data entries in the order they were
// written. Allocation table entries grow down from the top of the sector: the
// last slot is the close entry, and the slots below it are written one after
// another until the first erased slot.
func sectorEntries(sector []byte) []nvsATE {
	var entries []nvsATE
	for slot := settingsSectorSize - 2*nvsATESize; slot >= 0; slot -= nvsATESize {
		raw := sector[slot : slot+nvsATESize]
		if erased(raw) {
			break
		}
		if crc8CCITT(0xff, raw[:7]) != raw[7] {
			continue
		}
		id := binary.LittleEndian.Uint16(raw[0:2])
		offset := int(binary.LittleEndian.Uint16(raw[2:4]))
		length := int(binary.LittleEndian.Uint16(raw[4:6]))
		if id == nvsSpecialID {
			continue
		}
		if offset+length > slot {
			continue
		}
		entries = append(entries, nvsATE{id: id, entry: nvsEntry{length: length, data: sector[offset : offset+length]}})
	}
	return entries
}

func erased(b []byte) bool {
	for _, v := range b {
		if v != 0xff {
			return false
		}
	}
	return true
}

// crc8CCITT is Zephyr's crc8_ccitt: polynomial 0x07, most significant bit
// first, which NVS runs over the first seven bytes of each allocation entry.
func crc8CCITT(seed byte, data []byte) byte {
	crc := seed
	for _, b := range data {
		crc ^= b
		for range 8 {
			if crc&0x80 != 0 {
				crc = crc<<1 ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// tierErasesIdentity is true for the tiers whose image predates the settings
// instance: Tier 5 mounts its own NVS on top of it, and nothing older knows it
// is there.
func tierErasesIdentity(tier string) bool {
	number, err := strconv.Atoi(tier)
	return err == nil && number < 6
}

const flashIdentityWarning = `Warning: an image from a tier below 06 erases part of the storage partition
at its first boot, not during this flash. On a board that went through Tier 6
or Tier 7 that can destroy the Factory identity and the Operational identity,
and nothing records the loss. The update service still believes the device is
claimed.`

// guardIdentity runs before any byte of an image below Tier 6 is written. It
// always prints the warning, then reads the storage partition off the board.
// It refuses when the settings instance holds a live identity entry, unless
// the Learner passed --destroy-identity. When the read fails it continues on
// the warning alone, as #206 decided, rather than refusing a flash it cannot
// judge.
func (a *app) guardIdentity(tier string, destroy bool, read func() ([]byte, error)) error {
	fmt.Fprintln(a.out, flashIdentityWarning)
	fmt.Fprintln(a.out, "Checking the board before writing anything.")

	dump, err := read()
	if err != nil {
		fmt.Fprintf(a.out, "Could not read the storage partition (%v).\n", err)
		fmt.Fprintln(a.out, "Continuing on the warning alone. If this board holds an identity, stop now.")
		return nil
	}
	found := inspectStorage(dump)
	if !found.enrolled() {
		fmt.Fprintln(a.out, "The storage partition holds no Secure Storage identity entry. Flashing.")
		if found.Residue {
			fmt.Fprintln(a.out, "It does hold the name of a deleted or unreachable identity record, which the board can no longer use.")
		}
		return nil
	}
	fmt.Fprintf(a.out, "The storage partition holds the Secure Storage entries %v.\n", found.Entries)
	if destroy {
		fmt.Fprintln(a.out, "--destroy-identity was given. Flashing, and the first boot may destroy them.")
		return nil
	}
	return fmt.Errorf("this board is enrolled (%v), and a tier %s image can destroy that identity at its first boot with no record; nothing was written. Pass --destroy-identity to flash it anyway", found.Entries, tier)
}

// readStoragePartition reads the storage partition into a temporary file,
// returns its bytes and removes the file, and resets the board off the ROM
// loader esptool leaves it in. It is the same bounded read ./course device
// dump makes.
func (a *app) readStoragePartition(device string) ([]byte, error) {
	dumpDir := filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "dumps")
	if err := os.MkdirAll(dumpDir, 0o700); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(dumpDir, "flash-guard-*.bin")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	file.Close()
	defer os.Remove(path)

	if err := a.esptoolReadStorage(device, path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// A failed reset must not throw the read away: the guard would then fall
	// back to the warning and flash an enrolled board. The flash that follows
	// resets the chip anyway, and a refusal says how to reset it by hand.
	if err := a.deviceReset(); err != nil {
		fmt.Fprintf(a.out, "Could not reset the board off the ROM loader (%v); ./course device reset does it.\n", err)
	}
	return data, nil
}
