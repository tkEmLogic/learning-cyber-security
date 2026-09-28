package courseapp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// nvsImage builds a storage partition the way Zephyr's NVS lays it out, so the
// guard is tested against the format and not against a string search. The
// layout was checked against a real Tier 6 dump off the DevKitC-1: allocation
// entries grow down from the top of each 4 KiB sector, data grows up from the
// bottom, the top slot is the close entry, and settings stores each name in
// clear at an id above 0x8000 with its value 0x4000 ids further on.
type nvsImage struct {
	data  []byte
	ate   [settingsSectorCount]int
	datap [settingsSectorCount]int
}

func newNVSImage() *nvsImage {
	img := &nvsImage{data: bytes.Repeat([]byte{0xff}, 0x30000)}
	for i := range img.ate {
		img.ate[i] = settingsSectorSize - 2*nvsATESize
	}
	return img
}

func (img *nvsImage) slot(sector, offset int, id uint16, dataOffset, length int) {
	raw := make([]byte, nvsATESize)
	binary.LittleEndian.PutUint16(raw[0:], id)
	binary.LittleEndian.PutUint16(raw[2:], uint16(dataOffset))
	binary.LittleEndian.PutUint16(raw[4:], uint16(length))
	raw[6] = 0xff
	raw[7] = crc8CCITT(0xff, raw[:7])
	copy(img.data[sector*settingsSectorSize+offset:], raw)
}

func (img *nvsImage) write(sector int, id uint16, value []byte) *nvsImage {
	base := sector * settingsSectorSize
	copy(img.data[base+img.datap[sector]:], value)
	img.slot(sector, img.ate[sector], id, img.datap[sector], len(value))
	img.ate[sector] -= nvsATESize
	img.datap[sector] += (len(value) + 3) &^ 3
	return img
}

func (img *nvsImage) close(sector int) *nvsImage {
	img.slot(sector, settingsSectorSize-nvsATESize, nvsSpecialID, img.datap[sector], 0)
	return img
}

// setting writes one settings entry: the name counter, the value, the name.
func (img *nvsImage) setting(sector int, nameID uint16, name string, value []byte) *nvsImage {
	counter := make([]byte, 2)
	binary.LittleEndian.PutUint16(counter, nameID)
	img.write(sector, settingsNameCountID, counter)
	img.write(sector, nameID+settingsNameIDOffset, value)
	return img.write(sector, nameID, []byte(name))
}

// deleteSetting is what settings_delete does on NVS: a zero-length write to
// the name and to the value.
func (img *nvsImage) deleteSetting(sector int, nameID uint16) *nvsImage {
	img.write(sector, nameID, nil)
	return img.write(sector, nameID+settingsNameIDOffset, nil)
}

// tier5Records writes the raw Tier 5 records that share the instance.
func (img *nvsImage) tier5Records(sector int) *nvsImage {
	record := make([]byte, 144)
	copy(record, "tier-05-healthy")
	return img.write(sector, 1, record).write(sector, 2, record[:72])
}

var ciphertext = bytes.Repeat([]byte{0x5a}, 97)

func TestInspectStorage(t *testing.T) {
	cases := []struct {
		name    string
		image   []byte
		entries []string
		residue bool
	}{
		{"blank board", newNVSImage().data, nil, false},
		{"Tier 5 records only", newNVSImage().tier5Records(0).data, nil, false},
		{"Tier 6 enrolled", newNVSImage().tier5Records(0).
			setting(0, 0x8001, "its/2/601", ciphertext).
			setting(0, 0x8002, "course/identity/factory-cert", []byte("cert")).data,
			[]string{"its/2/601"}, false},
		{"Tier 7 claimed", newNVSImage().
			setting(0, 0x8001, "its/2/601", ciphertext).
			setting(0, 0x8003, "its/2/701", ciphertext).data,
			[]string{"its/2/601", "its/2/701"}, false},
		{"erased by provision erase", newNVSImage().
			setting(0, 0x8001, "its/2/601", ciphertext).
			deleteSetting(0, 0x8001).data,
			nil, true},
		{"re-enrolled after an erase, as the recorded dump was", newNVSImage().
			setting(0, 0x8001, "its/2/601", ciphertext).close(0).
			deleteSetting(1, 0x8001).
			setting(1, 0x8001, "its/2/601", ciphertext).data,
			[]string{"its/2/601"}, false},
		// The ring: sector 0 is the write sector, so sectors 6 and 7 are older.
		{"created in an older sector, deleted in the write sector", newNVSImage().
			setting(6, 0x8001, "its/2/701", ciphertext).close(6).close(7).
			deleteSetting(0, 0x8001).data,
			nil, true},
		{"deleted in an older sector, created in the write sector", newNVSImage().
			setting(6, 0x8001, "its/2/701", ciphertext).deleteSetting(6, 0x8001).close(6).close(7).
			setting(0, 0x8001, "its/2/701", ciphertext).data,
			[]string{"its/2/701"}, false},
		{"name outside the settings id range is not an entry", newNVSImage().
			write(0, 3, []byte("its/2/601")).data,
			nil, true},
		{"truncated read", newNVSImage().setting(0, 0x8001, "its/2/601", ciphertext).data[:settingsSectorSize], nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inspectStorage(tc.image)
			if !reflect.DeepEqual(got.Entries, tc.entries) || got.Residue != tc.residue {
				t.Fatalf("inspectStorage = %+v, want entries %v residue %v", got, tc.entries, tc.residue)
			}
		})
	}
}

func TestInspectStorageIgnoresCorruptEntry(t *testing.T) {
	img := newNVSImage().setting(0, 0x8001, "its/2/601", ciphertext)
	// Flip the CRC of the name entry, the third slot written.
	img.data[settingsSectorSize-2*nvsATESize-2*nvsATESize+7] ^= 0xff
	if got := inspectStorage(img.data); got.enrolled() {
		t.Fatalf("a name entry with a bad CRC counted as live: %+v", got)
	}
}

// A dump taken off the board with ./course device dump. It is never committed:
// it holds a device private key under a key derived from public values.
func TestInspectStorageRecordedDump(t *testing.T) {
	path := os.Getenv("COURSE_STORAGE_DUMP")
	if path == "" {
		t.Skip("set COURSE_STORAGE_DUMP to a dump from ./course device dump")
	}
	dump, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: %+v", path, inspectStorage(dump))
}

func TestTierErasesIdentity(t *testing.T) {
	for tier, want := range map[string]bool{"00": true, "02": true, "05": true, "06": false, "07": false, "08": false, "x": false} {
		if got := tierErasesIdentity(tier); got != want {
			t.Errorf("tierErasesIdentity(%q) = %v, want %v", tier, got, want)
		}
	}
}

func TestGuardIdentity(t *testing.T) {
	enrolled := newNVSImage().setting(0, 0x8001, "its/2/601", ciphertext).setting(0, 0x8003, "its/2/701", ciphertext).data
	blank := newNVSImage().data
	cases := []struct {
		name    string
		destroy bool
		read    func() ([]byte, error)
		refused bool
		says    string
	}{
		{"enrolled board is refused", false, func() ([]byte, error) { return enrolled, nil }, true, "its/2/601 its/2/701"},
		{"enrolled board with --destroy-identity flashes", true, func() ([]byte, error) { return enrolled, nil }, false, "--destroy-identity was given"},
		{"blank board flashes", false, func() ([]byte, error) { return blank, nil }, false, "holds no Secure Storage identity entry"},
		{"failed read warns and flashes", false, func() ([]byte, error) { return nil, errors.New("no port") }, false, "Continuing on the warning alone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			a := &app{out: &out, errOut: &out}
			err := a.guardIdentity("05", tc.destroy, tc.read)
			if (err != nil) != tc.refused {
				t.Fatalf("guardIdentity error = %v, refused want %v", err, tc.refused)
			}
			if !strings.Contains(out.String(), "erases part of the storage partition") {
				t.Fatalf("no warning printed:\n%s", out.String())
			}
			if !strings.Contains(out.String(), tc.says) {
				t.Fatalf("output lacks %q:\n%s", tc.says, out.String())
			}
			if tc.refused && !strings.Contains(err.Error(), "nothing was written") {
				t.Fatalf("refusal does not say nothing was written: %v", err)
			}
		})
	}
}

// flashRig is a board-free ./course device flash: a stable serial path that is
// a plain file, and a Zephyr workspace whose esptool logs each call and
// answers read-flash with the storage image it is given. It proves the order
// the guard relies on, that the refusal comes before any write-flash.
func flashRig(t *testing.T, storage []byte) (*app, *bytes.Buffer, string) {
	t.Helper()
	root := t.TempDir()
	workspace := t.TempDir()
	t.Setenv("ZEPHYR_WORKSPACE", workspace)

	source, err := os.ReadFile(filepath.Join("..", "..", "course.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := yaml.Unmarshal(source, &m); err != nil {
		t.Fatal(err)
	}
	byID := filepath.Join(root, "by-id")
	if err := os.MkdirAll(byID, 0o700); err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(byID, "usb-Espressif_USB_JTAG_serial_debug_unit_00:00:00:00:00:00-if00")
	if err := os.WriteFile(device, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	beacon := m.Devices["reference_beacon"]
	beacon.StableSerialPrefix = byID
	m.Devices["reference_beacon"] = beacon

	fixture := filepath.Join(root, "storage-fixture.bin")
	if err := os.WriteFile(fixture, storage, 0o600); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(root, "esptool-calls")
	bin := filepath.Join(workspace, ".venv", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho \"$@\" >> " + calls + "\n" +
		"for last; do :; done\n" +
		"case \" $* \" in *\" read-flash \"*) cp " + fixture + " \"$last\" ;; esac\n"
	if err := os.WriteFile(filepath.Join(bin, "esptool"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	build := filepath.Join(workspace, "build", "tier-05-recovery-healthy")
	for _, dir := range []string{build, filepath.Join(build+"-bootloader", "zephyr")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(build, "domains.yaml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(build+"-bootloader", "zephyr", "zephyr.bin"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	a := &app{root: root, manifest: m, out: &out, errOut: &out}
	if err := os.MkdirAll(a.releaseDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.releaseDir(), "tier-05-healthy.bin"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(a.publicKeyPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.publicKeyPath(), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return a, &out, calls
}

func esptoolCalls(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

func TestDeviceFlashRefusesEnrolledBoardBeforeWriting(t *testing.T) {
	enrolled := newNVSImage().setting(0, 0x8001, "its/2/601", ciphertext).setting(0, 0x8003, "its/2/701", ciphertext).data
	a, out, calls := flashRig(t, enrolled)

	err := a.deviceFlash([]string{"--tier", "05", "--variant", "healthy"})
	if err == nil || !strings.Contains(err.Error(), "this board is enrolled") {
		t.Fatalf("deviceFlash = %v, want a refusal\n%s", err, out)
	}
	log := esptoolCalls(t, calls)
	if !strings.Contains(log, "read-flash 0x3b0000 0x030000") {
		t.Fatalf("the guard did not read the storage partition: %q", log)
	}
	if strings.Contains(log, "write-flash") {
		t.Fatalf("esptool wrote to the board before the refusal: %q", log)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "dumps", "flash-guard-*")); len(leftovers) > 0 {
		t.Fatalf("the guard left its read on disk: %v", leftovers)
	}
}

func TestDeviceFlashWritesWhenAllowed(t *testing.T) {
	enrolled := newNVSImage().setting(0, 0x8001, "its/2/601", ciphertext).data
	for name, tc := range map[string]struct {
		storage []byte
		args    []string
	}{
		"blank board":        {newNVSImage().data, nil},
		"--destroy-identity": {enrolled, []string{"--destroy-identity"}},
	} {
		t.Run(name, func(t *testing.T) {
			a, out, calls := flashRig(t, tc.storage)
			if err := a.deviceFlash(append([]string{"--tier", "05", "--variant", "healthy"}, tc.args...)); err != nil {
				t.Fatalf("deviceFlash = %v\n%s", err, out)
			}
			log := esptoolCalls(t, calls)
			read := strings.Index(log, "read-flash")
			write := strings.Index(log, "write-flash")
			if read < 0 || write < read {
				t.Fatalf("want a read before the write, got %q", log)
			}
		})
	}
}

func TestDestroyIdentityRejectedFromTier6(t *testing.T) {
	a := &app{out: &bytes.Buffer{}, errOut: &bytes.Buffer{}}
	err := a.deviceFlash([]string{"--tier", "07", "--destroy-identity"})
	if err == nil || !strings.Contains(err.Error(), "applies only to images below Tier 6") {
		t.Fatalf("--destroy-identity on a Tier 7 flash: %v", err)
	}
}
