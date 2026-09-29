package courseapp

// E-8-11, the far-future manifest, on the host (#262).
//
// Issue #217 decided that whoever holds the release signing key can end every
// Operational credential by dating a manifest in the future, and that this is
// shown on the host only. It must never reach a board: the board's Time floor
// would stay ahead for good, and every certificate issued before that date
// would be refused.
//
// The Time floor exists only in the firmware, so the only honest judge is the
// firmware's own code. This runner does not model the floor. It builds
// firmware/tier-08-time-floor-host for native_sim, which compiles Tier 8's
// time_floor.c, release_policy.c and recovery_state.c unchanged, and it reads
// the verdict those files print. A Go copy of the floor would be the fixture
// grading itself.
//
// What the runner generates, and why none of it can reach a board:
//
//   - A throwaway P-256 release key, made in memory for this run. Its private
//     half signs two manifests and is then dropped; it is never written to
//     disk. Its public half is compiled into the host build, where the board
//     has the Learner's key. The board trusts no manifest this key signs.
//   - Two synthetic Operational certificates, each valid for 90 days from
//     now, from a throwaway authority the service has never seen.
//   - Two manifests: one dated twenty years ahead, and an ordinary one dated
//     now. Neither describes an image, and neither is written to the release
//     store.
//
// It opens no socket. It needs no running service, no marker handshake and no
// board, and it touches none of them. The Learner's Release signing key is not
// read. The one thing it needs is the Zephyr workspace, for the native_sim
// build.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	timeFloorHostApp = "firmware/tier-08-time-floor-host"

	// The two release identifiers the host manifests carry. Neither names a
	// release the course publishes.
	timeFloorFarRelease      = "tier-08-far-future-host"
	timeFloorOrdinaryRelease = "tier-08-ordinary-host"

	// How far ahead the far-future manifest is dated. Twenty years is far
	// past any 90-day certificate, and well short of the year 9999 the
	// firmware's parser stops at.
	timeFloorFarYears = 20

	// The synthetic certificates' life, the service's default.
	timeFloorCertificateDays = 90

	// The boot names the host program reads from -testargs.
	timeFloorFirstBoot     = "first"
	timeFloorRecoveredBoot = "after-recovery"
)

// timeFloorInputs is what one run generated, for the runner and its tests.
type timeFloorInputs struct {
	dir       string
	seed      string
	farDate   string
	validTo   string
	recovered string
	publicKey *ecdsa.PublicKey
}

// writeTimeFloorInputs generates this run's inputs into dir, as the .inc files
// the host build compiles in, and a Kconfig fragment carrying the seed.
func writeTimeFloorInputs(dir string, now time.Time) (timeFloorInputs, error) {
	now = now.UTC().Truncate(time.Second)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return timeFloorInputs{}, err
	}

	// The throwaway release key. Its PEM exists only in memory, so that the
	// course's own signManifest signs these manifests exactly as it signs a
	// real one.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return timeFloorInputs{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return timeFloorInputs{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	far := now.AddDate(timeFloorFarYears, 0, 0)
	operational, validTo, err := timeFloorCertificate(now, "beacon-bypass-e8-11")
	if err != nil {
		return timeFloorInputs{}, err
	}
	// Issued a second later, as a recovery would issue one after the
	// first was refused. It is just as far from the far-future date.
	recovered, recoveredTo, err := timeFloorCertificate(now.Add(time.Second), "beacon-bypass-e8-11")
	if err != nil {
		return timeFloorInputs{}, err
	}

	farManifest, err := timeFloorManifest(timeFloorFarRelease, far)
	if err != nil {
		return timeFloorInputs{}, err
	}
	ordinaryManifest, err := timeFloorManifest(timeFloorOrdinaryRelease, now)
	if err != nil {
		return timeFloorInputs{}, err
	}
	farSig, err := signManifest(keyPEM, farManifest)
	if err != nil {
		return timeFloorInputs{}, err
	}
	ordinarySig, err := signManifest(keyPEM, ordinaryManifest)
	if err != nil {
		return timeFloorInputs{}, err
	}
	// The same far-future bytes under a second throwaway key, which the
	// host build does not trust. Without the release key, a date moves
	// nothing.
	untrustedPEM, err := throwawaySigningKeyPEM()
	if err != nil {
		return timeFloorInputs{}, err
	}
	untrustedSig, err := signManifest(untrustedPEM, farManifest)
	if err != nil {
		return timeFloorInputs{}, err
	}

	point := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	files := map[string][]byte{
		"release_pubkey.inc":         point,
		"operational_cert.inc":       operational,
		"recovered_cert.inc":         recovered,
		"far_manifest.inc":           farManifest,
		"far_manifest_sig.inc":       farSig,
		"untrusted_manifest_sig.inc": untrustedSig,
		"ordinary_manifest.inc":      ordinaryManifest,
		"ordinary_manifest_sig.inc":  ordinarySig,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), byteArrayInc(data), 0o600); err != nil {
			return timeFloorInputs{}, err
		}
	}
	seed := tier08TimeFloorSeed(now)
	fragment := fmt.Sprintf("CONFIG_COURSE_TIME_FLOOR_SEED=%q\nCONFIG_COURSE_SIGNING_KEY_FINGERPRINT=%q\n",
		seed, "throwaway key for E-8-11, never the Release signing key")
	if err := os.WriteFile(filepath.Join(dir, "host.conf"), []byte(fragment), 0o600); err != nil {
		return timeFloorInputs{}, err
	}
	return timeFloorInputs{
		dir:       dir,
		seed:      seed,
		farDate:   far.Format(time.RFC3339),
		validTo:   validTo.Format(time.RFC3339),
		recovered: recoveredTo.Format(time.RFC3339),
		publicKey: &key.PublicKey,
	}, nil
}

// throwawaySigningKeyPEM is a P-256 key in the PEM shape signManifest reads,
// held only in memory.
func throwawaySigningKeyPEM() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// timeFloorCertificate is a synthetic Operational certificate from a
// throwaway authority, valid for 90 days from notBefore. Only its validity
// window matters to the floor; the host build never verifies its chain, and
// neither does the board.
func timeFloorCertificate(notBefore time.Time, deviceID string) ([]byte, time.Time, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, err
	}
	notAfter := notBefore.AddDate(0, 0, timeFloorCertificateDays)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, time.Time{}, err
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "E-8-11 throwaway authority"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	leaf := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: deviceID, OrganizationalUnit: []string{"e8-11-host"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	return der, notAfter, err
}

// timeFloorManifest is a manifest in the course's own shape and encoding,
// dated createdAt. It describes no image: the host build never downloads
// one, and the floor moves before anything asks.
func timeFloorManifest(releaseID string, createdAt time.Time) ([]byte, error) {
	manifest := releaseManifest{
		SchemaVersion:       1,
		ReleaseID:           releaseID,
		Version:             "0.8.0-host",
		SecurityCounter:     tier08SecurityCounter,
		Channel:             tier04Channel,
		Board:               "native_sim/native/64",
		HardwareRevisionMin: tier04HardwareRevision,
		HardwareRevisionMax: tier04HardwareRevision,
		ImagePath:           "none; this manifest describes no image",
		ImageSize:           0,
		ImageSHA256:         strings.Repeat("0", 64),
		CreatedAt:           createdAt.UTC().Format(time.RFC3339),
		SupportedUntil:      createdAt.UTC().AddDate(tier04SupportYears, 0, 0).Format(time.RFC3339),
	}
	return json.MarshalIndent(manifest, "", "  ")
}

// byteArrayInc is the body of a C array initializer, in the shape
// writeSigningPublicKeyInc writes.
func byteArrayInc(data []byte) []byte {
	var out bytes.Buffer
	out.WriteString("/* Generated by ./course service bypass e-8-11. Do not edit or commit. */\n")
	for i, b := range data {
		if i%12 == 0 {
			out.WriteString("\n\t")
		}
		fmt.Fprintf(&out, "0x%02x, ", b)
	}
	out.WriteString("\n")
	return out.Bytes()
}

// rowTimeFloorFarFuture builds the host program, runs its two boots on one
// simulated flash file, and reads the verdict the firmware's own code printed.
func (a *app) rowTimeFloorFarFuture() error {
	workspace := a.zephyrWorkspace()
	west := filepath.Join(workspace, ".venv", "bin", "west")
	if _, err := os.Stat(west); err != nil {
		return fmt.Errorf("no Zephyr workspace at %s; E-8-11 builds the firmware's Time floor for native_sim, so run it where ./course build firmware runs, or set ZEPHYR_WORKSPACE", workspace)
	}
	buildDir := filepath.Join(workspace, "build", "tier-08-time-floor-host")
	inputs, err := writeTimeFloorInputs(filepath.Join(a.root, a.manifest.Paths.State, "bypass", tier08BypassKey, "e-8-11"), time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "  seed %s, certificate valid_to %s, far-future created_at %s\n",
		inputs.seed, inputs.validTo, inputs.farDate)
	fmt.Fprintln(a.out, "  building firmware/tier-08-time-floor-host for native_sim/native/64")
	var buildLog bytes.Buffer
	err = runAttachedFrom(a.root, workspace, &buildLog, &buildLog,
		[]string{
			"ZEPHYR_BASE=" + filepath.Join(workspace, "zephyr"),
			"ZEPHYR_SDK_INSTALL_DIR=" + filepath.Join(workspace, "zephyr-sdk-1.0.1"),
			"PATH=" + filepath.Join(workspace, ".venv", "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
			"COURSE_TIME_FLOOR_HOST_INPUTS=" + inputs.dir,
		},
		west, "build", "--pristine=always", "--board", "native_sim/native/64",
		"--build-dir", buildDir, filepath.Join(a.root, timeFloorHostApp),
		"--", "-DEXTRA_CONF_FILE="+filepath.Join(inputs.dir, "host.conf"))
	if err != nil {
		tail := buildLog.String()
		if len(tail) > 4000 {
			tail = tail[len(tail)-4000:]
		}
		return fmt.Errorf("the native_sim build failed: %w\n%s", err, tail)
	}

	program := filepath.Join(buildDir, "zephyr", "zephyr.exe")
	flash := filepath.Join(buildDir, "e-8-11-flash.bin")
	_ = os.Remove(flash)
	first, err := a.runTimeFloorBoot(program, flash, timeFloorFirstBoot, true)
	if err != nil {
		return err
	}
	second, err := a.runTimeFloorBoot(program, flash, timeFloorRecoveredBoot, false)
	if err != nil {
		return err
	}
	return checkTimeFloorVerdict(inputs, first, second)
}

// runTimeFloorBoot runs one boot of the host program and echoes what it
// printed, indented, the way the other rows echo the wire.
func (a *app) runTimeFloorBoot(program, flash, boot string, erase bool) (string, error) {
	args := []string{"--flash=" + flash}
	if erase {
		args = append(args, "--flash_erase")
	}
	args = append(args, "-testargs", boot)
	cmd := exec.Command(program, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	fmt.Fprintf(a.out, "\n  + %s %s\n", filepath.Base(program), strings.Join(args, " "))
	runErr := cmd.Run()
	echoIndented(a.out, out.String())
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		return "", runErr
	}
	return out.String(), nil
}

func echoIndented(w io.Writer, text string) {
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		fmt.Fprintf(w, "  | %s\n", strings.TrimRight(line, "\r"))
	}
}

var timeFloorExpiredLine = regexp.MustCompile(`time\.floor expired valid_to=(\S+) floor=(\S+)`)

// checkTimeFloorVerdict reads the lines time_floor.c and the host program
// printed. Every condition is one the firmware's code decided; this function
// only reads which way it decided, and refuses a run where it did not.
func checkTimeFloorVerdict(inputs timeFloorInputs, first, second string) error {
	raised := "time.floor raised to " + inputs.farDate + " by the signed created_at of release " + timeFloorFarRelease
	at := strings.Index(first, raised)
	if at < 0 {
		return fmt.Errorf("the first boot did not print %q; the floor did not move", raised)
	}
	before := first[:at]
	if strings.Count(before, "host.present operational certificate presented") != 2 {
		return errors.New("the first boot did not present its certificate both before any manifest and after the untrusted one, so the refusal would prove nothing")
	}
	if !strings.Contains(before, "release.refused check=manifest-signature") {
		return errors.New("the manifest under a key the image does not trust was not refused at manifest-signature")
	}
	match := timeFloorExpiredLine.FindStringSubmatch(first)
	if match == nil || match[1] != inputs.validTo || match[2] != inputs.farDate {
		return fmt.Errorf("the first boot did not refuse valid_to=%s at floor=%s", inputs.validTo, inputs.farDate)
	}
	if !strings.Contains(first, "host.present operational certificate refused err=-EKEYEXPIRED") {
		return errors.New("the first boot judged the certificate expired and still presented it")
	}

	persisted := "time.floor " + inputs.farDate + ", set by release " + timeFloorFarRelease
	if !strings.Contains(second, persisted) {
		return fmt.Errorf("the second boot did not read the floor back from NVS record 4 (%q)", persisted)
	}
	match = timeFloorExpiredLine.FindStringSubmatch(second)
	if match == nil || match[1] != inputs.recovered || match[2] != inputs.farDate {
		return fmt.Errorf("the second boot did not refuse the recovered certificate, valid_to=%s, at floor=%s", inputs.recovered, inputs.farDate)
	}
	stays := "time.floor stays at " + inputs.farDate + "; release " + timeFloorOrdinaryRelease
	if !strings.Contains(second, stays) {
		return fmt.Errorf("the ordinary manifest moved the floor, or was not seen (%q)", stays)
	}
	if !strings.Contains(second, "host.present operational certificate refused err=-EKEYEXPIRED") {
		return errors.New("the second boot presented the recovered certificate")
	}
	return nil
}

// runLocalBypassRow is the wrapper for a row with no target: the dry run, the
// exact identifier to execute, and the evidence record, as every row has.
//
// It takes no marker handshake, because there is nothing to hand-shake with:
// the row opens no socket, and a marker fetch would be the one network
// request it made. It does not require the Learner's service either, and it
// runs the same whether or not one is up. That is the point of the row. The
// far-future manifest must never be where a board can fetch it.
func (a *app) runLocalBypassRow(row bypassRow, executeID string) error {
	fmt.Fprintf(a.out, "Bypass: %s\nTarget: none. This row opens no socket and reaches no service or board.\n",
		strings.ToUpper(row.id))
	fmt.Fprintf(a.out, "Test: %s\nExpected result: %s\nObserved on: %s\n", row.test, row.expected, row.witness)
	fmt.Fprintf(a.out, "Capability under test: %s\n", row.holds)
	fmt.Fprintf(a.out, "Changes: generated inputs under %s, and a native_sim build under %s\n",
		filepath.ToSlash(filepath.Join(a.manifest.Paths.State, "bypass", tier08BypassKey, row.id)),
		filepath.Join(a.zephyrWorkspace(), "build", "tier-08-time-floor-host"))
	fmt.Fprintln(a.out, "Reset: none needed. Every run makes new keys and erases its simulated flash first.")
	fmt.Fprintln(a.out, "Plan:")
	for i, line := range row.plan {
		fmt.Fprintf(a.out, "  %d. %s\n", i+1, line)
	}
	if executeID == "" {
		fmt.Fprintln(a.out, "Result: dry run only")
		fmt.Fprintf(a.out, "Execute: ./course service bypass %s --execute %s\n", row.id, row.id)
		return nil
	}
	if strings.ToLower(executeID) != row.id {
		return errors.New("--execute value must exactly match the row identifier")
	}

	fmt.Fprintln(a.out)
	start := time.Now().UTC()
	runErr := row.local(a)
	result := "passed"
	if runErr != nil {
		result = "failed"
	}
	record := map[string]any{
		"schema_version":           1,
		"bypass_id":                row.id,
		"target":                   "none",
		"started_at":               start,
		"ended_at":                 time.Now().UTC(),
		"command":                  fmt.Sprintf("./course service bypass %s --execute %s", row.id, row.id),
		"test":                     row.test,
		"expected_effect":          row.expected,
		"observed_on":              row.witness,
		"built_from":               timeFloorHostApp,
		"firmware_sources":         []string{"time_floor.c", "release_policy.c", "recovery_state.c"},
		"operational_ca_key_used":  false,
		"release_signing_key_used": false,
		"result":                   result,
	}
	if runErr != nil {
		record["failure"] = runErr.Error()
	}
	evidencePath, evidenceErr := a.writeAttackEvidence(filepath.Join(tier08BypassKey, row.id), record)
	if evidenceErr != nil {
		return evidenceErr
	}
	if runErr == nil {
		fmt.Fprintln(a.out, "\nResult: the firmware's own Time floor refused the device's own Operational")
		fmt.Fprintln(a.out, "certificate after one signed, far-future manifest, and kept refusing after a")
		fmt.Fprintln(a.out, "reset and a fresh certificate. The release key has power over time.")
	}
	fmt.Fprintf(a.out, "Evidence: %s\n", evidencePath)
	fmt.Fprintln(a.out, "Observed on: host. This is a host result, from a native_sim build of the")
	fmt.Fprintln(a.out, "firmware's code; a host result never stands in for a device result.")
	return runErr
}
