package courseapp

// Tier 3 gives the Reference product a bootloader that checks who published an
// image. This file holds the Learner-facing key handling and the signing and
// publishing path that goes with it.
//
// The shape is settled on issue #51. The Learner creates their own key with an
// explicit command rather than through ./course setup, the key lives under
// .course-secrets/, and no firmware build command ever names it.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// signingRoles are the two keys a Learner makes, and they are made by the same
// command on purpose.
//
// The attacker key is cryptographically identical to the Release signing key.
// Nothing about it is weaker, forged, or special. The only thing separating
// them is their names, and the names are the Learner's own. That is the whole
// lesson of CTL-06, so the course does not hide it behind two different
// generation paths.
var signingRoles = map[string]string{
	"release":  "The Release signing key. The bootloader trusts the public half of this one.",
	"attacker": "An attacker's key. Exactly as valid, and trusted by nothing.",
}

func (a *app) signingDir() string {
	return filepath.Join(a.root, a.manifest.Paths.Secrets, "signing")
}

func (a *app) signingKeyPath(role string) string {
	return filepath.Join(a.signingDir(), role+".pem")
}

// publicKeyPath is the only half of the key pair that a build ever reads.
//
// It lives under the generated artifacts rather than beside the private key,
// so that pointing a build at it cannot accidentally reach the private key
// sitting in the same directory.
func (a *app) publicKeyPath() string {
	return filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "signing", "release.pub.pem")
}

func (a *app) imgtool() (string, string) {
	workspace := a.zephyrWorkspace()
	return filepath.Join(workspace, ".venv", "bin", "python"),
		filepath.Join(workspace, "bootloader", "mcuboot", "scripts", "imgtool.py")
}

func (a *app) keys(args []string) error {
	if len(args) == 0 {
		return errors.New("keys requires create, list or inventory")
	}
	switch args[0] {
	case "create":
		if len(args) < 2 {
			return errors.New("usage: ./course keys create release|attacker|device-ca|operational-ca|shared-identity")
		}
		return a.keysCreate(args[1])
	case "list":
		return a.keysList()
	case "inventory":
		return a.keysInventory()
	default:
		return fmt.Errorf("unknown keys command %q; use create, list or inventory", args[0])
	}
}

// keysCreate runs the real imgtool, and shows the Learner the command before it
// runs it.
//
// The course owns the path and the overwrite guard. It does not own the key
// generation itself, because a Learner who never sees imgtool has been handed a
// key by a course command rather than having made one.
func (a *app) keysCreate(role string) error {
	// The manufacturer device CA is a certificate authority, not an MCUboot
	// signing key, so it does not go through imgtool. It is here rather than in
	// ./course setup because Tier 6 is where it first means anything, and
	// because a Learner should watch the third trust relationship appear rather
	// than find it already present.
	if role == "device-ca" {
		return a.keysCreateDeviceCA()
	}
	if role == "operational-ca" {
		return a.keysCreateOperationalCA()
	}
	if role == "shared-identity" {
		return a.keysCreateSharedIdentity()
	}
	description, ok := signingRoles[role]
	if !ok {
		return fmt.Errorf("unknown key role %q; use release, attacker, device-ca, operational-ca or shared-identity", role)
	}
	path := a.signingKeyPath(role)

	// Refuse rather than replace, and make the Learner type the removal.
	//
	// There is deliberately no --replace flag. A flag that destroys a signing
	// key in one keystroke is a habit worth not teaching, and typing the rm is
	// the moment the custody lesson lands.
	if _, err := os.Stat(path); err == nil {
		fingerprint, ferr := a.keyFingerprint(path)
		if ferr != nil {
			fingerprint = "unreadable"
		}
		fmt.Fprintf(a.errOut, "A %s key already exists.\n", role)
		fmt.Fprintf(a.errOut, "  path:        %s\n", a.relative(path))
		fmt.Fprintf(a.errOut, "  fingerprint: %s\n", fingerprint)
		fmt.Fprintln(a.errOut, "Nothing signed by it can be signed again once it is gone.")
		fmt.Fprintf(a.errOut, "To make a new one, remove it yourself first:\n  rm %s\n", a.relative(path))
		return fmt.Errorf("refusing to replace the existing %s key", role)
	}

	if err := os.MkdirAll(a.signingDir(), 0o700); err != nil {
		return err
	}

	python, imgtool := a.imgtool()
	if _, err := os.Stat(imgtool); err != nil {
		return fmt.Errorf("imgtool is not where it should be: %s", imgtool)
	}

	fmt.Fprintln(a.out, description)
	fmt.Fprintln(a.out, "Generating it with MCUboot's own tool, not with anything this course wrote:")
	fmt.Fprintf(a.out, "+ %s %s keygen -k %s -t ecdsa-p256\n", python, imgtool, a.relative(path))
	if err := runAttached(a.root, a.out, a.errOut, python, imgtool,
		"keygen", "-k", path, "-t", "ecdsa-p256"); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}

	fingerprint, err := a.keyFingerprint(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: %s key created, fingerprint %s\n", role, fingerprint)

	if role == "release" {
		if err := a.writePublicKey(); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(a.out, "No public half is extracted for this one. The bootloader must never trust it.")
	}

	fmt.Fprintf(a.out, "This key is private. It stays in %s, it never reaches the OTA service, and it is never committed.\n",
		a.relative(a.signingDir()))
	return nil
}

// writePublicKey extracts the half a build is allowed to read.
//
// MCUboot's default is to point the bootloader build at the private key and let
// it take the public half out for itself. That would put the Release signing
// key into a firmware build command, which docs/fixture-safety-contract.md
// forbids, so the course extracts it once, here, and the build reads only this.
func (a *app) writePublicKey() error {
	python, imgtool := a.imgtool()
	out := a.publicKeyPath()
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Taking out the public half, which is the only part a build ever reads:")
	fmt.Fprintf(a.out, "+ %s %s getpub -k %s -e pem > %s\n",
		python, imgtool, a.relative(a.signingKeyPath("release")), a.relative(out))

	var buffer strings.Builder
	if err := runAttached(a.root, &buffer, a.errOut, python, imgtool,
		"getpub", "-k", a.signingKeyPath("release"), "-e", "pem"); err != nil {
		return err
	}
	if !strings.Contains(buffer.String(), "BEGIN PUBLIC KEY") {
		return errors.New("imgtool did not produce a public key")
	}
	if err := os.WriteFile(out, []byte(buffer.String()), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: public key written to %s\n", a.relative(out))
	return nil
}

// keyFingerprint is the SHA-256 of the public key in the form MCUboot records.
//
// A signed image carries the same value in its key hash TLV, and the bootloader
// uses it to pick a key. So this is the number to compare when asking whether
// the device would trust a given image.
func (a *app) keyFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("%s is not a PEM file", a.relative(path))
	}
	public, err := publicFromPEM(block)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func publicFromPEM(block *pem.Block) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		private, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("the key is not an ECDSA key")
		}
		return private.Public(), nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key.Public(), nil
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("the file holds neither an ECDSA private key nor a public key")
}

// keysList prints both fingerprints side by side.
//
// This is the command that makes CTL-06 visible rather than asserted. Two keys,
// made by the same tool, equally valid, and the only thing telling them apart
// is which name the Learner typed.
//
// It answers one question — which signing key is which — and Tier 3 quotes its
// whole output. The wider question of who signs what in this course belongs to
// ./course keys inventory, which Tier 7 quotes. They were one command briefly
// and it put four authorities and seven leaf roles in front of a Tier 3
// Learner who has met neither.
func (a *app) keysList() error {
	a.signingKeyRoster()
	return nil
}

// keysInventory prints the certificate-role inventory: the signing keys, then
// every authority and every leaf role in one place.
//
// It is a superset of keys list rather than the inventory alone, because the
// closing sentence only lands if the two certificate-less signing keys are
// printed above the four authorities it contrasts them with.
func (a *app) keysInventory() error {
	a.signingKeyRoster()
	a.certificateRoleInventory()
	return nil
}

// signingKeyRoster prints the signing keys and what the bootloader was built
// against. Both ./course keys list and ./course keys inventory open with it.
func (a *app) signingKeyRoster() {
	roles := make([]string, 0, len(signingRoles))
	for role := range signingRoles {
		roles = append(roles, role)
	}
	sort.Strings(roles)

	found := 0
	for _, role := range roles {
		path := a.signingKeyPath(role)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		found++
		fingerprint, err := a.keyFingerprint(path)
		if err != nil {
			fingerprint = "unreadable: " + err.Error()
		}
		fmt.Fprintf(a.out, "%-9s %s\n", role, fingerprint)
		fmt.Fprintf(a.out, "          %s\n", a.relative(path))
	}
	if found == 0 {
		fmt.Fprintln(a.out, "No signing keys yet. Make one with ./course keys create release")
		return
	}
	if _, err := os.Stat(a.publicKeyPath()); err == nil {
		fmt.Fprintf(a.out, "\nThe bootloader is built against %s, and nothing else.\n", a.relative(a.publicKeyPath()))
	}
	if found > 1 {
		fmt.Fprintln(a.out, "\nBoth keys are ECDSA P-256 and both are equally valid.")
		fmt.Fprintln(a.out, "Only the fingerprint compiled into the bootloader decides which one the device will run.")
	}
}

// certificateRoleInventory prints every authority and every leaf role in one
// place.
//
// Until Tier 7 a Learner assembled this by hand from scattered sources: a
// directory listing of .course-secrets/pki for the Course CA and the service
// certificate, which no command prints, and the one-time output of keys create
// device-ca, operational-ca and shared-identity. One command turns the lab
// artifact from a screenshot a Learner is handed into a command they run. Each
// authority still prints itself at creation; this is the place to look back.
func (a *app) certificateRoleInventory() {
	dir := a.pkiDir()
	authorities := []struct {
		file  string
		signs string
	}{
		{coursepki.CourseCACert, "the update service's own server certificate"},
		{coursepki.DeviceCACert, "Factory identities: which board this is"},
		{coursepki.OperationalCACert, "Operational identities: which board, whose, for ninety days"},
		{coursepki.UntrustedCACert, "nothing this course trusts, on purpose"},
	}
	fmt.Fprintln(a.out, "\nAuthorities")
	for _, authority := range authorities {
		state := "not made yet"
		if _, err := os.Stat(filepath.Join(dir, authority.file)); err == nil {
			state = a.relative(filepath.Join(dir, authority.file))
		}
		fmt.Fprintf(a.out, "  %-24s %s\n", authority.file, authority.signs)
		fmt.Fprintf(a.out, "  %-24s %s\n", "", state)
	}

	leaves := []struct {
		role   string
		issuer string
		where  string
	}{
		{"service certificate", "Course CA", coursepki.ServiceCert},
		{"wrong-name certificate", "Course CA", coursepki.WrongNameCert},
		{"untrusted service certificate", "Untrusted CA", coursepki.UntrustedCert},
		{"shared development identity", "Manufacturer Device CA", coursepki.SharedIdentityCert},
		{"Factory identity", "Manufacturer Device CA", "on the board, key never a file"},
		{"Operational identity", "Operational Device CA", "on the board, key never a file"},
		{"foreign client certificate", "Untrusted CA", "minted by the fixture at run time"},
	}
	fmt.Fprintln(a.out, "\nLeaf roles")
	for _, leaf := range leaves {
		where := leaf.where
		if strings.HasSuffix(where, ".pem") {
			if _, err := os.Stat(filepath.Join(dir, where)); err != nil {
				where += ", not made yet"
			}
		}
		fmt.Fprintf(a.out, "  %-30s %-24s %s\n", leaf.role, leaf.issuer, where)
	}

	fmt.Fprintln(a.out, "\nThe two signing keys above have no certificate at all, and that is the")
	fmt.Fprintln(a.out, "point of listing them beside four authorities: a trust root does not have")
	fmt.Fprintln(a.out, "to be a certificate authority. The bootloader anchors on a raw public key.")
}

func (a *app) relative(path string) string {
	rel, err := filepath.Rel(a.root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		// Outside the repository, such as the Zephyr build tree. An absolute
		// path reads better there than a chain of parent directories.
		return path
	}
	return rel
}

// Tier 3's flash geometry, from the pinned map in section 6 of
// docs/course-specification.md. The map is a fixed contract asserted in CI, so
// these are constants rather than something read back out of a build tree.
const (
	tier03HeaderSize = "0x20"
	tier03SlotSize   = "1835008"
	tier03Align      = "4"
	tier03Version    = "0.3.0+0"
)

// hostileImages are the four images the device must refuse.
//
// Every one is derived from the Learner's own good image, at the moment they
// ask for them. None is committed, so a fork of this repository never carries a
// ready made attack payload.
var hostileImages = []struct {
	name   string
	suffix string
	why    string
}{
	{"unsigned", "unsigned", "Nobody signed it. The bootloader finds no signature at all."},
	{"modified", "modified", "Signed correctly, then one byte was changed afterwards."},
	{"wrong-key", "wrong-key", "Signed properly, by a key the bootloader was not built to trust."},
	{"truncated", "truncated", "The download stopped before the signature arrived."},
}

func (a *app) release(args []string) error {
	if len(args) == 0 {
		return errors.New("release requires sign, assign, or hostile")
	}
	switch args[0] {
	case "sign":
		switch releaseTierOption(args[1:]) {
		case "04":
			return a.releaseSignTier04(releaseVariantOption(args[1:]))
		case "05":
			return a.releaseSignTier05(releaseVariantOption(args[1:]))
		case "06":
			return a.releaseSignTier06(releaseVariantOption(args[1:]))
		case "07":
			return a.releaseSignTier07(releaseVariantOption(args[1:]))
		}
		return a.releaseSign()
	case "assign":
		switch releaseTierOption(args[1:]) {
		case "05":
			return a.releaseAssignTier05(releaseVariantOption(args[1:]))
		case "06":
			return a.releaseAssignTier06(releaseVariantOption(args[1:]))
		}
		return errors.New("release assign needs a tier that has more than one release; pass --tier 05 or --tier 06")
	case "hostile":
		if tier := releaseTierOption(args[1:]); tier == "04" {
			return a.releaseHostileTier04()
		}
		return a.releaseHostile()
	default:
		return fmt.Errorf("unknown release command %q; use sign, assign, or hostile", args[0])
	}
}

func (a *app) tier03BuildDir() string {
	return filepath.Join(a.zephyrWorkspace(), "build", "tier-03-signed-images-baseline")
}

func (a *app) tier03RawImage() string {
	return filepath.Join(a.tier03BuildDir(), "tier-03-signed-images", "zephyr", "zephyr.bin")
}

func (a *app) releaseDir() string {
	return filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "releases")
}

// releaseSign is the step the build deliberately does not do.
//
// The private key is named here and nowhere else. The firmware build never sees
// it, which is the whole reason the bootloader is built separately.
func (a *app) releaseSign() error {
	key := a.signingKeyPath("release")
	if _, err := os.Stat(key); err != nil {
		return errors.New("no Release signing key yet; run ./course keys create release first")
	}
	raw := a.tier03RawImage()
	if _, err := os.Stat(raw); err != nil {
		return errors.New("no Tier 3 image to sign; run ./course build firmware --tier 03 first")
	}
	variant := tier03Variants["baseline"]
	out := filepath.Join(a.releaseDir(), variant.imageName)
	if err := os.MkdirAll(a.releaseDir(), 0o700); err != nil {
		return err
	}

	fingerprint, err := a.keyFingerprint(key)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Signing with the %s key, fingerprint %s\n", "release", fingerprint)
	if err := a.signImage(key, raw, out, "", tier03Version); err != nil {
		return err
	}

	release, err := a.publishSigned(variant, out, fingerprint)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: published %s, %d bytes, signed\n", variant.releaseID, release["image_size"])
	fmt.Fprintln(a.out, "The device will run this one, because its bootloader holds the matching public key.")
	return nil
}

// signImage runs imgtool and shows the command, the same way key creation does.
// counter is the security counter to place in the image's protected TLV area,
// or "" for no counter at all. Tier 3 and everything before it pass "", which
// is why those images have no protected TLV area: imgtool creates one only
// when something needs to go in it.
// signImage runs imgtool sign.
//
// extra carries arguments only some tiers need. Tier 5 uses it for the
// protected custom TLV that holds the source revision; nothing before Tier 5
// passes anything, and their call sites are unchanged.
func (a *app) signImage(key, in, out, counter, version string, extra ...string) error {
	python, imgtool := a.imgtool()
	if version == "" {
		version = tier03Version
	}
	arguments := []string{
		imgtool, "sign",
		"--version", version,
		"--header-size", tier03HeaderSize,
		"--slot-size", tier03SlotSize,
		"--align", tier03Align,
	}
	if counter != "" {
		arguments = append(arguments, "--security-counter", counter)
	}
	arguments = append(arguments, extra...)
	shown := append([]string{}, arguments...)
	if key != "" {
		arguments = append(arguments, "--key", key)
		shown = append(shown, "--key", a.relative(key))
	}
	arguments = append(arguments, in, out)
	shown = append(shown, a.relative(in), a.relative(out))
	fmt.Fprintf(a.out, "+ %s %s\n", python, strings.Join(shown, " "))
	return runAttached(a.root, a.out, a.errOut, python, arguments...)
}

// publishSigned writes the release record the OTA service serves.
//
// "signed": true is the service's claim about itself. No device reads it, and a
// compromised service would write it happily over a hostile image. Tier 4 is
// where the downloaded bytes start being checked by the application.
func (a *app) publishSigned(variant firmwareVariant, image, fingerprint string) (map[string]any, error) {
	data, err := os.ReadFile(image)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	release := map[string]any{
		"schema_version": 1, "release_id": variant.releaseID, "version": variant.version,
		"board": a.manifest.Devices["reference_beacon"].Board, "image_path": variant.imageName,
		"image_sha256": hex.EncodeToString(sum[:]), "image_size": len(data),
		"mutable": true, "signed": true, "signing_key_fingerprint": fingerprint,
	}
	state := filepath.Join(a.root, a.manifest.Paths.State, "ota")
	if err := os.MkdirAll(state, 0o700); err != nil {
		return nil, err
	}
	for _, name := range []string{"built-baseline.json", "seed-release.json", "current-release.json"} {
		if err := writeJSON(filepath.Join(state, name), release, 0o600); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(a.out, "  digest: %s\n", release["image_sha256"])
	return release, nil
}

// releaseHostile builds the four images the device must refuse.
//
// They are made from the Learner's own good image, here, rather than shipped.
// The attacker key that signs one of them came from the same command as the
// Release signing key and is exactly as valid.
func (a *app) releaseHostile() error {
	raw := a.tier03RawImage()
	if _, err := os.Stat(raw); err != nil {
		return errors.New("no Tier 3 image to work from; run ./course build firmware --tier 03 first")
	}
	attacker := a.signingKeyPath("attacker")
	if _, err := os.Stat(attacker); err != nil {
		return errors.New("no attacker key yet; run ./course keys create attacker first")
	}
	good := filepath.Join(a.releaseDir(), tier03Variants["baseline"].imageName)
	if _, err := os.Stat(good); err != nil {
		return errors.New("no signed release to work from; run ./course release sign first")
	}

	fmt.Fprintln(a.out, "Building four images your device should refuse, from your own good image.")
	fmt.Fprintln(a.out, "None of them is shipped with this course. They are made here, now, from what you just signed.")

	for _, image := range hostileImages {
		out := filepath.Join(a.releaseDir(), "tier-03-hostile-"+image.suffix+".bin")
		fmt.Fprintf(a.out, "\n%s: %s\n", image.name, image.why)
		var err error
		switch image.name {
		case "unsigned":
			err = a.signImage("", raw, out, "", tier03Version)
		case "wrong-key":
			fingerprint, ferr := a.keyFingerprint(attacker)
			if ferr != nil {
				return ferr
			}
			fmt.Fprintf(a.out, "  attacker key fingerprint %s, as valid as yours and trusted by nothing\n", fingerprint)
			err = a.signImage(attacker, raw, out, "", tier03Version)
		case "modified":
			err = deriveModified(good, out)
		case "truncated":
			err = deriveTruncated(good, out)
		}
		if err != nil {
			return err
		}
		info, serr := os.Stat(out)
		if serr != nil {
			return serr
		}
		fmt.Fprintf(a.out, "  wrote %s, %d bytes\n", a.relative(out), info.Size())
	}

	fmt.Fprintln(a.out, "\nResult: four hostile images ready.")
	fmt.Fprintln(a.out, "Publish one through your own service with ./course attack run tier-03/hostile-image")
	return nil
}

// deriveModified flips one byte well inside the payload of a correctly signed
// image, so everything about it still looks right except the bytes the
// signature covers.
func deriveModified(good, out string) error {
	data, err := os.ReadFile(good)
	if err != nil {
		return err
	}
	const offset = 0x8000
	if len(data) <= offset {
		return errors.New("the signed image is too small to modify")
	}
	changed := append([]byte{}, data...)
	changed[offset] ^= 0xff
	return os.WriteFile(out, changed, 0o600)
}

// deriveTruncated cuts the tail off a correctly signed image, which is what a
// download that stops early leaves behind.
func deriveTruncated(good, out string) error {
	data, err := os.ReadFile(good)
	if err != nil {
		return err
	}
	const missing = 120
	if len(data) <= missing {
		return errors.New("the signed image is too small to truncate")
	}
	return os.WriteFile(out, data[:len(data)-missing], 0o600)
}

// fixtureUsesTLS says whether a fixture's data traffic goes over the verified
// connection Tier 2 added. It is true from Tier 2 onward: a later tier never
// goes back to plain HTTP for release data. The marker handshake is separate
// and stays in the clear in every tier, for the reason the safety contract
// gives.
func fixtureUsesTLS(id string) bool {
	return strings.HasPrefix(id, "tier-02/") ||
		strings.HasPrefix(id, "tier-03/") ||
		strings.HasPrefix(id, "tier-04/")
}

// fixtureCommand is the exact command that reproduces a run, including the
// selector when the fixture takes one. It goes in the evidence record, so it
// has to be the whole command and not an approximation of it.
//
// The option name comes from the fixture, because Tier 3 selects an image and
// Tier 4 selects a signed release. A command that named the wrong one would not
// reproduce anything.
func (a *app) fixtureCommand(id, selector string) string {
	command := fmt.Sprintf("./course attack run %s --execute %s", id, id)
	if selector == "" {
		return command
	}
	_, option := a.manifest.Fixtures[id].selectors()
	return command + " " + option + " " + selector
}

// tier03HostileImage publishes a hostile image through the genuine service.
//
// This is the Tier 0 altered-image attack with the Learner standing somewhere
// new. In Tier 0 they stood beside the service with an imposter. Here they are
// inside it: the service is the real one, its certificate verifies, the
// connection is encrypted, and it hands out exactly what they tell it to.
//
// Nothing in this function refuses anything, and that is the point. Every step
// succeeds. The refusal happens on the board, after the download, and the
// Learner reads it there.
func (a *app) tier03HostileImage(target string, env environment) (string, string, map[string]string, error) {
	selector := a.selector
	f := a.manifest.Fixtures["tier-03/hostile-image"]
	name := f.Images[selector]
	path := filepath.Join(a.releaseDir(), name)

	image, err := os.ReadFile(path)
	if err != nil {
		return "", "", nil, fmt.Errorf("no %s image yet; run ./course release hostile first", selector)
	}
	sum := sha256.Sum256(image)
	digest := hex.EncodeToString(sum[:])

	a.step(1, fmt.Sprintf("Take the %s image you built from your own good release.", selector))
	for _, described := range hostileImages {
		if described.name == selector {
			a.note("%s", described.why)
		}
	}
	a.note("%d bytes, sha256 %s", len(image), digest)
	a.note("Compare that digest with the one ./course release sign printed. The bytes are not the same bytes.")

	a.step(2, "Publish it through your own update service.")
	a.note("Not an imposter. The real service, with the certificate your device verifies.")
	// The hostile release carries its own identifier. The device decides
	// whether to install by comparing that, so reusing the good one would make
	// it shrug and carry on, which looks like the control working and is not.
	release := map[string]any{
		"schema_version": 1, "release_id": "tier-03-hostile-" + selector, "version": "0.3.1-hostile",
		"board": a.manifest.Devices["reference_beacon"].Board, "image_path": name,
		"image_sha256": digest, "image_size": len(image),
		"mutable": true, "signed": true,
	}
	// The service overwrites signed to false on every PUT, so this claim
	// never reaches a device. That is one honest bit in an otherwise
	// unverified record, and it changes nothing: no device reads the field,
	// and a release published through the signing path sets it to true
	// without anything checking that either. See issue #80.
	a.note("This record claims \"signed\": true. The service refuses to store that claim, and nothing verifies it either way.")
	if err := a.putRelease(target, env, release); err != nil {
		return "", "", nil, err
	}
	a.got("The service now offers this image to every device that asks.")

	a.step(3, "Confirm it comes back, the way the device will fetch it.")
	body, err := a.fetchFirmware(target, name)
	if err != nil {
		return "", "", nil, err
	}
	if !bytes.Equal(body, image) {
		return "", "", nil, errors.New("the service did not return the image unchanged")
	}
	a.got("%d bytes, byte for byte what you published, over a connection the device verified.", len(body))

	a.step(4, "Stop. Nothing here can refuse this image.")
	a.note("Every check Tier 2 added passed. The service is authentic, the connection is private,")
	a.note("the name matched, and the bytes arrived intact. All of that is true of hostile firmware.")
	a.note("The only thing that can still refuse it is the bootloader on the board.")
	a.note("Watch it with ./course device logs, and reset the board to make it install.")

	return fmt.Sprintf("the genuine service published the %s image and delivered it unchanged; the device outcome is not known to this fixture", selector),
		"The refusal under test is the bootloader's. This fixture records only what it published. Read the board.",
		map[string]string{name: digest}, nil
}

// putRelease overwrites the record that decides what every device installs.
//
// The service asks who is changing it in exactly the way Tier 0 showed: it does
// not. Tier 3 changes nothing about that, which is why this is still one PUT.
func (a *app) putRelease(target string, env environment, release map[string]any) error {
	body, err := json.Marshal(release)
	if err != nil {
		return err
	}
	client, endpoint := a.serviceClient(target)
	a.sent(http.MethodPut, endpoint+"/v1/releases/current")
	a.sentBody("replacing the current release with:", release)
	request, err := http.NewRequest(http.MethodPut, endpoint+"/v1/releases/current", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Course-Environment-ID", env.EnvironmentID)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("the service refused the release update: %s", response.Status)
	}
	return nil
}

func (a *app) fetchFirmware(target, name string) ([]byte, error) {
	client, endpoint := a.serviceClient(target)
	a.sent(http.MethodGet, endpoint+"/v1/firmware/"+url.PathEscape(name))
	response, err := client.Get(endpoint + "/v1/firmware/" + url.PathEscape(name))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the service returned %s for the firmware", response.Status)
	}
	return io.ReadAll(response.Body)
}

// serviceClient talks to the service the way the device does, over the verified
// connection Tier 2 added. The attack runs inside that, not around it.
func (a *app) serviceClient(target string) (*http.Client, string) {
	pool, err := a.trustAnchorPool()
	if err != nil {
		return a.client, target
	}
	return a.verifyingClient(pool, coursepki.ServiceName, a.tlsAddress(target)),
		"https://" + coursepki.ServiceName + ":" + strconv.Itoa(a.manifest.Runtime.TLSPort)
}

var tier03Plan = map[string][]string{
	"tier-03/hostile-image": {
		"Take one of the four images you built from your own good release.",
		"Publish it through your own update service, over the connection the device verifies.",
		"Fetch it back to prove the service delivers it unchanged.",
		"Stop. Nothing on this host can refuse it, and that is the finding.",
	},
}

var tier03Proves = map[string][]string{
	"tier-03/hostile-image": {
		"REQ-06: an operator with full control of the update service still cannot make a device run their firmware.",
		"T0-W-04 and T0-W-05: an unsigned or altered image is no longer enough, but only because the device checks.",
		"What Tier 2 did not do: every check it added passes here, on hostile firmware.",
	},
}

// Tier 3's flash offsets, from the pinned map in section 6 of
// docs/course-specification.md.
const (
	tier03BootloaderOffset = "0x0"
	tier03PrimarySlot      = "0x20000"
)

// flashSignedRelease writes the two images a signing tier builds separately.
//
// The bootloader comes from its own build, against the public half of the
// Learner's key. The application is the signed release, not the unsigned image
// the build produced, because an unsigned image is what these tiers exist to
// have refused.
//
// Tier 4 uses this unchanged. Its flash map is the same pinned map, its
// bootloader is built the same separate way, and its application is signed by
// the same command, so a second copy of this would only be a second thing to
// keep in step.
func (a *app) flashSignedRelease(device, buildDir string, variant firmwareVariant, tier string) error {
	bootloader := filepath.Join(buildDir+"-bootloader", "zephyr", "zephyr.bin")
	if _, err := os.Stat(bootloader); err != nil {
		return fmt.Errorf("no separately built bootloader; run ./course build firmware --tier %s --variant %s first", tier, variant.label)
	}
	image := filepath.Join(a.releaseDir(), variant.imageName)
	if _, err := os.Stat(image); err != nil {
		return fmt.Errorf("no signed release to flash; run ./course release sign%s first", signCommandSuffix(tier, variant))
	}

	workspace := a.zephyrWorkspace()
	esptool := filepath.Join(workspace, ".venv", "bin", "esptool")
	board := a.manifest.Devices["reference_beacon"].Board

	fingerprint, err := a.keyFingerprint(a.publicKeyPath())
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Tier %s writes two images that were built separately.\n", strings.TrimLeft(tier, "0"))
	fmt.Fprintf(a.out, "  bootloader: %s\n", bootloader)
	fmt.Fprintf(a.out, "              built against %s, and it will refuse anything else\n", fingerprint)
	fmt.Fprintf(a.out, "  application: %s\n", a.relative(image))
	fmt.Fprintln(a.out, "              the release you signed, not the unsigned image the build produced")
	fmt.Fprintln(a.out, "This writes normal flash only. It runs no eFuse, secure boot, or flash encryption command.")
	fmt.Fprintf(a.out, "+ %s --chip %s -p %s write-flash %s <bootloader> %s <application>\n",
		esptool, espChip(board), device, tier03BootloaderOffset, tier03PrimarySlot)

	return runAttachedFrom(a.root, workspace, a.out, a.errOut,
		[]string{"PATH=" + filepath.Join(workspace, ".venv", "bin") + string(os.PathListSeparator) + os.Getenv("PATH")},
		esptool, "--chip", espChip(board), "-p", device, "write-flash",
		tier03BootloaderOffset, bootloader, tier03PrimarySlot, image)
}

// signCommandSuffix names the options ./course release sign needs for a tier
// that has more than the one release Tier 3 had.
func signCommandSuffix(tier string, variant firmwareVariant) string {
	if tier == "03" {
		return ""
	}
	return " --tier " + tier + " --variant " + variant.label
}

// espChip turns the board target into the chip name esptool expects.
func espChip(board string) string {
	if before, _, found := strings.Cut(board, "_"); found {
		return before
	}
	return "esp32c6"
}

// releaseTierOption reads an optional --tier from a release subcommand. The
// default stays Tier 3, so every command a published module prints keeps
// working unchanged.
func releaseTierOption(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--tier" {
			return normalizeTier(args[i+1])
		}
	}
	return "03"
}

// releaseVariantOption reads an optional --variant from a release subcommand.
// Tier 4 has more than one good release, because a downgrade needs something to
// downgrade from, and the Learner signs each one separately.
func releaseVariantOption(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--variant" {
			return args[i+1]
		}
	}
	return "baseline"
}

// keysCreateDeviceCA makes the manufacturer device certificate authority.
//
// Section 8 requires three distinct trust relationships. This is the one that
// signs Factory identities and is trusted by the enrollment service, and it is
// deliberately not the Course certificate authority that signs the OTA
// service's TLS certificate. A course that used one authority for both would
// teach that a certificate authority is a thing you have one of.
func (a *app) keysCreateDeviceCA() error {
	dir := a.deviceCADir()
	if coursepki.DeviceCAExists(dir) {
		fmt.Fprintln(a.errOut, "A manufacturer device CA already exists.")
		fmt.Fprintf(a.errOut, "  path: %s\n", a.relative(filepath.Join(dir, coursepki.DeviceCACert)))
		fmt.Fprintln(a.errOut, "Every Factory certificate already issued chains to it. Replacing it")
		fmt.Fprintln(a.errOut, "would strand every provisioned board with an identity nothing verifies.")
		fmt.Fprintf(a.errOut, "To make a new one, remove it yourself first:\n  rm %s\n",
			a.relative(filepath.Join(dir, coursepki.DeviceCACert)))
		return errors.New("refusing to replace the existing manufacturer device CA")
	}
	fmt.Fprintln(a.out, "The manufacturer device CA. It signs Factory identities and nothing else.")
	fmt.Fprintln(a.out, "It is not the Course CA: that one signs the update service's own")
	fmt.Fprintln(a.out, "certificate, and the two answer different questions.")
	if err := coursepki.GenerateDeviceCA(dir); err != nil {
		return err
	}
	described, err := coursepki.Describe(filepath.Join(dir, coursepki.DeviceCACert))
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "%s\n", described)
	fmt.Fprintf(a.out, "Result: manufacturer device CA written to %s\n", a.relative(dir))
	return nil
}

// keysCreateOperationalCA makes the fourth authority.
//
// It is the second authority that signs device identities, and it is made by
// the Learner rather than by ./course setup. Two reasons, and the second is
// the one that would have bitten. A Learner should watch the fourth trust
// relationship appear, as they did the third. And adding a file to
// coursepki.Generate() would do nothing for anyone who has already run setup,
// because Exists() refuses to regenerate: every existing environment would
// silently lack it and the symptom would surface a long way from the cause.
func (a *app) keysCreateOperationalCA() error {
	dir := a.deviceCADir()
	if coursepki.OperationalCAExists(dir) {
		fmt.Fprintln(a.errOut, "An operational device CA already exists.")
		fmt.Fprintf(a.errOut, "  path: %s\n", a.relative(filepath.Join(dir, coursepki.OperationalCACert)))
		fmt.Fprintln(a.errOut, "Every Operational certificate already issued chains to it, and the")
		fmt.Fprintln(a.errOut, "update service verifies client certificates against it. Replacing it")
		fmt.Fprintln(a.errOut, "would lock every claimed device out of its own update service.")
		fmt.Fprintf(a.errOut, "To make a new one, remove it yourself first:\n  rm %s\n",
			a.relative(filepath.Join(dir, coursepki.OperationalCACert)))
		return errors.New("refusing to replace the existing operational device CA")
	}
	fmt.Fprintln(a.out, "The operational device CA. It signs Operational identities: one device,")
	fmt.Fprintln(a.out, "one owner, ninety days. It is not the manufacturer device CA, which says")
	fmt.Fprintln(a.out, "which board this is and says nothing about who owns it.")
	fmt.Fprintln(a.out, "")
	fmt.Fprintln(a.out, "The update service signs with this key while it is running, so the key")
	fmt.Fprintln(a.out, "and the service that uses it live on one machine. In a product they do")
	fmt.Fprintln(a.out, "not, and the module says what that separation buys.")
	if err := coursepki.GenerateOperationalCA(dir); err != nil {
		return err
	}
	described, err := coursepki.Describe(filepath.Join(dir, coursepki.OperationalCACert))
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "%s\n", described)
	fmt.Fprintf(a.out, "Result: operational device CA written to %s\n", a.relative(dir))
	return nil
}

// keysCreateSharedIdentity makes the fleet's one identity.
//
// This is the credential Tier 6 exists to argue against, and it is made with
// the same command that makes the others because nothing about it is
// technically inferior. It is a real Factory certificate signed by the real
// manufacturer device CA, carrying a real P-256 key. What is wrong with it is
// that there is one of it.
//
// The private half is deliberately compiled into the shared firmware variant,
// which is the single exception to the rule that no firmware build command
// names a private key. The exception is bounded to this one throwaway
// credential and written down in docs/fixture-safety-contract.md, because a
// credential a Learner cannot extract from their own image cannot teach why
// shared credentials fail.
func (a *app) keysCreateSharedIdentity() error {
	dir := a.deviceCADir()
	if !coursepki.DeviceCAExists(dir) {
		return errors.New("make the manufacturer device CA first: ./course keys create device-ca")
	}
	if coursepki.SharedIdentityExists(dir) {
		fmt.Fprintln(a.errOut, "A shared development identity already exists.")
		fmt.Fprintf(a.errOut, "  path: %s\n", a.relative(filepath.Join(dir, coursepki.SharedIdentityCert)))
		fmt.Fprintf(a.errOut, "To make a new one, remove it yourself first:\n  rm %s %s\n",
			a.relative(filepath.Join(dir, coursepki.SharedIdentityCert)),
			a.relative(filepath.Join(dir, coursepki.SharedIdentityKey)))
		return errors.New("refusing to replace the existing shared development identity")
	}

	fmt.Fprintln(a.out, "The shared development identity. One key pair and one certificate for")
	fmt.Fprintln(a.out, "the whole fleet, signed by your manufacturer device CA.")
	fmt.Fprintln(a.out, "")
	fmt.Fprintln(a.out, "Nothing about this certificate is weaker than the per-device ones that")
	fmt.Fprintln(a.out, "replace it. Same curve, same authority, same lifetime. What is wrong")
	fmt.Fprintln(a.out, "with it is that there is one of it, and every image built in the shared")
	fmt.Fprintln(a.out, "variant carries its private half.")
	if err := coursepki.GenerateSharedIdentity(dir); err != nil {
		return err
	}
	described, err := coursepki.Describe(filepath.Join(dir, coursepki.SharedIdentityCert))
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "%s\n", described)
	fmt.Fprintf(a.out, "Result: shared development identity written to %s\n", a.relative(dir))
	return nil
}
