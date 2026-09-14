package courseapp

// Tier 3 gives the Reference product a bootloader that checks who published an
// image. This file holds the Learner-facing key handling and the signing and
// publishing path that goes with it.
//
// The shape is settled on issue #51. The Learner creates their own key with an
// explicit command rather than through ./course setup, the key lives under
// .course-secrets/, and no firmware build command ever names it.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		return errors.New("keys requires create or list")
	}
	switch args[0] {
	case "create":
		if len(args) < 2 {
			return errors.New("usage: ./course keys create release|attacker")
		}
		return a.keysCreate(args[1])
	case "list":
		return a.keysList()
	default:
		return fmt.Errorf("unknown keys command %q; use create or list", args[0])
	}
}

// keysCreate runs the real imgtool, and shows the Learner the command before it
// runs it.
//
// The course owns the path and the overwrite guard. It does not own the key
// generation itself, because a Learner who never sees imgtool has been handed a
// key by a course command rather than having made one.
func (a *app) keysCreate(role string) error {
	description, ok := signingRoles[role]
	if !ok {
		return fmt.Errorf("unknown key role %q; use release or attacker", role)
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
func (a *app) keysList() error {
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
		return nil
	}
	if _, err := os.Stat(a.publicKeyPath()); err == nil {
		fmt.Fprintf(a.out, "\nThe bootloader is built against %s, and nothing else.\n", a.relative(a.publicKeyPath()))
	}
	if found > 1 {
		fmt.Fprintln(a.out, "\nBoth keys are ECDSA P-256 and both are equally valid.")
		fmt.Fprintln(a.out, "Only the fingerprint compiled into the bootloader decides which one the device will run.")
	}
	return nil
}

func (a *app) relative(path string) string {
	if rel, err := filepath.Rel(a.root, path); err == nil {
		return rel
	}
	return path
}
