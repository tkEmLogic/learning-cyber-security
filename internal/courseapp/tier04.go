package courseapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Tier 4 signs two things with one key.
//
// Tier 3 signed a firmware image, which proves who published it. Tier 4 also
// signs the exact bytes of a Release manifest, which is what lets the device
// decide anything before the image arrives. Section 7 of the specification
// fixes that it is one key: "The offline firmware release-signing key signs
// the MCUboot image and the exact bytes of an immutable release manifest."
//
// The two are checked by different verifiers all the same. MCUboot holds the
// public key for the image, the application holds it for the manifest, and
// section 18 says passing one never counts as evidence for the other.
const (
	tier04Version = "0.4.0+0"

	// The security counter is a property of the release, not of a build flag,
	// so it lives in the variant beside the version. One value feeds both
	// imgtool's --security-counter and the manifest's security_counter field,
	// so the two cannot disagree.
	//
	// It is deliberately not derived from the version. Section 11 names
	// "human-readable versions override the security counter" as this tier's
	// failure criterion.
	tier04SecurityCounter = 1

	// The hardware revision this build asserts it is for. The chip can report
	// its silicon stepping, but nothing on this part reports the product's
	// hardware revision, so it is asserted here and signed rather than read.
	tier04HardwareRevision = 1

	// Five years, which is the support period section 4 fixes for the
	// Reference product.
	tier04SupportYears = 5
)

var tier04Variants = map[string]firmwareVariant{
	"baseline": {
		releaseID:       "tier-04-baseline",
		label:           "baseline",
		beaconState:     "steady",
		version:         "0.4.0-release-policy",
		imageName:       "tier-04-baseline.bin",
		securityCounter: tier04SecurityCounter,
	},
}

// releaseManifest is the Release manifest as it is written to disk.
//
// It is a struct rather than a map so the field order is the order a reader
// wants, and it is marshalled exactly once. Whatever bytes come out are the
// bytes that get signed and the bytes the service must serve back unchanged.
// Re-encoding the same values elsewhere produces different bytes and breaks
// the signature, which is why section 7 verifies the downloaded bytes before
// parsing rather than canonicalising them.
type releaseManifest struct {
	SchemaVersion       int    `json:"schema_version"`
	ReleaseID           string `json:"release_id"`
	Version             string `json:"version"`
	SecurityCounter     int    `json:"security_counter"`
	Channel             string `json:"channel"`
	Board               string `json:"board"`
	HardwareRevisionMin int    `json:"hardware_revision_min"`
	HardwareRevisionMax int    `json:"hardware_revision_max"`
	ImagePath           string `json:"image_path"`
	ImageSize           int    `json:"image_size"`
	ImageSHA256         string `json:"image_sha256"`
	CreatedAt           string `json:"created_at"`
	SupportedUntil      string `json:"supported_until"`
}

// manifestPath and signaturePath are the names the OTA service serves from.
// They sit beside the image in the release directory.
func (a *app) manifestPath(releaseID string) string {
	return filepath.Join(a.releaseDir(), releaseID+".manifest.json")
}

func (a *app) manifestSignaturePath(releaseID string) string {
	return filepath.Join(a.releaseDir(), releaseID+".manifest.sig")
}

// buildManifest describes one release. Nothing here is read from the service,
// and nothing here is negotiable at install time: these are the facts the
// device checks the delivered bytes against.
func (a *app) buildManifest(variant firmwareVariant, image []byte, now time.Time) releaseManifest {
	sum := sha256.Sum256(image)
	return releaseManifest{
		SchemaVersion:   1,
		ReleaseID:       variant.releaseID,
		Version:         variant.version,
		SecurityCounter: variant.securityCounter,
		// Two channels exist. A device refuses a manifest for a channel it was
		// not configured for, which is one more thing a mistaken release can
		// get wrong without anybody being an attacker.
		Channel:             "stable",
		Board:               a.manifest.Devices["reference_beacon"].Board,
		HardwareRevisionMin: tier04HardwareRevision,
		HardwareRevisionMax: tier04HardwareRevision,
		ImagePath:           variant.imageName,
		ImageSize:           len(image),
		ImageSHA256:         hex.EncodeToString(sum[:]),
		// The device has no clock and cannot check either of these. They are
		// carried and signed so they cannot be edited afterwards, reported in
		// status events, and consumed by Tier 9. Nothing on the device treats
		// them as a condition, and the module says so rather than letting a
		// date field imply a check that does not happen.
		CreatedAt:      now.UTC().Format(time.RFC3339),
		SupportedUntil: now.UTC().AddDate(tier04SupportYears, 0, 0).Format(time.RFC3339),
	}
}

// signManifest signs the exact bytes it is given.
//
// This is the first thing in the course that signs something other than a
// firmware image, so it does not go through imgtool, which is image shaped.
// It is ECDSA P-256 over SHA-256, and the signature is ASN.1 DER in a file of
// its own, which is what "detached" means: the manifest is not modified to
// carry its own signature, because then the bytes being signed would have to
// exclude part of themselves.
func signManifest(keyPEM []byte, data []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("release signing key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse release signing key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("release signing key is not ECDSA")
	}
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}

// writeSigningPublicKeyInc emits the image verification public key for the
// application build, the way writeTrustAnchor emits the Course certificate
// authority.
//
// It writes the bare 65 byte uncompressed EC point, not the SPKI wrapper the
// PEM file holds. The device imports that point directly through PSA, so
// stripping the wrapper here costs the firmware no ASN.1 parser at all and
// keeps CONFIG_MBEDTLS_PEM_PARSE_C off. Research on #65 measured that turning
// PEM parsing on would cost 1696 bytes of .text to do at run time what this
// does for free.
//
// Only the public half is ever read here. No firmware build command names the
// Release signing key, which docs/fixture-safety-contract.md forbids in as
// many words.
func (a *app) writeSigningPublicKeyInc() (string, error) {
	pemBytes, err := os.ReadFile(a.publicKeyPath())
	if err != nil {
		return "", errors.New("no public signing key yet; run ./course keys create release first")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", errors.New("public signing key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse public signing key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("public signing key is not ECDSA")
	}
	point := elliptic.Marshal(key.Curve, key.X, key.Y)

	dir := filepath.Join(a.root, a.manifest.Paths.State, "firmware", "anchor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var out []byte
	out = append(out, "/* Generated by ./course build firmware. Do not edit or commit. */\n"...)
	for i, b := range point {
		if i%12 == 0 {
			out = append(out, "\n\t"...)
		}
		out = append(out, fmt.Sprintf("0x%02x, ", b)...)
	}
	out = append(out, '\n')
	path := filepath.Join(dir, "release_pubkey.inc")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

func (a *app) tier04BuildDir() string {
	return filepath.Join(a.zephyrWorkspace(), "build", "tier-04-release-policy-baseline")
}

func (a *app) tier04RawImage() string {
	return filepath.Join(a.tier04BuildDir(), "tier-04-release-policy", "zephyr", "zephyr.bin")
}

// releaseSignTier04 signs the image and the manifest, in that order, because
// the manifest describes the signed image and has to be built from its bytes.
func (a *app) releaseSignTier04() error {
	key := a.signingKeyPath("release")
	if _, err := os.Stat(key); err != nil {
		return errors.New("no Release signing key yet; run ./course keys create release first")
	}
	raw := a.tier04RawImage()
	if _, err := os.Stat(raw); err != nil {
		return errors.New("no Tier 4 image to sign; run ./course build firmware --tier 04 first")
	}
	variant := tier04Variants["baseline"]
	out := filepath.Join(a.releaseDir(), variant.imageName)
	if err := os.MkdirAll(a.releaseDir(), 0o700); err != nil {
		return err
	}

	fingerprint, err := a.keyFingerprint(key)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Signing with the release key, fingerprint %s\n", fingerprint)

	// The counter goes into the image here and into the manifest below, from
	// the same constant. Section 6 requires the same value in both.
	if err := a.signImage(key, raw, out, strconv.Itoa(variant.securityCounter)); err != nil {
		return err
	}

	image, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	manifest := a.buildManifest(variant, image, time.Now())
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	manifestFile := a.manifestPath(variant.releaseID)
	if err := os.WriteFile(manifestFile, data, 0o600); err != nil {
		return err
	}

	keyPEM, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	signature, err := signManifest(keyPEM, data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(a.manifestSignaturePath(variant.releaseID), signature, 0o600); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "+ signed %d manifest bytes with ECDSA P-256 over SHA-256\n", len(data))
	fmt.Fprintf(a.out, "  manifest:  %s\n", a.relative(manifestFile))
	fmt.Fprintf(a.out, "  signature: %s, %d bytes of ASN.1 DER\n",
		a.relative(a.manifestSignaturePath(variant.releaseID)), len(signature))
	fmt.Fprintf(a.out, "  digest:    %s\n", manifest.ImageSHA256)
	fmt.Fprintf(a.out, "  counter:   %d, in the image TLV and in the manifest\n", manifest.SecurityCounter)
	fmt.Fprintln(a.out, "The signature covers these exact bytes. Reformatting the file breaks it,")
	fmt.Fprintln(a.out, "which is why the device verifies the bytes before it parses them.")
	return nil
}
