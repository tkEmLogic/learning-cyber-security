package courseapp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testReleaseKey(t *testing.T) ([]byte, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), &key.PublicKey
}

// The signature covers bytes, not values. This is the whole reason section 7
// verifies the downloaded bytes before parsing instead of canonicalising them,
// and the reason the service must serve a stored manifest back unchanged.
func TestManifestSignatureCoversExactBytesNotValues(t *testing.T) {
	keyPEM, public := testReleaseKey(t)

	manifest := releaseManifest{
		SchemaVersion: 1, ReleaseID: "tier-04-baseline", Version: "0.4.0-release-policy",
		SecurityCounter: 1, Channel: "stable", Board: "esp32c6_devkitc/esp32c6/hpcore",
		HardwareRevisionMin: 1, HardwareRevisionMax: 1,
		ImagePath: "tier-04-baseline.bin", ImageSize: 663611,
		ImageSHA256: "8ad643509ec835b176bd623632be35b6c21db35610ab1d74daca70bd077b69bc",
		CreatedAt:   "2026-09-14T13:20:00Z", SupportedUntil: "2031-09-14T13:20:00Z",
	}

	signed, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	signed = append(signed, '\n')

	signature, err := signManifest(keyPEM, signed)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(public, digest[:], signature) {
		t.Fatal("the signature must verify against the bytes that were signed")
	}

	// Same values, different bytes. A service that parsed the manifest and
	// re-encoded it would produce exactly this, and the device would refuse a
	// release that nobody had tampered with.
	reformatted, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(reformatted) == string(signed) {
		t.Fatal("the reformatted manifest must differ in bytes, or this proves nothing")
	}
	reDigest := sha256.Sum256(reformatted)
	if ecdsa.VerifyASN1(public, reDigest[:], signature) {
		t.Error("reformatting the manifest must break the signature")
	}

	// One value changed, everything else identical.
	tampered := manifest
	tampered.SecurityCounter = 2
	raised, err := json.MarshalIndent(tampered, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raised = append(raised, '\n')
	raisedDigest := sha256.Sum256(raised)
	if ecdsa.VerifyASN1(public, raisedDigest[:], signature) {
		t.Error("raising the security counter must break the signature")
	}
}

// Section 6 requires the same security counter in the signed image TLV and the
// signed manifest. They are the same constant here so they cannot drift, and
// this asserts nobody has split them apart later.
func TestSecurityCounterHasOneSource(t *testing.T) {
	variant := tier04Variants["baseline"]
	if variant.securityCounter != tier04SecurityCounter {
		t.Errorf("variant counter %d should be the tier constant %d",
			variant.securityCounter, tier04SecurityCounter)
	}

	a := &app{}
	a.manifest.Devices = map[string]struct {
		SyntheticID        string   `yaml:"synthetic_id"`
		SpoofID            string   `yaml:"spoof_id"`
		Board              string   `yaml:"board"`
		StableSerialPrefix string   `yaml:"stable_serial_prefix"`
		HardwareRequired   []string `yaml:"hardware_required"`
	}{"reference_beacon": {Board: "esp32c6_devkitc/esp32c6/hpcore"}}
	manifest := a.buildManifest(variant, []byte("firmware"), time.Date(2026, 9, 14, 13, 20, 0, 0, time.UTC))
	if manifest.SecurityCounter != variant.securityCounter {
		t.Errorf("manifest counter %d should equal the variant's %d",
			manifest.SecurityCounter, variant.securityCounter)
	}
}

// Every tier before Tier 4 carries no counter at all, which is what makes
// MCUboot allow the first swap. That is the migration case, not an oversight,
// so it is asserted rather than left to be rediscovered.
func TestTiersBeforeFourCarryNoCounter(t *testing.T) {
	for name, variants := range map[string]map[string]firmwareVariant{
		"tier-00": firmwareVariants, "tier-02": tier02Variants, "tier-03": tier03Variants,
	} {
		for label, variant := range variants {
			if variant.securityCounter != 0 {
				t.Errorf("%s/%s carries counter %d; tiers before Tier 4 carry none",
					name, label, variant.securityCounter)
			}
		}
	}
}

// The default stays Tier 3, so every command a published module prints keeps
// working unchanged.
func TestReleaseSignDefaultsToTierThree(t *testing.T) {
	if got := releaseTierOption(nil); got != "03" {
		t.Errorf("bare release sign should stay Tier 3, got %q", got)
	}
	if got := releaseTierOption([]string{"--tier", "04"}); got != "04" {
		t.Errorf("--tier 04 should select Tier 4, got %q", got)
	}
	if got := releaseTierOption([]string{"--tier", "4"}); got != "04" {
		t.Errorf("--tier 4 should normalize to 04, got %q", got)
	}
}

// Tier 4 builds its own application, the way every tier since Tier 2 has. A
// control added in one tier must never be able to change the firmware a
// published tier describes.
func TestTierFourBuildsItsOwnApplication(t *testing.T) {
	dir, ok := firmwareApps["04"]
	if !ok {
		t.Fatal("Tier 4 has no firmware application")
	}
	if dir == firmwareApps["03"] {
		t.Fatal("Tier 4 must not share Tier 3's application directory")
	}
	for _, name := range []string{
		"CMakeLists.txt", "Kconfig", "prj.conf", "sysbuild.conf",
		"bootloader/mcuboot.conf", "anchor/release_pubkey.inc",
		"src/release_policy.c", "src/release_policy.h",
	} {
		if _, err := os.Stat(filepath.Join("..", "..", dir, name)); err != nil {
			t.Errorf("%s is missing from the Tier 4 application: %v", name, err)
		}
	}
}

// From Tier 3 the bootloader is built separately against the public half of
// the Learner's key, and the image is signed afterwards rather than by the
// build. Tier 4 inherits that whole arrangement.
func TestSignedTiersBuildTheirBootloaderSeparately(t *testing.T) {
	for tier, want := range map[string]bool{"00": false, "02": false, "03": true, "04": true} {
		if got := tierSignsItsOwnImage(tier); got != want {
			t.Errorf("tier %s: separate bootloader build %v, want %v", tier, got, want)
		}
	}
}

// The channel the build publishes to and the channel the device is configured
// to follow are one constant, for the same reason the counter is. A device
// that refused the channel its own build published to would be a puzzle
// rather than a lesson.
func TestReleaseChannelHasOneSource(t *testing.T) {
	a := &app{}
	a.manifest.Devices = map[string]struct {
		SyntheticID        string   `yaml:"synthetic_id"`
		SpoofID            string   `yaml:"spoof_id"`
		Board              string   `yaml:"board"`
		StableSerialPrefix string   `yaml:"stable_serial_prefix"`
		HardwareRequired   []string `yaml:"hardware_required"`
	}{"reference_beacon": {Board: "esp32c6_devkitc/esp32c6/hpcore"}}

	manifest := a.buildManifest(tier04Variants["baseline"], []byte("firmware"),
		time.Date(2026, 9, 14, 13, 20, 0, 0, time.UTC))
	if manifest.Channel != tier04Channel {
		t.Errorf("manifest channel %q should be the tier constant %q",
			manifest.Channel, tier04Channel)
	}

	// The manifest's hardware range has to cover the revision the build
	// asserts, or the device refuses its own release.
	if manifest.HardwareRevisionMin > tier04HardwareRevision ||
		manifest.HardwareRevisionMax < tier04HardwareRevision {
		t.Errorf("manifest hardware range %d..%d does not cover the asserted revision %d",
			manifest.HardwareRevisionMin, manifest.HardwareRevisionMax, tier04HardwareRevision)
	}
}

// Tier 4 needs two good releases, not one. A downgrade needs something to go
// backwards from, and the counter it has to be lower than has to be in an image
// the device is already running.
func TestTierFourHasTwoReleasesWithDifferentCounters(t *testing.T) {
	baseline := tier04Variants["baseline"]
	fix, ok := tier04Variants["security-fix"]
	if !ok {
		t.Fatal("Tier 4 needs a second good release for the replay fixture to have anything to replay past")
	}
	if fix.securityCounter <= baseline.securityCounter {
		t.Errorf("the later release must raise the counter, got %d after %d",
			fix.securityCounter, baseline.securityCounter)
	}
	if fix.releaseID == baseline.releaseID || fix.imageName == baseline.imageName || fix.label == baseline.label {
		t.Error("the two Tier 4 releases must be separate releases, with their own identifier, image and build")
	}
}

// Every hostile release needs its own identifier. The device decides whether to
// look at a release by comparing that against what it is running, so one that
// reused the good identifier would be ignored, and a Learner would read a
// device doing nothing as a refusal.
func TestEveryHostileReleaseHasItsOwnIdentifier(t *testing.T) {
	seen := map[string]bool{}
	for _, variant := range tier04Variants {
		seen[variant.releaseID] = true
	}
	for _, variant := range hostileManifests {
		id := hostileReleaseID(variant.name)
		if seen[id] {
			t.Errorf("%s reuses an identifier that already exists", id)
		}
		seen[id] = true
	}
	if len(hostileManifests) != 6 {
		t.Errorf("Tier 4 has six hostile releases, found %d", len(hostileManifests))
	}
}

// The split is the lesson, so it is asserted rather than left to prose. Two of
// the six are forgeries anyone could make. The other four can only be signed by
// whoever holds the Release signing key.
func TestOnlyTheTwoSignatureFailuresAreForgeries(t *testing.T) {
	forgeries := map[string]bool{}
	for _, variant := range hostileManifests {
		if !variant.learnerSigned {
			forgeries[variant.name] = true
		}
	}
	if len(forgeries) != 2 || !forgeries["modified"] || !forgeries["wrong-key"] {
		t.Errorf("the forgeries are modified and wrong-key, got %v", forgeries)
	}
}

func testGoodManifest() releaseManifest {
	return releaseManifest{
		SchemaVersion: 1, ReleaseID: "tier-04-baseline", Version: "0.4.0-release-policy",
		SecurityCounter: tier04SecurityCounter, Channel: tier04Channel,
		Board:               "esp32c6_devkitc/esp32c6/hpcore",
		HardwareRevisionMin: tier04HardwareRevision, HardwareRevisionMax: tier04HardwareRevision,
		ImagePath: "tier-04-baseline.bin", ImageSize: 1024,
		ImageSHA256: "5c3eb80066420002bc3dcc7ca4ab6efad7ed4b746f7b2a3ac0b0b0dd9b0d4f79",
		CreatedAt:   "2026-09-14T13:20:00Z", SupportedUntil: "2031-09-14T13:20:00Z",
	}
}

// Each variant must change exactly the one thing it is named for, beside its
// own release identifier. A variant that changed two things would have a
// Learner watching a refusal without knowing which check produced it.
func TestEachHostileVariantChangesOnlyWhatItIsNamedFor(t *testing.T) {
	good := testGoodManifest()
	good.ImageSize = 1024
	image := make([]byte, good.ImageSize)
	for i := range image {
		image[i] = byte(i)
	}
	sum := sha256.Sum256(image)
	good.ImageSHA256 = hex.EncodeToString(sum[:])

	expected := map[string][]string{
		// modified and wrong-key are signature failures. Their manifest values
		// are the good ones, because what is wrong with them is not a value.
		"modified":  {"release_id"},
		"wrong-key": {"release_id"},
		"hardware":  {"release_id", "hardware_revision_min", "hardware_revision_max"},
		"channel":   {"release_id", "channel"},
		"size":      {"release_id", "image_size"},
		"digest":    {"release_id", "image_sha256"},
	}
	for _, variant := range hostileManifests {
		hostile := deriveHostileManifest(variant.name, good, image)
		var changed []string
		for _, line := range manifestDifferences(good, hostile) {
			changed = append(changed, strings.SplitN(line, ",", 2)[0])
		}
		want := expected[variant.name]
		if len(changed) != len(want) {
			t.Errorf("%s changed %v, want %v", variant.name, changed, want)
			continue
		}
		for i := range want {
			if changed[i] != want[i] {
				t.Errorf("%s changed %v, want %v", variant.name, changed, want)
				break
			}
		}
	}
}

// The size and digest variants have to lie about the bytes that will actually
// be delivered. A size that happened to be right, or a digest that happened to
// match, would publish a perfectly good release and a Learner would watch for a
// refusal that never comes.
func TestSizeAndDigestVariantsDisagreeWithTheDeliveredImage(t *testing.T) {
	good := testGoodManifest()
	image := make([]byte, 4096)
	for i := range image {
		image[i] = byte(i)
	}
	sum := sha256.Sum256(image)
	good.ImageSHA256 = hex.EncodeToString(sum[:])
	good.ImageSize = len(image)

	size := deriveHostileManifest("size", good, image)
	if size.ImageSize == len(image) {
		t.Error("the size variant must declare a size the delivery will not match")
	}
	if size.ImageSize >= len(image) {
		t.Error("the declared size should be below the delivery, so Content-Length gives it away before a byte is written")
	}

	digest := deriveHostileManifest("digest", good, image)
	if digest.ImageSHA256 == good.ImageSHA256 {
		t.Error("the digest variant must declare a digest the delivered bytes will not produce")
	}
	if len(digest.ImageSHA256) != 64 {
		t.Errorf("the wrong digest must still be a real SHA-256, got %d characters", len(digest.ImageSHA256))
	}
	if _, err := hex.DecodeString(digest.ImageSHA256); err != nil {
		t.Errorf("the wrong digest must still be hex: %v", err)
	}
}

// The modified variant is the tampering case: the signature is genuine and the
// bytes it covered are gone. Both halves matter, so both are asserted.
func TestEditingAfterSigningBreaksTheSignatureItKeeps(t *testing.T) {
	keyPEM, public := testReleaseKey(t)
	good := testGoodManifest()
	image := make([]byte, 4096)
	sum := sha256.Sum256(image)
	good.ImageSHA256 = hex.EncodeToString(sum[:])

	hostile := deriveHostileManifest("modified", good, image)
	body, err := marshalManifest(hostile)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signManifest(keyPEM, body)
	if err != nil {
		t.Fatal(err)
	}
	if !manifestVerifies(public, body, signature) {
		t.Fatal("the manifest must verify before it is edited, or this proves nothing")
	}

	edited := bytes.Replace(body, []byte(good.ImageSHA256), []byte(wrongDigest(image)), 1)
	if bytes.Equal(edited, body) {
		t.Fatal("the edit must change the bytes")
	}
	if manifestVerifies(public, edited, signature) {
		t.Error("editing the manifest after signing must break the signature")
	}
}

// A manifest signed by the attacker key is as valid a signature as any. What
// makes it refusable is that it is not the key the application was built with,
// which is the same lesson Tier 3 taught about images.
func TestAnotherKeysSignatureIsValidAndStillRefused(t *testing.T) {
	_, public := testReleaseKey(t)
	attackerPEM, attackerPublic := testReleaseKey(t)

	body, err := marshalManifest(deriveHostileManifest("wrong-key", testGoodManifest(), nil))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signManifest(attackerPEM, body)
	if err != nil {
		t.Fatal(err)
	}
	if !manifestVerifies(attackerPublic, body, signature) {
		t.Fatal("the attacker signature is a real signature and must verify against the attacker key")
	}
	if manifestVerifies(public, body, signature) {
		t.Error("it must not verify against the key the application was built with")
	}
}

// MCUboot compares security_counter[0] > security_counter[1], so an equal
// counter is accepted. The replay has to name a strictly lower one, or it
// installs and looks like the control failing.
func TestReplayPicksTheHighestStrictlyLowerCounter(t *testing.T) {
	releases := []goodRelease{
		{manifest: releaseManifest{ReleaseID: "a", SecurityCounter: 1}},
		{manifest: releaseManifest{ReleaseID: "b", SecurityCounter: 2}},
		{manifest: releaseManifest{ReleaseID: "c", SecurityCounter: 3}},
	}
	older, ok := olderRelease(releases, 3)
	if !ok || older.manifest.ReleaseID != "b" {
		t.Errorf("the replay should choose the release just below the current one, got %q ok=%v", older.manifest.ReleaseID, ok)
	}
	if _, ok := olderRelease(releases, 1); ok {
		t.Error("nothing is lower than the lowest counter, so the fixture must refuse instead of replaying")
	}
	equal := []goodRelease{{manifest: releaseManifest{ReleaseID: "a", SecurityCounter: 2}}}
	if _, ok := olderRelease(equal, 2); ok {
		t.Error("an equal counter is accepted by MCUboot, so it is not a downgrade and must not be replayed")
	}
}

// Tier 4 selects a signed release, Tier 3 selects an image file, and the
// evidence record has to name the command that actually reproduces the run.
func TestFixtureSelectorNamesTheRightOption(t *testing.T) {
	images := fixture{Images: map[string]string{"modified": "tier-03-hostile-modified.bin"}}
	if allowed, option := images.selectors(); option != "--image" || len(allowed) != 1 {
		t.Errorf("an image fixture selects with --image, got %q", option)
	}
	releases := fixture{Releases: map[string]string{"channel": "tier-04-hostile-channel"}}
	if allowed, option := releases.selectors(); option != "--release" || len(allowed) != 1 {
		t.Errorf("a release fixture selects with --release, got %q", option)
	}
	none := fixture{}
	if allowed, option := none.selectors(); option != "--image" || len(allowed) != 0 {
		t.Errorf("a fixture with no selector offers none, got %q with %d entries", option, len(allowed))
	}

	a := &app{}
	a.manifest.Fixtures = map[string]fixture{"tier-04/hostile-release": releases}
	got := a.fixtureCommand("tier-04/hostile-release", "channel")
	want := "./course attack run tier-04/hostile-release --execute tier-04/hostile-release --release channel"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// course.yml owns the selector allowlist, and the table in tier04.go owns what
// each selector means. If they drift, a Learner can ask for a release the
// course cannot build, or build one the runner will not let them publish.
func TestCourseManifestOffersEveryHostileRelease(t *testing.T) {
	a, err := load("../..", io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	hostile, ok := a.manifest.Fixtures["tier-04/hostile-release"]
	if !ok {
		t.Fatal("course.yml is missing tier-04/hostile-release")
	}
	if len(hostile.Images) != 0 {
		t.Error("Tier 4 publishes hostile metadata, not hostile images, so it must not declare images")
	}
	for _, variant := range hostileManifests {
		got, ok := hostile.Releases[variant.name]
		if !ok {
			t.Errorf("course.yml does not offer the %s release", variant.name)
			continue
		}
		if got != hostileReleaseID(variant.name) {
			t.Errorf("course.yml names %s for %s, want %s", got, variant.name, hostileReleaseID(variant.name))
		}
	}
	if len(hostile.Releases) != len(hostileManifests) {
		t.Errorf("course.yml offers %d releases, the course builds %d", len(hostile.Releases), len(hostileManifests))
	}
	if !hostile.HardwareRequired {
		t.Error("the refusal under test is the device's, so the fixture must declare it needs hardware")
	}

	replay, ok := a.manifest.Fixtures["tier-04/replay-release"]
	if !ok {
		t.Fatal("course.yml is missing tier-04/replay-release")
	}
	if len(replay.Releases) != 0 || len(replay.Images) != 0 {
		t.Error("the replay forges nothing and chooses its release by counter, so it takes no selector")
	}
	if !replay.HardwareRequired {
		t.Error("the refusal under test is the device's, so the fixture must declare it needs hardware")
	}
}

// writeTestKey puts an ECDSA P-256 key where the course keeps one, and the
// public half where a build is allowed to read it.
func writeTestKey(t *testing.T, root, role string, public bool) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".course-secrets", "signing")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, role+".pem"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if public {
		spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(root, "artifacts", "generated", "signing")
		if err := os.MkdirAll(out, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "release.pub.pem"),
			pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &key.PublicKey
}

// testTier04Environment stands up just enough of a Course environment to run
// the hostile release generator: two keys, a signed good release, and the image
// it describes.
func testTier04Environment(t *testing.T) (*app, *bytes.Buffer, *ecdsa.PublicKey) {
	t.Helper()
	root := t.TempDir()
	out := &bytes.Buffer{}
	a := &app{root: root, out: out, errOut: out}
	a.manifest.Paths.Secrets = ".course-secrets"
	a.manifest.Paths.GeneratedArtifacts = "artifacts/generated"
	a.manifest.Devices = map[string]struct {
		SyntheticID        string   `yaml:"synthetic_id"`
		SpoofID            string   `yaml:"spoof_id"`
		Board              string   `yaml:"board"`
		StableSerialPrefix string   `yaml:"stable_serial_prefix"`
		HardwareRequired   []string `yaml:"hardware_required"`
	}{"reference_beacon": {Board: "esp32c6_devkitc/esp32c6/hpcore"}}

	public := writeTestKey(t, root, "release", true)
	writeTestKey(t, root, "attacker", false)

	signTestRelease(t, a, tier04Variants["baseline"])
	return a, out, public
}

// signTestRelease does what ./course release sign --tier 04 does to the release
// directory: an image, its manifest, and a detached signature over the exact
// manifest bytes.
func signTestRelease(t *testing.T, a *app, variant firmwareVariant) {
	t.Helper()
	image := make([]byte, 4096+variant.securityCounter)
	for i := range image {
		image[i] = byte(i)
	}
	if err := os.MkdirAll(a.releaseDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.releaseDir(), variant.imageName), image, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := a.buildManifest(variant, image, time.Date(2026, 9, 14, 13, 20, 0, 0, time.UTC))
	body, err := marshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(a.signingKeyPath("release"))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signManifest(keyPEM, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.manifestPath(variant.releaseID), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.manifestSignaturePath(variant.releaseID), signature, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The whole generator, run for real. Four of the six must verify against the
// Learner's own key, because nothing else can reach the checks that run after
// the signature has passed, and two must not, because they are forgeries.
func TestHostileReleaseGeneratorProducesBothKinds(t *testing.T) {
	a, out, public := testTier04Environment(t)
	if err := a.releaseHostileTier04(); err != nil {
		t.Fatal(err)
	}

	good, _, err := a.loadStoredManifest(tier04Variants["baseline"].releaseID)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range hostileManifests {
		id := hostileReleaseID(variant.name)
		manifest, body, err := a.loadStoredManifest(id)
		if err != nil {
			t.Errorf("%s: %v", variant.name, err)
			continue
		}
		signature, err := os.ReadFile(a.manifestSignaturePath(id))
		if err != nil {
			t.Errorf("%s has no detached signature: %v", variant.name, err)
			continue
		}
		if manifest.ReleaseID != id {
			t.Errorf("%s names release %s, want %s", variant.name, manifest.ReleaseID, id)
		}
		if manifest.ImagePath != good.ImagePath {
			t.Errorf("%s publishes its own image %s; every hostile release points at the good one",
				variant.name, manifest.ImagePath)
		}
		if got := manifestVerifies(public, body, signature); got != variant.learnerSigned {
			t.Errorf("%s verifies=%v against the release key, want %v", variant.name, got, variant.learnerSigned)
		}
	}

	// The narration is a contract rule, not a nicety. A Learner watching their
	// own key sign hostile manifests with no explanation will conclude it has
	// leaked.
	for _, phrase := range []string{
		"Your key has not leaked",
		"signing with your release key, fingerprint",
		"signing with the attacker key, fingerprint",
		"valid signature, and only your key could have produced it",
		"invalid signature, and anyone at all could have produced it",
	} {
		if !strings.Contains(out.String(), phrase) {
			t.Errorf("the generator must say %q while it signs", phrase)
		}
	}
}

// The replay may only name a release this environment produced. Four of the six
// hostile manifests carry a valid signature and sit in the same directory, so a
// scan of the directory would happily offer one of them.
func TestReplayNeverOffersAHostileRelease(t *testing.T) {
	a, _, _ := testTier04Environment(t)
	if err := a.releaseHostileTier04(); err != nil {
		t.Fatal(err)
	}
	releases, err := a.goodReleases()
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 1 || releases[0].manifest.ReleaseID != tier04Variants["baseline"].releaseID {
		t.Fatalf("only the good releases this environment produced may be replayed, got %d", len(releases))
	}
	// One good release is not enough to replay anything, which is the
	// migration precondition stated as an outcome rather than a surprise.
	if _, ok := olderRelease(releases, releases[0].manifest.SecurityCounter); ok {
		t.Error("a single release has nothing below it, so the fixture must refuse")
	}
}

// The hostile releases have to carry the counter of the newest signed release,
// not the baseline's. The application refuses a manifest whose counter is below
// its own, and that check runs before the channel check, so a hostile release
// stuck at the baseline's counter would show a Learner the downgrade control
// while they were trying to watch the channel control.
func TestHostileReleasesTrackTheNewestSignedRelease(t *testing.T) {
	a, _, _ := testTier04Environment(t)
	later := tier04Variants["security-fix"]
	signTestRelease(t, a, later)

	if err := a.releaseHostileTier04(); err != nil {
		t.Fatal(err)
	}
	newest, err := a.newestRelease()
	if err != nil {
		t.Fatal(err)
	}
	if newest.manifest.ReleaseID != later.releaseID {
		t.Fatalf("the newest release is %s, want %s", newest.manifest.ReleaseID, later.releaseID)
	}
	for _, variant := range hostileManifests {
		manifest, _, err := a.loadStoredManifest(hostileReleaseID(variant.name))
		if err != nil {
			t.Errorf("%s: %v", variant.name, err)
			continue
		}
		if manifest.SecurityCounter != later.securityCounter {
			t.Errorf("%s carries counter %d, want the newest release's %d",
				variant.name, manifest.SecurityCounter, later.securityCounter)
		}
		if manifest.ImagePath != later.imageName {
			t.Errorf("%s points at %s, want the newest release's image %s",
				variant.name, manifest.ImagePath, later.imageName)
		}
	}
}
