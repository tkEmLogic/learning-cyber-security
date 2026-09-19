package courseapp

// Every host-witnessed Tier 7 row must be refused, and refused at the check
// the section 11 table names. A refusal at a different check has not tested
// the row, which is Tier 6's rule carried into a second namespace.
//
// These run over a real TLS handshake against the real service, not against a
// synthesized request. That is deliberate and it is the whole reason the
// listener changed on this ticket: a synthesized r.TLS cannot see a
// certificate the handshake would have thrown away, and that is exactly how
// clause 1 of certificate-active came to be unreachable while seventeen tests
// passed.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
	"github.com/tkEmLogic/learning-cyber-security/services/ota"
)

// The Learner's own board, as the record will hold it after E-7-01. The
// ownership-context row forges against a device somebody else has claimed,
// and in an ordinary lab that is this one.
const (
	testBoardID    = "beacon-remfg-404cca5ea9fc"
	testBoardOwner = "northwind"
	testBoardSeria = "81985529216486895"
)

type bypassFixture struct {
	app  *app
	out  *bytes.Buffer
	root string
}

// newBypassFixture stands up the Learner's own environment: the four
// authorities, the three listeners the service runs with --mutual-tls, and a
// course.yml that is the one this repository ships.
func newBypassFixture(t *testing.T) *bypassFixture {
	t.Helper()
	root := testRepository(t)
	stateDir := filepath.Join(root, ".course-state", "ota")
	provisioning := filepath.Join(root, ".course-state", "provisioning")
	releases := filepath.Join(root, "artifacts", "generated", "releases")
	pki := filepath.Join(root, ".course-secrets", "pki")
	for _, dir := range []string{stateDir, provisioning, releases} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The four authorities, made the way ./course setup and ./course keys
	// create make them.
	if err := coursepki.Generate(pki); err != nil {
		t.Fatal(err)
	}
	if err := coursepki.GenerateDeviceCA(pki); err != nil {
		t.Fatal(err)
	}
	if err := coursepki.GenerateOperationalCA(pki); err != nil {
		t.Fatal(err)
	}

	mutual := &ota.MutualTLS{
		ManufacturerCA:  readTestCA(t, filepath.Join(pki, coursepki.DeviceCACert)),
		OperationalCA:   readTestCA(t, filepath.Join(pki, coursepki.OperationalCACert)),
		ProvisioningDir: provisioning,
		PKIDir:          pki,
	}
	service, err := ota.New(ota.Config{
		CourseID:      "learning-cyber-security",
		EnvironmentID: "bypass-test",
		Tier:          "07",
		StateDir:      stateDir,
		ReleaseDir:    releases,
		MutualTLS:     mutual,
	})
	if err != nil {
		t.Fatal(err)
	}

	serverCertificate, err := tls.LoadX509KeyPair(
		filepath.Join(pki, coursepki.ServiceCert), filepath.Join(pki, coursepki.ServiceKey))
	if err != nil {
		t.Fatal(err)
	}

	// The device listener, configured exactly as cmd/ota configures it: a
	// client certificate is required, and the only question asked of it in the
	// handshake is which authority signed it.
	device := httptest.NewUnstartedServer(service.DeviceHandler())
	device.TLS = &tls.Config{
		Certificates:          []tls.Certificate{serverCertificate},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: mutual.VerifyClientCertificate,
	}
	device.StartTLS()
	t.Cleanup(device.Close)

	operator := httptest.NewUnstartedServer(service.OperatorHandler())
	operator.TLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}}
	operator.StartTLS()
	t.Cleanup(operator.Close)

	devicePort := portOf(t, device.URL)
	operatorPort := portOf(t, operator.URL)
	plain := httptest.NewServer(service.SplitPublicHandler(devicePort, operatorPort, coursepki.ServiceName))
	t.Cleanup(plain.Close)

	writeJSON(filepath.Join(root, ".course-state", "environment.json"), environment{
		SchemaVersion: 1,
		CourseID:      "learning-cyber-security",
		EnvironmentID: "bypass-test",
		Tier:          "07",
		SyntheticData: true,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(time.Hour),
	}, 0o600)

	// The fixture requires the Learner's own service to be up under
	// --mutual-tls and refuses to start one. In a test the listeners above are
	// that service, so the two files ./course service start would have written
	// are written here.
	if err := os.WriteFile(filepath.Join(root, ".course-state", "ota.pid"),
		[]byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".course-state", "service-mode"),
		[]byte("mutual-tls"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	a, err := load(root, out, out)
	if err != nil {
		t.Fatal(err)
	}
	// The manifest is this repository's own, so the block's shape, its bounded
	// identifier list and its owner slug are all under test. Only the three
	// values that cannot be known until a listener is bound are replaced.
	block := a.manifest.Bypass[tier07BypassKey]
	block.Target = plain.URL
	block.DevicePort = devicePort
	block.OperatorPort = operatorPort
	a.manifest.Bypass[tier07BypassKey] = block

	return &bypassFixture{app: a, out: out, root: root}
}

func readTestCA(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func portOf(t *testing.T, url string) int {
	t.Helper()
	_, port, ok := strings.Cut(strings.TrimPrefix(url, "https://"), ":")
	if !ok {
		t.Fatalf("no port in %s", url)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return number
}

// claimTheBoard writes the claim record E-7-01 leaves behind, so the
// ownership-context row has a device that somebody other than the adversary
// owns.
func (f *bypassFixture) claimTheBoard(t *testing.T) {
	t.Helper()
	if err := f.app.writeRecord(provisionRecord{
		Kind:       recordClaim,
		DeviceID:   testBoardID,
		OwnerID:    testBoardOwner,
		Lifecycle:  "claimed",
		CertSerial: testBoardSeria,
		Station:    "course-ota-service",
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *bypassFixture) run(t *testing.T, row string) string {
	t.Helper()
	f.out.Reset()
	if err := f.app.serviceBypass([]string{row, "--execute", row}); err != nil {
		t.Fatalf("%s: %v\n%s", row, err, f.out.String())
	}
	return f.out.String()
}

// The thirteen host rows, each asserting the check its table row names.
func TestEveryHostRowRefusesAtItsOwnCheck(t *testing.T) {
	rows := []struct {
		id    string
		check string
	}{
		{"e-7-03", "identity-operational"},
		{"e-7-04", "identity-factory"},
		{"e-7-05", "certificate-active"},
		{"e-7-06", "certificate-active"},
		{"e-7-07", "certificate-active"},
		{"e-7-08", "device-claimed"},
		{"e-7-09", "identifier-consistent"},
		{"e-7-10", "ownership-context"},
		{"e-7-11", "nonce-unspent"},
		{"e-7-13", "nonce-match"},
		{"e-7-14", "device-unowned"},
	}
	f := newBypassFixture(t)
	f.claimTheBoard(t)
	for _, row := range rows {
		t.Run(row.id, func(t *testing.T) {
			output := f.run(t, row.id)
			want := "refused at check " + row.check
			if !strings.Contains(output, want) {
				t.Fatalf("%s did not %s:\n%s", row.id, want, output)
			}
			if !strings.Contains(output, "Result: "+strings.ToUpper(row.id)+" refused at "+row.check) {
				t.Fatalf("%s did not report its result line:\n%s", row.id, output)
			}
		})
	}
}

// E-7-12 spends the whole attempt budget, and the backoff between attempts is
// real, so it costs about fourteen seconds. It is skipped in short mode and
// run otherwise: the row is what proves a closed window refuses differently
// from a window that is open, and a test that never ran it would leave that
// unproven.
func TestClosedWindowIsRefusedAtClaimWindowOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("E-7-12 spends the real backoff, about fourteen seconds")
	}
	f := newBypassFixture(t)
	output := f.run(t, "e-7-12")
	if !strings.Contains(output, "refused at check claim-window-open") {
		t.Fatalf("E-7-12 did not refuse at claim-window-open:\n%s", output)
	}
	// The substitution is stated rather than hidden: the row says ten minutes
	// and the runner closes the window with the budget.
	if !strings.Contains(output, "may not move the") {
		t.Fatalf("E-7-12 did not say why it closed the window the way it did:\n%s", output)
	}
}

// E-7-15 is the row whose evidence is that there is no evidence. It must
// record the absence as an absence, and it must never invent a reason code for
// a layer that emits none.
func TestForeignIssuerClosesTheHandshakeAndLeavesNoTrail(t *testing.T) {
	f := newBypassFixture(t)
	output := f.run(t, "e-7-15")
	for _, want := range []string{
		"the connection closed",
		"There is no check name",
		"Result: E-7-15 closed the handshake and left nothing behind",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("E-7-15 did not report %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "refused at check") {
		t.Fatalf("E-7-15 reported a check name for a layer that emits none:\n%s", output)
	}
}

// The expired row is the reason the listener changed. Over a real handshake
// with tls.RequireAndVerifyClientCert it produced E-7-15's outcome, and a
// Learner reading the two rows side by side would have seen one refusal
// described two ways.
func TestTheExpiredRowIsRefusedByACheckAndNotByTheHandshake(t *testing.T) {
	f := newBypassFixture(t)
	output := f.run(t, "e-7-05")
	if strings.Contains(output, "E-7-15 outcome") {
		t.Fatalf("E-7-05 collapsed into E-7-15:\n%s", output)
	}
	if !strings.Contains(output, "refused at check certificate-active") {
		t.Fatalf("E-7-05 did not refuse at certificate-active:\n%s", output)
	}
	if !strings.Contains(output, "expired") {
		t.Fatalf("E-7-05's reason did not say the certificate expired:\n%s", output)
	}
}

// Every row signing with the Operational CA key must say so while it is doing
// it, name the row, print the fingerprint of the key, and call the capability
// what it is. The contract requires this in the same words it requires of a
// Tier 4 fixture signing with the Release signing key.
func TestEveryForgingRowNarratesTheCAKey(t *testing.T) {
	f := newBypassFixture(t)
	f.claimTheBoard(t)
	for _, row := range []string{"e-7-05", "e-7-07", "e-7-08", "e-7-10"} {
		t.Run(row, func(t *testing.T) {
			output := f.run(t, row)
			for _, want := range []string{
				"signs with your own Operational Device CA key",
				"key fingerprint: sha256:",
				"the capability under test is a leaked CA key",
			} {
				if !strings.Contains(output, want) {
					t.Fatalf("%s did not narrate %q:\n%s", row, want, output)
				}
			}
		})
	}
}

// The wrong-owner refusal never names the current owner. The check already
// tells the caller that the device is owned, and that oracle is decided and
// bounded; naming whom it belongs to is the one thing the caller could not
// otherwise obtain, and in a real fleet it maps a device to a customer.
func TestTheOwnershipRefusalNeverNamesTheOwner(t *testing.T) {
	f := newBypassFixture(t)
	f.claimTheBoard(t)
	output := f.run(t, "e-7-10")
	refusal := output[strings.Index(output, "refused at check"):]
	if strings.Contains(refusal, testBoardOwner) {
		t.Fatalf("the refusal named the current owner:\n%s", refusal)
	}
}

// The ownership-context row has nothing to forge against until somebody other
// than the adversary owns a device, and it says so precisely rather than
// refusing at the wrong check.
func TestOwnershipContextSaysWhatItNeedsWhenNobodyElseOwnsADevice(t *testing.T) {
	f := newBypassFixture(t)
	err := f.app.serviceBypass([]string{"e-7-10", "--execute", "e-7-10"})
	if err == nil {
		t.Fatalf("E-7-10 ran with no other owner in the record:\n%s", f.out.String())
	}
	if !strings.Contains(err.Error(), "Claim your board first") {
		t.Fatalf("E-7-10 did not say what it needs: %v", err)
	}
}

// A dry run first, and an execute identifier that has to match exactly.
func TestABypassRowIsADryRunUntilItsOwnIdentifierIsGiven(t *testing.T) {
	f := newBypassFixture(t)
	if err := f.app.serviceBypass([]string{"e-7-03"}); err != nil {
		t.Fatal(err)
	}
	output := f.out.String()
	if !strings.Contains(output, "Result: dry run only") {
		t.Fatalf("no dry run:\n%s", output)
	}
	for _, want := range []string{
		"Marker matched:",
		"Expected result: Refused at identity-operational",
		"Observed on: host",
		"Execute: ./course service bypass e-7-03 --execute e-7-03",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("the dry run did not disclose %q:\n%s", want, output)
		}
	}
	f.out.Reset()
	if err := f.app.serviceBypass([]string{"e-7-03", "--execute", "e-7-04"}); err == nil {
		t.Fatal("a mismatched execute identifier was accepted")
	}
}

// The marker handshake happens before any side effect, so a missing marker
// leaves the owner store and the manufacturing record untouched.
func TestAMissingMarkerRefusesBeforeAnySideEffect(t *testing.T) {
	f := newBypassFixture(t)
	if err := os.Remove(filepath.Join(f.root, ".course-state", "environment.json")); err != nil {
		t.Fatal(err)
	}
	if err := f.app.serviceBypass([]string{"e-7-03", "--execute", "e-7-03"}); err == nil {
		t.Fatal("a row ran with no Course environment marker")
	}
	for _, path := range []string{f.app.ownerStorePath(), f.app.provisionRecordPath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s was written before the marker check, err=%v", path, err)
		}
	}
}

// The fixture is a client. It never starts the service it is testing, and it
// says precisely what is wrong when the Learner's own service is not up under
// mutual TLS.
func TestARowRefusesWhenTheLearnerServiceIsNotInMutualTLS(t *testing.T) {
	f := newBypassFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, ".course-state", "service-mode"),
		[]byte("https"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := f.app.serviceBypass([]string{"e-7-03", "--execute", "e-7-03"})
	if err == nil || !strings.Contains(err.Error(), "--mutual-tls") {
		t.Fatalf("a row ran against a service without mutual TLS: %v", err)
	}
}

// Every identifier comes from the manifest's bounded list. One outside it is
// refused before anything is enrolled.
func TestAnIdentifierOutsideTheManifestListIsRefused(t *testing.T) {
	f := newBypassFixture(t)
	adversary, err := f.app.newTier07Adversary("E-7-03")
	if err != nil {
		t.Fatal(err)
	}
	if err := adversary.allowedIdentifier("beacon-not-in-the-manifest"); err == nil {
		t.Fatal("an identifier outside the bounded list was allowed")
	}
	for _, id := range adversary.manifest.SyntheticIDs {
		if err := adversary.allowedIdentifier(id); err != nil {
			t.Fatalf("the manifest's own identifier %s was refused: %v", id, err)
		}
		if err := validateDeviceID(id); err != nil {
			t.Fatalf("the manifest names an identifier the station cannot accept: %v", err)
		}
	}
}

// Reset clears live authorization state and rewinds no history.
//
// A record of what happened is never rewound, and a store that decides what
// happens next is. This test is that sentence.
func TestResetClearsLiveStateAndRewindsNoHistory(t *testing.T) {
	f := newBypassFixture(t)
	f.claimTheBoard(t)
	f.run(t, "e-7-06")

	before := f.readLines(t, f.app.provisionRecordPath())
	trail, err := f.app.serviceTrailLines()
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := f.app.revokedSerials(); err != nil || len(revoked) == 0 {
		t.Fatalf("E-7-06 marked nothing revoked, err=%v", err)
	}

	f.out.Reset()
	if err := f.app.bypassReset(); err != nil {
		t.Fatal(err)
	}

	// Cleared: the adversary owner, and the serials this fixture marked.
	owners, err := f.app.readOwnerRecords()
	if err != nil {
		t.Fatal(err)
	}
	adversary := f.app.manifest.Bypass[tier07BypassKey].AdversaryOwner
	for _, record := range owners {
		if record.OwnerID == adversary {
			t.Fatal("reset left the adversary owner as a live account")
		}
	}
	revoked, err := f.app.revokedSerials()
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 0 {
		t.Fatalf("reset left %d serial(s) marked revoked", len(revoked))
	}
	if _, err := os.Stat(f.app.bypassStatePath()); !os.IsNotExist(err) {
		t.Fatalf("reset left the fixture's own state behind, err=%v", err)
	}

	// Kept: every line of history, plus one more saying what was reset.
	after := f.readLines(t, f.app.provisionRecordPath())
	if len(after) != len(before)+1 {
		t.Fatalf("the manufacturing record went from %d lines to %d; reset appends one line and removes none",
			len(before), len(after))
	}
	if !strings.Contains(after[len(after)-1], recordFixtureReset) {
		t.Fatalf("the appended line is not a fixture_reset: %s", after[len(after)-1])
	}
	for i, line := range before {
		if after[i] != line {
			t.Fatalf("line %d of the manufacturing record changed:\n%s\n%s", i, line, after[i])
		}
	}
	if now, err := f.app.serviceTrailLines(); err != nil || now < trail {
		t.Fatalf("reset removed %d lines from the service's own trail, err=%v", trail-now, err)
	}

	// Kept: the Learner's own claim, which reset may not touch.
	if !f.app.recordsName(testBoardID) {
		t.Fatal("reset removed the Learner's own claim record")
	}
}

// Reset must not remove a serial the fixture did not mark, or an owner it does
// not hold.
func TestResetTouchesNothingTheFixtureDidNotMark(t *testing.T) {
	f := newBypassFixture(t)
	f.claimTheBoard(t)
	if err := f.app.claimRevoke([]string{"--serial", testBoardSeria}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.app.mintOwner(testBoardOwner); err != nil {
		t.Fatal(err)
	}
	if err := f.app.bypassReset(); err != nil {
		t.Fatal(err)
	}
	revoked, err := f.app.revokedSerials()
	if err != nil {
		t.Fatal(err)
	}
	if !revoked[testBoardSeria] {
		t.Fatal("reset removed a serial the Learner marked")
	}
	owners, err := f.app.readOwnerRecords()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := currentOwnerRecord(owners, testBoardOwner); !ok {
		t.Fatal("reset removed the Learner's own owner")
	}
}

// Reset is idempotent: running it twice is not an error and appends one line
// each time, because the fixture_reset entry is what satisfies the standing
// rule that refuses the next run until reset has succeeded.
func TestResetIsIdempotent(t *testing.T) {
	f := newBypassFixture(t)
	if err := f.app.bypassReset(); err != nil {
		t.Fatal(err)
	}
	if err := f.app.bypassReset(); err != nil {
		t.Fatalf("a second reset failed: %v", err)
	}
}

// The listing names every row, its witness, and whether it needs the CA key,
// and it reaches through the real command dispatch.
func TestTheRowListingIsCompleteAndReachable(t *testing.T) {
	root := testRepository(t)
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--repo", root, "service", "bypass", "list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	output := stdout.String()
	for _, row := range tier07Rows() {
		if !strings.Contains(output, strings.ToUpper(row.id)) {
			t.Fatalf("the listing omits %s:\n%s", row.id, output)
		}
	}
	if !strings.Contains(output, "A host result never stands in for a device result") {
		t.Fatalf("the listing does not carry the witness rule:\n%s", output)
	}
}

// The two board rows are listed and are not runnable here. A host runner that
// answered for them would be the one thing the witness rule forbids.
func TestTheBoardRowsAreNotHostRunners(t *testing.T) {
	f := newBypassFixture(t)
	for _, row := range []string{"e-7-01", "e-7-02"} {
		err := f.app.serviceBypass([]string{row, "--execute", row})
		if err == nil || !strings.Contains(err.Error(), "board row") {
			t.Fatalf("%s ran on the host: %v", row, err)
		}
	}
}

// Fifteen rows, and the witness column takes exactly the three values issue
// #142 settled.
func TestTheRowSetMatchesTheSectionElevenTable(t *testing.T) {
	rows := tier07Rows()
	if len(rows) != 15 {
		t.Fatalf("%d rows, want 15", len(rows))
	}
	witnesses := map[string]int{}
	for _, row := range rows {
		switch row.witness {
		case witnessHost, witnessDevice, witnessBoth:
			witnesses[row.witness]++
		default:
			t.Fatalf("%s has witness %q, which is not one of the three", row.id, row.witness)
		}
		if row.witness == witnessDevice && row.run != nil {
			t.Fatalf("%s is a device row with a host runner", row.id)
		}
		if row.witness != witnessDevice && row.run == nil {
			t.Fatalf("%s has no runner", row.id)
		}
	}
	if witnesses[witnessDevice] != 2 {
		t.Fatalf("%d device rows, want the two successes", witnesses[witnessDevice])
	}
}

func (f *bypassFixture) readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}
