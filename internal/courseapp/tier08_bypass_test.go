package courseapp

// Every Tier 8 row must be refused, and refused at the check its row names.
// They run the way the Tier 7 rows do: over a real TLS handshake, against the
// real service, started in process by the test. The one station row runs the
// real station in process, as a Learner's run does.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// newTier08Fixture is the Tier 7 fixture with the Tier 8 block pointed at the
// same listeners, and the shared development identity made, as ./course keys
// create shared-identity makes it.
func newTier08Fixture(t *testing.T) *bypassFixture {
	t.Helper()
	f := newBypassFixture(t)
	tier07 := f.app.manifest.Bypass[tier07BypassKey]
	block, ok := f.app.manifest.Bypass[tier08BypassKey]
	if !ok {
		t.Fatal("course.yml has no tier-08 bypass block")
	}
	block.Target = tier07.Target
	block.DevicePort = tier07.DevicePort
	block.OperatorPort = tier07.OperatorPort
	f.app.manifest.Bypass[tier08BypassKey] = block
	if err := coursepki.GenerateSharedIdentity(f.app.pkiDir()); err != nil {
		t.Fatal(err)
	}
	return f
}

var tier08Checks = []struct {
	id    string
	check string
}{
	{"e-8-01", "claim-window-open"},
	{"e-8-02", "identifier-consistent"},
	{"e-8-03", "key-unused"},
	{"e-8-04", "renewal-due"},
	{"e-8-05", "certificate-active"},
	{"e-8-06", "certificate-active"},
	{"e-8-07", "device-unrevoked"},
	{"e-8-08", "certificate-active"},
	{"e-8-09", "device-in-service"},
	{"e-8-10", "hardware-in-service"},
}

// claimThenRestart claims E-8-01's device and restarts the test's own
// service, so the answered window from that claim is no longer in memory.
// That is the state a lost Operational identity is found in: days after the
// claim, not seconds.
func claimThenRestart(t *testing.T, f *bypassFixture) {
	t.Helper()
	adversary, err := f.app.newTier08Adversary("E-8-01")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := adversary.claimSynthetic("beacon-bypass-e8-01"); err != nil {
		t.Fatal(err)
	}
	f.restart(t)
}

func TestEveryTier8RowRefusesAtItsOwnCheck(t *testing.T) {
	f := newTier08Fixture(t)
	claimThenRestart(t, f)
	for _, row := range tier08Checks {
		t.Run(row.id, func(t *testing.T) {
			output := f.run(t, row.id)
			if !strings.Contains(output, "refused at check "+row.check) {
				t.Fatalf("%s did not refuse at %s:\n%s", row.id, row.check, output)
			}
			if !strings.Contains(output, "Result: "+strings.ToUpper(row.id)+" refused at "+row.check) {
				t.Fatalf("%s did not report its result line:\n%s", row.id, output)
			}
			if !strings.Contains(output, "This is a host result; a host result never stands in for a device result") {
				t.Fatalf("%s did not label itself a host result:\n%s", row.id, output)
			}
			if strings.Contains(output, "signs with your own Operational Device CA key") {
				t.Fatalf("%s signed with the Operational CA key, which no Tier 8 row needs:\n%s", row.id, output)
			}
		})
	}
}

// Every row can be run again and still refuses at its own check. The
// operations it withdraws authority with are one-way, so a second run must
// find them done rather than be refused by them at some other check.
func TestEveryTier8RowRefusesAtItsOwnCheckTheSecondTime(t *testing.T) {
	f := newTier08Fixture(t)
	claimThenRestart(t, f)
	for _, row := range tier08Checks {
		f.run(t, row.id)
	}
	if err := f.app.bypassReset(); err != nil {
		t.Fatal(err)
	}
	for _, row := range tier08Checks {
		t.Run(row.id, func(t *testing.T) {
			output := f.run(t, row.id)
			if !strings.Contains(output, "Result: "+strings.ToUpper(row.id)+" refused at "+row.check) {
				t.Fatalf("%s did not refuse at %s on a second run after a reset:\n%s", row.id, row.check, output)
			}
		})
	}
}

// Each row's clause, where one check has more than one: the refusals at
// certificate-active are all the revoked-serial clause, and each names the
// serial, so a Learner can see it is status and not expiry or a missing
// record.
func TestTheCertificateActiveRowsAreTheRevokedClause(t *testing.T) {
	f := newTier08Fixture(t)
	for _, id := range []string{"e-8-05", "e-8-06", "e-8-08"} {
		output := f.run(t, id)
		if !strings.Contains(output, "is marked revoked") {
			t.Fatalf("%s did not refuse at the revoked clause:\n%s", id, output)
		}
	}
}

// The operations leave the lifecycle record in the state the row claims, and
// the serial store says only what each operation writes.
func TestTheTier8RowsLeaveTheRecordTheyClaim(t *testing.T) {
	f := newTier08Fixture(t)
	for _, id := range []string{"e-8-07", "e-8-08", "e-8-09"} {
		f.run(t, id)
	}
	for id, want := range map[string]string{
		"beacon-bypass-e8-07": lifecycle.Revoked,
		"beacon-bypass-e8-08": lifecycle.Transferred,
		"beacon-bypass-e8-09": lifecycle.Decommissioned,
	} {
		state, err := f.app.lifecycleStateOf(id)
		if err != nil {
			t.Fatal(err)
		}
		if state != want {
			t.Fatalf("%s is %q, want %q", id, state, want)
		}
	}
	adversary, err := f.app.newTier08Adversary("E-8-07")
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := f.app.revokedSerials()
	if err != nil {
		t.Fatal(err)
	}
	// Device revocation and decommissioning revoke no serial, or
	// certificate-active would refuse first and the row's own check would be
	// unreachable. A transfer revokes the old certificate.
	for id, want := range map[string]bool{
		"beacon-bypass-e8-07": false,
		"beacon-bypass-e8-08": true,
		"beacon-bypass-e8-09": false,
	} {
		serial := adversary.state.Devices[id].OperationalSerial
		if revoked[serial] != want {
			t.Fatalf("%s's serial %s revoked=%t, want %t", id, serial, revoked[serial], want)
		}
	}
}

// E-8-02 needs the shared development identity, and says how to make it when
// there is none, rather than refusing at the wrong check.
func TestTheSharedIdentityRowSaysWhatItNeeds(t *testing.T) {
	f := newTier08Fixture(t)
	for _, name := range []string{coursepki.SharedIdentityCert, coursepki.SharedIdentityKey} {
		if err := os.Remove(filepath.Join(f.app.pkiDir(), name)); err != nil {
			t.Fatal(err)
		}
	}
	err := f.app.serviceBypass([]string{"e-8-02", "--execute", "e-8-02"})
	if err == nil || !strings.Contains(err.Error(), "./course keys create shared-identity") {
		t.Fatalf("E-8-02 with no shared identity = %v", err)
	}
}

// The evidence record lands under tier-08, says host, and says no CA key was
// used.
func TestATier8RowWritesItsOwnEvidence(t *testing.T) {
	f := newTier08Fixture(t)
	f.run(t, "e-8-04")
	matches, err := filepath.Glob(filepath.Join(f.root, "artifacts", "generated", "attacks", "tier-08", "e-8-04", "*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("evidence records = %v, err=%v", matches, err)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record["observed_on"] != witnessHost || record["operational_ca_key_used"] != false ||
		record["result"] != "passed" {
		t.Fatalf("evidence record: %v", record)
	}
	state, err := f.app.readAdversaryState()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{state.OwnerCredential, state.Devices["beacon-bypass-e8-04"].OperationalKey} {
		if secret != "" && strings.Contains(string(raw), secret) {
			t.Fatal("the evidence record carries a secret")
		}
	}
	if strings.Contains(f.out.String(), state.OwnerCredential) {
		t.Fatal("the run printed the owner credential")
	}
}

// Dry run first, and the marker handshake before any side effect.
func TestATier8RowIsADryRunUntilItsOwnIdentifierIsGiven(t *testing.T) {
	f := newTier08Fixture(t)
	if err := f.app.serviceBypass([]string{"e-8-07"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Marker matched:",
		"Expected result: Refused at device-unrevoked",
		"Observed on: host",
		"Capability under test: the owner account of its own synthetic devices",
		"Result: dry run only",
		"Execute: ./course service bypass e-8-07 --execute e-8-07",
	} {
		if !strings.Contains(f.out.String(), want) {
			t.Fatalf("the dry run did not disclose %q:\n%s", want, f.out.String())
		}
	}
	if _, err := os.Stat(f.app.provisionRecordPath()); !os.IsNotExist(err) {
		t.Fatalf("a dry run wrote the manufacturing record, err=%v", err)
	}
	if err := os.Remove(filepath.Join(f.root, ".course-state", "environment.json")); err != nil {
		t.Fatal(err)
	}
	if err := f.app.serviceBypass([]string{"e-8-07", "--execute", "e-8-07"}); err == nil {
		t.Fatal("a Tier 8 row ran with no Course environment marker")
	}
}

// One adversary owner. A Tier 8 block that named a second would mint a second
// live account, and the runner refuses it.
func TestTheTier8BlockMayNotNameASecondAdversaryOwner(t *testing.T) {
	f := newTier08Fixture(t)
	block := f.app.manifest.Bypass[tier08BypassKey]
	block.AdversaryOwner = "second-rival"
	f.app.manifest.Bypass[tier08BypassKey] = block
	err := f.app.serviceBypass([]string{"e-8-04", "--execute", "e-8-04"})
	if err == nil || !strings.Contains(err.Error(), "exactly one adversary owner") {
		t.Fatalf("a second adversary owner = %v", err)
	}
}

// The manifest's own list is what the rows use, every name is one the station
// accepts, and the two E-8-10 names key to one board.
func TestTheTier8ManifestListIsBoundedAndValid(t *testing.T) {
	f := newTier08Fixture(t)
	block := f.app.manifest.Bypass[tier08BypassKey]
	if block.AdversaryOwner != f.app.manifest.Bypass[tier07BypassKey].AdversaryOwner {
		t.Fatal("the two blocks name different adversary owners")
	}
	for _, id := range block.SyntheticIDs {
		if err := validateDeviceID(id); err != nil {
			t.Fatal(err)
		}
	}
	if boardOf(tier08OldBoardID) != boardOf(tier08NewBoardID) || boardOf(tier08OldBoardID) != "02000000e810" {
		t.Fatalf("the E-8-10 names key to %q and %q", boardOf(tier08OldBoardID), boardOf(tier08NewBoardID))
	}
	adversary, err := f.app.newTier08Adversary("E-8-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := adversary.allowedIdentifier("beacon-bypass-e7-03"); err == nil {
		t.Fatal("a Tier 7 identifier was allowed to a Tier 8 row")
	}
}

// The Tier 8 listing is reachable through the real command dispatch, and the
// plain listing is still Tier 7's alone, as the published Tier 7 module
// quotes it.
func TestTheTier8ListingIsReachableAndTheTier7ListingIsUnchanged(t *testing.T) {
	root := testRepository(t)
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--repo", root, "service", "bypass", "list", "--tier", "08"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, row := range tier08Rows() {
		if !strings.Contains(stdout.String(), strings.ToUpper(row.id)) {
			t.Fatalf("the Tier 8 listing omits %s:\n%s", row.id, stdout.String())
		}
	}
	if !strings.Contains(stdout.String(), "A host result never stands in for a device result") {
		t.Fatalf("the Tier 8 listing does not carry the witness rule:\n%s", stdout.String())
	}
	stdout.Reset()
	if code := Run([]string{"--repo", root, "service", "bypass", "list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "E-8-") {
		t.Fatalf("the plain listing, which the Tier 7 module quotes, gained Tier 8 rows:\n%s", stdout.String())
	}
}

// Ten rows, every one a host runner, and none of them forges.
func TestTheTier8RowSet(t *testing.T) {
	rows := tier08Rows()
	if len(rows) != len(tier08Checks) {
		t.Fatalf("%d rows, want %d", len(rows), len(tier08Checks))
	}
	for i, row := range rows {
		if row.id != tier08Checks[i].id || row.run == nil || row.forges || row.witness != witnessHost {
			t.Fatalf("row %d: %+v", i, row)
		}
		if !strings.Contains(row.expected, tier08Checks[i].check) {
			t.Fatalf("%s expects %q, and its test asserts %q", row.id, row.expected, tier08Checks[i].check)
		}
	}
}

// E-8-01 straight after a claim, with no restart. The service keeps the
// window that claim answered so the device can collect its certificate, and it
// must not treat that window as open (#261).
func TestE801RefusesStraightAfterAClaim(t *testing.T) {
	f := newTier08Fixture(t)
	if err := f.app.serviceBypass([]string{"e-8-01", "--execute", "e-8-01"}); err != nil {
		t.Fatalf("E-8-01 with the answered window in memory: %v\n%s", err, f.out.String())
	}
}
