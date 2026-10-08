package courseapp

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// repositoryManifest loads this repository's own course.yml, so the plan under
// test is the one the course ships.
func repositoryManifest(t *testing.T) manifest {
	t.Helper()
	a, err := load(testRepository(t), &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	return a.manifest
}

// The shipped plan: the support listener first and asking for inventory, every
// board-capable fixture covered, and each line labelled by the list it is in.
func TestRegressionPlanFromCourseYML(t *testing.T) {
	m := repositoryManifest(t)
	plan, err := buildRegressionPlan(m)
	if err != nil {
		t.Fatal(err)
	}
	first := plan.board[0]
	if first.entry.ID != supportListenerFixtureID || first.selector != "inventory" || first.kind != kindSupportListener {
		t.Fatalf("the first board step is %s, want the support listener asking for inventory", first.name())
	}
	ran := map[string]bool{}
	for _, step := range plan.board {
		if step.label != labelBoard {
			t.Errorf("%s is in the board list and labelled %s", step.name(), step.label)
		}
		if !m.Fixtures[step.entry.ID].HardwareRequired {
			t.Errorf("%s needs no hardware and cannot give a board result", step.name())
		}
		ran[step.entry.ID] = true
	}
	for _, step := range plan.host {
		if step.label != labelHost {
			t.Errorf("%s is in the host list and labelled %s", step.name(), step.label)
		}
		if f, ok := m.Fixtures[step.entry.ID]; ok && f.HardwareRequired {
			t.Errorf("%s needs hardware and is in the host list", step.name())
		}
	}
	for _, id := range []string{"tier-00/altered-image", "tier-03/hostile-image", "tier-04/hostile-release",
		"tier-04/replay-release", supportListenerFixtureID} {
		if !ran[id] {
			t.Errorf("%s is board-capable and the shipped plan does not rerun it", id)
		}
	}
	var releases []string
	for _, step := range plan.board {
		if step.entry.ID == "tier-04/hostile-release" {
			releases = append(releases, step.selector)
		}
	}
	if len(releases) != len(m.Fixtures["tier-04/hostile-release"].Releases) {
		t.Errorf("the plan runs %d of Tier 4's hostile releases (%v), want all of them", len(releases), releases)
	}
	skipped := map[string]bool{}
	for _, skip := range plan.notRerun {
		skipped[skipName(skip)] = true
	}
	for _, want := range []string{"tier-09/support-listener reboot", "e-8-11", "tier-06/clone-shared-identity"} {
		if !skipped[want] {
			t.Errorf("%s should be listed as not rerun, with its reason", want)
		}
	}
}

// Each way the block can be wrong is refused before anything runs.
func TestRegressionPlanRefusesABadBlock(t *testing.T) {
	cases := []struct {
		name string
		edit func(*regressionManifest)
		want string
	}{
		{"a board-capable fixture left out", func(r *regressionManifest) {
			var kept []regressionEntry
			for _, entry := range r.Board {
				if entry.ID != "tier-04/replay-release" {
					kept = append(kept, entry)
				}
			}
			r.Board = kept
		}, "tier-04/replay-release"},
		{"the support listener not first", func(r *regressionManifest) {
			r.Board[0], r.Board[1] = r.Board[1], r.Board[0]
		}, "must start with"},
		{"a reboot request", func(r *regressionManifest) { r.Board[0].Request = "reboot" }, "inventory only"},
		{"a host fixture under board", func(r *regressionManifest) {
			r.Board = append(r.Board, regressionEntry{ID: "tier-00/plaintext-inspection", Expect: "refused"})
		}, "needs no hardware"},
		{"a board fixture under host", func(r *regressionManifest) {
			r.Host = append(r.Host, regressionEntry{ID: "tier-04/replay-release", Probe: probePlainReleaseRecord, Expect: "refused"})
		}, "belongs under board"},
		{"a selector outside the allowlist", func(r *regressionManifest) { r.Board[1].Release = "forged" }, "allowlist"},
		{"an expectation that can never pass", func(r *regressionManifest) { r.Board[1].Expect = "refuesd" }, "not one of"},
		{"a board row with no host runner", func(r *regressionManifest) {
			r.Host = append(r.Host, regressionEntry{ID: "e-7-01", Expect: "refused"})
		}, "no host runner"},
		{"an exclusion without a reason", func(r *regressionManifest) { r.NotRerun[0].Reason = " " }, "no reason"},
		{"an unbounded wait", func(r *regressionManifest) { r.BoardWaitSeconds = 3600 }, "board_wait_seconds"},
		{"an unbounded retry", func(r *regressionManifest) { r.SupportAttempts = 50 }, "support_attempts"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := repositoryManifest(t)
			c.edit(&m.Regression)
			if _, err := buildRegressionPlan(m); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal naming %q", err, c.want)
			}
		})
	}
}

const testBoard = "beacon-t08c-206ef1170d64"

func event(device, kind, running, detail string, at time.Time) boardEvent {
	return boardEvent{DeviceID: device, Event: kind, RunningReleaseID: running, Detail: detail,
		AcceptedFrom: "client_certificate", ReceivedAt: at}
}

// The board's reaction is read from its own stored events and nothing else.
func TestClassifyReleaseReactionFromEventRecords(t *testing.T) {
	since := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	before, after := since.Add(-time.Minute), since.Add(time.Minute)
	running, offered := "tier-10-corrected", "tier-04-hostile-channel"
	cases := []struct {
		name    string
		events  []boardEvent
		outcome string
		check   string
	}{
		{"refused before the download", []boardEvent{
			event(testBoard, "status.observed", running, "", after),
			event(testBoard, "update.refused", running, offered, after.Add(time.Second)),
		}, outcomeRefused, ""},
		{"refused after the download", []boardEvent{
			event(testBoard, "update.failed", running, offered, after),
		}, outcomeRefused, ""},
		{"a check the board names", []boardEvent{
			event(testBoard, "update.refused", running, offered+" check=release-channel", after),
		}, outcomeRefused, "release-channel"},
		{"refused by the bootloader at the next boot", []boardEvent{
			event(testBoard, "update.installed", running, offered, after),
			event(testBoard, "status.observed", running, "", after.Add(time.Minute)),
		}, outcomeRefusedAtBoot, ""},
		{"installed and running", []boardEvent{
			event(testBoard, "update.installed", running, offered, after),
			event(testBoard, "status.observed", offered, "", after.Add(time.Minute)),
		}, outcomeInstalled, ""},
		{"tried and reverted", []boardEvent{
			event(testBoard, "update.reverted", running, offered+" beacon-advancing", after),
		}, outcomeReverted, ""},
		{"another device's refusal is not the board's", []boardEvent{
			event("beacon-fleet-e9-01", "update.refused", running, offered, after),
		}, "", ""},
		{"a refusal from before the publish is an earlier run", []boardEvent{
			event(testBoard, "update.refused", running, offered, before),
		}, "", ""},
		{"the board's ordinary already-confirmed is no reaction", []boardEvent{
			event(testBoard, "update.refused", running, "already-confirmed", after),
		}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			outcome, check := classifyReleaseReaction(c.events, testBoard, offered, running, since)
			if outcome != c.outcome || check != c.check {
				t.Fatalf("got %q %q, want %q %q", outcome, check, c.outcome, c.check)
			}
		})
	}
}

// A wait that runs out is no result, never a pass.
func TestWaitForReactionTimesOutAsNoResult(t *testing.T) {
	clock := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	slept := 0
	sleep := func(d time.Duration) { clock = clock.Add(d); slept++ }
	read := func() ([]boardEvent, error) {
		return []boardEvent{event(testBoard, "status.observed", "tier-10-corrected", "", clock)}, nil
	}
	outcome, _, err := waitForReaction(read, testBoard, "tier-04-hostile-size", "tier-10-corrected",
		clock, 30*time.Second, now, sleep)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != "" {
		t.Fatalf("a wait with no reaction returned %q", outcome)
	}
	if slept == 0 || slept > 16 {
		t.Fatalf("slept %d times for a 30 s bound polled every 2 s", slept)
	}
	if verdict := judge(outcomeRefused, "image-size", outcome, ""); verdict != verdictNoResult {
		t.Fatalf("a timeout was judged %q, want %q", verdict, verdictNoResult)
	}
}

func TestJudge(t *testing.T) {
	cases := []struct{ expected, expectedCheck, observed, observedCheck, want string }{
		{outcomeRefused, "security-counter", outcomeRefused, "", verdictPass},
		{outcomeRefused, "security-counter", outcomeRefused, "security-counter", verdictPass},
		{outcomeRefused, "security-counter", outcomeRefused, "release-channel", verdictFail},
		{outcomeRefused, "", outcomeInstalled, "", verdictFail},
		{outcomeAbsent, "", outcomeAnswered, "", verdictFail},
		{outcomeAbsent, "", "", "", verdictNoResult},
	}
	for _, c := range cases {
		if got := judge(c.expected, c.expectedCheck, c.observed, c.observedCheck); got != c.want {
			t.Errorf("judge(%q, %q, %q, %q) = %q, want %q", c.expected, c.expectedCheck, c.observed, c.observedCheck, got, c.want)
		}
	}
}

// The board is found in the log, never named on a command line.
func TestIdentifyBoard(t *testing.T) {
	m := repositoryManifest(t)
	synthetic, prefixes := syntheticDeviceIDs(m)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	fresh := 10 * time.Minute
	events := []boardEvent{
		event("beacon-t07b-206ef1170d64", "status.observed", "tier-07-operational-identity", "", now.Add(-48*time.Hour)),
		event(m.Fleet.DeviceIDs[0], "status.observed", "tier-09-remediation", "", now.Add(-time.Minute)),
		event("beacon-bypass-e6-07", "status.observed", "x", "", now.Add(-time.Minute)),
		event(testBoard, "status.observed", "tier-09-remediation", "", now.Add(-4*time.Minute)),
		event(testBoard, "update.installed", "tier-09-remediation", "tier-10-candidate", now.Add(-2*time.Minute)),
	}
	board, err := identifyBoard(events, synthetic, prefixes, now, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if board.DeviceID != testBoard || board.RunningReleaseID != "tier-09-remediation" {
		t.Fatalf("board = %+v", board)
	}
	if board.TrialReleaseID != "tier-10-candidate" || board.againstReleaseID() != "tier-10-candidate" {
		t.Fatalf("an install with nothing after it is a trial in progress: %+v", board)
	}

	reverted := append(events, event(testBoard, "update.reverted", "tier-09-remediation", "tier-10-candidate beacon-advancing", now.Add(-time.Minute)))
	board, err = identifyBoard(reverted, synthetic, prefixes, now, fresh)
	if err != nil || board.TrialReleaseID != "" || board.againstReleaseID() != "tier-09-remediation" {
		t.Fatalf("a revert closes the trial: %+v %v", board, err)
	}

	if _, err := identifyBoard(events[:3], synthetic, prefixes, now, fresh); err == nil {
		t.Error("with only synthetic and stale reporters there is no board, and the run must say so")
	}
	two := append(events, event("beacon-t10x-0000000000aa", "status.observed", "tier-09-remediation", "", now))
	if _, err := identifyBoard(two, synthetic, prefixes, now, fresh); err == nil || !strings.Contains(err.Error(), "cannot tell") {
		t.Errorf("two recent boards must be refused, got %v", err)
	}
}

// The replay may name any tier's good release now, but never a withdrawn one,
// and never the Time floor lab image.
func TestReplayCandidatesSpanTiersAndSkipWithdrawn(t *testing.T) {
	a, _, _ := testTier04Environment(t)
	a.manifest.Paths.State = ".course-state"
	for _, variant := range []firmwareVariant{tier08Variants["baseline"], tier08Variants["time-floor"],
		tier09Variants["support-listener"], tier09Variants["remediation"]} {
		signTestRelease(t, a, variant)
	}
	// One line, as the service appends it.
	line, _ := json.Marshal(map[string]any{"kind": releaseWithdrawnKind, "release_id": "tier-09-support-listener"})
	if err := os.MkdirAll(filepath.Dir(a.provisionRecordPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.provisionRecordPath(), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	releases, err := a.replayCandidates()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, release := range releases {
		ids = append(ids, release.manifest.ReleaseID)
	}
	got := strings.Join(ids, " ")
	for _, want := range []string{"tier-04-baseline", "tier-08-credential-lifecycle", "tier-09-remediation"} {
		if !strings.Contains(got, want) {
			t.Errorf("candidates %q are missing %s", got, want)
		}
	}
	for _, never := range []string{"tier-09-support-listener", "tier-08-time-floor"} {
		if strings.Contains(got, never) {
			t.Errorf("candidates %q include %s", got, never)
		}
	}
	older, ok := olderRelease(releases, tier09RemediationCounter+2)
	if !ok || older.manifest.ReleaseID != "tier-09-remediation" {
		t.Errorf("against counter %d the replay picks %q", tier09RemediationCounter+2, older.manifest.ReleaseID)
	}
}

// regressionBench is the Learner's mutual-TLS service from the bypass harness,
// with the regression block and the runtime ports pointed at its listeners, a
// board that has reported, its signed release, and its recorded address.
func regressionBench(t *testing.T, supportPort int) *bypassFixture {
	t.Helper()
	f := newBypassFixture(t)
	f.claimTheBoard(t)
	f.seedBaseline(t)
	bypass := f.app.manifest.Bypass[tier07BypassKey]
	block := f.app.manifest.Regression
	block.Target = bypass.Target
	block.DevicePort = bypass.DevicePort
	block.OperatorPort = bypass.OperatorPort
	block.BoardWaitSeconds = 1
	block.SupportAttempts = 1
	f.app.manifest.Regression = block
	f.app.manifest.Runtime.OperatorTLSPort = bypass.OperatorPort
	support := f.app.manifest.Fixtures[supportListenerFixtureID]
	support.Port = supportPort
	f.app.manifest.Fixtures[supportListenerFixtureID] = support

	writeTestKey(t, f.root, "release", true)
	signTestRelease(t, f.app, tier09Variants["remediation"])
	if err := f.app.deviceAddress([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	status := event(testBoardID, "status.observed", "tier-09-remediation", "", time.Now().UTC())
	line, _ := json.Marshal(status)
	if err := os.WriteFile(f.app.eventsPath(), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	f.out.Reset()
	return f
}

// closedUDPPort is a loopback port nothing listens on, so the kernel answers
// port unreachable, as the corrected board's stack does.
func closedUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()
	return port
}

// A whole run against the real listeners: the dry run touches nothing, the
// executed run labels every line, the support listener's port unreachable is a
// board pass, a published release the board never answers is no result, the
// baseline comes back byte for byte, the event log survives, and the receipt
// holds the opening section of the final claim matrix.
func TestRegressionRunAgainstTheMutualTLSService(t *testing.T) {
	f := regressionBench(t, closedUDPPort(t))
	block := f.app.manifest.Regression
	block.Host = []regressionEntry{
		{ID: "tier-00/plaintext-inspection", Probe: probePlainReleaseRecord, Expect: outcomeNotServed},
		{ID: "tier-02/plaintext-inspection", Probe: probeClientCertificateRequired, Expect: outcomeRefused},
		{ID: "tier-02/name-mismatch", Probe: probeWrongNameCertificate, Expect: outcomeRefused},
		{ID: "e-7-03", Expect: outcomeRefused},
	}
	f.app.manifest.Regression = block
	baselineBefore, err := os.ReadFile(f.app.baselinePath())
	if err != nil {
		t.Fatal(err)
	}

	if err := f.app.regressionRun(nil); err != nil {
		t.Fatalf("dry run: %v\n%s", err, f.out.String())
	}
	dry := f.out.String()
	for _, want := range []string{"Board: " + testBoardID, "Against: tier-09-remediation, counter 6",
		"Result: dry run only", "Execute: ./course regression run --execute regression"} {
		if !strings.Contains(dry, want) {
			t.Fatalf("dry run does not say %q:\n%s", want, dry)
		}
	}
	if _, err := os.Stat(filepath.Join(f.root, ".course-state", "regression")); err == nil {
		t.Fatal("a dry run wrote a receipt")
	}

	f.out.Reset()
	err = f.app.regressionRun([]string{"--execute", "regression"})
	output := f.out.String()
	if err == nil {
		t.Fatalf("a run whose releases drew no board reaction passed:\n%s", output)
	}

	lines := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[0] == labelBoard || fields[0] == labelHost) {
			lines[fields[0]+" "+strings.Join(fields[1:], " ")] = line
		}
	}
	expectLine := func(prefix, verdict string) {
		t.Helper()
		for key, line := range lines {
			if strings.HasPrefix(key, prefix+" ") || key == prefix {
				if !strings.Contains(line, "  "+verdict+" ") {
					t.Errorf("%s: want %q in %q", prefix, verdict, line)
				}
				return
			}
		}
		t.Errorf("no line for %s in:\n%s", prefix, output)
	}
	expectLine("board tier-09/support-listener --request inventory", verdictPass)
	expectLine("board tier-00/altered-image", verdictNoResult)
	expectLine("host tier-00/plaintext-inspection", verdictPass)
	expectLine("host tier-02/plaintext-inspection", verdictPass)
	expectLine("host tier-02/name-mismatch", verdictPass)
	expectLine("host e-7-03", verdictPass)
	expectLine("board tier-09/support-listener reboot", verdictNotRun)
	expectLine("host e-8-11", verdictNotRun)

	baselineAfter, err := os.ReadFile(f.app.baselinePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baselineBefore, baselineAfter) {
		t.Fatalf("the Fleet baseline was not restored byte for byte:\nbefore %s\nafter  %s", baselineBefore, baselineAfter)
	}
	if _, err := os.Stat(f.app.hostingSavedPath()); err == nil {
		t.Fatal("a saved baseline was left behind after the reset")
	}
	if _, err := os.Stat(f.app.eventsPath()); err != nil {
		t.Fatalf("the event log did not survive the run: %v", err)
	}

	matches, _ := filepath.Glob(filepath.Join(f.root, ".course-state", "regression", "*.json"))
	if len(matches) != 1 {
		t.Fatalf("want one receipt, found %v", matches)
	}
	var receipt struct {
		CourseRevision string             `json:"course_revision"`
		Board          boardState         `json:"board"`
		Release        regressionRelease  `json:"release"`
		Results        []regressionResult `json:"results"`
		Result         string             `json:"result"`
		ServiceBefore  serviceSnapshot    `json:"service_before"`
		ServiceAfter   serviceSnapshot    `json:"service_after"`
	}
	if err := readJSON(matches[0], &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Board.DeviceID != testBoardID || receipt.Release.ReleaseID != "tier-09-remediation" ||
		receipt.Release.SecurityCounter != tier09RemediationCounter || len(receipt.Release.ImageSHA256) != 64 ||
		!receipt.Release.SignatureVerified || len(receipt.Release.ManifestSHA256) != 64 {
		t.Errorf("the receipt's opening section is incomplete: board %+v release %+v", receipt.Board, receipt.Release)
	}
	if receipt.Result != verdictFail || receipt.ServiceBefore != receipt.ServiceAfter {
		t.Errorf("receipt result %q, service before %+v after %+v", receipt.Result, receipt.ServiceBefore, receipt.ServiceAfter)
	}
	for _, result := range receipt.Results {
		if result.Fixture == "" || result.Result == "" || (result.Label != labelBoard && result.Label != labelHost) {
			t.Errorf("a receipt line lacks its fixture, result or label: %+v", result)
		}
	}
}

// During the candidate's trial the listener answers, and that is a board
// failure: the planted regression caught. While the rollout is open, a release
// entry cannot reach the board and says so as no result.
func TestRegressionCatchesTheListenerDuringATrial(t *testing.T) {
	f := regressionBench(t, startUDPEcho(t, "device_id=beacon release=tier-10-candidate counter=7"))
	f.approveAndStartRollout(t, testBoardID)
	block := f.app.manifest.Regression
	block.Host = nil
	f.app.manifest.Regression = block

	err := f.app.regressionRun([]string{"--execute", "regression"})
	output := f.out.String()
	if err == nil {
		t.Fatalf("a run that reached the planted listener passed:\n%s", output)
	}
	if !strings.Contains(output, "tier-09/support-listener --request inventory") ||
		!strings.Contains(output, "fail       expected absent, observed answered") {
		t.Fatalf("the listener's answer was not a board failure:\n%s", output)
	}
	if !strings.Contains(output, "no result  expected refused, observed nothing; not offered: the rollout of tier-09-support-listener is open") {
		t.Fatalf("a release entry under an open rollout must be no result:\n%s", output)
	}
}

// --only narrows the run to one fixture, and names nothing outside the plan.
func TestRegressionOnlyNarrowsThePlan(t *testing.T) {
	plan, err := buildRegressionPlan(repositoryManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	narrowed, err := plan.only("tier-04/hostile-release")
	if err != nil {
		t.Fatal(err)
	}
	if len(narrowed.board) != 7 || len(narrowed.host) != 0 {
		t.Errorf("--only tier-04/hostile-release kept %d board and %d host steps", len(narrowed.board), len(narrowed.host))
	}
	if _, err := plan.only("beacon-t08c-206ef1170d64"); err == nil {
		t.Error("--only must refuse anything that is not in the plan, including a device id")
	}
}

// A published release the board refuses is a board pass, read from the event
// the board stored while the release was the Fleet baseline. A stand-in for
// the board appends that event the moment the baseline names the release, as
// the service would on the board's next poll.
func TestRegressionReadsTheBoardsRefusalOfAPublishedRelease(t *testing.T) {
	f := regressionBench(t, closedUDPPort(t))
	block := f.app.manifest.Regression
	block.BoardWaitSeconds = 10
	f.app.manifest.Regression = block

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
			}
			var record releaseRecord
			if readJSON(f.app.baselinePath(), &record) != nil || record.ReleaseID != "tier-00-altered" {
				continue
			}
			refusal := event(testBoardID, "update.refused", "tier-09-remediation", "tier-00-altered", time.Now().UTC())
			line, _ := json.Marshal(refusal)
			file, err := os.OpenFile(f.app.eventsPath(), os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				return
			}
			file.Write(append(line, '\n'))
			file.Close()
			return
		}
	}()

	if err := f.app.regressionRun([]string{"--execute", "regression", "--only", "tier-00/altered-image"}); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	output := f.out.String()
	t.Log(output)
	if !strings.Contains(output, "pass       expected refused, observed refused; offered tier-00-altered") {
		t.Fatalf("the board's stored refusal was not a pass:\n%s", output)
	}
	if !strings.Contains(output, "Result: pass") {
		t.Fatalf("the run did not pass:\n%s", output)
	}
}

// On the mutual-TLS service a hosting fixture writes the baseline file and its
// reset writes back exactly the bytes it replaced, never the lab reset. It
// refuses to save over an earlier publish that was never reset, and it refuses
// while a rollout is open, because the board would never be offered the file.
func TestHostingPublishAndRestoreOnTheMutualTLSService(t *testing.T) {
	f := regressionBench(t, closedUDPPort(t))
	a := f.app
	original := []byte("{\"release_id\": \"tier-09-remediation\",   \"schema_version\": 1}\n")
	if err := os.WriteFile(a.baselinePath(), original, 0o600); err != nil {
		t.Fatal(err)
	}
	if !a.hostingMode("tier-03/hostile-image") || a.hostingMode("tier-02/plaintext-inspection") {
		t.Fatal("hosting mode is for the four baseline fixtures on a mutual-TLS service only")
	}
	hostile := map[string]any{"schema_version": 1, "release_id": "tier-03-hostile-unsigned", "version": "0.3.1-hostile"}
	if err := a.hostingPublish("tier-03/hostile-image", hostile); err != nil {
		t.Fatal(err)
	}
	var record releaseRecord
	if err := readJSON(a.baselinePath(), &record); err != nil || record.ReleaseID != "tier-03-hostile-unsigned" {
		t.Fatalf("the baseline holds %q, %v", record.ReleaseID, err)
	}
	if err := a.hostingPublish("tier-04/hostile-release", hostile); err == nil ||
		!strings.Contains(err.Error(), "./course attack reset tier-03/hostile-image") {
		t.Fatalf("a second publish over an unreset one must be refused, got %v", err)
	}
	if err := a.hostingRestore("tier-04/hostile-release"); err == nil {
		t.Fatal("one fixture's reset must not restore another fixture's save")
	}
	if err := a.resetFixtureState("tier-03/hostile-image", a.manifest.Regression.Target, environment{}); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(a.baselinePath())
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("restored %q, want the exact bytes %q", restored, original)
	}
	if _, err := os.Stat(a.eventsPath()); err != nil {
		t.Fatalf("the reset dropped the event log: %v", err)
	}
	if err := a.resetFixtureState("tier-03/hostile-image", a.manifest.Regression.Target, environment{}); err != nil {
		t.Fatalf("a second reset must be a no-op: %v", err)
	}

	f.approveAndStartRollout(t, testBoardID)
	if err := a.hostingPublish("tier-03/hostile-image", hostile); err == nil || !strings.Contains(err.Error(), "rollout") {
		t.Fatalf("a publish under an open rollout must be refused, got %v", err)
	}
	if _, err := os.Stat(a.hostingSavedPath()); err == nil {
		t.Fatal("a refused publish left a save behind")
	}
}
