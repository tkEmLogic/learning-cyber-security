package courseapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scenarioTestApp loads the real course.yml and roots the app in a temp dir,
// so state files land there and the manifest is the one the runner ships with.
func scenarioTestApp(t *testing.T) (*app, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	a, err := load("../..", out, out)
	if err != nil {
		t.Fatal(err)
	}
	a.root = t.TempDir()
	return a, out
}

// The block in course.yml is the one #288 settled, and it validates.
func TestScenarioBlockInCourseYMLIsValid(t *testing.T) {
	a, _ := scenarioTestApp(t)
	if err := validateScenarioManifest(a.manifest); err != nil {
		t.Fatal(err)
	}
	events := a.manifest.Scenario.Events
	if events[0].Present != "wrong-name" {
		t.Errorf("event 1 presents %q, want wrong-name", events[0].Present)
	}
	if events[1].Fixture != "tier-04/hostile-release" || events[1].Selector != "wrong-key" {
		t.Errorf("event 2 is %s %s, want tier-04/hostile-release wrong-key", events[1].Fixture, events[1].Selector)
	}
	if events[2].Fixture != "tier-04/replay-release" {
		t.Errorf("event 3 is %s, want tier-04/replay-release", events[2].Fixture)
	}
	if events[3].Row != "e-8-07" || events[3].Where != "host" {
		t.Errorf("event 4 is %s on %s, want e-8-07 on host", events[3].Row, events[3].Where)
	}
	if events[7].Fixture != supportListenerFixtureID || events[7].Selector != "inventory" {
		t.Errorf("event 8 is %s %s, want the support listener's inventory", events[7].Fixture, events[7].Selector)
	}
	if a.manifest.Scenario.Actor != "teammate" || a.manifest.Scenario.CandidateRelease != "tier-10-candidate" {
		t.Errorf("actor %q and candidate %q are not the names #287 fixed",
			a.manifest.Scenario.Actor, a.manifest.Scenario.CandidateRelease)
	}
}

// A block the runner could not run as designed is refused before anything
// happens: wrong order, an unlisted selector, an unlabelled host row, the
// right certificate where a wrong one belongs, and an unbounded wait.
func TestScenarioManifestRefusesWhatItCannotRun(t *testing.T) {
	a, _ := scenarioTestApp(t)
	good := a.manifest
	cases := map[string]func(m *manifest){
		"order": func(m *manifest) {
			m.Scenario.Events[1], m.Scenario.Events[3] = m.Scenario.Events[3], m.Scenario.Events[1]
		},
		"selector":        func(m *manifest) { m.Scenario.Events[1].Selector = "anything" },
		"reboot":          func(m *manifest) { m.Scenario.Events[7].Fixture = "tier-04/replay-release" },
		"host label":      func(m *manifest) { m.Scenario.Events[3].Where = "board" },
		"right cert":      func(m *manifest) { m.Scenario.Events[0].Present = "service" },
		"fraction":        func(m *manifest) { m.Scenario.InterruptFraction = 1 },
		"unbounded wait":  func(m *manifest) { m.Scenario.ListenerMaxSeconds = 100000 },
		"public target":   func(m *manifest) { m.Scenario.Target = "http://8.8.8.8:8080" },
		"missing actor":   func(m *manifest) { m.Scenario.Actor = " " },
		"renumbered":      func(m *manifest) { m.Scenario.Events[4].ID = "tier-10/event-99" },
		"too few events":  func(m *manifest) { m.Scenario.Events = m.Scenario.Events[:7] },
		"unknown fixture": func(m *manifest) { m.Scenario.Events[2].Fixture = "tier-99/none" },
	}
	for name, mutate := range cases {
		m := good
		m.Scenario.Events = append([]scenarioEvent(nil), good.Scenario.Events...)
		mutate(&m)
		if err := validateScenarioManifest(m); err == nil {
			t.Errorf("%s: the block was accepted, want a refusal", name)
		}
	}
}

// The teammate's slip: the last adjacent pair of differing characters,
// swapped, and never a slip that names a real device.
func TestMisspellDeviceID(t *testing.T) {
	got, err := misspellDeviceID("beacon-t08c-206ef1170d64", nil)
	if err != nil || got != "beacon-t08c-206ef1170d46" {
		t.Fatalf("misspellDeviceID = %q, %v; want beacon-t08c-206ef1170d46", got, err)
	}
	got, err = misspellDeviceID("beacon-t08c-206ef1170d64", map[string]bool{"beacon-t08c-206ef1170d46": true})
	if err != nil || got != "beacon-t08c-206ef11706d4" {
		t.Fatalf("with the first slip taken, got %q, %v; want beacon-t08c-206ef11706d4", got, err)
	}
	// A pair of equal characters is no slip at all, so it is skipped.
	got, err = misspellDeviceID("ab11", nil)
	if err != nil || got != "a1b1" {
		t.Fatalf("misspellDeviceID(ab11) = %q, %v; want a1b1", got, err)
	}
	if _, err := misspellDeviceID("aaaa", nil); err == nil {
		t.Fatal("an id with no differing pair must be refused")
	}
}

func activeDeviceRecords(id, owner, serial string) []provisionRecord {
	return []provisionRecord{
		{Kind: "enrollment", DeviceID: id, Result: "issued"},
		{Kind: "claim", DeviceID: id, OwnerID: owner, CertSerial: serial},
		{Kind: "activation", DeviceID: id, CertSerial: serial},
	}
}

// The board is the one active device no manifest list names as synthetic.
func TestScenarioBoardDevice(t *testing.T) {
	a, _ := scenarioTestApp(t)
	m := a.manifest
	board := "beacon-t08c-206ef1170d64"
	var records []provisionRecord
	records = append(records, activeDeviceRecords(board, "harbor-owner", "1")...)
	records = append(records, activeDeviceRecords(m.Fleet.DeviceIDs[0], "beacon-fleet-ops", "2")...)
	records = append(records, activeDeviceRecords("beacon-bypass-e8-07", "rival-labs", "3")...)
	records = append(records, activeDeviceRecords("beacon-phantom-0001", "rival-labs", "4")...)
	// Enrolled and claimed but never used: not active, so not the board.
	records = append(records, provisionRecord{Kind: "enrollment", DeviceID: "beacon-t08c-idle", Result: "issued"})

	got, err := scenarioBoardDevice(records, m, "")
	if err != nil || got != board {
		t.Fatalf("scenarioBoardDevice = %q, %v; want %s", got, err, board)
	}
	if _, err := scenarioBoardDevice(records, m, m.Fleet.DeviceIDs[0]); err == nil {
		t.Fatal("--device naming a fleet device must be refused")
	}
	if got, err := scenarioBoardDevice(records, m, board); err != nil || got != board {
		t.Fatalf("--device naming the board = %q, %v", got, err)
	}

	two := append(append([]provisionRecord(nil), records...), activeDeviceRecords("beacon-t08c-second", "harbor-owner", "5")...)
	if _, err := scenarioBoardDevice(two, m, ""); err == nil || !strings.Contains(err.Error(), "--device") {
		t.Fatalf("two boards must be refused with a pointer to --device, got %v", err)
	}
	if _, err := scenarioBoardDevice(nil, m, ""); err == nil {
		t.Fatal("no active board must be refused")
	}
}

// fakeScenario replaces every step that touches a service or a board, and
// records what the sequencing asked of each.
type fakeScenario struct {
	calls     []string
	undos     []string
	failStage string
	failUndo  bool
	clock     time.Time
}

func newFakeRunner(t *testing.T) (*scenarioRunner, *fakeScenario, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	a, _ := scenarioTestApp(t)
	terminal := &bytes.Buffer{}
	staging := &bytes.Buffer{}
	a.out = terminal
	r := a.newScenarioRunner(staging)
	f := &fakeScenario{clock: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	r.now = func() time.Time { f.clock = f.clock.Add(time.Minute); return f.clock }
	r.sleep = func(time.Duration) {}
	r.preflight = func() (environment, error) { return environment{EnvironmentID: "env"}, nil }
	r.serviceFlags = func() ([]string, error) { return scenarioServiceFlags, nil }
	r.undo = func(st *scenarioState, keepRange bool) error {
		f.undos = append(f.undos, describeTemporary(st, keepRange))
		if f.failUndo {
			return errors.New("undo exploded at tier-04/hostile-release")
		}
		st.Present, st.HeldFixture = "", ""
		if !keepRange {
			st.Range = ""
		}
		return nil
	}
	step := func(name string, apply func(*scenarioState, scenarioEvent)) func(*scenarioState, scenarioEvent) error {
		return func(st *scenarioState, event scenarioEvent) error {
			f.calls = append(f.calls, name)
			if f.failStage == name {
				return errors.New("tier-04/replay-release exploded with a revoked certificate")
			}
			apply(st, event)
			return nil
		}
	}
	r.stages = map[string]func(*scenarioState, scenarioEvent) error{
		stagePresent:       step(stagePresent, func(st *scenarioState, e scenarioEvent) { st.Present = e.Present }),
		stageFixture:       step(stageFixture, func(st *scenarioState, e scenarioEvent) { st.HeldFixture = e.Fixture }),
		stageBypass:        step(stageBypass, func(*scenarioState, scenarioEvent) {}),
		stageRollout:       step(stageRollout, func(st *scenarioState, _ scenarioEvent) { st.Range = "interrupt:600" }),
		stageTransfer:      step(stageTransfer, func(st *scenarioState, _ scenarioEvent) { st.Range = "" }),
		stageRevert:        step(stageRevert, func(*scenarioState, scenarioEvent) {}),
		stageFixtureSeries: step(stageFixtureSeries, func(*scenarioState, scenarioEvent) {}),
	}
	if err := r.saveState(&scenarioState{SchemaVersion: 1, BoardDeviceID: "beacon-t08c-206ef1170d64",
		CanaryDeviceID: "beacon-t08c-206ef1170d46", ServiceFlags: scenarioServiceFlags}); err != nil {
		t.Fatal(err)
	}
	return r, f, terminal, staging
}

func describeTemporary(st *scenarioState, keepRange bool) string {
	return "present=" + st.Present + " range=" + st.Range + " held=" + st.HeldFixture +
		map[bool]string{true: " keep-range", false: ""}[keepRange]
}

// Eight nexts stage the eight events in order, each undoing the change the
// previous one left, except the interruption Event 6 needs from Event 5. A
// ninth is refused.
func TestScenarioNextStagesTheEventsInOrder(t *testing.T) {
	r, f, terminal, _ := newFakeRunner(t)
	for i := 1; i <= 8; i++ {
		if err := r.next(); err != nil {
			t.Fatalf("next %d: %v", i, err)
		}
	}
	wantCalls := []string{stagePresent, stageFixture, stageFixture, stageBypass, stageRollout, stageTransfer, stageRevert, stageFixtureSeries}
	if strings.Join(f.calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("stages ran as %v, want %v", f.calls, wantCalls)
	}
	wantUndos := []string{
		"present= range= held=",
		"present=wrong-name range= held=",
		"present= range= held=tier-04/hostile-release",
		"present= range= held=tier-04/replay-release",
		"present= range= held=",
		"present= range=interrupt:600 held= keep-range",
		"present= range= held=",
		"present= range= held=",
	}
	if strings.Join(f.undos, "|") != strings.Join(wantUndos, "|") {
		t.Fatalf("undo saw\n%s\nwant\n%s", strings.Join(f.undos, "\n"), strings.Join(wantUndos, "\n"))
	}
	st, err := r.loadState()
	if err != nil || st == nil || len(st.Staged) != 8 {
		t.Fatalf("state after eight events: %+v, %v", st, err)
	}
	for i, staged := range st.Staged {
		if staged.Number != i+1 || staged.ID != r.block.Events[i].ID {
			t.Fatalf("staged[%d] = %+v", i, staged)
		}
		if !strings.Contains(terminal.String(), "Event "+staged.ID[len(staged.ID)-1:]+" staged at "+staged.StagedAt) {
			t.Fatalf("the terminal lacks the staged line for %+v:\n%s", staged, terminal.String())
		}
	}
	if err := r.next(); err == nil || !strings.Contains(err.Error(), "ended") {
		t.Fatalf("a ninth next must be refused, got %v", err)
	}
}

// A step that fails stages nothing, keeps its reason off the terminal, and
// leaves the state where a rerun of next retries the same event.
func TestScenarioNextFailureKeepsTheEventAndTheMechanismPrivate(t *testing.T) {
	r, f, terminal, staging := newFakeRunner(t)
	if err := r.next(); err != nil {
		t.Fatal(err)
	}
	if err := r.next(); err != nil {
		t.Fatal(err)
	}
	f.failStage = stageFixture
	err := r.next()
	if err == nil {
		t.Fatal("a failing step must fail next")
	}
	if strings.Contains(err.Error(), "replay") || strings.Contains(err.Error(), "revoked") {
		t.Fatalf("the terminal error leaks the mechanism: %v", err)
	}
	if !strings.Contains(staging.String(), "tier-04/replay-release exploded") {
		t.Fatal("the reason must be in the staging log")
	}
	st, _ := r.loadState()
	if len(st.Staged) != 2 {
		t.Fatalf("a failed step staged an event: %+v", st.Staged)
	}
	if strings.Contains(terminal.String(), "Event 3 staged") {
		t.Fatal("the terminal claims Event 3 was staged")
	}
	f.failStage = ""
	if err := r.next(); err != nil {
		t.Fatal(err)
	}
	st, _ = r.loadState()
	if len(st.Staged) != 3 || st.Staged[2].Number != 3 {
		t.Fatalf("the retry did not stage Event 3: %+v", st.Staged)
	}

	// An undo that fails stages nothing either.
	f.failUndo = true
	if err := r.next(); err == nil || strings.Contains(err.Error(), "hostile") {
		t.Fatalf("a failed undo must refuse next without naming the mechanism, got %v", err)
	}
	st, _ = r.loadState()
	if len(st.Staged) != 3 {
		t.Fatalf("an event was staged after a failed undo: %+v", st.Staged)
	}
}

// next, status and reset refuse or explain when no scenario is in progress,
// and start refuses a second scenario and a service without the Tier 9 flags,
// before any side effect.
func TestScenarioRefusals(t *testing.T) {
	r, f, terminal, _ := newFakeRunner(t)
	if err := r.start(""); err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("start over a scenario in progress = %v", err)
	}
	if err := os.Remove(r.a.scenarioStatePath()); err != nil {
		t.Fatal(err)
	}
	if err := r.next(); err == nil || !strings.Contains(err.Error(), "scenario start") {
		t.Fatalf("next with no scenario = %v", err)
	}
	r.serviceFlags = func() ([]string, error) { return []string{"--https", "--mutual-tls"}, nil }
	if err := r.start(""); err == nil || !strings.Contains(err.Error(), "--release-approval") {
		t.Fatalf("start without --release-approval = %v", err)
	}
	if _, err := os.Stat(r.a.scenarioStatePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused start wrote state")
	}
	r.preflight = func() (environment, error) { return environment{}, errors.New("Course environment marker mismatch") }
	r.serviceFlags = func() ([]string, error) { return scenarioServiceFlags, nil }
	if err := r.start(""); err == nil || !strings.Contains(err.Error(), "marker") {
		t.Fatalf("start outside the course environment = %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refusal ran a step: %v", f.calls)
	}
	terminal.Reset()
	if err := r.reset(); err != nil || !strings.Contains(terminal.String(), "Nothing to reset") {
		t.Fatalf("reset with no scenario = %v, %q", err, terminal.String())
	}
}

// The scenario fails closed outside the course environment on every step,
// not only at start.
func TestScenarioNextFailsClosedOutsideTheEnvironment(t *testing.T) {
	r, f, _, _ := newFakeRunner(t)
	r.preflight = func() (environment, error) { return environment{}, errors.New("Course environment marker mismatch") }
	if err := r.next(); err == nil {
		t.Fatal("next must refuse when the marker does not match")
	}
	if len(f.calls) != 0 || len(f.undos) != 0 {
		t.Fatalf("a refused next ran something: calls %v undos %v", f.calls, f.undos)
	}
}

// Reset undoes the temporary change and forgets the scenario.
func TestScenarioResetUndoesAndClears(t *testing.T) {
	r, f, terminal, _ := newFakeRunner(t)
	if err := r.next(); err != nil {
		t.Fatal(err)
	}
	if err := r.reset(); err != nil {
		t.Fatal(err)
	}
	if last := f.undos[len(f.undos)-1]; last != "present=wrong-name range= held=" {
		t.Fatalf("reset undid %q, want the wrong-name restart undone", last)
	}
	if _, err := os.Stat(r.a.scenarioStatePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reset left the state file")
	}
	if !strings.Contains(terminal.String(), "untouched") {
		t.Fatalf("reset must say what it leaves: %q", terminal.String())
	}
}

// The state file is the runner's memory between commands and round-trips.
func TestScenarioStateFileRoundTrips(t *testing.T) {
	r, _, _, _ := newFakeRunner(t)
	for i := 0; i < 5; i++ {
		if err := r.next(); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(r.a.scenarioStatePath())
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(r.a.scenarioStatePath())
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v, want 0600", info.Mode().Perm())
	}
	var st scenarioState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.Range != "interrupt:600" || len(st.Staged) != 5 || st.CanaryDeviceID != "beacon-t08c-206ef1170d46" {
		t.Fatalf("state after Event 5: %+v", st)
	}
}

// What the Learner reads names no class, boundary, control or mechanism. The
// mechanism is the Mentor key's. Event 4 is labelled as a host result.
func TestScenarioTerminalWordingLeaksNothing(t *testing.T) {
	r, _, terminal, _ := newFakeRunner(t)
	for i := 1; i <= 8; i++ {
		if err := r.next(); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.status(); err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(terminal.String())
	forbidden := []string{
		"attack", "fail", "imperson", "hostile", "malicious", "hosting", "replay", "credential",
		"revok", "error", "misspel", "slip", "typo", "interrupt", "decoy", "health", "listener",
		"regression", "boundary", "control", "signature", "signed", "counter", "tls", "certificate",
		"canary", "wrong", "rollback", "downgrade", "teammate", "fixture", "bypass", "inventory",
		"e-8-07", "tier-04", "tier-09", "candidate", "trial", "revert", "resume", "operator",
	}
	for _, word := range forbidden {
		if strings.Contains(text, word) {
			t.Errorf("the terminal says %q:\n%s", word, terminal.String())
		}
	}
	if !strings.Contains(terminal.String(), "HOST result: Event 4") {
		t.Fatalf("Event 4 is not labelled as a host result:\n%s", terminal.String())
	}
	if strings.Count(terminal.String(), "HOST result") != 1 {
		t.Fatal("only Event 4 is a host result")
	}
}

// ota.log is truncated on an ordinary start and appended to under the
// scenario, so one continuous log survives the runner's restarts.
func TestServiceLogAppendsOnlyUnderTheScenario(t *testing.T) {
	a, _ := scenarioTestApp(t)
	if err := os.MkdirAll(filepath.Dir(a.serviceLogPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(text string) {
		file, err := os.OpenFile(a.serviceLogPath(), a.serviceLogFlags(), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := io.WriteString(file, text); err != nil {
			t.Fatal(err)
		}
	}
	write("tier 9 line\n")
	a.scenario = true
	write("event 1 line\n")
	write("event 2 line\n")
	got, _ := os.ReadFile(a.serviceLogPath())
	if string(got) != "tier 9 line\nevent 1 line\nevent 2 line\n" {
		t.Fatalf("under the scenario ota.log reads %q", got)
	}
	a.scenario = false
	write("fresh\n")
	got, _ = os.ReadFile(a.serviceLogPath())
	if string(got) != "fresh\n" {
		t.Fatalf("an ordinary start must truncate, got %q", got)
	}
}

// Under the scenario a fixture's reset never reaches the lab reset, which
// would delete events.jsonl and reseed Tier 0.
func TestScenarioNeverResetsTheLab(t *testing.T) {
	a, _ := scenarioTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the service was asked for %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	a.scenario = true
	for _, id := range []string{"tier-04/hostile-release", "tier-04/replay-release", "tier-00/altered-image"} {
		if err := a.resetFixtureState(id, server.URL, environment{EnvironmentID: "env"}); err == nil {
			t.Errorf("%s: the reset went ahead under the scenario", id)
		}
	}
}

// The symptom readers: the cut and the resume in ota.log, the revert report
// in events.jsonl, and the listener's answer in the fixture's result line.
func TestScenarioSymptomReaders(t *testing.T) {
	log := "2026/10/09 12:00:00 firmware tier-10-candidate.bin: connection lost after 600 of 1000 bytes from offset 0\n" +
		"2026/10/09 12:00:05 firmware tier-10-candidate.bin: sent 400 bytes from offset 600\n"
	if !transferCutAndResumed(log, "tier-10-candidate.bin") {
		t.Fatal("the cut and resume were not recognised")
	}
	if transferCutAndResumed(log, "tier-09-remediation.bin") {
		t.Fatal("another image's transfer was taken for the candidate's")
	}
	resumeFirst := "firmware a.bin: sent 400 bytes from offset 600\nfirmware a.bin: connection lost after 600 of 1000 bytes from offset 0\n"
	if transferCutAndResumed(resumeFirst, "a.bin") {
		t.Fatal("a resume before the cut is not a resume")
	}

	events := `{"source":"service","check":"device-unrevoked"}` + "\n" +
		`{"event":"update.reverted","running_release_id":"tier-09-remediation","detail":"tier-10-candidate beacon-advancing","service_received_at":"2026-10-09T12:03:00Z"}` + "\n"
	if !revertReported(events, "tier-10-candidate") {
		t.Fatal("the revert report was not recognised")
	}
	if revertReported(events, "tier-10-corrected") {
		t.Fatal("a revert of another release was taken for the candidate's")
	}

	if !listenerAnswered("Result: the unauthenticated support listener answered \"inventory\" with \"device_id=x security_counter=7\"\n", "inventory") {
		t.Fatal("the answer was not recognised")
	}
	if listenerAnswered("Result: no reply within 3 s from the support listener; weak evidence, read the boot log\n", "inventory") {
		t.Fatal("a timeout was taken for an answer")
	}
}
