package courseapp

// The Tier 10 integration scenario runner (#291), designed in #288.
//
// `./course scenario next` stages one scenario event and prints only
// `Event N staged at <UTC time>` and where to look. The Learner writes a first
// classification before staging the next one. The mechanism of every event is
// the Mentor key's, so everything the runner does, and everything the
// commands it calls print, goes to a staging log under `.course-state/` and
// never to the terminal.
//
// The runner adds no attack of its own. Every event is machinery the course
// already has, called through its own Go entry point with the inputs the
// `scenario:` block in course.yml allowlists: a service restart with
// `--present`, two Tier 4 fixtures, one Tier 8 bypass row, the rollout
// commands acting as the role `teammate`, a service restart with `--range`,
// and a bounded series of Tier 9 support-listener runs. It fails closed on
// the same marker handshake every fixture uses, and it never asks the service
// to reset the lab, because that deletes events.jsonl, the record the Learner
// is reconstructing.
//
// Each `next` first undoes the temporary change the previous event left, so
// two events never overlap. The one exception is planned: the interruption
// behind Event 6 is switched on while Event 5 is staged, because the board
// downloads within about 30 s of the rollout's advance, and it stays on until
// Event 8 is over. Switching it off at Event 6 meant a service restart just as
// the board finished its download, which cut the board's update.installed
// report and printed a misleading TLS refusal on its console (#293). Later
// trial downloads are cut and resumed too, which the Mentor key says. Event 8
// restores the Tier 9 flags at its end, inside a trial window, when the board
// is not polling.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// scenarioManifest is the `scenario:` block. Every value the runner passes to
// the machinery it calls comes from here, never from a command line.
type scenarioManifest struct {
	Tier      string `yaml:"tier"`
	Target    string `yaml:"target"`
	Interface string `yaml:"interface"`

	BaselineRelease  string `yaml:"baseline_release"`
	CandidateVariant string `yaml:"candidate_variant"`
	CandidateRelease string `yaml:"candidate_release"`
	Actor            string `yaml:"actor"`

	InterruptFraction       float64 `yaml:"interrupt_fraction"`
	TransferWaitSeconds     int     `yaml:"transfer_wait_seconds"`
	RevertWaitSeconds       int     `yaml:"revert_wait_seconds"`
	TrialWaitSeconds        int     `yaml:"trial_wait_seconds"`
	ListenerIntervalSeconds int     `yaml:"listener_interval_seconds"`
	ListenerReplySeconds    int     `yaml:"listener_reply_seconds"`
	ListenerMaxSeconds      int     `yaml:"listener_max_seconds"`

	Events  []scenarioEvent `yaml:"events"`
	Changes []string        `yaml:"changes"`
	Reset   string          `yaml:"reset"`
}

// scenarioEvent is one registered event. Stage names the runner's step, which
// is the answer key's mechanism, so nothing Learner-facing prints it.
type scenarioEvent struct {
	ID       string `yaml:"id"`
	Number   int    `yaml:"number"`
	Where    string `yaml:"where"`
	Stage    string `yaml:"stage"`
	Present  string `yaml:"present"`
	Fixture  string `yaml:"fixture"`
	Selector string `yaml:"selector"`
	Row      string `yaml:"row"`
}

// The runner's steps, in the one order #288 settled. The order is enforced,
// not merely documented: the transfer step reads offsets the rollout step
// recorded, and the revert step waits for the trial the transfer started.
const (
	stagePresent       = "present"
	stageFixture       = "fixture"
	stageBypass        = "bypass"
	stageRollout       = "rollout"
	stageTransfer      = "transfer"
	stageRevert        = "revert"
	stageFixtureSeries = "fixture-series"
)

var scenarioStageOrder = []string{
	stagePresent, stageFixture, stageFixture, stageBypass,
	stageRollout, stageTransfer, stageRevert, stageFixtureSeries,
}

// scenarioWhereToLook is the operator-visible place each step's symptom
// shows. It names records and commands, never the mechanism.
var scenarioWhereToLook = map[string][]string{
	stagePresent:       {"the board's serial console (./course device logs)", ".course-state/ota.log"},
	stageFixture:       {"the board's serial console (./course device logs)", ".course-state/ota.log"},
	stageBypass:        {".course-state/ota/events.jsonl"},
	stageRollout:       {"./course rollout status", ".course-state/ota/events.jsonl"},
	stageTransfer:      {"the board's serial console (./course device logs)", ".course-state/ota.log"},
	stageRevert:        {"the board's serial console (./course device logs)", ".course-state/ota/events.jsonl"},
	stageFixtureSeries: {"the board's serial console (./course device logs)"},
}

// scenarioLongStages wait on the board, for minutes. The terminal says so in a
// neutral line, so a Learner does not think the command hung.
// scenarioKeepsRange are the steps that run while Event 5's interruption is
// still in force.
var scenarioKeepsRange = map[string]bool{stageTransfer: true, stageRevert: true, stageFixtureSeries: true}

var scenarioLongStages = map[string]bool{stageTransfer: true, stageRevert: true, stageFixtureSeries: true}

// The bounds on Event 8's series, whatever course.yml says.
const (
	minListenerIntervalSeconds = 2
	maxListenerSeriesSeconds   = 120
)

// The flags the Tier 9 end state runs the service with. The runner restarts
// the service with exactly these, plus the one event's change.
var scenarioServiceFlags = []string{"--https", "--mutual-tls", "--release-approval"}

// validateScenarioManifest refuses a scenario block the runner could not run
// as #288 designed it, before any side effect.
func validateScenarioManifest(m manifest) error {
	block := m.Scenario
	if block.Tier != "10" {
		return errors.New("course.yml has no Tier 10 scenario block")
	}
	if err := validateTarget(block.Target); err != nil {
		return err
	}
	if err := validateSelectedInterface(block.Target, block.Interface, true); err != nil {
		return err
	}
	if block.BaselineRelease == "" || block.CandidateVariant == "" || block.CandidateRelease == "" {
		return errors.New("the scenario block must name the baseline release and the candidate")
	}
	// A role, never a person's name (#287). The check is only that it is set:
	// nothing on the service authenticates an actor (T9-W-37).
	if strings.TrimSpace(block.Actor) == "" {
		return errors.New("the scenario block must name the actor role")
	}
	if block.InterruptFraction <= 0 || block.InterruptFraction >= 1 {
		return errors.New("scenario interrupt_fraction must be between 0 and 1")
	}
	for name, seconds := range map[string]int{
		"transfer_wait_seconds": block.TransferWaitSeconds,
		"revert_wait_seconds":   block.RevertWaitSeconds,
		"trial_wait_seconds":    block.TrialWaitSeconds,
	} {
		if seconds <= 0 || seconds > maxFixtureHoldSeconds {
			return fmt.Errorf("scenario %s must be between 1 and %d", name, maxFixtureHoldSeconds)
		}
	}
	// Event 8's series is dense because the candidate's listener is live for
	// about ten seconds per trial: the gate gives up at its second 5 s sample
	// once the beacon stops (#293). Dense is still bounded: one datagram per
	// run, at most one run per interval, inside one trial's span.
	if block.ListenerMaxSeconds <= 0 || block.ListenerMaxSeconds > maxListenerSeriesSeconds {
		return fmt.Errorf("scenario listener_max_seconds must be between 1 and %d", maxListenerSeriesSeconds)
	}
	if block.ListenerIntervalSeconds < minListenerIntervalSeconds || block.ListenerIntervalSeconds > block.ListenerMaxSeconds {
		return fmt.Errorf("scenario listener_interval_seconds must be at least %d and within listener_max_seconds", minListenerIntervalSeconds)
	}
	if block.ListenerReplySeconds < 1 || block.ListenerReplySeconds > block.ListenerIntervalSeconds ||
		time.Duration(block.ListenerReplySeconds)*time.Second > supportReplyTimeout {
		return errors.New("scenario listener_reply_seconds must be at least 1, within the interval and no longer than the fixture's own 3 s")
	}
	if len(block.Events) != len(scenarioStageOrder) {
		return fmt.Errorf("the scenario has %d events; #288 settled %d", len(block.Events), len(scenarioStageOrder))
	}
	for i, event := range block.Events {
		number := i + 1
		if event.Number != number || event.ID != fmt.Sprintf("tier-10/event-%02d", number) {
			return fmt.Errorf("scenario event %d must be numbered %d with id tier-10/event-%02d", number, number, number)
		}
		if event.Stage != scenarioStageOrder[i] {
			return fmt.Errorf("scenario event %d must use stage %s", number, scenarioStageOrder[i])
		}
		if event.Where != "board" && event.Where != "host" && event.Where != "service" {
			return fmt.Errorf("scenario event %d has an unknown where %q", number, event.Where)
		}
		switch event.Stage {
		case stagePresent:
			if _, ok := presentedCertificate[event.Present]; !ok || event.Present == "service" {
				return fmt.Errorf("scenario event %d must present a manifest-owned wrong certificate", number)
			}
		case stageFixture, stageFixtureSeries:
			f, ok := m.Fixtures[event.Fixture]
			if !ok {
				return fmt.Errorf("scenario event %d names unknown fixture %q", number, event.Fixture)
			}
			allowed, _ := f.selectors()
			if len(allowed) > 0 {
				if _, ok := allowed[event.Selector]; !ok {
					return fmt.Errorf("scenario event %d selects %q, which %s does not allow", number, event.Selector, event.Fixture)
				}
			} else if event.Selector != "" {
				return fmt.Errorf("scenario event %d gives a selector to %s, which takes none", number, event.Fixture)
			}
		case stageBypass:
			row, ok := lookupBypassRow(event.Row)
			if !ok || row.run == nil {
				return fmt.Errorf("scenario event %d names %q, which is not a host bypass row", number, event.Row)
			}
			// A bypass row runs from the host, so the event is a host result
			// and is labelled as one. Settled input 9 of #284.
			if event.Where != "host" {
				return fmt.Errorf("scenario event %d runs on the host and must say where: host", number)
			}
		}
	}
	return nil
}

// scenarioState is what the runner remembers between commands. It lives under
// `.course-state/scenario/`, ignored and never committed.
type scenarioState struct {
	SchemaVersion int    `json:"schema_version"`
	EnvironmentID string `json:"environment_id"`
	StartedAt     string `json:"started_at"`

	// The board, found in the manufacturing record, and the canary group the
	// teammate types instead of it.
	BoardDeviceID  string `json:"board_device_id"`
	CanaryDeviceID string `json:"canary_device_id"`

	// ServiceFlags are the running service's flags when the scenario started.
	// Nothing records --release-approval anywhere else.
	ServiceFlags []string `json:"service_flags"`

	// The temporary changes in force. Each `next` undoes them first, except
	// the interruption Event 6 needs from Event 5.
	Present        string `json:"present,omitempty"`
	Range          string `json:"range,omitempty"`
	InterruptBytes int64  `json:"interrupt_bytes,omitempty"`
	HeldFixture    string `json:"held_fixture,omitempty"`

	// Where ota.log and events.jsonl stood when the candidate was offered, so
	// the transfer and the revert are read from that point on.
	LogOffset    int64 `json:"ota_log_offset"`
	EventsOffset int64 `json:"events_offset"`

	Staged []stagedScenarioEvent `json:"staged"`
}

type stagedScenarioEvent struct {
	Number   int    `json:"number"`
	ID       string `json:"id"`
	StagedAt string `json:"staged_at"`
}

// scenarioRunner holds the steps as fields, so the tests can drive the
// sequencing, the state file and the terminal wording without a board or a
// service. Production fills them from the app.
type scenarioRunner struct {
	a        *app
	block    scenarioManifest
	terminal io.Writer
	staging  io.Writer
	now      func() time.Time
	sleep    func(time.Duration)

	preflight    func() (environment, error)
	serviceFlags func() ([]string, error)
	stages       map[string]func(*scenarioState, scenarioEvent) error
	undo         func(st *scenarioState, keepRange bool) error
}

func (a *app) scenarioDir() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "scenario")
}

func (a *app) scenarioStatePath() string {
	return filepath.Join(a.scenarioDir(), "state.json")
}

func (a *app) scenarioStagingLogPath() string {
	return filepath.Join(a.scenarioDir(), "staging.log")
}

// scenarioCommand routes ./course scenario.
func (a *app) scenarioCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("scenario requires start, next, status, or reset")
	}
	switch args[0] {
	case "start", "next", "status", "reset":
	default:
		return fmt.Errorf("unknown scenario command %q; use start, next, status, or reset", args[0])
	}
	if err := validateScenarioManifest(a.manifest); err != nil {
		return err
	}
	if args[0] == "status" {
		r := a.newScenarioRunner(io.Discard)
		return r.status()
	}
	if err := os.MkdirAll(a.scenarioDir(), 0o700); err != nil {
		return err
	}
	staging, err := os.OpenFile(a.scenarioStagingLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer staging.Close()
	r := a.newScenarioRunner(staging)
	switch args[0] {
	case "start":
		device := ""
		for i := 1; i < len(args); i++ {
			if args[i] != "--device" || i+1 >= len(args) {
				return fmt.Errorf("unknown scenario start option %s; the only option is --device <id>", args[i])
			}
			device = args[i+1]
			i++
		}
		return r.start(device)
	case "next":
		if len(args) != 1 {
			return errors.New("scenario next takes no options")
		}
		return r.next()
	default:
		return r.reset()
	}
}

// newScenarioRunner wires the production steps. Everything the called
// commands print goes to the staging log; the terminal keeps the app's own
// writer for the few lines the Learner sees.
func (a *app) newScenarioRunner(staging io.Writer) *scenarioRunner {
	r := &scenarioRunner{
		a:        a,
		block:    a.manifest.Scenario,
		terminal: a.out,
		staging:  staging,
		now:      time.Now,
		sleep:    time.Sleep,
	}
	a.out = staging
	a.errOut = staging
	a.scenario = true
	r.preflight = r.checkEnvironment
	r.serviceFlags = r.runningServiceFlags
	r.undo = r.undoTemporary
	r.stages = map[string]func(*scenarioState, scenarioEvent) error{
		stagePresent:       r.stagePresent,
		stageFixture:       r.stageFixture,
		stageBypass:        r.stageBypass,
		stageRollout:       r.stageRollout,
		stageTransfer:      r.stageTransfer,
		stageRevert:        r.stageRevert,
		stageFixtureSeries: r.stageFixtureSeries,
	}
	return r
}

func (r *scenarioRunner) logf(format string, args ...any) {
	fmt.Fprintf(r.staging, "[scenario %s] %s\n", r.now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

func (r *scenarioRunner) loadState() (*scenarioState, error) {
	var st scenarioState
	if err := readJSON(r.a.scenarioStatePath(), &st); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("the scenario state is unreadable; run ./course scenario reset: %w", err)
	}
	return &st, nil
}

func (r *scenarioRunner) saveState(st *scenarioState) error {
	if err := os.MkdirAll(r.a.scenarioDir(), 0o700); err != nil {
		return err
	}
	return writeJSON(r.a.scenarioStatePath(), st, 0o600)
}

// checkEnvironment is the fail-closed check every scenario command makes
// before a side effect: the same target rules and the same marker handshake
// over plain HTTP as every fixture, and the Learner's own mutual-TLS service.
func (r *scenarioRunner) checkEnvironment() (environment, error) {
	if err := validateTarget(r.block.Target); err != nil {
		return environment{}, err
	}
	if err := validateSelectedInterface(r.block.Target, r.block.Interface, true); err != nil {
		return environment{}, err
	}
	env, _, err := r.a.matchMarker(r.block.Target)
	if err != nil {
		return environment{}, err
	}
	if err := r.a.requireLearnerService(); err != nil {
		return environment{}, err
	}
	return env, nil
}

// runningServiceFlags reads the running service's own command line. Nothing
// else records --release-approval, and a check against a file the runner
// wrote itself would only prove what the runner believed.
func (r *scenarioRunner) runningServiceFlags() ([]string, error) {
	process, running := r.a.runningService()
	if !running {
		return nil, errors.New("no course service is running")
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(process.Pid), "cmdline"))
	if err != nil {
		return nil, fmt.Errorf("cannot read the running service's flags, so the Tier 9 end state cannot be confirmed: %w", err)
	}
	parts := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	if len(parts) == 0 {
		return nil, errors.New("the running service's command line is empty")
	}
	return parts[1:], nil
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

func (r *scenarioRunner) start(device string) error {
	existing, err := r.loadState()
	if err != nil {
		return err
	}
	if existing != nil {
		return errors.New("a scenario is already in progress; ./course scenario status shows it, and ./course scenario reset clears it")
	}
	r.logf("start requested")
	env, err := r.preflight()
	if err != nil {
		return err
	}

	// The Tier 9 end state, checked before any side effect.
	flags, err := r.serviceFlags()
	if err != nil {
		return err
	}
	for _, want := range scenarioServiceFlags {
		if !contains(flags, want) {
			return fmt.Errorf("the service is running without %s; the scenario starts from the Tier 9 end state, ./course service start %s",
				want, strings.Join(scenarioServiceFlags, " "))
		}
	}
	var baseline releaseRecord
	if err := readJSON(filepath.Join(r.a.root, r.a.manifest.Paths.State, "ota", "current-release.json"), &baseline); err != nil {
		return fmt.Errorf("cannot read the Fleet baseline: %w", err)
	}
	if baseline.ReleaseID != r.block.BaselineRelease {
		return fmt.Errorf("the Fleet baseline is %s, not %s; the scenario starts from the Tier 9 end state", baseline.ReleaseID, r.block.BaselineRelease)
	}
	rollout, err := r.rolloutState()
	if err != nil {
		return err
	}
	if rollout.Open {
		return fmt.Errorf("a rollout of %s is open; the scenario starts with none open", rollout.ReleaseID)
	}
	if contains(rollout.Withdrawn, r.block.CandidateRelease) {
		return fmt.Errorf("%s was withdrawn in an earlier run, and a withdrawal is permanent; this environment cannot stage the scenario again", r.block.CandidateRelease)
	}

	records, err := r.a.readRecords()
	if err != nil {
		return err
	}
	board, err := scenarioBoardDevice(records, r.a.manifest, device)
	if err != nil {
		return err
	}
	canary, err := misspellDeviceID(board, knownDeviceIDs(records))
	if err != nil {
		return err
	}
	if _, err := r.a.boardAddress(); err != nil {
		return err
	}
	for _, event := range r.block.Events {
		f := r.a.manifest.Fixtures[event.Fixture]
		if event.Stage == stageFixture && len(f.Releases) > 0 {
			if _, _, err := r.a.loadStoredManifest(f.Releases[event.Selector]); err != nil {
				return fmt.Errorf("event %d needs the %s release, which is not built; run ./course release hostile --tier 04", event.Number, event.Selector)
			}
		}
	}

	if variant := variantsForTier(r.block.Tier)[r.block.CandidateVariant]; variant.releaseID != r.block.CandidateRelease {
		return fmt.Errorf("this checkout cannot build or sign %s yet; it needs the Tier 10 firmware (#290)", r.block.CandidateRelease)
	}

	// The candidate arrives approved by the teammate (#287): signed,
	// described, tested honestly, and approved. Signing is the first side
	// effect, and it is refused before writing anything when the candidate
	// has not been built.
	if !contains(rollout.Approved, r.block.CandidateRelease) {
		tierArgs := []string{"--tier", r.block.Tier, "--variant", r.block.CandidateVariant}
		steps := [][]string{
			append([]string{"sign"}, tierArgs...),
			append([]string{"firmware"}, tierArgs...),
			append([]string{"test"}, tierArgs...),
			append(append([]string{"approve"}, tierArgs...), "--approver", r.block.Actor),
		}
		for i, step := range steps {
			r.logf("candidate preparation: %s", strings.Join(step, " "))
			run := r.a.release
			if i == 1 {
				run = r.a.sbom
			}
			if err := run(step); err != nil {
				r.logf("candidate preparation failed: %v", err)
				return fmt.Errorf("the candidate could not be prepared (%v); build it with ./course build firmware --tier %s --variant %s, and see %s",
					err, r.block.Tier, r.block.CandidateVariant, r.a.relative(r.a.scenarioStagingLogPath()))
			}
		}
	}

	st := &scenarioState{
		SchemaVersion:  1,
		EnvironmentID:  env.EnvironmentID,
		StartedAt:      r.now().UTC().Format(time.RFC3339),
		BoardDeviceID:  board,
		CanaryDeviceID: canary,
		ServiceFlags:   append([]string(nil), scenarioServiceFlags...),
	}
	if err := r.saveState(st); err != nil {
		return err
	}
	r.logf("scenario ready: board %s, the teammate's canary group will read %s", board, canary)
	fmt.Fprintf(r.terminal, "Scenario ready. The board is %s.\n", board)
	fmt.Fprintln(r.terminal, "Run ./course scenario next to stage Event 1.")
	return nil
}

// rolloutView is the part of GET /v1/rollouts/current the runner reads.
type rolloutView struct {
	Open      bool     `json:"open"`
	ReleaseID string   `json:"release_id"`
	Served    []string `json:"served_device_ids"`
	Approved  []string `json:"approved_release_ids"`
	Withdrawn []string `json:"withdrawn_release_ids"`
}

func (r *scenarioRunner) rolloutState() (rolloutView, error) {
	var view rolloutView
	status, answer, err := r.a.operatorCall(http.MethodGet, "/v1/rollouts/current", nil)
	if err != nil {
		return view, err
	}
	if status != http.StatusOK {
		return view, operatorRefusal(r.staging, "reading the rollout", status, answer)
	}
	if err := json.Unmarshal(answer, &view); err != nil {
		return view, fmt.Errorf("the rollout state is unreadable: %w", err)
	}
	return view, nil
}

// scenarioBoardDevice finds the board: the one active device in the
// manufacturing record that no manifest list names as synthetic. A named
// device must pass the same test, so an override cannot point the scenario at
// a fleet device, an adversary's device or a phantom.
func scenarioBoardDevice(records []provisionRecord, m manifest, named string) (string, error) {
	synthetic := map[string]bool{}
	for _, id := range m.Fleet.DeviceIDs {
		synthetic[id] = true
	}
	for _, block := range m.Bypass {
		for _, id := range block.SyntheticIDs {
			synthetic[id] = true
		}
	}
	for _, f := range m.Fixtures {
		for _, id := range f.PhantomIDs {
			synthetic[id] = true
		}
	}
	devices := lifecycle.Derive(lifecycleRecords(records))
	var candidates []string
	for id, device := range devices {
		if device.State == lifecycle.Active && !synthetic[id] {
			candidates = append(candidates, id)
		}
	}
	sort.Strings(candidates)
	if named != "" {
		if !contains(candidates, named) {
			return "", fmt.Errorf("%s is not an active board in the manufacturing record", named)
		}
		return named, nil
	}
	switch len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		return "", errors.New("the manufacturing record holds no active board; the scenario starts from the Tier 9 end state")
	default:
		return "", fmt.Errorf("the manufacturing record holds more than one active board (%s); name one with --device", strings.Join(candidates, ", "))
	}
}

func knownDeviceIDs(records []provisionRecord) map[string]bool {
	known := map[string]bool{}
	for _, record := range records {
		if record.DeviceID != "" {
			known[record.DeviceID] = true
		}
	}
	return known
}

// misspellDeviceID is the teammate's typing slip (#288): the last adjacent
// pair of differing characters, swapped. canaryGroup checks syntax only
// (services/ota/rollout.go), so the slip is accepted and names no device. A
// slip that happened to name a real device would not be the event, so the
// next pair back is tried instead.
func misspellDeviceID(id string, known map[string]bool) (string, error) {
	for i := len(id) - 2; i >= 0; i-- {
		if id[i] == id[i+1] {
			continue
		}
		b := []byte(id)
		b[i], b[i+1] = b[i+1], b[i]
		slip := string(b)
		if !known[slip] {
			return slip, nil
		}
	}
	return "", fmt.Errorf("cannot derive a slip of %s that names no device", id)
}

// ---------------------------------------------------------------------------
// next, status and reset
// ---------------------------------------------------------------------------

func (r *scenarioRunner) next() error {
	st, err := r.loadState()
	if err != nil {
		return err
	}
	if st == nil {
		return errors.New("no scenario is in progress; run ./course scenario start")
	}
	number := len(st.Staged) + 1
	if number > len(r.block.Events) {
		return fmt.Errorf("all %d events are staged and the scenario has ended; ./course scenario reset clears it", len(r.block.Events))
	}
	event := r.block.Events[number-1]
	if _, err := r.preflight(); err != nil {
		return err
	}
	logPath := r.a.relative(r.a.scenarioStagingLogPath())

	// Undo first, so two events never overlap. The interruption Event 5
	// switched on stays through Events 6 to 8; Event 8 switches it off.
	r.logf("event %d (%s): undoing the previous event's temporary change", number, event.ID)
	if err := r.undo(st, scenarioKeepsRange[event.Stage]); err != nil {
		r.logf("undo failed: %v", err)
		_ = r.saveState(st)
		return fmt.Errorf("the change the previous event left could not be undone, so Event %d was not staged; the reason is in %s", number, logPath)
	}
	if err := r.saveState(st); err != nil {
		return err
	}

	if scenarioLongStages[event.Stage] {
		fmt.Fprintf(r.terminal, "Staging Event %d. This waits for the board and can take several minutes.\n", number)
	}
	r.logf("event %d (%s): stage %s", number, event.ID, event.Stage)
	stage := r.stages[event.Stage]
	if stage == nil {
		return fmt.Errorf("the runner has no step %q", event.Stage)
	}
	if err := stage(st, event); err != nil {
		r.logf("event %d was not staged: %v", number, err)
		_ = r.saveState(st)
		return fmt.Errorf("Event %d could not be staged; the reason is in %s. Run ./course scenario next again once it is fixed", number, logPath)
	}
	at := r.now().UTC().Truncate(time.Second).Format(time.RFC3339)
	st.Staged = append(st.Staged, stagedScenarioEvent{Number: number, ID: event.ID, StagedAt: at})
	if err := r.saveState(st); err != nil {
		return err
	}
	r.logf("event %d (%s) staged at %s", number, event.ID, at)
	r.printStaged(event, at, number == len(r.block.Events))
	return nil
}

// printStaged is everything the Learner sees about an event: when it was
// staged, by the host clock the timeline lines the board console up against,
// and where an operator would look. A host result says so.
func (r *scenarioRunner) printStaged(event scenarioEvent, at string, last bool) {
	fmt.Fprintf(r.terminal, "Event %d staged at %s\n", event.Number, at)
	if event.Where == "host" {
		fmt.Fprintf(r.terminal, "HOST result: Event %d ran from this host, not from the board. A host result never stands in for a board result.\n", event.Number)
	}
	fmt.Fprintln(r.terminal, "Look at:")
	for _, place := range scenarioWhereToLook[event.Stage] {
		fmt.Fprintf(r.terminal, "  %s\n", place)
	}
	if last {
		fmt.Fprintln(r.terminal, "That was the last event. Finish your first classifications, then follow the module.")
		return
	}
	fmt.Fprintf(r.terminal, "Write your first classification, then run ./course scenario next for Event %d.\n", event.Number+1)
}

func (r *scenarioRunner) status() error {
	st, err := r.loadState()
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Fprintln(r.terminal, "No scenario is in progress. ./course scenario start begins one.")
		return nil
	}
	fmt.Fprintf(r.terminal, "Scenario started at %s on board %s\n", st.StartedAt, st.BoardDeviceID)
	fmt.Fprintf(r.terminal, "Events staged: %d of %d\n", len(st.Staged), len(r.block.Events))
	for _, staged := range st.Staged {
		fmt.Fprintf(r.terminal, "  Event %d staged at %s\n", staged.Number, staged.StagedAt)
	}
	if st.Present != "" || st.Range != "" || st.HeldFixture != "" {
		fmt.Fprintln(r.terminal, "A temporary change from the last event is still in place. The next step undoes it first.")
	}
	if len(st.Staged) == len(r.block.Events) {
		fmt.Fprintln(r.terminal, "Every event is staged.")
	}
	return nil
}

// reset undoes the runner's own temporary changes and forgets the scenario.
// It rewinds nothing an event left in a record, and it never resets the lab:
// the rollout, the approval and every record line stay, because closing them
// is the Learner's recovery and the records are the incident's evidence.
func (r *scenarioRunner) reset() error {
	st, err := r.loadState()
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Fprintln(r.terminal, "No scenario is in progress. Nothing to reset.")
		return nil
	}
	// Only an undo touches the environment, so only an undo needs the
	// marker. A scenario with nothing in force can be forgotten even when the
	// service is down.
	if st.Present != "" || st.Range != "" || st.HeldFixture != "" {
		if _, err := r.preflight(); err != nil {
			return err
		}
	}
	r.logf("reset requested after %d events", len(st.Staged))
	if err := r.undo(st, false); err != nil {
		r.logf("reset could not undo: %v", err)
		_ = r.saveState(st)
		return fmt.Errorf("the scenario's temporary change could not be undone; the reason is in %s", r.a.relative(r.a.scenarioStagingLogPath()))
	}
	if err := os.Remove(r.a.scenarioStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	r.logf("reset done")
	fmt.Fprintln(r.terminal, "Result: the scenario is cleared, and its temporary service and fixture changes are undone.")
	fmt.Fprintln(r.terminal, "Rollouts, approvals and records the events left are untouched; ./course rollout status shows them.")
	return nil
}

// ---------------------------------------------------------------------------
// The production steps
// ---------------------------------------------------------------------------

// restartService restarts the Learner's service with the Tier 9 flags and the
// one event's change. The scenario flag on the app keeps ota.log continuous.
func (r *scenarioRunner) restartService(st *scenarioState, present, rangeBehaviour string) error {
	r.logf("restarting the service: %s present=%q range=%q", strings.Join(st.ServiceFlags, " "), present, rangeBehaviour)
	if err := r.a.serviceStop(); err != nil {
		return err
	}
	https := contains(st.ServiceFlags, "--https")
	mutualTLS := contains(st.ServiceFlags, "--mutual-tls")
	approval := contains(st.ServiceFlags, "--release-approval")
	if err := r.a.serviceStart(https, mutualTLS, approval, present, rangeBehaviour); err != nil {
		return err
	}
	st.Present = present
	st.Range = rangeBehaviour
	return nil
}

// undoTemporary returns the service and the fixtures to the Tier 9 end state
// the scenario started from. A held fixture is reset through its own reset,
// which the scenario flag keeps away from the lab reset.
func (r *scenarioRunner) undoTemporary(st *scenarioState, keepRange bool) error {
	if st.HeldFixture != "" {
		r.logf("resetting %s", st.HeldFixture)
		if err := r.a.resetFixture(st.HeldFixture); err != nil {
			return err
		}
		st.HeldFixture = ""
	}
	if st.Present != "" || (st.Range != "" && !keepRange) {
		if err := r.restartService(st, "", ""); err != nil {
			return err
		}
		st.InterruptBytes = 0
	}
	return nil
}

func (r *scenarioRunner) stagePresent(st *scenarioState, event scenarioEvent) error {
	return r.restartService(st, event.Present, "")
}

// fixtureArgs is the exact attack run command line, built from the manifest.
func (r *scenarioRunner) fixtureArgs(event scenarioEvent) []string {
	args := []string{event.Fixture, "--execute", event.Fixture}
	if event.Selector != "" {
		_, option := r.a.manifest.Fixtures[event.Fixture].selectors()
		args = append(args, option, event.Selector)
	}
	return args
}

// stageFixture runs a board fixture through the ordinary attack runner, with
// every one of its checks, and leaves its state in place for the board to
// poll. The next step resets it with ./course attack reset.
func (r *scenarioRunner) stageFixture(st *scenarioState, event scenarioEvent) error {
	r.logf("./course attack run %s", strings.Join(r.fixtureArgs(event), " "))
	if err := r.a.attackRun(r.fixtureArgs(event)); err != nil {
		return err
	}
	st.HeldFixture = event.Fixture
	return nil
}

func (r *scenarioRunner) stageBypass(_ *scenarioState, event scenarioEvent) error {
	r.logf("./course service bypass %s --execute %s", event.Row, event.Row)
	if err := r.a.serviceBypass([]string{event.Row, "--execute", event.Row}); err != nil {
		return err
	}
	// The row leaves the adversary owner's credential live. Its own reset
	// clears that at once, as an ordinary run would be followed by it; it
	// deletes nothing from events.jsonl, so the refusal the Learner reads
	// stays where it is.
	r.logf("./course service bypass reset")
	return r.a.serviceBypass([]string{"reset"})
}

// stageRollout is the teammate's operator error (#288): start the candidate's
// rollout with a misspelled canary group, see nobody served, and advance.
// Before it, the service is restarted with the interruption Event 6 needs,
// because the board downloads within about 30 s of the advance.
func (r *scenarioRunner) stageRollout(st *scenarioState, _ scenarioEvent) error {
	candidate, _, err := r.a.loadStoredManifest(r.block.CandidateRelease)
	if err != nil {
		return fmt.Errorf("the candidate is not signed: %w", err)
	}
	limit := int64(float64(candidate.ImageSize) * r.block.InterruptFraction)
	if limit <= 0 || limit >= int64(candidate.ImageSize) {
		return fmt.Errorf("the candidate's size %d gives no usable interruption point", candidate.ImageSize)
	}
	if err := r.restartService(st, "", "interrupt:"+strconv.FormatInt(limit, 10)); err != nil {
		return err
	}
	st.InterruptBytes = limit
	st.LogOffset = fileSize(r.a.serviceLogPath())
	st.EventsOffset = fileSize(r.eventsPath())
	if err := r.saveState(st); err != nil {
		return err
	}

	actor := []string{"--actor", r.block.Actor}
	start := append([]string{"start", "--tier", r.block.Tier, "--variant", r.block.CandidateVariant,
		"--canary", st.CanaryDeviceID}, actor...)
	r.logf("./course rollout %s", strings.Join(start, " "))
	if err := r.a.rollout(start); err != nil {
		return err
	}
	view, err := r.rolloutState()
	if err != nil {
		return err
	}
	r.logf("the teammate reads the rollout: served so far %q, and advances anyway", strings.Join(view.Served, ", "))
	advance := append([]string{"advance"}, actor...)
	r.logf("./course rollout %s", strings.Join(advance, " "))
	return r.a.rollout(advance)
}

func (r *scenarioRunner) eventsPath() string {
	return filepath.Join(r.a.root, r.a.manifest.Paths.State, "ota", "events.jsonl")
}

// stageTransfer waits for the candidate's interrupted transfer and its resume
// in ota.log. It leaves the interruption on: a restart here would land just as
// the board reports the install (#293).
func (r *scenarioRunner) stageTransfer(st *scenarioState, _ scenarioEvent) error {
	candidate, _, err := r.a.loadStoredManifest(r.block.CandidateRelease)
	if err != nil {
		return err
	}
	name := filepath.Base(candidate.ImagePath)
	return r.waitFor("the interrupted and resumed transfer", r.block.TransferWaitSeconds, func() (bool, error) {
		text, err := readFrom(r.a.serviceLogPath(), st.LogOffset)
		if err != nil {
			return false, err
		}
		return transferCutAndResumed(text, name), nil
	})
}

var (
	transferCutLine    = regexp.MustCompile(`firmware (\S+): connection lost after \d+ of \d+ bytes from offset \d+`)
	transferResumeLine = regexp.MustCompile(`firmware (\S+): sent \d+ bytes from offset (\d+)`)
)

// transferCutAndResumed says whether the log shows one image's transfer cut
// and then finished from a later offset.
func transferCutAndResumed(text, image string) bool {
	cut := false
	for _, line := range strings.Split(text, "\n") {
		if m := transferCutLine.FindStringSubmatch(line); m != nil && m[1] == image {
			cut = true
			continue
		}
		if m := transferResumeLine.FindStringSubmatch(line); cut && m != nil && m[1] == image && m[2] != "0" {
			return true
		}
	}
	return false
}

// stageRevert waits for the board's own report that the candidate failed its
// trial and was reverted. The runner causes nothing here; it keeps the events
// in order, so the Learner never classifies Event 7 before it happened.
func (r *scenarioRunner) stageRevert(st *scenarioState, _ scenarioEvent) error {
	return r.waitFor("the board's revert report", r.block.RevertWaitSeconds, func() (bool, error) {
		text, err := readFrom(r.eventsPath(), st.EventsOffset)
		if err != nil {
			return false, err
		}
		return revertReported(text, r.block.CandidateRelease), nil
	})
}

// revertReported finds `update.reverted` naming the candidate in the device
// events the service recorded.
func revertReported(text, release string) bool {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var event struct {
			Event  string `json:"event"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		if event.Event == "update.reverted" && strings.Contains(event.Detail, release) {
			return true
		}
	}
	return false
}

// stageFixtureSeries reaches the support listener inside a trial window, and
// then restores the Tier 9 flags.
//
// The window is short. The candidate's gate gives up at its second 5 s sample
// once the beacon stops, so the listener is live for about ten seconds per
// trial, not the 60 s #287 assumed, and a series every 10 s missed both
// windows it straddled on the board (#293). So the runner times the series
// from the board's own report instead: the trial image boots about 20 s after
// the board stores update.installed, and the series starts there, dense and
// bounded. Each run is still an ordinary fixture run with its own marker
// handshake, single datagram, evidence record and no-op reset, and nothing
// retries inside a run. See docs/fixture-safety-contract.md, "Tier 10
// scenario".
func (r *scenarioRunner) stageFixtureSeries(st *scenarioState, event scenarioEvent) error {
	err := r.reachListener(st, event)
	if st.Range != "" || st.Present != "" {
		if restoreErr := r.restartService(st, "", ""); restoreErr != nil && err == nil {
			err = restoreErr
		}
		st.InterruptBytes = 0
	}
	return err
}

func (r *scenarioRunner) reachListener(st *scenarioState, event scenarioEvent) error {
	rollout, err := r.rolloutState()
	if err != nil {
		return err
	}
	if !rollout.Open || rollout.ReleaseID != r.block.CandidateRelease {
		return fmt.Errorf("no rollout of %s is open, so no further trial is coming", r.block.CandidateRelease)
	}

	// A trial whose install the board reported moments ago has not opened its
	// window yet, so the series can start on it. An older one is over, or
	// nearly, and the next trial is the one to wait for.
	before := fileSize(r.eventsPath())
	text, err := readFrom(r.eventsPath(), st.EventsOffset)
	if err != nil {
		return err
	}
	signal, at := nextCandidateTrial(text, st.BoardDeviceID, r.block.CandidateRelease)
	switch {
	case signal == trialRefused:
		return errors.New("the board refuses the candidate at its trial limit, so no further trial is coming")
	case signal == trialInstalled && r.now().Sub(at) <= scenarioFreshInstall:
		r.logf("the board reported installing %s at %s; the trial boots next", r.block.CandidateRelease, at.Format(time.RFC3339))
	default:
		err = r.waitFor("the board's next install of the candidate", r.block.TrialWaitSeconds, func() (bool, error) {
			text, err := readFrom(r.eventsPath(), before)
			if err != nil {
				return false, err
			}
			signal, _ := nextCandidateTrial(text, st.BoardDeviceID, r.block.CandidateRelease)
			if signal == trialRefused {
				return false, errors.New("the board refuses the candidate at its trial limit, so no further trial is coming")
			}
			return signal == trialInstalled, nil
		})
		if err != nil {
			return err
		}
	}

	// An ordinary run, reset at once: the listener fixture holds nothing.
	r.a.scenario = false
	r.a.supportTimeout = time.Duration(r.block.ListenerReplySeconds) * time.Second
	defer func() { r.a.scenario, r.a.supportTimeout = true, 0 }()
	deadline := r.now().Add(time.Duration(r.block.ListenerMaxSeconds) * time.Second)
	interval := time.Duration(r.block.ListenerIntervalSeconds) * time.Second
	for attempt := 1; ; attempt++ {
		began := r.now()
		var captured bytes.Buffer
		r.a.out = io.MultiWriter(r.staging, &captured)
		r.logf("run %d: ./course attack run %s", attempt, strings.Join(r.fixtureArgs(event), " "))
		err := r.a.attackRun(r.fixtureArgs(event))
		r.a.out = r.staging
		if err != nil {
			r.logf("run %d ended without an answer: %v", attempt, err)
		} else if listenerAnswered(captured.String(), r.a.manifest.Fixtures[event.Fixture].Requests[event.Selector]) {
			r.logf("run %d was answered", attempt)
			return nil
		}
		// Runs start one interval apart, so a slow run is not followed by a
		// wait as well.
		next := began.Add(interval)
		if !next.Before(deadline) {
			return fmt.Errorf("no answer in %d runs over %d s", attempt, r.block.ListenerMaxSeconds)
		}
		if wait := next.Sub(r.now()); wait > 0 {
			r.sleep(wait)
		}
	}
}

// scenarioFreshInstall is how recent an install report must be for its trial
// window to be still ahead. The trial image's listener comes up about 20 s
// after the report.
const scenarioFreshInstall = 15 * time.Second

type trialSignal int

const (
	trialNone trialSignal = iota
	trialInstalled
	trialRefused
)

// nextCandidateTrial reads the board's events in order and says where the
// candidate's trials stand at the end: an install not yet followed by its
// revert is a trial under way, a refusal at the trial limit means no trial is
// coming, and anything else means none is under way. It returns when the
// board reported the last install.
func nextCandidateTrial(text, device, release string) (trialSignal, time.Time) {
	signal := trialNone
	var at time.Time
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var event struct {
			Event      string `json:"event"`
			DeviceID   string `json:"device_id"`
			Detail     string `json:"detail"`
			ReceivedAt string `json:"service_received_at"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil || event.DeviceID != device {
			continue
		}
		switch {
		case event.Event == "update.installed" && strings.HasPrefix(event.Detail, release):
			signal = trialInstalled
			at, _ = time.Parse(time.RFC3339Nano, event.ReceivedAt)
		case event.Event == "update.reverted" && strings.Contains(event.Detail, release):
			signal = trialNone
		case event.Event == "update.refused" && strings.Contains(event.Detail, "trial-limit"):
			signal = trialRefused
		}
	}
	return signal, at
}

// listenerAnswered reads the fixture's own result line. It answers only when
// the listener replied, never on a timeout or a refused port.
func listenerAnswered(output, request string) bool {
	return strings.Contains(output, fmt.Sprintf("Result: the unauthenticated support listener answered %q", request))
}

// waitFor polls check until it holds or the bound runs out.
func (r *scenarioRunner) waitFor(what string, seconds int, check func() (bool, error)) error {
	deadline := r.now().Add(time.Duration(seconds) * time.Second)
	r.logf("waiting up to %d s for %s", seconds, what)
	for {
		done, err := check()
		if err != nil {
			return err
		}
		if done {
			r.logf("saw %s", what)
			return nil
		}
		if !r.now().Before(deadline) {
			return fmt.Errorf("no sign of %s within %d s; check the board is powered and polling", what, seconds)
		}
		r.sleep(5 * time.Second)
	}
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// readFrom returns a file's text from an offset. A file that shrank, because
// something else truncated it, is read from the start.
func readFrom(path string, offset int64) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if offset < 0 || offset > int64(len(data)) {
		offset = 0
	}
	return string(data[offset:]), nil
}
