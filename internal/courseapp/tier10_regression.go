package courseapp

// Tier 10's regression rerun (#292): ./course regression run.
//
// One command reruns every board-capable fixture against the release the
// board is running, and reports the host fixtures and runners separately, as
// the regression evidence the final claim matrix opens with (#289). It is the
// step before advancing a rollout that T10-W-39 rests on: approval never boots
// the image, so this is where a release that regresses a control is caught.
//
// Three rules shape everything here.
//
//   - A board result is the device's own reaction, as the service stored it in
//     events.jsonl under the board's device id, or the board's own answer on the
//     wire. Nothing on the host decides what the board did.
//   - Every line carries the fixture id, the result and a board or host label,
//     and a host result never stands in for a board result. The label comes
//     from which list in course.yml an entry is in, never from its outcome.
//   - A wait that runs out is "no result". It is never a pass, because the
//     absence of a refusal is not a refusal.
//
// The plan is course.yml's `regression:` block and nothing else. No device id,
// release id, address or port is ever typed: the board is found in the event
// log, its address is the one `./course device address` recorded, and every
// other input is a manifest value. See docs/fixture-safety-contract.md, "Tier
// 10".

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// regressionManifest is course.yml's `regression:` block.
type regressionManifest struct {
	Tier      string `yaml:"tier"`
	Target    string `yaml:"target"`
	Interface string `yaml:"interface"`

	// The two TLS ports and the name the service presents, read from here so
	// no endpoint is ever on a command line, as the fleet block does.
	DevicePort   int    `yaml:"device_port"`
	OperatorPort int    `yaml:"operator_port"`
	ServiceName  string `yaml:"service_name"`

	BoardWaitSeconds  int `yaml:"board_wait_seconds"`
	BoardFreshSeconds int `yaml:"board_fresh_seconds"`

	// The support listener is asked at most SupportAttempts times,
	// SupportIntervalSeconds apart, and the run stops at the first answer:
	// a reply, or the board's port unreachable. Only silence is retried.
	SupportAttempts        int `yaml:"support_attempts"`
	SupportIntervalSeconds int `yaml:"support_interval_seconds"`

	Board    []regressionEntry `yaml:"board"`
	Host     []regressionEntry `yaml:"host"`
	NotRerun []regressionSkip  `yaml:"not_rerun"`
}

// regressionEntry is one line of the plan. ID is a registered fixture id or a
// bypass row id. At most one selector is set, and it must be one the fixture's
// own allowlist holds.
type regressionEntry struct {
	ID      string `yaml:"id"`
	Request string `yaml:"request"`
	Image   string `yaml:"image"`
	Release string `yaml:"release"`
	Probe   string `yaml:"probe"`
	Answers string `yaml:"answers"`
	Expect  string `yaml:"expect"`
	Check   string `yaml:"check"`
}

// regressionSkip is a fixture or variant the plan decided not to rerun.
type regressionSkip struct {
	ID       string `yaml:"id"`
	Selector string `yaml:"selector"`
	Reason   string `yaml:"reason"`
}

// The two labels. They are the only two, and which one a line carries depends
// on the list its entry sits in.
const (
	labelBoard = "board"
	labelHost  = "host"
)

// The verdicts a line can carry.
const (
	verdictPass     = "pass"
	verdictFail     = "fail"
	verdictNoResult = "no result"
	verdictNotRun   = "not run"
)

// The kinds of step, which decide how an entry runs.
const (
	kindSupportListener = "support-listener"
	kindRelease         = "release"
	kindProbe           = "probe"
	kindBypass          = "bypass"
	kindStation         = "station"
)

// The outcomes a board reaction is classified into, from stored events.
const (
	// The application refused the offered release: update.refused before the
	// download or update.failed after it, both naming the release.
	outcomeRefused = "refused"
	// The application wrote the image and the board then reported the release
	// it was already running: MCUboot refused it at the next boot.
	outcomeRefusedAtBoot = "refused-at-boot"
	// The board reported running the offered release. Always a failure.
	outcomeInstalled = "installed"
	// The board tried the release and put the old one back. A trial failure,
	// not a security refusal.
	outcomeReverted = "reverted"

	// The support listener's two answers. Silence is no result, not an outcome.
	outcomeAbsent   = "absent"
	outcomeAnswered = "answered"

	// Host probes.
	outcomeNotServed = "not-served"
	outcomeServed    = "served"
)

// The host probes, each one request that replays a Tier 0 or Tier 2 attack
// against the running Tier 10 service.
const (
	probePlainReleaseRecord        = "plain-release-record"
	probeClientCertificateRequired = "client-certificate-required"
	probeUntrustedCertificate      = "untrusted-certificate"
	probeWrongNameCertificate      = "wrong-name-certificate"
)

// stationRows are the Tier 6 station runners the plan may name. Only E-6-07 is
// in the plan today; the map keeps the dispatch in one place.
var stationRows = map[string]func(*app) error{
	"e-6-07": (*app).bypassClonedSharedCredential,
}

// The bound on the support listener's retry, whatever course.yml says.
const (
	maxSupportAttempts    = 6
	maxSupportSpanSeconds = 120
)

// regressionStep is one entry, checked against the manifest and ready to run.
type regressionStep struct {
	label    string
	kind     string
	entry    regressionEntry
	option   string
	selector string
}

// name is the fixture id with its selector, exactly as the line prints it.
func (s regressionStep) name() string {
	if s.selector == "" {
		return s.entry.ID
	}
	return s.entry.ID + " " + s.option + " " + s.selector
}

// regressionPlan is the checked plan: board steps first and in order, then
// host steps, then the decided exclusions.
type regressionPlan struct {
	board    []regressionStep
	host     []regressionStep
	notRerun []regressionSkip
}

// The outcomes each kind may expect. An expectation outside these is a typo in
// course.yml, and a typo must not quietly become a line that can never pass.
var expectable = map[string][]string{
	kindSupportListener: {outcomeAbsent},
	kindRelease:         {outcomeRefused, outcomeRefusedAtBoot},
	kindProbe:           {outcomeNotServed, outcomeRefused},
	kindBypass:          {outcomeRefused},
	kindStation:         {outcomeRefused},
}

// buildRegressionPlan checks the `regression:` block against the rest of the
// manifest and returns the plan.
//
// It refuses an incomplete plan. Every registered fixture that needs hardware
// must be rerun on the board or be listed in not_rerun with a reason, because
// "every board-capable fixture" is the claim the final matrix rests on, and a
// fixture added later must not be left out silently.
func buildRegressionPlan(m manifest) (regressionPlan, error) {
	var plan regressionPlan
	block := m.Regression
	if len(block.Board) == 0 {
		return plan, errors.New("course.yml has no regression board entries")
	}
	if block.BoardWaitSeconds <= 0 || block.BoardWaitSeconds > maxFixtureHoldSeconds {
		return plan, fmt.Errorf("regression.board_wait_seconds must be between 1 and %d", maxFixtureHoldSeconds)
	}
	if block.BoardFreshSeconds <= 0 {
		return plan, errors.New("regression.board_fresh_seconds must be positive")
	}
	// Bounded, so the retry can never become a flood: a handful of datagrams
	// across about one health window, and no more.
	if block.SupportAttempts < 1 || block.SupportAttempts > maxSupportAttempts ||
		block.SupportIntervalSeconds < 1 || block.SupportIntervalSeconds*(block.SupportAttempts-1) > maxSupportSpanSeconds {
		return plan, fmt.Errorf("regression.support_attempts must be 1 to %d, at least 1 s apart, spanning at most %d s",
			maxSupportAttempts, maxSupportSpanSeconds)
	}

	covered := map[string]bool{}
	for i, entry := range block.Board {
		step, err := boardStep(m, entry)
		if err != nil {
			return plan, fmt.Errorf("regression.board[%d]: %w", i, err)
		}
		// The planted regression is live only during a candidate trial, so
		// the support listener is asked first, before anything that waits.
		if i == 0 && step.kind != kindSupportListener {
			return plan, errors.New("regression.board must start with tier-09/support-listener --request inventory")
		}
		covered[entry.ID] = true
		plan.board = append(plan.board, step)
	}
	for i, entry := range block.Host {
		step, err := hostStep(m, entry)
		if err != nil {
			return plan, fmt.Errorf("regression.host[%d]: %w", i, err)
		}
		plan.host = append(plan.host, step)
	}
	for i, skip := range block.NotRerun {
		if strings.TrimSpace(skip.Reason) == "" {
			return plan, fmt.Errorf("regression.not_rerun[%d] (%s) has no reason", i, skip.ID)
		}
		if skip.Selector == "" {
			covered[skip.ID] = true
		}
		plan.notRerun = append(plan.notRerun, skip)
	}

	var missing []string
	for id, f := range m.Fixtures {
		if f.HardwareRequired && !covered[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return plan, fmt.Errorf("board-capable fixtures neither rerun nor listed in regression.not_rerun: %s",
			strings.Join(missing, ", "))
	}
	return plan, nil
}

// boardStep checks one board entry. It must name a registered fixture that
// needs hardware, because a fixture that does not cannot produce a board
// result, whatever list it is put in.
func boardStep(m manifest, entry regressionEntry) (regressionStep, error) {
	f, ok := m.Fixtures[entry.ID]
	if !ok {
		return regressionStep{}, fmt.Errorf("%q is not a registered fixture", entry.ID)
	}
	if !f.HardwareRequired {
		return regressionStep{}, fmt.Errorf("%s needs no hardware, so it cannot give a board result; list it under host", entry.ID)
	}
	if entry.Probe != "" || entry.Answers != "" {
		return regressionStep{}, fmt.Errorf("%s: probe and answers are host fields", entry.ID)
	}
	step := regressionStep{label: labelBoard, entry: entry, kind: kindRelease}
	if entry.ID != supportListenerFixtureID && !hostingFixtures[entry.ID] {
		return regressionStep{}, fmt.Errorf("%s has no way to reach the board from this command", entry.ID)
	}
	if entry.ID == supportListenerFixtureID {
		step.kind = kindSupportListener
		// Inventory only. A reboot during a candidate trial is a failed
		// trial, so it would cause the revert the run is there to observe.
		if entry.Request != "inventory" {
			return regressionStep{}, errors.New("the support listener is asked for inventory only; reboot is destructive during a trial")
		}
	}
	allowed, option := f.selectors()
	given := map[string]string{"--request": entry.Request, "--image": entry.Image, "--release": entry.Release}
	for name, value := range given {
		if value != "" && name != option {
			return regressionStep{}, fmt.Errorf("%s selects with %s, not %s", entry.ID, option, name)
		}
	}
	if len(allowed) > 0 {
		value := given[option]
		if _, ok := allowed[value]; !ok {
			return regressionStep{}, fmt.Errorf("%s needs %s from its own allowlist, not %q", entry.ID, option, value)
		}
		step.option, step.selector = option, value
	}
	if err := checkExpectation(step); err != nil {
		return regressionStep{}, err
	}
	return step, nil
}

// hostStep checks one host entry: a host probe on a registered fixture that
// needs no hardware, a Tier 6 station runner, or a Tier 7 or 8 bypass row with
// a host runner.
func hostStep(m manifest, entry regressionEntry) (regressionStep, error) {
	step := regressionStep{label: labelHost, entry: entry}
	if entry.Request != "" || entry.Image != "" || entry.Release != "" {
		return step, fmt.Errorf("%s: host entries take no fixture selector", entry.ID)
	}
	switch {
	case entry.Probe != "":
		f, ok := m.Fixtures[entry.ID]
		if !ok {
			return step, fmt.Errorf("%q is not a registered fixture", entry.ID)
		}
		if f.HardwareRequired {
			return step, fmt.Errorf("%s needs hardware; its result belongs under board", entry.ID)
		}
		switch entry.Probe {
		case probePlainReleaseRecord, probeClientCertificateRequired, probeUntrustedCertificate, probeWrongNameCertificate:
		default:
			return step, fmt.Errorf("%s: unknown probe %q", entry.ID, entry.Probe)
		}
		step.kind = kindProbe
	case stationRows[entry.ID] != nil:
		step.kind = kindStation
	default:
		row, ok := lookupBypassRow(entry.ID)
		if !ok {
			return step, fmt.Errorf("%q is neither a host fixture probe nor a bypass row", entry.ID)
		}
		if row.run == nil {
			// A board row, or E-8-11, which builds for native_sim and opens
			// no socket. Neither is a host runner this command can drive.
			return step, fmt.Errorf("%s has no host runner against the service", entry.ID)
		}
		step.kind = kindBypass
	}
	if entry.Answers != "" {
		if _, ok := m.Fixtures[entry.Answers]; !ok {
			return step, fmt.Errorf("%s answers %q, which is not a registered fixture", entry.ID, entry.Answers)
		}
	}
	if err := checkExpectation(step); err != nil {
		return step, err
	}
	return step, nil
}

func checkExpectation(step regressionStep) error {
	if contains(expectable[step.kind], step.entry.Expect) {
		return nil
	}
	return fmt.Errorf("%s: expect %q is not one of %s", step.entry.ID, step.entry.Expect,
		strings.Join(expectable[step.kind], ", "))
}

// ------------------------------------------------------------------
// The board, read from the service's event log
// ------------------------------------------------------------------

// boardEvent is the part of one events.jsonl line this command reads.
type boardEvent struct {
	DeviceID         string    `json:"device_id"`
	Event            string    `json:"event"`
	RunningReleaseID string    `json:"running_release_id"`
	Detail           string    `json:"detail"`
	AcceptedFrom     string    `json:"accepted_from"`
	ReceivedAt       time.Time `json:"service_received_at"`
}

// readBoardEvents reads the service's event log. A line that does not parse is
// skipped rather than fatal: the log has had several writers across eleven
// tiers, and one malformed line must not hide every board result after it.
func readBoardEvents(path string) ([]boardEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var events []boardEvent
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var event boardEvent
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.DeviceID != "" {
			events = append(events, event)
		}
	}
	return events, scanner.Err()
}

// boardState is what the log says about the board when the run starts.
type boardState struct {
	DeviceID         string    `json:"device_id"`
	RunningReleaseID string    `json:"running_release_id"`
	LastStatusAt     time.Time `json:"last_status_at"`
	// TrialReleaseID is set when the board stored update.installed for another
	// release after its last status report and nothing since: it rebooted into
	// that release on trial, and a trial reports nothing until it is over.
	TrialReleaseID   string     `json:"trial_release_id,omitempty"`
	TrialInstalledAt *time.Time `json:"trial_installed_at,omitempty"`
}

// againstReleaseID is the release this run tests: the one on trial if there is
// one, because that is the image the board is executing.
func (b boardState) againstReleaseID() string {
	if b.TrialReleaseID != "" {
		return b.TrialReleaseID
	}
	return b.RunningReleaseID
}

// syntheticDeviceIDs is every device id this manifest names as synthetic, plus
// the prefixes the course's synthetic devices are named under. The board is
// the one recent reporter that is none of these.
func syntheticDeviceIDs(m manifest) (map[string]bool, []string) {
	ids := map[string]bool{}
	for _, id := range m.Fleet.DeviceIDs {
		ids[id] = true
	}
	for _, block := range m.Bypass {
		for _, id := range block.SyntheticIDs {
			ids[id] = true
		}
	}
	for _, f := range m.Fixtures {
		for _, id := range f.PhantomIDs {
			ids[id] = true
		}
	}
	for _, device := range m.Devices {
		ids[device.SyntheticID] = true
		ids[device.SpoofID] = true
	}
	return ids, []string{"beacon-bypass-", "beacon-fleet-", "beacon-phantom-"}
}

// identifyBoard finds the board in the log: the device that reported a status
// over mutual TLS within the freshness bound and is not synthetic. It refuses
// when there is none or more than one, rather than guess, because every board
// result in the run is read under the id it returns.
func identifyBoard(events []boardEvent, synthetic map[string]bool, prefixes []string,
	now time.Time, fresh time.Duration) (boardState, error) {
	isSynthetic := func(id string) bool {
		if synthetic[id] {
			return true
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(id, prefix) {
				return true
			}
		}
		return false
	}
	latest := map[string]boardEvent{}
	for _, event := range events {
		if event.Event != "status.observed" || event.AcceptedFrom != "client_certificate" || isSynthetic(event.DeviceID) {
			continue
		}
		if event.ReceivedAt.After(latest[event.DeviceID].ReceivedAt) {
			latest[event.DeviceID] = event
		}
	}
	var recent []string
	for id, event := range latest {
		if now.Sub(event.ReceivedAt) <= fresh {
			recent = append(recent, id)
		}
	}
	sort.Strings(recent)
	switch len(recent) {
	case 0:
		return boardState{}, fmt.Errorf("no board reported its status over mutual TLS in the last %s; start the board and wait for a poll", fresh)
	case 1:
	default:
		return boardState{}, fmt.Errorf("more than one device that is not synthetic reported recently (%s); the run cannot tell which is the board",
			strings.Join(recent, ", "))
	}
	status := latest[recent[0]]
	state := boardState{DeviceID: status.DeviceID, RunningReleaseID: status.RunningReleaseID, LastStatusAt: status.ReceivedAt}
	for _, event := range events {
		if event.DeviceID != state.DeviceID || !event.ReceivedAt.After(status.ReceivedAt) {
			continue
		}
		if event.Event == "update.installed" && event.Detail != "" && event.Detail != status.RunningReleaseID {
			at := event.ReceivedAt
			state.TrialReleaseID, state.TrialInstalledAt = event.Detail, &at
		}
		// A revert or a confirmation after the install closes the trial.
		if event.Event == "update.reverted" || event.Event == "update.confirmed" {
			state.TrialReleaseID, state.TrialInstalledAt = "", nil
		}
	}
	return state, nil
}

// releaseDetailNames reports whether an event's detail names the release. The
// board writes the bare release id, or for a revert the id and a reason.
func releaseDetailNames(detail, releaseID string) bool {
	return detail == releaseID || strings.HasPrefix(detail, releaseID+" ")
}

// detailCheck returns the check= token from a detail, if the board ever
// writes one. Today the check name is on the serial console only.
func detailCheck(detail string) string {
	for _, field := range strings.Fields(detail) {
		if value, ok := strings.CutPrefix(field, "check="); ok {
			return value
		}
	}
	return ""
}

// classifyReleaseReaction reads what the board did with one offered release,
// from the events it stored after since. It returns "" when the log does not
// yet hold a decisive reaction.
//
// It reads only the board's own events, under its own id. A refusal another
// device stored, or the service's own refusal of a request, is not the board
// refusing anything.
func classifyReleaseReaction(events []boardEvent, deviceID, offered, original string, since time.Time) (outcome, check string) {
	installed := false
	for _, event := range events {
		if event.DeviceID != deviceID || event.ReceivedAt.Before(since) {
			continue
		}
		switch event.Event {
		case "update.refused", "update.failed":
			if releaseDetailNames(event.Detail, offered) {
				return outcomeRefused, detailCheck(event.Detail)
			}
		case "update.installed":
			if releaseDetailNames(event.Detail, offered) {
				installed = true
			}
		case "update.reverted":
			if releaseDetailNames(event.Detail, offered) {
				return outcomeReverted, ""
			}
		case "status.observed", "update.confirmed":
			if event.RunningReleaseID == offered {
				return outcomeInstalled, ""
			}
			if installed && event.Event == "status.observed" && event.RunningReleaseID == original {
				return outcomeRefusedAtBoot, ""
			}
		}
	}
	return "", ""
}

// waitForReaction polls the log until the board's reaction to an offered
// release is decisive or the bound runs out. Running out is "no result".
func waitForReaction(read func() ([]boardEvent, error), deviceID, offered, original string,
	since time.Time, bound time.Duration, now func() time.Time, sleep func(time.Duration)) (outcome, check string, err error) {
	deadline := now().Add(bound)
	for {
		events, err := read()
		if err != nil {
			return "", "", err
		}
		if outcome, check := classifyReleaseReaction(events, deviceID, offered, original, since); outcome != "" {
			return outcome, check, nil
		}
		if !now().Before(deadline) {
			return "", "", nil
		}
		sleep(2 * time.Second)
	}
}

// judge turns an expectation and an observation into a verdict. An empty
// observation is no result. A check the board stored that differs from the
// expected one is a failure, because a refusal for the wrong reason has not
// tested what the line claims.
func judge(expected, expectedCheck, observed, observedCheck string) string {
	switch {
	case observed == "":
		return verdictNoResult
	case observed != expected:
		return verdictFail
	case expectedCheck != "" && observedCheck != "" && observedCheck != expectedCheck:
		return verdictFail
	default:
		return verdictPass
	}
}

// ------------------------------------------------------------------
// The release the board is running
// ------------------------------------------------------------------

// regressionRelease is the opening section of the final claim matrix: what the
// board runs, as its signed manifest says, and where that build came from.
type regressionRelease struct {
	ReleaseID         string `json:"release_id"`
	Version           string `json:"version"`
	SecurityCounter   int    `json:"security_counter"`
	ImagePath         string `json:"image_path"`
	ImageSHA256       string `json:"image_sha256"`
	ImageSize         int    `json:"image_size"`
	ManifestSHA256    string `json:"manifest_sha256"`
	SignatureVerified bool   `json:"signature_verified"`
	SourceRevision    string `json:"source_revision,omitempty"`
	CleanTree         *bool  `json:"clean_tree,omitempty"`
}

// describeRelease reads the signed manifest for a release out of the release
// store and checks its signature with the public half the firmware carries. A
// manifest that does not verify is refused: it is not what the board accepted.
func (a *app) describeRelease(releaseID string) (regressionRelease, error) {
	manifest, body, err := a.loadStoredManifest(releaseID)
	if err != nil {
		return regressionRelease{}, fmt.Errorf("the board reports %s, and %w in the release store", releaseID, err)
	}
	signature, err := os.ReadFile(a.manifestSignaturePath(releaseID))
	if err != nil {
		return regressionRelease{}, fmt.Errorf("no stored signature for %s", releaseID)
	}
	key, err := a.releaseVerifyKey()
	if err != nil {
		return regressionRelease{}, err
	}
	if !manifestVerifies(key, body, signature) {
		return regressionRelease{}, fmt.Errorf("the stored manifest for %s does not verify against the release key", releaseID)
	}
	sum := sha256.Sum256(body)
	release := regressionRelease{
		ReleaseID: manifest.ReleaseID, Version: manifest.Version, SecurityCounter: manifest.SecurityCounter,
		ImagePath: manifest.ImagePath, ImageSHA256: manifest.ImageSHA256, ImageSize: manifest.ImageSize,
		ManifestSHA256: hex.EncodeToString(sum[:]), SignatureVerified: true,
	}
	// The build manifest says which source the image came from (#277). A
	// release signed before Tier 9 has none, and the receipt says so by
	// leaving the field out rather than inventing one.
	var build struct {
		SourceRevision string `json:"source_revision"`
		CleanTree      *bool  `json:"clean_tree"`
	}
	if readJSON(filepath.Join(a.releaseDir(), releaseID+".build-manifest.json"), &build) == nil {
		release.SourceRevision, release.CleanTree = build.SourceRevision, build.CleanTree
	}
	return release, nil
}

// ------------------------------------------------------------------
// The command
// ------------------------------------------------------------------

// regressionResult is one line of the run, as printed and as the receipt
// stores it.
type regressionResult struct {
	Fixture       string `json:"fixture"`
	Option        string `json:"option,omitempty"`
	Selector      string `json:"selector,omitempty"`
	Label         string `json:"label"`
	Answers       string `json:"answers,omitempty"`
	Expected      string `json:"expected,omitempty"`
	ExpectedCheck string `json:"expected_check,omitempty"`
	Observed      string `json:"observed,omitempty"`
	ObservedCheck string `json:"observed_check,omitempty"`
	Result        string `json:"result"`
	Detail        string `json:"detail,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
}

// serviceSnapshot is the Fleet baseline and the rollout state, read before and
// after the run so a run that moved either is caught.
type serviceSnapshot struct {
	BaselineReleaseID string `json:"baseline_release_id"`
	RolloutOpen       bool   `json:"rollout_open"`
	RolloutReleaseID  string `json:"rollout_release_id,omitempty"`
	RolloutStage      string `json:"rollout_stage,omitempty"`
	RolloutPaused     bool   `json:"rollout_paused,omitempty"`
}

// regression routes ./course regression.
func (a *app) regression(args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return errors.New("regression requires run")
	}
	return a.regressionRun(args[1:])
}

// regressionExecuteID is the identifier a run is confirmed with, the way a
// fixture is confirmed with its own id.
const regressionExecuteID = "regression"

// regressionRun is ./course regression run [--only <fixture>] [--execute regression].
func (a *app) regressionRun(args []string) error {
	executeID, only := "", ""
	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			return fmt.Errorf("option %s requires a value", args[i])
		}
		switch args[i] {
		case "--execute":
			executeID = args[i+1]
		case "--only":
			only = args[i+1]
		default:
			return fmt.Errorf("unknown regression option %s; it takes --only <fixture> and --execute %s", args[i], regressionExecuteID)
		}
		i++
	}
	plan, err := buildRegressionPlan(a.manifest)
	if err != nil {
		return err
	}
	if only != "" {
		if plan, err = plan.only(only); err != nil {
			return err
		}
	}
	block := a.manifest.Regression

	// The Tier 0 guarantees, before any side effect: one literal target, the
	// named interface, and the marker handshake over plain HTTP.
	if err := validateTarget(block.Target); err != nil {
		return err
	}
	if err := validateSelectedInterface(block.Target, block.Interface, true); err != nil {
		return err
	}
	env, fingerprint, err := a.matchMarker(block.Target)
	if err != nil {
		return err
	}
	if err := a.requireLearnerService(); err != nil {
		return err
	}
	// A hosting fixture that published and was never reset has left the Fleet
	// baseline holding a hostile release. The run refuses to start on that,
	// because every board result after it would be read against the wrong
	// baseline, and the fix is that fixture's own reset.
	var saved hostingSaved
	if readJSON(a.hostingSavedPath(), &saved) == nil {
		return fmt.Errorf("the Fleet baseline is not what it was: %s published a release that was never reset; run ./course attack reset %s first",
			saved.Fixture, saved.Fixture)
	}

	eventsPath := a.eventsPath()
	events, err := readBoardEvents(eventsPath)
	if err != nil {
		return fmt.Errorf("cannot read the service's event log: %w", err)
	}
	synthetic, prefixes := syntheticDeviceIDs(a.manifest)
	board, err := identifyBoard(events, synthetic, prefixes, time.Now().UTC(),
		time.Duration(block.BoardFreshSeconds)*time.Second)
	if err != nil {
		return err
	}
	release, err := a.describeRelease(board.againstReleaseID())
	if err != nil {
		return err
	}
	before, err := a.serviceSnapshot()
	if err != nil {
		return err
	}
	// The course revision the command ran from, beside the release's own
	// source revision from its build manifest. Outside a Git checkout there is
	// none, and the receipt says so with an empty field rather than an error
	// message.
	revision, err := gitOutput(a.root, "rev-parse", "HEAD")
	if err != nil {
		revision = ""
	}
	dirty, err := gitOutput(a.root, "status", "--porcelain")
	if err != nil {
		dirty = ""
	}

	fmt.Fprintf(a.out, "Regression rerun, Tier %s\n", block.Tier)
	fmt.Fprintf(a.out, "Target: %s\nInterface: %s\nMarker fingerprint: %s\n", block.Target, block.Interface, fingerprint)
	treeClean := strings.TrimSpace(dirty) == ""
	command := "./course regression run --execute " + regressionExecuteID
	if only != "" {
		command += " --only " + only
	}
	shown := strings.TrimSpace(revision)
	if shown == "" {
		shown = "unknown, not a Git checkout"
	}
	fmt.Fprintf(a.out, "Course revision: %s", shown)
	if !treeClean {
		fmt.Fprint(a.out, " (uncommitted changes)")
	}
	fmt.Fprintln(a.out)
	fmt.Fprintf(a.out, "Board: %s, last status %s, running %s\n", board.DeviceID,
		board.LastStatusAt.Format(time.RFC3339), board.RunningReleaseID)
	if board.TrialReleaseID != "" {
		fmt.Fprintf(a.out, "On trial: %s, installed %s. The board is executing it now.\n",
			board.TrialReleaseID, board.TrialInstalledAt.Format(time.RFC3339))
	}
	fmt.Fprintf(a.out, "Against: %s, counter %d, image sha256 %s\n", release.ReleaseID, release.SecurityCounter, release.ImageSHA256)
	fmt.Fprintf(a.out, "  signed manifest sha256 %s, signature verified\n", release.ManifestSHA256)
	if release.SourceRevision != "" {
		fmt.Fprintf(a.out, "  built from %s, clean tree %v\n", release.SourceRevision, release.CleanTree != nil && *release.CleanTree)
	}
	fmt.Fprintf(a.out, "Fleet baseline: %s\n", before.BaselineReleaseID)
	if before.RolloutOpen {
		fmt.Fprintf(a.out, "Open rollout: %s, stage %s, paused %t\n", before.RolloutReleaseID, before.RolloutStage, before.RolloutPaused)
	} else {
		fmt.Fprintln(a.out, "Open rollout: none")
	}

	if executeID == "" {
		fmt.Fprintln(a.out, "\nPlan:")
		for _, step := range append(append([]regressionStep{}, plan.board...), plan.host...) {
			fmt.Fprintf(a.out, "  %-5s  %s, expect %s\n", step.label, step.name(), step.entry.Expect)
		}
		for _, skip := range plan.notRerun {
			fmt.Fprintf(a.out, "  not run  %s\n", skipName(skip))
		}
		fmt.Fprintln(a.out, "Result: dry run only")
		fmt.Fprintf(a.out, "Execute: %s\n", command)
		return nil
	}
	if executeID != regressionExecuteID {
		return fmt.Errorf("--execute value must be exactly %q", regressionExecuteID)
	}

	start := time.Now().UTC()
	fmt.Fprintln(a.out, "\nBoard results")
	var results []regressionResult
	// A release reaches the board only through the Fleet baseline, and a
	// device in an open rollout is offered the rollout's release instead. So
	// while a rollout is open the release entries cannot reach the board, and
	// each says so as no result rather than reading silence as a refusal.
	releaseBlocked := ""
	if before.RolloutOpen {
		releaseBlocked = fmt.Sprintf("not offered: the rollout of %s is open, so the board is offered that release and never the baseline a fixture writes; run again after it is completed or withdrawn",
			before.RolloutReleaseID)
	}
	for _, step := range plan.board {
		var result regressionResult
		switch {
		case step.kind == kindRelease && releaseBlocked != "":
			result = newResult(step)
			result.Result, result.Detail = verdictNoResult, releaseBlocked
		default:
			result = a.runBoardStep(step, board, env, fingerprint)
		}
		results = append(results, result)
		a.printResult(result)
		// A release step that could not restore the baseline stops the
		// release steps after it: they would publish over a hostile baseline.
		if step.kind == kindRelease && releaseBlocked == "" {
			if now, err := a.serviceSnapshot(); err != nil || now.BaselineReleaseID != before.BaselineReleaseID {
				releaseBlocked = "not offered: an earlier release step did not restore the Fleet baseline"
			}
		}
	}
	fmt.Fprintln(a.out, "\nHost results. A host result never stands in for a board result.")
	ranBypass := false
	for _, step := range plan.host {
		result := a.runHostStep(step)
		ranBypass = ranBypass || step.kind == kindBypass
		results = append(results, result)
		a.printResult(result)
	}
	for _, skip := range plan.notRerun {
		result := regressionResult{Fixture: skip.ID, Selector: skip.Selector, Label: skipLabel(a.manifest, skip),
			Result: verdictNotRun, Detail: skip.Reason}
		results = append(results, result)
		a.printResult(result)
	}

	// The bypass rows leave the adversary owner live; their own reset clears
	// it and appends rather than deletes, so it runs once, after all of them.
	resetResult := "not needed"
	if ranBypass {
		resetResult = "passed"
		if _, err := a.quietly(a.bypassReset); err != nil {
			resetResult = "failed: " + err.Error()
		}
		fmt.Fprintf(a.out, "\nReset: %s, %s\n", a.manifest.Bypass[tier07BypassKey].Reset, resetResult)
	}

	after, err := a.serviceSnapshot()
	var runProblems []string
	if err != nil {
		runProblems = append(runProblems, "could not read the Fleet baseline after the run: "+err.Error())
	} else if after != before {
		runProblems = append(runProblems, fmt.Sprintf("the Fleet baseline or rollout changed during the run: before %+v, after %+v", before, after))
	}
	if strings.HasPrefix(resetResult, "failed") {
		runProblems = append(runProblems, "the bypass reset failed; run "+a.manifest.Bypass[tier07BypassKey].Reset)
	}

	counts := map[string]int{}
	for _, result := range results {
		counts[result.Label+" "+result.Result]++
	}
	overall := verdictPass
	for _, result := range results {
		if result.Result == verdictFail || result.Result == verdictNoResult {
			overall = verdictFail
		}
	}
	if len(runProblems) > 0 {
		overall = verdictFail
	}

	receipt := map[string]any{
		"schema_version":     1,
		"tier":               block.Tier,
		"command":            command,
		"only":               only,
		"started_at":         start,
		"ended_at":           time.Now().UTC(),
		"marker_fingerprint": fingerprint,
		"course_revision":    strings.TrimSpace(revision),
		"course_tree_clean":  treeClean,
		"board":              board,
		"release":            release,
		"service_before":     before,
		"service_after":      after,
		"results":            results,
		"bypass_reset":       resetResult,
		"problems":           runProblems,
		"result":             overall,
	}
	path, err := a.writeRegressionReceipt(receipt)
	if err != nil {
		return err
	}

	fmt.Fprintln(a.out)
	for _, problem := range runProblems {
		fmt.Fprintf(a.out, "Problem: %s\n", problem)
	}
	fmt.Fprintf(a.out, "Board: %d pass, %d fail, %d no result, %d not run\n",
		counts["board pass"], counts["board fail"], counts["board no result"], counts["board not run"])
	fmt.Fprintf(a.out, "Host: %d pass, %d fail, %d no result, %d not run\n",
		counts["host pass"], counts["host fail"], counts["host no result"], counts["host not run"])
	fmt.Fprintf(a.out, "Receipt: %s\n", a.relative(path))
	fmt.Fprintf(a.out, "Result: %s\n", overall)
	if overall != verdictPass {
		return errors.New("the regression run did not pass; every line that is not a pass is above")
	}
	return nil
}

// only narrows the plan to the entries for one fixture or row id.
func (p regressionPlan) only(id string) (regressionPlan, error) {
	var narrowed regressionPlan
	for _, step := range p.board {
		if step.entry.ID == id {
			narrowed.board = append(narrowed.board, step)
		}
	}
	for _, step := range p.host {
		if step.entry.ID == id {
			narrowed.host = append(narrowed.host, step)
		}
	}
	if len(narrowed.board)+len(narrowed.host) == 0 {
		return narrowed, fmt.Errorf("--only %q names nothing in the regression plan", id)
	}
	return narrowed, nil
}

func skipName(skip regressionSkip) string {
	if skip.Selector == "" {
		return skip.ID
	}
	return skip.ID + " " + skip.Selector
}

// skipLabel is the label an excluded entry would have carried. A registered
// fixture that needs hardware is a board fixture whether or not it ran.
func skipLabel(m manifest, skip regressionSkip) string {
	if f, ok := m.Fixtures[skip.ID]; ok && f.HardwareRequired {
		return labelBoard
	}
	return labelHost
}

// printResult prints one line: the label, the fixture id with its selector,
// the verdict, and what was expected and seen.
func (a *app) printResult(r regressionResult) {
	name := r.Fixture
	if r.Selector != "" {
		if r.Option != "" {
			name += " " + r.Option + " " + r.Selector
		} else {
			name += " " + r.Selector
		}
	}
	fmt.Fprintf(a.out, "%-5s  %-48s  %-9s", r.Label, name, r.Result)
	switch {
	case r.Result == verdictNotRun:
		fmt.Fprintf(a.out, "  %s", r.Detail)
	default:
		observed := r.Observed
		if observed == "" {
			observed = "nothing"
		}
		fmt.Fprintf(a.out, "  expected %s, observed %s", r.Expected, observed)
		if r.Detail != "" {
			fmt.Fprintf(a.out, "; %s", r.Detail)
		}
	}
	fmt.Fprintln(a.out)
}

func newResult(step regressionStep) regressionResult {
	return regressionResult{
		Fixture: step.entry.ID, Option: step.option, Selector: step.selector, Label: step.label,
		Answers: step.entry.Answers, Expected: step.entry.Expect, ExpectedCheck: step.entry.Check,
	}
}

// runBoardStep runs one board entry and judges what the board did.
func (a *app) runBoardStep(step regressionStep, board boardState, env environment, fingerprint string) regressionResult {
	result := newResult(step)
	switch step.kind {
	case kindSupportListener:
		observed, detail, err := a.askSupportListener(step)
		result.Observed, result.Detail = observed, detail
		if err != nil {
			result.Detail = err.Error()
		}
	case kindRelease:
		result = a.deliverRelease(step, board, env, fingerprint)
	}
	result.Result = judge(step.entry.Expect, step.entry.Check, result.Observed, result.ObservedCheck)
	return result
}

// askSupportListener sends the one manifest-owned request to the board's
// recorded address and classifies the board's answer. A reply means the
// listener is there, whatever it says.
//
// It may ask more than once, and that is Tier 10's one addition to the Tier 9
// fixture's single datagram: the planted listener is live only while the
// candidate is on trial, so a run may start a little before the trial boot
// opens it. It stops at the first answer, a reply or the board's port
// unreachable, and only silence is retried, within the bound course.yml sets
// and buildRegressionPlan caps. Each attempt is still one datagram out and at
// most one in.
func (a *app) askSupportListener(step regressionStep) (string, string, error) {
	block := a.manifest.Regression
	f := a.manifest.Fixtures[supportListenerFixtureID]
	request := f.Requests[step.selector]
	port := f.Port
	if port == 0 {
		port = supportListenerPortDefault
	}
	address, err := a.boardAddress()
	if err != nil {
		return "", "", err
	}
	target := net.JoinHostPort(address, strconv.Itoa(port))
	attempts := block.SupportAttempts
	for attempt := 1; ; attempt++ {
		reply, err := sendSupportRequest(target, request, supportReplyTimeout)
		switch {
		case errors.Is(err, errSupportRefused):
			return outcomeAbsent, fmt.Sprintf("the board's stack answered port unreachable on UDP %d (attempt %d of %d)", port, attempt, attempts), nil
		case errors.Is(err, errSupportTimeout):
			if attempt < attempts {
				time.Sleep(time.Duration(block.SupportIntervalSeconds) * time.Second)
				continue
			}
			// Weak, so it is no result rather than absent: a lost datagram,
			// a board that rate-limits port unreachable, and a board that is
			// down all look the same. The boot log's "absent" line is the
			// record.
			return "", fmt.Sprintf("no reply to %d attempts; weak evidence, read the boot log for the listener's absent line", attempts), nil
		case err != nil:
			return "", "", err
		}
		return outcomeAnswered, fmt.Sprintf("unauthenticated %s answered %q (attempt %d of %d, T10-W-38)",
			request, strings.TrimSpace(reply), attempt, attempts), nil
	}
}

// deliverRelease runs one hosting fixture through the attack runner's own
// guarded execution and reads the board's reaction while the release is
// published, before the fixture's reset restores the baseline.
//
// The fixture is the one ./course attack run executes, with its marker
// handshake already done by this run, its evidence record and its
// block-after-failed-reset. On the mutual-TLS service it publishes as a
// compromised hosting side and its reset writes back the exact bytes it
// replaced (tier10_hosting.go). The wait sits where --hold sleeps: the board
// polls on its own schedule, so the release has to stay published until the
// board has answered or the bound has run out.
func (a *app) deliverRelease(step regressionStep, board boardState, env environment, fingerprint string) regressionResult {
	result := newResult(step)
	block := a.manifest.Regression
	f := a.manifest.Fixtures[step.entry.ID]
	if _, err := os.Stat(a.fixtureBlockPath(step.entry.ID)); err == nil {
		result.Detail = "the fixture is blocked after a failed reset; run " + f.Reset
		return result
	}
	since := time.Now().UTC()
	offered := ""
	hold := func() {
		var record releaseRecord
		if err := readJSON(a.baselinePath(), &record); err != nil {
			return
		}
		offered = record.ReleaseID
		read := func() ([]boardEvent, error) { return readBoardEvents(a.eventsPath()) }
		outcome, check, err := waitForReaction(read, board.DeviceID, offered, board.RunningReleaseID, since,
			time.Duration(block.BoardWaitSeconds)*time.Second, time.Now, time.Sleep)
		if err != nil {
			result.Detail = err.Error()
			return
		}
		result.Observed, result.ObservedCheck = outcome, check
	}
	var run fixtureRun
	output, err := a.quietly(func() error {
		var runErr error
		run, runErr = a.executeAndReset(step.entry.ID, step.selector, block.Target, block.Interface, env, fingerprint, hold)
		return runErr
	})
	result.Evidence = run.evidence
	switch {
	case err != nil:
		result.Detail = err.Error()
		if line := lastLineWith(output, "Reset result:"); line != "" {
			result.Detail += "; " + line
		}
	case result.Observed == "" && result.Detail == "":
		result.Detail = fmt.Sprintf("the board stored no reaction to %s within %d s", offered, block.BoardWaitSeconds)
	case result.Detail == "":
		result.Detail = "offered " + offered
		if result.ObservedCheck == "" && step.entry.Check != "" {
			result.Detail += "; the stored event names no check, so the serial line release.refused check=" +
				step.entry.Check + " is the witness"
		}
	}
	return result
}

// runHostStep runs one host entry. Each kind keeps the guarantees its own
// command gives: the bypass rows go through their own wrapper, with its marker
// handshake and evidence record.
func (a *app) runHostStep(step regressionStep) regressionResult {
	result := newResult(step)
	switch step.kind {
	case kindProbe:
		observed, detail, err := a.runProbe(step.entry.Probe)
		result.Observed, result.Detail = observed, detail
		if err != nil {
			result.Detail = err.Error()
		}
	case kindStation:
		output, err := a.quietly(func() error { return stationRows[step.entry.ID](a) })
		result.Observed, result.Detail = refusalOutcome(output, err)
	case kindBypass:
		row, _ := lookupBypassRow(step.entry.ID)
		output, err := a.quietly(func() error { return a.runBypassRow(row, row.id) })
		result.Observed, result.Detail = refusalOutcome(output, err)
		result.Evidence = evidenceLine(output)
	}
	result.Result = judge(step.entry.Expect, "", result.Observed, "")
	return result
}

// refusalOutcome reads a runner's verdict. Each runner already fails unless the
// refusal came at the check its row names, so a nil error is that refusal.
func refusalOutcome(output string, err error) (string, string) {
	line := lastLineWith(output, "Result:")
	if err != nil {
		if line == "" {
			line = err.Error()
		}
		return "not refused as the row requires", line
	}
	return outcomeRefused, strings.TrimSpace(strings.TrimPrefix(line, "Result:"))
}

func lastLineWith(output, prefix string) string {
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), prefix) {
			return strings.TrimSpace(lines[i])
		}
	}
	return ""
}

func evidenceLine(output string) string {
	return strings.TrimSpace(strings.TrimPrefix(lastLineWith(output, "Evidence:"), "Evidence:"))
}

// quietly runs a runner with its narration captured rather than printed, so the
// regression output stays one line per result. The narration is still in each
// runner's own evidence record.
func (a *app) quietly(run func() error) (string, error) {
	saved := a.out
	var buffer bytes.Buffer
	a.out = &buffer
	defer func() { a.out = saved }()
	err := run()
	return buffer.String(), err
}

// runProbe replays one Tier 0 or Tier 2 attack as one request against the
// running service. None of them changes service state, so none needs a reset,
// and none uses the old fixtures' reset, which reseeds the service.
func (a *app) runProbe(probe string) (string, string, error) {
	block := a.manifest.Regression
	pool, err := a.trustAnchorPool()
	if err != nil {
		return "", "", err
	}
	host := hostOf(block.Target)
	switch probe {
	case probePlainReleaseRecord:
		response, err := a.client.Get(strings.TrimRight(block.Target, "/") + "/v1/releases/current")
		if err != nil {
			return "", "", err
		}
		response.Body.Close()
		if response.StatusCode == http.StatusNotFound {
			return outcomeNotServed, "GET /v1/releases/current on the plain port answered 404", nil
		}
		return outcomeServed, "the plain port answered " + response.Status, nil
	case probeClientCertificateRequired:
		client := a.verifyingClient(pool, block.ServiceName, net.JoinHostPort(host, strconv.Itoa(block.DevicePort)))
		response, err := client.Get("https://" + block.ServiceName + ":" + strconv.Itoa(block.DevicePort) + "/v1/releases/current")
		if err != nil {
			return outcomeRefused, "a verified client with no client certificate was refused: " + err.Error(), nil
		}
		response.Body.Close()
		return outcomeServed, "the device listener answered a client with no certificate: " + response.Status, nil
	case probeUntrustedCertificate, probeWrongNameCertificate:
		cert, key := coursepki.UntrustedCert, coursepki.UntrustedKey
		if probe == probeWrongNameCertificate {
			cert, key = coursepki.WrongNameCert, coursepki.WrongNameKey
		}
		env, _, err := a.matchMarker(block.Target)
		if err != nil {
			return "", "", err
		}
		plainPort, tlsPort := a.manifest.Runtime.ImpersonationPort, a.manifest.Runtime.ImpersonationTLSPort
		stop, err := a.serveWith(env, host, plainPort, tlsPort, cert, key)
		if err != nil {
			return "", "", err
		}
		defer stop()
		if _, _, err := a.matchMarker(fmt.Sprintf("http://%s", net.JoinHostPort(host, strconv.Itoa(plainPort)))); err != nil {
			return "", "", err
		}
		client := a.verifyingClient(pool, block.ServiceName, net.JoinHostPort(host, strconv.Itoa(tlsPort)))
		response, err := client.Get("https://" + block.ServiceName + ":" + strconv.Itoa(tlsPort) + "/v1/releases/current")
		if err != nil {
			return outcomeRefused, "the imposter's certificate was refused: " + err.Error(), nil
		}
		response.Body.Close()
		return outcomeServed, "the imposter was accepted", nil
	}
	return "", "", fmt.Errorf("unknown probe %q", probe)
}

// serviceSnapshot reads the Fleet baseline and the rollout state from the
// operator listener. Both routes are reads, and the operator listener serves
// them to the lab bench for exactly this.
func (a *app) serviceSnapshot() (serviceSnapshot, error) {
	var snapshot serviceSnapshot
	var baseline struct {
		ReleaseID string `json:"release_id"`
	}
	if err := a.operatorRead("/v1/releases/current", &baseline); err != nil {
		return snapshot, err
	}
	var rollout struct {
		Open      bool   `json:"open"`
		ReleaseID string `json:"release_id"`
		Stage     string `json:"stage"`
		Paused    bool   `json:"paused"`
	}
	if err := a.operatorRead("/v1/rollouts/current", &rollout); err != nil {
		return snapshot, err
	}
	return serviceSnapshot{BaselineReleaseID: baseline.ReleaseID, RolloutOpen: rollout.Open,
		RolloutReleaseID: rollout.ReleaseID, RolloutStage: rollout.Stage, RolloutPaused: rollout.Paused}, nil
}

func (a *app) operatorRead(path string, value any) error {
	block := a.manifest.Regression
	return a.operatorGet(hostOf(block.Target), block.OperatorPort, block.ServiceName, path, value)
}

func (a *app) eventsPath() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "ota", "events.jsonl")
}

// writeRegressionReceipt writes the machine-readable record of one run under
// .course-state/regression, one file per run, so an earlier run is never
// overwritten by a later one.
func (a *app) writeRegressionReceipt(receipt map[string]any) (string, error) {
	runID := time.Now().UTC().Format("20060102T150405.000000000Z")
	path := filepath.Join(a.root, a.manifest.Paths.State, "regression", runID+".json")
	if err := writeJSON(path, receipt, 0o600); err != nil {
		return "", err
	}
	return path, nil
}
