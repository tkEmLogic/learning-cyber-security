package courseapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tier10Metadata is the metadata table every filled-in Tier 10 record below
// opens with, so the four structural checks pass and only the Tier 10 rules
// are under test.
const tier10Metadata = `| Field | Value |
| --- | --- |
| artifact_id | T10-TK |
| artifact_type | incident-record |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-10 |
| revision | 1 |
| status | draft |
| created_at | 2026-10-09 |
| last_reviewed_at |  |
| source_revision | 6fe7c2c |
| environment | course_id learning-cyber-security, tier 10, synthetic_data true |
| limitations | Times name their clock. |
`

// tier10Incident is a filled-in incident record: every timeline row names one
// of the three clocks, and the first pass classifies all eight events.
const tier10Incident = "# Incident record\n\n" + tier10Metadata + `
## Timeline

| Row | Time (UTC) | Clock source | Kind | Source | What happened | Event | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09T10:00:00Z | host | action | ./course scenario next | Event 1 staged | Event 1 |  |
| 2 |  | none | observation | serial | TLS handshake refused | Event 1 | serial-1.txt |
| 3 | 2026-10-09T10:01:12Z | service | observation | ota.log | no request from the board | Event 1 |  |

## Events: first pass

| Event | First observed | Clock source | Symptom | First classification | Boundary | Predicted control |
| --- | --- | --- | --- | --- | --- | --- |
| Event 1 | 10:00:30 | host | handshake refused | attack | device to service | TLS name check |
| Event 2 | 10:05:00 | service | refused | attack | hosted release | manifest signature |
| Event 3 | 10:09:00 | service | refused | undetermined | hosted release | security counter |
| Event 4 | 10:12:00 | service | refused | attack | device to service | certificate status |
| Event 5 | 10:15:00 | service | zero served | undetermined | none | none |
| Event 6 | 10:18:00 | service | resumed | operational failure | none | resumable download |
| Event 7 | 10:25:00 | none | reverted | operational failure | none | health gate |
| Event 8 | 10:26:00 | none | answered | attack | device to network | none |
`

const tier10Matrix = "# Final claim matrix\n\n" + tier10Metadata + `
## The matrix

| ID | Claim | Status after Tier 9 | Status after Tier 10 | Controls | Evidence | Open ledger rows | Gap |
| --- | --- | --- | --- | --- | --- | --- | --- |
| SC-01 | firmware | partly_supported | partly_supported | CTL-03 | tier-03/hostile-image (board) | T3-W-10 | bootloader |
| SC-02 | install | partly_supported | partly_supported | CTL-05 | tier-04/replay-release (board) | T4-W-13 | USB flash |
| SC-03 | channel | supported | supported | CTL-01 | tier-02/name-mismatch (host); tier-04/hostile-release (board) |  |  |
| SC-04 | status | partly_supported | partly_supported | CTL-11 | e-7-03 (host) | T8-W-31 | host result only |
| SC-05 | recovery | partly_supported | partly_supported | CTL-07 | scenario Event 7 | T5-W-14 | power cut |
| SC-06 | keys | partly_supported | partly_supported | CTL-09 | e-6-07 (host) | T6-W-16 | host result only |
| SC-07 | identity | partly_supported | partly_supported | CTL-12 | e-7-09 (host) | T7-W-21 | host result only |
| SC-08 | lifecycle | partly_supported | partly_supported | CTL-15 | e-8-07 (host) | T8-W-31 | host result only |
| SC-09 | release | partly_supported | partly_supported | CTL-17 | tier-09/support-listener (board) | T10-W-39 | manual step |
`

const tier10Risk = "# Residual-risk summary\n\n" + tier10Metadata + `
## The residual risks

| ID | Residual risk | Group | Owner | Treatment or acceptance | Revisit |
| --- | --- | --- | --- | --- | --- |
| T3-W-10 | The bootloader itself is unverified | Advanced Tier A | Release engineer | Secure Boot, ledger T3-W-10 | Advanced Tier A |
| T6-W-19 | The nonce is drawn once per boot | Accepted for the core course | Firmware lead | Accepted, ledger T6-W-19 | Any Zephyr upgrade |
| T10-W-40 | rollout advance checks no canary | Recorded limit | Operator | Manual check, ledger T10-W-40 | Next service change |
`

func tier10RecordWith(t *testing.T, name, body string) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	problems, err := checkTierEvidenceRecord("10", path)
	if err != nil {
		t.Fatal(err)
	}
	return problems
}

func expectOneProblem(t *testing.T, problems []string, wants ...string) {
	t.Helper()
	if len(problems) != 1 {
		t.Fatalf("expected one problem containing %q, got %v", wants, problems)
	}
	for _, want := range wants {
		if !strings.Contains(problems[0], want) {
			t.Fatalf("expected the problem to contain %q, got %q", want, problems[0])
		}
	}
}

func TestCompleteTier10RecordsHaveNoProblems(t *testing.T) {
	for name, body := range map[string]string{
		incidentRecordFile:      tier10Incident,
		finalClaimMatrixFile:    tier10Matrix,
		residualRiskSummaryFile: tier10Risk,
	} {
		if problems := tier10RecordWith(t, name, body); len(problems) != 0 {
			t.Fatalf("%s: expected no problems, got %v", name, problems)
		}
	}
}

// Tier 10 records are not CRA records, so the Tier 9 boundary line is not
// required, and a record without it is complete.
func TestTier10RecordsNeedNoCRABoundaryLine(t *testing.T) {
	if strings.Contains(tier10Incident, craBoundaryLine) {
		t.Fatal("the fixture should not carry the Tier 9 boundary line")
	}
	if problems := tier10RecordWith(t, incidentRecordFile, tier10Incident); len(problems) != 0 {
		t.Fatalf("expected no problems, got %v", problems)
	}
}

// Rule (a). The clock source is exact, like `observed`: "Host" and "serial"
// are not one of the three clocks, and an empty cell has not named one.
func TestTier10TimelineRowNeedsOneOfThreeClocks(t *testing.T) {
	for _, source := range []string{"", "Host", "serial", "board", "host clock"} {
		body := strings.Replace(tier10Incident, "| 2 |  | none |", "| 2 |  | "+source+" |", 1)
		problems := tier10RecordWith(t, incidentRecordFile, body)
		expectOneProblem(t, problems, `timeline row "2"`, "clock source")
	}
}

// The first pass carries a First observed time, so its clock source is held
// to the same three words.
func TestTier10FirstPassRowNeedsOneOfThreeClocks(t *testing.T) {
	body := strings.Replace(tier10Incident, "| Event 7 | 10:25:00 | none |", "| Event 7 | 10:25:00 | board |", 1)
	expectOneProblem(t, tier10RecordWith(t, incidentRecordFile, body), "Event 7", "clock source")
}

// A row with nothing in it says nothing, and a Learner who leaves a spare
// blank row has not broken the timeline.
func TestTier10BlankTimelineRowIsSkipped(t *testing.T) {
	body := strings.Replace(tier10Incident, "\n## Events: first pass", "|  |  |  |  |  |  |  |  |\n\n## Events: first pass", 1)
	if problems := tier10RecordWith(t, incidentRecordFile, body); len(problems) != 0 {
		t.Fatalf("expected no problems, got %v", problems)
	}
}

func TestTier10IncidentRecordWithoutTimelineIsReported(t *testing.T) {
	start := strings.Index(tier10Incident, "## Timeline")
	end := strings.Index(tier10Incident, "## Events: first pass")
	body := tier10Incident[:start] + tier10Incident[end:]
	expectOneProblem(t, tier10RecordWith(t, incidentRecordFile, body), "no timeline table")
}

// Rule (b). Every one of the eight events has a row.
func TestTier10FirstPassMissingEventIsReported(t *testing.T) {
	body := strings.Replace(tier10Incident, "| Event 5 | 10:15:00 | service | zero served | undetermined | none | none |\n", "", 1)
	expectOneProblem(t, tier10RecordWith(t, incidentRecordFile, body), "Event 5 has no row")
}

// The classification is one of three exact words. "failure" alone, a
// capitalized word and a hedge have not answered the question the column asks.
func TestTier10FirstClassificationMustBeOneOfThree(t *testing.T) {
	for _, class := range []string{"", "failure", "Attack", "attack?", "probably attack"} {
		body := strings.Replace(tier10Incident, "| Event 6 | 10:18:00 | service | resumed | operational failure |", "| Event 6 | 10:18:00 | service | resumed | "+class+" |", 1)
		expectOneProblem(t, tier10RecordWith(t, incidentRecordFile, body), "Event 6", "first classification")
	}
}

func TestTier10FirstPassRowThatIsNotAnEventIsReported(t *testing.T) {
	for _, row := range []string{"| Event 9 | 10:30:00 | host | x | attack | none | none |\n", "| Step 1 | 10:30:00 | host | x | attack | none | none |\n"} {
		body := strings.Replace(tier10Incident, "| Event 8 |", row+"| Event 8 |", 1)
		expectOneProblem(t, tier10RecordWith(t, incidentRecordFile, body), "first pass")
	}
}

func TestTier10IncidentRecordWithoutFirstPassIsReported(t *testing.T) {
	body := tier10Incident[:strings.Index(tier10Incident, "## Events: first pass")]
	expectOneProblem(t, tier10RecordWith(t, incidentRecordFile, body), "no first-pass table")
	if problems := tier10RecordWith(t, "recovery-record.md", body); len(problems) != 0 {
		t.Fatalf("a record that is not the incident record needs no first pass, got %v", problems)
	}
}

// Rule (c). All nine claims, and no tenth.
func TestTier10ClaimMatrixMissingClaimIsReported(t *testing.T) {
	body := strings.Replace(tier10Matrix, "| SC-05 | recovery | partly_supported | partly_supported | CTL-07 | scenario Event 7 | T5-W-14 | power cut |\n", "", 1)
	expectOneProblem(t, tier10RecordWith(t, finalClaimMatrixFile, body), "SC-05 has no row")
}

func TestTier10ClaimMatrixAddsNoClaim(t *testing.T) {
	body := strings.Replace(tier10Matrix, "| SC-09 |", "| SC-10 | new | (new) | partly_supported |  |  |  |  |\n| SC-09 |", 1)
	expectOneProblem(t, tier10RecordWith(t, finalClaimMatrixFile, body), "SC-10", "adds no claim")
}

func TestTier10ClaimStatusMustBeOneOfFour(t *testing.T) {
	for _, status := range []string{"", "partly supported", "Supported", "verified"} {
		body := strings.Replace(tier10Matrix, "| SC-02 | install | partly_supported | partly_supported |", "| SC-02 | install | partly_supported | "+status+" |", 1)
		expectOneProblem(t, tier10RecordWith(t, finalClaimMatrixFile, body), "SC-02", "status after Tier 10")
	}
}

// A host result never stands in for a board result: a claim supported on
// host results alone is reported, and the same evidence at partly_supported
// passes.
func TestTier10SupportedClaimNeedsBoardEvidence(t *testing.T) {
	for _, evidence := range []string{"tier-02/name-mismatch (host)", "", "board result in my notes"} {
		body := strings.Replace(tier10Matrix, "| tier-02/name-mismatch (host); tier-04/hostile-release (board) |", "| "+evidence+" |", 1)
		expectOneProblem(t, tier10RecordWith(t, finalClaimMatrixFile, body), "SC-03", "(board)")
	}
	body := strings.Replace(tier10Matrix, "| supported | supported | CTL-01 | tier-02/name-mismatch (host); tier-04/hostile-release (board) |", "| supported | partly_supported | CTL-01 | tier-02/name-mismatch (host) |", 1)
	if problems := tier10RecordWith(t, finalClaimMatrixFile, body); len(problems) != 0 {
		t.Fatalf("a partly supported claim may rest on host results, got %v", problems)
	}
}

func TestTier10ClaimMatrixWithoutItsTableIsReported(t *testing.T) {
	body := tier10Matrix[:strings.Index(tier10Matrix, "## The matrix")]
	expectOneProblem(t, tier10RecordWith(t, finalClaimMatrixFile, body), "no table with a Status after Tier 10 column")
}

// Rule (d). Every row has one of the four groups and an owner.
func TestTier10ResidualRiskGroupMustBeOneOfFour(t *testing.T) {
	for _, group := range []string{"", "advanced tier a", "Residual risk with an owner", "Recheck on any Zephyr upgrade", "Accepted"} {
		body := strings.Replace(tier10Risk, "| Accepted for the core course | Firmware lead |", "| "+group+" | Firmware lead |", 1)
		expectOneProblem(t, tier10RecordWith(t, residualRiskSummaryFile, body), "T6-W-19", "group")
	}
}

func TestTier10ResidualRiskNeedsAnOwner(t *testing.T) {
	body := strings.Replace(tier10Risk, "| Recorded limit | Operator |", "| Recorded limit |  |", 1)
	expectOneProblem(t, tier10RecordWith(t, residualRiskSummaryFile, body), "T10-W-40 has no owner")
}

func TestTier10ResidualRiskSummaryWithoutItsTableIsReported(t *testing.T) {
	body := tier10Risk[:strings.Index(tier10Risk, "## The residual risks")]
	expectOneProblem(t, tier10RecordWith(t, residualRiskSummaryFile, body), "no table with Group and Owner")
}

// The Tier 10 rules belong to Tier 10. The same records checked as another
// tier get only the four checks, which they pass, even with a broken row.
func TestTier10RulesDoNotReachOtherTiers(t *testing.T) {
	broken := strings.Replace(tier10Risk, "| Recorded limit | Operator |", "| Recorded limit |  |", 1)
	path := filepath.Join(t.TempDir(), residualRiskSummaryFile)
	if err := os.WriteFile(path, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tier := range []string{"", "01", "08"} {
		problems, err := checkTierEvidenceRecord(tier, path)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) != 0 {
			t.Fatalf("tier %q: expected no problems, got %v", tier, problems)
		}
	}
}

// Every published Tier 10 template carries the metadata table and the tables
// its rules need, so a Learner who copies them starts from a record the check
// can read. The judgment cells ship empty on purpose, and the check must say
// so: the template is not a finished record.
func TestPublishedTier10TemplatesCarryTheirTables(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "evidence", "templates", "tier-10", "*.md"))
	if err != nil || len(matches) != 5 {
		t.Fatalf("expected five Tier 10 templates, found %v (%v)", matches, err)
	}
	rules := tierRecordRules["10"]
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(path)
		lines := readLines(string(data))
		if problems := checkMetadata(lines); len(problems) != 0 {
			t.Errorf("%s: %v", path, problems)
		}
		var problems []string
		for _, rule := range rules {
			problems = append(problems, rule(name, lines)...)
		}
		for _, problem := range problems {
			if strings.Contains(problem, "no table") || strings.Contains(problem, "no timeline table") ||
				strings.Contains(problem, "no first-pass table") || strings.Contains(problem, "has no row") ||
				strings.Contains(problem, "adds no claim") || strings.Contains(problem, "not \"") {
				t.Errorf("%s: a structural problem in the template itself: %s", path, problem)
			}
		}
		switch name {
		case incidentRecordFile, finalClaimMatrixFile, residualRiskSummaryFile:
			if len(problems) == 0 {
				t.Errorf("%s: the empty judgment cells were not reported", path)
			}
		default:
			if len(problems) != 0 {
				t.Errorf("%s: %v", path, problems)
			}
		}
	}
}

// The templates pre-fill what the course knows and leave every judgment to the
// Learner (#289 point 4): the nine claims with their status after Tier 9, and
// the 29 open ledger rows with their text.
func TestPublishedTier10TemplatesPreFillClaimsAndOpenRows(t *testing.T) {
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join("..", "..", "evidence", "templates", "tier-10", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	matrix := readLines(read(finalClaimMatrixFile))
	claims := 0
	tableRows(matrix, func(cells []string) bool { return columnOf(cells, "status after tier 10") >= 0 }, func(header, row []string) {
		claims++
		if cellOf(header, row, "claim") == "" || cellOf(header, row, "status after tier 9") == "" {
			t.Errorf("%s is not pre-filled with its text and status after Tier 9", row[0])
		}
		for _, column := range []string{"status after tier 10", "controls", "evidence", "open ledger rows", "gap"} {
			if cellOf(header, row, column) != "" {
				t.Errorf("%s: %s is the Learner's judgment and must ship empty", row[0], column)
			}
		}
	})
	if claims != finalClaims {
		t.Errorf("expected %d claim rows, got %d", finalClaims, claims)
	}

	summary := readLines(read(residualRiskSummaryFile))
	rows := map[string]bool{}
	tableRows(summary, func(cells []string) bool { return columnOf(cells, "group") >= 0 && columnOf(cells, "owner") >= 0 }, func(header, row []string) {
		rows[row[0]] = true
		if cellOf(header, row, "residual risk") == "" {
			t.Errorf("%s has no text", row[0])
		}
		for _, column := range []string{"group", "owner", "treatment or acceptance", "revisit"} {
			if cellOf(header, row, column) != "" {
				t.Errorf("%s: %s is the Learner's judgment and must ship empty", row[0], column)
			}
		}
	})
	if len(rows) != 29 {
		t.Errorf("expected 29 open ledger rows, got %d", len(rows))
	}
	for _, id := range []string{"T10-W-39", "T10-W-40", "T9-W-36", "T9-W-37", "T2-W-09"} {
		if !rows[id] {
			t.Errorf("%s is missing from the residual-risk summary", id)
		}
	}
	for _, closed := range []string{"T9-W-34", "T10-W-38"} {
		if rows[closed] {
			t.Errorf("%s is closed and must not be a residual risk", closed)
		}
	}
}
