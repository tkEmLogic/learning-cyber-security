package courseapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// completeRecord is the shape a Learner's copy takes once they have filled it
// in: metadata answered, one row watched and written down, one row still
// pending, and the row that never moves.
const completeRecord = `# Refusal observations

| Field | Value |
| --- | --- |
| artifact_id | T4-REFUSE-TK |
| artifact_type | verification-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-04 |
| revision | 1 |
| status | draft |
| created_at | 2026-09-21 |
| last_reviewed_at |  |
| source_revision | aa6d5cf |
| environment | course_id learning-cyber-security, tier 04 |
| limitations | Every refusal row is a device result. |

## Results

| Evidence ID | Test | Expected result | Check that refused it | Actual result | Observed on | Record state |
| --- | --- | --- | --- | --- | --- | --- |
| E-4-01 | Publish ` + "`modified`" + ` | Refused | manifest-signature | refused as expected | device | observed |
| E-4-02 | Publish ` + "`hardware`" + ` | Refused |  |  | device | pending |
| E-4-07 | Take the signing key | Everything is defeated |  |  | reasoning | not an observation |
`

func recordWith(t *testing.T, body string) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "record.md")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	problems, err := checkEvidenceRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	return problems
}

func TestCompleteRecordHasNoProblems(t *testing.T) {
	if problems := recordWith(t, completeRecord); len(problems) != 0 {
		t.Fatalf("expected no problems, got %v", problems)
	}
}

// The reviewer field ships with a placeholder that is the correct value until a
// Mentor reviews the record. Flagging it would teach a Learner to fill in a
// field that is not theirs to fill.
func TestReviewerPlaceholderIsNotAProblem(t *testing.T) {
	for _, problem := range recordWith(t, completeRecord) {
		if strings.Contains(problem, "reviewer") {
			t.Fatalf("reviewer placeholder was reported: %s", problem)
		}
	}
}

func TestObservedRowWithoutObservationIsReported(t *testing.T) {
	body := strings.Replace(completeRecord,
		"| E-4-02 | Publish `hardware` | Refused |  |  | device | pending |",
		"| E-4-02 | Publish `hardware` | Refused |  |  | device | observed |", 1)
	problems := recordWith(t, body)
	if len(problems) != 1 || !strings.Contains(problems[0], "E-4-02") {
		t.Fatalf("expected E-4-02 to be reported, got %v", problems)
	}
}

// `not an observation` contains neither the word nor the intent. Tier 4's
// E-4-07 must never be treated as watched.
func TestRowThatNeverMovesIsNotObserved(t *testing.T) {
	for _, problem := range recordWith(t, completeRecord) {
		if strings.Contains(problem, "E-4-07") {
			t.Fatalf("E-4-07 was treated as an observation: %s", problem)
		}
	}
}

func TestPlaceholdersAreReported(t *testing.T) {
	body := strings.Replace(completeRecord, "| source_revision | aa6d5cf |",
		"| source_revision | (output of `git rev-parse --short HEAD`) |", 1)
	problems := recordWith(t, body)
	if len(problems) != 1 || !strings.Contains(problems[0], "source_revision") {
		t.Fatalf("expected source_revision to be reported, got %v", problems)
	}
}

func TestMissingMetadataFieldIsReported(t *testing.T) {
	body := strings.Replace(completeRecord, "| scope | tier-04 |\n", "", 1)
	problems := recordWith(t, body)
	if len(problems) != 1 || !strings.Contains(problems[0], "scope") {
		t.Fatalf("expected scope to be reported, got %v", problems)
	}
}

func TestEmptyMetadataValueIsReported(t *testing.T) {
	body := strings.Replace(completeRecord, "| status | draft |", "| status |  |", 1)
	problems := recordWith(t, body)
	if len(problems) != 1 || !strings.Contains(problems[0], "status is empty") {
		t.Fatalf("expected status to be reported, got %v", problems)
	}
}

func TestUncopiedTemplateIsReported(t *testing.T) {
	problems, err := checkEvidenceRecord(filepath.Join(t.TempDir(), "absent.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "not copied") {
		t.Fatalf("expected an uncopied report, got %v", problems)
	}
}

func TestSeparatorRowIsNotACell(t *testing.T) {
	if cells := splitRow("| --- | --- |"); cells != nil {
		t.Fatalf("separator parsed as a row: %v", cells)
	}
	if cells := splitRow("| :--- | ---: |"); cells != nil {
		t.Fatalf("aligned separator parsed as a row: %v", cells)
	}
	if cells := splitRow("| artifact_id | T4-REFUSE-TK |"); len(cells) != 2 {
		t.Fatalf("expected two cells, got %v", cells)
	}
	if cells := splitRow("not a table row"); cells != nil {
		t.Fatalf("prose parsed as a row: %v", cells)
	}
}

// Every published template must pass the metadata and placeholder checks once
// its placeholders are answered, or the check is testing a shape the course
// does not ship.
func TestPublishedTemplatesCarryTheMetadataTable(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "evidence", "templates", "tier-0[1-7]", "*.md"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no templates found: %v", err)
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if problems := checkMetadata(readLines(string(data))); len(problems) != 0 {
			t.Errorf("%s: %v", path, problems)
		}
	}
}
