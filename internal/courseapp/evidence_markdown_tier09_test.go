package courseapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tier09Record is a filled-in Tier 9 record: the four structural checks pass,
// the boundary line stands in its own paragraph, and every matrix row names a
// dated legal source and a legal-review answer.
const tier09Record = `# CRA traceability matrix

This is course evidence. It does not show CRA conformity, and it is not a legal determination.

| Field | Value |
| --- | --- |
| artifact_id | T9-CRA-MATRIX-TK |
| artifact_type | traceability-matrix |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-09 |
| revision | 1 |
| status | draft |
| created_at | 2026-10-01 |
| last_reviewed_at |  |
| source_revision | ebd7560 |
| environment | course_id learning-cyber-security, tier 09, synthetic_data true |
| limitations | One row per CRA duty for a fictional manufacturer. |

## The matrix

| CRA duty | Evidence | Status | Legal source | Accessed | Legal review |
| --- | --- | --- | --- | --- | --- |
| Article 13(8): Support period | support-statement.md | partly_supported | Regulation (EU) 2024/2847, Article 13(8) | 2026-09-30 | yes |
| Article 14: reporting | both reporting records | partly_supported | Regulation (EU) 2024/2847, Article 14 | 2026-09-30 | no |
`

func tier09RecordWith(t *testing.T, name, body string) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	problems, err := checkTierEvidenceRecord("09", path)
	if err != nil {
		t.Fatal(err)
	}
	return problems
}

func TestCompleteTier09RecordHasNoProblems(t *testing.T) {
	if problems := tier09RecordWith(t, traceabilityMatrixFile, tier09Record); len(problems) != 0 {
		t.Fatalf("expected no problems, got %v", problems)
	}
}

func TestTier09RecordWithoutBoundaryLineIsReported(t *testing.T) {
	body := strings.Replace(tier09Record, craBoundaryLine+"\n", "", 1)
	problems := tier09RecordWith(t, traceabilityMatrixFile, body)
	if len(problems) != 1 || !strings.Contains(problems[0], "boundary line") {
		t.Fatalf("expected the boundary line to be reported, got %v", problems)
	}
}

// A reworded boundary line is not the boundary line. The wording was settled
// once, and a softer paraphrase is exactly the drift the rule exists to catch.
func TestTier09RewordedBoundaryLineIsReported(t *testing.T) {
	body := strings.Replace(tier09Record, "It does not show CRA conformity", "It may not show CRA conformity", 1)
	problems := tier09RecordWith(t, traceabilityMatrixFile, body)
	if len(problems) != 1 || !strings.Contains(problems[0], "boundary line") {
		t.Fatalf("expected the reworded line to be reported, got %v", problems)
	}
}

// The line must be a paragraph of its own. Buried inside another sentence it
// no longer reads as the boundary of the whole record.
func TestTier09BoundaryLineInsideAParagraphIsReported(t *testing.T) {
	body := strings.Replace(tier09Record, craBoundaryLine, "Read this first. "+craBoundaryLine, 1)
	problems := tier09RecordWith(t, traceabilityMatrixFile, body)
	if len(problems) != 1 || !strings.Contains(problems[0], "boundary line") {
		t.Fatalf("expected the buried line to be reported, got %v", problems)
	}
}

func TestTraceabilityRowWithoutLegalSourceIsReported(t *testing.T) {
	body := strings.Replace(tier09Record, "| Regulation (EU) 2024/2847, Article 14 |", "|  |", 1)
	problems := tier09RecordWith(t, traceabilityMatrixFile, body)
	if len(problems) != 1 || !strings.Contains(problems[0], "Article 14: reporting has no legal source") {
		t.Fatalf("expected the Article 14 row to be reported, got %v", problems)
	}
}

func TestTraceabilityRowWithoutAccessDateIsReported(t *testing.T) {
	for _, accessed := range []string{"", "September 2026", "30.09.2026"} {
		body := strings.Replace(tier09Record, "| 2026-09-30 | yes |", "| "+accessed+" | yes |", 1)
		problems := tier09RecordWith(t, traceabilityMatrixFile, body)
		if len(problems) != 1 || !strings.Contains(problems[0], "Article 13(8): Support period has no access date") {
			t.Fatalf("accessed %q: expected the Article 13(8) row to be reported, got %v", accessed, problems)
		}
	}
}

// The legal-review cell is exact, like `observed`. "Yes", "maybe" and a
// qualified answer have not answered the question the column asks.
func TestTraceabilityLegalReviewMustReadYesOrNo(t *testing.T) {
	for _, review := range []string{"", "Yes", "maybe", "yes, for Norway"} {
		body := strings.Replace(tier09Record, "| 2026-09-30 | no |", "| 2026-09-30 | "+review+" |", 1)
		problems := tier09RecordWith(t, traceabilityMatrixFile, body)
		if len(problems) != 1 || !strings.Contains(problems[0], "Article 14: reporting") || !strings.Contains(problems[0], "legal review") {
			t.Fatalf("review %q: expected the Article 14 row to be reported, got %v", review, problems)
		}
	}
}

func TestTraceabilityMatrixWithoutItsTableIsReported(t *testing.T) {
	body := tier09Record[:strings.Index(tier09Record, "## The matrix")]
	problems := tier09RecordWith(t, traceabilityMatrixFile, body)
	if len(problems) != 1 || !strings.Contains(problems[0], "no table with Legal source and Legal review") {
		t.Fatalf("expected the missing table to be reported, got %v", problems)
	}
	if problems := tier09RecordWith(t, "support-statement.md", body); len(problems) != 0 {
		t.Fatalf("a record that is not the matrix needs no matrix table, got %v", problems)
	}
}

// The Tier 9 rules belong to Tier 9. A record from another tier, which never
// mentions the CRA, gets the same four checks it always got, and nothing else,
// even when its file happens to share the matrix's name.
func TestTier09RulesDoNotReachOtherTiers(t *testing.T) {
	path := filepath.Join(t.TempDir(), traceabilityMatrixFile)
	if err := os.WriteFile(path, []byte(completeRecord), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tier := range []string{"", "01", "04", "08"} {
		problems, err := checkTierEvidenceRecord(tier, path)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) != 0 {
			t.Fatalf("tier %q: expected no problems, got %v", tier, problems)
		}
	}
}

// Every published Tier 9 template carries the metadata table and the boundary
// line, and the matrix template ships with its table, so a Learner who copies
// them starts from a record the check can read. The matrix rows ship empty on
// purpose: filling them is the Learner's work, and the check must say so.
func TestPublishedTier09TemplatesCarryTheBoundaryLine(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "evidence", "templates", "tier-09", "*.md"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no Tier 9 templates found: %v", err)
	}
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
		if problems := checkBoundaryLine(name, lines); len(problems) != 0 {
			t.Errorf("%s: %v", path, problems)
		}
		problems := checkTraceabilityRows(name, lines)
		if name != traceabilityMatrixFile {
			if len(problems) != 0 {
				t.Errorf("%s: %v", path, problems)
			}
			continue
		}
		if len(problems) == 0 {
			t.Errorf("%s: the empty matrix rows were not reported", path)
		}
		for _, problem := range problems {
			if strings.Contains(problem, "no table") {
				t.Errorf("%s: %s", path, problem)
			}
		}
	}
}
