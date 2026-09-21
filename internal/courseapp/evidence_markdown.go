package courseapp

// Tier 0 records observations a machine can check, so `evidence check` reads
// its four JSON files against a schema. Every tier after it records reasoning
// for a Mentor to read, in Markdown, and there is no schema that could say
// whether a threat model is right.
//
// What a machine can still say about a Markdown record is structural, and it
// is worth saying, because the failures it catches are the ones a Learner
// makes while concentrating on something else: a template that was never
// copied, a placeholder left standing, a row marked `observed` by someone who
// meant to come back to it. None of those need judgement, all of them make the
// pack untrue, and a Mentor should not be spending gate time on them.
//
// The check never reads what the Learner wrote. It reports that a field is
// empty, never that its contents are wrong.

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// metadataFields are the rows every template's metadata table carries. They are
// checked by name rather than by position, because a Learner who adds a row of
// their own has not broken anything.
var metadataFields = []string{
	"artifact_id",
	"artifact_type",
	"owner",
	"scope",
	"revision",
	"status",
	"created_at",
	"source_revision",
	"environment",
	"limitations",
}

// placeholders are the literal strings the templates ship with. `reviewer` and
// the Mentor review fields are deliberately absent: "(empty until a Mentor
// reviews it)" is the correct value right up until a Mentor reviews it, so
// flagging it would teach the Learner to fill in a field that is not theirs.
var placeholders = []string{
	"<your initials>",
	"(date)",
	"(output of `git rev-parse --short HEAD`)",
}

var tableRowPattern = regexp.MustCompile(`^\s*\|(.*)\|\s*$`)

// evidenceTierPattern is the tier argument's shape: two digits, as every path
// and manifest key in this repository spells a tier.
var evidenceTierPattern = regexp.MustCompile(`^[0-9]{2}$`)

// checkLearnerMarkdownEvidence reports the structural problems in one tier's
// Learner evidence directory. It returns an error only when it could not look,
// not when it found something: a Learner mid-tier is expected to have problems,
// and the command's job is to list them.
func (a *app) checkLearnerMarkdownEvidence(tier string) error {
	if !evidenceTierPattern.MatchString(tier) {
		return fmt.Errorf("tier must be two digits, such as 04, not %q", tier)
	}
	if tier == "00" {
		return errors.New("Tier 0 records are JSON; run `./course evidence check` with no --tier")
	}

	templateDir := filepath.Join(a.root, "evidence", "templates", "tier-"+tier)
	templates, err := filepath.Glob(filepath.Join(templateDir, "*.md"))
	if err != nil || len(templates) == 0 {
		return fmt.Errorf("no templates exist for tier %s", tier)
	}
	sort.Strings(templates)

	learnerDir := filepath.Join(a.root, a.manifest.Paths.LearnerEvidence, "tier-"+tier)
	if info, err := os.Stat(learnerDir); err != nil || !info.IsDir() {
		return fmt.Errorf("%s does not exist; copy the templates into it first, as the tier's Update the Security evidence pack section says",
			filepath.ToSlash(filepath.Join(a.manifest.Paths.LearnerEvidence, "tier-"+tier)))
	}

	fmt.Fprintf(a.out, "checked %s\n", filepath.ToSlash(filepath.Join(a.manifest.Paths.LearnerEvidence, "tier-"+tier)))

	total := 0
	for _, template := range templates {
		name := filepath.Base(template)
		path := filepath.Join(learnerDir, name)
		problems, err := checkEvidenceRecord(path)
		if err != nil {
			return err
		}
		total += len(problems)
		if len(problems) == 0 {
			fmt.Fprintf(a.out, "  %-34s ok\n", name)
			continue
		}
		fmt.Fprintf(a.out, "  %-34s %s\n", name, countProblems(len(problems)))
		for _, problem := range problems {
			fmt.Fprintf(a.out, "    %s\n", problem)
		}
	}

	if total == 0 {
		fmt.Fprintf(a.out, "Result: Tier %s records are structurally complete. What they say is for your Mentor to read.\n", tier)
		return nil
	}
	return fmt.Errorf("%s in the Tier %s evidence pack", countProblems(total), tier)
}

func countProblems(n int) string {
	if n == 1 {
		return "1 problem"
	}
	return fmt.Sprintf("%d problems", n)
}

// checkEvidenceRecord runs the four structural checks over one copied template.
func checkEvidenceRecord(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{"not copied from evidence/templates yet"}, nil
		}
		return nil, err
	}
	lines := readLines(string(data))

	problems := append([]string{}, checkMetadata(lines)...)
	problems = append(problems, checkPlaceholders(lines)...)
	problems = append(problems, checkObservedRows(lines)...)
	return problems, nil
}

func readLines(text string) []string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

// splitRow returns the cells of a Markdown table row, or nil when the line is
// not one. A separator row such as `| --- | --- |` is not a row.
func splitRow(line string) []string {
	match := tableRowPattern.FindStringSubmatch(line)
	if match == nil {
		return nil
	}
	cells := strings.Split(match[1], "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	separator := true
	for _, cell := range cells {
		if strings.Trim(cell, "-: ") != "" {
			separator = false
			break
		}
	}
	if separator {
		return nil
	}
	return cells
}

func checkMetadata(lines []string) []string {
	present := map[string]bool{}
	values := map[string]string{}
	for _, line := range lines {
		cells := splitRow(line)
		if len(cells) != 2 {
			continue
		}
		field := strings.ToLower(cells[0])
		present[field] = true
		if _, seen := values[field]; !seen {
			values[field] = cells[1]
		}
	}

	var problems []string
	for _, field := range metadataFields {
		if !present[field] {
			problems = append(problems, fmt.Sprintf("the metadata table has no %s row", field))
			continue
		}
		if values[field] == "" {
			problems = append(problems, fmt.Sprintf("%s is empty", field))
		}
	}
	return problems
}

func checkPlaceholders(lines []string) []string {
	var problems []string
	for _, placeholder := range placeholders {
		for _, line := range lines {
			if !strings.Contains(line, placeholder) {
				continue
			}
			if cells := splitRow(line); len(cells) == 2 {
				problems = append(problems, fmt.Sprintf("%s still reads %q", cells[0], placeholder))
			} else {
				problems = append(problems, fmt.Sprintf("a placeholder is still standing: %q", placeholder))
			}
			break
		}
	}
	return problems
}

// checkObservedRows finds every row that claims to be `observed` and reports
// the ones with nothing recorded under them. Two shapes carry record state: a
// results table with a `Record state` column, and a field-and-value block with
// a `Record state` field. Both appear in the published templates.
func checkObservedRows(lines []string) []string {
	var problems []string
	var header []string

	for _, line := range lines {
		cells := splitRow(line)
		if cells == nil {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				header = nil
			}
			continue
		}

		if columnOf(cells, "record state") >= 0 && columnOf(cells, "evidence id") >= 0 {
			header = cells
			continue
		}

		if len(cells) == 2 && strings.EqualFold(cells[0], "Record state") {
			if isObserved(cells[1]) {
				problems = append(problems, "a record is marked observed; check the fields above it are filled in")
			}
			continue
		}

		if header == nil {
			continue
		}
		stateAt := columnOf(header, "record state")
		actualAt := columnOf(header, "actual result")
		if stateAt < 0 || actualAt < 0 || stateAt >= len(cells) || actualAt >= len(cells) {
			continue
		}
		if !isObserved(cells[stateAt]) || cells[actualAt] != "" {
			continue
		}
		identifier := cells[0]
		if identifier == "" {
			identifier = "a row"
		}
		problems = append(problems, fmt.Sprintf("%s is marked observed with no observation recorded", identifier))
	}
	return problems
}

// isObserved is deliberately exact. The templates ship rows reading `pending`
// and `not an observation`, and Tier 4's `E-4-07` must never move, so a cell
// merely containing the word is not a claim that something was watched.
func isObserved(cell string) bool {
	return strings.EqualFold(strings.TrimSpace(cell), "observed")
}

func columnOf(cells []string, name string) int {
	for i, cell := range cells {
		if strings.EqualFold(cell, name) {
			return i
		}
	}
	return -1
}
