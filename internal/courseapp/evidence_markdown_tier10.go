package courseapp

// Tier 10's record rules (#289, point 8). Like Tier 9's, each one reads the
// shape of a table and never what the Learner concluded: a clock source is
// one of three words, a classification is one of three words, a claim status
// is one of four, and a residual-risk group is one of four. Whether the word
// is the right one is for the Mentor.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The files that must hold each table. The row rules apply to any table with
// the right columns, but only these files are required to have one, so a
// deleted table is reported rather than passing silently.
const (
	incidentRecordFile      = "incident-record.md"
	finalClaimMatrixFile    = "final-claim-matrix.md"
	residualRiskSummaryFile = "residual-risk-summary.md"
)

// tableRows walks every table whose header row satisfies isHeader and calls
// visit for each body row, with the header it sits under. It reports whether
// any such table was found. A heading ends a table, as in the other rules.
func tableRows(lines []string, isHeader func([]string) bool, visit func(header, row []string)) bool {
	var header []string
	found := false
	for _, line := range lines {
		cells := splitRow(line)
		if cells == nil {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				header = nil
			}
			continue
		}
		if isHeader(cells) {
			header = cells
			found = true
			continue
		}
		if header != nil {
			visit(header, cells)
		}
	}
	return found
}

// cellOf returns a row's cell under the named column, or "" when the column or
// the cell is missing.
func cellOf(header, row []string, column string) string {
	at := columnOf(header, column)
	if at < 0 || at >= len(row) {
		return ""
	}
	return row[at]
}

func rowIsBlank(row []string) bool {
	for _, cell := range row {
		if cell != "" {
			return false
		}
	}
	return true
}

// rowName is how a problem names a row: its first cell, or failing that the
// fallback.
func rowName(row []string, fallback string) string {
	if len(row) > 0 && row[0] != "" {
		return row[0]
	}
	return fallback
}

// clockSources are the three clocks a Tier 10 time can come from. `none` is a
// real answer: the board console prints no time.
var clockSources = map[string]bool{"host": true, "service": true, "none": true}

// checkClockSources is rule (a): every row of a table with a Clock source
// column names one of the three clocks. That is the timeline, and the
// first-pass table, whose First observed time needs a clock just as much. A
// row with nothing in it says nothing, so it is skipped.
func checkClockSources(name string, lines []string) []string {
	var problems []string
	isTimeline := func(cells []string) bool {
		return columnOf(cells, "clock source") >= 0 && columnOf(cells, "what happened") >= 0
	}
	hasClock := func(cells []string) bool { return columnOf(cells, "clock source") >= 0 }

	// The timeline must exist even before it has a row, so look for its
	// header first, then check the rows of every table with a clock.
	found := tableRows(lines, isTimeline, func(_, _ []string) {})
	tableRows(lines, hasClock, func(header, row []string) {
		if rowIsBlank(row) {
			return
		}
		identifier := rowName(row, "a row")
		switch {
		case isTimeline(header):
			identifier = "timeline row " + strconv.Quote(rowLabel(header, row))
		case columnOf(header, "first classification") >= 0:
			identifier = "first pass: " + identifier
		}
		switch source := cellOf(header, row, "clock source"); {
		case source == "":
			problems = append(problems, fmt.Sprintf("%s has no clock source; write host, service or none", identifier))
		case !clockSources[source]:
			problems = append(problems, fmt.Sprintf("%s: clock source must read host, service or none, not %q", identifier, source))
		}
	})

	if !found && name == incidentRecordFile {
		problems = append(problems, "the incident record has no timeline table with Clock source and What happened columns")
	}
	return problems
}

// rowLabel names a timeline row by its number when it has one, and otherwise
// by what happened, which is the cell a Learner recognizes.
func rowLabel(header, row []string) string {
	if number := cellOf(header, row, "row"); number != "" {
		return number
	}
	return cellOf(header, row, "what happened")
}

// firstClassifications are the three first-sight answers. `undetermined` is
// allowed on purpose: a Learner who cannot yet tell should say so.
var firstClassifications = map[string]bool{"attack": true, "operational failure": true, "undetermined": true}

// scenarioEvents is how many events the integration scenario stages (#288).
const scenarioEvents = 8

var eventRowPattern = regexp.MustCompile(`^Event ([0-9]+)\b`)

// checkFirstPass is rule (b): the first-pass table has a row for each of
// Event 1 to Event 8, and each row's first classification is one of the three
// words. The rule cannot tell when a row was written; the template and the
// Mentor carry that.
func checkFirstPass(name string, lines []string) []string {
	var problems []string
	seen := map[int]bool{}
	isFirstPass := func(cells []string) bool { return columnOf(cells, "first classification") >= 0 }

	found := tableRows(lines, isFirstPass, func(header, row []string) {
		if rowIsBlank(row) {
			return
		}
		match := eventRowPattern.FindStringSubmatch(row[0])
		if match == nil {
			problems = append(problems, fmt.Sprintf("first pass: %q does not name a scenario event; write Event 1 to Event %d", row[0], scenarioEvents))
			return
		}
		number, _ := strconv.Atoi(match[1])
		if number < 1 || number > scenarioEvents {
			problems = append(problems, fmt.Sprintf("first pass: the scenario has no Event %d", number))
			return
		}
		seen[number] = true
		switch class := cellOf(header, row, "first classification"); {
		case class == "":
			problems = append(problems, fmt.Sprintf("first pass: Event %d has no first classification; write attack, operational failure or undetermined", number))
		case !firstClassifications[class]:
			problems = append(problems, fmt.Sprintf("first pass: Event %d's first classification must read attack, operational failure or undetermined, not %q", number, class))
		}
	})

	if !found {
		if name == incidentRecordFile {
			problems = append(problems, "the incident record has no first-pass table with a First classification column")
		}
		return problems
	}
	for number := 1; number <= scenarioEvents; number++ {
		if !seen[number] {
			problems = append(problems, fmt.Sprintf("first pass: Event %d has no row", number))
		}
	}
	return problems
}

// claimStatuses are the four statuses section 10 of the specification allows.
var claimStatuses = map[string]bool{"supported": true, "partly_supported": true, "unsupported": true, "not_applicable": true}

// finalClaims is how many Security claims the core course ends with. Tier 10
// adds none.
const finalClaims = 9

var claimIDPattern = regexp.MustCompile(`^SC-([0-9]{2})$`)

// boardEvidence is the label a board result carries in an Evidence cell, as
// the template asks it to be written.
const boardEvidence = "(board)"

// checkFinalClaimMatrix is rule (c): the matrix has SC-01 to SC-09, each with
// one of the four statuses, and a `supported` row has at least one evidence
// entry labeled board. A host result never stands in for a board result.
func checkFinalClaimMatrix(name string, lines []string) []string {
	var problems []string
	seen := map[int]bool{}
	isMatrix := func(cells []string) bool { return columnOf(cells, "status after tier 10") >= 0 }

	found := tableRows(lines, isMatrix, func(header, row []string) {
		if rowIsBlank(row) {
			return
		}
		match := claimIDPattern.FindStringSubmatch(row[0])
		number := 0
		if match != nil {
			number, _ = strconv.Atoi(match[1])
		}
		if number < 1 || number > finalClaims {
			problems = append(problems, fmt.Sprintf("claim matrix: %q is not one of SC-01 to SC-%02d; Tier 10 adds no claim", row[0], finalClaims))
			return
		}
		seen[number] = true
		id := row[0]
		status := cellOf(header, row, "status after tier 10")
		switch {
		case status == "":
			problems = append(problems, fmt.Sprintf("%s has no status after Tier 10", id))
		case !claimStatuses[status]:
			problems = append(problems, fmt.Sprintf("%s: status after Tier 10 must read supported, partly_supported, unsupported or not_applicable, not %q", id, status))
		case status == "supported" && !strings.Contains(cellOf(header, row, "evidence"), boardEvidence):
			problems = append(problems, fmt.Sprintf("%s is supported with no evidence entry labeled (board); a claim with host results only is at most partly_supported", id))
		}
	})

	if !found {
		if name == finalClaimMatrixFile {
			problems = append(problems, "the final claim matrix has no table with a Status after Tier 10 column")
		}
		return problems
	}
	for number := 1; number <= finalClaims; number++ {
		if !seen[number] {
			problems = append(problems, fmt.Sprintf("claim matrix: SC-%02d has no row", number))
		}
	}
	return problems
}

// residualRiskGroups are the four groups of #289 point 3. "Recheck on any
// Zephyr upgrade" and "residual risk with an owner" are not groups: they go
// into Accepted for the core course with their revisit trigger.
var residualRiskGroups = map[string]bool{
	"Advanced Tier A":              true,
	"Advanced Tier B":              true,
	"Accepted for the core course": true,
	"Recorded limit":               true,
}

// checkResidualRiskGroups is rule (d): every residual-risk row has one of the
// four groups and a non-empty owner. An unowned risk is one nobody will
// revisit.
func checkResidualRiskGroups(name string, lines []string) []string {
	var problems []string
	isSummary := func(cells []string) bool {
		return columnOf(cells, "group") >= 0 && columnOf(cells, "owner") >= 0
	}

	found := tableRows(lines, isSummary, func(header, row []string) {
		if rowIsBlank(row) {
			return
		}
		id := rowName(row, "a residual-risk row")
		switch group := cellOf(header, row, "group"); {
		case group == "":
			problems = append(problems, fmt.Sprintf("%s has no group", id))
		case !residualRiskGroups[group]:
			problems = append(problems, fmt.Sprintf("%s: group must read Advanced Tier A, Advanced Tier B, Accepted for the core course or Recorded limit, not %q", id, group))
		}
		if cellOf(header, row, "owner") == "" {
			problems = append(problems, fmt.Sprintf("%s has no owner", id))
		}
	})

	if !found && name == residualRiskSummaryFile {
		problems = append(problems, "the residual-risk summary has no table with Group and Owner columns")
	}
	return problems
}
