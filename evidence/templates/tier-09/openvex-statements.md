# OpenVEX statements

Copy this file into `evidence/learner/tier-09/` and write in the copy.

This is course evidence. It does not show CRA conformity, and it is not a legal determination.

| Field | Value |
| --- | --- |
| artifact_id | T9-VEX-<your initials> |
| artifact_type | vex-document |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-09 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 09, synthetic_data true |
| limitations | A VEX statement exports a decision from a vulnerability record. It is true as of the database date of that decision, and grype applies it only to a component whose purl matches the statement's product exactly. |

## The document

The vulnerability records hold your reasoning. This document exports the decisions in a form a scanner reads, so that a later scan shows only matches nobody has reviewed.

| Field | Value |
| --- | --- |
| File you wrote |  |
| Database date the statements are true as of |  |
| Number of statements |  |
| Statements whose product purl matches no SBOM component |  |
| OpenVEX file for the service, written by the service scan |  |

Save the JSON as its own file, for example `evidence/learner/tier-09/firmware.openvex.json`, and pass it to the firmware scan with `--vex`. Then paste your finished JSON below in place of the skeleton, so this record shows what the scanner read.

## One statement per decision

Write one statement for every firmware record whose outcome is `not affected` or `fixed`. Write `affected` and `under investigation` statements as well: grype leaves those in the results, which is what you want.

| Record | Vulnerability | Product purl, copied from the SBOM | Status | Justification or action |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

OpenVEX has five justifications for `not_affected`: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary` and `inline_mitigations_already_exist`. An `affected` statement needs an `action_statement` that says what a user should do.

## The skeleton

Replace every value in angle brackets. The product `@id` must be the component's purl exactly as the SBOM spells it. A statement that names a CPE, or a purl with a different version string, suppresses nothing and prints no warning.

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://harbor-devices.example/vex/<release id>-<date>",
  "author": "<your initials>, Harbor Devices Ltd (course exercise)",
  "timestamp": "<UTC time, such as 2026-10-01T09:00:00Z>",
  "version": 1,
  "statements": [
    {
      "vulnerability": { "name": "<CVE identifier>" },
      "products": [ { "@id": "<purl of the component, copied from the SBOM>" } ],
      "status": "not_affected",
      "justification": "<one of the five justifications>",
      "impact_statement": "<one sentence from the vulnerability record, naming the check you made>"
    },
    {
      "vulnerability": { "name": "<CVE identifier>" },
      "products": [ { "@id": "<purl of the component, copied from the SBOM>" } ],
      "status": "affected",
      "action_statement": "<what a user should do until the remediation release reaches them>"
    }
  ]
}
```

## The rerun

| Field | Value |
| --- | --- |
| Command you ran with `--vex` |  |
| Matches in the results |  |
| Matches under `ignoredMatches` |  |
| A statement that did not suppress what you expected, and why |  |
| Observed on | host |
| Record state | pending until you have rerun the scan with your own document |
