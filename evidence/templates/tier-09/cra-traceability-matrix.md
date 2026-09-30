# CRA traceability matrix

Copy this file into `evidence/learner/tier-09/` and write in the copy.

This is course evidence. It does not show CRA conformity, and it is not a legal determination.

| Field | Value |
| --- | --- |
| artifact_id | T9-CRA-MATRIX-<your initials> |
| artifact_type | traceability-matrix |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-09 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 09, synthetic_data true |
| limitations | One row per CRA duty for a fictional manufacturer and product. A row links a duty to the engineering evidence that bears on it. It never says the duty is met, and the legal-review column is the place to say who must decide. |

## How to fill it in

The course has named the duty in every row. Fill in the other columns yourself. The two Annex I rows point at the Annex I control map instead of repeating it.

- **Legal source** names the text you read: the Regulation's article or annex, and any guidance you relied on, such as the Commission guidance or national guidance.
- **Accessed** is the date you read that source, written as `YYYY-MM-DD`. Law and guidance change, so a source without a date cannot be checked.
- **Legal review** reads exactly `yes` or `no`. Write `yes` when a lawyer must decide something before the row can be relied on for a real product.
- **Status** is one of `supported`, `partly_supported`, `unsupported` or `not_applicable`.

`./course evidence check --tier 09` reports a row with no legal source, no access date, or a legal-review cell that is not `yes` or `no`. It does not read what you wrote in any of them.

## The matrix

| CRA duty | Product assumption | Requirement | Control | Evidence | Status | Residual risk | Responsible role | Legal source | Accessed | Legal review |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Article 13(2) and 13(3): cybersecurity risk assessment |  |  |  |  |  |  |  |  |  |  |
| Article 13(5): due diligence on components from third parties |  |  |  |  |  |  |  |  |  |  |
| Article 13(6): report a component vulnerability to its maintainer |  |  |  |  |  |  |  |  |  |  |
| Article 13(8): Support period |  |  |  |  |  |  |  |  |  |  |
| Article 13(9): each security update stays available for ten years |  |  |  |  |  |  |  |  |  |  |
| Article 13(19): end-of-support information for users |  |  |  |  |  |  |  |  |  |  |
| Article 14: reporting of an actively exploited vulnerability and a severe incident |  |  |  |  |  |  |  |  |  |  |
| Annex I Part I: cybersecurity requirements for the product |  |  | See the Annex I control map, rows I.1 to I.2(m) | See the Annex I control map |  |  |  |  |  |  |
| Annex I Part II: vulnerability handling requirements |  |  | See the Annex I control map, rows II.1 to II.8 | See the Annex I control map |  |  |  |  |  |  |
| Annex II: information and instructions for the user |  |  |  |  |  |  |  |  |  |  |
| Annex VII: technical documentation |  |  |  |  |  |  |  |  |  |  |

Add a row for any other duty your work touched. Delete no row: a duty you cannot link to evidence is a gap, and the gap belongs in the matrix.

## The live case for Article 13(6)

One component vulnerability in this tier was found by reading the supplier's advisory, and its fix already exists upstream. Write what Harbor Devices would still report to the maintainer, and what it would not need to report.

Your text:
