# Final claim matrix

Copy this file into `evidence/learner/tier-10/` and write in the copy.

This matrix gives every Security claim its status at the end of the core course. It adds no new claim. It opens with the regression run, because every evidence entry below is a result from that run.

| Field | Value |
| --- | --- |
| artifact_id | T10-CLAIMS-<your initials> |
| artifact_type | claim-matrix |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-10 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 10, synthetic_data true |
| limitations | This matrix is not a CRA record. It cites the Tier 9 Annex I control map and CRA traceability matrix only as evidence identifiers, and it does not revise them. A host result never stands in for a board result. |

## The regression run

Fill this section from the receipt that `./course regression run` wrote. Its path is on the `Receipt:` line the command printed. Copy each value from the receipt field named in the second column.

Run it against the corrected release, after the rollout is complete. While a rollout is open, the board is offered the rollout's release instead of each test release, and those lines read `no result`.

| Field | Receipt field | Value |
| --- | --- | --- |
| Command | `command` |  |
| Receipt path | (the `Receipt:` line) |  |
| Started at (UTC) | `started_at` |  |
| Course source revision | `course_revision` |  |
| Was the course tree clean | `course_tree_clean` |  |
| Release the board ran | `release.release_id` |  |
| Security counter | `release.security_counter` |  |
| Image digest (sha256) | `release.image_sha256` |  |
| Signed manifest digest (sha256) | `release.manifest_sha256` |  |
| Source revision the image was built from | `release.source_revision` |  |
| Overall result | `result` |  |

One row for each entry in the receipt's `results` list, in the same order. Copy the label exactly: `board` or `host`. Add a row for each entry the run printed as `not run`, with the reason the plan gives.

| Fixture | Selector | Label | Result | Evidence |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

A `fail` or `no result` line is not a detail to explain away. Name it in the Gap of every claim it touches.

## The matrix

- **Status after Tier 10** is exactly one of `supported`, `partly_supported`, `unsupported` or `not_applicable`.
- **Controls** lists the `CTL-` identifiers behind the claim.
- **Evidence** lists fixture identifiers from the regression run. Write each one with its label in brackets, for example `tier-04/replay-release (board)` or `e-7-03 (host)`, and separate them with semicolons. You may also cite an earlier evidence identifier, such as a Tier 9 record.
- **Open ledger rows** lists the weakness ledger rows that still limit the claim. Every row you name must be in your residual-risk summary.
- **Gap** says what the evidence does not show.

A claim is `supported` only with at least one `board` entry. A claim whose only evidence is `host` is at most `partly_supported`, and its Gap says "host result only".

| ID | Claim | Status after Tier 9 | Status after Tier 10 | Controls | Evidence | Open ledger rows | Gap |
| --- | --- | --- | --- | --- | --- | --- | --- |
| SC-01 | Only firmware authored by the manufacturer runs on the Reference product | partly_supported |  |  |  |  |  |
| SC-02 | The device installs only the release the manufacturer currently approves, and never an earlier one | partly_supported |  |  |  |  |  |
| SC-03 | The device exchanges updates and status only with the genuine update service, and the network can neither read nor change what they exchange | supported |  |  |  |  |  |
| SC-04 | A status report can only be produced by the device it names | partly_supported |  |  |  |  |  |
| SC-05 | An interrupted or failed update never leaves the device without a working image | partly_supported |  |  |  |  |  |
| SC-06 | Each device's private key is generated on that device, never leaves it, and no credential permits enrolling a second device in its name | partly_supported |  |  |  |  |  |
| SC-07 | A device obtains an operational identity only through a physical action on that device and an authenticated owner, and only that owner's authority applies to it | partly_supported |  |  |  |  |  |
| SC-08 | A credential stops authorizing a device when the authority behind it is withdrawn, whether by revocation, renewal, transfer or decommissioning, and a device leaves service only by a recorded act | partly_supported |  |  |  |  |  |
| SC-09 | A release reaches devices only after it is approved with its source, build manifest, SBOM, tests and signatures linked, and a vulnerability found in a released version is triaged, and answered by withdrawing that release and offering a signed Remediation release at a higher security counter | partly_supported |  |  |  |  |  |

No control in this course has reached `verified`, and this tier does not change that. A control is `verified` only when an independent party has checked it.

## What moved, and why

Write one short paragraph for each claim whose status changed in this tier, and for each claim the scenario weakened without moving. Name the regression line or the scenario event that moved it. A claim that did not move needs no paragraph.
