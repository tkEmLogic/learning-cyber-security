# Corrected release record

Copy this file into `evidence/learner/tier-10/` and write in the copy.

This record links your corrected release to the defects it fixes, to what it was built from, and to the canary rollout that delivered it.

| Field | Value |
| --- | --- |
| artifact_id | T10-RELEASE-<your initials> |
| artifact_type | release-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-10 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 10, synthetic_data true |
| limitations | The Release approval is a record the service keeps. It shows that the linked files are consistent, not that the release behaves. The regression run before the advance is a manual step, and the service does not enforce it. |

## What the candidate got wrong

Name both defects. For each one, give the change in your corrected source that removes it. A fix for the defect that failed the boot does not remove the other one.

| Defect | What it did | Ledger row | Your change, as a short diff or a file and line |
| --- | --- | --- | --- |
| Defect 1 |  |  |  |
| Defect 2 |  |  |  |

Put the full diff of each change in a file under `evidence/learner/tier-10/`, and write its path here.

| Field | Value |
| --- | --- |
| Diff that closes `T10-W-38` |  |
| Diff that fixes the health failure |  |
| How you know no other hunk of the handover changed a control |  |

## The release

| Field | Value |
| --- | --- |
| Release identifier | tier-10-corrected |
| Security counter | 8 |
| Release it replaces, and that release's counter |  |
| Source revision |  |
| Was the tree clean when it was built |  |

Write the sha256 of each file as you computed it, and then the digest the Release approval names.

| Artifact | File | sha256 you computed | sha256 in the Release approval | Do they match |
| --- | --- | --- | --- | --- |
| Image |  |  |  |  |
| Release manifest |  |  |  |  |
| Signature |  |  |  |  |
| Build manifest |  |  |  |  |
| Firmware SBOM |  |  |  |  |
| Test report |  |  |  |  |

| Field | Value |
| --- | --- |
| Time of the `release.approved` line in `records.jsonl` |  |
| Who the approval names as approver |  |
| What the approval does not prove |  |

## The canary

The board is the Canary group. Name it by the device identifier it really reports, and confirm that it installed counter 8 before you advance the rollout.

One row for each rollout and update event, in the order the records show them.

| Time | Event kind | Release | Devices it covered | Result |
| --- | --- | --- | --- | --- |
|  | rollout.started |  |  |  |
|  | rollout.served |  |  |  |
|  | update.confirmed |  |  |  |
|  | rollout.advanced |  |  |  |

| Field | Value |
| --- | --- |
| Device identifier your board reports, and where you read it |  |
| Devices in the Canary group of `rollout.started` |  |
| Time of `update.confirmed` at counter 8 |  |
| Time of `rollout.advanced` |  |
| Regression run before the advance: the receipt path and its result |  |
| What the board printed when it confirmed counter 8 |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

The `update.confirmed` time must be earlier than the `rollout.advanced` time. If it is not, the canary did not do its job, and this record says so.

## Completion

| Field | Value |
| --- | --- |
| Time of the `rollout.completed` line |  |
| Fleet baseline after completion |  |
| Expected Fleet baseline | tier-10-corrected |
| What the board does if anyone offers `tier-10-candidate` again |  |
