# Recovery record

Copy this file into `evidence/learner/tier-10/` and write in the copy.

Recovery puts the fleet back on a known good release before any fix ships. It does not fix the candidate release. Your corrected release does that, and it has its own record.

| Field | Value |
| --- | --- |
| artifact_id | T10-RECOVERY-<your initials> |
| artifact_type | recovery-record |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-10 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 10, synthetic_data true |
| limitations | Recovery uses only the release path: the rollout commands, the Release withdrawal and the board's own revert. It shows the fleet back on the release it ran before the scenario. It says nothing about whether the candidate's defects are fixed. |

## Before you start

| Field | Value |
| --- | --- |
| Time recovery started (UTC), and its clock source |  |
| Why recovery could start at this point |  |
| Evidence you saved before step 1, with its path |  |

Save the board's serial log and the service records before step 1. Every step below changes what they show.

## Step 1: Pause the teammate's rollout

| Field | Value |
| --- | --- |
| Command you ran |  |
| Time of the `rollout.paused` line in `records.jsonl` |  |
| Actor the line names |  |
| What `./course rollout status` showed afterward |  |

## Step 2: Withdraw the candidate release

| Field | Value |
| --- | --- |
| Command you ran |  |
| Release withdrawn | tier-10-candidate |
| Reason written, which names a vulnerability record (VR) identifier |  |
| Time of the `release.withdrawn` line in `records.jsonl` |  |
| What happened to the open rollout |  |

## Step 3: Confirm the Fleet baseline

| Field | Value |
| --- | --- |
| Command you ran |  |
| Fleet baseline it showed |  |
| Expected Fleet baseline | tier-09-remediation |
| Do they match |  |

## Step 4: Show the board is confirmed at counter 6

Use two sources: the board's own console, and the event the service stored for it. One source alone is not enough.

| Field | Value |
| --- | --- |
| Serial line that shows the running release and its counter |  |
| The `update.confirmed` or `update.reverted` line in `events.jsonl` that ends the last trial, with its time |  |
| Release and security counter the board runs now |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

## Trial attempts

The board retried the candidate until you withdrew it. Count every trial boot of the candidate, from the first one to the withdrawal. Copy the number into your incident timeline as a fact.

| Field | Value |
| --- | --- |
| Number of trial attempts before the withdrawal |  |
| How you counted them, and from which record |  |
| What stayed reachable on the board during each trial |  |

## What recovery did not do

Write one or two sentences. Name what is still wrong with the candidate release, and what would happen if anyone offered it again now.
