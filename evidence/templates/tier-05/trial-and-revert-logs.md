# Confirmation and revert logs

Copy this file into `evidence/learner/tier-05/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T5-TRIAL-<your initials> |
| artifact_type | verification-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-05 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 05, synthetic_data true |
| limitations | Every row here is a device result. Nothing on the host can put an image on trial or revert one, so no host result can stand in for one. |

## The five releases

One row for each release this tier publishes. Keep every row `pending` until you have watched it on the board.

| Release | What it does during the trial | Expected outcome | What you observed | Record state |
| --- | --- | --- | --- | --- |
| `healthy` | Passes every check and holds the window | Confirmed, and it becomes the image the device falls back to |  | pending |
| `crash` | Faults before the health gate starts | Reverted after the watchdog resets the board |  | pending |
| `hang` | Stops in the thread that feeds the watchdog | Reverted after the watchdog resets the board |  | pending |
| `fail-health` | Fails one named check before the window | Reverted, and the next boot names the check |  | pending |
| `timeout-health` | Passes every check, then stops during the window | Reverted, and the next boot says the beacon stopped |  | pending |

## The logs

Paste the console lines for each release. Keep the line that states the swap type, the line that states the trial attempt, and the line the next boot printed.

```text

```

## The revert and the security counter

A revert takes the device back to an image with a lower security counter, and the anti-rollback control from Tier 4 does not block it. Record the counters you saw, so that the exemption is evidence rather than a belief.

| Field | Value |
| --- | --- |
| Counter on the trial image |  |
| Counter on the confirmed image it reverted to |  |
| Any downgrade-prevention line in the boot output |  |
| Record state | pending |

If every release on your board carried the same counter, this row proves nothing. Say so rather than recording a pass.

## The trial limit

| Field | Value |
| --- | --- |
| Release you offered repeatedly |  |
| Attempts before it was refused |  |
| Check name in the refusal |  |
| What the device did afterwards |  |
| Record state | pending |

Write in one sentence why the count is incremented when a trial begins rather than when one fails.

## The report

A failed trial reboots, so the image that reports the revert is the one that came back. Record both fields, because they are different.

| Field | Value |
| --- | --- |
| Running release in the event |  |
| Release that failed |  |
| When the event was sent |  |
| Record state | pending |
