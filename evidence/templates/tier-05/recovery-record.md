# Recovery record

Copy this file into `evidence/learner/tier-05/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T5-RECOVERY-<your initials> |
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
| limitations | This tier does not build MCUboot's serial recovery mode. The core boot matrix row for signed serial recovery is not satisfied by this tier and is recorded as such. |

## The normal recovery path

The last confirmed image is the normal recovery path. Record what keeps it available.

| Field | Value |
| --- | --- |
| What the device falls back to |  |
| What makes that image available |  |
| When it stops being available |  |
| Record state | pending |

## Recovery when no valid image is left

Write the procedure you would follow for a device whose primary image no longer works, in the order you would perform it. Write it for someone who has never done it.

| Step | What you do | What you expect to see |
| --- | --- | --- |
| 1 |  |  |
| 2 |  |  |
| 3 |  |  |

Two facts belong in that procedure, because both look like a broken board when you meet them for the first time.

| Fact | What it looks like | What it actually is |
| --- | --- | --- |
| Flashing does not clear the bootloader trailer |  |  |
| The chip is left in ROM download mode |  |  |

## If you ran it

| Field | Value |
| --- | --- |
| Did you perform this recovery on a board |  |
| Date |  |
| What the board did |  |
| Record state | pending until performed on the board |

A procedure you have written and not run stays `pending`. Write that plainly rather than leaving the field empty, because an empty field reads like an oversight and a `pending` field reads like a fact.

## What this tier does not cover

Signed serial recovery on a dedicated recovery port is not built here. State in one sentence what that means for a device in the field, and which tier or advanced module owns it.
