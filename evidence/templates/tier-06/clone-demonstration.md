# Clone demonstration

Copy this file into `evidence/learner/tier-06/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T6-CLONE-<your initials> |
| artifact_type | verification-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-06 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 06, synthetic_data true |
| limitations | The clone runs on the host and registers devices that do not exist. It is evidence about the shared credential, not about any board. |

## The extraction

Record how the fleet credential came out of the image. Name what you searched and what you found, not only that it worked.

| Field | Value |
| --- | --- |
| Image variant you built |  |
| Where the credential was found in it |  |
| Credential fingerprint |  |
| Observed on | host |
| Record state |  |

Paste the extraction output here.

```text

```

## The devices the clone registered

The point of this table is that one recovered key registers many devices, and every one of them carries the same fingerprint.

| Device identifier the clone used | Certificate fingerprint | Was the device real |
| --- | --- | --- |
|  |  | no |
|  |  | no |
|  |  | no |

Write in one sentence what a fleet operator reading this record would believe, and why they would be wrong.

## The clone after hardening

Run the same clone against the hardened station and record what it meets.

| Field | Value |
| --- | --- |
| Command you ran |  |
| Check that refused it |  |
| What the station named in its refusal |  |
| Observed on | host |
| Record state |  |

The refusal is made on the host, by the station, and the device is not consulted. That makes it a host result and it stays one. It says what the station will not do. It says nothing about your board.

## What the attacker still controls

| What they can still do | Why the control does not stop it |
| --- | --- |
|  |  |
