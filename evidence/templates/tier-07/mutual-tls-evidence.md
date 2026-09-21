# Mutual TLS evidence

Copy this file into `evidence/learner/tier-07/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T7-MTLS-<your initials> |
| artifact_type | verification-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-07 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 07, synthetic_data true |
| limitations | This record shows that the connection proved who the sender was. It says nothing about anyone who holds a copy of the private key. |

## What the device presented

| Field | Value |
| --- | --- |
| Certificate it presented |  |
| Key it presented |  |
| Endpoint it connected to |  |
| Result |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

Paste the device's own handshake line here.

```text

```

## What the service accepted

| Field | Value |
| --- | --- |
| How the service derived the identity |  |
| Certificate in the event record |  |
| Path in the event record |  |
| Accepted identifier in the event record |  |
| Do all three agree |  |
| Observed on | host |
| Record state |  |

Paste the service's event record here.

```text

```

## The pair that closes the row

One closure in this tier rests on a pair rather than on a single row, and this record is half of it.

| Field | Value |
| --- | --- |
| Device result |  |
| Host result it is paired with |  |
| Why the host half cannot be produced on a board |  |
| What the pair closes |  |

The refusal is observed on the host and the replacement behavior is observed on the board. Neither half alone closes the row, so record both or record neither.

## What this does not prove

Write in your own words the sentence this tier asks you to memorize: what the service can no longer be told, and what it can still be shown.
