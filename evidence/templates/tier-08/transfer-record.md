# Transfer record

Copy this file into `evidence/learner/tier-08/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T8-TRANSFER-<your initials> |
| artifact_type | lifecycle-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-08 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 08, synthetic_data true |
| limitations | This record holds no Owner credential and no nonce. It covers one transfer between two owners on one lab host, where one person holds both credentials. |

## The first act: the owner of record gives the device up

| Field | Value |
| --- | --- |
| Device identifier |  |
| Owner of record |  |
| Time of the transfer |  |
| Certificate serial revoked |  |
| Reason written in `revoked.jsonl` |  |
| Recovery authorization voided, if any |  |
| Lifecycle state after the first act |  |
| Observed on | host |
| Record state |  |

## What the board did while it belonged to no one

| Field | Value |
| --- | --- |
| The refusal line on the board's console |  |
| The serial it names |  |
| Does that serial match the one revoked above |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

## The second act: a new owner claims it

| Field | Value |
| --- | --- |
| New owner |  |
| Time of the press |  |
| Time the device half reached the service |  |
| Time of the approval |  |
| New certificate serial |  |
| Owner the board printed at its next boot |  |
| Observed on | device, with the operator half on the host |
| Record state | pending until you have run it on the board |

## What the transfer kept

| Kept item | How you checked it | Before | After the transfer | After the new claim |
| --- | --- | --- | --- | --- |
| Factory certificate fingerprint |  |  |  |  |
| Security counter of the running image |  |  |  |  |
| Time floor |  |  |  |  |
| The device's history in the record |  |  |  |  |

## What the transfer did not clear

| Item | Where it lives | Why the transfer cannot clear it |
| --- | --- | --- |
| Wi-Fi passphrase |  |  |
|  |  |  |

## The replay after the transfer

| Field | Value |
| --- | --- |
| Release offered |  |
| Its security counter |  |
| Check that refused it |  |
| Were image bytes requested |  |
| What a USB flash by the new owner could still do |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

Write in one sentence who becomes the owner of a transferred device, and why the transfer names no recipient.
