# Claim sequence

Copy this file into `evidence/learner/tier-07/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T7-CLAIM-SEQ-<your initials> |
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
| limitations | This record holds no nonce and no Owner credential. It holds times, fingerprints, and what each half of the claim printed. |

## The device half

| Field | Value |
| --- | --- |
| Device identifier |  |
| Physical action you performed |  |
| Time the Claim window opened |  |
| Time the window closed |  |
| Was a nonce printed |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

Note the times. The window is the control, and a record with no times cannot show that the window was open when the approval arrived.

## The operator half

| Field | Value |
| --- | --- |
| Owner identity |  |
| Time of the approval |  |
| Result |  |
| Lifecycle state after the claim |  |
| Certificate serial |  |
| Certificate fingerprint |  |
| Observed on | device, with the operator half on the host |
| Record state |  |

Paste both halves of the console output here: the window opening, the nonce and the request going out, and the operator approval with the certificate it returned.

```text

```

## The claim record

| Field | Value |
| --- | --- |
| Device |  |
| Owner |  |
| Lifecycle state |  |
| Certificate serial and fingerprint |  |
| What the record holds in place of the nonce |  |

A nonce is a secret that authorized a state change, so the record keeps a verifier of it rather than the nonce itself. Do not copy a nonce into this file.

## Why the match has to be two-party

Write in one sentence what a device that decided its own ownership would be claimed by, and which party the record makes the authority on ownership.
