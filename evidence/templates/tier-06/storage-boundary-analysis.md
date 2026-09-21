# Storage boundary analysis

Copy this file into `evidence/learner/tier-06/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T6-STORAGE-<your initials> |
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
| limitations | Both rows below are true at once. A record that keeps only one of them describes a boundary that does not exist. |

## The two results

| Evidence ID | Test | Expected result | What you observed | Observed on | Record state |
| --- | --- | --- | --- | --- | --- |
| E-6-04 | Ask the device to export its private key | Refused on the device. `status=-133`, `PSA_ERROR_NOT_PERMITTED` |  | device | pending |
| E-6-05 | Read the same private key out of a flash dump | Succeeds. The key is recovered by running a known derivation over public values |  | device dump, decrypted on the host | pending |

`E-6-04` is a device result and becomes `observed` only from your own board. `E-6-05` starts with a dump taken from your own board, so it becomes `observed` only when the key you recovered is your board's key. Neither row may be filled in from the module.

## What the device printed

```text

```

## The derivation

Record the derivation you ran, so that a reviewer can repeat it.

| Field | Value |
| --- | --- |
| Record name in the dump |  |
| Values the encryption key is derived from |  |
| Where each of those values is published |  |
| Result of the decryption |  |

Say whether the recovered key matches the public key in the certificate the device holds, and what it would mean if it did not.

## What the boundary is

Write both halves in your own words, in one sentence each.

| Field | Value |
| --- | --- |
| What is true at the course API boundary |  |
| What is true at the flash boundary |  |
| Who the set of people able to read the key narrowed from, and to |  |

The claim you must not make is that the key cannot be copied to another device. You copied it. Record that here rather than leaving it to the claim record to notice.
