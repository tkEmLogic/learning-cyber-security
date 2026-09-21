# Certificate role inventory

Copy this file into `evidence/learner/tier-07/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T7-INVENTORY-<your initials> |
| artifact_type | certificate-inventory |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-07 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 07, synthetic_data true |
| limitations | Fingerprints and public paths only. No private key material belongs in this record, and two of the leaves below have a private half that has never been a file. |

## Signing keys

Two signing keys, and neither of them has a certificate.

| Key | Fingerprint | Where the private half lives | What trusts it |
| --- | --- | --- | --- |
|  |  |  |  |
|  |  |  |  |

Write in one sentence why a key with no certificate is still an authority in this course, and what decides which of the two the device will run.

## Authorities

Four authorities, and each answers a different question.

| Authority | What it signs | Question it answers |
| --- | --- | --- |
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |

## Leaf roles

Seven leaf roles. Two of them have a private half that has never been a file, and those two are the ones this tier is about.

| Leaf role | Issuing authority | Where the private half lives |
| --- | --- | --- |
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |

## The two that were never files

| Leaf role | Where the key was generated | Why it was never a file | What that does not protect it from |
| --- | --- | --- | --- |
|  |  |  |  |
|  |  |  |  |

The last column is the honest one. A key that was never a file is still readable from a flash dump under the derivation Tier 6 published, so record what the property buys and what it does not.

## The output

Paste the inventory output you recorded this from.

```text

```

| Field | Value |
| --- | --- |
| Observed on | host |
| Record state |  |
