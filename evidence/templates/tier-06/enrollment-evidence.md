# Provisioning record and proof of possession

Copy this file into `evidence/learner/tier-06/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T6-ENROL-<your initials> |
| artifact_type | provisioning-record |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-06 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 06, synthetic_data true |
| limitations | This record holds no private key and never may. It holds public material, fingerprints, and what the station recorded. |

## The device

| Field | Value |
| --- | --- |
| Device identifier |  |
| How the identifier was built |  |
| Board |  |
| Record state | pending until you have enrolled the board |

Your device identifier comes from the board in front of you, so a name taken from the module would name somebody else's board.

## The Bootstrap credential

| Field | Value |
| --- | --- |
| Credential fingerprint or identifier |  |
| Issued at |  |
| Consumed at |  |
| Which certificate consumed it |  |
| Record state |  |

The credential is one use. Record when it was consumed, because that fact is what makes a replay of it refusable later.

## The provisioning record

The station's record is what proves the enrollment, because it is the half a device cannot fake.

| Field | Value |
| --- | --- |
| Certificate serial |  |
| Certificate fingerprint |  |
| Issuing authority |  |
| Subject on the certificate |  |
| Recorded at |  |
| Observed on | device, with the station's record on the host |
| Record state | pending until you have run enrollment on the board |

Paste the station's record output and the device's own identity line here.

```text

```

State whether the identifier the device reports and the identifier in the station's record agree, and say what it would mean if they did not.

## Proof of possession

The certification request carried the Bootstrap credential inside its own signature. That is what ties the credential to the key, and it is worth recording as its own fact rather than as a step in the enrollment.

| Field | Value |
| --- | --- |
| What the request proved about the private key |  |
| Where the credential sat in the request |  |
| Check that would refuse a request without it |  |
| Evidence ID for a request that fails it |  |
| Record state |  |

Write in one sentence why a station that accepted a public key with no proof of possession would issue certificates to the wrong party.
