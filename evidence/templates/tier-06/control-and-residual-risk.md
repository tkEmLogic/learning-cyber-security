# Requirement, controls and residual risk

Copy this file into `evidence/learner/tier-06/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T6-CONTROL-<your initials> |
| artifact_type | control-record |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-06 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 06, synthetic_data true |
| limitations | Nothing at runtime yet requires the device to prove possession of its key. That is Tier 7, and until then this tier supports nothing about status reports. |

## The new requirement

`REQ-07` is new, because the claim under it is new. Add this row to your own requirement table, in the form Tier 1 used.

| ID | Requirement | Acceptance criterion | Supports |
| --- | --- | --- | --- |
| REQ-07 | Each device holds a private key that was generated on that device and never leaves it, and no credential enrols a second device in a device's name | The private key is present in no firmware image and in no other device's records, and a credential that has already enrolled one device is refused when it is presented for a second | SC-06 |

## The controls

Neither control was planned in Tier 1, because neither existed there. Both enter your records directly at `implemented` instead of moving from `planned`.

| ID | Control | Meets requirement | Lifecycle state | Evidence | Record state |
| --- | --- | --- | --- | --- | --- |
| CTL-08 | The device generates a non-exportable identity key and stores it through the limited Secure Storage configuration | REQ-07 | implemented |  |  |
| CTL-09 | A unique one-use Bootstrap credential and an append-only manufacturing record, so no credential enrols a second device | REQ-07 | implemented |  |  |

A control entering at `implemented` still needs evidence under it. Name the evidence for each one, and keep the record `pending` where the evidence is still `pending`.

No control in this course has reached `verified`. That state means an independent party checked the evidence, and this course cannot supply one. Leave it empty and say why.

## Residual risks

Every residual risk needs an owner and either a treatment or a recorded acceptance.

| ID | Residual risk | Owner | Treatment or acceptance | Revisit |
| --- | --- | --- | --- | --- |
| T6-W-16 | The Secure Storage encryption key is `SHA-256` of the board's MAC and the record's UID, both public. Anyone who can read the flash can derive the key |  |  | Advanced Tier B, STSAFE-A120 |
| T6-W-17 | Stored records carry no freshness, so writing back an older copy is accepted as authentic |  |  | No tier on this course closes it |
| T6-W-18 | The private key is protected at rest only. Privileged firmware, the application itself, and a debugger can all reach it |  |  | Advanced Tier B, STSAFE-A120 |
| T6-W-19 | The AES-GCM nonce is randomised once per boot then incremented, while the record's key never changes |  |  | Recheck on any Zephyr upgrade |

`T6-W-17` is the row most likely to be skipped, because nothing in the lab fails when you exercise it. Write its owner down anyway.

Add any residual risk your own work found. A tier that produces none has usually not looked.
