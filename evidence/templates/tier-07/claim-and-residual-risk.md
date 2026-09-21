# Claims, controls and residual risk

Copy this file into `evidence/learner/tier-07/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T7-CLAIM-<your initials> |
| artifact_type | security-claim |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-07 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 07, synthetic_data true |
| limitations | A claim moves on evidence, not on work done nearby. Leave a claim where it was until the evidence under it is recorded and `observed`. |

## The claim movements

Three claims move, one gains evidence without moving, and one is new. Revise the records you already hold. Do not create a second record for a claim that already has one.

| ID | Claim | Status before | Status after | Evidence | Gap that remains |
| --- | --- | --- | --- | --- | --- |
| SC-03 | The device exchanges updates and status only with the genuine update service, and the network can neither read nor change what they exchange | partly_supported |  |  |  |
| SC-04 | A status report can only be produced by the device it names | unsupported |  |  |  |
| SC-06 | Each device's private key is generated on that device, never leaves it, and no credential permits enrolling a second device in its name | partly_supported | partly_supported |  |  |
| SC-07 | A device obtains an operational identity only through a physical action on that device and an authenticated owner, and only that owner's authority applies to it | (new) |  |  |  |

`SC-06` gains evidence without changing status. Record the gap that closed as well as the two that remain, because a register that only ever records status changes hides most of the work.

## The new requirement

`REQ-08` is new, because the claim under it is new. Add this row to your own requirement table, in the form Tier 1 used.

| ID | Requirement | Acceptance criterion | Supports |
| --- | --- | --- | --- |
| REQ-08 | A device takes an operational identity only when a physical action on that device and an authenticated owner are both present, and afterwards only that owner's authority applies to it | A request made without the physical action is refused and recorded as refused, and so is a request made by an owner other than the one the device already holds | SC-07 |

## Controls

| ID | Control | Meets requirement | Lifecycle state before | Lifecycle state after | Evidence |
| --- | --- | --- | --- | --- | --- |
| CTL-04 | A per-device identity generated on the device, then mutual TLS binding every report to the connection that carried it | REQ-04 | planned |  |  |
| CTL-10 | The physical Claim window, the one-use nonce, and the match that spends it | REQ-08 | (new) | implemented |  |
| CTL-11 | The Owner credential and the owner-scoped certificate, with `ownership-context` enforced on every connection | REQ-08 | (new) | implemented |  |

`CTL-04` was planned in Tier 1 and is completed here. It is the first control in this course planned across two tiers and completed in the second, so revise the record you already hold rather than writing a new one.

No control in this course has reached `verified`, and this tier does not change that. That state means an independent party has checked the evidence, and nothing in a course where the Learner writes the control, runs the attack and records the result can supply that. Leave it empty and say why.

## Residual risks

Every residual risk needs an owner and either a treatment or a recorded acceptance.

| ID | Residual risk | Owner | Treatment or acceptance | Revisit |
| --- | --- | --- | --- | --- |
| T7-W-20 | Authorization lifetime is enforced only by the service. The device cannot evaluate its own certificate's validity window, there is no revocation list and no OCSP |  |  | Tier 8 |
| T7-W-21 | The Owner credential is a bearer token on a server-authenticated listener. Whoever holds it is the owner, with no rotation and no second factor |  |  | Tier 8 |
| T7-W-22 | With mutual TLS the service holds a certificate authority signing key, so compromising the service mints devices |  |  |  |
| T7-W-23 | The claim endpoint is an oracle. Distinguishable refusals reveal whether a device exists and whether it is owned |  |  | Accepted |
| T7-W-24 | The Factory credential survives claiming permanently and reopens the claim path forever, by design |  |  | Accepted |
| T7-W-25 | Synthetic devices land in the real manufacturing record with no marker field. The naming convention is the only tell |  |  | Recorded limit |

Four rows you inherited widen in this tier rather than closing. Record the widening against the rows you already hold, in Tier 6's scope, instead of opening new ones here.

Add any residual risk your own work found. A tier that produces none has usually not looked.

## What you must not claim

Write, in your own words, the three statements this tier does not support. If you cannot write them without checking, reread the Security claim section of the module before the Mentor review gate.
