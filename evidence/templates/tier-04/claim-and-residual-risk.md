# Claim and residual risk

Copy this file into `evidence/learner/tier-04/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T4-CLAIM-<your initials> |
| artifact_type | security-claim |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-04 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 04, synthetic_data true |
| limitations | The claim below rests on device results. Keep it at its earlier status until the rows that support it are `observed` on your own board. |

## The claim this tier moves

| Field | Value |
| --- | --- |
| ID | SC-02 |
| Claim | The device installs only the release the manufacturer currently approves, and never an earlier one |
| Status before this tier | unsupported |
| Status after this tier |  |
| Evidence that supports it |  |
| First gap that stops it reaching supported |  |
| Second gap that stops it reaching supported |  |
| Tier or module that closes each gap |  |

The module names both gaps. Write them in your own words first, then check that you named two and not one.

## Controls

Revise the control records you already hold. Do not create a second record for a control that already has one.

| ID | Control | Meets requirement | Lifecycle state before | Lifecycle state after | Evidence |
| --- | --- | --- | --- | --- | --- |
| CTL-02 | The device verifies a signed Release manifest before it believes any of it, and refuses a lower security counter | REQ-02 | planned |  |  |
| CTL-01 | MCUboot refuses to swap in an image whose signed counter is lower than the running one | REQ-02, REQ-06 | implemented | implemented |  |

`CTL-01` was already implemented in Tier 3. This tier gives it a second job rather than a new state, so its state does not move. Write one sentence saying which of the two controls is the security boundary and what would still be true if you deleted the other.

## Residual risks

Every residual risk needs an owner and either a treatment or a recorded acceptance.

| ID | Residual risk | Owner | Treatment or acceptance | Revisit |
| --- | --- | --- | --- | --- |
| T4-W-12 | Downgrade prevention does not protect the first install, because MCUboot allows a swap when the primary image carries no counter |  |  | Advanced Tier A |
| T4-W-13 | The security counter is compared, never remembered. Both copies live in flash, and a physical attacker who can rewrite the primary slot chooses what the device thinks it is running |  |  | Advanced Tier A |

Add any residual risk your own work found. A tier that produces none has usually not looked.

## What you must not claim

Write, in your own words, the four statements this tier does not support. If you cannot write them without checking, reread the Security claim section of the module before the next tier.
