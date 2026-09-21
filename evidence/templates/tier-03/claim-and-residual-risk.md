# Claim and residual risk

Copy this file into `evidence/learner/tier-03/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T3-CLAIM-<your initials> |
| artifact_type | claim-record |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-03 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 03, synthetic_data true |
| limitations | `SC-01` reaches partly supported and no further. The bootloader that holds the key is not itself verified, so the claim rests on a component this tier does not check. |

## Claim

| Claim | Statement | Status before | Status after | Supporting evidence | Stated gap |
| --- | --- | --- | --- | --- | --- |
| SC-01 | Only firmware authored by the manufacturer runs on the Reference product | unsupported | partly_supported | E-3-01 to E-3-05 |  |

Write the gap yourself, in one sentence, before reading the module's version again.

## Controls

| Control | Statement | Requirement | Status before | Status after |
| --- | --- | --- | --- | --- |
| CTL-01 | MCUboot verifies an image signature against the public key compiled into the bootloader | REQ-01 | planned | implemented |
| CTL-06 | The release signing key is held away from the update service, which holds only public material | REQ-06 | planned | implemented |

For `CTL-06`, record what "held away" actually means on your machine, and what a manufacturer does instead.

## Residual risks

| Risk | Why it remains | Owner | Treatment or acceptance | Revisit |
| --- | --- | --- | --- | --- |
| T3-W-10 | The bootloader is not itself verified. Whoever can flash a bootloader chooses the key |  |  | Advanced Tier A |
| T3-W-11 | The Release signing key lives on the same machine as the build and the service |  |  | Tier 8 |

## What this tier does not claim

List at least three things signing did not do. The module names four. Write yours before comparing.
