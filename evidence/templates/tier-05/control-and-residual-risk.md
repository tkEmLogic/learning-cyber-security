# Control and residual risk

Copy this file into `evidence/learner/tier-05/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T5-CONTROL-<your initials> |
| artifact_type | control-record |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-05 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 05, synthetic_data true |
| limitations | This control is not exercised against a power cut at three of the transitions. Those three are recorded as `not_reached` in the update state model, not as passes. |

## The control this tier moves

Revise the control record you wrote in Tier 1. Do not create a second one.

| ID | Control | Meets requirement | Supports claim | Lifecycle state before | Lifecycle state after | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| CTL-05 | Two image slots with test boot, explicit confirmation, and automatic revert | REQ-05 | SC-05 | planned |  |  |

`CTL-05` is the control Tier 1 planned for this tier, in the words Tier 1 used. Your own record for it has been sitting at `planned` since Tier 1, and this is the tier that moves it.

Move it only when your own device rows are `observed`. A control whose evidence is still `pending` is a control you have read about.

## What the control is not exercised against

| Gap | Why it remains | Record state |
| --- | --- | --- |
| A power cut at the trailer update |  | not_reached |
| A power cut at the confirmation write |  | not_reached |
| A power cut at the first reboot after confirmation |  | not_reached |
| Sustained physical interference during the health window |  | open, see T5-W-14 |

## Residual availability risks

Every residual risk needs an owner and either a treatment or a recorded acceptance.

| ID | Residual risk | Owner | Treatment or acceptance | Revisit |
| --- | --- | --- | --- | --- |
| T5-W-14 | Anyone who can power-cycle the board during the sixty second health window forces a revert, with no key, no network and no credential. The device can never complete an update while someone keeps doing it |  |  |  |
| T5-W-15 | The watchdog catches a hung thread only because the driver's stage 0 handler fails to feed it. An upstream fix would change this silently |  |  | Recheck on any Zephyr upgrade |

`T5-W-14` is the first time in this course that adding a control has created new attack surface. Write one sentence on what an attacker gains from it, and one on what it costs the customer.

Add any residual risk your own work found. A tier that produces none has usually not looked.
