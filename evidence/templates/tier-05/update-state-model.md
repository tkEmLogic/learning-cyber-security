# Update state model and interruption matrix

Copy this file into `evidence/learner/tier-05/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T5-STATE-<your initials> |
| artifact_type | control-rationale |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-05 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 05, synthetic_data true |
| limitations | A transition you reasoned about is not a transition you interrupted. Record a transition you did not reach as `not_reached`, never as a pass. |

## The update state diagram

Draw the path the device takes: download, verify, test boot, judge, confirm or revert. A fenced `mermaid` block or a plain list both work, as long as every state and every transition has a name.

```text

```

State in text what the diagram shows, so that a reader who cannot see it still gets the answer.

## The interruption matrix

One row for each transition. Say what happens when that transition is interrupted, and how you interrupted it.

| Transition | How you interrupted it | What the device did | Record state |
| --- | --- | --- | --- |
| Download in progress |  |  | pending |
| Progress record written after the flash write |  |  | pending |
| Trailer update |  |  | not_reached |
| Test boot begins |  |  | pending |
| Health gate running |  |  | pending |
| Confirmation write |  |  | not_reached |
| First reboot after confirmation |  |  | not_reached |
| Revert in progress |  |  | pending |

Three transitions were not reached during the course's own validation: the trailer update, the confirmation write, and the first reboot after confirmation. Each is a window of a few milliseconds. They are recorded as `not_reached` rather than as passes, because a skipped check never supports a claim. If you did reach one, record what you saw and say how you reached it.

## The safe ordering

Write in one sentence which of the two orderings of a progress record and a flash write is the safe one, and why the other one is not.

| Field | Value |
| --- | --- |
| Order used when writing |  |
| Order used when discarding |  |
| Why each order is the safe one |  |

## What the device cannot tell you

Two of the four failures leave no reason behind. Record which, and why.

| Release | What the next boot could say | What you observed | Record state |
| --- | --- | --- | --- |
| `fail-health` | The named check that failed |  | pending |
| `timeout-health` | That the beacon stopped, and when |  | pending |
| `crash` | Nothing. Reset cause only |  | pending |
| `hang` | Nothing. Reset cause only |  | pending |
