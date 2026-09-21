# Device lifecycle model

Copy this file into `evidence/learner/tier-07/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T7-LIFECYCLE-<your initials> |
| artifact_type | control-rationale |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-07 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 07, synthetic_data true |
| limitations | This model covers the states this course has reached. The states after them are named here and built in a later tier, so nothing about them is evidence. |

## Your device's journey

One row for each transition your device actually made.

| From | To | What caused the transition | Record that marks it | Date | Record state |
| --- | --- | --- | --- | --- | --- |
| (none) | manufactured |  |  |  | pending |
| manufactured | claimed |  |  |  | pending |

Update the model rather than replacing it. The states your device has been through are evidence, and a model that only shows the current state has thrown that away.

## The diagram

Draw the states and the transitions. A fenced `mermaid` block or a plain list both work.

```text

```

State in text what the diagram shows, so that a reader who cannot see it still gets the answer.

## The states this tier does not reach

| State | What it would need | Which tier owns it | Record state |
| --- | --- | --- | --- |
|  |  |  | not built |

Nothing in this tier can transfer a device to a new owner, retire one, or take an identity back once it is issued. Record those as states that are not built rather than leaving them off the model, because a model that shows only what exists reads as if nothing else is needed.

## First claim wins

| Field | Value |
| --- | --- |
| What happens to a second claim attempt |  |
| Who owns a device that a stranger claimed first |  |
| What the device itself does during a refused claim |  |

Ownership here is first come, and the service will not take it back. Write down what that means for a device that leaves your desk unclaimed.
