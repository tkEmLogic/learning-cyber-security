# Lifecycle event records

Copy this file into `evidence/learner/tier-08/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T8-LIFECYCLE-<your initials> |
| artifact_type | lifecycle-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-08 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 08, synthetic_data true |
| limitations | This record copies lines out of `.course-state/provisioning/records.jsonl` and your board's console. It holds no nonce, no Owner credential and no private key. The state column is derived by you from the record kinds, and the `lifecycle_state` field on a line is only a copy of that derivation. |

## Your board's journey

One row for each record your board caused, in the order the record holds them. Keep the rows from Tier 6 and Tier 7 as well, because the journey is the evidence.

| Time | Identifier | Record kind | State after it | Did the state change | Record state |
| --- | --- | --- | --- | --- | --- |
|  |  | enrollment | manufactured | yes | pending |
|  |  | claim | claimed | yes | pending |
|  |  | activation | active | yes | pending |
|  |  | renewal_request |  |  | pending |
|  |  | renewal |  |  | pending |
|  |  | activation |  |  | pending |
|  |  | transfer |  |  | pending |
|  |  | claim |  |  | pending |
|  |  | recovery_authorization |  |  | pending |
|  |  | recovery |  |  | pending |
|  |  | revocation |  |  | pending |
|  |  | remanufacture |  |  | pending |
|  |  | enrollment |  |  | pending |
|  |  | factory_loss |  |  | pending |
|  |  | decommission |  |  | pending |
|  |  | remanufacture |  |  | pending |
|  |  | claim |  |  | pending |

Add a row for every record you see that is not in this list, and delete none. A row becomes `observed` when you have read the line in your own record.

## Which operations moved the state

| Operation | Record kind it wrote | Did the state change | Why, in one sentence |
| --- | --- | --- | --- |
| Renewal |  |  |  |
| Ownership transfer |  |  |  |
| Recovery |  |  |  |
| Device revocation |  |  |  |
| Decommissioning |  |  |  |

A Device lifecycle state tracks what a device is authorized to do, not what it is holding. Write down which two operations left the state where it was, and what the record could not see during each one.

## The renewal overlap

Both certificates are accepted for a short time. Record the times that prove the new one was used before the old one was retired. All three come from the service's own clock.

| Field | Value |
| --- | --- |
| Old certificate serial |  |
| New certificate serial |  |
| `activation` record time for the new serial |  |
| `superseded` line time for the old serial, in `revoked.jsonl` |  |
| `renewal.activated` event time, in `events.jsonl` |  |
| Which of the three is the proof, and why |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

## The recovery

| Field | Value |
| --- | --- |
| What the board printed after the fault and a reset |  |
| What the record said about the device at that moment |  |
| Recovery authorization identifier |  |
| Serial the authorization revoked |  |
| Result the operator half returned |  |
| Lifecycle state before and after |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

## The two revocations

| Field | Certificate revocation | Device revocation |
| --- | --- | --- |
| Command you ran |  |  |
| Where it was recorded |  |  |
| Check that refused the device afterwards |  |  |
| Could the device still recover |  |  |
| What lifts it |  |  |

## The Time floor

| Field | Value |
| --- | --- |
| Floor at first Tier 8 boot, and what set it |  |
| Floor after the first verified manifest, and what set it |  |
| Floor after a trial revert |  |
| Floor after an older manifest was offered |  |
| Seed you built the time-floor image with |  |
| The certificate `valid_to` it was judged against |  |
| What the device stopped doing |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

## The states in one picture

Draw the six states and the operations between them. A fenced `mermaid` block or a plain list both work.

```text

```

State in text what the diagram shows, so that a reader who cannot see it still gets the answer.
