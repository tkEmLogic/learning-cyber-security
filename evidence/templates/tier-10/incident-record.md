# Incident record

Copy this file into `evidence/learner/tier-10/` and write in the copy.

This record is for the team that handled the events. It is not a report to a regulator. Write one record for the whole integration scenario, not one record for each event.

| Field | Value |
| --- | --- |
| artifact_id | T10-INCIDENT-<your initials> |
| artifact_type | incident-record |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-10 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 10, synthetic_data true |
| limitations | The board console prints no time, so every time in this record names the clock it came from. The first-pass table records what you believed when you wrote it, and it is never edited after the next event is staged. |

## Record header

| Field | Value |
| --- | --- |
| Incident lead |  |
| Incident status |  |
| Summary |  |
| Assets in scope |  |
| Related records |  |

The incident status is one of `open`, `contained`, `recovering` or `closed`. Write the summary last, in three sentences or fewer.

The assets in scope are the board, the synthetic fleet devices, the OTA service, and every release the scenario offered. Related records are weakness ledger rows and the earlier evidence records the events touched.

## The clocks

Every time in this record has a clock source. There are three, and you write exactly one of these words in each Clock source cell.

| Write | When the time comes from |
| --- | --- |
| `host` | The `Event N staged at` line that `./course scenario next` printed, or a capture you started on the host |
| `service` | A line in `.course-state/ota/ota.log` or `.course-state/ota/events.jsonl` |
| `none` | A line on the board's serial console. The console prints no time. Leave the time empty, and place the row by its order between the rows around it |

Do not invent a time for a board line. A line with no clock is still a fact, and its order is the fact you have.

## Timeline

Write facts only: what you saw and what you did, quoted or closely copied. An opinion belongs in the event tables below, not here.

Never delete a row. To correct a row, add a new row that says which row it corrects. Number the rows in time order.

The Kind is one of `observation`, `action`, `decision` or `communication`. The Event column may stay empty until you know which event a row belongs to.

The first sign of an event is when it was first observed. Do not call it the awareness time. In this course that term is the start of a CRA reporting deadline, which is a Tier 9 idea and a different question.

The rows below are already in your timeline. Fill in each time from the line the command printed, then add your own rows between them.

| Row | Time (UTC) | Clock source | Kind | Source | What happened | Event | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
|  |  | host | action | `./course scenario next` | The `Event 1 staged at` line | Event 1 |  |
|  |  | host | action | `./course scenario next` | The `Event 2 staged at` line | Event 2 |  |
|  |  | host | action | `./course scenario next` | The `Event 3 staged at` line | Event 3 |  |
|  |  | host | action | `./course scenario next` | The `Event 4 staged at` line | Event 4 |  |
|  |  | host | action | `./course scenario next` | The `Event 5 staged at` line | Event 5 |  |
|  |  | host | action | `./course scenario next` | The `Event 6 staged at` line | Event 6 |  |
|  |  | host | action | `./course scenario next` | The `Event 7 staged at` line | Event 7 |  |
|  |  | host | action | `./course scenario next` | The `Event 8 staged at` line | Event 8 |  |
|  |  |  | observation |  | The number of trial attempts the board made before the withdrawal, from your recovery record |  |  |

The Evidence column holds the path of a file you saved under `evidence/learner/tier-10/`, such as a serial capture.

## Events: first pass

Write one row each time you stage an event, before you run `./course scenario next` again. Never edit a row in this table after the next event is staged. If you change your mind later, the final table records it.

- **First observed** is the time of the first sign, with its clock source in the next column.
- **First classification** is exactly one of `attack`, `operational failure` or `undetermined`. Write `undetermined` when you cannot yet tell. A guess is worse than an honest `undetermined`.
- **Boundary** is the trust boundary from section 2 of the course specification that something crossed or tried to cross. Write `none` for a failure that crossed no boundary.
- **Predicted control** is the control you expect to answer the event, written before you check the evidence.

| Event | First observed | Clock source | Symptom | First classification | Boundary | Predicted control |
| --- | --- | --- | --- | --- | --- | --- |
| Event 1 |  |  |  |  |  |  |
| Event 2 |  |  |  |  |  |  |
| Event 3 |  |  |  |  |  |  |
| Event 4 |  |  |  |  |  |  |
| Event 5 |  |  |  |  |  |  |
| Event 6 |  |  |  |  |  |  |
| Event 7 |  |  |  |  |  |  |
| Event 8 |  |  |  |  |  |  |

## Events: final

Write this table after the last event and the diagnosis. A first classification that turned out wrong is not a mistake in this record. It shows how the evidence changed your view.

- **Final classification** is exactly one of `attack`, `operational failure` or `undetermined`.
- **Actor** is one role from the actors table in section 2 of the course specification, such as `Hosting attacker`, `Remote attacker` or `Operational failure`.
- **Responsible control** is the control that answered the event, or `none` if nothing did.
- **What changed** names the timeline row that moved you away from the first classification, or says `unchanged`.

| Event | Final classification | Actor | Responsible control | What changed |
| --- | --- | --- | --- | --- |
| Event 1 |  |  |  |  |
| Event 2 |  |  |  |  |
| Event 3 |  |  |  |  |
| Event 4 |  |  |  |  |
| Event 5 |  |  |  |  |
| Event 6 |  |  |  |  |
| Event 7 |  |  |  |  |
| Event 8 |  |  |  |  |

## Diagnosis of the candidate release

This is the diagnostic evidence for the release your teammate prepared. Work from the failing check to the change that caused it. Read the material in this order: the event that names the failing check, the serial log of the same boot, and then the teammate's handover. You should not need to search the source tree.

The candidate has two defects. One of them makes the boot fail. The other one does not, and a fix for the first alone still ships it.

| Defect | What you observed | Where you observed it | The hunk in the handover that causes it | Ledger row |
| --- | --- | --- | --- | --- |
| Defect 1 |  |  |  |  |
| Defect 2 |  |  |  |  |

| Field | Value |
| --- | --- |
| The failing check, as the stored event names it |  |
| Why the failure is not a network problem |  |
| Why the release test and the Release approval did not catch either defect |  |

## Response and lessons

| Field | Value |
| --- | --- |
| Containment step, and whether it is an emergency, temporary or permanent measure |  |
| Evidence you kept before you changed anything |  |
| Recovery | Your copy of `recovery-record.md` |
| Removal of the cause | Your copy of `corrected-release.md` |
| End of recovery: the time, and the criterion you used |  |
| Who you told, what, and when, including the teammate who prepared the candidate |  |
| Reportability: would any event start a CRA Article 14 report? |  |

For reportability, give a yes or no and one reason. If the answer is yes, point to the Tier 9 reporting template you would use. Do not repeat that template here.

Each shortcut below is a way to make the board look healthy again that goes around a control or around the release path. Record each one you considered, even if only for a moment.

| Shortcut you considered | Why it is unsafe | What you did instead |
| --- | --- | --- |
|  |  |  |

Write a lesson when you find it, not only at the end. Name the timeline row where you found it.

| Lesson | Timeline row | What you would do differently |
| --- | --- | --- |
|  |  |  |
