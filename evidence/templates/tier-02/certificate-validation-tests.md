# Certificate validation tests

Copy this file into `evidence/learner/tier-02/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T2-TESTS-<your initials> |
| artifact_type | verification-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-02 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 02, synthetic_data true |
| limitations | A host result never stands in for a device result. Rows about the device stay pending until observed on the board. |

## Results

| Evidence ID | Test | Expected result | Actual result | Observed on |
| --- | --- | --- | --- | --- |
| E-2-01 | A verified client reads the release record over TLS | The record is returned |  | host |
| E-2-02 | The plain HTTP port is asked for the release record | Refused, and it says where the data went |  | host |
| E-2-03 | A client connects by address without stating the name | Refused: no address in the certificate |  | host |
| E-2-04 | A certificate for the right name from an untrusted authority | Refused: signed by unknown authority |  | host |
| E-2-05 | A certificate from the trusted authority for another name | Refused: valid for a different name |  | host |
| E-2-06 | The device is offered an untrusted certificate | The device refuses and keeps running its current image |  | device |
| E-2-07 | The device is offered a certificate for the wrong name | The device refuses and keeps running its current image |  | device |

## What the device actually printed

Paste the serial lines for E-2-06 and E-2-07. If you have no board, write `pending` and say so in the claim record.

```text

```

## Which check refused what

For each refusal, say which check ran, what it compared, and what it rejected. A refusal you cannot explain is not evidence.

| Evidence ID | Check that ran | What it compared | What it rejected |
| --- | --- | --- | --- |
|  |  |  |  |
