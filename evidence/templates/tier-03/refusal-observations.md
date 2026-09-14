# Refusal observations

Copy this file into `evidence/learner/tier-03/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T3-REFUSE-<your initials> |
| artifact_type | verification-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-03 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 03, synthetic_data true |
| limitations | Every row here is a device result. Nothing on the host can refuse a firmware image, so no host result can stand in for one. |

## Results

| Evidence ID | Image published | Expected result | Bootloader facts line | Verdict line | Observed on |
| --- | --- | --- | --- | --- | --- |
| E-3-01 | Your signed release | Installs, swaps, and runs |  |  | device |
| E-3-02 | Unsigned | Refused, no signature present |  |  | device |
| E-3-03 | Modified after signing | Refused, every fact correct |  |  | device |
| E-3-04 | Signed by the attacker key | Refused, key does not match |  |  | device |
| E-3-05 | Truncated | Refused, signature area incomplete |  |  | device |

Keep every row pending until you have watched it on the board.

## After each refusal

For each of `E-3-02` through `E-3-05`, record what the device was running afterwards.

```text

```

`REQ-01` does not ask the device to detect an attack. It asks the device to keep running the release it already had. Say whether it did.

## The two identical rows

`E-3-01` and `E-3-03` produce the same facts line. Explain in your own words why, and what the pair of lines together tells you that either one alone does not.
