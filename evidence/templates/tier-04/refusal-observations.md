# Refusal observations

Copy this file into `evidence/learner/tier-04/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T4-REFUSE-<your initials> |
| artifact_type | verification-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-04 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 04, synthetic_data true |
| limitations | Every refusal row is a device result. The fixtures cannot tell you what the device did, so no host result stands in for one. |

## The good install

Record the install that works before you record the ones that fail. A table of refusals with no success in it proves only that the device refuses everything.

| Field | Value |
| --- | --- |
| Release identifier |  |
| Version |  |
| Security counter |  |
| Manifest checks the application passed |  |
| Bootloader line for the candidate image |  |
| Running release after the install |  |
| Observed on | device |
| Record state | pending until you watched it on the board |

## Results

Write your own result in the last two columns. Do not copy the expected result into them.

| Evidence ID | Test | Expected result | Check that refused it | Actual result | Observed on | Record state |
| --- | --- | --- | --- | --- | --- | --- |
| E-4-01 | Publish `modified` and `wrong-key` | Both refused at `manifest-signature`, no image bytes requested |  |  | device | pending |
| E-4-02 | Publish `hardware`, `channel`, `size`, `digest` | Each refused at its own named check, and the running release is unchanged |  |  | device | pending |
| E-4-03 | Replay a genuinely signed older release | Refused at `security-counter` with every signature verifying |  |  | device | pending |
| E-4-04 | Publish `counter-mismatch` | The application accepts, the bytes are written, and MCUboot erases the slot for downgrade prevention |  |  | device | pending |
| E-4-05 | Rebuild the application with the attacker's public key compiled in, then publish a manifest signed by the attacker key | The manifest verifies and the image is still refused by the bootloader |  |  | device | pending |
| E-4-06 | Install a release onto a device whose primary image carries no security counter | The swap is allowed. Downgrade prevention does not protect the first install |  |  | device | pending |
| E-4-07 | Take the Release signing key and sign anything you like | Everything in this tier is defeated. No device result is needed to know this |  |  | reasoning | not an observation |

A row moves from `pending` to `observed` only when you watched it on the board. `E-4-07` is the one row that never moves, because it is a conclusion you can reach without running anything, and recording it as an observation would be a false record.

## What the device printed

Paste the serial lines for each refusal, so that the check name in the table above can be read back to its source.

```text

```

## Which verifier refused what

Two verifiers run in this tier and they check different things about different bytes. For each row, say which one refused and what it compared.

| Evidence ID | Verifier that refused | What it compared | What it rejected |
| --- | --- | --- | --- |
|  |  |  |  |

`E-4-05` is the row that shows why this column matters. Write in one sentence why the bootloader still refused an image whose manifest the application had just accepted.
