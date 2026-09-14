# Signed release evidence

Copy this file into `evidence/learner/tier-03/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T3-SIGN-<your initials> |
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
| limitations | The signing key lives on the same machine as the build and the service. Its custody is a convention here, not a control. |

## The key

| Field | Value |
| --- | --- |
| Release signing key fingerprint | (from `./course keys create release` or `./course keys list`) |
| Attacker key fingerprint | (the same commands) |
| Where the private keys live | `.course-secrets/signing`, never committed |
| What the firmware build reads | `artifacts/generated/signing/release.pub.pem`, the public half only |

Record in one sentence why the build reads only the public half, in your own words.

## The release

| Field | Value |
| --- | --- |
| Release identifier |  |
| Image digest from `./course release sign` |  |
| Image size |  |
| Signature algorithm | ECDSA P-256 |

## What the device reported

Paste the boot line naming the key the build trusted, and the line beneath it.

```text

```

State whether that fingerprint matches the one above, and say what it would mean if it did not.

Record what that line does **not** tell you. The application cannot read what the bootloader holds.
