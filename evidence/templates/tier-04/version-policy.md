# Version policy decision

Copy this file into `evidence/learner/tier-04/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T4-POLICY-<your initials> |
| artifact_type | control-rationale |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-04 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 04, synthetic_data true |
| limitations | This record is reasoning, not observation. Nothing in it is ever `observed`, because no command was run to produce it. |

## Your rule

Write the rule you will follow every time, in one sentence, before you fill in the table.

## The six cases

Your device is running `0.4.0-release-policy` at security counter 1. Commit to all six rows before you open the worked model.

| Case | The change | Version you would publish | Does the counter move | Why |
| --- | --- | --- | --- | --- |
| 1 | A log message says `recieved`. Someone fixes the spelling |  |  |  |
| 2 | The beacon gains a second blink pattern, requested by the product owner |  |  |  |
| 3 | A malformed status response from the service makes the device reboot. No data is exposed and nothing is bypassed, but a hostile service can keep a fleet rebooting indefinitely |  |  |  |
| 4 | The service name comparison is skipped when the configured name is the empty string, so a certificate for any name is accepted. Fixed |  |  |  |
| 5 | An Mbed TLS advisory is published. The vulnerable code path is not reachable in this product, and the dependency is updated anyway |  |  |  |
| 6 | A second Mbed TLS advisory. This path is reachable and can leak private key material. The dependency is updated |  |  |  |

## After you compare

The companion answers page holds one worked model, not a list of correct answers. Record the differences here rather than a copy of the answer.

| Case | What you decided | What the worked model decided | Why they differ |
| --- | --- | --- | --- |
|  |  |  |  |

## The arguable one

One of the six is genuinely arguable and the worked page says which. If you disagree with it, write your argument here. That disagreement is the artifact worth keeping, not the table.
