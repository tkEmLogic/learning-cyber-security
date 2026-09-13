# Security claim and Residual risks

Copy this file into `evidence/learner/tier-02/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T2-CLAIM-<your initials> |
| artifact_type | security-claim |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-02 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 02, synthetic_data true |
| limitations | Tier 2 protects the connection. It makes no claim about the authenticity of a firmware image. |

## The claim this tier moves

| Field | Value |
| --- | --- |
| ID | SC-03 |
| Claim | The device exchanges updates and status only with the genuine update service, and the network can neither read nor change what they exchange |
| Status before this tier | unsupported |
| Status after this tier |  |
| Evidence that supports it |  |
| The gap that stops it reaching supported |  |
| Tier that closes the gap |  |

A claim may reach `partly_supported` here. It may not reach `supported`, because the status path still trusts a device identifier that nothing proves.

## Controls

| ID | Control | Lifecycle state before | Lifecycle state after | Evidence |
| --- | --- | --- | --- | --- |
| CTL-03 | HTTPS with a course-local certificate authority, certificate validation, and hostname validation on the device | planned |  |  |

Revise the same control record you wrote in Tier 1. Do not create a second one.

## Residual risks

Every Residual risk needs an owner and either a treatment or a recorded acceptance.

| ID | Residual risk | Owner | Treatment or acceptance | Tier |
| --- | --- | --- | --- | --- |
| RES-05 | A compromised but trusted update service can still supply any firmware image, over a perfectly valid connection |  |  | Tier 3 |
| RES-06 | The device does not check certificate validity dates, because it has no clock |  |  | Tier 8 |
| RES-07 | The Course certificate authority's private key can issue a certificate for any name |  |  |  |

Add any Residual risk your own work found. A tier that produces none has usually not looked.

## What you must not claim

Write, in your own words, the three statements this tier does not support. If you cannot write them without checking, reread the Security claim section of the module before the next tier.
