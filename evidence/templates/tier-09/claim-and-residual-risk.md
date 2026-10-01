# Claims, controls and residual risk

Copy this file into `evidence/learner/tier-09/` and write in the copy.

This is course evidence. It does not show CRA conformity, and it is not a legal determination.

| Field | Value |
| --- | --- |
| artifact_id | T9-CLAIM-<your initials> |
| artifact_type | security-claim |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-09 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 09, synthetic_data true |
| limitations | A claim moves on evidence, not on work done nearby. A clean scan is not a clean product, a Release approval is not something the device checks, and none of these records is a statement about CRA conformity. |

## What you must not claim

Write these first, before the claim movements, in your own words. There are three: about a clean scan, about the Release approval, and about CRA conformity.

| Statement you must not make | Why it is false in this course | Evidence that shows it |
| --- | --- | --- |
|  |  |  |
|  |  |  |
|  |  |  |

## The claim movements

Revise the records you already hold. Do not create a second record for a claim that already has one.

| ID | Claim | Status before | Status after | Evidence | Gap that remains |
| --- | --- | --- | --- | --- | --- |
| SC-01 | Only firmware authored by the manufacturer runs on the Reference product |  |  |  |  |
| SC-02 | The device installs only the release the manufacturer currently approves, and never an earlier one | partly_supported |  |  |  |
| SC-09 | A release reaches devices only after it is approved with its source, build manifest, SBOM, tests and signatures linked, and a vulnerability found in a released version is triaged, and answered by withdrawing that release and offering a signed Remediation release at a higher security counter | (new) |  |  |  |

Add a row for any other claim your Tier 9 work moved.

## The new requirement

| ID | Requirement | Acceptance criterion | Supports |
| --- | --- | --- | --- |
| REQ-10 | The service offers a release to devices only while a recorded approval names the current digests of all its linked evidence, offers it to a named group of devices before the rest of the fleet, and never offers a withdrawn release again |  | SC-09 |

## Controls

| ID | Control | Meets requirement | Status before | Status after | Evidence |
| --- | --- | --- | --- | --- | --- |
| CTL-17 | Release approval: the service offers a release only when an approval names the digests of its image, manifest, signature, build manifest, SBOM and test report, and those digests still match | REQ-10 | (new) | implemented |  |
| CTL-18 | Rollout and Release withdrawal: a release reaches the Canary group first, the rest of the fleet only by a separate step, and a withdrawn release is never offered again | REQ-10 | (new) | implemented |  |

No control in this course has reached `verified`, and this tier does not change that.

## Residual risks

Every residual risk needs an owner and either a treatment or a recorded acceptance.

| ID | Residual risk | Owner | Treatment or acceptance | Revisit |
| --- | --- | --- | --- | --- |
| T9-W-34 | The support listener at counter 5 answers an inventory request and a reboot request from anything that can send it a datagram |  |  |  |
| T9-W-36 | Anyone who can reach the operator listener can ask for a Release approval |  |  |  |
| T9-W-37 | An unauthorized pause or withdrawal is an attack on availability |  |  |  |
| T7-W-22 | The service holds the Operational Device CA key, so compromising the service mints devices |  |  | Read again after the severe incident scenario |

`T9-W-35` is not used. The row was reserved for the case where the TF-PSA-Crypto backport could not be applied, and it applied.

## Open findings

| Finding | Where it lives | Why it is recorded and not fixed |
| --- | --- | --- |
| The signed `supported_until` in each release manifest rolls forward with every release, while the Support period is fixed |  |  |

Add any residual risk or open finding your own work found. A tier that produces none has usually not looked.
