# Remediation release evidence

Copy this file into `evidence/learner/tier-09/` and write in the copy.

This is course evidence. It does not show CRA conformity, and it is not a legal determination.

| Field | Value |
| --- | --- |
| artifact_id | T9-RELEASE-<your initials> |
| artifact_type | release-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-09 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 09, synthetic_data true |
| limitations | This record links one Remediation release to what it was built from and to what the service did with it. The Release approval is a record the service keeps. The device never checks it, and it is not Mentor approval or a conformity decision. |

## The release

| Field | Value |
| --- | --- |
| Release identifier | tier-09-remediation |
| Security counter | 6 |
| Release it replaces, and that release's counter |  |
| Source revision |  |
| Was the tree clean when it was built |  |
| Records it fixes, by vulnerability record identifier |  |

## What the release links

Every release links to its exact source revision, build manifest, SBOM, release manifest, signature evidence, test results and approval. Write the sha256 of each file as you computed it, then the digest the Release approval names.

| Artifact | File | sha256 you computed | sha256 in the Release approval | Do they match |
| --- | --- | --- | --- | --- |
| Image |  |  |  |  |
| Release manifest |  |  |  |  |
| Signature |  |  |  |  |
| Build manifest |  |  |  |  |
| Firmware SBOM |  |  |  |  |
| Test report |  |  |  |  |

| Field | Value |
| --- | --- |
| Test report result |  |
| Tests it ran |  |
| Time of the `release.approved` line in `records.jsonl` |  |
| Who the approval names as approver |  |
| What the approval does not prove |  |

## The rollout

One row for each rollout event in `records.jsonl`, in order. Include the served events for your own board.

| Time | Event kind | Release | Devices it covered | Result |
| --- | --- | --- | --- | --- |
|  | rollout.started |  |  |  |
|  | rollout.served |  |  |  |
|  | rollout.advanced |  |  |  |
|  | rollout.completed |  |  |  |

| Field | Value |
| --- | --- |
| Devices in the Canary group |  |
| What you checked before you advanced the rollout |  |
| What the board printed when it confirmed counter 6 |  |
| Did the support listener still answer after the update |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

## The withdrawal

| Field | Value |
| --- | --- |
| Release withdrawn |  |
| Time of the `release.withdrawn` line |  |
| Reason written, which names a vulnerability record |  |
| What the service answers when the withdrawn release would be offered |  |
| What the board does if an older copy of the withdrawn release reaches it |  |
| What happens to a device that never polls |  |
| Observed on | device, with the service on the host |
| Record state | pending until you have run it on the board |

## What the release path refused

Each row is a way to ship a fix outside the signed release path. Record the check that refused it, or record that nothing did.

| Attempt | Expected result | Check that refused it | Actual result | Observed on | Record state |
| --- | --- | --- | --- | --- | --- |
| E-9-01: Approve a release that is already approved | Refused |  |  | host | pending |
| E-9-02: Set a signed release that has no Release approval as the Fleet baseline, through the PUT | Refused |  |  | host | pending |
| E-9-03: Change one linked artifact after the approval, then start the release's rollout | Refused |  |  | host | pending |
| E-9-04 and E-9-05: Offer the withdrawn release again, as a rollout and as the Fleet baseline | Refused |  |  | host | pending |
| E-9-06: Advance a paused rollout | Refused |  |  | host | pending |
| E-9-07: Approve a release whose build manifest says the tree was not clean | Refused |  |  | host | pending |

Add a row for every other attempt you made. A host refusal is a result about the service, never about the device.

## The chain in one paragraph

Write one paragraph that walks from the vulnerability record to the confirmed image on your board, naming each link above in order. Then name one thing a person who can reach the operator listener can still do.
