# Claims, controls and residual risk

Copy this file into `evidence/learner/tier-08/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T8-CLAIM-<your initials> |
| artifact_type | security-claim |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-08 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 08, synthetic_data true |
| limitations | A claim moves on evidence, not on work done nearby. A response to a copied key is not support against one, and a host refusal is not a device result. |

## What you must not claim

Write these first, before the claim movements, in your own words. There are three: about a revoked credential, about a destroyed key, and about the Time floor.

| Statement you must not make | Why it is false in this course | Evidence that shows it |
| --- | --- | --- |
|  |  |  |
|  |  |  |
|  |  |  |

## The claim movements

One claim is new, one keeps its status and closes two gaps, three gain evidence or lose ground without moving, and one is untouched. Revise the records you already hold. Do not create a second record for a claim that already has one.

| ID | Claim | Status before | Status after | Evidence | Gap that remains |
| --- | --- | --- | --- | --- | --- |
| SC-02 | The device installs only the release the manufacturer currently approves, and never an earlier one | partly_supported | partly_supported |  |  |
| SC-03 | The device exchanges updates and status only with the genuine update service, and the network can neither read nor change what they exchange | supported | supported |  |  |
| SC-04 | A status report can only be produced by the device it names | partly_supported | partly_supported |  |  |
| SC-06 | Each device's private key is generated on that device, never leaves it, and no credential permits enrolling a second device in its name | partly_supported | partly_supported |  |  |
| SC-07 | A device obtains an operational identity only through a physical action on that device and an authenticated owner, and only that owner's authority applies to it | partly_supported | partly_supported |  |  |
| SC-08 | A credential stops authorizing a device when the authority behind it is withdrawn, whether by revocation, renewal, transfer or decommissioning, and a device leaves service only by a recorded act | (new) |  |  |  |

`SC-06` keeps its status and is weakened in substance. Record the new gap beside the two it already had.

## The new requirement

`REQ-09` is new, because the claim under it is new. Add this row to your own requirement table, in the form Tier 1 used.

| ID | Requirement | Acceptance criterion | Supports |
| --- | --- | --- | --- |
| REQ-09 | A credential the service has withdrawn no longer authorizes the device, and a device leaves service only by a recorded act | A request carrying a revoked, superseded or withdrawn credential, or from a decommissioned device, is refused by a named check and recorded as refused | SC-08 |

## Controls

None of these was planned in Tier 1, so each is recorded directly as `implemented`.

| ID | Control | Meets requirement | Status before | Status after | Evidence |
| --- | --- | --- | --- | --- | --- |
| CTL-12 | Revocation: the Owner revokes a certificate or a device, the manufacturer blocks a Factory serial, and `certificate-active` and `device-unrevoked` refuse them | REQ-09 | (new) | implemented |  |
| CTL-13 | Renewal with a bounded overlap: `renewal-due`, `key-unused`, and superseding the old certificate on `activation` | REQ-09 | (new) | implemented |  |
| CTL-14 | Decommissioning: the `decommission` record, `device-in-service` and `hardware-in-service`, and re-entry only through remanufacture | REQ-09 | (new) | implemented |  |
| CTL-15 | The Time floor: the device refuses its own lapsed Operational certificate | REQ-09 | (new) | implemented |  |
| CTL-16 | `owner-of-record`, which gates transfer and recovery authorization | REQ-08 | (new) | implemented |  |

No control in this course has reached `verified`, and this tier does not change that.

## Residual risks

Every residual risk needs an owner and either a treatment or a recorded acceptance.

| ID | Residual risk | Owner | Treatment or acceptance | Revisit |
| --- | --- | --- | --- | --- |
| T7-W-20 | Narrowed. Revocation status lives only at the service. The device judges its own Operational certificate against the Time floor, but cannot see an expiry later than the last release it verified |  |  | Accepted for the core course |
| T7-W-21 | Rewritten. The Owner credential is a bearer token. Its holder can revoke and transfer the owner's devices without the device. Taking over a device still needs physical presence |  |  | Accepted for the core course: the operator is the lab host's user |
| T8-W-28 | A pre-Tier-6 image at an equal security counter erases a Tier 6 or Tier 7 board's identities |  |  | Closed for Tier 8 boards by counter 4. Open for Tier 7 boards |
| T8-W-29 | Whoever holds the Release signing key can end every Operational credential by dating a manifest in the future |  |  |  |
| T8-W-30 | The station trusts the firmware's own MAC report at enrollment |  |  |  |
| T8-W-31 | A copied Operational key can renew onto a fresh key, and whichever copy renews first keeps the identity |  |  |  |
| T8-W-32 | A transfer names no recipient, so whoever next presses the button with any Owner credential becomes the owner |  |  |  |
| T8-W-33 | A warm reset leaves key material in SRAM that reads out over the USB cable with no debugger |  |  | Recorded limit |

Several rows you inherited widen in this tier rather than closing. Record the widening against the rows you already hold, in their own scope, instead of opening new ones here.

Add any residual risk your own work found. A tier that produces none has usually not looked.
