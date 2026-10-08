# Residual-risk summary

Copy this file into `evidence/learner/tier-10/` and write in the copy.

This summary lists every residual risk still open at the end of the core course, and says who closes it. Fill it in after the scenario and the recovery are over.

| Field | Value |
| --- | --- |
| artifact_id | T10-RISK-<your initials> |
| artifact_type | residual-risk-summary |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-10 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 10, synthetic_data true |
| limitations | Each row records who closes a risk or why it is accepted. It does not reduce the risk. A row that is accepted for the core course is still open in a real product. |

## How to fill each row

The ID and the text of each row are already written. Every other column is your judgment, and each judgment comes from your own weakness ledger. Cite the ledger row in the Treatment or acceptance column.

- **Group** is exactly one of `Advanced Tier A`, `Advanced Tier B`, `Accepted for the core course` or `Recorded limit`.
- **Owner** names who is responsible for the risk. A role is enough, such as the manufacturer's release engineer. It is never empty.
- **Treatment or acceptance** says what will close the risk, or why it is accepted for now.
- **Revisit** says the event that makes you read the row again.

Two dispositions from your ledger have no group of their own. A row marked "recheck on any Zephyr upgrade" goes into `Accepted for the core course`, with the Zephyr upgrade as its revisit trigger. A row marked "residual risk with an owner" also goes into `Accepted for the core course`, with its owner and its revisit trigger.

## The residual risks

| ID | Residual risk | Group | Owner | Treatment or acceptance | Revisit |
| --- | --- | --- | --- | --- | --- |
| T2-W-09 | The device has no clock and checks no dates on a certificate it is shown |  |  |  |  |
| T3-W-10 | The bootloader itself is unverified |  |  |  |  |
| T3-W-11 | The Release signing key lives on the same machine as the build and the service. One key signs the image and the manifest, so taking it defeats both |  |  |  |  |
| T4-W-12 | Downgrade prevention does not protect the first install |  |  |  |  |
| T4-W-13 | The security counter is compared, never remembered |  |  |  |  |
| T5-W-14 | A power cut during the health window forces a revert indefinitely |  |  |  |  |
| T5-W-15 | The watchdog depends on a driver quirk an upstream fix would change |  |  |  |  |
| T5-W-26 | A revert is reported once and nothing acknowledges it, so a board that restarts before it reaches the service never reports that revert |  |  |  |  |
| T6-W-16 | The Secure Storage encryption key is a hash of public values, and a destroyed key stays decryptable in flash |  |  |  |  |
| T6-W-17 | Stored records carry no freshness, so an older copy is accepted as authentic, and an older record rewinds the Time floor |  |  |  |  |
| T6-W-18 | The private key is protected at rest only |  |  |  |  |
| T6-W-19 | The AES-GCM nonce is drawn once per boot while the record key never changes |  |  |  |  |
| T6-W-27 | The Wi-Fi passphrase is compiled into every image this course builds |  |  |  |  |
| T7-W-20 | Authorization lifetime is enforced by the service. The device judges only its own Operational certificate, against the Time floor, and cannot see an expiry later than the last release it verified |  |  |  |  |
| T7-W-21 | The Owner credential is a bearer token. Its holder can revoke and transfer the owner's devices without touching them |  |  |  |  |
| T7-W-22 | With `--mutual-tls` the service holds a certificate authority signing key, so compromising the service mints devices |  |  |  |  |
| T7-W-23 | The claim endpoint is an oracle. Distinguishable refusals reveal whether a device exists and whether it is owned |  |  |  |  |
| T7-W-24 | The Factory credential reopens the claim path until the board is decommissioned, and its key survives on the board until a verified erase |  |  |  |  |
| T7-W-25 | Synthetic devices land in the real manufacturing record with no marker field. The naming convention is the only sign |  |  |  |  |
| T8-W-28 | A pre-Tier-6 image at an equal security counter erases a Tier 6 or Tier 7 board's identities |  |  |  |  |
| T8-W-29 | Whoever holds the Release signing key can end every Operational credential by dating a manifest in the future |  |  |  |  |
| T8-W-30 | The station trusts the firmware's own MAC report at enrollment |  |  |  |  |
| T8-W-31 | A copied Operational key can renew onto a fresh key, and whichever copy renews first keeps the identity |  |  |  |  |
| T8-W-32 | A transfer names no recipient, so whoever next presses the button with any Owner credential becomes the owner |  |  |  |  |
| T8-W-33 | A warm reset leaves key material in readable SRAM |  |  |  |  |
| T9-W-36 | Anyone who can reach the operator listener can approve a release, in any name |  |  |  |  |
| T9-W-37 | Rollout actions name their actor but do not authenticate it. An unauthorized pause or withdrawal stops a fix from reaching the fleet |  |  |  |  |
| T10-W-39 | Release test and approval never boot the image or run the fixtures, so a release that regresses a control passes approval |  |  |  |  |
| T10-W-40 | `rollout advance` does not check that the canary group names real devices or that any of them confirmed, so a rollout can skip its canary |  |  |  |  |

Add a row for any residual risk or finding your own work found. A row you add needs a group and an owner like every other row.
