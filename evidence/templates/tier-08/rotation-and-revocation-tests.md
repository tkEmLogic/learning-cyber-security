# Rotation and revocation tests

Copy this file into `evidence/learner/tier-08/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T8-TESTS-<your initials> |
| artifact_type | verification-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-08 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 08, synthetic_data true |
| limitations | `E-8-01` to `E-8-11` are host results and they stay host results. They are evidence about your service and, for `E-8-11`, about the firmware's code built for the host. The board rows are the evidence about your device. |

## Results

The `Observed on` column has three values. `device` means your board produced it. `host` means the fixture produced it on this machine. `host, board required` means the station or the service refused it on this machine, and a board is what made the row possible at all.

| Evidence ID | Test | Expected result | Observed on | Actual result | Record state |
| --- | --- | --- | --- | --- | --- |
| E-8-01 | Recovery with the Owner credential alone, and no press | Refused at `claim-window-open` | host | | pending |
| E-8-02 | Tier 6's shared-image identity as the device half of a recovery | Refused at `identifier-consistent` | host | | pending |
| E-8-03 | Renewal onto the key that is already certified | Refused at `key-unused` | host | | pending |
| E-8-04 | Renewal that nobody asked for, early in the certificate's life | Refused at `renewal-due` | host | | pending |
| E-8-05 | Operational certificate the owner revoked | Refused at `certificate-active`, clause 2 | host | | pending |
| E-8-06 | Factory certificate the manufacturer blocked, at the claim endpoint | Refused at `certificate-active`, clause 2 | host | | pending |
| E-8-07 | Revoked device presenting its own unrevoked certificate | Refused at `device-unrevoked` | host | | pending |
| E-8-08 | Transferred device presenting its old certificate before a new claim | Refused at `certificate-active`, clause 2 | host | | pending |
| E-8-09 | Decommissioned board presenting its own certificate | Refused at `device-in-service` | host | | pending |
| E-8-10 | Decommissioned board enrolling again under a new identifier | Refused at `hardware-in-service` | host | | pending |
| E-8-11 | A release dated far in the future, on a native_sim build of the firmware's floor code | The device's own certificate is refused, and stays refused after a reset | host | | pending |
| E-8-12 | Tier 8 over the air onto the Tier 7 identity | Succeeds. Both fingerprints unchanged, slot A current, an `activation` record | device | | pending |
| E-8-13 | A verified manifest, then a trial revert | The Time floor rises to the manifest's `created_at` and keeps it after the revert | device | | pending |
| E-8-14 | A forced renewal | Succeeds. The candidate is stored in the other slot, and the `activation` record comes before the `superseded` line | device | | pending |
| E-8-15 | A reset between the candidate write and the pointer flip | The candidate is presented first after the reset, and activated | device | | pending |
| E-8-16 | The transferred board presents its old certificate | Refused at `certificate-active` on the board's console, naming the revoked serial | device | | pending |
| E-8-17 | The counter before the transfer, after it, and after the new claim, then a counter 3 release | Counter 4 all three times. Refused at `security-counter`, no image bytes requested | device | | pending |
| E-8-18 | A second owner claims the transferred board | Succeeds, with a press | device | | pending |
| E-8-19 | The Operational certificate is corrupted, then the board is reset | No Operational identity, no fallback to the Factory identity, and the record still shows the device in service | device | | pending |
| E-8-20 | Recovery by the owner of record | Succeeds as `recovered`, with no change of lifecycle state | device | | pending |
| E-8-21 | The revoked device presents its own certificate | Refused at `device-unrevoked` on the board's console | device | | pending |
| E-8-22 | The time-floor lab image, seeded past the certificate's `valid_to` | The device refuses its own certificate and asks the service nothing | device | | pending |
| E-8-23 | `provision erase`, then a storage dump | The device reports every key destroyed, and the dump still holds the Secure Storage record names | device | | pending |
| E-8-24 | Enrolling an identifier whose suffix is not the board's MAC | Refused at `identifier-matches-hardware` | host, board required | | pending |
| E-8-25 | Enrolling a new identifier while an older identity of the board is still owned in the record | Enrolled, and a `factory_loss` observation is written | host, board required | | pending |
| E-8-26 | The decommissioned board opens a claim window | Refused at `device-in-service` on the board's console | device | | pending |
| E-8-27 | The decommissioned board enrolls under a new identifier | Refused at `hardware-in-service` by the station | host, board required | | pending |
| E-8-28 | Flashing a Tier 5 image onto the enrolled board | Refused by the flash guard, and nothing is written | host, board required | | pending |
| E-8-29 | The same flash with `--destroy-identity`, then a dump | The first boot reports that it cannot mount the storage partition, and the dump holds no live identity | device | | pending |
| E-8-30 | `esptool erase-flash` over the whole part, then a read-back | Every byte of the 8 MB reads `0xFF` | device | | pending |
| E-8-31 | Remanufacture, enroll and claim | Claimed and active under a new identifier | device | | pending |
| E-8-32 | Optional. An SRAM dump after a warm reset with a Claim window open | The public halves of the Factory, Operational and pending keys are readable | device | | pending |

Fill in the actual result from your own run. A board row becomes `observed` only from the board. A host row never becomes a device result, however convincing its refusal reads.

## Where the runners wrote their records

| Field | Value |
| --- | --- |
| Evidence records written by the runners |  |
| The service's own trail |  |
| The lifecycle record |  |
| The revocation store |  |

## The three rows about the same clause

`E-8-05`, `E-8-06` and `E-8-08` are all refused at clause 2 of `certificate-active`. Three different authorities withdrew three different credentials.

| Evidence ID | Who withdrew it | What they withdrew | Reason written in `revoked.jsonl` |
| --- | --- | --- | --- |
| E-8-05 |  |  |  |
| E-8-06 |  |  |  |
| E-8-08 |  |  |  |

## The pair that shows the two revocations differ

| Field | E-8-05 | E-8-07 |
| --- | --- | --- |
| What was stopped |  |  |
| Check that refused |  |  |
| Can the device recover through its Factory identity |  |  |
| What lifts it |  |  |
