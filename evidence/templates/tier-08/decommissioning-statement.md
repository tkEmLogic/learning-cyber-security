# Decommissioning statement

Copy this file into `evidence/learner/tier-08/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T8-DECOMMISSION-<your initials> |
| artifact_type | decommissioning-statement |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-08 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 08, synthetic_data true |
| limitations | This statement covers one board on a lab bench. It claims only what the chip's erase command guarantees, and nothing about physical remanence. It holds no private key and no Wi-Fi passphrase. |

## The board

| Field | Value |
| --- | --- |
| Board MAC, read with `esptool read-mac` |  |
| MAC the firmware reported at enrollment |  |
| Do the two agree |  |
| Flash size the chip reports |  |
| Flash size the course's partition map covers |  |

Say which of the two sizes you mean every time you write "the flash" below.

## The destroy that was not an erase

| Field | Value |
| --- | --- |
| What the device printed after `provision erase` |  |
| Live Secure Storage entries in the dump afterwards |  |
| Record names still present in the dump |  |
| Bytes in the storage partition that were not `0xFF` |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

## The accidental erase

| Field | Value |
| --- | --- |
| Entries the flash guard found before it refused |  |
| What the Tier 5 image printed at its first boot |  |
| Live identity entries in the dump afterwards |  |
| What the service still believed about the device |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

## The decommission record

| Field | Value |
| --- | --- |
| Identifier decommissioned |  |
| Board key written in the record |  |
| Time |  |
| Serials revoked by it |  |
| Check that refused the board on the service |  |
| Check that refused the board at the station |  |
| Observed on | device, with the station on the host |
| Record state | pending until you have run it on the board |

## The erase that counts

| Field | Value |
| --- | --- |
| Command |  |
| Bytes read back |  |
| Bytes that were not `0xFF` |  |
| What the next flash puts back on the board |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

## What was retained, and why

Nothing is deleted from the records. Map each retained category onto the record kinds that carry it.

| Retained category | Record kinds that carry it | Why it is kept |
| --- | --- | --- |
| Manufacturing |  |  |
| Support |  |  |
| Vulnerability |  |  |
| Decommissioning |  |  |

## Re-entry

| Field | Value |
| --- | --- |
| Remanufacture record, identifier and reason |  |
| New identifier enrolled |  |
| Any `factory_loss` observation written, and what it named |  |
| Owner who claimed it |  |
| Lifecycle state at the end of the tier |  |
| Observed on | device |
| Record state | pending until you have run it on the board |

## The statement

Write three sentences in your own words: what stops this board re-entering service, what the erase removed and what it did not, and what returns with the next flash.
