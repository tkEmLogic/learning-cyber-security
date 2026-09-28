---
status: accepted
---

# Device lifecycle state is derived from the record, and tracks authorization rather than possession

Section 8 of `docs/course-specification.md` says the provisioning record carries "the current lifecycle state: manufactured, claimed, active, transferred, revoked, or decommissioned", and `internal/courseapp/tier06.go` has declared all six since Tier 6 with the comment "Tier 8 the rest". Tier 8 is where the other four have to mean something, and issue #205 settled what.

Two decisions, and both will surprise a reader who finds the `lifecycle_state` field first.

**The record is the state; the field is a copy.** Nothing reads `lifecycle_state`. The service's reader unmarshals four fields and derives a device's standing from record kinds, and four of the six constants are referenced nowhere at all. That is not an oversight to fix by making the field load-bearing. A single current-state field in an append-only log is a read-modify-write, and Tier 6 bought its atomicity by making one `O_APPEND` write the whole state change. So the derivation over the log is the authority, the field stays and is written by that same derivation so it cannot disagree, and the module says so out loud. Deleting the field was rejected because published Tiers 6 and 7 quote output that contains it.

**A lifecycle state describes authorization, not possession.** This is the consequence a later reader is most likely to trip over. Of the five operations Tier 8 is named after, only three move a device's state. Renewal happens entirely inside the `active` self-loop, because an overlap is two certificates and one device. Recovery moves nothing and is invisible to the record, because a device that has lost its Operational key is still `claimed` or `active` as far as the log knows — the log does not know what the device is holding. That gap is where recovery lives, and stating it is better teaching than a model that pretends the five operations are five transitions.

Three smaller rulings follow from the same reasoning. `active` means a device has *used* its Operational identity at least once, not merely been issued one, which is what gives renewal a name for section 8's "proves the new identity works"; it is derived from an `activation` record appended once per Operational certificate, so `records.jsonl` stays the single authority the glossary claims it is. `transferred` is transient, written by a transfer and immediately superseded by the new owner's claim, so no device rests there — a state passed straight through is an event wearing a state's name, and section 8's list forced it. And revocation is two mechanisms kept deliberately apart, a revoked certificate serial and a revoked device, because revoking a credential and stopping a device from getting another are different acts; `revoked` is escapable only by remanufacture, since a state its own owner can lift is a suspension and should not be called revocation.

A future writer who finds four constants that nothing assigns, or a `lifecycle_state` field that no check reads, should not wire them up. The first is a list section 8 fixes and Tier 8 gives meaning; the second is documentation.
