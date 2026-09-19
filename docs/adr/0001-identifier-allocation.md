---
status: accepted
---

# Security claim, requirement and control identifiers are allocated once and never reused

The course numbers its security claims (`SC-<nn>`), requirements (`REQ-<nn>`) and controls (`CTL-<nn>`) in one flat sequence per kind, across all tiers, and a Learner carries these identifiers in their own Security evidence pack from the tier that introduces one onward. An identifier is therefore a permanent name, not a position in a list: once a tier that names it is published, that identifier means one thing forever, and it is never reassigned to a different claim, requirement or control, even after it is withdrawn.

Two rules follow, and both were applied when issue #186 repaired the Tier 1 to Tier 7 chains.

**A withdrawn identifier stays dead.** Tier 5 published `CTL-07` for the control Tier 1 had already planned as `CTL-05`. The repair renamed it to `CTL-05`, because Tier 1's planned control describes exactly what Tier 5 built, and a Learner whose record said `planned` needed the tier that implements it to say so. `CTL-07` was not then recycled for the next new control: Tier 6 keeps `CTL-08` and `CTL-09`, and Tier 7 keeps `CTL-10` and `CTL-11`. There is a permanent hole at `CTL-07`, and the next new control after Tier 7 is `CTL-12`. Renumbering Tier 6 and Tier 7 downwards to close the hole was rejected: it would rewrite four identifiers in two published tiers so that a sequence looks tidy, and it would break every Learner record that already used them.

**A requirement or control invented after Tier 1 is stated in the tier that introduces it, not backfilled into Tier 1.** `REQ-07` is stated in Tier 6 and `REQ-08` in Tier 7. Tier 1 records what Tier 1's analysis produced, and the register grows by observation: the course already says this out loud for `SC-06` in Tier 6 and `SC-07` in Tier 7, and Tier 6 restored a missing Tier 1 weakness row in its own ledger rather than reaching back into Tier 1. Backfilling would also silently change a page that Learners have already forked.

A future writer who finds the gap at `CTL-07`, or a requirement table in Tier 1 that stops at `REQ-06`, should leave both alone.
