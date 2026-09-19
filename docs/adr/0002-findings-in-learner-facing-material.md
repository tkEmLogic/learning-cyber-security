---
status: accepted
---

# A finding reaches learner-facing material only when it was silent and changed a belief

Every control tier so far has found a defect in the tier before it, and the course grew a section to record them: `## What this tier found in <the earlier tier or tiers>`, section 14 of the module template. It grew with the tiers, from 175 words in Tier 5 to 641 in Tier 7, and by Tier 7 three of its five findings were firmware defects with no security content. The section had become a bug diary. This ADR records the rule that stops it, decided in issue #185 while repairing the Tier 0 to 7 content.

**A finding earns a place in section 14 only when both halves hold: it changes what a Learner believes about a trust boundary, a control's reach or the trustworthiness of evidence, and it was silent while that belief was false.** The second half is the one that does the sorting, and it is the surprising half. Tier 7 found a control that passed seventeen tests and could not fire over the wire, and a Weakness ledger row that had fallen off four tiers earlier; both sat there looking correct, and both are in. Tier 7 also found a JSON unescape bug and a key-permission intersection that each failed the first time a real handshake asked anything of them; both are out. A defect that fails loudly teaches debugging, not security, however many days it cost. The cost of finding a defect is not an argument for teaching it.

Two rules follow from the same reasoning.

**No finding is written twice.** Where a Weakness ledger row, an earlier tier's body or another tier's section 14 already carries a finding, section 14 names it in one line and links. This is what keeps Tier 5's stale trial record out of Tier 7 at length: `T5-W-26` and Tier 5's own text already tell that story, and Tier 7 telling it a third time is duplication, not emphasis.

**A defect the Learner cannot reproduce has no learner-facing home.** The Learner does not write the firmware; they build the tree they are given, so a defect already fixed in that tree is one they can never meet. If the symptom is still reachable it earns one Troubleshooting row in the tier where it appears, and nothing more. If it is not, the commit and the tracker issue are the record. A one-line mention in section 14 was rejected as a compromise: it reintroduces the diary at lower resolution and still spends the Learner's attention on a bug they cannot hit.

**A Weakness ledger row is admitted cause-blind.** A row earns its place when a risk is still present in the product the Learner carries forward and can be stated as an attack vector plus an expected result. Whether the cause was a security defect or an ordinary engineering choice is irrelevant, because the ledger records what remains true, not how it got there. A fixed bug is not a weakness. This is what keeps `T5-W-26`, a row produced entirely by a non-security defect, and `T5-W-15`, a Zephyr watchdog driver quirk. Prose under the ledger table is held to a narrower test: it earns its place only when the honest choice looks worse than the broken one, and a Learner would otherwise read the row as a bug nobody fixed.

A future writer should expect section 14 to be short, and should expect most of what a tier finds to appear nowhere a Learner can see. That is the intended outcome, not an omission. The section is still never left out: a tier that found nothing says so in one line, and says why. Tier 2 is the worked example, because Tier 1 handed it a threat model rather than an implementation, so there was nothing in it to break.
