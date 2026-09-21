# Learner evidence

This directory is reserved for Learner evidence and is ignored by Git except for this file.

Each tier tells you which templates to copy, in its `Update the Security evidence pack` section. The pattern is the same in every tier: create the directory for the tier, then copy that tier's templates into it.

```text
mkdir -p evidence/learner/tier-00
cp evidence/templates/tier-00/*.json evidence/learner/tier-00/
```

Templates exist for Tier 0 to Tier 7. Tier 0 uses JSON records. Every tier from Tier 1 onwards uses Markdown records, so the copy command for those tiers ends in `*.md` instead.

Do not use files under `evidence/examples/` as proof of your own observation.

Run `./course evidence context` after the four Tier 0 fixtures. Copy its revision, environment identifier, marker fingerprint, and fixture paths into the records.

Run `./course evidence check` when the four Tier 0 records are complete.

Both commands cover Tier 0 only. No schema exists for the later tiers, so from Tier 1 onwards nothing checks your records for you, and the Mentor review gates are where they are read. Keeping a record honest is your own work: when you did not observe something, you record it as `pending`, and you never write down a result you did not see.
