# Repository guidance

## Agent skills

### Issue tracker

Track planning work and specifications in GitHub Issues for
`tkEmLogic/learning-cyber-security`. See
`docs/agents/issue-tracker.md`.

### Triage labels

Uses the five default canonical triage labels (`needs-triage`, `needs-info`,
`ready-for-agent`, `ready-for-human`, `wontfix`). See
`docs/agents/triage-labels.md`.

### Domain docs

Use the single-context glossary in `CONTEXT.md` and decisions in `docs/adr/`.
See `docs/agents/domain.md`.

### Course writing

Write course material in plain English for non-native English speakers. Keep
the Markdown to the portable subset in section 20 of
`docs/course-specification.md`: no raw HTML, no GitHub alert syntax, simple
pipe tables, and one prose paragraph per source line. See
`docs/agents/course-writing.md`.

### Course module template

Every Hardening tier module follows one section order and one page shape. See
`docs/agents/course-module-template.md`.

### Publishing a tier

A tier is not published until `README.md` says it is. The tier table under
"What is published" gains a row, and the hardware sentence under "Hardware"
gains the tier if the board validated it. `course-material/index.md` and the
previous tier's Continue section are not enough on their own, because the
README is what a reader sees first and it is the only place that states which
tiers are hardware validated.

Check this in the same commit that publishes the module. Tier 5 was published
without it and the gap was found two tiers later.
