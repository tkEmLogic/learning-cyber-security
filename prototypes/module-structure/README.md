# Module structure prototype

This is a throwaway prototype for
[Prototype the Docmost course module](https://github.com/tkEmLogic/learning-cyber-security/issues/15),
whose title still names the wiki the course was going to be published to. The
directory was called `docmost-hardening-tier` for the same reason and has been
renamed, because what it fixes is the structure of a tier module and that was
never about the delivery target.

It compares three structures for Tier 3, **Require authentic firmware images**.
The technical content is intentionally the same. The information order and
learner flow are different.

The selected candidate combines the variants in this order:

1. Variant C for the incident and attack.
2. Variant A for the hardening procedure.
3. Variant B for evidence and weakness tracking.

The course is read on GitHub and is no longer published to Docmost, so the
Docmost round-trip artifacts that sat beside these files have been removed:
a rendered `index.html` preview and a `mermaid-probe.md` that tested whether a
fenced Mermaid block survived a paste. Both were about a delivery target the
course no longer has, and the probe's own finding was already superseded when
the live instance turned out to render Mermaid correctly.

What is left is the structural comparison, which is not about Docmost at all.
`selected-cab.md` is named in section 14 of `docs/course-specification.md` as
the reference example for every core and advanced module, and
`docs/agents/course-module-template.md` points writers at it.

## Read the comparison

Read the three variants as Markdown:

- `variant-a-linear-procedure.md`
- `variant-b-evidence-first.md`
- `variant-c-incident-mission.md`

and `selected-cab.md` for the combination that was chosen. A rendered
side-by-side viewer used to live here as `index.html`; it was a Docmost-era
convenience and reading the files directly loses nothing now that the course is
read on GitHub.

## Prototype question

Which structure best helps a learner:

1. Understand the inherited weakness.
2. Run a safe attack demonstration.
3. Add one focused control.
4. Compare the behavior before and after hardening.
5. Update the weakness ledger and security evidence pack.
6. Prepare for an informal mentor review.

The final course module will be rewritten from the selected structure. This
prototype is not production course material.
