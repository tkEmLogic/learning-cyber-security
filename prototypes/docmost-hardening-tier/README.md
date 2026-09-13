# Docmost hardening-tier prototype

This is a throwaway prototype for
[Prototype the Docmost course module](https://github.com/tkEmLogic/learning-cyber-security/issues/15).

It compares three structures for Tier 3, **Require authentic firmware images**.
The technical content is intentionally the same. The information order and
learner flow are different.

The selected candidate combines the variants in this order:

1. Variant C for the incident and attack.
2. Variant A for the hardening procedure.
3. Variant B for evidence and weakness tracking.

Import `selected-cab.md` for the Docmost round-trip test.

The first round-trip showed that fenced Mermaid source remained intact but
rendered as a code block in the tested Docmost sandbox. The selected candidate
therefore uses a plain-text flow diagram.

That finding is superseded. The live Docmost instance renders a fenced
`mermaid` block as a diagram. Course material may use Mermaid. This prototype
is left as written, because it is a record of what the round-trip found.

## Open the comparison

Open `index.html` in a browser.

Use the bottom switcher, the left and right arrow keys, or these URLs:

- `index.html?variant=A` for the linear procedure
- `index.html?variant=B` for the evidence-first review sheet
- `index.html?variant=C` for the incident-driven mission

## Test the Markdown in Docmost

Import these files separately:

- `variant-a-linear-procedure.md`
- `variant-b-evidence-first.md`
- `variant-c-incident-mission.md`
- `selected-cab.md`
- `mermaid-probe.md`, which tests whether Mermaid renders when pasted

Export each page back to Markdown. Check headings, tables, code blocks, links,
and the Mermaid diagram. Record any changes caused by import or export.

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
