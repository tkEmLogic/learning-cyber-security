# Course module template

This template is for writers of course material. It is not learner-facing and
it does not belong in `course-material/`.

Read it once, then work from the heading list.

It fixes the shape settled in
[Decide the Docmost page structure for a tier](https://github.com/tkEmLogic/learning-cyber-security/issues/32)
and the section order fixed in section 14 of `docs/course-specification.md`.

The reference example is
[`selected-cab.md`](../../prototypes/docmost-hardening-tier/selected-cab.md).
Reuse its structure, tone, table shapes, and command-and-expected-result
pattern. Do not copy its text, which is throwaway prototype material.

## Page rules

One Hardening tier is one Docmost page and one repository file. All headings
below live on that one page, in this order.

- File: `course-material/tiers/tier-NN-short-name/index.md`.
- Page title and level-1 heading: the tier name from section 11 of
  `docs/course-specification.md`, in full. For example
  `Tier 0: Build the unsecured reference product`.
- Parent page in the wiki: `Learning Cyber Security`. Tiers are its direct
  children. Nothing sits between them.
- Environment setup does not belong in a tier. It lives on the landing page.
- Follow `course-writing.md`: plain English, no em dashes, no raw HTML, simple
  pipe tables, one prose paragraph per source line.
- Tag a command or console block `text`. Use a fenced `mermaid` block for
  diagrams.
- Use the canonical terms in `CONTEXT.md`, including their capitals: Learner,
  Mentor, Reference product, Weakness ledger, Security evidence pack, Security
  claim, Residual risk, Lab artifact.

## Tier variants

Three shapes exist. They share every heading. Only the content of five sections
changes.

| Variant | Tiers | What the tier does |
| --- | --- | --- |
| Baseline | Tier 0 | Builds the unsecured product. No control to add, no attack to defeat. Records the successful attack as its result. |
| Analysis | Tier 1 | Produces analysis artifacts. Changes no code and adds no control. Reclassifies the Tier 0 observation against threats, requirements, and planned controls. |
| Control | Tier 2 to Tier 9, Advanced Tier A, Advanced Tier B | Reproduces an attack, adds one focused control, replays the attack, tests bypasses. |

Tier 10 uses a fourth shape for integrated diagnosis and regression. It is not
covered here, because nothing on the current map writes it.

## Section order

Every section is required in every variant. The only section a tier may omit is
section 11, and only when the tier has neither a bypass to test nor a failure
behavior to show. Say why in the module when you omit it.

| # | Heading | Fixed or tier-named |
| --- | --- | --- |
| 1 | `# Tier N: <specification name>` | Tier-named |
| 2 | `## Scenario` | Fixed |
| 3 | `## Learning result` | Fixed |
| 4 | `## Safety boundary` | Fixed |
| 5 | `## Starting state` | Fixed |
| 6 | `## Weakness ledger before the work` | Fixed |
| 7 | `## Reproduce the <attack or observation>` | Tier-named |
| 8 | `## Investigate the missing boundary` | Tier-named, plural when there is more than one |
| 9 | `## <name the work this tier performs>` | Tier-named |
| 10 | `## Replay the <attack or observation>` | Tier-named |
| 11 | `## Test bypass attempts` or `## Test safety and failure behavior` | Tier-named |
| 12 | `## Weakness ledger after the work` | Fixed |
| 13 | `## Security claim and evidence status` | Fixed |
| 14 | `## Update the Security evidence pack` | Fixed |
| 15 | `## Troubleshooting` | Fixed |
| 16 | `## Informal Mentor conversation` | Fixed |
| 17 | `## Continue` | Fixed |
| 18 | `## Primary references` | Fixed |

A fixed heading is the same string in every module. Do not reword it. A
tier-named heading says what this tier actually does, so a Learner scanning the
page knows where the work is.

Section 9 may use more than one level-2 heading when the tier's work has two
distinct phases. Tier 0 uses two, because building the product and running the
fixtures are separate jobs.

Level-3 headings are optional everywhere except section 7, which always opens
with `### Predict`.

## Show the mechanism, not the verdict

This applies to the module and to the command it drives, and it is the rule
most likely to be broken by accident.

A command that performs an attack silently and prints `Result: it worked`
teaches nothing. The Learner sees an outcome and has to take it on faith.

Every course command that demonstrates something must narrate it: the numbered
steps it takes, each request it sends, each answer it gets back, and what each
answer means. The final result line is the summary, not the lesson.

If the command cannot explain itself, fix the command before writing the
module around it. The module quotes the command's real output, so the two are
one piece of work rather than two.

The same rule governs a control tier's procedure. Adding a control is not
running three commands and reporting success. Show what changed, show the
check now happening that was not happening before, and show what the attacker
sees when it fails.

## What belongs in each section

**2. Scenario.** Set the situation before naming the problem. Say what the
product does and that it works, then what is missing or what an attacker did,
then why this tier exists. End with a short list of what the Learner will do
and what they will have at the end. Warm and unhurried: this is the first
thing a Learner reads, and an abrupt opening reads as a wall rather than a
door. Six to ten short paragraphs.

For a control tier this is an incident: name the attacker's action and its
result on the Reference product. For a baseline or analysis tier nothing has
gone wrong yet, so it is a situation rather than an incident. The heading is
`## Scenario` either way, which is why it is not called an incident brief.

**3. Learning result.** A bullet list starting `After this tier, you can:`.
Each bullet is an ability the Learner can demonstrate, not a topic covered.

**4. Safety boundary.** Where the attack may be run, which network, which
credentials. State what must never be used, such as a production key. Explain
any destructive or irreversible step before its command.

**5. Starting state.** What must already work before this tier. Name the
preceding tier, the running services, and the Security evidence pack the
Learner carries in. End with one sentence naming the weakness that is still
present.

**6. Weakness ledger before the work.** A pipe table of weaknesses inherited
into this tier. Columns: Identifier, Weakness, Attack vector, Expected result,
Planned treatment. Identifiers use the form `TN-W-01`. This table is inherited
context, so it is not the Learner's own work.

**7. Reproduce the attack or observation.** Opens with `### Predict` and a
numbered list of questions the Learner answers before running anything. Then a
`### Look before you act` subsection showing a dry run. Then **one subsection
per attack**, not one list of commands. End with what the attacks share and
what to record.

Each attack subsection follows the same four beats:

1. One or two sentences on what the attack targets and why it can work.
2. The command.
3. The part of its real output that carries the lesson, in a fenced block.
   Quote what the command actually prints. Never write output from memory.
4. What it means, including what it would cost outside the lab, and the
   Weakness ledger identifiers it demonstrates with the tier that closes each.

Never present an attack as one command and one result line. A Learner who
types a command and reads a verdict has watched a magic trick. The lesson is
in the request, the answer, and the reason the answer was given.

**8. Investigate the missing boundary.** A numbered list of questions about who
authenticated what and where the check should happen. Then a trust boundary
diagram in a fenced `mermaid` block. Then one paragraph naming which actor holds
which responsibility. Put the essential meaning in the text, not only in the
diagram, because a reader who cannot see the diagram still needs the answer.

**9. The work.** Ordered steps in the order the Learner performs them. Say
where to run each command. Show the expected result after every important step.
Separate required work from optional exploration.

**10. Replay.** Rerun the same attack and show the changed result, quoting the
real output the way section 7 does. Show the point of refusal, not only that a
refusal happened: which check ran, what it compared, and what it rejected.
Then one paragraph stating plainly what the attacker still controls and what
they no longer achieve.

**11. Bypass or failure tests.** A pipe table with columns Evidence ID, Test,
Expected result, Actual result, and the Actual result column left empty for the
Learner. Evidence identifiers use the form `E-N-01`. Close with an instruction
to record an unexpected actual result before troubleshooting it, and not to
mark the Security claim supported.

**12. Weakness ledger after the work.** A pipe table with columns Weakness,
Result after this tier, Status, Evidence or next action. Status is one of
closed, reduced, transferred, accepted, or open. This table states the result
the Learner should expect to observe. Label it that way, so a Learner who
observes something else knows they went wrong. The Learner's own ledger lives
in their workspace under `evidence/learner/`, never in the wiki.

**13. Security claim and evidence status.** The claim in bold with its
identifier, then the conditions for supported, partly supported, and
unsupported. State any claim the Learner must not make, and why.

**14. Update the Security evidence pack.** The commands that create the Learner
evidence directory and copy templates, then a bullet list of what to record.
Say which records become `observed` and which stay `pending`, and never let a
host-only result replace a pending hardware field.

**15. Troubleshooting.** A two-column pipe table: Observation, First check.
Five or six rows. Close with one line on when to involve a Mentor.

**16. Informal Mentor conversation.** What to show, what to explain, and one
prepared failure case to diagnose together. State that there is no grade.

The heading is fixed, but the content depends on whether the tier ends at a
required Mentor review gate. Section 13 of `docs/course-specification.md` names
the six tiers that do: Tier 1, Tier 3, Tier 5, Tier 7, Tier 9, and Tier 10, and
`course.yml` carries the same fact as `mentor_review`. A tier with no gate says
so and offers an optional conversation, which is what Tier 0 does. A tier with a
gate says which gate it is and publishes its prompts under the four fixed
headings from section 13: Show, Explain, Diagnose, and Plan. Every gate is still
an informal coaching conversation with no grade, so the heading does not change.

**17. Continue.** The next tier's name in bold, then two or three sentences
previewing its attack.

**18. Primary references.** A pipe table with columns Reading, Level, Type,
Learning question, Where to read. Level is Required or Optional.

## Variant differences

Only these five sections differ between variants.

| Section | Baseline | Analysis | Control |
| --- | --- | --- | --- |
| 7 Reproduce | Run the fixtures and record that they succeed. The attack working is the expected result. | Reread the Tier 0 evidence. Nothing is run, so the subsections explain records rather than requests. | Run the attack against the inherited product. |
| 9 The work | Build the product and run the fixtures. Often two level-2 sections. | Produce the analysis artifacts: product and asset model, actors, trust boundaries, misuse scenarios, risk register, claims, planned controls. | Add one focused control, then publish and install an approved release. |
| 10 Replay | State that no control exists yet and link forward to the next tier. | Reclassify the same observation against threats, requirements, and planned controls. Do not claim technical rejection. | Rerun the attack and show it failing. |
| 11 Tests | Safety and failure behavior, not bypasses. | Completeness of the analysis, such as every asset and actor appearing in the risk register. | Bypass attempts against the new control. |
| 13 Claim | No positive Security claim. Say so plainly. | No claim reaches supported. | The claim the control supports, with its limits. |

An analysis tier must state in its Scenario and its Learning result that
it changes no code and adds no control, so a Learner does not expect the device
to behave differently afterwards.

## Companion answers page

A tier whose work is reasoning rather than commands may publish a second page
holding the finished answers, so the Learner commits to an answer before seeing
one. Tier 1 is the first tier to do this.

Rules for an answers page:

- One extra file, `course-material/tiers/tier-NN-short-name/answers.md`, and one
  extra Docmost page created by hand as a child of the tier page.
- It is not a module. It does not carry the 18 headings. One section per
  exercise, in the order the tier asks them.
- The module refers to it by page title in bold, never by a Markdown link,
  because a pasted link does not become a Docmost page link.
- Every answer shows the wrong version beside the right one. The wrong versions
  are the answers engineers actually write, not strawmen, and each one carries
  the reason it fails.
- The page states that it is one worked model and not a marking scheme, and
  tells the Learner to record the differences rather than copy the answer.

## Skeleton

```text
# Tier N: <specification section 11 name>

## Scenario
## Learning result
## Safety boundary
## Starting state
## Weakness ledger before the work
## Reproduce the <attack or observation>
### Predict
## Investigate the missing boundary
## <name the work this tier performs>
## Replay the <attack or observation>
## Test bypass attempts
## Weakness ledger after the work
## Security claim and evidence status
## Update the Security evidence pack
## Troubleshooting
## Informal Mentor conversation
## Continue
## Primary references
```

## Before you accept a module

1. Read it as a technically capable Learner who is new to cybersecurity.
2. Check every heading against the list above, in order.
3. Check that every command has an expected result.
4. Check that no em dash remains.
5. Check that every canonical term matches `CONTEXT.md`.
6. Check that each fact appears in exactly one place in the module.
7. Check that every attack shows its steps and its real output, not a verdict.
8. Paste it into Docmost and check that the structure survives.
