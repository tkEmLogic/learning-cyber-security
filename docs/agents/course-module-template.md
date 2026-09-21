# Course module template

This template is for writers of course material. It is not learner-facing and
it does not belong in `course-material/`.

Read it once, then work from the heading list.

It fixes the shape settled in
[Decide the Docmost page structure for a tier](https://github.com/tkEmLogic/learning-cyber-security/issues/32)
and the section order fixed in section 14 of `docs/course-specification.md`.

The course is now read on GitHub rather than pasted into a wiki. The section
order and every writing rule survive that change. What does not survive is the
page tree and the ban on linking between course pages: a tier is one file, and
it links to the tiers and companion pages around it.

The reference example is
[`selected-cab.md`](../../prototypes/module-structure/selected-cab.md).
Reuse its structure, tone, table shapes, and command-and-expected-result
pattern. Do not copy its text, which is throwaway prototype material.

## Page rules

One Hardening tier is one repository file. All headings below live in that one
file, in this order.

- File: `course-material/tiers/tier-NN-short-name/index.md`.
- Level-1 heading: the tier name from section 11 of
  `docs/course-specification.md`, in full. For example
  `Tier 0: Build the unsecured reference product`.
- Link it from the tier table and the closing section of
  `course-material/index.md`, and from the previous tier's Continue section.
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
| Control | Tier 2 to Tier 9, Advanced Tier A, Advanced Tier B | Reproduces an attack, adds one focused control, replays the attack, tests bypasses. Tier 2 is the worked example; see "What a control tier learned from Tier 2 and Tier 3". |

Tier 10 uses a fourth shape for integrated diagnosis and regression. It is not
covered here, because nothing on the current map writes it.

### There is no lifecycle variant

`course.yml` gives every tier a `kind`, and from Tier 6 that value is
`lifecycle`. It says where the tier sits in the course arc. It does not select a
module shape, and no code reads it: the field is parsed into the tier struct in
`internal/courseapp/app.go` and nothing in the repository consumes it.

Tiers 6 to 9 are Control tiers. They reproduce an attack, add one focused
control, replay the attack and test bypasses, which is the Control variant in
full, and Tiers 5, 6 and 7 all say so in their own published text. What makes a
tier a lifecycle tier is what the control *is*, not how the module is written.
`CONTEXT.md` has held this since the beginning: a Hardening tier adds "one
focused security control or lifecycle capability".

This was asked twice before it was settled, in
[#107](https://github.com/tkEmLogic/learning-cyber-security/issues/107) and
again in
[#145](https://github.com/tkEmLogic/learning-cyber-security/issues/145). The
answer came from reading all eight published modules: the departures from this
template do not track `kind` at all. The most template-conformant module since
Tier 4 is Tier 7, a lifecycle tier, and the module that departs most is Tier 5,
a control tier. Do not ask it a third time.

## Section order

Every section is required in every variant, except section 11a, `## Reveal`,
which a tier carries only when its Predict owes one. Its heading and its slot
are fixed when it is there. "Where Predict goes" below says when a tier owes
one. It is numbered 11a rather than 12 so that every other number in this list,
and every reference to one elsewhere, keeps its meaning.

The list binds in two different strengths, and the difference is the one thing
to understand before writing a module.

**Sections 2 to 6 and 12 to 19 are the fixed spine.** Their headings are the
same string in every module. Do not reword them, do not drop them, and do not
move them. Eight published modules have never touched them, and a Learner
navigates by them.

**Sections 7 to 11 are the work band.** Their headings are tier-named by
design, so naming one after what your tier actually does is the normal case and
not a departure. A module may omit a section in this band when the tier has no
such step, and when it does it **says so in its own text**, in one line a
Learner reads, at the point where the step would have been. Section 11 already
worked this way; the duty now covers the whole band. Tier 5 discharges it well
for a step it does not build: `## Serial recovery` records outright that the
boot matrix row is not satisfied by that tier, rather than leaving it silently
absent.

**A module may insert its own sections between listed ones**, in either band,
as long as it moves no listed content out of a listed section. This is how the
list learns. Section 14 below arrived exactly that way: three tiers inserted it
in the same place before it was ever written down here.

A bare "section N" in this file means a section of *this* list. Every reference
to a section of `docs/course-specification.md` names that document, because the
two numbering schemes collide and both are in use here.

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
| 11a | `## Reveal` | Fixed, and optional |
| 12 | `## Weakness ledger after the work` | Fixed |
| 13 | `## Security claim and evidence status` | Fixed |
| 14 | `## What this tier found in <the earlier tier or tiers>` | Tier-named |
| 15 | `## Update the Security evidence pack` | Fixed |
| 16 | `## Troubleshooting` | Fixed |
| 17 | `## Informal Mentor conversation` | Fixed |
| 18 | `## Continue` | Fixed |
| 19 | `## Primary references` | Fixed |

A fixed heading is the same string in every module. Do not reword it. A
tier-named heading says what this tier actually does, so a Learner scanning the
page knows where the work is. Section 14 sits in the fixed spine but is
tier-named, because a tier may have found something in one earlier tier or in
several.

Section 9 may use more than one level-2 heading when the tier's work has two
distinct phases. Tier 0 uses two, because building the product and running the
fixtures are separate jobs.

### Where Predict goes

Level-3 headings are optional everywhere except section 7, which normally opens
with `### Predict`.

A module may lift Predict to a level-2 section of its own, placed before section
7, **when its predictions span the whole tier rather than the reproduction**.
The reason section 7 is the default home is that a control tier's answers arrive
as real output rather than as a page to compare against, which holds while the
questions are about the attack and stops holding when they are about the tier.

**A written commitment creates the debt, not the sentence that promises to
settle it.** Asking a Learner to write an answer down is itself the promise.
"You will compare them at the end" and a bare "write down your answers" owe the
same thing, so deleting the promise sentence is not a repair. A Learner who
wrote four answers down does not care which verb the page used.

**The span of the question decides where the debt is discharged, and there are
two places.**

A question that the command the Learner is about to run answers **closes itself
where the output lands**. The Predict says so in one sentence, naming the
section whose output carries each answer. There is no closing section, because
one would restate output a screen above it. Tier 0 and Tier 2 work this way.

A question about the tier as a whole owes **`## Reveal`**, placed after section
11 and before section 12. Tier 5 and Tier 6 both chose that heading and that
slot independently, and Tiers 3, 4 and 7 were brought to it. A tier that
publishes a companion answers page may discharge there instead, in a section of
its own before the exercises, which is what Tier 1 does.

**A Reveal answers, then corrects.** One or two lines per question, each answer
read out of the module's own quoted output and evidence identifiers rather than
written from memory. Then one paragraph naming the wrong answer most engineers
give and why the tier is built to correct it. Roughly 150 to 250 words. This
does not break the one-fact-one-place check below, because a Reveal is not
restating the demonstration, it is scoring a commitment. A Reveal that only
points at section numbers is an index, and it gives a Learner who got it wrong
nothing.

**Position and closure are independent.** Whether Predict is lifted to a
level-2 section is decided by span alone. Whether it owes a close is decided by
the commitment. The two rules do not interact, and a `### Predict` inside
section 7 may be closed by a level-2 `## Reveal` near the end, as long as the
Predict names it.

**A repaired tier admits the repair in one line.** A published tier must not
change under a Learner, and someone who worked that tier last month wrote
answers down. One line at the end of the Reveal tells them the answers exist
now. One line is enough for a fact that ages out.

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

The number in an identifier is one sequence running across the whole course,
not a per-tier count: `T5-W-15` is followed by `T6-W-16`. The prefix names the
tier that introduced the row and the number is only ever a unique id, so a row
added to an already-published tier takes the next free number rather than one
near its neighbours. Check the highest number in use across all modules before
adding a row. Sorting the identifiers by prefix hides a collision, because two
rows from different tiers can share a number; sort by the number instead.

**A row is admitted cause-blind.** A weakness earns a row when a risk is still
present in the product the Learner carries forward and can be stated as an
attack vector plus an expected result. Whether the cause was a security defect
or an ordinary engineering choice is irrelevant, because the ledger records what
remains true, not how it got there. A fixed bug is not a weakness, however much
it cost to find. This is the test that admits `T5-W-26`, a row produced entirely
by a non-security defect, and `T5-W-15`, a Zephyr watchdog driver quirk, without
special pleading for either. The reasoning is in
[`docs/adr/0002-findings-in-learner-facing-material.md`](../adr/0002-findings-in-learner-facing-material.md).

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

New rows are admitted by the cause-blind test in section 6. **Prose under the
table is held to a narrower test.** It earns its place only when the choice is
counter-intuitive: when the honest engineering looks worse than the broken
version, and a Learner would otherwise read the row as a bug nobody fixed.
Otherwise the row stands alone. Tier 5 has one passage that passes this test,
under `T5-W-26`, and it is the clearest statement in that tier that a message
repeated until it is wrong is not more reliable than a message sent once.

**13. Security claim and evidence status.** The claim in bold with its
identifier, then the conditions for supported, partly supported, and
unsupported. State any claim the Learner must not make, and why.

**14. What this tier found in the earlier tiers.** What exercising the previous
tier's work in a new way turned up, one bold lead sentence per finding and one
short paragraph under it, roughly 100 words. The lead sentence states the
transferable lesson, not the symptom. Say for each finding whether this tier
fixed it, named it as a limit, or handed it to a later tier, and name that tier.
A finding that belongs to an earlier tier's code says so, so a Learner who meets
the symptom knows where it lives.

**Most of what a tier finds does not belong here.** A finding is admitted only
when both halves hold: it changes what a Learner believes about a trust
boundary, a control's reach or the trustworthiness of evidence, **and** it was
silent while that belief was false. A defect that fails loudly the first time it
is exercised teaches debugging, not security, however many days it cost. Expect
this section to be short, and expect most of a tier's debugging to appear
nowhere a Learner can see. That is the intended outcome, not an omission.
[`docs/adr/0002-findings-in-learner-facing-material.md`](../adr/0002-findings-in-learner-facing-material.md)
records the decision and works through the examples.

**No finding is written twice.** Where a Weakness ledger row, an earlier tier's
body or another tier's section 14 already carries a finding, name it in one line
and link to it rather than retelling it. Telling the same story a third time is
duplication, not emphasis.

**A defect the Learner cannot reproduce has no learner-facing home.** The
Learner does not write the firmware, they build the tree they are given, so a
defect already fixed in that tree is one they can never meet. If the symptom is
still reachable, it earns one Troubleshooting row in the tier where it appears,
and nothing more. If it is not, the commit and the tracker issue are the record.
A one-line mention here is not a compromise: it reintroduces the bug diary at
lower resolution and still spends the Learner's attention on a bug they cannot
hit.

**The section is never omitted from a tier that has something to exercise.** A
tier that found nothing says so in one line, and says why. Tier 2 is the worked
example, because Tier 1 handed it a threat model rather than an implementation,
so there was nothing in it to break. The duty begins at Tier 2 for the same
reason the counting rule does: a Baseline tier has no earlier tier at all, and
an Analysis tier runs nothing, so neither can exercise a predecessor's work in a
new way. Tier 0 and Tier 1 carry no section 14 and are not departures. Every
Control tier carries one. The
section exists because three modules invented the same heading in the same place
before it was written down here, and because leaving it out silently is what let
Tiers 2, 3 and 4 read as if they had found nothing at all.

**15. Update the Security evidence pack.** The commands that create the Learner
evidence directory and copy templates, then a bullet list of what to record.
Say which records become `observed` and which stay `pending`, and never let a
host-only result replace a pending hardware field.

**16. Troubleshooting.** A two-column pipe table: Observation, First check.
Five or six rows. Close with one line on when to involve a Mentor.

**17. Informal Mentor conversation.** What to show, what to explain, and one
prepared failure case to diagnose together. State that there is no grade.

The heading is fixed, but the content depends on whether the tier ends at a
required Mentor review gate. Section 13 of `docs/course-specification.md` names
the six tiers that do: Tier 1, Tier 3, Tier 5, Tier 7, Tier 9, and Tier 10, and
`course.yml` carries the same fact as `mentor_review`. A tier with no gate says
so and offers an optional conversation, which is what Tier 0 does. A tier with a
gate says which gate it is and publishes its prompts under the four fixed
headings from section 13 of `docs/course-specification.md`: Show, Explain, Diagnose, and Plan. Every gate is still
an informal coaching conversation with no grade, so the heading does not change.

Three rules came out of writing the first gate, in Tier 3. They are the pattern
for Tier 5, Tier 7, Tier 9, and Tier 10.

**Show is one success and one failure the Mentor chooses.** Never a fixed
script. A Learner who knows in advance which failure they will demonstrate can
rehearse exactly that one, and a rehearsed demonstration checks nothing. Tier 3
has four refusals that are four identical cycles, so watching all of them
teaches nothing the first one did not: the Mentor picks one and the rest come
from evidence records.

**Publish at least one prepared failure whose symptom points somewhere other
than its cause.** Tier 3's is a bootloader built against the wrong key, where
the device refuses an image the Learner knows is theirs. Every instinct says the
image is bad and the cause is in the bootloader. That inversion is the most
valuable half hour in the tier, and it is the mistake a Learner will make for
real when they regenerate a key after flashing. A prepared failure that is
simply one of the tier's own attacks replayed is not worth the session, because
the Learner has just spent the tier running it.

**Explain always asks what the attacker can still do.** Overreading the control
is the failure mode of every control tier, not just one of them, and the
specification names it as the stated failure criterion for several. Tier 3 asks
the Learner to name three things an attacker who owns the update service
completely can still do. A Learner who cannot name one has overread the control,
and the question finds that out in seconds without anyone feeling caught out,
which section 13 of `docs/course-specification.md` explicitly asks for.

Section 13 of `docs/course-specification.md` already fixes the rest: the three
outcomes, that only safety and dependency prerequisites may block progress, and
what the Mentor review record contains. Do not reinvent any of it per tier.

**18. Continue.** The next tier's name in bold, then two or three sentences
previewing its attack.

**19. Primary references.** A pipe table with columns Reading, Level, Type,
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

## What a control tier learned from Tier 2 and Tier 3

Tier 2 was the first tier to use the Control variant against a real control, and
five things came out of it. Tier 3 was the second, and it is different in ways
Tier 2 could not show: it carries two controls rather than one, its refusal is
printed by the bootloader rather than by the application, and its attack is the
Learner inhabiting a service that Tier 2 spent a whole tier teaching them to
trust. Four of Tier 2's five survived. One needed amending, and three more
arrived.

**Decide who witnesses the refusal before writing section 10.** This is the
first question a control tier must answer, and getting it wrong reshapes the
whole tier.

Ask who performs the check, because that decides who can report it. Tier 2's
answer was the host: the fixture's own TLS client rejected the certificate, so
the fixture had a refusal of its own to narrate. Tier 3's answer is the
bootloader, so the fixture cannot narrate anything. It publishes hostile
firmware through a genuine service, every step succeeds, and its last step says
`Stop. Nothing here can refuse this image.` The Learner reads the device.

Getting this backwards produces a fixture that claims a refusal it never saw,
which `docs/fixture-safety-contract.md` already forbids but which nothing told a
writer to check for.

**Section 10 needs the point of refusal, and whoever performs the check must
supply it.** This is Tier 2's rule, amended. Tier 2 said the fixture must
supply it, which was true of a control that runs on the host and false of one
that runs on the device.

The rule underneath both is that a replay must never print a bare verdict.
Something must say which check ran, what it compared, and what it rejected. In
Tier 2 the fixture says it. In Tier 3 the bootloader says it, in more detail
than Tier 2's fixture managed, and the tier's job is to make the Learner able to
read it rather than to translate it for them. A course command that turned
`signature=none` into prose would put the Learner back to trusting a verdict.

**Budget for the work that makes a refusal observable.** It is not the control,
the Learner does not write it, and in both control tiers so far it was
discovered late and turned out to be substantial.

Tier 2 needed `./course service start --present untrusted|wrong-name`, without
which no device refusal could be produced at all. Tier 3 needed an entire
out-of-tree Zephyr module supplying a MCUboot hook, because stock MCUboot prints
one identical line for every kind of bad image and names no reason.

Two tiers out of two is a pattern rather than bad luck. A control that cannot be
observed failing cannot be taught, and the work to make it observable is
routinely as large as the control itself. A tier that plans only the control
will find this out at the worst possible moment, which is when both tiers found
it.

**One bypass per thing that can be defeated separately.** Tier 2 said one bypass
per half of the control, which held while a tier had one control with two
checks. Tier 3 has two controls and three bypasses: signing with an equally
valid key, replacing the bootloader that holds the key, and taking the key
itself. The third needs no device at all.

Write section 11 by asking what could be defeated independently, then defeating
each answer separately. Counting halves of a control is the special case, not
the rule.

**Section 13 usually moves a claim rather than supporting it.** Unchanged from
Tier 2. Tier 2 moved `SC-03` to `partly supported`, Tier 3 moves `SC-01` the
same way and names the gap as the unverified bootloader. A control tier that
reports a claim as supported should be read twice: it usually means the claim
was written too small, or a host result was allowed to stand for a device
result.

Tier 3 added one thing here. A claim can need more than one control, and when it
does, say so in a table rather than a sentence. `SC-01` needs `CTL-01` for the
device's check and `CTL-06` for the key's custody, and a Learner who sees only
the first has understood half the claim.

**A control tier inherits a control and must say what it did not touch.**
Unchanged, and Tier 3 strengthened it. Its ledger adds two new weaknesses, both
limits rather than achievements, and its section 13 lists four things a Learner
must not claim. A tier that only adds closed rows has usually not been read
carefully.

**Expect to find a bug in the previous tier.** A control tier is the first thing
to exercise the previous tier's control in a new way, and the previous tier
shipped without that exercise existing.

Tier 3 found that Tier 2's HTTPS client cannot receive a response larger than
2 KB. Every response Tier 2 ever fetched was small JSON, so nothing noticed, and
a firmware image arrives in 16 KiB TLS records. Tier 2's published behaviour was
never wrong, and a Learner who went looking would have hit it with a symptom
pointing nowhere near the cause.

Budget time for this, and when it happens, decide deliberately whether to fix
the published tier or to name the limit. Do not fix it silently: a published
tier changing underneath a Learner is its own problem.

Count only control tiers whose predecessor built something. Tier 2 could find
nothing in Tier 1, which produced a threat model rather than an implementation,
so the count starts at Tier 3. On that count, five control tiers out of five
have found something, which is why this has a section of its own. State the
counting rule in one tier only: Tier 3 states it, and later tiers give the
number and link back. Write what you found in section 14, not in a paragraph
buried in section 12, and admit it there by the test section 14 sets out.

**A control tier publishes no companion answers page.** Unchanged from Tier 2.
A control tier's work is running and reading, and its answers arrive as real
output rather than as a page to compare against. Tier 3 opens section 7 with
`### Predict`, as the template requires, and publishes no second page. Do not
add one to a control tier unless the tier asks the Learner to design something.
This says nothing about whether the Predict is closed. Every Predict is closed,
and "Where Predict goes" above says where.

## Companion answers page

A tier whose work is reasoning rather than commands may publish a second page
holding the finished answers, so the Learner commits to an answer before seeing
one. Tier 1 is the first tier to do this.

Rules for an answers page:

- One extra file, `course-material/tiers/tier-NN-short-name/answers.md`.
- It is not a module. It does not carry the 18 headings. One section per
  exercise, in the order the tier asks them.
- The module links to it, and it links back to the module.
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
## What this tier found in <the earlier tier or tiers>
## Update the Security evidence pack
## Troubleshooting
## Informal Mentor conversation
## Continue
## Primary references
```

## Before you accept a module

1. Read it as a technically capable Learner who is new to cybersecurity.
2. Check every heading against the list above, in order. Nothing enforces this,
   so it is checked by a reader or not at all. The fixed spine must match
   string for string. In the work band, check that every listed step is either
   present under a tier-specific name or declared absent in the module's own
   text.
3. Check that every command has an expected result.
4. Check that no em dash remains.
5. Check that every canonical term matches `CONTEXT.md`.
6. Check that each fact appears in exactly one place in the module.
7. Check that every attack shows its steps and its real output, not a verdict.
8. Read it rendered on GitHub and follow every link in it.
