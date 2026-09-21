# Course writing

Write all learner-facing material for embedded software engineers who may not
be native English speakers.

## Plain English

- Use short, direct sentences.
- Prefer common words.
- Use active voice.
- State one main idea per sentence.
- Keep paragraphs short.
- Make each instruction explicit.
- Define a necessary technical term before using it without explanation.
- Avoid idioms, jokes, culture-specific references, and esoteric language.
- Do not use em dashes. Use a full stop, comma, colon, or a new sentence.
- Do not use a complex word when a simple word has the same meaning.
- Use US spelling: `behavior`, `recognize`, `labeled`, `skeptical`. The section
  11 heading `## Test safety and failure behavior` is fixed spine and cannot be
  reworded, so the choice is already made. Never change spelling inside quoted
  output, a command, a path, an identifier or the title of an external reading.
- Keep every prose sentence under 50 words. Tiers 6 and 7 drifted past that with
  two and three colon-joined clauses; Tiers 0 to 3 never did, so the target is
  already in the course.

The 2026-09 review found idiom, spelling and sentence length in eight published
modules, and the first rule in that list had been written here since the
beginning. A rule nobody checks is not a rule, so the three tests below are the
ones to actually run, and none of them can be answered by reading the list
above.

**The idiom test is a reader, not a word list.** Ask whether a competent
engineer reading English as a second language gets the meaning on the first
pass. "A stranger who found it in a skip", "the factory canteen" and "sit with
that" all passed a search for jokes and slang and failed a reader.

**Replace an idiom, never delete it.** The course's voice is one of its
strengths, and a pass that flattens every sentence into instructions costs more
than the idioms do. Keep the work the sentence was doing.

**Measure sentence length, do not eyeball it.** Script it over prose, excluding
fenced blocks and table rows. Eight sentences were over the limit and none of
them looked long in place.

## Procedures

- Give steps in the order the learner performs them.
- State where to run each command.
- Show the expected result after important steps.
- Explain destructive or irreversible actions before the command.
- Separate required work from optional exploration.
- Use the same name for a concept in every module.

## Markdown

Course material is read on GitHub, in the repository. A Learner forks the
repository and works through the material in their own copy, so the material
and the code they are changing are the same checkout.

- Use normal headings, paragraphs, links, blockquotes, lists, and fenced code
  blocks.
- Use simple pipe tables.
- Avoid raw HTML, MDX, GitHub alert syntax, and deeply nested lists.
- Mermaid renders on GitHub. Use a fenced `mermaid` block for flow and trust
  boundary diagrams. A plain-text diagram, a simple table, or an image remains
  acceptable where it reads better.
- Put essential meaning in text, even when a diagram also shows it. A reader
  who cannot see the diagram still needs the answer.
- **Link to other course pages.** Use relative repository links and descriptive
  link text. The next tier, a companion page, and the landing page should all
  be one click away. This reverses an earlier rule that existed only because
  the course was published by pasting into a wiki, where a pasted link did not
  become a page link.
- Keep each prose paragraph on one source line. It makes a diff show which
  paragraph changed, and it lets a review comment land on one idea.

## Review

Before accepting course material:

1. Read it as a technically capable learner who is new to cybersecurity.
2. Remove unexplained terms and indirect instructions.
3. Split long sentences and paragraphs.
4. Check that no em dash remains.
5. Read it rendered on GitHub, not only as source.
6. Follow every link in it.
