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
