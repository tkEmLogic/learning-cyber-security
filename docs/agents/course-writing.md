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

## Docmost-compatible Markdown

- Use normal headings, paragraphs, links, blockquotes, lists, and fenced code
  blocks.
- Use simple pipe tables.
- Avoid raw HTML, MDX, GitHub alert syntax, and deeply nested lists.
- Mermaid renders in Docmost. Use a fenced `mermaid` block for flow and trust
  boundary diagrams. A plain-text diagram, a simple table, or an imported image
  remains acceptable where it reads better.
- Put essential meaning in text, even when a diagram also shows it.
- Use descriptive link text and relative links for repository content.
- Keep each prose paragraph on one source line. The tested Docmost importer
  preserves source line wraps as visible hard breaks.

## Review

Before accepting course material:

1. Read it as a technically capable learner who is new to cybersecurity.
2. Remove unexplained terms and indirect instructions.
3. Split long sentences and paragraphs.
4. Check that no em dash remains.
5. Import a representative document into Docmost.
6. Export it to Markdown and check that the structure remains clear.
