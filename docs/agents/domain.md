# Domain docs

This repository uses one domain context.

## Before exploring

Read:

- `CONTEXT.md` for the project glossary.
- Relevant decisions under `docs/adr/`, when that directory exists.

If a file or directory does not exist, continue without reporting it as an
error. The domain-modeling process creates these files only when there is
content to record.

## Layout

```text
/
├── CONTEXT.md
├── docs/
│   └── adr/
└── src/
```

## Vocabulary

Use the terms defined in `CONTEXT.md` in issue titles, specifications, tests,
and course material. Do not replace them with listed alternatives.

If a needed project term is missing, use the domain-modeling process to define
it before adding it to several documents.

## Decisions

Read relevant ADRs before proposing a change. State any conflict with an
existing ADR instead of silently replacing the decision.
