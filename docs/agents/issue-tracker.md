# Issue tracker: GitHub

Issues and specifications for this repository live in GitHub Issues:

`tkEmLogic/learning-cyber-security`

Use the GitHub CLI for write operations. Pass
`--repo tkEmLogic/learning-cyber-security` because the Git remote uses a local
SSH host alias.

## Conventions

- Create an issue with `gh issue create`.
- Read an issue and its comments with `gh issue view`.
- List issues with `gh issue list`.
- Comment with `gh issue comment`.
- Add or remove labels with `gh issue edit`.
- Close an issue with `gh issue close`.
- Use a file or heredoc for a multi-line issue body.

Pull requests are not a triage request surface.

## Publishing

When a skill says to publish to the issue tracker, create a GitHub issue in this
repository.

When a skill says to fetch a ticket, read the issue body, labels, assignees, and
comments.

## Wayfinding operations

The Wayfinder map is one issue. Its decision tickets are child issues.

### Map

Create one issue with the `wayfinder:map` label. Its body contains the
destination, notes, decisions so far, fog, and out-of-scope work.

### Child ticket

Create an issue with one of these labels:

- `wayfinder:research`
- `wayfinder:prototype`
- `wayfinder:grilling`
- `wayfinder:task`

Link it to the map with the GitHub sub-issues API. If sub-issues are not
available, add it to a task list in the map and put `Part of #<map>` at the top
of the child body.

### Blocking

Use GitHub's native issue dependencies. The dependency API needs the blocker's
numeric database ID, not its issue number or node ID.

If native dependencies are not available, put
`Blocked by: #<number>, #<number>` at the top of the child issue.

A ticket is unblocked when all blocking tickets are closed.

### Frontier

The frontier contains the map's open child issues that have no open blocker and
no assignee. The first issue in map order is the next issue to claim.

### Claim

Assign the ticket to the current GitHub user before doing any work.

### Resolve

1. Add the answer as a resolution comment.
2. Close the ticket.
3. Add a one-line summary and named link under the map's Decisions so far
   section.
