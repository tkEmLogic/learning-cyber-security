#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
paths=("$repo_root/course-material")

if grep -RIn $'\u2014' "${paths[@]}"; then
	printf 'Learner material contains an em dash.\n' >&2
	exit 1
fi

if grep -RInE '<(div|span|section|article|table|script|style|img|br|details|summary)([[:space:]>])' "${paths[@]}"; then
	printf 'Learner material contains raw HTML.\n' >&2
	exit 1
fi

if grep -RInE '^(> \\[!|[[:space:]]{4,}[-*] )' "${paths[@]}"; then
	printf 'Learner material contains unsupported alert or deeply nested list formatting.\n' >&2
	exit 1
fi

printf 'Markdown formatting checks passed.\n'
