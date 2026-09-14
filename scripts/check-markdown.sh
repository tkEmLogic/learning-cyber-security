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

# Course material links to other course pages now that the course is read on
# GitHub. A broken relative link is a dead end for a Learner, so it fails the
# build rather than waiting for someone to click it.
broken=0
while IFS= read -r source; do
	while IFS= read -r target; do
		case "$target" in
		http*|"#"*|mailto:*) continue ;;
		esac
		clean=${target%%#*}
		[[ -z "$clean" ]] && continue
		if [[ ! -e "$(dirname "$source")/$clean" ]]; then
			printf 'Broken relative link in %s: %s\n' "$source" "$target" >&2
			broken=1
		fi
	done < <(grep -oE '\]\([^)]+\)' "$source" | sed -E 's/^\]\(//; s/\)$//')
done < <(find "$repo_root/course-material" -name '*.md'; echo "$repo_root/README.md")

if [[ $broken -ne 0 ]]; then
	printf 'Learner material contains a broken relative link.\n' >&2
	exit 1
fi

printf 'Markdown formatting checks passed.\n'
