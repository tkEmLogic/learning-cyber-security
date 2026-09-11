#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

files=$(git ls-files --cached --others --exclude-standard)

if printf '%s\n' "$files" | grep -E '(^|/)(id_rsa|id_ed25519|.*\\.key|.*\\.pem|.*\\.p12|.*\\.pfx)$'; then
	printf 'Forbidden private-key-like file is tracked.\n' >&2
	exit 1
fi

while IFS= read -r file; do
	[[ -z "$file" || "$file" == "docs/course-specification.md" ]] && continue
	if grep -nE -- '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}' "$file"; then
		printf 'Potential secret material found in %s.\n' "$file" >&2
		exit 1
	fi
done <<< "$files"

printf 'Secret checks passed.\n'
