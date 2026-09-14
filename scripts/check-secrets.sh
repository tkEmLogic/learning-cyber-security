#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

files=$(git ls-files --cached --others --exclude-standard)

# Nothing under the secrets directory may be tracked or staged, ever.
#
# .gitignore already lists it, but an ignore rule is advice and "git add -f"
# walks straight through it. This check looks at what is actually staged, which
# is the thing that would reach a commit. Tier 3 puts a Release signing key
# there, so this stopped being a belt-and-braces check.
if printf '%s\n' "$files" | grep -E '^\.course-secrets/'; then
	printf 'A file under .course-secrets/ is staged or tracked. Nothing there may be committed.\n' >&2
	exit 1
fi

# Private-key-like names, by extension.
#
# This pattern used to read '.*\\.key', where the doubled backslash asked for a
# literal backslash in the filename. It matched nothing a Learner would ever
# create: release.key and release.pem both walked past it, and only id_rsa and
# id_ed25519 were caught, by name. The content check below still fired on a PEM
# body, so this was not wide open, but the extension half of it never worked.
if printf '%s\n' "$files" | grep -E '(^|/)(id_rsa|id_ed25519|[^/]*\.(key|pem|p12|pfx))$'; then
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
