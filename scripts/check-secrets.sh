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

# Anchor includes are placeholders in the repository and are generated at build
# time into ignored state. A tracked one carrying a byte list means a generated
# file was committed over a placeholder, and from Tier 6 one of those files
# holds a private key.
#
# This is the enforcement point for the compiled-in credential exception in
# docs/fixture-safety-contract.md. The exception permits the key to reach one
# firmware build; it does not permit the key to reach the repository, and a
# rule with no enforcement point is a wish.
#
# It catches a committed trust anchor and a committed release public key by the
# same rule, because none of the three belongs in a commit.
while IFS= read -r file; do
	[[ -z "$file" ]] && continue
	case "$file" in
	*/anchor/*.inc) ;;
	*) continue ;;
	esac
	if grep -qE '0x[0-9a-fA-F]{2},' "$file"; then
		printf 'Anchor include %s carries a byte list. Generated anchors belong in ignored state, never in a commit.\n' "$file" >&2
		exit 1
	fi
done <<< "$files"

printf 'Secret checks passed.\n'
