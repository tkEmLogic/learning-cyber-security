#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

mkdir -p build/tmp
export TMPDIR="$repo_root/build/tmp"
python=python3
if [[ -x build/python/bin/python ]]; then
	python=build/python/bin/python
fi

printf '+ go test ./...\n'
go test ./...

printf '+ go vet ./...\n'
go vet ./...

printf '+ bash -n course scripts/*.sh\n'
bash -n course scripts/*.sh

printf '+ python3 scripts/validate-json.py\n'
"$python" scripts/validate-json.py

printf '+ go run ./tools/course --repo %s validate\n' "$repo_root"
go run ./tools/course --repo "$repo_root" validate

printf '+ scripts/check-markdown.sh\n'
scripts/check-markdown.sh

printf '+ scripts/check-secrets.sh\n'
scripts/check-secrets.sh

printf 'Tier 0 host verification passed.\n'
printf 'Hardware flash: pending\n'
printf 'Hardware serial: pending\n'
printf 'Altered-image device execution: pending\n'
