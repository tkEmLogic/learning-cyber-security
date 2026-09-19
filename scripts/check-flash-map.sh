#!/usr/bin/env bash
#
# The pinned 4 MiB ESP32-C6 flash map is the core-course flash contract.
# Section 6 of docs/course-specification.md fixes every offset and size and
# says to assert them in CI. This is that assertion.
#
# A bootloader larger than its partition or an application that does not fit
# its slot is a build failure, not a reason to change the map inside a tier.
# Nothing here is a style check: a changed number means a changed contract.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

# node offset size, straight from section 6's table.
expected="\
flash0 0x000000 0x400000
boot_partition 0x000000 0x010000
sys_partition 0x010000 0x010000
slot0_partition 0x020000 0x1c0000
slot1_partition 0x1e0000 0x1c0000
slot0_lpcore_partition 0x3a0000 0x008000
slot1_lpcore_partition 0x3a8000 0x008000
storage_partition 0x3b0000 0x030000
scratch_partition 0x3e0000 0x01f000
coredump_partition 0x3ff000 0x001000"

# firmware/ only, on purpose. A copy under prototypes/ is outside the contract:
# a prototype tree is thrown away when its tier lands, and trying a different
# map is one of the things a prototype is for. Asserting it there would fail the
# branch doing the exploring and would still prove nothing about what ships.
mapfile -t maps < <(find firmware -name esp32c6_4m_flash_map.dtsi | sort)

if [[ ${#maps[@]} -eq 0 ]]; then
	printf 'check-flash-map: no flash map found under firmware/\n' >&2
	exit 1
fi

status=0

# Section 6 asks for one checked-in include. Each tier carries its own copy, so
# the next best guarantee is that every copy is byte identical.
first_sum=$(md5sum "${maps[0]}" | cut -d' ' -f1)
for map in "${maps[@]}"; do
	sum=$(md5sum "$map" | cut -d' ' -f1)
	if [[ "$sum" != "$first_sum" ]]; then
		printf 'check-flash-map: %s differs from %s\n' "$map" "${maps[0]}" >&2
		status=1
	fi
done

# Parse "&node { reg = <0xAAA 0xBBB>; };" out of one file and compare the whole
# set, so an added or removed partition fails as loudly as a changed number.
for map in "${maps[@]}"; do
	actual=$(sed -n 's/^&\([a-z0-9_]*\) {$/\1/p;s/^\treg = <\(0x[0-9a-f]*\) \(0x[0-9a-f]*\)>;$/\1 \2/p' "$map" \
		| paste - - 2>/dev/null \
		| tr '\t' ' ')
	if [[ "$actual" != "$expected" ]]; then
		printf 'check-flash-map: %s does not match section 6\n' "$map" >&2
		diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
		status=1
	fi
done

if [[ $status -ne 0 ]]; then
	printf '\nThe flash map is fixed by section 6 of docs/course-specification.md.\n' >&2
	printf 'Changing it is a specification change, not a tier change.\n' >&2
	exit 1
fi

printf 'check-flash-map: %d map(s) match section 6\n' "${#maps[@]}"
