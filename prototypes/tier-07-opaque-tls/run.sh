#!/usr/bin/env bash
#
# PROTOTYPE. Throwaway runbook for the issue #157 spike. Not a course command.
#
# ./course does not know about this application and deliberately is not taught
# about it: adding a firmware variant to internal/courseapp for a spike would be
# production code written for throwaway firmware. This script does by hand the
# three things ./course would have done, with the same arguments it uses, and it
# says which of them run in the container and which run on the host.
#
#   ./run.sh build    in the container: sysbuild, then imgtool sign
#   ./run.sh flash    on the host: esptool writes the primary slot only
#   ./run.sh server   on the host: the spike server that demands a client cert
#   ./run.sh console  on the host: watch the board
#
# The bootloader on the board is left alone. It is the Tier 6 one, it already
# holds the Release public key, and the spike image is signed with the matching
# private half so that bootloader will run it.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
container=${SPIKE_CONTAINER:-tier2-validate}
container_repo=/workspaces/learning-cyber-security
workspace=/opt/zephyr-workspace
build_dir="$workspace/build/tier-07-spike"
app_rel=prototypes/tier-07-opaque-tls/firmware
signed="$repo_root/build/tmp/tier-07-spike.bin"

# The pinned esptool. Host board I/O needs 5.4.0 and the host workspace venv
# does not carry it, so the path is a variable rather than an assumption.
esptool=${SPIKE_ESPTOOL:-}
device=$(ls /dev/serial/by-id/* 2>/dev/null | head -1 || true)

# Signing arguments, copied from internal/courseapp so the image the bootloader
# sees is shaped exactly like a Tier 6 release.
version=0.6.0+0
header_size=0x20
slot_size=1835008
align=4
security_counter=3
revision_tlv=0x00A0
primary_slot=0x20000

build() {
	local revision
	revision=$(git -C "$repo_root" rev-parse HEAD)
	if ! git -C "$repo_root" diff --quiet HEAD; then
		revision="$revision-dirty"
	fi

	podman exec "$container" env \
		ZEPHYR_WORKSPACE="$workspace" \
		COURSE_FIRMWARE_APP="$app_rel" \
		COURSE_FIRMWARE_CONF="$container_repo/.course-state/firmware/tier-06-factory.conf" \
		COURSE_CA_INC_DIR="$container_repo/.course-state/firmware/anchor" \
		COURSE_RELEASE_KEY_INC_DIR="$container_repo/.course-state/firmware/anchor" \
		ZEPHYR_BUILD_DIR="$build_dir" \
		"$container_repo/scripts/build-zephyr-baseline.sh"

	mkdir -p "$repo_root/build/tmp"
	podman exec "$container" "$workspace/.venv/bin/python" \
		"$workspace/bootloader/mcuboot/scripts/imgtool.py" sign \
		--version "$version" \
		--header-size "$header_size" \
		--slot-size "$slot_size" \
		--align "$align" \
		--security-counter "$security_counter" \
		--custom-tlv "$revision_tlv" "$revision" \
		--key "$container_repo/.course-secrets/signing/release.pem" \
		"$build_dir/firmware/zephyr/zephyr.bin" \
		"$container_repo/build/tmp/tier-07-spike.bin"
	printf 'Signed spike image: %s\n' "$signed"
}

flash() {
	if [[ -z "$esptool" ]]; then
		printf 'Set SPIKE_ESPTOOL to a pinned esptool 5.4.0.\n' >&2
		exit 1
	fi
	if [[ -z "$device" ]]; then
		printf 'No board on /dev/serial/by-id.\n' >&2
		exit 1
	fi
	# The primary slot only. Writing the bootloader as well would replace the
	# one that verifies signatures with whatever sysbuild produced, and the
	# storage partition holding the Factory key is not touched by either.
	"$esptool" --chip esp32c6 -p "$device" write-flash "$primary_slot" "$signed"
	printf 'esptool leaves the chip in the ROM download loader. Reset the board.\n'
}

server() {
	go run "$repo_root/prototypes/tier-07-opaque-tls/server" \
		-pki "$repo_root/.course-secrets/pki" "$@"
}

console() {
	if [[ -z "$device" ]]; then
		printf 'No board on /dev/serial/by-id.\n' >&2
		exit 1
	fi
	python3 -m serial.tools.miniterm "$device" 115200
}

case "${1:-}" in
build) build ;;
flash) flash ;;
server)
	shift
	server "$@"
	;;
console) console ;;
*)
	printf 'usage: %s build|flash|server|console\n' "$0" >&2
	exit 1
	;;
esac
