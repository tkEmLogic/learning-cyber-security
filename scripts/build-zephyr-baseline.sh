#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workspace=${ZEPHYR_WORKSPACE:-"$(dirname "$repo_root")/zephyr-v4.4.2"}
build_dir=${ZEPHYR_BUILD_DIR:-"$workspace/build/reference-product-baseline"}
app_dir="$repo_root/firmware/reference-product-baseline"
west="$workspace/.venv/bin/west"

if [[ ! -x "$west" || ! -d "$workspace/zephyr" || ! -d "$workspace/zephyr-sdk-1.0.1" ]]; then
	printf 'Zephyr workspace is not ready: %s\n' "$workspace" >&2
	printf 'Follow docs/esp32c6-build-baseline.md before running this script.\n' >&2
	exit 1
fi

export ZEPHYR_BASE="$workspace/zephyr"
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_SDK_INSTALL_DIR="$workspace/zephyr-sdk-1.0.1"
export PATH="$workspace/.venv/bin:$PATH"

# COURSE_FIRMWARE_CONF is one generated Kconfig fragment holding the course
# Wi-Fi network, the OTA service address, and the release identity of this
# image. ./course build firmware writes it from generated state; it is never
# committed. Without it the build produces the offline default image.
#
# The fragment belongs to the application image, not to sysbuild itself, so it
# is passed with the image-scoped variable name.
west_args=(
	build
	--sysbuild
	--pristine=always
	--board esp32c6_devkitc/esp32c6/hpcore
	--build-dir "$build_dir"
	"$app_dir"
)

cmake_args=()

if [[ -n "${COURSE_FIRMWARE_CONF:-}" ]]; then
	if [[ ! -f "$COURSE_FIRMWARE_CONF" ]]; then
		printf 'Generated firmware configuration is missing: %s\n' "$COURSE_FIRMWARE_CONF" >&2
		exit 1
	fi
	extra_conf_abs="$(cd "$(dirname "$COURSE_FIRMWARE_CONF")" && pwd)/$(basename "$COURSE_FIRMWARE_CONF")"
	cmake_args+=("-Dreference-product-baseline_EXTRA_CONF_FILE=$extra_conf_abs")
fi

# MCUboot needs its console routed to the USB-Serial/JTAG peripheral too,
# otherwise its messages are invisible on this board.
cmake_args+=("-Dmcuboot_EXTRA_DTC_OVERLAY_FILE=$app_dir/sysbuild/mcuboot-console.overlay")

if [[ ${#cmake_args[@]} -gt 0 ]]; then
	west_args+=(-- "${cmake_args[@]}")
fi

"$west" "${west_args[@]}"

printf 'Build completed: %s\n' "$build_dir"
