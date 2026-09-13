#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workspace=${ZEPHYR_WORKSPACE:-"$(dirname "$repo_root")/zephyr-v4.4.2"}
build_dir=${ZEPHYR_BUILD_DIR:-"$workspace/build/reference-product-baseline"}

# COURSE_FIRMWARE_APP selects which tier's application is built, as a path
# relative to the repository root. It defaults to Tier 0, so the command and
# the output quoted on the published Tier 0 page stay exactly as they are.
#
# The script keeps its name for the same reason.
app_rel=${COURSE_FIRMWARE_APP:-firmware/reference-product-baseline}
app_dir="$repo_root/$app_rel"
app_name=$(basename "$app_dir")

if [[ ! -f "$app_dir/CMakeLists.txt" ]]; then
	printf 'No firmware application at %s\n' "$app_dir" >&2
	exit 1
fi
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
	cmake_args+=("-D${app_name}_EXTRA_CONF_FILE=$extra_conf_abs")
fi

# COURSE_CA_INC_DIR holds the generated trust anchor for tiers that verify a
# service certificate. Tier 0 never sets it. A tier that needs an anchor and
# does not get one falls back to its own empty anchor and produces an image
# that trusts nothing, which it says on the console.
if [[ -n "${COURSE_CA_INC_DIR:-}" ]]; then
	if [[ ! -f "$COURSE_CA_INC_DIR/course_ca_der.inc" ]]; then
		printf 'Generated trust anchor is missing: %s/course_ca_der.inc\n' "$COURSE_CA_INC_DIR" >&2
		exit 1
	fi
	# Exported rather than passed as a CMake cache variable: sysbuild keeps an
	# image-scoped -D<image>_VAR in its own cache and does not forward it into
	# the image build, which produced an image with no trust anchor and no
	# error. The environment reaches every image's configure step.
	COURSE_CA_INC_DIR="$(cd "$COURSE_CA_INC_DIR" && pwd)"
	export COURSE_CA_INC_DIR
fi

# MCUboot needs its console routed to the USB-Serial/JTAG peripheral too,
# otherwise its messages are invisible on this board.
cmake_args+=("-Dmcuboot_EXTRA_DTC_OVERLAY_FILE=$app_dir/sysbuild/mcuboot-console.overlay")

if [[ ${#cmake_args[@]} -gt 0 ]]; then
	west_args+=(-- "${cmake_args[@]}")
fi

"$west" "${west_args[@]}"

printf 'Build completed: %s\n' "$build_dir"
