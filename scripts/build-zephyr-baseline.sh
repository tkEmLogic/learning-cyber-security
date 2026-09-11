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

"$west" build \
	--sysbuild \
	--pristine=always \
	--board esp32c6_devkitc/esp32c6/hpcore \
	--build-dir "$build_dir" \
	"$app_dir"

printf 'Build completed: %s\n' "$build_dir"
