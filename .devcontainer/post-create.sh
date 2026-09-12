#!/usr/bin/env bash
# Provisions the Zephyr workspace on the persistent $ZEPHYR_WORKSPACE volume.
# Idempotent: safe to re-run on every container start. Heavy steps (west
# update, SDK install, blob fetch) are skipped once their markers exist, so a
# container rebuild does not re-download the world.
set -euo pipefail

: "${ZEPHYR_WORKSPACE:=/opt/zephyr-workspace}"
ZEPHYR_VERSION="v4.4.2"
SDK_VERSION="1.0.1"

echo "==> Provisioning Zephyr workspace at ${ZEPHYR_WORKSPACE}"

if [ ! -x "${ZEPHYR_WORKSPACE}/.venv/bin/west" ]; then
    echo "==> Creating venv and installing west"
    python3 -m venv "${ZEPHYR_WORKSPACE}/.venv"
    "${ZEPHYR_WORKSPACE}/.venv/bin/python" -m pip install --upgrade pip west
fi

WEST="${ZEPHYR_WORKSPACE}/.venv/bin/west"

if [ ! -d "${ZEPHYR_WORKSPACE}/zephyr" ]; then
    echo "==> west init (${ZEPHYR_VERSION})"
    "${WEST}" init -m https://github.com/zephyrproject-rtos/zephyr.git \
        --mr "${ZEPHYR_VERSION}" "${ZEPHYR_WORKSPACE}"
fi

cd "${ZEPHYR_WORKSPACE}"

if [ ! -f "${ZEPHYR_WORKSPACE}/.west-update.done" ]; then
    # tf-psa-crypto is a separate west project, not an mbedtls submodule. The
    # ESP32-C6 Wi-Fi driver selects MBEDTLS and PSA_CRYPTO, and the mbedtls
    # module fails to configure without it.
    echo "==> west update (hal_espressif mcuboot mbedtls tf-psa-crypto)"
    "${WEST}" update hal_espressif mcuboot mbedtls tf-psa-crypto
    touch "${ZEPHYR_WORKSPACE}/.west-update.done"
fi

if [ ! -f "${ZEPHYR_WORKSPACE}/.west-packages-pip.done" ]; then
    echo "==> west packages pip --install"
    "${WEST}" packages pip --install
    touch "${ZEPHYR_WORKSPACE}/.west-packages-pip.done"
fi

echo "==> west zephyr-export"
"${WEST}" zephyr-export

# OpenOCD for on-chip debugging over the board's built-in USB-Serial/JTAG.
# The Zephyr SDK ships an OpenOCD with Xtensa ESP32 targets only, so the
# RISC-V ESP32-C6 needs Espressif's fork.
OPENOCD_VERSION="v0.12.0-esp32-20260831"
OPENOCD_DIR="${ZEPHYR_WORKSPACE}/openocd-esp32"
if [ ! -x "${OPENOCD_DIR}/bin/openocd" ]; then
    echo "==> installing openocd-esp32 ${OPENOCD_VERSION}"
    OPENOCD_TARBALL="openocd-esp32-linux-amd64-${OPENOCD_VERSION#v}.tar.gz"
    curl -fsSL -o /tmp/openocd-esp32.tar.gz \
        "https://github.com/espressif/openocd-esp32/releases/download/${OPENOCD_VERSION}/${OPENOCD_TARBALL}"
    tar -xzf /tmp/openocd-esp32.tar.gz -C "${ZEPHYR_WORKSPACE}"
    rm -f /tmp/openocd-esp32.tar.gz
fi

if [ ! -f "${ZEPHYR_WORKSPACE}/.west-blobs.done" ]; then
    echo "==> west blobs fetch hal_espressif"
    (cd "${ZEPHYR_WORKSPACE}/zephyr" && "${WEST}" blobs fetch hal_espressif)
    touch "${ZEPHYR_WORKSPACE}/.west-blobs.done"
fi

if [ ! -d "${ZEPHYR_WORKSPACE}/zephyr-sdk-${SDK_VERSION}" ]; then
    echo "==> west sdk install ${SDK_VERSION}"
    (cd "${ZEPHYR_WORKSPACE}/zephyr" && "${WEST}" sdk install \
        --version "${SDK_VERSION}" \
        --install-dir "${ZEPHYR_WORKSPACE}/zephyr-sdk-${SDK_VERSION}" \
        --gnu-toolchains riscv64-zephyr-elf)
fi

echo "==> Go module download"
if [ -f "${WORKSPACE_ROOT:-/workspaces/learning-cyber-security}/go.mod" ]; then
    (cd "${WORKSPACE_ROOT:-/workspaces/learning-cyber-security}" && go mod download)
fi

echo "==> Python tooling (requirements.txt: PyYAML, jsonschema for host verification)"
if [ -f "${WORKSPACE_ROOT:-/workspaces/learning-cyber-security}/requirements.txt" ]; then
    python3 -m pip install --break-system-packages --quiet \
        -r "${WORKSPACE_ROOT:-/workspaces/learning-cyber-security}/requirements.txt"
fi

echo "==> Done. Build with:"
echo "    ZEPHYR_WORKSPACE=${ZEPHYR_WORKSPACE} ./scripts/build-zephyr-baseline.sh"
