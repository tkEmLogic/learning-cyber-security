# ESP32-C6 build baseline

This baseline checks that the Reference product can build with Zephyr and MCUboot before Tier 0 application work starts.

It uses Zephyr 4.4.2, MCUboot 2.4.0, Zephyr SDK 1.0.1, and board target `esp32c6_devkitc/esp32c6/hpcore`.

The build uses unsigned MCUboot because this is the Tier 0 baseline. It does not enable image signatures, downgrade prevention, serial recovery, secure boot, flash encryption, or any eFuse change.

## External workspace

Keep the Zephyr workspace outside this Git repository because it contains large third-party source trees and toolchains.

The validated workspace was `/home/tarjeik/.copilot/session-state/5a5f49b5-28f2-476f-b367-fdb9c04354ac/files/zephyr-v4.4.2`.

Set `ZEPHYR_WORKSPACE` if your workspace is in another location.

## Provision the pinned environment

Install the Zephyr host packages for your operating system first. The validation host needed `python3-devel`, `gperf`, `dtc`, and `libusb1-devel` in addition to Git, CMake, Ninja, ccache, a C compiler, and XZ support.

Run these commands from the parent directory that will contain the external workspace:

```bash
export ZEPHYR_WORKSPACE="$PWD/zephyr-v4.4.2"
python3 -m venv "$ZEPHYR_WORKSPACE/.venv"
"$ZEPHYR_WORKSPACE/.venv/bin/python" -m pip install --upgrade pip west
"$ZEPHYR_WORKSPACE/.venv/bin/west" init \
  -m https://github.com/zephyrproject-rtos/zephyr.git \
  --mr v4.4.2 \
  "$ZEPHYR_WORKSPACE"
cd "$ZEPHYR_WORKSPACE"
"$ZEPHYR_WORKSPACE/.venv/bin/west" update hal_espressif mcuboot mbedtls
"$ZEPHYR_WORKSPACE/.venv/bin/west" packages pip --install
"$ZEPHYR_WORKSPACE/.venv/bin/west" zephyr-export
"$ZEPHYR_WORKSPACE/.venv/bin/west" blobs fetch hal_espressif
cd "$ZEPHYR_WORKSPACE/zephyr"
"$ZEPHYR_WORKSPACE/.venv/bin/west" sdk install \
  --version 1.0.1 \
  --install-dir "$ZEPHYR_WORKSPACE/zephyr-sdk-1.0.1" \
  --gnu-toolchains riscv64-zephyr-elf
```

Zephyr 4.4.2 pins MCUboot commit `6d3b3d2c38ab20c242e5b9abb04d050086383eb2`. This commit is the MCUboot 2.4.0 release.

## Build

Run this command from the repository root:

```bash
ZEPHYR_WORKSPACE=/path/to/zephyr-v4.4.2 ./scripts/build-zephyr-baseline.sh
```

The script writes generated files to `$ZEPHYR_WORKSPACE/build/reference-product-baseline`, outside the repository.

The application contains compile-time checks for every flash partition offset and size. A partition mismatch makes the build fail.

## Flash map

| Partition | Offset | Size |
| --- | ---: | ---: |
| MCUboot | `0x000000` | 64 KiB |
| System data | `0x010000` | 64 KiB |
| Primary image | `0x020000` | 1,792 KiB |
| Secondary image | `0x1e0000` | 1,792 KiB |
| Reserved LP-core image 0 | `0x3a0000` | 32 KiB |
| Reserved LP-core image 1 | `0x3a8000` | 32 KiB |
| Storage | `0x3b0000` | 192 KiB |
| Scratch | `0x3e0000` | 124 KiB |
| Coredump | `0x3ff000` | 4 KiB |

The checked-in map is `firmware/reference-product-baseline/dts/esp32c6_4m_flash_map.dtsi`.

Zephyr 4.4.2 selects a 2 MiB esptool image header by default even though this board includes an 8 MiB module and the course uses a 4 MiB partition contract. The baseline explicitly selects the 4 MiB header for both MCUboot and the application.

## Validated result

The baseline was validated on Fedora Linux 44 because that was the available host. The first release supports current Linux distributions. Ubuntu 24.04 is the CI and reference environment, not the only supported host.

The exact build command was:

```bash
./scripts/build-zephyr-baseline.sh
```

The build used Zephyr `v4.4.2` at commit `dccb09599635bdff17633fa7e9dab014b91dce90` and MCUboot 2.4.0 at commit `6d3b3d2c38ab20c242e5b9abb04d050086383eb2`.

The supporting tool versions were west 1.5.0, Python 3.14.7, CMake 4.3.0, Ninja 1.13.2, devicetree compiler 1.7.0, Zephyr SDK 1.0.1, GCC 14.3.0, and esptool 5.4.0.

The MCUboot binary was 39,600 bytes in its 64 KiB partition. The application binary was 133,364 bytes. The unsigned MCUboot image with its header and hash trailer was 133,404 bytes in the 1,792 KiB primary slot.

The resolved MCUboot configuration includes `CONFIG_BOOT_SIGNATURE_TYPE_NONE=y`, `CONFIG_BOOT_SWAP_USING_SCRATCH=y`, `CONFIG_BOOT_VALIDATE_SLOT0=y`, and `CONFIG_UPDATEABLE_IMAGE_NUMBER=1`.

The resolved application configuration includes `CONFIG_MCUBOOT_GENERATE_UNSIGNED_IMAGE=y`, `CONFIG_FLASH_LOAD_OFFSET=0x20000`, and `CONFIG_FLASH_LOAD_SIZE=0x1c0000`.

The build reports one non-fatal upstream Kconfig warning. Sysbuild calculates `MCUBOOT_UPDATE_FOOTER_SIZE`, but this small baseline does not enable the image manager that consumes the value. The warning does not affect the generated MCUboot or application images.

## Safe hardware check

Connect one ESP32-C6-DevKitC and identify its serial device before flashing.

Do not guess when several serial adapters are present. Use a stable path under `/dev/serial/by-id`.

Flash the combined sysbuild image with:

```bash
ZEPHYR_WORKSPACE=/path/to/zephyr-v4.4.2 \
ZEPHYR_BUILD_DIR=/path/to/zephyr-v4.4.2/build/reference-product-baseline \
"$ZEPHYR_WORKSPACE/.venv/bin/west" flash
```

Flashing this baseline writes normal flash only. Do not run any eFuse, secure boot, flash encryption, or debug-disable command.

No safely identifiable ESP32-C6 was connected during validation. The available USB serial devices identified themselves as Nordic, FTDI, ADI, and STMicroelectronics equipment. Physical flashing and serial output inspection remain pending.
