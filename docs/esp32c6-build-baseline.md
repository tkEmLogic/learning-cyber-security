# ESP32-C6 build baseline

This baseline checks that the Reference product can build with Zephyr and MCUboot before Tier 0 application work starts.

It uses Zephyr 4.4.2, MCUboot 2.4.0, Zephyr SDK 1.0.1, and board target `esp32c6_devkitc/esp32c6/hpcore`.

The build uses unsigned MCUboot because this is the Tier 0 baseline. It does not enable image signatures, downgrade prevention, serial recovery, secure boot, flash encryption, or any eFuse change.

## External workspace

Keep the Zephyr workspace outside this Git repository because it contains large third-party source trees and toolchains.

The recommended way to provision this baseline is the repo's dev container
(`.devcontainer/`), which pins Zephyr, MCUboot, and the SDK inside a Podman
container and keeps the workspace on a named volume across rebuilds. See
`.devcontainer/README.md`. The manual steps below are what that container
automates, kept here for hosts that cannot use it.

The validated workspace was `/home/tarjeik/.copilot/session-state/5a5f49b5-28f2-476f-b367-fdb9c04354ac/files/zephyr-v4.4.2` for the host build, and `/opt/zephyr-workspace` inside the dev container for the physical hardware validation below.

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

Connect one ESP32-C6 board and identify its serial device before flashing.

Do not guess when several serial adapters are present. Use a stable path under `/dev/serial/by-id`.

Flash the combined sysbuild image with:

```bash
ZEPHYR_WORKSPACE=/path/to/zephyr-v4.4.2 \
"$ZEPHYR_WORKSPACE/.venv/bin/west" flash -d "$ZEPHYR_WORKSPACE/build/reference-product-baseline"
```

Pass the sysbuild **top-level** build directory (the one containing
`domains.yaml`), not the nested per-domain directory
(`.../reference-product-baseline/reference-product-baseline`). Passing the
nested directory silently flashes only the application image and skips
MCUboot, leaving stale or absent boot firmware on the device.

Flashing this baseline writes normal flash only. Do not run any eFuse, secure boot, flash encryption, or debug-disable command.

### Validated on physical hardware

Validated using the repo's dev container (`.devcontainer/`, Podman) against a
**nanoESP32-C6 1.0 board (Muse Lab)**, identified by esptool as an ESP32-C6
(QFN40, chip revision v0.1), connected over its onboard USB-Serial/JTAG
adapter at a stable path under `/dev/serial/by-id/` (host-specific serial
number redacted).

Build and flash commands were exactly the two shown above, run from
`ZEPHYR_WORKSPACE=/opt/zephyr-workspace` inside the container. Both MCUboot
(64 KiB at offset `0x000000`) and the application (at `0x020000`) were
written and verified by esptool.

Serial capture after a board reset showed the expected boot sequence:

```
ESP-ROM:esp32c6-20220919
...
I (soc_init): MCUboot 2nd stage bootloader
...
I (boot): Loading image 0 - slot 0 from flash, area id: 2
*** Booting Zephyr OS build v4.4.2 ***
ESP32-C6 Reference product: intentionally unsecured Tier 0
Board: esp32c6_devkitc/esp32c6/hpcore
Tier 0 boot mode: unsigned MCUboot with swap using scratch
Synthetic shared device identifier: beacon-development-shared
Prepared HTTP assignment endpoint: /v1/releases/current
Prepared HTTP status endpoint: /v1/devices/beacon-development-shared/events
Beacon state: steady, toggle period: 0 ms
Hardware note: Wi-Fi, HTTP transfer, flash, serial, and LED output require physical validation
```

This confirms the unsigned MCUboot baseline boots the Reference product
application on real hardware.

**Console fix required.** The `esp32c6_devkitc/esp32c6/hpcore` board's
default console is the physical `uart0` pins, which are not wired to the
DevKitC's/nanoESP32's onboard USB connector, so the application's `printk`
output was not visible over it (only the ROM/MCUboot's own early boot
messages appeared, since those print unconditionally over
USB-Serial/JTAG). Fixed by adding a board overlay
(`firmware/reference-product-baseline/boards/esp32c6_devkitc_esp32c6_hpcore.overlay`)
that enables the chip's built-in `usb_serial` (USB-Serial/JTAG) UART node and
routes `zephyr,console`/`zephyr,shell-uart` to it, so logs are visible on the
same connector already used to build and flash. No extra USB-UART adapter is
needed.

**LED hardware mapping.** Zephyr's `esp32c6_devkitc_hpcore` board devicetree
defines no LED node at all (only a user button and a watchdog alias). The
nanoESP32-C6 1.0 board has an onboard RGB LED, but on this board revision it
is wired to the 3V3 rail instead of 5V, so **the onboard LED does not work on
this hardware regardless of firmware**; this is a board wiring limitation,
not something a Zephyr driver or devicetree overlay can fix. No LED
implementation ticket is warranted against this board revision. A different
ESP32-C6 board (or an external LED wired correctly) would be needed to
validate the beacon LED behavior described in `firmware/reference-product-baseline/src/main.c`.

**Wi-Fi, HTTP, and OTA remain unimplemented, not just untested.** The
checked-in application (`main.c`) only prints its intended Wi-Fi/HTTP
endpoints and a beacon state name; it contains no actual Wi-Fi connection,
HTTP client, or OTA download code to exercise. Physical validation of Wi-Fi
association, the HTTP assignment/status exchange, OTA image download, and
execution of an altered (updated) image all remain pending until that
functionality is implemented — this is a gap in the firmware, not a hardware
limitation. The smallest next step is an implementation ticket to add Wi-Fi
connection and the HTTP client calls the log lines already advertise, before
any of those hardware claims can be validated.

