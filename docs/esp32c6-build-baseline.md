# ESP32-C6 build baseline

This baseline checks that the Reference product can build with Zephyr and MCUboot before Tier 0 application work starts.

It uses Zephyr 4.4.2, MCUboot 2.4.0, Zephyr SDK 1.0.1, and board target `esp32c6_devkitc/esp32c6/hpcore`.

The build uses unsigned MCUboot because this is the Tier 0 baseline. It does not enable image signatures, downgrade prevention, serial recovery, secure boot, flash encryption, or any eFuse change.

MCUboot runs in swap-using-offset mode, which is the mode the whole course uses. An update is swapped into the primary slot and the displaced image is kept in the secondary slot, so a way back exists on the flash. Tier 0 never uses it: the application asks for the swap to be permanent and runs no check afterwards, so there is still no test boot and no revert. Recoverable installation belongs to Tier 5.

## The target board

The course targets the Espressif ESP32-C6-DevKitC-1.

The Zephyr board target stays `esp32c6_devkitc/esp32c6/hpcore`, because that is the upstream target for this kit. The course already used this target while it ran on a third-party ESP32-C6 board, so moving to the official kit changes no build or flash command.

| Item | ESP32-C6-DevKitC-1 |
| --- | --- |
| Flash | 8 MiB on the module. The course keeps its 4 MiB partition contract, described under Flash map. |
| Onboard LED | One addressable RGB LED on `GPIO8`. See LED hardware mapping. |
| BOOT button | `GPIO9`, the ESP32-C6 strapping pin. Same pin as on the earlier board, so button behavior is unchanged. |
| USB | Two USB Type-C ports. One is the chip's native USB-Serial/JTAG. The other is behind a separate USB-to-UART bridge chip. The course uses the native one. |
| Headers | Two 16-pin rows, `J1` and `J3`. The course uses no header pins, so the footprint does not matter to it. |

The course ran on a nanoESP32-C6 1.0 board (Muse Lab) before this. Every hardware result recorded further down was observed on that earlier board, and each one says so where it appears. Those results have not yet been repeated on the ESP32-C6-DevKitC-1.

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

The scratch partition stays reserved but is unused. Swap-using-offset needs no scratch area. Keeping the partition means the pinned flash map does not move, and the mode is selected explicitly rather than left to the default that follows from an absent scratch node.

Zephyr 4.4.2 selects a 2 MiB esptool image header by default even though the ESP32-C6-DevKitC-1 module includes 8 MiB of flash and the course uses a 4 MiB partition contract. The baseline explicitly selects the 4 MiB header for both MCUboot and the application.

## Validated result

The baseline was validated on Fedora Linux 44 because that was the available host. The first release supports current Linux distributions. Ubuntu 24.04 is the CI and reference environment, not the only supported host.

The exact build command was:

```bash
./scripts/build-zephyr-baseline.sh
```

The build used Zephyr `v4.4.2` at commit `dccb09599635bdff17633fa7e9dab014b91dce90` and MCUboot 2.4.0 at commit `6d3b3d2c38ab20c242e5b9abb04d050086383eb2`.

The supporting tool versions were west 1.5.0, Python 3.14.7, CMake 4.3.0, Ninja 1.13.2, devicetree compiler 1.7.0, Zephyr SDK 1.0.1, GCC 14.3.0, and esptool 5.4.0.

The MCUboot binary was 39,600 bytes in its 64 KiB partition. The application binary was 133,364 bytes. The unsigned MCUboot image with its header and hash trailer was 133,404 bytes in the 1,792 KiB primary slot.

The resolved MCUboot configuration includes `CONFIG_BOOT_SIGNATURE_TYPE_NONE=y`, `CONFIG_BOOT_SWAP_USING_OFFSET=y`, `CONFIG_BOOT_VALIDATE_SLOT0=y`, and `CONFIG_UPDATEABLE_IMAGE_NUMBER=1`. Sysbuild sets the matching `CONFIG_MCUBOOT_BOOTLOADER_MODE_SWAP_USING_OFFSET=y` in the application, which is what makes Zephyr's image utilities write the download one sector into the secondary slot.

The resolved application configuration includes `CONFIG_MCUBOOT_GENERATE_UNSIGNED_IMAGE=y`, `CONFIG_FLASH_LOAD_OFFSET=0x20000`, and `CONFIG_FLASH_LOAD_SIZE=0x1c0000`.

The build reports one non-fatal upstream Kconfig warning. Sysbuild calculates `MCUBOOT_UPDATE_FOOTER_SIZE`, but this small baseline does not enable the image manager that consumes the value. The warning does not affect the generated MCUboot or application images.

## Safe hardware check

Connect one ESP32-C6 board and identify its serial device before flashing.

Do not guess when several serial adapters are present. Use a stable path under `/dev/serial/by-id`.

The ESP32-C6-DevKitC-1 has two USB Type-C ports, so one board can present two serial devices. The course uses the chip's native USB-Serial/JTAG port, whose `/dev/serial/by-id` name contains `usb-Espressif_USB_JTAG_serial_debug_unit`. The other port is behind a separate USB-to-UART bridge chip and carries a different name. Flashing, the serial console, and on-chip debugging all use the native port.

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

This validation was run before the course moved to the ESP32-C6-DevKitC-1. It
is kept exactly as it was observed. It has not been repeated on the
ESP32-C6-DevKitC-1 yet.

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
I: Starting bootloader
I: Bootloader chainload address offset: 0x20000
I: Jumping to the first image slot
*** Booting Zephyr OS build v4.4.2 ***
ESP32-C6 Reference product: intentionally unsecured Tier 0
Image label: baseline
Running release: tier-00-baseline
Board: esp32c6_devkitc/esp32c6/hpcore
Tier 0 boot mode: unsigned MCUboot, swap using offset, no test boot, no rollback
Synthetic shared device identifier: beacon-development-shared
OTA service: http://192.168.68.81:8080
Beacon state: steady, toggle period: 0 ms
```

**Console fix required.** The `esp32c6_devkitc/esp32c6/hpcore` board's
default console is the physical `uart0` pins, which are not wired to the
board's native USB-Serial/JTAG connector, so the application's `printk`
output was not visible over it (only the ROM/MCUboot's own early boot
messages appeared, since those print unconditionally over
USB-Serial/JTAG). Fixed by adding a board overlay
(`firmware/reference-product-baseline/boards/esp32c6_devkitc_esp32c6_hpcore.overlay`)
that enables the chip's built-in `usb_serial` (USB-Serial/JTAG) UART node and
routes `zephyr,console`/`zephyr,shell-uart` to it, so logs are visible on the
same connector already used to build and flash. No extra USB-UART adapter is
needed.

The overlay keeps the console on the native USB-Serial/JTAG port on the
ESP32-C6-DevKitC-1 as well. That kit's second USB Type-C port is behind a
USB-to-UART bridge chip, and the course does not use it, so one connector
still carries flashing, logs, and debugging.

MCUboot needed the same treatment separately
(`firmware/reference-product-baseline/sysbuild/mcuboot-console.overlay`,
passed to the mcuboot image by `scripts/build-zephyr-baseline.sh`). MCUboot
also logs nothing by default, so its config enables info-level logging in
minimal mode. The deferred default buffers messages and loses them if the
bootloader stops, which is exactly when they are needed.

## Validated network and update behavior

The following was observed on the same nanoESP32-C6 1.0 board, with the local
OTA service bound to the host's private address on the same Wi-Fi network.

| Behavior | Result |
| --- | --- |
| Wi-Fi station association, WPA2-PSK, 2.4 GHz | Observed |
| DHCP address assignment | Observed |
| `POST /v1/devices/<id>/events` accepted by the service | Observed |
| `GET /v1/releases/current` read and parsed | Observed |
| `GET /v1/firmware/<name>` written to the secondary slot | Observed, 590,396 bytes |
| MCUboot installing the downloaded image | Observed |
| Altered image running after the install | Observed |
| Downgrade back to the baseline release | Observed |
| Onboard LED | Not available on the nanoESP32-C6 board used for this run |

The device joined a 2.4 GHz WPA2 network. The ESP32-C6 radio does not support
5 GHz. A network that publishes the same name on both bands works, because the
driver scans every channel and associates on the band it can use.

A complete update looked like this on the console:

```
ota.assignment release_id=tier-00-altered version=0.0.0-altered image=tier-00-altered.bin
ota.assignment differs from running release tier-00-baseline, installing without any check
ota.install starting release_id=tier-00-altered version=0.0.0-altered size=590412
ota.install declared_sha256=... (Tier 0 does not check it)
ota.install wrote 590412 bytes to the secondary slot
ota.upgrade requested a permanent swap, no test boot, no rollback
Rebooting into the newly installed image
...
I: Image index: 0, Swap type: perm
I: Primary image: magic=good, swap_type=0x3, copy_done=0x1, image_ok=0x1
I: Secondary image: magic=good, swap_type=0x3, copy_done=0x3, image_ok=0x1
I: Boot source: none
I: Starting swap using offset algorithm.
I: Bootloader chainload address offset: 0x20000
I: Jumping to the first image slot
...
Image label: altered
Running release: tier-00-altered
Beacon state: fast, toggle period: 200 ms
```

The device accepted firmware from an unauthenticated service with no
signature and no publisher identity. That is the Tier 0 weakness `T0-W-04`.
Resetting the fixture returns the service to the baseline release, and the
device installs the older release just as readily, which is `T0-W-06`.

### A software reset hangs MCUboot on this SoC

The first working download did not produce a working update. MCUboot printed
its flash banner and stopped, and the board recovered only by a manual reset
back into the old image.

An on-chip debug session found the cause. Attaching OpenOCD over the board's
built-in USB-Serial/JTAG and halting the hung bootloader gave this stack:

```
regi2c_write_mask_impl
clk_ll_bbpll_set_config
rtc_clk_bbpll_configure
rtc_clk_cpu_freq_set_config
esp32_cpu_clock_configure
clock_control_esp32_init
z_sys_init_run_level (INIT_LEVEL_PRE_KERNEL_1)
```

MCUboot was not in its update path at all. It hung while configuring the CPU
clock, before reaching any of its own code.

Zephyr's `sys_reboot()` on this SoC ends in `esp_restart()`, which resets the
processor but deliberately leaves the BBPLL running so the ROM can keep
logging. MCUboot then tries to configure a PLL that is already on, and the
register write never completes. Every hang followed `rst:0xc (SW_CPU)`, and
every clean boot followed a hard reset from esptool.

The fix is in the application. It calls `esp_rom_software_reset_system()`,
which resets the whole digital system and returns the clocks to their
power-on state, so MCUboot starts exactly as it does after a power cycle.
See `course_reset_system()` in
`firmware/reference-product-baseline/src/main.c`.

Three MCUboot upgrade modes were tried before the debug session, and all three
hung identically, which is what pointed away from the upgrade path. None of
them was broken: the reset was.

The baseline first shipped on overwrite-only because it was the simplest mode
and matched the Tier 0 posture. It moved to swap-using-offset once the course
needed one upgrade mode for every tier, and the move was validated on the board
rather than assumed: the altered-image install was run end to end, MCUboot
printed `Starting swap using offset algorithm.`, the altered image booted, and
the fixture reset swapped the baseline back.

### Debugging the board

The dev container installs Espressif's OpenOCD fork, because the Zephyr SDK
ships an OpenOCD with Xtensa ESP32 targets only and the ESP32-C6 is RISC-V.
Start a debug session with:

```bash
"$ZEPHYR_WORKSPACE/openocd-esp32/bin/openocd" \
  -s "$ZEPHYR_WORKSPACE/openocd-esp32/share/openocd/scripts" \
  -f board/esp32c6-builtin.cfg
```

Then attach from another shell, choosing the ELF for whichever image you are
debugging:

```bash
"$ZEPHYR_WORKSPACE/zephyr-sdk-1.0.1/gnu/riscv64-zephyr-elf/bin/riscv64-zephyr-elf-gdb" \
  -ex "target extended-remote :3333" -ex "monitor halt" -ex "bt" \
  "$ZEPHYR_WORKSPACE/build/reference-product-baseline/mcuboot/zephyr/zephyr.elf"
```

This uses the same USB connector as flashing and the serial console. No extra
probe is needed.

### Host access to the board

Two host-side problems block the container from reaching the board, and both
look like a missing group at first.

The invoking user must be able to open the serial device. On a host where the
user is not in `dialout`, add the user to that group, or grant access for the
current session with `setfacl -m u:$USER:rw /dev/ttyACM0`.

On an SELinux host such as Fedora, the container is denied access to
`tty_device_t` even when the user has permission. The dev container passes
`--security-opt=label=disable` for this reason. The alternative is the
`container_use_devices` SELinux boolean on the host.

The stable `/dev/serial/by-id` path is mounted into the container rather than
passed with `--device`, because an Espressif USB-JTAG serial number is a MAC
address and the colons in it cannot be expressed in podman's `host:container`
device syntax.

### LED hardware mapping

Zephyr's `esp32c6_devkitc_hpcore` board devicetree defines no LED node at all
(only a user button and a watchdog alias), so the beacon LED needs a
devicetree overlay in this repository rather than an upstream alias.

The ESP32-C6-DevKitC-1 has one addressable RGB LED on `GPIO8`. It is a
WS2812-style device driven over a single data line, not a plain GPIO output,
so the firmware drives it through an addressable LED driver instead of
toggling a pin.

The earlier nanoESP32-C6 1.0 board could not do this at all. Its onboard RGB
LED is wired to the 3V3 rail instead of 5V on that board revision, so it did
not light regardless of firmware, which is why the hardware run recorded above
lists the onboard LED as not available. That was a board wiring limitation,
not something a Zephyr driver or devicetree overlay could fix.

On the ESP32-C6-DevKitC-1 the LED was watched during the Tier 0 run (#224).
It showed solid green for steady, red blinking fast for the fast state, and red
blinking slowly for the slow state, so the colour order in the driver is right.
The board boots normally with `GPIO8`, a strapping pin, driving the LED.
Channel value 24 was too bright to look at comfortably, and 8 is now the
default. The Reference product reports its simulated machine state on the
serial console as well, and that console output stays the primary record.
