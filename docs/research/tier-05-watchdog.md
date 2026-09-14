# Tier 5 research: does the ESP32-C6 watchdog reset a hung trial image?

Research for issue #89, a child of the Tier 5 map #86. Fact-finding only. Nothing
here was built, flashed, or run on the board; every statement below is read from
source or from Espressif documentation, and every claim names where it was read.

## Sources read

All paths starting `/opt/zephyr-workspace` are inside the long-lived `tier2-validate`
podman container, which holds the pinned workspace:

- Zephyr 4.4.2 (`/opt/zephyr-workspace/zephyr`, `VERSION` file reads 4.4.2).
- MCUboot 2.4.0 (`/opt/zephyr-workspace/bootloader/mcuboot`, tag `v2.4.0`,
  commit `6d3b3d2c38ab20c242e5b9abb04d050086383eb2`).
- Espressif HAL module (`/opt/zephyr-workspace/modules/hal/espressif`), which is
  where the ESP-IDF low-level watchdog code lives in a Zephyr build.
- ESP-IDF programming guide, Watchdogs page for ESP32-C6:
  <https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/wdts.html>

The board target is `esp32c6_devkitc/esp32c6/hpcore`, as in
`docs/esp32c6-build-baseline.md`.

## Summary for the impatient

The hardware and the drivers can do what section 6 needs, but **not with the
obvious configuration**. The Zephyr `wdt_esp32` driver always configures stage 0
of the watchdog as an *interrupt*, and its interrupt handler **feeds the
watchdog**. A trial image that hangs in a thread with interrupts still enabled is
therefore fed forever and never reset. Only a hang that also blocks interrupts
reaches the stage that resets the chip.

The fix is in the application, not the design: the timeout callback that the
driver invokes runs before the feed, so the callback must be the thing that
reboots. The five trial images and the 60-second health gate survive unchanged,
but the "hang" image has to hang in a way the course states explicitly, and the
watchdog handler has to reboot rather than rely on the hardware's second stage.

## 1. Which watchdog peripherals are exposed, and which actually reset the chip

The ESP32-C6 has three kinds of watchdog. Zephyr exposes one of them on this board.

**MWDT (Timer Group watchdogs) — exposed, and can reset the chip.**
`wdt_esp32.c` drives the two Timer Group watchdogs, instantiated from devicetree
nodes `wdt0` and `wdt1`
(`/opt/zephyr-workspace/zephyr/drivers/watchdog/wdt_esp32.c:215-221`, macro
`ESP32_WDT_INIT` at lines 183-200, binding `espressif,esp32-watchdog`). Both
nodes exist in the SoC devicetree with `status = "disabled"`
(`/opt/zephyr-workspace/zephyr/dts/riscv/espressif/esp32c6/esp32c6_common.dtsi:275`
for `wdt0` at `0x60008048`, and `:284` for `wdt1` at `0x60009048`). The dev kit
enables only `wdt0` and gives it the `watchdog0` alias
(`/opt/zephyr-workspace/zephyr/boards/espressif/esp32c6_devkitc/esp32c6_devkitc_hpcore.dts:29`
and `:78-80`). So out of the box the course has exactly one usable watchdog
device: `wdt0`, which is Timer Group 0's MWDT.

`wdt_esp32_install_timeout()` maps the Zephyr flags onto hardware actions
(`wdt_esp32.c:124-143`):

| Zephyr flag | Hardware action |
| --- | --- |
| `WDT_FLAG_RESET_SOC` | `WDT_STAGE_ACTION_RESET_SYSTEM` |
| `WDT_FLAG_RESET_CPU_CORE` | `WDT_STAGE_ACTION_RESET_CPU` |
| `WDT_FLAG_RESET_NONE` | `WDT_STAGE_ACTION_OFF` |

`WDT_STAGE_ACTION_RESET_SYSTEM` is the one that restarts the whole digital
system, so the boot ROM and then MCUboot run again. That the chip really restarts
this way is confirmed from the other end: the bootloader-side code checks for
exactly these reset reasons after a restart
(`/opt/zephyr-workspace/modules/hal/espressif/zephyr/esp32c6/src/soc_init.c:98-112`,
which tests `RESET_REASON_CORE_MWDT0`, `RESET_REASON_CORE_MWDT1`,
`RESET_REASON_CPU0_MWDT0`, `RESET_REASON_CPU0_MWDT1`, `RESET_REASON_CORE_RTC_WDT`
and `RESET_REASON_CPU0_RTC_WDT`, and logs "PRO CPU has been reset by WDT").

**RWDT (RTC watchdog) — not exposed to the application.** The Zephyr binding says
so in as many words: "ESP32 contains 3x Watchdog timers, 2x Main System Watchdog
Timer (MWDT), 1x RTC Watchdog Timer (RWDT). RWDT is not supported yet"
(`/opt/zephyr-workspace/zephyr/dts/bindings/watchdog/espressif,esp32-watchdog.yaml`).
There is no devicetree node and no Zephyr driver for it. It is used only by
bootloader and restart code — see question 5.

**XT_WDT — not available on this chip, and it never resets anything.**
`xt_wdt_esp32.c` guards itself with `#error "XT WDT is not supported"` for any SoC
series other than ESP32-S2, ESP32-S3 and ESP32-C3
(`/opt/zephyr-workspace/zephyr/drivers/watchdog/xt_wdt_esp32.c:166-176`), so it
cannot even compile for the C6. There is no `xt_wdt` node in any ESP32-C6
devicetree file in the tree. In any case it is not a system watchdog: it watches
the external 32 kHz crystal, and on failure its ISR switches the RTC slow clock
to the internal RC oscillator and calls the user callback
(`xt_wdt_esp32.c:88-111`). Its `feed` returns `-ENOSYS` (`:63-69`). It is
irrelevant to Tier 5.

**Super Watchdog (SWD) — permanently muzzled by the boot path.** The boot code
sets the SWD auto-feed bit, which stops it ever firing
(`/opt/zephyr-workspace/modules/hal/espressif/zephyr/esp32c6/src/soc_init.c:82-88`,
`super_wdt_auto_feed()`, called from
`/opt/zephyr-workspace/zephyr/soc/espressif/esp32c6/hw_init.c:41`).

## 2. Does MCUboot treat a watchdog reset as an ordinary boot?

Yes. MCUboot decides what to do from the flash trailers alone. It never reads a
reset cause when choosing a swap type.

`boot_swap_type_multi()` reads the swap state of the primary and secondary slots
and matches it against a static table
(`/opt/zephyr-workspace/bootloader/mcuboot/boot/bootutil/src/bootutil_public.c:425-470`).
The only inputs are the trailer fields `magic`, `image_ok` and `copy_done`. The
table itself is at `bootutil_public.c:105-150`. The first entry, which is the one
that applies in swap-using-offset mode (the mode the course uses everywhere, see
`docs/course-specification.md` and the `SB_CONFIG_MCUBOOT_MODE_SWAP_USING_OFFSET`
setting in each tier's `sysbuild.conf`), is:

```
.magic_secondary_slot     = BOOT_MAGIC_GOOD,
.image_ok_secondary_slot  = BOOT_FLAG_UNSET,
.copy_done_secondary_slot = BOOT_FLAG_SET,
.swap_type                = BOOT_SWAP_TYPE_REVERT,
```

That is exactly the state a trial image leaves behind when it is reset before
calling `boot_write_img_confirmed()`: the swap happened (`copy_done` set) and
nobody confirmed it (`image_ok` unset). MCUboot reverts. It makes no difference
whether the reset came from a watchdog, a power cut, a panic or the reset button,
because none of those are inputs to the decision.

MCUboot does look at reset causes in two places, and neither affects revert:

- `/opt/zephyr-workspace/bootloader/mcuboot/boot/zephyr/io.c:184-197`,
  `io_detect_pin_reset()`, compiled only under `CONFIG_BOOT_SERIAL_PIN_RESET` or
  `CONFIG_BOOT_FIRMWARE_LOADER_PIN_RESET`. It looks for `RESET_PIN` to decide
  whether to enter serial recovery.
- `/opt/zephyr-workspace/bootloader/mcuboot/boot/zephyr/include/io/io.h:68-109`,
  a Nordic-only path using `nrfx_reset_reason_get()`.
- `/opt/zephyr-workspace/bootloader/mcuboot/boot/espressif/port/esp_loader.c:123-126`
  checks for `RESET_REASON_CORE_DEEP_SLEEP`, but that file belongs to MCUboot's
  standalone Espressif port, which this course does not use; the course builds
  MCUboot as a Zephyr application through sysbuild.

For completeness, Zephyr's hwinfo driver does map every watchdog reset reason to
`RESET_WATCHDOG` (`/opt/zephyr-workspace/zephyr/drivers/hwinfo/hwinfo_esp32.c:70-88`),
so the *application* can report why it restarted even though MCUboot does not care.

## 3. Would `CONFIG_WDT_DISABLE_AT_BOOT` or a Zephyr default leave the watchdog off?

`CONFIG_WDT_DISABLE_AT_BOOT` is not the risk here. It is gated on a hidden symbol
that each driver must opt into: `HAS_WDT_DISABLE_AT_BOOT`, and the help text says
"Drivers that do not select HAS_WDT_DISABLE_AT_BOOT must ignore this option"
(`/opt/zephyr-workspace/zephyr/drivers/watchdog/Kconfig:14-36`). `Kconfig.esp32`
selects nothing of the kind (`/opt/zephyr-workspace/zephyr/drivers/watchdog/Kconfig.esp32`,
the whole file is 18 lines), and `wdt_esp32.c` never mentions the symbol. So the
option cannot even be set for this driver, let alone silently disable it.

The real answer is simpler and more important: **on ESP32-C6 the watchdog starts
off, and stays off until the application turns it on.**

- `CONFIG_WATCHDOG` has no `default y` anywhere that applies. It is a plain
  `menuconfig WATCHDOG` with no default
  (`/opt/zephyr-workspace/zephyr/drivers/watchdog/Kconfig:7-10`); the board
  defconfig (`esp32c6_devkitc_hpcore_defconfig`), the SoC `Kconfig.defconfig` files
  and MCUboot's `boot/zephyr/prj.conf` contain no `WATCHDOG` line, and neither does
  any `.conf` or `.overlay` in this repo's `firmware/` tree today.
- Even with `CONFIG_WATCHDOG=y`, driver init leaves the hardware disabled:
  `wdt_esp32_init()` calls `wdt_hal_init()` (`wdt_esp32.c:161`), and `wdt_hal_init()`
  "Disables the WDT and all of its stages"
  (`/opt/zephyr-workspace/modules/hal/espressif/components/esp_hal_wdt/wdt_hal_iram.c:62-88`
  and the doc comment at
  `/opt/zephyr-workspace/modules/hal/espressif/components/esp_hal_wdt/include/hal/wdt_hal.h:37-60`).
  The watchdog only starts when the application calls `wdt_setup()`, which reaches
  `wdt_esp32_set_config()` (`wdt_esp32.c:97-109`).

So the trial window is unprotected until the Tier 5 application explicitly enables
`CONFIG_WATCHDOG`, installs a timeout and calls `wdt_setup()`. That is a course
step to write down, not a defect.

One inherited hazard worth recording. MCUboot's Zephyr port will set up
`DT_ALIAS(watchdog0)` itself if `CONFIG_WATCHDOG` is ever enabled **in the
bootloader image**: `CONFIG_BOOT_WATCHDOG_SETUP_AT_BOOT` and
`CONFIG_BOOT_WATCHDOG_INSTALL_TIMEOUT_AT_BOOT` both default to `y` when
`WATCHDOG` is on, with `CONFIG_BOOT_WATCHDOG_TIMEOUT_MS` defaulting to 300000
(`/opt/zephyr-workspace/bootloader/mcuboot/boot/zephyr/Kconfig:1342-1378`), and
`mcuboot_watchdog_setup()` installs a `WDT_FLAG_RESET_SOC` timeout and calls
`wdt_setup()` (`/opt/zephyr-workspace/bootloader/mcuboot/boot/zephyr/watchdog.c:31-62`).
On this board `watchdog0` is `wdt0`, the same device Tier 5 wants. Today nothing
enables `CONFIG_WATCHDOG` in the bootloader, so this does not happen; if Tier 5
ever turns the watchdog on in MCUboot's config, the bootloader would hand the
application a running five-minute watchdog on the same timer.

## 4. Can the timeout exceed the 60-second health gate?

Yes, by a wide margin. No hardware cap forces the design lower.

- The MWDT clock source for the C6 is `MWDT_CLK_SRC_DEFAULT`, set in
  `wdt_hal_init()` (`wdt_hal_iram.c:81`), and for this chip
  `MWDT_CLK_SRC_DEFAULT = SOC_MOD_CLK_XTAL`
  (`/opt/zephyr-workspace/modules/hal/espressif/components/soc/esp32c6/include/soc/clk_tree_defs.h:459-462`).
  The C6's crystal is 40 MHz and only 40 MHz (`soc_caps.h:91`,
  `SOC_XTAL_SUPPORT_40M 1`; `clk_tree_defs.h:125`, `SOC_XTAL_FREQ_40M = 40`).
- Zephyr's driver uses a prescaler of 40000 (`wdt_esp32.c:29`,
  `MWDT_TICK_PRESCALER`), passed straight to `wdt_hal_init()` (`wdt_esp32.c:161`).
  40 MHz / 40000 = 1000 ticks per second, so **one tick is one millisecond** and the
  `window.max` value in milliseconds is used unscaled as a tick count
  (`wdt_esp32.c:120` stores it, `:102-103` passes it to `wdt_hal_config_stage()`).
- The stage timeout register is a full 32 bits: `wdt_stg0_hold`, bits 31:0,
  "Stage 0 timeout value, in MWDT clock cycles"
  (`/opt/zephyr-workspace/modules/hal/espressif/components/soc/esp32c6/register/soc/timer_group_struct.h:250-261`).
  The prescaler field is 16 bits, so 40000 fits (`:241-248`).

A 32-bit millisecond count is about 49.7 days. The driver's only validation is
`window.min == 0` and `window.max != 0` (`wdt_esp32.c:116-118`). A 60-second gate,
or a watchdog window comfortably longer than it, is nowhere near any limit.

What *does* need care is the multiplier at the other end. `wdt_esp32_set_config()`
programs **two** stages with the same value (`wdt_esp32.c:101-106`): stage 0 as
`WDT_STAGE_ACTION_INT` and stage 1 as the requested action. So the reset does not
happen at the instant the requested window expires; it happens when the stage
machine reaches stage 1. See the unresolved point below for how much later that
is.

## 5. Does the ESP32-C6 bootloader's own RTC watchdog interact with this?

Not during the trial window. It is switched off before the application starts, and
the code that does it is in the bootloader image only.

`config_wdt()` disables the RTC watchdog's flashboot protection, disables the RTC
watchdog itself, and then disables MWDT0's flashboot protection
(`/opt/zephyr-workspace/modules/hal/espressif/zephyr/common/soc_init.c:99-122`).
Its comment states the starting condition: "At this point, the flashboot
protection of RWDT and MWDT0 will have been automatically enabled" — that is the
ROM's doing — "We can disable flashboot protection as it's not needed anymore."
Unlike ESP-IDF, this Zephyr port has no `CONFIG_BOOTLOADER_WDT_ENABLE` equivalent
and never re-arms the RWDT for the rest of boot; it just leaves it off. This
matches the ESP-IDF guide's statement for the C6 that "by default RTC Watchdog is
disabled immediately before the user's main function"
(<https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/wdts.html>).

`config_wdt()` runs from `hardware_init()`
(`/opt/zephyr-workspace/zephyr/soc/espressif/esp32c6/hw_init.c:107-108`), and
`hardware_init()` is called only under `CONFIG_MCUBOOT` or `CONFIG_ESP_SIMPLE_BOOT`
(`/opt/zephyr-workspace/zephyr/soc/espressif/common/loader.c:331-337`); the SoC
CMakeLists compiles `hw_init.c` only when `CONFIG_BOOTLOADER_MCUBOOT` is *not* set
(`/opt/zephyr-workspace/zephyr/soc/espressif/esp32c6/CMakeLists.txt`). In this
course's layout that means it runs inside the MCUboot image and not in the
application, which is what we want: MCUboot tidies the RTC watchdog away, then
chainloads the trial image, which owns `wdt0` alone.

Two related facts that belong in the Tier 5 module rather than in a footnote:

- **A controlled reboot is itself watchdog-protected.** `sys_reboot()` on this SoC
  goes to `esp_restart()` (`/opt/zephyr-workspace/zephyr/soc/espressif/esp32c6/soc.c:56-59`),
  and `esp_restart_noos()` arms the RTC watchdog for one second with flashboot
  mode enabled, disables both Timer Group watchdogs, and then software-resets the
  CPU
  (`/opt/zephyr-workspace/modules/hal/espressif/components/esp_system/port/soc/esp32c6/system_internal.c:94-133`).
  So the "controlled reboot on failed or expired health" path cannot itself wedge:
  if it stalls, the RTC watchdog finishes the job within a second.
- **None of ESP-IDF's own watchdogs are running.** The interrupt watchdog and task
  watchdog (`components/esp_system/int_wdt.c`, task_wdt) are not in the Zephyr
  build; the Zephyr CMake integration compiles only `esp_err.c`, `clk.c`,
  `reset_reason.c` and `system_internal.c` from `esp_system`
  (`/opt/zephyr-workspace/modules/hal/espressif/zephyr/esp32c6/CMakeLists.txt:341-344`).
  Whatever the application sets up on `wdt0` is the only watchdog running.

## The finding that changes how Tier 5 must be written

This did not come from any of the five questions as asked, and it is the one that
matters most.

`wdt_esp32_set_config()` always configures stage 0 as an interrupt, regardless of
what the application asked for (`wdt_esp32.c:102`):

```c
wdt_hal_config_stage(&data->hal, WDT_STAGE0, data->timeout, WDT_STAGE_ACTION_INT);
wdt_hal_config_stage(&data->hal, WDT_STAGE1, data->timeout, data->mode);
```

and the driver's interrupt handler ends with `wdt_hal_handle_intr()`
(`wdt_esp32.c:202-212`):

```c
static void IRAM_ATTR wdt_esp32_isr(void *arg)
{
	...
	if (data->callback) {
		data->callback(dev, 0);
	}

	wdt_hal_handle_intr(&data->hal);
}
```

`wdt_hal_handle_intr()` **feeds the watchdog** before clearing the interrupt
(`/opt/zephyr-workspace/modules/hal/espressif/components/esp_hal_wdt/wdt_hal_iram.c:167-176`,
`mwdt_ll_feed()` then `mwdt_ll_clear_intr_status()`), and `mwdt_ll_feed()` "Resets
the current timer count and current stage"
(`/opt/zephyr-workspace/modules/hal/espressif/components/esp_hal_wdt/esp32c6/include/hal/mwdt_ll.h:213-222`).

The consequence for a trial image that hangs:

- If it hangs with interrupts still enabled — a `while (1) { }` in a thread, a
  deadlock on a mutex, a lost work item — the watchdog interrupt fires on schedule,
  the ISR runs, and the ISR feeds the watchdog. The chip is never reset. The image
  hangs forever with a watchdog that looks armed.
- If it hangs with interrupts masked — inside `irq_lock()`, inside an ISR, or
  spinning at a priority that starves the watchdog interrupt — the ISR cannot run,
  nothing feeds, and the stage-1 system reset fires.

The driver does call the application callback *before* feeding, so the usable
design is to treat the callback as the reset mechanism rather than the hardware's
stage 1: install a `wdt_timeout_cfg` callback that logs and reboots (or that
deliberately spins with interrupts locked so that hardware stage 1 finishes it).
Leaving `callback = NULL` and expecting `WDT_FLAG_RESET_SOC` to save a hung thread
is the trap.

## What I could not determine from sources

**How stage 1's timeout relates to stage 0's.** The Zephyr driver programs both
stages with the same tick count, so the moment of reset depends on whether the
hardware counts each stage's `hold` value as an absolute count since the last
feed, or restarts the counter at each stage. The evidence points to absolute:
ESP-IDF's interrupt watchdog sets stage 0 to `T` "Set timeout before interrupt"
and stage 1 to `2 * T` "Set timeout before reset"
(`/opt/zephyr-workspace/modules/hal/espressif/components/esp_system/int_wdt.c:119-121`
and `:134-135`), which reads naturally only if both are measured from the same
feed. I could not confirm it from the ESP32-C6 technical reference manual: the PDF
at <https://documentation.espressif.com/esp32-c6_technical_reference_manual_en.pdf>
is larger than the fetch limit I had available, and the ESP-IDF Watchdogs page
describes stage actions without stating the counter behaviour between stages.

The practical range is bounded either way: with equal stage values, a reset that
does happen lands somewhere between one and two times the configured window after
the last feed. That is enough to choose a window against a 60-second gate, but if
Tier 5 wants to quote an exact reset deadline in the module text, someone should
read the TRM's Timer Group chapter, or measure it on the board once the fixture
exists.

**Two smaller unknowns**, both low-stakes:

- `wdt_esp32_set_config()` ignores its `options` argument entirely
  (`wdt_esp32.c:97-109`), so `WDT_OPT_PAUSE_IN_SLEEP` and
  `WDT_OPT_PAUSE_HALTED_BY_DBG` have no effect. Whether the MWDT keeps counting
  while a debugger has the core halted is not stated in any source I read; it
  matters only if the course tells the Learner to break in the debugger during a
  trial boot.
- Nothing in Zephyr or MCUboot re-checks whether the application re-armed the
  watchdog after a revert. That is application behaviour to specify, not a
  behaviour to discover.
