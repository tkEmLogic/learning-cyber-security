# Swap-using-offset and a rejected candidate image

**Research question:** [GitHub issue #49](https://github.com/tkEmLogic/learning-cyber-security/issues/49), part of map [#48](https://github.com/tkEmLogic/learning-cyber-security/issues/48)

**Access and review date:** 14 September 2026

**Status:** Source reading. Nothing here was measured on the board. Every claim below comes from reading MCUboot 2.4.0 source or from the resolved Kconfig of a build this repository already produced. Claims that are inference are labelled as inference.

## Sources read

| Source | What was read |
| --- | --- |
| MCUboot v2.4.0 working tree at commit `6d3b3d2c38ab20c242e5b9abb04d050086383eb2`, inside the `tier2-validate` container at `/opt/zephyr-workspace/bootloader/mcuboot` | `boot/bootutil/src/loader.c`, `bootutil_loader.c`, `bootutil_area.c`, `bootutil_area.h`, `bootutil_priv.h`, `bootutil_public.c`, `image_validate.c`, `bootutil_img_hash.c`, `tlv.c`, `swap_offset.c`, `swap_misc.c`, `boot/zephyr/main.c`, `boot/zephyr/Kconfig`, `boot/zephyr/include/mcuboot_config/mcuboot_config.h`, `boot/zephyr/include/mcuboot_config/mcuboot_logging.h` |
| [MCUboot design document, v2.4.0](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/design.md) | Swap-using-offset section, swap-type tables, high-level boot procedure |
| Resolved MCUboot Kconfig for Tier 2, `/opt/zephyr-workspace/build/tier-02-authenticated-service-baseline/mcuboot/zephyr/.config` in the same container | The settings quoted below |
| `docs/esp32c6-build-baseline.md` in this repository | Pinned stack, flash map, slot sizes |

The tag is exact. `git describe --tags` in that tree returns `v2.4.0`, and the commit matches the one the baseline document records for Zephyr 4.4.2.

Line numbers below refer to MCUboot v2.4.0.

## The pinned configuration, as resolved

These are the values that actually decide the answers, read out of the built Tier 2 MCUboot `.config`:

```
CONFIG_BOOT_SWAP_USING_OFFSET=y
CONFIG_BOOT_VALIDATE_SLOT0=y
CONFIG_BOOT_SIGNATURE_TYPE_NONE=y
CONFIG_UPDATEABLE_IMAGE_NUMBER=1
CONFIG_MCUBOOT_STORAGE_WITH_ERASE=y
CONFIG_FLASH_HAS_EXPLICIT_ERASE=y
CONFIG_MCUBOOT_LOG_LEVEL_INF=y
CONFIG_MCUBOOT_LOG_LEVEL=3
CONFIG_LOG_MODE_MINIMAL=y
```

`CONFIG_MCUBOOT_STORAGE_MINIMAL_SCRAMBLE` is absent. It has no `default y` in `boot/zephyr/Kconfig`, so it is off. That matters: it decides how much of the slot gets wiped on a refusal.

`CONFIG_MCUBOOT_STORAGE_WITHOUT_ERASE` is also absent, so `MCUBOOT_SUPPORT_DEV_WITHOUT_ERASE` is never defined and `device_requires_erase(fa)` expands to the constant `(true)` (`bootutil_area.h:63-69`). MCUboot performs real flash erases, not overwrite-with-erase-value.

Tier 3 will change `CONFIG_BOOT_SIGNATURE_TYPE_NONE` to ECDSA P-256. Nothing else in this list needs to change for the answers below to hold.

## 1. What happens to the secondary slot after a refusal

**The candidate is erased. The whole slot, all 1,792 KiB of it.**

The decision path is `boot_validated_swap_type()` in `loader.c:730-751`. It reads the trailer, sees an upgrade request, and calls `boot_validate_slot()` on the secondary slot. `boot_validate_slot()` ends at `loader.c:646-659`:

```c
    if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
        BOOT_LOG_ERR("Image in the %s slot is not valid!",
                     (slot == BOOT_SLOT_PRIMARY) ? "primary" : "secondary");
        if ((slot != BOOT_SLOT_PRIMARY) || ARE_SLOTS_EQUIVALENT()) {
            boot_scramble_slot(fap, slot);
            /* Image is invalid, erase it to prevent further unnecessary
             * attempts to validate and boot it.
             */
        }
        fih_rc = FIH_NO_BOOTABLE_IMAGE;
        goto out;
    }
```

`ARE_SLOTS_EQUIVALENT()` is `0` for every swap mode (`bootutil_priv.h:190-193`), so the guard means "scramble the secondary slot, never the primary". The primary slot, the image the Learner is currently running, is never touched by a refusal.

`boot_scramble_slot()` with `MCUBOOT_MINIMAL_SCRAMBLE` off erases the entire flash area (`bootutil_area.c:363-375`):

```c
    /* Without minimal entire area needs to be scrambled */
#if !defined(MCUBOOT_MINIMAL_SCRAMBLE)
    size = flash_area_get_size(fa);
    ret = boot_scramble_region(fa, 0, size, false);
```

That reaches `boot_erase_region()` (`bootutil_area.c:195-291`), which walks the region sector by sector calling `flash_area_erase()`, feeding the watchdog after each sector. The slot's trailer, which carries the upgrade request, sits at the end of the same area and is erased with everything else.

So the answer is not "left in place", not "marked", but erased, and the request that pointed at it is erased along with it.

The candidate is **not** marked in any way that survives. `BOOT_SWAP_TYPE_FAIL` has a separate branch that writes `image_ok` into the primary trailer (`loader.c:1858-1870`), but that branch is almost unreachable here. `boot_validate_slot()` converts every content-level failure into `FIH_NO_BOOTABLE_IMAGE` at line 657, and `boot_validated_swap_type()` maps that to `BOOT_SWAP_TYPE_NONE` (`loader.c:740-746`). `BOOT_SWAP_TYPE_FAIL` is left for a flash read error or a resumed partial swap. The MCUboot design document still describes the old behaviour ("Persist failure of swap procedure to image trailers", design.md step 2), which is why the source and not the document is the authority here.

**Inference, not measured:** erasing 1,792 KiB one sector at a time on the ESP32-C6's SPI NOR flash takes a visible amount of time. At a 4 KiB sector that is 448 erase operations. The Learner is likely to see a pause between the refusal line and the boot of the primary image. Tier 3's procedure should not treat a few seconds of silence there as a hang. This has not been timed on the board and should be timed when Tier 3 is validated.

## 2. Does the next boot retry the candidate

**No. The refusal happens once. Every boot after it is a normal quiet boot of the primary slot.**

This follows directly from answer 1. The upgrade request lives in the secondary slot's trailer, and `boot_swap_type_multi()` (`bootutil_public.c:425-492`) derives the swap type from the two trailers' magic, `image_ok` and `copy_done` fields. After the erase, the secondary trailer magic reads as unset, no swap table row matches, and the function returns `BOOT_SWAP_TYPE_NONE` after printing:

```
I: Image index: 0, Swap type: none
```

`boot_validate_slot()` is then never called on the secondary slot at all, because `boot_validated_swap_type()` only calls it when `BOOT_IS_UPGRADE(swap_type)` is true. There is nothing left to refuse and nothing to print.

There is no repeating refusal loop. There is also no counter, no attempt limit and no backoff, because none is needed.

The one path that can break this is an erase that fails. `boot_scramble_slot()`'s return value is discarded at `loader.c:653`. If the flash erase failed, the candidate and its request would both survive and the refusal would repeat on every reset. Nothing in the pinned configuration makes that likely, and it is worth naming only because Tier 3's procedure should tell a Learner what a repeating refusal would mean if they ever saw one.

## 3. Does the Learner need a recovery step between hostile images

**No. No erase, no re-flash, no recovery command. The Learner publishes the next hostile image and reboots.**

MCUboot cleans up after itself, as answers 1 and 2 show. The device comes back running its unchanged primary image, with an empty secondary slot ready for the next download. The Reference product's existing OTA path writes the next candidate into that slot and calls `boot_request_upgrade()` exactly as it did the first time. `boot_set_pending_multi()` writes the request into the secondary slot's trailer (`bootutil_public.c`), which is now erased and writable.

This is the good news for the module: four hostile images in a row is a procedure of four identical cycles, publish, reboot, read the console. `./course` needs no per-attempt erase step, and the module needs no "if the board is stuck, do this" paragraph for the ordinary case.

## 4. Truncated images

**A truncated image never reaches the signature check. It is refused at the TLV header, one step earlier. At the pinned log level it prints the same single line as every other refusal.**

Swap-using-offset places the candidate one sector into the secondary slot, and MCUboot knows it. `boot_read_image_header()` in `swap_offset.c:80-101` applies `boot_img_sector_size(state, BOOT_SLOT_SECONDARY, 0)` as an offset when reading the secondary header, and `bootutil_img_hash()` and the TLV iterator both add `boot_get_state_secondary_offset()` to every read (`bootutil_img_hash.c:107-111`, `tlv.c:54-58`). Truncation does not confuse the offset, because the offset is a constant one sector, not something derived from the image.

Which check catches a truncated image depends on where the truncation falls.

**Truncated so far that nothing was written.** The header magic reads as erased flash. `boot_check_header_erased()` (`bootutil_loader.c:52-67`) returns true, `boot_validate_slot()` takes the branch at `loader.c:559`, calls `swap_scramble_trailer_sectors()` to remove the leftover upgrade request, and returns `FIH_NO_BOOTABLE_IMAGE`. **No error line is printed at all.** The board simply boots the primary image. This is the quietest possible refusal and the easiest one for a Learner to misread as "nothing happened".

**Truncated inside the header.** Fields such as `ih_img_size` read back as `0xffffffff`. `boot_check_header_valid()` (`bootutil_loader.c:69-124`) fails on the overflow check in `boot_u32_safe_add()` or on `size >= flash_area_get_size(fap)`, `boot_validate_slot()` sets `FIH_FAILURE` at `loader.c:634-636`, and the slot is erased with the standard error line.

**Truncated after the header, which is the realistic fixture.** The header is intact and still claims the full image size, so `boot_check_header_valid()` passes. `boot_check_image()` calls `bootutil_img_validate()`. That function hashes first, over the range the header claims, reading erased flash for the missing tail (`image_validate.c:258-266`). The hash succeeds as an operation and produces a wrong digest that is never compared, because the very next step fails. `bootutil_tlv_iter_begin()` reads the TLV info structure at the claimed end of the image, finds erased flash instead of `IMAGE_TLV_INFO_MAGIC`, and returns `-1` (`tlv.c:59-80`):

```c
    if (info.it_magic != IMAGE_TLV_INFO_MAGIC) {
        return -1;
    }
```

`image_validate.c:286-290` then bails out before the TLV loop:

```c
    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_ANY, false);
    if (rc) {
        BOOT_LOG_DBG("bootutil_img_validate: TLV iteration failed %d", rc);
        goto out;
    }
```

The hash TLV is never found, the signature TLV is never found, `bootutil_verify_sig()` is never called. So the answer to the ticket's question is that a truncated image does **not** reach the signature check, and it is refused by a different code path. But the second half of the question, whether that path produces different output, has an uncomfortable answer.

### The output is the same for every refusal

This is the finding that changes what Tier 3 can promise.

At `CONFIG_MCUBOOT_LOG_LEVEL=3` (info), Zephyr compiles `BOOT_LOG_DBG` out. `mcuboot_logging.h:25` maps it straight to `LOG_DBG`. Every discriminating message inside `bootutil_img_validate()`, `tlv.c`, `bootutil_find_key.c`, `image_ecdsa.c` and `bootutil_img_hash.c` is at debug level. None of them survives.

What survives is one error line, at `loader.c:649`:

```
E: Image in the secondary slot is not valid!
```

A hash mismatch, an absent signature, a signature made with the wrong key and a truncated image all produce that same line and nothing else. There is no "signature verification failed", no "hash mismatch", no "unknown key". The only refusal that looks different is the one that prints nothing.

The single exception is a swap-using-offset specific check at `loader.c:595-612`, which fires when the image was written to offset zero of the secondary slot rather than one sector in:

```
E: Secondary header magic detected in first sector, wrong upload address?
```

That is a tooling mistake, not a hostile image, but it is worth knowing because it is the one refusal message a Learner might meet that names a real cause.

**Raising the log level does not fully fix it.** With `CONFIG_MCUBOOT_LOG_LEVEL_DBG`, reading the debug lines in `image_validate.c` gives, for a single-key ECDSA P-256 configuration:

| Hostile image | Debug lines seen before the refusal | Distinguishable? |
| --- | --- | --- |
| Truncated | `TLV iteration failed -1` | Yes, clearly |
| Wrong key | `EXPECTED_HASH_TLV`, `EXPECTED_KEY_TLV`, `EXPECTED_SIG_TLV` | Yes, by reaching the signature step and still failing |
| Modified after signing | `EXPECTED_HASH_TLV` only, then silence | No |
| Unsigned | `EXPECTED_HASH_TLV` only, then silence | No |

Modified and unsigned are indistinguishable even at debug level. A modified image stops at the hash comparison (`image_validate.c:352-358`), which logs nothing on failure. An unsigned image passes the hash, finds no key TLV and no signature TLV, falls out of the loop, and fails because `valid_signature` was never set. Both produce exactly one debug line and then the shared error. This was read from source; it has not been observed on the board.

**What this means for the map.** Map #48's destination says the four hostile images are "refused with a distinguishable reason for each" and that "the bootloader must name the reason for each". Against MCUboot 2.4.0 as pinned, the bootloader names no reason for any of them. Tier 3 has to get the distinction from somewhere else: from what the Learner published and the device logged before it rebooted, from the device reporting which key it trusts, or from a deliberately chosen fixture set where the four failures land in different MCUboot code paths and the module teaches the Learner to read the difference. That decision belongs to [#55](https://github.com/tkEmLogic/learning-cyber-security/issues/55), and this finding should reach it before the fixture set is fixed. Patching MCUboot is not an option the course should take, because the course pins upstream and a Learner forking the repository gets upstream.

## 5. What `BOOT_VALIDATE_SLOT0` changes

**Nothing about the secondary slot refusal. It adds a separate check of the primary slot, and it introduces one real way to brick the board that Tier 3 must respect.**

`CONFIG_BOOT_VALIDATE_SLOT0` defines `MCUBOOT_VALIDATE_PRIMARY_SLOT` (`mcuboot_config.h:75`). In `loader.c:1923-1932` it adds, after the swap decision and any swap, a full validation of the primary slot:

```c
#ifdef MCUBOOT_VALIDATE_PRIMARY_SLOT
        FIH_CALL(boot_validate_slot, fih_rc, state, BOOT_SLOT_PRIMARY, NULL, 0);
```

Three consequences.

**It does not change the refusal path.** The secondary slot is validated by `boot_validated_swap_type()` regardless of this option. Turning `BOOT_VALIDATE_SLOT0` off would not stop the refusal, the erase, or the single error line.

**It never erases the primary slot.** The guard at `loader.c:652` excludes `BOOT_SLOT_PRIMARY` for swap modes. A primary slot that fails validation is left exactly as it is.

**It hangs the bootloader if the primary image fails.** A primary-slot failure sets `FIH_FAILURE`, skips to `out`, and `boot/zephyr/main.c:657-678` prints `E: Unable to find bootable image` and then `FIH_PANIC`. The board stops in the bootloader.

That last point is a Tier 3 hazard, and it does not come from a hostile image. It comes from a key mismatch. Once Tier 3 builds MCUboot with the Learner's public key and signs the application with the Learner's private key, any mismatch between the two, including a Learner who regenerates their key and reflashes only the application, makes the primary slot fail validation on every boot. The board will sit in the bootloader printing that line. It is recoverable by reflashing the full sysbuild image over USB, which is the command Tier 0 already documents, and it needs no eFuse work and no full chip erase. Tier 3 should say so, because a Learner meeting that line will reasonably think they broke the board.

Note also that `BOOT_VALIDATE_SLOT0` means the primary image is hashed and signature-checked on **every** boot, not just after an upgrade. That is a per-boot time cost on a 1,792 KiB slot that Tier 3 will want to notice when it quotes boot output.

## 6. State that survives a power cut, and the risk of needing a full erase

**No refusal writes state that outlives the erase it performs, and no ordinary Tier 3 sequence can leave the board needing a full flash erase.**

Nothing persistent is written by a refusal except the erase itself. There is no counter, no failure record, no eFuse, no retained RAM. The pinned configuration has `CONFIG_MCUBOOT_STORAGE_MINIMAL_SCRAMBLE` off and no hardware rollback protection, so nothing outside the two slots is touched.

The interesting case is a power cut in the middle of the erase, which is a real possibility because the erase takes hundreds of sector operations. MCUboot handles it deliberately. `boot_scramble_slot()` erases forward from offset zero, so the header goes first and the trailer last, and a power cut can leave an erased header with a surviving trailer. `boot_validate_slot()` addresses exactly that at `loader.c:559-578`, in a comment that names the scenario:

```c
        /*
         * This fixes an issue where an image might be erased, but a trailer
         * be left behind. It can happen if the image is in the secondary slot
         * and did not pass validation, in which case the whole slot is erased.
         * If during the erase operation, a reset occurs, parts of the slot
         * might have been erased while some did not. ...
         */
        if (slot != BOOT_SLOT_PRIMARY) {
            swap_scramble_trailer_sectors(state, fap);
        }
```

So a power cut mid-erase leaves a half-erased secondary slot, and the next boot finishes the cleanup of the part that matters. The primary slot is untouched throughout. The device boots its old image either way.

Ways a Learner could still end up needing to reflash, none of them caused by a refused image:

- A key mismatch between the bootloader and the primary image, as described in answer 5. Reflash the full sysbuild image. Not a full chip erase.
- Flashing only the nested per-domain build directory instead of the sysbuild top-level directory, which `docs/esp32c6-build-baseline.md` already warns about.
- A software reset that leaves the BBPLL running, already diagnosed and fixed in `course_reset_system()`.

A full flash erase is not required for any of these. Tier 3's procedure should carry the reflash command as its recovery step and should not promise a refusal can brick anything.

## What Tier 3's procedure has to say

Collecting the operational consequences in one place:

1. The four hostile images are four identical cycles. Publish, reboot, read the console. No erase, no reflash, no recovery command between them.
2. After each refusal the board runs the same unchanged image it ran before. The module should have the Learner confirm that, because a successful refusal looks like nothing happening.
3. Expect a pause while MCUboot erases the 1,792 KiB secondary slot. Time it during hardware validation and put the real number in the module.
4. The refusal line is `E: Image in the secondary slot is not valid!` and it is the same line for all four hostile images. A fixture that fails before the header check prints no line at all.
5. Tier 3 cannot get four distinguishable reasons from MCUboot's console at the pinned log level, and cannot get four even at debug level. The distinction must come from the publishing side or from a fixture set chosen so the Learner can tell the cases apart another way. This blocks nothing yet, but #55 needs it.
6. The one way Tier 3 can leave a board stuck is a key mismatch on the primary slot, which prints `E: Unable to find bootable image` and stops. The fix is reflashing the sysbuild top-level image over USB. Say so in the module.

## What was not established

- No timing. The erase duration, the added per-boot validation time from `BOOT_VALIDATE_SLOT0`, and the total time for one refusal cycle are all unmeasured. They need the board.
- No ESP32-C6 flash sector size was confirmed from the devicetree. The 4 KiB figure used in the estimate above is the usual value for this part and was not verified here.
- The debug-level output table in answer 4 was derived by reading the code paths, not by building MCUboot with `CONFIG_MCUBOOT_LOG_LEVEL_DBG` and running it.
- Nothing here was tested with `CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256` enabled. The refusal machinery in `loader.c` is signature-type independent, but the specific TLVs an unsigned or wrong-key image carries were reasoned about from `image_validate.c`, not observed.
