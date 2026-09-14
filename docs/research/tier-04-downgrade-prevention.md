# What `MCUBOOT_DOWNGRADE_PREVENTION_SECURITY_COUNTER` does on the ESP32-C6

Research for issue #66, under map #64. Nothing here changes the course. This
file records what was read and what was built, so Tier 4 can be written against
something that was checked rather than something that sounded right.

**Sources.** MCUboot at `/opt/zephyr-workspace/bootloader/mcuboot`, revision
`6d3b3d2c38ab20c242e5b9abb04d050086383eb2`, "Version bump for v2.4.0",
`git describe` = `v2.4.0`. Zephyr 4.4.2. All builds ran inside the
`tier2-validate` container, board `esp32c6_devkitc/esp32c6/hpcore`, into
`/opt/zephyr-workspace/build/research-66-counter/`. No board was flashed and
`/dev/ttyACM0` was not touched. Nothing under `artifacts/generated/releases/` or
`.course-secrets/` was modified.

## The short answer

The map's settled claim needs one word changed. The bootloader *is* what stops
the downgrade — but on this target it does not stop it against a monotonic
counter. It stops it against **the security counter TLV of whatever image is
sitting in the primary slot at that moment**. The reference value lives in the
same flash the attacker is attacking. There is no hardware counter, no eFuse,
no trusted storage, and no persisted value of any kind involved.

So the honest sentence for Tier 4 is not "the bootloader stops a downgrade
because it remembers how far you have come". It is "the bootloader refuses to
install an image older than the one already installed". Those are different
claims and only the second one is true here.

## 1. Where the confirmed image's counter comes from

Two different functions are easy to confuse, and the difference is the whole
answer.

`boot_nv_security_counter_get` / `boot_nv_security_counter_update` are the
**non-volatile** counter interface, declared in
`boot/bootutil/include/bootutil/security_cnt.h`. Its own header says who is
supposed to implement it (lines 22-25):

```c
 * @note A security counter might be implemented using non-volatile OTP memory
 *       (i.e. fuses) in which case it is the responsibility of the platform
 *       code to map each possible security counter values onto the fuse bits
 *       as the direct usage of counter values can be costly / impractical.
```

These two symbols are **declared and never implemented** for the Zephyr port in
this tree. The only implementations that exist anywhere in MCUboot v2.4.0 are
`sim/mcuboot-sys/csupport/security_cnt.c`, which forwards to per-thread Rust
memory for unit tests, and `boot/cypress/MCUBootApp/cy_security_cnt.c`, which
hardcodes `*security_cnt = 30;` and discards every update. `boot/zephyr/`
supplies neither.

That was confirmed by building it, not by reading it. Adding
`CONFIG_MCUBOOT_HW_DOWNGRADE_PREVENTION=y` (the Kconfig symbol that defines the
`MCUBOOT_HW_ROLLBACK_PROT` macro, see
`boot/zephyr/include/mcuboot_config/mcuboot_config.h:232-234`) to the Tier 3
bootloader config fails at link:

```text
/opt/zephyr-workspace/bootloader/mcuboot/boot/bootutil/src/image_validate.c:355:(.text.bootutil_img_validate+0x14c): undefined reference to `boot_nv_security_counter_get'
/opt/zephyr-workspace/bootloader/mcuboot/boot/bootutil/src/bootutil_loader.c:260:(.text.boot_update_security_counter+0x26): undefined reference to `boot_nv_security_counter_update'
collect2: error: ld returned 1 exit status
```

Hardware rollback protection is therefore not merely unused on this target. It
cannot be switched on at all without writing an ESP32-C6 eFuse driver for it,
which Tier 4 is not going to do.

`bootutil_get_img_security_cnt` is the other function, and it is the one that
actually runs. `boot/bootutil/src/bootutil_img_security_cnt.c:49-102`, in full
for the part that matters:

```c
    /* The security counter TLV is in the protected part of the TLV area. */
    if (boot_img_hdr(state, slot)->ih_protect_tlv_size == 0) {
        return BOOT_EBADIMAGE;
    }
...
    rc = bootutil_tlv_iter_begin(&it, boot_img_hdr(state, slot), fap, IMAGE_TLV_SEC_CNT, true);
```

It takes a *slot*, opens that slot's flash area, and reads tag `0x50` out of the
protected TLV area of the image lying there. That is its only source. It has no
access to anything persisted outside the image.

**What that implies for the threat model.** The "confirmed" counter is not
confirmed by anything. It is a field in a file in flash. Everything the
mechanism gives you is: a candidate in the secondary slot must not carry a
counter lower than the image currently in the primary slot. An attacker who can
write the primary slot — JTAG, a serial bootloader, an `esptool` write over USB,
anything the specification already means by "a physical attacker can rewrite
boot state" — moves the reference value backwards along with the image, and the
mechanism is satisfied again. Section 6's existing wording, "This is software
downgrade prevention, because a physical attacker can rewrite boot state", is
correct and should be kept. It is if anything understated: the state being
rewritten is not a boot-state trailer flag, it is the reference value itself.

There is a second consequence worth teaching. Look at the guard again:
`ih_protect_tlv_size == 0` returns `BOOT_EBADIMAGE`, and the caller treats a
non-zero return on the primary slot as "allow the swap" (see section 2). Every
Tier 3 image has `ih_protect_tlv_size == 0`. So a device running a Tier 3 image
has downgrade prevention entirely inert, whatever the bootloader was built
with. It only starts protecting anything once an image that carries a counter
has become the primary image.

## 2. What it compares, and what it prints

`boot/bootutil/src/loader.c:1671-1712`, verbatim:

```c
static int
check_downgrade_prevention(struct boot_loader_state *state)
{
#if defined(MCUBOOT_DOWNGRADE_PREVENTION) && \
    (defined(MCUBOOT_SWAP_USING_MOVE) || defined(MCUBOOT_SWAP_USING_SCRATCH) || defined(MCUBOOT_SWAP_USING_OFFSET))
    uint32_t security_counter[2];
    int rc;

    if (MCUBOOT_DOWNGRADE_PREVENTION_SECURITY_COUNTER) {
        /* If there was security no counter in slot 0, allow swap */
        rc = bootutil_get_img_security_cnt(state, BOOT_SLOT_PRIMARY,
                                           BOOT_IMG_AREA(state, 0),
                                           &security_counter[0]);
        if (rc != 0) {
            return 0;
        }
        /* If there is no security counter in slot 1, or it's lower than
         * that of slot 0, prevent downgrade */
        rc = bootutil_get_img_security_cnt(state, BOOT_SLOT_SECONDARY,
                                           BOOT_IMG_AREA(state, 1),
                                           &security_counter[1]);
        if (rc != 0 || security_counter[0] > security_counter[1]) {
            rc = -1;
        }
    }
    else {
        rc = boot_compare_version(
            &boot_img_hdr(state, BOOT_SLOT_SECONDARY)->ih_ver,
            &boot_img_hdr(state, BOOT_SLOT_PRIMARY)->ih_ver);
    }
    if (rc < 0) {
        /* Image in slot 0 prevents downgrade, delete image in slot 1 */
        BOOT_LOG_INF("Image %d in slot 1 erased due to downgrade prevention", BOOT_CURR_IMG(state));
        boot_scramble_slot(BOOT_IMG_AREA(state, 1), BOOT_SLOT_SECONDARY);
    } else {
        rc = 0;
    }
    return rc;
#else
    (void)state;
    return 0;
#endif
}
```

The comparison is plain and unsigned: `security_counter[0] > security_counter[1]`.
Equal is allowed, which matches what section 6 already fixed ("A candidate
counter may equal the confirmed one but never be lower") and what the Kconfig
help text says (`boot/zephyr/Kconfig:1153-1161`):

```
config MCUBOOT_DOWNGRADE_PREVENTION_SECURITY_COUNTER
	bool "Use image security counter instead of version number"
	depends on MCUBOOT_DOWNGRADE_PREVENTION
	depends on (BOOT_SWAP_USING_MOVE || BOOT_SWAP_USING_SCRATCH || BOOT_SWAP_USING_OFFSET)
	help
	  Security counter is used for version eligibility check instead of pure
	  version.  When this option is set, any upgrade must have greater or
	  equal security counter value.
	  Because of the acceptance of equal values it allows for software
	  downgrades to some extent.
```

Note the `depends on`: the course already builds with
`CONFIG_BOOT_SWAP_USING_OFFSET=y`, so the dependency is satisfied and nothing in
the pinned flash map has to move.

The refusal is a single `BOOT_LOG_INF`:

```text
I: Image 0 in slot 1 erased due to downgrade prevention
```

The format string was confirmed present in a real build. `strings` on
`research-66-counter/boot-counter/zephyr/zephyr.bin` gives
`%c: Image %d in slot 1 erased due to downgrade prevention`, and the same string
is absent from the shipped Tier 3 bootloader binary. The `I:` prefix and the
image number `0` above are how `BOOT_LOG_INF` and `BOOT_CURR_IMG` render for
this single-image build; **the rendered line has not been observed on hardware**
and must be re-checked against a board before it is quoted in a module.

Where it is called: `loader.c:1841`, inside `context_boot_go`'s swap-type
switch, for `BOOT_SWAP_TYPE_TEST` and `BOOT_SWAP_TYPE_PERM` only. Tier 3 and
Tier 4 request `perm`, so it is reached. Refusal sets
`BOOT_SWAP_TYPE(state) = BOOT_SWAP_TYPE_NONE` and scrambles the secondary slot,
so the candidate is erased and the primary image boots.

That switch runs after `boot_prepare_image_for_update` (`loader.c:1778`), which
is where `boot_validate_slot` and therefore signature checking happens
(`loader.c:1555`, `1576`, `1582`). Order matters for the fixtures: **signature
first, counter second.** A downgrade candidate that is also badly signed never
reaches the counter check.

### The `SECURITY_COUNTER` suffix changes the comparison, not the message

Two bootloaders were built and compared, identical apart from one Kconfig line:

| build | Kconfig | `zephyr.bin` |
| --- | --- | --- |
| shipped Tier 3 | neither | 47,872 bytes |
| `boot-version-only` | `MCUBOOT_DOWNGRADE_PREVENTION=y` | 48,112 bytes |
| `boot-counter` | `…=y` plus `…_SECURITY_COUNTER=y` | 48,176 bytes |

`bootutil_get_img_security_cnt` appears in the symbol table of `boot-counter`
and not of `boot-version-only`. Both contain the *same* log string. So the
suffix decides whether `ih_ver` or TLV `0x50` is compared, and nothing in the
log tells you which one refused. If Tier 4 wants the Learner to be able to see
that it was the counter and not the version, the course has to print that
itself.

Neither build defines `MCUBOOT_HW_ROLLBACK_PROT`. The resolved config of
`boot-counter` shows `# CONFIG_MCUBOOT_HW_DOWNGRADE_PREVENTION is not set`, and
no `boot_nv_security_counter_*` symbol is linked in. This is the important
negative result: **`MCUBOOT_DOWNGRADE_PREVENTION_SECURITY_COUNTER` does not
require, use, or touch the NV counter interface at all.** It is a pure
image-to-image comparison and it builds cleanly on a target with no counter
hardware.

## 3. Is the refusal distinguishable from Tier 3's four?

Yes, and more cleanly than expected — because a downgrade refusal is not a
validation failure at all.

Tier 3's published module records the generic line MCUboot prints for all four
of its attacks (`course-material/tiers/tier-03-signed-images/index.md:226`, and
again at :326 in the wrong-key transcript):

```text
E: Image in the secondary slot is not valid!
```

That comes from `loader.c:649`, `BOOT_LOG_ERR("Image in the %s slot is not valid!", …)`,
reached when `bootutil_img_validate` returns `FIH_FAILURE`. Unsigned, modified,
wrong-key and truncated all collapse into it; inside `image_validate.c` those
paths only `goto out` or log at `BOOT_LOG_DBG`, which is compiled out at the
course's `CONFIG_MCUBOOT_LOG_LEVEL_INF`.

A downgrade is different in kind. The candidate is correctly signed by the
Release key, so validation **passes**. `Image in the secondary slot is not
valid!` is never printed. What is printed instead is the `I:` line above, from a
completely different place in the boot flow. And the course's own hook line,
which runs during validation, will say the image is fine:

```text
I: course: slot=secondary header=ok tlv=ok signature=present key=match
```

That is a good teaching shape: the same four facts that convicted every Tier 3
attack come back clean, and the device refuses anyway. It is also a warning —
the refusal line is `I:`, not `E:`, so a Learner skimming for red lines will
miss it.

One caveat that cannot be settled from source: the exact interleaving of the
hook line, `Image index: 0, Swap type: perm`, and the downgrade line on a real
console. `check_downgrade_prevention` is unambiguously called after validation
in the source, but the observed Tier 3 transcript prints the swap-type line
*before* the hook line, so the console order is worth confirming on hardware
before any of it is quoted in a module.

## 4. Is `IMAGE_TLV_SEC_CNT` reachable from a `BOOT_IMAGE_ACCESS_HOOKS` hook?

**Yes — but the hook has to read it itself. MCUboot will not hand it over.**
This is the answer #71 depends on.

Not handed over, for two reasons:

- The signature carries nothing. `boot/bootutil/include/bootutil/boot_hooks.h:137`
  declares `fih_ret boot_image_check_hook(int img_index, int slot);` — an index
  and a slot number, no header, no flash area, no TLV iterator, no counter. No
  other hook in `boot_hooks.h` or `boot_public_hooks.h` carries a parsed
  counter either.
- The hook runs too early. `BOOT_HOOK_CALL_FIH(boot_image_check_hook, …)` is at
  `loader.c:637`, before `boot_check_image` → `bootutil_img_validate`
  (`bootutil_loader.c:190`). Nothing has been parsed yet when it fires.
- And MCUboot's own `IMAGE_TLV_SEC_CNT` case in `image_validate.c:437-491` is
  inside `#ifdef MCUBOOT_HW_ROLLBACK_PROT`, which as section 1 showed cannot be
  enabled on this target. MCUboot's validator never looks at tag `0x50` here at
  all.

Reachable anyway, because everything needed is public. `IMAGE_TLV_SEC_CNT 0x50`
is defined in the installed header `bootutil/image.h:120`, which
`firmware/mcuboot-refusal-reason/src/course_refusal_reason.c` already includes,
and the hook already opens the flash area and locates the image header for
itself (`course_find_image`, then `course_read_tlvs`).

There is one real obstacle in the module as it stands. `course_read_tlvs` walks
*past* the protected area to get to the signature:

```c
	/* A protected TLV area comes first when one is present. Step over it to
	 * reach the unprotected area, which is where the signature lives.
	 */
	if (info.it_magic == IMAGE_TLV_PROT_INFO_MAGIC) {
		off += info.it_tlv_tot;
```

Tag `0x50` is inside the area being stepped over, so the module cannot see it
today. The comment is accurate and the code is correct for what it was written
for; it just needs a second walk.

This was verified by building it. A scratch copy of the module under
`research-66-counter/mod/` was given a loop over the protected area before the
`off += info.it_tlv_tot` step, reporting `counter=present(N)` or `counter=none`
alongside the existing four facts. It compiles and links into the bootloader
using only `flash_area_read` and headers the module already includes — no
private `bootutil_priv.h`, no `LOAD_IMAGE_DATA`, no new dependency. The new
format string is present in the resulting binary:

```text
%c: course: slot=%s header=%s tlv=%s signature=%s key=%s counter=%s(%u)
```

**The patched hook's output has not been observed running on a board.** The
proof here is that it builds and that the TLV is within reach of the APIs the
hook already uses; the rendered line is unverified.

For #71 the practical note is that the protected TLV area is a second, separate
`image_tlv_info` block with its own magic (`IMAGE_TLV_PROT_INFO_MAGIC`,
`0x6908`) and its own length, sitting immediately after the payload and before
the unprotected area (`0x6907`). Reading it is the same loop over
`struct image_tlv` records, run over a different range. The alternative —
MCUboot's public `bootutil_tlv_iter_begin`/`bootutil_tlv_iter_next` from
`bootutil/image.h`, with `prot = true` — is also available to a hook and is what
`bootutil_get_img_security_cnt` uses internally, but it was not needed.

## 5. `--security-counter` creates the protected TLV area

Confirmed. `imgtool` is v2.4.0, from the same tree.

**Before.** `artifacts/generated/releases/tier-03-baseline.bin`, the image the
Learner's Tier 3 actually ships, dumped read-only and not modified:

```text
#### Image header (offset: 0x0) ############################
magic:              0x96f3b83d
load_addr:          0x0
hdr_size:           0x20
protected_tlv_size: 0x0
img_size:           0xa1f84
flags:              0x0
version:            0.3.0+0
############################################################
#### Payload (offset: 0x20) ################################
#### TLV area (offset: 0xa1fa4) ############################
magic:     0x6907
area size: 0x97
        type: SHA256 (0x10)    len: 0x20
        type: KEYHASH (0x1)    len: 0x20
        type: ECDSASIG (0x22)  len: 0x47
```

**After.** The same unsigned `zephyr.bin` that produced it, re-signed into a
scratch directory with exactly Tier 3's parameters plus one flag:

```text
imgtool.py sign --version 0.3.0+0 --header-size 0x20 --slot-size 1835008 \
    --align 4 --security-counter 5 --key <release key> raw.bin B-counter5.bin
```

```text
#### Image header (offset: 0x0) ############################
magic:              0x96f3b83d
load_addr:          0x0
hdr_size:           0x20
protected_tlv_size: 0xc
img_size:           0xa1f84
flags:              0x0
version:            0.3.0+0
############################################################
#### Payload (offset: 0x20) ################################
#### Protected TLV area (offset: 0xa1fa4) ##################
magic:     0x6908
area size: 0xc
        ---------------------------------------------
        type: SEC_CNT (0x50)
        len:  0x4
        data: 0x05 0x00 0x00 0x00 
############################################################
#### TLV area (offset: 0xa1fb0) ############################
magic:     0x6907
area size: 0x97
        type: SHA256 (0x10)    len: 0x20
        type: KEYHASH (0x1)    len: 0x20
        type: ECDSASIG (0x22)  len: 0x47
```

So: `ih_protect_tlv_size` goes `0x0` → `0xc`, a new area with magic `0x6908`
appears between the payload and the ordinary TLV area, it holds one four-byte
little-endian `SEC_CNT` record, the unprotected area is pushed from `0xa1fa4` to
`0xa1fb0`, and the file grows by twelve bytes of protected area. The two scratch signings
measured 663,612 and 663,623 bytes, eleven apart rather than twelve, because the
ECDSA signature TLV came out one byte shorter in the second one — ordinary DER
length variance, and the same reason the shipped image is 663,611.

"Protected" means covered by the signature, and that was checked rather than
assumed. The `SHA256` TLV differs between the two scratch images even though the
payload is byte-identical, and editing the counter from `5` to `6` in the signed
file with `dd` gives:

```text
Image has an invalid hash
```

from `imgtool verify` against the Learner's public key, where the untouched file
gives `Image was correctly validated`. The counter cannot be raised or lowered
without the Release signing key. That is the property the manifest's copy of the
counter has to match.

Two consequences for Tier 4:

- Tier 4 is the first tier whose images have a protected TLV area at all. Any
  course code that walks TLVs has to cope with two areas now, not one.
  `course_read_tlvs` already does, by stepping over the first one — so adding
  `--security-counter` does **not** break Tier 3's existing refusal reporting.
  That was read, not run.
- `--security-counter auto` exists and derives the value from the image version.
  It was not used here. Section 6 says the counter and the human-readable
  version stay separate, so Tier 4 should pass an explicit value.

## What Tier 4 should not say

- Do not say the device "remembers" a counter, or that the counter is
  monotonic, or that it is stored anywhere outside the image. On this target
  none of that is true.
- Do not say the bootloader's refusal survives a physical attacker. Rewriting
  the primary slot rewrites the reference value.
- Do not present the downgrade refusal as the same kind of event as Tier 3's
  four. The signature *passes*. That is the interesting part and it is worth
  building the fixture around.
- Do not quote `I: Image 0 in slot 1 erased due to downgrade prevention`, or the
  patched hook's `counter=` line, until a board has printed them. The format
  strings are real and were taken from built binaries; the rendered lines are
  not yet observations.

## Open, and needing hardware

1. The rendered downgrade-refusal line and its position relative to
   `Image index: 0, Swap type: perm` and the `course:` hook lines.
2. Whether the erased secondary slot leaves the application able to report
   anything useful afterwards, which decides the shape of Tier 4's evidence.
3. Whether an equal counter really is accepted end to end, since the source says
   so but the course has never exercised it.
