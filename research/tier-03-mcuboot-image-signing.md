# What MCUboot image signing costs and prints on the pinned stack

**Research question:** [GitHub issue #50](https://github.com/tkEmLogic/learning-cyber-security/issues/50), part of map [#48](https://github.com/tkEmLogic/learning-cyber-security/issues/48)

**Access and review date:** 14 September 2026

**Status:** Research findings. Read against the pinned tree only. Re-check if Zephyr or MCUboot moves.

## What was read

Everything below comes from the pinned tree inside the repo's own dev container, verified at read time:

| Component | Version | Commit |
| --- | --- | --- |
| Zephyr | v4.4.2 | `git describe --tags` reported `v4.4.2` |
| MCUboot | v2.4.0 | `6d3b3d2c38ab20c242e5b9abb04d050086383eb2` |

Paths below are inside the container: `/opt/zephyr-workspace/bootloader/mcuboot` and `/opt/zephyr-workspace/zephyr`. No blog posts were used.

## The finding that decides Tier 3

**At the pinned log level the four bad images are not distinguishable. They produce byte-identical console output.**

MCUboot 2.4.0 does not log a reason for any cryptographic rejection. `bootutil_img_validate()` in `boot/bootutil/src/image_validate.c` is the function that checks the hash, finds the key, and verifies the signature, and it contains exactly two `BOOT_LOG_ERR` calls in its whole body: lines 468 and 480, both about the hardware security counter, which this course does not enable. Every hash mismatch, every missing signature, every unknown key and every failed ECDSA verification leaves the function through a silent `goto out`.

What the Learner sees is produced one and two levels further up the stack, and it is the same text whatever went wrong:

```
E: Image in the <primary|secondary> slot is not valid!
E: Unable to find bootable image
```

The first is `boot/bootutil/src/loader.c:649-650`, the second is `boot/zephyr/main.c:658`. Neither has access to the reason, because the reason was never returned. `bootutil_img_validate()` returns a single `fih_ret` that is either success or failure; there is no error code carrying a cause.

This is a finding, not a failure, and the ticket's escape hatch applies. Section 7 works through each of the four fixtures and says exactly where they collapse.

## 1. Which Kconfig options turn on ECDSA P-256, and what the pinned tree already sets

**One sysbuild option does the whole job.** In `firmware/<app>/sysbuild.conf`, replace

```
SB_CONFIG_BOOT_SIGNATURE_TYPE_NONE=y
```

with

```
SB_CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y
SB_CONFIG_BOOT_SIGNATURE_KEY_FILE="/absolute/path/to/course-signing-key.pem"
```

Those two symbols are defined in `zephyr/share/sysbuild/images/bootloader/Kconfig:189` and `:197`. Sysbuild then drives four separate things from them, which is why nothing else has to be touched:

| Set by sysbuild | Where | Effect |
| --- | --- | --- |
| `CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y` on the mcuboot image | `image_configurations/BOOTLOADER_image_default.cmake:65-87` | Bootloader compiles in ECDSA verification |
| `CONFIG_BOOT_SIGNATURE_KEY_FILE` on the mcuboot image | `images/bootloader/CMakeLists.txt:20` | Public key compiled into the bootloader |
| `CONFIG_MCUBOOT_SIGNATURE_KEY_FILE` on the application image | `image_configurations/MAIN_image_default.cmake:9-11` | Application image gets signed |
| `CONFIG_MCUBOOT_GENERATE_UNSIGNED_IMAGE=n` on the application image | `image_configurations/MAIN_image_default.cmake:17-21` | Turns off the Tier 0 unsigned path |

That last row matters. `CONFIG_MCUBOOT_GENERATE_UNSIGNED_IMAGE=y` is in the Tier 0 resolved configuration today, and it is **not** something the repo sets by hand. Sysbuild derives it from `SB_CONFIG_SIGNATURE_TYPE` being `"NONE"`. Flip the signature type and it clears itself. Do not try to clear it directly.

The bootloader-side symbols the pinned tree **already** sets, and which signing needs, are in `firmware/<app>/sysbuild/mcuboot.conf`:

- `CONFIG_BOOT_VALIDATE_SLOT0=y` is already on. This is the symbol that makes the bootloader re-verify the primary slot on **every** boot rather than only at install time. `boot/zephyr/include/mcuboot_config/mcuboot_config.h:74-75` maps it to `MCUBOOT_VALIDATE_PRIMARY_SLOT`, which is what gates the `boot_validate_slot()` call at `loader.c:1924`. Tier 0 already pays for a full SHA-256 pass over the image at every boot. See section 4; this is the single most important cost fact in the ticket.
- `CONFIG_MCUBOOT_LOG_LEVEL_INF=y` and `CONFIG_LOG_MODE_MINIMAL=y` are already on, so refusals are visible at all.

Options that are chosen for you, and are worth knowing about:

- **`CONFIG_BOOT_ECDSA_TINYCRYPT=y` is the default implementation.** The `BOOT_ECDSA_IMPLEMENTATION` choice at `boot/zephyr/Kconfig:315-317` declares `default BOOT_ECDSA_TINYCRYPT`. MCUboot 2.4.0 bundles its own tinycrypt (`ext/tinycrypt/lib/source/ecc_dsa.c`) and its own cut-down Mbed TLS ASN.1 parser (`ext/mbedtls-asn1`), so the bootloader does not link against the Zephyr Mbed TLS 4.1.0 that Tier 2 uses. `BOOT_USE_TINYCRYPT` even `select`s `MBEDTLS_PROMPTLESS` (`Kconfig:37`) specifically to stop the two colliding. This is good news: **Tier 3's bootloader crypto is independent of Tier 2's TLS crypto.** The alternatives are `BOOT_ECDSA_MBEDTLS` and `BOOT_ECDSA_PSA`, and neither is needed.
- `BOOT_SIGNATURE_TYPE_ECDSA_P256` also `select`s `BOOT_IMG_HASH_ALG_SHA256_ALLOW` and `BOOT_ENCRYPTION_SUPPORT` (`Kconfig:308-311`). Encryption *support* is not encryption; `SB_CONFIG_BOOT_ENCRYPTION` stays off and no image is encrypted.
- `CONFIG_BOOT_SIGNATURE_TYPE_NONE` selects tinycrypt too, for the SHA-256 it already does. So the crypto backend does not change when you turn signing on, only what it is asked to do.

Two options the course should deliberately **not** set, both of which weaken the lesson:

- `CONFIG_BOOT_BYPASS_KEY_MATCH` (`Kconfig:457`) turns off matching the image's KEYHASH TLV against the compiled-in key. Leaving it off is what makes the "signed by a different key" fixture fail in the way described in section 7.
- `CONFIG_BOOT_VALIDATE_SLOT0_ONCE` caches a successful validation in the primary slot's magic area and skips it next boot. MCUboot's own `docs/design.md:1275-1282` says this "is reducing the security level". Tier 3 wants verification on every boot.

## 2. How the signing key reaches the build, and whether issue #43's trap applies

**No, the signing key does not have issue #43's problem, and the reason is worth understanding.**

Issue #43 found that sysbuild keeps an arbitrary image-scoped `-D<image>_VAR` in its own cache and does not forward it into the image build, which is why `COURSE_CA_INC_DIR` had to travel in the environment instead. That trap applies to *arbitrary* variables that sysbuild has never heard of.

The signing key is not an arbitrary variable. `SB_CONFIG_BOOT_SIGNATURE_KEY_FILE` is a first-class **sysbuild Kconfig** symbol with purpose-written forwarding code. Sysbuild pushes it into the image builds explicitly with `set_config_string()`:

```cmake
# zephyr/share/sysbuild/images/bootloader/CMakeLists.txt:20
set_config_string(${image} CONFIG_BOOT_SIGNATURE_KEY_FILE "${SB_CONFIG_BOOT_SIGNATURE_KEY_FILE}")
```

```cmake
# zephyr/share/sysbuild/image_configurations/MAIN_image_default.cmake:9-11
set_config_string(${ZCMAKE_APPLICATION} CONFIG_MCUBOOT_SIGNATURE_KEY_FILE
                  "${SB_CONFIG_BOOT_SIGNATURE_KEY_FILE}"
)
```

So one value in `sysbuild.conf` reaches both images, by a documented path, and Zephyr's own `doc/build/signing/index.rst:40` names `SB_CONFIG_BOOT_SIGNATURE_KEY_FILE` as the supported way to use your own key. This is the mechanism to use. Do not invent a new variable.

**How to express the path portably.** The Kconfig help says "Absolute path to signing key file to use with MCUBoot" (`images/bootloader/Kconfig:204-205`), and a committed absolute path is not portable across Learner machines. The tree's own defaults show the idiom: they use a Kconfig environment macro.

```
default "$(ZEPHYR_MCUBOOT_MODULE_DIR)/root-ec-p256.pem" if BOOT_SIGNATURE_TYPE_ECDSA_P256
```

`$(NAME)` in Kconfig expands an environment variable at configure time. So the repo can commit

```
SB_CONFIG_BOOT_SIGNATURE_KEY_FILE="$(COURSE_SIGNING_KEY)"
```

and have `scripts/build-zephyr-baseline.sh` export `COURSE_SIGNING_KEY` as an absolute path, exactly mirroring the existing `COURSE_CA_INC_DIR` pattern. That keeps the generated key out of Git and the path out of the committed config.

**Yes, the public key is compiled in through a generated C file, but it is not called `keys.c`.** There are two files and the distinction matters when reading the tree:

- `boot/zephyr/keys.c` is a checked-in, static file. It declares `bootutil_keys[]` and `bootutil_key_cnt = 1` and does nothing but point at an `extern const unsigned char ecdsa_pub_key[]`.
- The array itself is generated. `boot/zephyr/CMakeLists.txt:346-357` adds a custom command that runs `imgtool.py getpub -k <key>` and redirects its stdout to `${ZEPHYR_BINARY_DIR}/autogen-pubkey.c`, then adds that file to the bootloader's sources.

The key path is resolved at `CMakeLists.txt:318-328` in this order: absolute, then relative to `APPLICATION_CONFIG_DIR`, then relative to the MCUboot repository root. It is passed through `string(CONFIGURE ...)` first, which is what makes the escaped `\${CMAKE_CURRENT_LIST_DIR}` form in the Kconfig help work.

**A guard rail the course gets for free.** `CMakeLists.txt:333-345` compares the resolved key against MCUboot's seven checked-in development keys and prints

```
WARNING: Using default MCUboot signing key file, this file is for debug use only and is not secure!
```

If a Learner forgets to generate a key and inherits the `root-ec-p256.pem` default, the build says so. That is a teachable moment worth quoting in the module rather than hiding.

## 3. What signs the image, and what the signature covers

**`imgtool sign` signs it, invoked automatically by the build. Not `west sign`.**

Zephyr's `cmake/mcuboot.cmake` defines `zephyr_mcuboot_tasks()`, which assembles an `imgtool sign` command line and registers it as a post-build command on the application image. Zephyr's own documentation states the split plainly at `doc/build/signing/index.rst:5-8`: binaries "can be optionally signed as part of a build automatically using CMake code, there is also the ability to use `west sign`... this page describes the former".

So in the sysbuild flow nobody runs `west sign`. `west sign` exists and works, but it is a separate manual path. Tier 3 should teach the automatic one, because that is what the repo's build script already triggers.

The command is built from devicetree and Kconfig, not hand-written (`cmake/mcuboot.cmake:104-107, 118-120, 169-175`):

```
imgtool sign --version <CONFIG_MCUBOOT_IMGTOOL_SIGN_VERSION> \
             --header-size <CONFIG_ROM_START_OFFSET> \
             --slot-size <slot1_partition size from DT> \
             --align <flash write-block-size> \
             --key <resolved key file>
```

Note `--slot-size` comes from **slot1**, not slot0, in every mode except single-slot (`mcuboot.cmake:92-101`). For this flash map both slots are 1,792 KiB so it makes no difference, but it is a trap if the map ever becomes asymmetric.

**What the signature covers: the header, the payload, and the protected TLV area. Not the unprotected TLVs.**

The mechanism is in `scripts/imgtool/image.py`. By the time hashing happens, `self.payload` is header plus padded image plus, if any protected TLVs exist, the protected TLV block appended at line 681. Then:

```python
# scripts/imgtool/image.py:687-694
sha = hash_algorithm()
sha.update(self.payload)
digest = sha.digest()
tlv.add(hash_tlv, digest)
self.image_hash = digest
# Unless pure, we are signing digest.
message = digest
```

and the signature is taken over that digest (`image.py:725-731`). The resulting `KEYHASH` and `ECDSASIG` TLVs are then appended to the *unprotected* TLV block, which by construction cannot be covered.

MCUboot's `docs/design.md:1349-1351` states the same rule from the bootloader side: "Whenever an image has protected TLVs the SHA256 has to be calculated over ... the protected TLVs."

The concrete chain, which is the sentence Tier 3 should teach:

> ECDSA P-256 signs a SHA-256 digest of the header, the firmware, and the protected TLVs. The bootloader recomputes that digest from flash, compares it to the `SHA256` TLV, finds the key whose SHA-256 matches the `KEYHASH` TLV, and verifies the `ECDSASIG` TLV against the digest with that key.

The TLV identifiers, from `docs/design.md:106-113`: `IMAGE_TLV_KEYHASH` is `0x01`, `IMAGE_TLV_SHA256` is `0x10`, `IMAGE_TLV_ECDSA_SIG` is `0x22`.

**The signature is a variable-length DER encoding, not a fixed 72 bytes.** `ECDSA256P1.sign()` sets `pad_sig = False` by default (`scripts/imgtool/keys/ecdsa.py:183, 205-212`), so the TLV holds the raw DER signature, typically 70 to 72 bytes. `sig_len()` still returns 72 but only so padding can be applied on request. On the bootloader side `EXPECTED_SIG_LEN(x)` for EC256 is literally `(1)`, always true, with the comment "ASN.1 will validate" (`image_validate.c:86`). Do not build a fixture that assumes a fixed signature length.

## 4. What verification costs

### The cost that is already paid

**Tier 0 already hashes the entire image on every boot.** `CONFIG_BOOT_VALIDATE_SLOT0=y` is in `sysbuild/mcuboot.conf` today, and it compiles in `MCUBOOT_VALIDATE_PRIMARY_SLOT`, which calls `boot_validate_slot()` for the primary slot at `loader.c:1924` on every single boot. That call already runs `bootutil_img_hash()` over the full image and compares the result to the `SHA256` TLV.

This changes the honest answer to "what does signing cost at boot". It is **not** hash plus signature. The hash is already being paid. Turning on ECDSA P-256 adds:

1. one SHA-256 over the compiled-in public key, to match the `KEYHASH` TLV (`bootutil_find_key.c:68-75`), over a few dozen bytes, and
2. one ECDSA P-256 verification over a 32-byte digest.

Both are constant-time-ish fixed costs independent of image size. The image-size-proportional work, which is the part that actually takes real milliseconds on a 590 KB image, was already happening in Tier 0.

MCUboot's own documentation gives the only published figure, and it is for the hash, not the signature: `docs/design.md:1274-1275` describes validation as "a heavy process at boot (~1-2 seconds on a arm-cortex-M0)". The ESP32-C6 is a 160 MHz RISC-V core, far faster than a Cortex-M0, and again this describes work Tier 0 already does.

### Flash and SRAM, measured

Two pristine sysbuild builds of `firmware/reference-product-baseline` in the repo's own container, differing only by the two lines in section 1. Both configured and linked with no warnings and no extra Kconfig. Every number below is **measured**, not documented.

| Bootloader region | Unsigned | ECDSA P-256 | Delta |
| --- | ---: | ---: | ---: |
| `zephyr.bin` | 41,296 B | 46,864 B | **+5,568 B (+13.5%)** |
| `iram_seg` | 34,142 B | 39,402 B | +5,260 B |
| `dram_seg` | 31,384 B | 31,688 B | +304 B |
| `iram_loader_seg` | 1,038 B | 1,038 B | 0 |

**The signed bootloader still fits the 64 KiB partition, with 18,672 bytes spare.** It goes from 63.01% to 71.51% of the 65,536-byte `boot_partition`. The 64 KiB contract holds and needs no change.

On this target MCUboot is loaded into SRAM, so the `iram_seg` growth and the flash growth are the same code counted twice rather than two independent costs.

**The application image does not grow at all.** Its linked size is bit-identical across the signed and unsigned builds:

```
     FLASH:      589972 B    4194176 B     14.07%
sram0_0_seg:      181296 B     488976 B     37.08%
```

and `zephyr.bin` is 590,100 bytes in both. This is the right result and worth saying out loud in the module: **signing changes the bootloader, not the product.** The application never learns to verify anything. Only the 64 KiB of code that runs before it does.

One incidental measurement worth carrying into the tier text: the **unsigned Tier 0 build already runs `imgtool sign`**. The recorded command line differs by exactly one argument pair:

```
imgtool.py sign --version 0.0.0+0 --header-size 0x20 --slot-size 1835008 --align 4 \
  [--key /path/to/course-signing-key.pem] zephyr.bin zephyr.signed.bin
```

So the Tier 0 image is not an unprocessed binary. It already carries an MCUboot header and trailer; it simply has no signature TLV. The Tier 3 diff is one `--key`.

The resolved bootloader configuration confirms the backend from section 1 is what actually got built:

```
CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y
CONFIG_BOOT_ECDSA_TINYCRYPT=y
# CONFIG_BOOT_ECDSA_MBEDTLS is not set
# CONFIG_BOOT_ECDSA_PSA is not set
CONFIG_BOOT_USE_TINYCRYPT=y
CONFIG_BOOT_IMG_HASH_ALG_SHA256=y
```

`CONFIG_BOOT_USE_MBEDTLS` and `CONFIG_BOOT_USE_PSA_CRYPTO` are absent, which for a promptless Kconfig bool means `n`. **Verification is TinyCrypt, and Tier 2's Mbed TLS 4.1.0 is not involved.**

On the application side, sysbuild cleared the unsigned flag by itself, exactly as section 1 predicted:

```
# CONFIG_MCUBOOT_GENERATE_UNSIGNED_IMAGE is not set
CONFIG_MCUBOOT_SIGNATURE_KEY_FILE="/.../course-signing-key.pem"
```

**One caveat on the control.** `docs/esp32c6-build-baseline.md` records the MCUboot binary as 39,600 bytes. The unsigned control measured here is 41,296. The baseline figure predates later Tier 0 work, so the delta above is taken against a control built in the same session with the same options, not against the published number. Only the delta is claimed.

## 5. Does the signed image still fit

**Yes, comfortably. It grows by 112 bytes.** Measured:

| | Unsigned | Signed | Delta |
| --- | ---: | ---: | ---: |
| `zephyr.bin` (linked) | 590,100 B | 590,100 B | 0 |
| `zephyr.signed.bin` | 590,140 B | 590,252 B | **+112 B** |

Against the 1,835,008-byte `slot0_partition` that is **32.17% used, with 1,244,756 bytes of headroom**. The 1,792 KiB slot is not remotely under pressure.

The 112 bytes are exactly the two added TLVs and their alignment: a `KEYHASH` TLV (4-byte TLV header plus a 32-byte SHA-256) and an `ECDSASIG` TLV (4-byte header plus roughly 70 to 72 bytes of DER). The firmware itself does not change, as section 4 shows.

Carry the Tier 2 caveat forward: the linker's `FLASH` region is the whole chip, so **a link will not fail if the image ever outgrows slot0**. That remains true here and is still worth a build-time assertion, though at 32% there is no near-term risk.

## 6. Can a Learner generate the key themselves

**Yes, one command, and it is the only key command they need to run.**

```bash
imgtool.py keygen -k course-signing-key.pem -t ecdsa-p256
```

`ecdsa-p256` is a registered key type in `scripts/imgtool/main.py:77-80`, and `docs/imgtool.md:15-20` documents exactly this form. Adding `-p` prompts for a password and encrypts the private key at rest (`docs/imgtool.md:26`).

This was **run**, not just read. The pinned `imgtool.py version` reports `2.4.0`, and the command above exited 0 and produced a **241-byte** PEM file.

**What comes out is one file, not two.** It is a PEM-wrapped **PKCS#8** private key, unencrypted unless `-p` was given (`scripts/imgtool/keys/ecdsa.py:128-138`). An EC private key contains the public key, so there is no separate public key file to manage, and no separate public key artifact to feed the build.

`imgtool getpub` on that key produced the following, which is verbatim what the build compiles into the bootloader as `autogen-pubkey.c`:

```c
/* Autogenerated by imgtool.py, do not edit. */
const unsigned char ecdsa_pub_key[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    ...
};
const unsigned int ecdsa_pub_key_len = 91;
```

91 bytes. That is the entire trust anchor the bootloader carries, and it is a good number to put in front of a Learner next to Tier 2's certificate.

**The build needs nothing else.** Point `SB_CONFIG_BOOT_SIGNATURE_KEY_FILE` at that one PEM file and the build derives everything: `imgtool getpub` turns it into `autogen-pubkey.c` for the bootloader (section 2), and `imgtool sign` uses the private half to sign the application (section 3).

If the course wants to *show* the Learner the public key rather than only use it, `imgtool.py getpub` has three encodings (`main.py:76, 162-169`), all confirmed present in the pinned 2.4.0 by running `getpub --help`:

- `getpub -k key.pem` (default, `lang-c`): the C array the build actually compiles in
- `getpub -k key.pem -e pem`: a normal PEM public key, for handing to anyone else
- `getpub -k key.pem -e raw`: raw bytes

and `imgtool.py getpubhash -k key.pem` prints the SHA-256 of the public key, which is literally the value the bootloader compares the image's `KEYHASH` TLV against (`main.py:184-196`). That command is a good way to make the key-matching step visible in the module.

**A second, differently-valid key for the "wrong key" fixture is just a second `keygen` run.** Nothing distinguishes it from the real one except that the bootloader was not built with it.

## 7. What each of the four refusals prints

This is the ticket's central question, and the answer is the escape hatch.

### The common path

All four fixtures are images that fail `bootutil_img_validate()`. That function reports a single boolean-ish `fih_ret` and logs no reason. Here is each fixture traced through it.

**Fixture A, an unsigned image.** An image built with `CONFIG_MCUBOOT_GENERATE_UNSIGNED_IMAGE=y` carries a valid header and a correct `SHA256` TLV, and no `KEYHASH` or `ECDSASIG` TLV. Its hash *passes*. The refusal comes from initialisation: `FIH_DECLARE(valid_signature, FIH_FAILURE)` at `image_validate.c:218`. Because no `ECDSASIG` TLV is ever encountered, `valid_signature` is never overwritten, and at `image_validate.c:562-564` (the `FIH_SET` itself is line 563) `FIH_SET(fih_rc, valid_signature)` carries that initial failure out. Silent.

This is worth stating explicitly because MCUboot's `docs/design.md:1269` says an image "*may* contain a signature TLV", which reads as if unsigned images are tolerated. They are not, once `EXPECTED_SIG_TLV` is compiled in. The design document is describing the format, not the policy.

**Fixture B, modified after signing.** If the modification is in the payload, `bootutil_img_hash()` produces a different digest, `boot_fih_memequal()` against the `SHA256` TLV fails, and the code does `goto out` at `image_validate.c:354-358`. Silent. If instead the modification is to the signature bytes, the hash passes and `bootutil_verify_sig()` fails, leaving `valid_signature` as failure. Also silent, and by a different route that produces identical output.

**Fixture C, signed by a different but equally valid key.** The image carries a well-formed `KEYHASH` TLV holding the SHA-256 of the *other* public key. `bootutil_find_key()` hashes each compiled-in key and compares; with one key compiled in and no match, it returns `-1` (`bootutil_find_key.c:68-78`). Back in the TLV loop, `key_id` is `-1`, so when the `ECDSASIG` TLV arrives the handler hits

```c
/* image_validate.c:400-403 */
if (key_id < 0 || key_id >= bootutil_key_cnt) {
    key_id = -1;
    continue;
}
```

and skips the signature entirely. `bootutil_verify_sig()` is **never called**. `valid_signature` stays at its initial failure. Silent, and note that the bootloader never even attempts the cryptography.

**Fixture D, a truncated image.** This one depends on where the truncation lands, and it is the only fixture with a chance of behaving differently. If the truncation removes or corrupts the TLV area, `bootutil_tlv_iter_begin()` fails its `info.it_magic != IMAGE_TLV_INFO_MAGIC` check and returns `-1` (`boot/bootutil/src/tlv.c:79-80`). If truncation leaves the TLV header intact but the declared sizes now exceed the slot, `image_validate.c:298-303` fails instead. If neither, the hash simply mismatches and it degenerates into fixture B.

### What actually reaches the console

At the pinned `CONFIG_MCUBOOT_LOG_LEVEL_INF=y`, every one of A, B, C and D produces exactly:

```
E: Image in the primary slot is not valid!
E: Unable to find bootable image
```

(`loader.c:649-650` and `boot/zephyr/main.c:658`), or the same with `secondary` if the bad image is a downloaded candidate rather than the running one. **Four different security failures, one message, no reason.**

### The one distinction that is free

The `primary`/`secondary` word in that message is chosen at `loader.c:649` and it is real information: it tells the Learner *which slot* was rejected. For Tier 3 that separates "the device refused to install what it downloaded" from "the device refused to boot what is already on it". It does not say why.

There is also a behavioural difference worth building the tier around, because it is louder than any log line: at `loader.c:652-657`, a rejected image is **erased**. For a secondary-slot candidate the bad download is scrambled and the device carries on booting the good primary image. That is a demonstrable, observable outcome that needs no log parsing at all. (The primary-slot erase behaviour interacts with swap-using-offset; that is the subject of issue #49 and is not re-derived here.)

### Turning the log level up does not rescue it

Raising to `CONFIG_MCUBOOT_LOG_LEVEL_DBG=y` adds the `BOOT_LOG_DBG` traces in `image_validate.c` at lines 256, 288, 297, 302, 333, 343, 367 and 398, plus the TLV iterator traces in `tlv.c` at lines 50, 117, 128, 136, 147 and 156. These are **entry traces, not failure reasons**. Not one of them says "hash mismatch" or "signature invalid". What you get is the ability to infer the cause from how far the trace got:

| Fixture | Last debug line reached | Distinguishable? |
| --- | --- | --- |
| A, unsigned | `EXPECTED_HASH_TLV == 16`, then the iterator runs to the end and reports no more TLVs | Only from the *absence* of key and signature traces |
| B, payload modified | `EXPECTED_HASH_TLV == 16`, then nothing | Confusable with A; differs only by the missing trailing iterator lines |
| B', signature bytes modified | `EXPECTED_HASH_TLV`, `EXPECTED_KEY_TLV == 1`, `EXPECTED_SIG_TLV == 34` | Not distinguishable from C |
| C, wrong key | `EXPECTED_HASH_TLV`, `EXPECTED_KEY_TLV == 1`, `EXPECTED_SIG_TLV == 34` | Not distinguishable from B' |
| D, truncated | `bootutil_img_validate: TLV iteration failed -1` or `TLV beyond image size` | **Yes, genuinely distinct** |

So debug level buys one clean distinction (the truncated image) and a set of inferences from silence. It does not give four named reasons. Asking a Learner to tell "unsigned" from "modified" by noticing which debug line is *missing* is not a lesson, it is a puzzle.

### What this means for Tier 3

The tier cannot get its four distinguishable reasons from the stock bootloader console. The options, in the order I would consider them:

1. **Teach the refusal, not the reason.** All four are refused, the device keeps running good firmware, the bad image is erased. Show the identical message four times and make the *point* that the bootloader deliberately does not tell an attacker which check failed. This is honest, needs no patch, and is itself a real security-engineering lesson about not leaking oracle information.
2. **Distinguish the fixtures on the host, not the device.** `imgtool verify -k key.pem <image>` run on the Learner's machine does name the reason, and the four fixtures differ clearly there. Pair a host-side explanation with a device-side refusal.
3. **Patch the bootloader to log reasons.** Small and local: the failure sites in `image_validate.c` are few and each could carry a `BOOT_LOG_ERR`. But it forks the pinned MCUboot, which the course has so far avoided, and it teaches a bootloader the Learner cannot get anywhere else.

That decision belongs to the ticket that follows this one, not to this note. What this note settles is that option 1 is available at zero cost and options 2 and 3 are the only ways to get four named reasons.

## 8. Log level, and what it costs

`CONFIG_MCUBOOT_LOG_LEVEL` is a standard Zephyr log-level symbol, generated from `subsys/logging/Kconfig.template.log_config` by `boot/zephyr/Kconfig:1015-1017`, so the usual `_ERR`, `_WRN`, `_INF`, `_DBG` variants exist.

**The pinned level is already sufficient for the refusal messages.** Both `Image in the ... slot is not valid!` and `Unable to find bootable image` are `BOOT_LOG_ERR`, so they appear at `ERR` level and above. `CONFIG_MCUBOOT_LOG_LEVEL_INF=y` is already set in `sysbuild/mcuboot.conf`, so **Tier 3 needs no logging change at all** to see refusals. Keeping `INF` also keeps the install and swap messages the course already quotes in Tier 0.

`CONFIG_LOG_MODE_MINIMAL=y` must stay. The baseline doc records why: the deferred default buffers messages and loses them exactly when the bootloader stops, which is precisely the moment a refusal happens.

**If the tier does decide to raise the level, it is affordable but not free.** A third build, identical to the signed one except with `CONFIG_MCUBOOT_LOG_LEVEL_DBG=y` replacing `_INF`, was measured:

| Bootloader | Unsigned, INF | Signed, INF | Signed, DBG |
| --- | ---: | ---: | ---: |
| `zephyr.bin` | 41,296 B | 46,864 B | 51,104 B |
| % of 64 KiB | 63.01% | 71.51% | **77.98%** |
| spare | 24,240 B | 18,672 B | 14,432 B |
| `iram_seg` | 34,142 B | 39,402 B | 40,874 B |
| `dram_seg` | 31,384 B | 31,688 B | 34,456 B |

Debug logging costs a further **+4,240 bytes** of flash on top of signing. It still fits, with 14,432 bytes spare, so it is a real option. But note that signing plus debug logging together consume 9,808 of the 24,240 bytes that were free in the unsigned bootloader, which is about 40% of the remaining headroom in a partition the course has declared a hard contract. Spend it knowingly, and only if section 7 persuades the tier that the debug traces are worth it. My reading is that they are not.

## What I could not establish

1. **Boot-time cost was not measured on hardware.** No board was touched, by instruction. The reasoning in section 4 (that the SHA-256 pass is already paid in Tier 0 and only a fixed-cost P-256 verification is added) is derived from source, not from a stopwatch. *Settle it:* bracket the boot with a GPIO toggle or compare timestamps in the MCUboot log across a signed and unsigned build on the same board.
2. **The four fixtures were not actually built and refused on hardware.** Section 7 is traced from source, carefully, but it is a reading of control flow rather than a serial capture. The escape-hatch conclusion is the kind of claim that deserves a capture before it reaches course material. *Settle it:* build the four fixtures, install each over OTA, and capture the console. Expect four identical refusals; if anything differs, this note is wrong and should be corrected.
3. **Whether truncation in practice lands in the TLV area.** Section 7 fixture D branches three ways depending on where the cut falls. Which branch a realistic truncated download takes is an empirical question. *Settle it:* truncate at a few different fractions and see which message appears at debug level.
4. **Whether `imgtool verify` names all four reasons distinctly.** Option 2 in section 7 assumes it does. I read `imgtool`'s signing path, not its verify path. *Settle it:* run `imgtool verify` against each of the four fixtures and read the output.
5. **Interaction with swap-using-offset for a rejected image.** Deliberately not re-derived here; it is issue #49's subject.
