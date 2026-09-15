# What the section 8 PSA Secure Storage configuration guarantees on ESP32-C6

Research ticket [#110](https://github.com/tkEmLogic/learning-cyber-security/issues/110), part of map
[#104](https://github.com/tkEmLogic/learning-cyber-security/issues/104).

This report extends the "Zephyr: secure storage, settings, and a caveat for ESP32-C6"
section of `research/device-identity-and-provisioning.md` on branch `research/provisioning`.
That section established the caveat. This one establishes the mechanism, so the Tier 6
module can state the positive half as precisely as the negative half.

Everything below is read from Zephyr 4.4.2 as it sits in the `tier2-validate` container at
`/opt/zephyr-workspace`, from Espressif's published documentation, and from Zephyr's own
documentation source. Nothing here has been run on the board. Where a fact needs a board
run before the module asserts it, this report says so.

## Short answer

The configuration gives three real things and one thing that looks real and is not.

Real. The stored record is AES-GCM ciphertext plus a 16 byte tag, so the P-256 private key
is not sitting in flash as readable bytes. Any modification to the record is detected on
read and the read fails instead of returning altered data. The record is bound to its own
UID and to this particular board, so it cannot be moved to another slot or another device.

Not real. The key that does all of this is `SHA-256(MAC || 0x0000 || UID)`. The MAC is the
board's Wi-Fi station address. It is printed by `esptool read-mac` over the same USB cable
used to dump the flash, and it is in every Wi-Fi frame the device sends. The UID is the PSA
key ID from source the Learner built, and it is also written in clear text as the settings
entry name in the same flash dump. So the attacker who dumps the flash already holds both
halves of the key derivation. The encryption raises the cost of reading the key out of a
dump from "look at it" to "run one hash and one decrypt".

Zephyr says both halves itself. The Kconfig help text for the default key provider ends
"This is not necessarily secure as the device ID may be easily readable by an attacker, not
unique, and/or guessable, depending on the device." The subsystem prints
`WARNING: Using a potentially insecure PSA ITS encryption key provider.` at every boot. And
the Secure Storage documentation states outright that "the data stored in the ITS is not
protected against replay attacks".

The phrase to keep out of the module is "encrypted at rest" standing on its own. It is
literally true and it stops the Learner thinking. Section 4 below gives wording that does
not.

## 1. What the device-ID-hash provider derives its key from on ESP32-C6

### The derivation, exactly

`CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_PROVIDER_DEVICE_ID_HASH` is implemented in
`secure_storage_its_transform_aead_get_key()`, at
`zephyr/subsys/secure_storage/src/its/transform/aead_get.c` lines 65 to 92. It builds a
12 byte packed struct and hashes it:

| Field | Size | Source on ESP32-C6 |
| --- | --- | --- |
| `device_id` | 8 bytes | `hwinfo_get_device_eui64()` first, then `hwinfo_get_device_id()` |
| `uid` | 4 bytes | the ITS entry UID, 30 bit UID plus 2 bit caller ID, acting as a salt |

The 32 byte AES key is `SHA-256` over those 12 bytes (`hash_data_into_key()`, lines 38 to 59,
with `CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_SIZE` defaulting to 32, which equals the
SHA-256 output size, so no truncation happens). The key is derived fresh on every read and
every write, is never stored, and is zeroized after use with `mbedtls_platform_zeroize()`
(`aead.c` line 53, `aead_get.c` line 90).

### What `device_id` actually is on this chip

The ESP32 hwinfo driver is `zephyr/drivers/hwinfo/hwinfo_esp32.c`. It implements
`z_impl_hwinfo_get_device_id()` only. It does **not** implement
`z_impl_hwinfo_get_device_eui64()`, so that call falls through to the weak stub in
`hwinfo_weak_impl.c` line 14, which returns `-ENOSYS`. The provider therefore always takes
the second branch on this board.

`z_impl_hwinfo_get_device_id()` reads `EFUSE_RD_MAC_SPI_SYS_0_REG` and
`EFUSE_RD_MAC_SPI_SYS_1_REG` (the `#elif !defined(CONFIG_SOC_SERIES_ESP32)` branch, lines 27
to 33) and assembles **6 bytes of the factory MAC address** from eFuse BLK1 (lines 34 to 54).
It returns 6.

Back in `aead_get.c`, the buffer is 8 bytes, the driver filled 6, so lines 83 to 85 zero-pad
the remaining two:

```c
if (hwinfo_ret < sizeof(data.device_id)) {
        memset(data.device_id + hwinfo_ret, 0, sizeof(data.device_id) - hwinfo_ret);
}
```

So the key input is `MAC[0..5] || 0x00 0x00 || UID[0..3]`, hashed with SHA-256.

There is no configuration mistake here. This is Zephyr's default on this board:
`CONFIG_HWINFO_ESP32` is `default y` for `SOC_FAMILY_ESPRESSIF_ESP32` and it
`select HWINFO_HAS_DRIVER` (`drivers/hwinfo/Kconfig.esp32`), and the key provider choice in
`Kconfig.its_transform` is `default SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_PROVIDER_DEVICE_ID_HASH
if HWINFO_HAS_DRIVER`. The spec's pinned configuration names it explicitly, which is correct
and should stay. It is the guarantee, not the setting, that needs care.

### How readable that MAC is, in practice

Four ways, ordered by how little the attacker needs.

| Route | What it needs | Cost |
| --- | --- | --- |
| `esptool read-mac` | the same USB cable used to dump the flash | seconds |
| Any Wi-Fi capture | RF range while the device is associating or probing | passive, no contact |
| The service's own records | a look at the device record, since the MAC is the obvious device identifier | none |
| Guessing within a batch | knowing the vendor and roughly when the boards were made | Espressif assigns universally administered addresses sequentially from its OUI blocks |

The Wi-Fi route is the one worth naming in the module, because it removes the "but the
attacker needed physical access anyway" objection. Espressif's MAC address allocation
documentation for ESP32-C6 states that the base MAC address is pre-programmed into eFuse
BLK1 in the factory, and that the Wi-Fi station MAC is the base MAC unchanged. This is
confirmed in the vendored HAL: `generate_mac()` in
`modules/hal/espressif/components/esp_hw_support/mac_addr.c` does
`case ESP_MAC_WIFI_STA: memcpy(mac, base_mac_addr, 6);`. The station MAC is therefore byte
for byte the value Zephyr hashes into the storage key, and it is transmitted in clear in
every frame the device sends.

That is the finding that makes the fixed limitation in section 8 concrete: this is not a
secret that happens to be weak, it is a value the device advertises.

### The UID half is not entropy either

The second input is the ITS entry UID. For a persistent PSA Crypto key, the ITS UID is the
PSA key ID itself: `psa_its_identifier_of_slot()` in
`modules/crypto/tf-psa-crypto/core/psa_crypto_storage.c` lines 40 to 57 returns the key ID
directly. The Learner's own application chooses that ID, from the range at
`zephyr/include/zephyr/psa/key_ids.h` (`ZEPHYR_PSA_APPLICATION_KEY_ID_RANGE_BEGIN` is
`0x30000000`). It is in the source they built. It is also written in clear text into the
flash, as shown in section 3.

So the UID is a salt in the strict sense, it separates keys between records, and it is not a
secret. The whole derivation has no secret input.

## 2. What the AES-GCM transform detects, and why replay is not among it

### The stored record

`zephyr/subsys/secure_storage/src/its/transform/aead.c` lines 63 to 76 define what lands in
flash and what is authenticated:

```c
struct stored_entry {
        secure_storage_packed_create_flags_t create_flags;   /* 1 byte, in clear */
        uint8_t nonce[CONFIG_..._AEAD_NONCE_SIZE];           /* 12 bytes, in clear */
        uint8_t ciphertext[CIPHERTEXT_MAX_SIZE];             /* data + 16 byte tag */
} __packed;

struct additional_data {
        secure_storage_its_uid_t uid;                        /* AAD */
        secure_storage_packed_create_flags_t create_flags;   /* AAD */
} __packed;
```

`CONFIG_SECURE_STORAGE_ITS_TRANSFORM_OUTPUT_OVERHEAD` defaults to 28, documented in
`Kconfig.its_transform` as "authentication tag (16) + nonce (12)". With the one clear
`create_flags` byte, a record is 29 bytes larger than its plaintext.

### What it detects

| Modification | Detected | Mechanism |
| --- | --- | --- |
| Any bit flipped in the ciphertext | Yes | GCM tag check fails |
| The 16 byte tag altered | Yes | tag check fails |
| The 12 byte nonce altered | Yes | decryption uses the stored nonce, so the tag no longer matches |
| The clear `create_flags` byte altered, for example clearing `WRITE_ONCE` | Yes | `create_flags` is in the AAD |
| A record copied into a different UID's settings entry | Yes, twice over | the UID is in the AAD, and the UID is also hashed into the key |
| A record copied to a second ESP32-C6 | Yes | the other board's MAC derives a different key |
| Truncation below the minimum length | Yes | `stored_data_len < STORED_ENTRY_LEN(0)` returns `PSA_ERROR_DATA_CORRUPT` (`aead.c` lines 111 to 113) |
| **An older, genuine copy of the same record written back** | **No** | nothing in the record is fresh |

The last row is the whole of sub-question 2 and it is worth being exact about why.

### Why replay is not detected

Zephyr states it directly, in `zephyr/doc/services/storage/secure_storage/index.rst`
lines 74 and 75:

> In addition, the data stored in the ITS is not protected against replay attacks,
> because this requires storage that is protected by hardware.

The mechanism behind that sentence, from the source:

1. The authenticated data is `{uid, create_flags}` and nothing else. There is no version,
   no counter, no generation number, no timestamp.
2. The key is a pure function of the device ID and the UID. It does not change when the
   record is rewritten.
3. Therefore every ciphertext ever validly written for a given UID on a given board stays
   valid for that UID on that board, forever. "This record is authentic" is a true statement
   about an old record as much as a current one.
4. The nonce does not help. It is stored in clear alongside the ciphertext and is read back
   from the record being decrypted, so replaying an old record replays its own nonce with it.

There is a second, more practical half. The store backend is the settings subsystem over NVS
(`CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS` with `SETTINGS_NVS`, as section 8
pins). Zephyr's NVS documentation describes it as a FIFO-managed circular buffer where
"Elements are appended to a sector until storage space in the sector is exhausted", with old
copies surviving until that sector is garbage collected. So the attacker does not have to
have saved an old record. Superseded copies of a rewritten record are usually still physically
present in the same flash dump.

The practical consequence for Tier 6, which is a lifecycle tier and therefore rewrites
identity records: an attacker who can write flash can restore a previous operational key, or
restore a Factory record to its state before a revocation or an ownership transfer, without
ever deriving the key. This is worth stating in the module because it is the one weakness
here that does not require even the MAC.

### What "detected" means at the API

Detection is a refusal, not a repair. `transform_stored_data()` in
`src/its/implementation.c` lines 63 to 78 logs and returns `PSA_ERROR_GENERIC_ERROR`. Above
it, `keep_stored_entry()` (lines 96 to 130) treats a record that fails to decrypt as absent,
with the comment "Allow overwriting corrupted entries to not be stuck with them forever", and
`secure_storage_its_remove()` (lines 242 to 269) likewise allows removal of a corrupted
record. So a tampered identity record becomes an unusable and replaceable record. The device
does not serve a forged key, and it does not recover the real one either. That is an
availability outcome, and the module should say so rather than let "detected" imply
"survived".

### One caveat the module should record rather than claim

The default nonce provider (`aead_get.c` lines 122 to 153) generates one random nonce with
`psa_generate_random()` at the first write after boot and then increments it for each
subsequent write. The Kconfig help text says "A random source that doesn't repeat values
between reboots is required for this to be secure." Since the key for a given record never
changes, a nonce that repeats across reboots would be an AES-GCM nonce reuse under a fixed
key, which is the failure mode GCM handles worst.

On ESP32-C6, Espressif documents that the hardware RNG produces true random numbers when the
RF subsystem is enabled (Wi-Fi, Bluetooth or 802.15.4) or when the SAR ADC entropy source is
explicitly enabled, and that otherwise "the output of the RNG should be considered as
pseudo-random only". The Zephyr driver comment in `drivers/entropy/entropy_esp32.c` says the
same thing, that the extra entropy arrives "provided Wi-Fi or BT are enabled".

This matters for Tier 6 specifically, because the first ITS write happens during provisioning,
which may run before the network is up. This report does **not** claim a defect. It flags a
condition to check on the board: confirm Wi-Fi is initialised before the first Secure Storage
write, or record it as an open limit. Proposed as ledger row `T6-W-19` in section 5, in the
shape of `T5-W-15`.

## 3. What an attacker who reads the flash gets, and what they need next

This is the fact the flash-dump demonstration turns into an observation, so it is set out
here as the expected result of the lab, to be confirmed on the board before the module
asserts it.

### What is in the dump

`esptool read-flash` over the storage partition yields, for each stored record:

| Item | State in flash | Where it comes from |
| --- | --- | --- |
| The settings entry name, for example `its/2/30000001` | clear text | `settings.c` lines 35 to 51, prefix `its/` from `CONFIG_SECURE_STORAGE_ITS_STORE_SETTINGS_PREFIX`, then `<caller_id hex>/<uid hex>` |
| `create_flags` | clear text, 1 byte | `struct stored_entry`, first field |
| The nonce | clear text, 12 bytes | `struct stored_entry`, second field |
| The private key | AES-GCM ciphertext | `struct stored_entry.ciphertext` |
| The GCM tag | 16 bytes | appended to the ciphertext by PSA |
| The plaintext length | inferable | GCM is a stream mode with no padding, so plaintext length is `record length - 29` |
| Older copies of the same record | often present | NVS appends and garbage collects later |
| NVS metadata | clear text | 8 byte entries written from the end of each sector |

The caller ID for a persistent PSA Crypto key is `SECURE_STORAGE_ITS_CALLER_MBEDTLS`, which
is `2` in the enum at
`subsys/secure_storage/include/internal/zephyr/secure_storage/its/common.h` lines 17 to 22,
selected by `ITS_CALLER_ID` in `include/psa/internal_trusted_storage.h` when
`BUILDING_MBEDTLS_CRYPTO` is defined. So `its/2/<key id in hex>` is the name to expect. Confirm
the exact string on the board.

So the dump alone tells the attacker: this device holds a PSA persistent key, here is its key
ID, here is exactly how many bytes the private key encoding is, and here is the ciphertext
and its nonce. It does not yet give them the key bytes.

### What they need next

One value: the board's 6 byte base MAC. Then:

```
key       = SHA-256( MAC[0..5] || 0x00 0x00 || UID_as_stored_4_bytes )
plaintext = AES-256-GCM-decrypt( key, nonce, ciphertext||tag, aad = UID||create_flags )
```

The UID they already have from the entry name. The `create_flags` byte they already have from
the record. The nonce they already have. So the entire remaining unknown is the MAC, and
`esptool read-mac` on the cable already attached returns it.

Two details to pin down on the board before the module prints a recipe, because they are
byte-order questions that source reading should not settle:

1. The exact 4 byte layout of `secure_storage_its_uid_t` as hashed. It is a packed bitfield
   struct, 30 bits of UID and 2 bits of caller ID, asserted to be 4 bytes at
   `src/its/implementation.c` line 15. The byte order as fed to SHA-256 should be read off a
   working decrypt, not assumed.
2. Whether the settings entry name in the dump matches `its/2/<hex>` exactly.

### The honest summary for the Learner

The encryption did not stop the extraction. It added one hash and one decrypt, using a value
the device broadcasts. What it did stop is a `strings` or pattern scan finding the key by
accident, and what it does do is make any edit to the record fail loudly. Those are real and
they are small. The module should let the Learner watch the decrypt succeed, because the
memory of that is what makes "encrypted at rest" stop being reassuring.

## 4. The precise wording the course may use

Shaped to match the "Security claims permitted and prohibited" subsection in section 9 of
`docs/course-specification.md`.

### Permitted sentences

The course may say that the section 8 Secure Storage configuration:

1. Encrypts each stored record with AES-GCM and authenticates it with a 16 byte tag, so the
   private key does not appear in flash as readable bytes.
2. Detects any change to a stored record. A modified ciphertext, tag, nonce or flags byte
   makes the read fail, and the device refuses the record rather than returning altered data.
3. Binds each record to its own entry UID and to this one board, so a record moved to another
   entry, or copied onto a second ESP32-C6, fails to decrypt.
4. Derives its encryption key at each use and never stores it, zeroizing it from memory
   afterwards.
5. Raises the cost of reading a key out of a flash dump from reading it directly to running a
   known derivation first.
6. Is Zephyr's own default configuration on this board, which Zephyr documents as functional
   support for the PSA Secure Storage API rather than a guarantee that data is secure at rest.
7. Warns about itself. Zephyr prints `WARNING: Using a potentially insecure PSA ITS encryption
   key provider.` at every boot, and the course leaves that warning enabled.
8. Is replaced, in a production design, by a custom key provider rooted in protected
   device-specific hardware, or by another reviewed secure-storage design.

Every one of these is a statement about detection, binding or cost. None is a statement about
secrecy holding against someone who wants the key.

### Prohibited sentences

The course must never say that this configuration:

1. Is hardware-backed, hardware-protected, or rooted in hardware.
2. Stores the key in a secure element, a protected key store, or anywhere the application
   cannot reach.
3. Keeps the private key from being extracted from the device, or from a flash dump.
4. Means only this device can decrypt its own records. Anyone who knows the device's MAC can.
5. Treats the device ID as a device secret, a root secret, a root of trust, or a unique key.
6. Prevents tampering, or makes records tamper-proof. It detects tampering. It does not
   prevent it.
7. Prevents an old record from being restored, prevents rollback of a stored identity, or
   protects against replay. Zephyr states that it does not.
8. Protects keys from privileged firmware, from the application itself, from a debugger, or
   at runtime in any form. Zephyr states that stored data "is not protected from direct
   read/write by software or debugging".
9. Enforces the non-exportable marking on the private key. The course marks keys
   non-exportable at its own API boundary, and the storage cannot enforce that property
   against compromised privileged firmware.
10. Is PSA compliant, or satisfies the PSA Internal Trusted Storage requirements. Zephyr states
    that its implementation "does not aim at full compliance with the specification" and lists
    the deviations.
11. Makes NVS encrypted. NVS supplies persistence. The transform supplies encryption.
12. Is sufficient, adequate, production ready, or good enough for a shipped product.

### Softer wordings that are also prohibited

These are the phrases that would smuggle claim 1 back in while sounding careful. They are
banned by name so that a later edit cannot reintroduce them as a simplification.

| Do not write | Why it is wrong here |
| --- | --- |
| "a hardware-derived key" | true of the input, and it reads as hardware protection of the key |
| "a hardware-unique key", "a chip-unique key" | the value is unique per chip and is also public. Uniqueness is not secrecy |
| "keyed to the silicon", "bound to the hardware root" | implies a root secret. There is none |
| "uses the chip's hardware identity" | same implication, softer |
| "encrypted at rest", standing alone | true, and it ends the Learner's thinking. Only usable when the next sentence says with what key |
| "protected storage", "the secure store protects the key" | "protects" is exactly the word under dispute |
| "secure storage keeps the key safe" | unqualified safety claim |
| "an attacker cannot simply read the key" | "simply" hides that they can, with one extra step |
| "the key never leaves the device" | true of the private key and irrelevant, since the attacker comes to the device |

### A suggested paragraph in section 9's voice

If this is folded into `docs/course-specification.md`, the section 9 shape is:

> **Fixed decision.** The course may say that the section 8 Secure Storage configuration
> encrypts and authenticates each stored record with AES-GCM, detects any modification to a
> record so that the read fails rather than returning altered data, binds each record to its
> own entry UID and to one physical board, derives its encryption key at each use without
> storing it, and raises the cost of reading a key out of a flash dump. The course must never
> say that this configuration is hardware-backed or hardware-protected, that it prevents
> extraction of the private key, that only this device can decrypt its records, that the
> device ID is a secret, that it prevents rather than detects tampering, that it protects
> against replay or rollback of a stored record, that it protects keys from privileged
> firmware, a debugger or the application at runtime, that it enforces a non-exportable
> marking, that it is PSA compliant, that NVS is encrypted, or that it is sufficient for a
> shipped product. Wordings such as "hardware-derived key", "chip-unique key", "bound to the
> silicon" and a bare "encrypted at rest" are prohibited on the same grounds.

## 5. Weakness ledger rows

Section 8 says the Tier 6 ledger keeps these risks open, so these are new `T6-W-` rows and
they are limits rather than achievements. Tier 5 closed at `T5-W-15`, so numbering continues
at 16. The numbers below are provisional: Tier 6 has other tickets producing rows, and the
final order is the module's to fix.

Two table shapes are in use. `course-material/tiers/tier-05-recovery/index.md` uses
`| Weakness | Result after this tier | Status | Evidence or next action |` for the after table
(line 417) and `| Weakness | What it means today | How you would see it | Where it is
addressed |` for the inherited table (line 60). Both are given.

### Rows for the "after the work" table

| Weakness | Result after this tier | Status | Evidence or next action |
| --- | --- | --- | --- |
| T6-W-16 | New. The Secure Storage encryption key is `SHA-256` of the board's MAC and the record's UID. Both are public. The MAC is printed by `esptool read-mac` on the same cable used to dump the flash, and is broadcast in every Wi-Fi frame. Anyone who can read the flash can derive the key | Open | Residual risk with an owner. Demonstrated in the flash-dump lab. Advanced Tier B, STSAFE-A120 |
| T6-W-17 | New. Stored records carry no freshness. Nothing in a record distinguishes the current version from an earlier one, so writing back an older copy is accepted as authentic. NVS appends rather than overwrites, so superseded copies are usually still in the same dump. An operational key, or a record's state before a revocation or transfer, can be restored without deriving any key | Open | Recorded limit. Zephyr states it does not protect against replay. Needs hardware-protected storage |
| T6-W-18 | New. The private key is protected at rest only. Privileged firmware, the application itself and a debugger can all ask PSA for the key or read it from RAM. The course marks keys non-exportable at its own API boundary and nothing below that boundary enforces it | Open | Residual risk with an owner. Advanced Tier B, STSAFE-A120 |
| T6-W-19 | New. The AES-GCM nonce is randomised once per boot and then incremented, while the record's key never changes. The ESP32-C6 RNG is only a true random source while the RF subsystem is enabled, so a nonce drawn before Wi-Fi is up would weaken the guarantee. Zephyr's own Kconfig says a source that does not repeat between reboots is required | Open | Recorded limit. Confirm on the board that Wi-Fi is up before the first Secure Storage write. Recheck on any Zephyr upgrade |

### The same rows as the next tier will inherit them

| Weakness | What it means today | How you would see it | Where it is addressed |
| --- | --- | --- | --- |
| T6-W-16 | The storage key is derived from a value the device advertises | Dump the flash, read the MAC, derive the key, decrypt the record | Advanced Tier B |
| T6-W-17 | A stored record can be rolled back to an earlier valid version | Write back an older copy of the record from the same dump | Needs hardware-protected storage. Out of scope for the core course |
| T6-W-18 | Storage protects the key at rest, never at runtime | Ask PSA for the key from the application, or attach a debugger | Advanced Tier B |
| T6-W-19 | Nonce freshness depends on the RNG state at the first write | Compare the nonce across a cold boot before the network is up | Recorded limit. Recheck on any Zephyr upgrade |

### Notes on the shape

Four new rows, all limits. That is consistent with Tier 5's observation that a control tier's
ledger is mostly limits, and stronger here: Tier 6 adds per-device identity and closes
`T0-W-02`, and the storage underneath that identity opens four rows at once.

`T6-W-16` is the row to put in front of the Learner, because it is the one the lab makes
visible. `T6-W-17` is the one most likely to be skipped, because nothing in the lab fails when
it is exercised, which is precisely what makes it worth naming.

Two of the four point at Advanced Tier B rather than at a later core tier, which matches
section 8's statement that Advanced Tier B replaces this boundary with STSAFE-A120 key
isolation. `T6-W-17` points at neither, because the course has no tier that fixes it. It needs
hardware-protected storage, which section 9's STSAFE-A120 module does not provide for arbitrary
records either. Say so rather than pointing it somewhere for tidiness.

## Sources

Read on 2026-09-15. Container paths are inside `tier2-validate` at `/opt/zephyr-workspace`,
Zephyr `VERSION` confirmed as 4.4.2.

### Zephyr source, read in the container

- `zephyr/subsys/secure_storage/Kconfig.its_transform` — key provider choice and its help text,
  `DEVICE_ID_HASH` default when `HWINFO_HAS_DRIVER`, "not necessarily secure as the device ID
  may be easily readable by an attacker, not unique, and/or guessable"; AEAD scheme choice with
  AES-GCM as default; `OUTPUT_OVERHEAD` default 28 commented "authentication tag (16) + nonce
  (12)"; `AEAD_KEY_SIZE` default 32; nonce provider help text "A random source that doesn't
  repeat values between reboots is required for this to be secure";
  `SECURE_STORAGE_ITS_TRANSFORM_AEAD_NO_INSECURE_KEY_WARNING`.
- `zephyr/subsys/secure_storage/src/its/transform/aead_get.c` lines 31 to 59
  (`hash_data_into_key`), 61 to 92 (`secure_storage_its_transform_aead_get_key`, the 12 byte
  struct, the eui64-then-device-id fallback, the zero padding at 83 to 85), 107 to 117 (the boot
  warning `printk`), 122 to 153 (the default nonce provider).
- `zephyr/subsys/secure_storage/src/its/transform/aead.c` lines 10 to 55 (`psa_aead_crypt`, key
  zeroization at 53), 63 to 76 (`struct stored_entry` and `struct additional_data`), 78 to 103
  (`..._to_store`), 105 to 128 (`..._from_store`, the length check at 111 to 113).
- `zephyr/subsys/secure_storage/src/its/implementation.c` line 15 (the 4 byte UID assert), 63 to
  78 (`transform_stored_data` returning `PSA_ERROR_GENERIC_ERROR`), 96 to 130
  (`keep_stored_entry`, "Allow overwriting corrupted entries"), 242 to 269
  (`secure_storage_its_remove`).
- `zephyr/subsys/secure_storage/src/its/store/settings.c` lines 28 to 53 (the settings entry name
  `<prefix><caller_id hex>/<uid hex>`), 55 to 76, 94 to 115, 117 to 128.
- `zephyr/subsys/secure_storage/Kconfig` — subsystem help text, "not a guarantee of the
  subsystem"; `SECURE_STORAGE_ITS_MAX_DATA_SIZE` default 128.
- `zephyr/subsys/secure_storage/Kconfig.its_store` — settings prefix default `"its/"`, name
  length defaults.
- `zephyr/subsys/secure_storage/include/internal/zephyr/secure_storage/its/common.h` lines 17 to
  22 (caller ID enum, `MBEDTLS` is 2), 35 to 47 (the 30 plus 2 bit packed UID).
- `zephyr/subsys/secure_storage/include/internal/zephyr/secure_storage/common.h` line 11
  (`secure_storage_packed_create_flags_t` is `uint8_t`).
- `zephyr/subsys/secure_storage/include/psa/internal_trusted_storage.h` lines 13 to 18
  (`ITS_CALLER_ID` selection).
- `zephyr/drivers/hwinfo/hwinfo_esp32.c` lines 16 to 55 — `z_impl_hwinfo_get_device_id()` reads
  `EFUSE_RD_MAC_SPI_SYS_0_REG` and `_1_REG` and returns 6 MAC bytes. No `eui64` implementation.
- `zephyr/drivers/hwinfo/hwinfo_weak_impl.c` line 14 — `z_impl_hwinfo_get_device_eui64()` weak
  stub returns `-ENOSYS`.
- `zephyr/drivers/hwinfo/Kconfig.esp32` — `HWINFO_ESP32` is `default y` and
  `select HWINFO_HAS_DRIVER`.
- `zephyr/drivers/entropy/entropy_esp32.c` lines 42 to 52 — "provided Wi-Fi or BT are enabled".
- `zephyr/include/zephyr/psa/key_ids.h` lines 47 to 49 —
  `ZEPHYR_PSA_APPLICATION_KEY_ID_RANGE_BEGIN` is `0x30000000`.
- `modules/crypto/tf-psa-crypto/core/psa_crypto_storage.c` lines 40 to 57 —
  `psa_its_identifier_of_slot()` returns the key ID as the ITS UID.
- `modules/hal/espressif/components/esp_hw_support/mac_addr.c` — `generate_mac()`,
  `case ESP_MAC_WIFI_STA: memcpy(mac, base_mac_addr, 6);`.

### Zephyr documentation

- `zephyr/doc/services/storage/secure_storage/index.rst`, read in the container, and published at
  https://docs.zephyrproject.org/latest/services/storage/secure_storage/index.html
  — lines 30 to 45 (limitations, "does not guarantee that the data it stores will be secure at
  rest in all cases"), 58 to 75 ("It requires a random entropy source and especially a secure
  encryption key provider", and "the data stored in the ITS is not protected against replay
  attacks, because this requires storage that is protected by hardware"), 77 to 82 ("not
  protected from direct read/write by software or debugging. It is only secured at rest"), 116
  to 118 (custom key provider recommended).
- `zephyr/doc/services/storage/nvs/nvs.rst`, published at
  https://docs.zephyrproject.org/latest/services/storage/nvs/nvs.html
  — "Elements, represented as id-data pairs, are stored in flash using a FIFO-managed circular
  buffer", appended until the sector is exhausted, copied forward before erase.

### Espressif documentation

- MAC Address Allocation, ESP32-C6, stable:
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/misc_system_api.html
  — base MAC pre-programmed into eFuse BLK1 in the factory; Wi-Fi station MAC is the base MAC,
  SoftAP is base plus one, Bluetooth is base plus two.
- Random Number Generation, ESP32-C6, stable:
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/random.html
  — true random when the RF subsystem is enabled or the SAR ADC entropy source is enabled,
  otherwise "the output of the RNG should be considered as pseudo-random only".
- esptool basic commands, ESP32-C6:
  https://docs.espressif.com/projects/esptool/en/latest/esp32c6/esptool/basic-commands.html
  — `read-flash` reads back flash contents to a file, `read-mac` reads the built-in MAC address.
- eFuse Manager, ESP32-C6, stable (inherited from the section 8 source report):
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html

### Course repository

- `research/device-identity-and-provisioning.md` on branch `research/provisioning`, section
  "Zephyr: secure storage, settings, and a caveat for ESP32-C6" — the existing state of
  knowledge this report extends.
- `docs/course-specification.md` section 8, "Key generation and storage" and its **Fixed
  limitation** paragraph; section 9, "Security claims permitted and prohibited".
- `course-material/tiers/tier-05-recovery/index.md` lines 56 to 68 and 413 to 429 — the two
  ledger table shapes and the `T5-W-14` / `T5-W-15` precedent.
- `course-material/tiers/tier-04-release-policy/index.md` lines 476 to 481 — the "limits rather
  than achievements" framing.
