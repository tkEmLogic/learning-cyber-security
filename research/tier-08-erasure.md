# What reliable erasure means on an ESP32-C6

**Research question:** [GitHub issue #209](https://github.com/tkEmLogic/learning-cyber-security/issues/209), part of map [#203](https://github.com/tkEmLogic/learning-cyber-security/issues/203)

**Access and review date:** 22 September 2026

**Status:** Research. This report establishes facts. It designs nothing and it decides nothing.

**How to read the evidence marks.** Every claim in this report carries one of three marks. **Source** means the claim was read out of a pinned source file or an official document, and the file and line are named. **Observed** means something was run and its result is reported. **Not established** means the question was asked and no answer was found; the report says so rather than guessing. The repository has a standing rule that a documented claim never stands in for an observed one, and this report keeps the two apart on purpose. Nothing in this report was observed on a board. Everything marked Observed here was observed on the host, against built artefacts and pinned source trees.

## Short answer

Nothing in the core course's configuration erases a secret from the flash of an ESP32-C6. Every deletion path the course owns ends in the same place: an NVS entry of length zero, appended after the record it supersedes. The old bytes stay where they were until the NVS ring wraps around to that sector and garbage collection erases it, which may be many reboots away and which nothing in the application controls.

That matters more for the key than for the certificate, because the leftover record is not merely present, it is readable. The Secure Storage AEAD key is SHA-256 over six bytes of the factory MAC address, zero-padded to eight, with the entry's own identifier as salt. Anyone holding a flash dump and the MAC can derive it. So `psa_destroy_key()` on this configuration removes the device's access to its private key and leaves a decryptable copy of that private key in the flash. This is `T6-W-16` and `T6-W-17` meeting at decommissioning, and it is the single fact Tier 8 has to say out loud.

Two honest erasures are available. `nvs_clear()` erases every sector of the settings ring and verifies each erase against the flash parameters' erase value, and it is reachable from the application because Tier 7 already holds the settings NVS instance through `settings_storage_get()`. `flash_erase()` over the whole `storage` partition does the same for the 160 KiB the ring never touches. Both cost the same thing: they take everything, including the Tier 5 recovery records, and the settings subsystem cannot be used again without a reboot.

A properly verifiable erase of a secret does exist on this chip and is not reachable from this stack. ESP-IDF can derive NVS encryption keys at runtime from an eFuse HMAC key, so that nothing is stored in flash, and `esp_efuse_destroy_block()` can then destroy the derivation. Espressif says in as many words that this gives secure storage on ESP32-C6 without flash encryption. It belongs to ESP-IDF's NVS and not to Zephyr's Secure Storage, so the course cannot use it, and that is the honest shape of the answer to "is there a verifiable erase without Advanced Tier A": yes on the part, no in this tree.

The Wi-Fi passphrase cannot be removed by the device at all. It is a string literal in the running image's read-only data, inside the slot the signature covers. A device that erased it would be erasing itself, and MCUboot would find no valid image afterwards. `T6-W-27` is not closeable by any device-side operation. It is closeable only by a host holding the cable, and only by overwriting or erasing the slots.

eFuse offers one relevant one-way operation and the course should not go near it. Every field discussed below is write-once in the direction that matters, and two of them end USB and UART reflashing permanently. A Learner's own board must survive the tier.

## 1. PSA key destruction in this tree

### The configuration under test

The course sets, in `firmware/tier-07-operational-identity/prj.conf`, exactly what section 8 of the specification fixes: `SECURE_STORAGE`, the AEAD transform with the AES-GCM scheme, the device-ID-hash key provider, and the settings store implementation, over `SETTINGS` and `SETTINGS_NVS`. **Source:** `firmware/tier-07-operational-identity/prj.conf`, the block headed "Storing the private key, in the exact configuration section 8 fixes".

Tier 6 stores the Factory key at persistent PSA key identifier `0x00000601` and Tier 7 the Operational key at `0x00000701`. The pending Operational key, live for one Claim window, is volatile. **Source:** `firmware/tier-07-operational-identity/src/identity.c:48` and `:58`.

The pinned tree is Zephyr 4.4.2 (`VERSION` reads major 4, minor 4, patchlevel 2, at tag `v4.4.2`, commit `dccb0959963`) with Mbed TLS 4.1.0 and the separate tf-psa-crypto module. Everything in this section was read out of `/opt/zephyr-workspace` inside the long-lived `tier2-validate` container, which is the tree the course builds against. **Observed:** `git describe --tags` in that tree.

### What the specification promises

The PSA Crypto API specification, version 1.2, which is the version this tree declares through `PSA_CRYPTO_API_VERSION_MINOR 2`, says this about `psa_destroy_key()`: "This function destroys a key from both volatile memory and, if applicable, non-volatile storage. Implementations must make a best effort to ensure that that the key material cannot be recovered." **Source:** [PSA Crypto API 1.2, key management](https://arm-software.github.io/psa-api/crypto/1.2/api/keys/management.html).

"Best effort" is the strongest word in it. The two hard guarantees are that the identifier becomes invalid and that metadata is erased. The caveats are attached to storage: `PSA_ERROR_STORAGE_FAILURE` is described as "Implementations must make a best effort to erase key material even in this situation, however, it might be impossible to guarantee that the key material is not recoverable in such cases", and `PSA_ERROR_DATA_CORRUPT` says the same. **Source:** same page.

The implementation's own header repeats it and adds a warning the specification does not have: "We can only guarantee that the the key material will eventually be wiped from memory. With threading enabled and during concurrent execution, copies of the key material may still exist until all threads have finished using the key." **Source:** `tf-psa-crypto/include/psa/crypto.h:532-548`.

The project's own architecture note is blunter still: "In the long term, it would be good to guarantee that `psa_destroy_key` wipes all copies of the key material." **Source:** `tf-psa-crypto/docs/architecture/psa-thread-safety/psa-thread-safety.md:302`.

For volatile keys the specification does use the word guarantee, and it is the only place it does: "The key material is guaranteed to be erased on a power reset." **Source:** [PSA Crypto API 1.2, key lifetimes](https://arm-software.github.io/psa-api/crypto/1.2/api/keys/lifetimes.html).

The PSA Secure Storage API specification, which governs the layer underneath, promises less than people assume. `psa_its_remove()` "Deletes the data from internal storage", and "If `uid` exists it and any metadata are removed from storage." **Source:** [PSA Storage API 1.0](https://arm-software.github.io/psa-api/storage/1.0/api/api.html), section 5.3.6.

There is no erasure requirement anywhere in that text. The verbs are "deletes" and "removed from storage", and nothing distinguishes physical erasure from inaccessibility. The specification's own risk analysis puts the medium out of scope and assumes the very mechanism that leaves stale copies: "It is assumed that the implementation will use the standard techniques, error correcting codes, wear levelling and so on, to ensure the storage is reliable." **Source:** [PSA Storage API 1.0, security risk assessment](https://arm-software.github.io/psa-api/storage/1.0/appendix/sra.html).

The accurate statement for a course page is therefore that the specification does not require erasure, and that this implementation does not perform one. It is not that the specification permits mere inaccessibility; the specification does not address the question.

### What `psa_destroy_key()` does, step by step

The call chain is short and every step is in the pinned tree.

`psa_destroy_key()` locks the key slot, moves it to `PSA_SLOT_PENDING_DELETION`, and for a key that is not volatile calls `psa_destroy_persistent_key(slot->attr.id)`. The comment above that call states its own scope: "Destroy the copy of the persistent key from storage." **Source:** `tf-psa-crypto/core/psa_crypto.c:1208` onward, the block guarded by `MBEDTLS_PSA_CRYPTO_STORAGE_C`.

`psa_destroy_persistent_key()` turns the key identifier into a storage identifier and calls `psa_its_remove()` on it. It then calls `psa_its_get_info()` again and returns `PSA_ERROR_DATA_INVALID` unless the answer is now `PSA_ERROR_DOES_NOT_EXIST`. **Source:** `tf-psa-crypto/core/psa_crypto_storage.c:166-186`.

That second call is worth naming precisely, because it is the only verification anywhere on this path. It verifies that the entry can no longer be found. It does not verify that any byte changed. The implementation checks absence from the index, which is exactly the distinction the ticket asked about.

The storage identifier is the key identifier. With `MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER` off, `psa_its_identifier_of_slot()` returns the key id unchanged, with the comment "Use the key id directly as a file name." **Source:** `tf-psa-crypto/core/psa_crypto_storage.c:40-57`.

Zephyr's `psa_its_remove()` is a one-line inline that calls `secure_storage_its_remove(ITS_CALLER_ID, uid)`, where `ITS_CALLER_ID` is `SECURE_STORAGE_ITS_CALLER_MBEDTLS`. **Source:** `zephyr/subsys/secure_storage/include/psa/internal_trusted_storage.h:15` and `:121`.

`secure_storage_its_remove()` reads the entry first, refuses if it was created `WRITE_ONCE`, and otherwise calls `secure_storage_its_store_remove(its_uid)`. **Source:** `zephyr/subsys/secure_storage/src/its/implementation.c:242-267`.

The settings store's remove is three lines of substance: build the entry name, call `settings_delete(name)`, map the error. **Source:** `zephyr/subsys/secure_storage/src/its/store/settings.c`, `secure_storage_its_store_remove()`.

The name is the prefix `its/` (Kconfig default, `Kconfig.its_store:77`) followed by the caller id and the identifier in hexadecimal, formatted `"%x/%lx"`. `SECURE_STORAGE_ITS_CALLER_MBEDTLS` is the third value of the caller enumeration, so it is 2. **Source:** `zephyr/subsys/secure_storage/src/its/store/settings.c`, `secure_storage_its_store_settings_get_name()`, and `zephyr/subsys/secure_storage/include/internal/zephyr/secure_storage/its/common.h:16-22`.

So the Factory key lives at settings name `its/2/601` and the Operational key at `its/2/701`. The code comment in `identity.c` that says a flash dump shows "its/2/601 and its/2/701 side by side" is therefore correct about this build, and the derivation above is where it comes from. **Source:** `firmware/tier-07-operational-identity/src/identity.c:50-57`.

### The answer to the question the ticket asked

Destroying a persistent PSA key in this configuration removes the index entry and does not remove the ciphertext. The ITS backing record is neither erased nor unlinked in any sense that reaches the flash. It is superseded by an appended entry of length zero, and section 2 follows that entry down to the flash.

There is exactly one ITS record per key at the crypto layer, so there is no separate metadata record and no key registry left behind. Magic, version, lifetime, type, bits, policy, data length and key bytes are one blob under one identifier, in `psa_persistent_key_storage_format`, whose header is the literal `"PSA\0KEY"`. **Source:** `tf-psa-crypto/core/psa_crypto_storage.c:212-226`. That header is useful for a lab, because it is what a correctly decrypted leftover record begins with. There is no enumeration function either, which is why key presence is tested by probing `psa_its_get_info()`. **Source:** `tf-psa-crypto/core/psa_crypto_storage.c:93-105`.

One identifier is reserved and is not a key: `PSA_CRYPTO_ITS_RANDOM_SEED_UID`, `0xFFFFFF52`. **Source:** `tf-psa-crypto/core/psa_crypto_storage.h:43-44`. Neither course key is near it.

Below the crypto layer there is an index, and it is worth showing a Learner, because it is the clearest picture of "index entry removed, ciphertext still present". The settings backend stores each entry as two NVS records, a name and a value, plus a global counter, and deleting one writes a tombstone for each and sometimes a third write for the counter. Section 2 traces it. So one `psa_destroy_key()` on a persistent key *adds* two or three records to the flash and removes none.

What the AEAD transform actually leaves behind is `create_flags`, then the nonce, then the ciphertext with its 16-byte GCM tag, in `struct stored_entry`. **Source:** `zephyr/subsys/secure_storage/src/its/transform/aead.c:63-71`. The tag matters for the wrong reason: an attacker who recomputes the key gets authenticated confirmation that the plaintext they recovered is the genuine record.

One further weakness surfaced while reading this path, and it belongs in the Weakness ledger rather than in this tier's claim. The default nonce provider seeds a static counter with one call to `psa_generate_random` on first use and then increments it byte-wise, so the counter restarts on every boot. **Source:** `zephyr/subsys/secure_storage/src/its/transform/aead_get.c`, `secure_storage_its_transform_aead_get_nonce()`. Nonce reuse across power cycles under the same derived key is therefore possible. This report did not establish whether the course's write pattern actually produces a repeat, and it is not a decommissioning question, but it is a real property of the configuration section 8 fixes.

`psa_destroy_key()` does wipe the RAM copy. `psa_unregister_read()` wipes the slot when the last reader unregisters, through `psa_wipe_key_slot()`, which calls `psa_remove_key_data_from_memory()` and then `memset`s the slot. **Source:** `tf-psa-crypto/core/psa_crypto.c:1135` onward. So the in-memory half of destruction is real, and the persistent half is a rename of the problem.

### The volatile pending key

The pending Operational key is created volatile and discarded with `psa_destroy_key()` on a volatile slot, which never touches storage at all: the persistent branch above is guarded on `!PSA_KEY_LIFETIME_IS_VOLATILE`. **Source:** `tf-psa-crypto/core/psa_crypto.c`, the same guard, and `firmware/tier-07-operational-identity/src/identity.c:663`.

A volatile key therefore leaves nothing in flash by construction, and this is the one part of the identity story where erasure is not a problem. `course_identity_erase()` discards it anyway, and the comment gives the right reason: remanufacturing a device halfway through a Claim window should not leave the window open. **Source:** `firmware/tier-07-operational-identity/src/identity.c:890-905`.

Destroying a volatile key is the strongest erasure anywhere in this stack, because the only copy was in RAM and `psa_remove_key_data_from_memory()` genuinely overwrites it, with `mbedtls_platform_zeroize` or `mbedtls_zeroize_and_free`. **Source:** `tf-psa-crypto/core/psa_crypto.c:1115-1131`. The documented holes are copies held by in-flight multi-part operations, which the code states plainly — "key material can linger until all operations are completed" — and, with threading, other threads' copies. **Source:** `tf-psa-crypto/core/psa_crypto.c:1185-1193`.

On power loss the specification's guarantee is about the key ceasing to exist, not about a scrub. Nothing in tf-psa-crypto or Zephyr's secure storage zeroizes key slots on reset, shutdown or fault: `psa_wipe_all_key_slots()` runs only from an orderly `psa_crypto_free()`. **Source:** read of the slot management path, `tf-psa-crypto/core/psa_crypto_slot_management.c`. So after an unclean reset the erasure comes from SRAM losing charge rather than from software.

**Not established:** whether a volatile PSA key's slot bytes remain readable in ESP32-C6 SRAM across a warm reset, such as `sys_reboot()` or a watchdog reset, where the RAM is not power-cycled. The software side is settled, above: nothing scrubs it. The hardware side was not established and this report does not guess it. It is a fair question for the recovery ticket, because the pending Operational key is exactly such a key.

### Why the leftover record is worse than a leftover record

The AEAD key for an ITS entry is derived, not stored. The device-ID-hash provider reads a device identifier through `hwinfo`, zero-pads it to eight bytes, appends the entry's packed UID as a salt, and hashes the lot with SHA-256 into the AES key. **Source:** `zephyr/subsys/secure_storage/src/its/transform/aead_get.c`, `secure_storage_its_transform_aead_get_key()` and `hash_data_into_key()`.

On this part that identifier is six bytes of the factory MAC address, read straight out of eFuse. Zephyr's ESP32 `hwinfo` driver reads `EFUSE_RD_MAC_SPI_SYS_0_REG` and `EFUSE_RD_MAC_SPI_SYS_1_REG` and returns six bytes. **Source:** `zephyr/drivers/hwinfo/hwinfo_esp32.c`, `z_impl_hwinfo_get_device_id()`.

Every input to that key is public or derivable: the MAC the device broadcasts in every Wi-Fi frame, a fixed zero pad, and the entry identifier this report derived above from Kconfig defaults. So a superseded `its/2/601` record recovered from a flash dump can be decrypted by anyone who can read the board's MAC. Zephyr says as much about the provider itself, and the course leaves the warning switched on: "WARNING: Using a potentially insecure PSA ITS encryption key provider." **Source:** the `WARNING` macro and `warn_insecure_key()` in the same file.

Tier 6 already proved the live version of this on the board and recorded it as `T6-W-16`. What is new at Tier 8 is that it applies to a key the device believes it has destroyed. Tier 6 reads a key that exists; Tier 8 would be reading a key that does not.

## 2. NVS and settings deletion, down to the flash

### NVS deletion is an append

In the pinned tree NVS lives at `subsys/kvss/nvs/nvs.c`, not the older `subsys/fs/nvs/`. `nvs_delete()` is one line: `return nvs_write(fs, id, NULL, 0);`. **Source:** `zephyr/subsys/kvss/nvs/nvs.c:1454-1457`.

A zero-length write appends an allocation table entry with `len` zero and reserves no data space. The public header states the consequence without hedging: "When `len` parameter is equal to 0 then entry is effectively removed (it is equivalent to calling of `nvs_delete`) ... It is not possible to distinguish between deleted entry and entry with data of length 0." **Source:** `zephyr/include/zephyr/kvss/nvs.h:96-102`.

Nothing on the delete path overwrites, scrubs or erases the superseded data. There is no secure-delete or shred option in the NVS Kconfig. **Source:** read of `zephyr/subsys/kvss/nvs/nvs.c` delete and write paths, and of the NVS Kconfig; no such symbol exists.

### When the old bytes actually go

Old bytes go when the sector holding them is erased, and a sector is erased in exactly three places.

Garbage collection erases one sector at the end of its run: "Erase the gc'ed sector", `nvs_flash_erase_sector(fs, sec_addr)`, where `sec_addr` is the sector after the current write sector in the rotation. **Source:** `zephyr/subsys/kvss/nvs/nvs.c`, end of `nvs_gc()`.

Garbage collection runs when a write has to move to the next sector, which happens when the current sector fills. So a superseded record survives until the write pointer has advanced all the way around the ring to its sector. On a device that writes rarely, that is a long time, and the application has no way to ask for it.

Mounting can also erase. `nvs_startup()` erases the next sector when it finds a GC-done marker, and erases the write sector outright when it does not find one and has to restart garbage collection. **Source:** `zephyr/subsys/kvss/nvs/nvs.c`, `nvs_startup()`.

This is not a theoretical remark in this repository. Tier 6 found it the expensive way: Tier 5's own three-sector NVS instance and the settings instance both landed on the first bytes of the same partition, and, as the Tier 7 source now records, "the damage did not even wait for a write, because mounting erases the sector after the write sector." **Source:** `firmware/tier-07-operational-identity/src/recovery_state.c:20-48`, issues #109 and #120.

And `nvs_clear()` erases every sector in the instance, which section 4 covers.

### The size of the ring, and how long a leftover lives

The `storage` partition is 192 KiB at `0x3b0000` in the pinned flash map. **Source:** `firmware/tier-07-operational-identity/dts/esp32c6_4m_flash_map.dtsi`.

The settings NVS backend does not use all of it. It takes the hardware sector size times `CONFIG_SETTINGS_NVS_SECTOR_SIZE_MULT` (default 1) as its sector size, and counts up to `CONFIG_SETTINGS_NVS_SECTOR_COUNT` sectors (default 8) or until the partition runs out. **Source:** `zephyr/subsys/settings/src/settings_nvs.c`, `settings_backend_init()`, and `zephyr/subsys/settings/Kconfig:201-215`.

Neither symbol is set anywhere in `firmware/`, so the defaults hold. **Observed:** `grep -rn "SETTINGS_NVS_SECTOR" firmware/` returns nothing.

The ESP32-C6 erase block is 4096 bytes. **Source:** `zephyr/dts/riscv/espressif/esp32c6/esp32c6_common.dtsi:302`, `erase-block-size = <4096>`.

So the settings ring is eight sectors of 4 KiB, 32 KiB, at the front of a 192 KiB partition, and the remaining 160 KiB is never written by settings at all. Rotating a superseded record out of the ring takes on the order of 32 KiB of subsequent entries. An Operational certificate is capped at 800 bytes and a key record is smaller, so a handful of records does not come close.

This has a second consequence worth stating for the dump lab. The 160 KiB beyond the ring has never held a course secret, and the eight sectors that have are the only ones worth examining.

### What deleting a settings entry does

`settings_delete()` reaches `settings_nvs_save()` with a NULL value, which sets `delete = true`, and the delete branch issues two `nvs_delete()` calls: one for the name entry at `name_id`, one for the value entry at `name_id + NVS_NAME_ID_OFFSET`. If the deleted id was the highest in use, it decrements `last_name_id` and writes that counter back. **Source:** `zephyr/subsys/settings/src/settings_nvs.c:215-315`.

The identifier scheme is `NVS_NAMECNT_ID` at `0x8000` for the counter, name entries above it, and value entries offset by `NVS_NAME_ID_OFFSET`, `0x4000`. **Source:** `zephyr/subsys/settings/include/settings/settings_nvs.h:33-34`.

So deleting one settings entry appends three NVS entries in the ordinary case: two tombstones and, sometimes, a counter update. It frees the name id for reuse and it removes nothing from the flash.

### The answer for `course/identity/operational-cert`

An old copy of `course/identity/operational-cert` survives a delete, in the same eight-sector ring, until the ring wraps. Recovering it from a dump needs no key at all, because the certificate is stored in settings in the clear, and deliberately so: Tier 6 put the certificate in settings rather than Secure Storage on the grounds that a certificate is public by construction. **Source:** `firmware/tier-07-operational-identity/src/identity.c:59-77`.

This is the same class of problem as `T6-W-17`, and there is a sharper version of it than a flash dump. `nvs_read_hist()` is a public API that reads the *n*th previous copy of an entry, and `nvs_read()` is just `nvs_read_hist()` with a count of zero. The current read refuses a tombstone, returning `-ENOENT` when the newest matching entry has `len == 0`. A read with a count of one walks back one further matching entry and returns the value that was deleted. **Source:** `zephyr/subsys/kvss/nvs/nvs.c:1459-1560`, the length check at the top of the walk and the history loop above it.

So a superseded record is recoverable by the firmware itself, with no cable, no dump and no key derivation. That is a claim about the code path and it has not been run; the distinction matters and this report keeps it. But if it holds on the board it is the cheapest possible demonstration of the whole finding: the same device that reports a key destroyed can read the certificate it deleted back out of its own flash.

Two smaller facts belong with it. The settings *name* is stored in the clear in its own NVS entry, so the name of a deleted setting survives as stale bytes alongside the value. **Source:** `zephyr/subsys/settings/src/settings_nvs.c`, the name write in `settings_nvs_save()`. And garbage collection copies still-live entries forward before erasing the old sector, so during a collection a live record briefly exists twice. **Source:** `zephyr/subsys/kvss/nvs/nvs.c`, `nvs_flash_block_move()` called from `nvs_gc()`.

There is also an implicit whole-region wipe worth knowing about. With `CONFIG_NVS_INIT_BAD_MEMORY_REGION`, mounting flattens the entire NVS region when every sector reads as closed. **Source:** `zephyr/subsys/kvss/nvs/Kconfig` and `nvs_startup()`. The course does not set it, so this is a route not taken rather than a behaviour in play.

## 3. Wi-Fi credentials

### Where the passphrase is

`CONFIG_COURSE_WIFI_PSK` is a Kconfig string in `firmware/common/Kconfig`, generated by `./course build firmware` from `.course-secrets/wifi.conf`. `net_link.c` passes it to the association parameters as `(const uint8_t *)CONFIG_COURSE_WIFI_PSK` with `strlen()` for the length. **Source:** `firmware/common/Kconfig`, `config COURSE_WIFI_PSK`, and `firmware/common/src/net_link.c:73-77`.

A Kconfig string used that way becomes a string literal in the compiled image's read-only data. There is no runtime path that reads it from storage, because there is no storage copy to read.

**Observed, on the host.** The passphrase from this repository's `.course-secrets/wifi.conf` appears verbatim in `artifacts/generated/releases/tier-07-operational-identity.bin` and in `artifacts/generated/releases/tier-06-factory-identity.bin`. In the Tier 7 image it appears exactly once, at byte offset 691568 of a 758691-byte signed image. This was run against the built artefacts on the development host on 22 September 2026. It was not observed on a board, and the passphrase itself is not reproduced here.

### Whether the Wi-Fi library keeps a second copy

It does not, on this port, and the reason is worth recording because the ESP-IDF answer is the opposite.

ESP-IDF's `esp_wifi_set_storage()` defaults to `WIFI_STORAGE_FLASH`, "All configuration will store in both memory and flash", and the Wi-Fi blob calls out to `nvs_open`, `nvs_set_blob`, `nvs_get_blob`, `nvs_commit` and `nvs_erase_key` through the OS adapter. The blob genuinely references those symbols. **Source:** `modules/hal/espressif/components/esp_wifi/include/esp_wifi.h:1065` and `esp_wifi_types_generic.h:635-636`; **Observed:** `nm --undefined-only` on `modules/hal/espressif/zephyr/blobs/lib/esp32c6/libnet80211.a` lists `wifi_nvs_get`, `wifi_nvs_commit`, `misc_nvs_init` and related symbols.

On the Zephyr port every one of those adapter wrappers is a stub that ignores its arguments and returns 0. `nvs_open_wrapper`, `nvs_set_blob`, `nvs_get_blob`, `nvs_commit`, `nvs_close` and `nvs_erase_key` all do nothing. **Source:** `modules/hal/espressif/components/esp_wifi/esp32c6/esp_adapter.c:545-600`.

There is also no ESP-IDF-style `nvs` partition in the course's flash map to write to. **Source:** `firmware/tier-07-operational-identity/dts/esp32c6_4m_flash_map.dtsi`.

So the Wi-Fi credential exists in exactly one place per image: the image's read-only data. There is no second, driver-owned copy for a decommissioning routine to delete. That is a good finding rather than a bad one, because it makes the count of copies knowable.

### Can the device remove it

No, and the reason is structural rather than a missing feature.

The string is inside the application image, in the slot the device is executing from. Erasing it means erasing the running firmware's own read-only data, which on this part is mapped and executed in place. After such an erase the device has no valid image, and from Tier 3 onward MCUboot verifies a signature over that image, so the device cannot rewrite the region and keep it bootable either: any edit invalidates the signature. A device-side "remove the Wi-Fi credential" operation is therefore a device-side "destroy this device's firmware" operation.

Nothing in this build stops it from trying. ESP-IDF has a guard for exactly this, `CONFIG_SPI_FLASH_DANGEROUS_WRITE`, which "can optionally abort or return a failure code if erasing or writing addresses that fall at the beginning of flash (covering the bootloader and partition table) or that overlap the app partition that contains the running app", and whose ESP-IDF default is Aborts. **Source:** `modules/hal/espressif/components/spi_flash/Kconfig:263-287`. That symbol does not exist in the Zephyr build. **Observed:** the built Tier 7 configuration at `/opt/zephyr-workspace/build/tier-07-148/tier-07-operational-identity/zephyr/.config` contains no `SPI_FLASH_DANGEROUS_WRITE` symbol at all, so the guard compiles out and an application erase of the running slot is permitted by the driver. Tier 8 should know that before anyone writes a wipe routine, and the same fact is a hazard for the tier's own lab sessions.

What a reflash removes that an erase cannot is the credential itself, and only because a host is holding the cable and can write a replacement image in the same operation. That is the asymmetry Tier 8 should state: this secret is removable only by the party that put it there, and only by replacing the thing that contains it.

One partial, honest device-side act does exist. From Tier 3 the device owns the secondary slot and already erases and writes it. **Source:** `CONFIG_IMG_ERASE_PROGRESSIVELY=y` and the `IMG_MANAGER` block in `firmware/tier-07-operational-identity/prj.conf`. After an MCUboot swap the secondary slot holds the previous image, which contains its own copy of the passphrase, so a device can reduce the number of copies of the credential in its flash from two to one. It cannot reach zero.

`T6-W-27` is therefore not closeable by any device-side operation. That is a finding, and the ticket said so in advance. What Tier 8 can honestly claim is a bounded version: the count of copies on the device, which party can reduce it, and what the residue is after a reflash. A reflash of slot 0 with a credential-free image, followed by an erase of slot 1, would leave no copy on the board; nothing the board does on its own gets there.

### The lab constraint that goes with it

Tier 8 cannot demonstrate any of this by dumping the board's flash. The fixture safety contract binds the dump to the `storage` partition precisely because slot 0 carries the real passphrase, and `./course device dump` refuses arguments so that no range can be named. **Source:** `docs/fixture-safety-contract.md`, "Reading the board's flash", and `internal/courseapp/tier06.go:1470-1490`.

Tier 6 already chose the right instrument for this row: "Read the strings of any image you built." **Source:** `course-material/tiers/tier-06-factory-identity/index.md:295`. Tier 8 inherits both the row and the instrument.

## 4. Flash-level erase on this part

### What Espressif's own API promises, which is less than people assume

`esp_flash_erase_region()` is documented in terms of alignment and error codes and not in terms of the state of the bytes afterwards. "Sector size is specified in chip->drv->sector_size field (typically 4096 bytes.) ESP_ERR_INVALID_ARG will be returned if the start & length are not a multiple of this size", and "Erase is performed using block (multi-sector) erases where possible ... Remaining sectors are erased using individual sector erase commands." **Source:** [ESP-IDF SPI Flash API, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/peripherals/spi_flash/index.html).

There is no statement on that page that the region reads as `0xFF` afterwards. The `0xFF` claim is documented by esptool, "To erase the entire flash chip (all data replaced with 0xFF bytes)", and indirectly by the write API's note that "SPI NOR flash can only write bits 1->0". **Source:** [esptool basic commands](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/esptool/basic-commands.html) and the SPI Flash API page.

There is no erase verification anywhere in ESP-IDF. The only read-back verification is for writes, through `CONFIG_SPI_FLASH_VERIFY_WRITE`, which is off by default, and there is no equivalent for erase. **Source:** [ESP-IDF Kconfig reference, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/kconfig-reference.html).

The cache question has a documented answer and a documented soft edge. Caches are disabled during SPI1 flash operations: "For all SPI1 operations (read/write), caches are disabled during these operations by default." But the statement about existing mappings is hedged: "When flash erasing/writing happen while cache mapping exists, it often causes some cache region to be invalidated and reloaded again." **Source:** [SPI flash concurrency constraints](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/peripherals/spi_flash/spi_flash_concurrency.html) and the SPI Flash API page. The technical reference manual adds that manual invalidation "only works on the unlocked data".

The practical rule that follows, and it is the rule Tier 8 should use: verify an erase by reading the region back over the SPI path, never through a memory-mapped pointer. Zephyr's `flash_read()` takes the SPI path, as established below.

### What the Zephyr flash API gives the application

`flash_erase()` requires the region to be aligned to the erase page layout, and the flash parameters report the erased value. The ESP32 driver declares `erase_value = 0xff` and a write block size from the devicetree. **Source:** `zephyr/drivers/flash/flash_esp32.c:111-112`.

The driver's erase calls `esp_flash_erase_region()` and returns its status. It does not read the region back. **Source:** `zephyr/drivers/flash/flash_esp32.c`, `flash_esp32_erase()`.

Reads go through `esp_flash_read()`, the SPI read path, not the memory-mapped instruction-cache path used for execute-in-place. **Source:** `zephyr/drivers/flash/flash_esp32.c:147`. This is what makes read-back verification meaningful: the application can erase a region and then read the same region through `flash_read()` and compare every byte to `0xff`, and the comparison is against the flash, not against a cached view of it.

NVS already does exactly that, and it is the one place in this stack where an erase is verified. `nvs_flash_erase_sector()` calls `flash_flatten()` and then `nvs_flash_cmp_const()` against `fs->flash_parameters->erase_value` over the whole sector, returning `-ENXIO` if any byte differs. Its own comment says "erase a sector and verify erase was OK." **Source:** `zephyr/subsys/kvss/nvs/nvs.c:443-473`.

Two cautions about the Zephyr layer itself. `flash_erase()` is a thin dispatch to the driver: it performs no alignment check and no read-back, and returns only what the driver returns. And the erased value is a per-device property rather than a constant, so an application that wants to check a region must ask `flash_get_parameters()` rather than assume `0xFF`. On this part it is `0xFF`, as quoted above. **Source:** `zephyr/include/zephyr/drivers/flash.h`, `flash_erase()` and `struct flash_parameters`.

There is also a second primitive worth naming, because it does something erase cannot. `flash_fill()` writes a chosen value across a range at write-block alignment. **Source:** `zephyr/include/zephyr/drivers/flash.h`, `flash_fill()`. On NOR flash a write can only clear bits, so filling a record with zeros overwrites it in place without erasing its sector, which is the one way to destroy a single record without taking its neighbours with it. This report did not establish whether doing that to a live NVS partition leaves the instance mountable, and it very plausibly does not, since the ATE and its CRC would be zeroed under the file system's feet. It is named here as an option the design ticket should evaluate rather than as a technique this report endorses.

So a verifiable erase is available on this part today, at the granularity of a 4 KiB sector, without flash encryption and without anything Advanced Tier A owns. It is verifiable because the application can read the bytes back over a path that does not lie to it. What is not available is a *guaranteed* erase, in the sense of a promise that no copy of the data exists anywhere on the die. Those are different claims and Tier 8 should use the first and not the second.

### Erasing the whole partition, and what it costs

Two routes exist and both are reachable from the application.

`nvs_clear()` is public in `zephyr/include/zephyr/kvss/nvs.h`. It loops over every sector of the instance calling `nvs_flash_erase_sector()`, which means every sector is erased and every erase is verified, and then sets `fs->ready = false` with the comment "nvs needs to be reinitialized after clearing." **Source:** `zephyr/subsys/kvss/nvs/nvs.c:1210-1232`.

The application can reach the settings instance to do this, because Tier 7 already holds it: `recovery_state_init()` calls `settings_storage_get()` and keeps the `struct nvs_fs *` that settings owns. **Source:** `firmware/tier-07-operational-identity/src/recovery_state.c:52-80`.

The cost is threefold and none of it is hidden. It takes everything in the ring, so the Tier 5 download, trial and failure records at ids 1, 2 and 3 go with the identity records; the settings subsystem's in-memory state, including `last_name_id` and the name cache, is left describing a store that no longer exists; and there is no public call that re-initialises the settings backend, so the practical sequence is clear, report, reboot. This report did not find a supported way to keep running usefully after `nvs_clear()` on the settings instance.

`flash_erase()` over the whole `storage` partition, opened by its fixed-partition id, erases all forty-eight sectors including the 160 KiB the settings ring never used. It is not verified by the driver, so the application must read it back itself, which as established above it can do. The cost is the same as `nvs_clear()` plus the reboot being unavoidable rather than merely advisable.

**Not established:** whether the NVS instance that `settings_storage_get()` returns can be re-mounted in place by calling `nvs_mount()` on it after `nvs_clear()`, leaving the settings subsystem usable without a reboot. The fields are all there and `nvs_mount()` is public, but nothing in the settings subsystem is documented to tolerate it and no run was made.

### Wear levelling and stale copies

Espressif's flash access on this part is direct: `esp_flash_erase_region()` erases the sectors named, and the partition table maps regions to fixed offsets. The wear levelling ESP-IDF offers is a separate software component layered over a partition and used by FATFS, and nothing in this course uses it. **Source:** read of `zephyr/drivers/flash/flash_esp32.c`, which calls `esp_flash_erase_region()` directly with no remapping layer.

That component is worth one sentence anyway, because it is a real residue mechanism on this chip for anyone who does use it. Espressif documents that it relocates logical sectors across physical ones and copies sector contents through RAM or through a spare sector while erasing, which means a record deleted through the wear-levelling layer can survive in a physical sector the logical view no longer addresses. **Source:** [ESP-IDF wear levelling API, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/wear-levelling.html).

**Not established, and it matters.** Whether the SPI NOR die fitted to the board performs any internal remapping, bad-block substitution or wear levelling of its own is a property of the die, not of Espressif's driver. Espressif does not answer it: the module datasheet does not publish a flash part number, saying only that module variants "vary in flash part number", and neither the ESP32-C6 technical reference manual nor the module datasheet uses the terms wear levelling, bad block or remapping anywhere. **Source:** the [ESP32-C6-WROOM-1/1U datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-c6-wroom-1_wroom-1u_datasheet_en.pdf) and the [ESP32-C6 technical reference manual](https://www.espressif.com/sites/default/files/documentation/esp32-c6_technical_reference_manual_en.pdf), checked for those terms and found not to contain them.

Commodity SPI NOR parts are conventionally addressed directly, with no translation layer, which is why an erase of a sector is normally the erase of that sector. Tier 8 may say that. It may not say that Espressif guarantees it, because Espressif does not specify the die. The defensible claim is the read-back one: after an erase, a read over the SPI path returns the erase value, and there is no documented mechanism by which the pre-erase content remains readable through the standard interface.

One more fact about the board Tier 8 must validate on. Espressif's user guide says the ESP32-C6-DevKitC-1 is "based on ESP32-C6-WROOM-1(U), a general-purpose module with a 8 MB SPI flash". **Source:** [ESP32-C6-DevKitC-1 user guide](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32c6/esp32-c6-devkitc-1/user_guide.html). The course builds for 4 MB: `CONFIG_ESPTOOLPY_FLASHSIZE="4MB"` and a flash map that ends at `0x400000`. **Observed:** the built Tier 7 configuration, and `firmware/tier-07-operational-identity/dts/esp32c6_4m_flash_map.dtsi`. So on that board roughly half the part sits outside every partition the course defines. Nothing the course writes ever reaches it, which is reassuring for residue, but a claim of the form "the device erased its flash" would be false about the part and true only about the map. This also means a host-side `esptool erase-flash` on the DevKitC-1 covers twice what the course's map describes.

This is the honest boundary of the whole section. The application can verify that the bytes it can address read as `0xff`. It cannot verify that no copy exists in a place it cannot address. Tier 8 should say that in one sentence and not hedge it into vagueness.

### Is a verifiable erase available without flash encryption

The ticket asked this directly, and the answer has two halves that must not be merged.

On the chip, yes, and Espressif documents the pieces. ESP-IDF offers an NVS encryption scheme whose XTS keys are derived at runtime from an HMAC key held in an eFuse block, and it says so in exactly these words: "Since the encryption keys are derived at runtime, they are not stored anywhere in the flash", and "This scheme enables us to achieve secure storage on ESP32-C6 without enabling flash encryption." **Source:** [ESP-IDF NVS encryption, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/nvs_encryption.html). The matching destruction primitive is `esp_efuse_destroy_block()`, which burns the unset bits of a block and then sets read protection, after which "data becomes inaccessible, and the software reads it as all zeros". **Source:** [ESP-IDF eFuse Manager, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html). Destroying the block destroys the derivation, and the stored records become undecryptable without anything being erased.

In this stack, no. That scheme is ESP-IDF's NVS library and its key provider, and the course runs Zephyr, whose Secure Storage derives its AEAD key from a MAC-based device identifier instead. The primitive exists on the part and is not reachable from the code the course builds.

That gap is worth recording rather than merely noting, because it is the concrete shape of what the specification already asks for: section 8's fixed limitation says a production design "must instead validate a custom provider rooted in protected device-specific hardware". Zephyr's Secure Storage supports a custom AEAD key provider, and the ESP32-C6's HMAC peripheral with an eFuse key is what such a provider would be rooted in. That is Advanced Tier B's subject and not Tier 8's, and this report names it so that the option is on the record rather than rediscovered later.

Two corrections belong here, because both are easy to get wrong.

Bumping `SPI_BOOT_CRYPT_CNT` is not a cryptographic erase and Espressif never calls it one. The term does not appear in the Espressif documentation read for this report. What the counter does is enable or disable transparent decryption, and disabling it leaves both the key and the ciphertext where they were. Espressif also documents that in development mode it "can only be done one time per chip", and that in release mode the bootloader write-protects the counter so it cannot be done at all. **Source:** [ESP32-C6 flash encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/flash-encryption.html).

Flash encryption would not have covered this course's storage anyway. Espressif states it plainly: "NVS partitions for non-volatile storage cannot be encrypted since the NVS library is not directly compatible with flash encryption." **Source:** same page. That is about ESP-IDF's NVS rather than Zephyr's, but it is the reason the HMAC scheme above exists, and it should stop anyone concluding that Advanced Tier A would have made Tier 8's problem disappear.

The Zephyr driver does have a flash-encryption branch, and it is a good illustration of how deep the assumption runs: with encryption enabled an erase additionally writes `0xff` bytes, because reads are decrypted on the way out and MCUboot's erased-state checks would otherwise see noise. **Source:** `zephyr/drivers/flash/flash_esp32.c`, `flash_esp32_erase()` under `CONFIG_ESP_FLASH_ENCRYPTION`.

## 5. eFuse

### The shape of the answer

eFuse bits go from 0 to 1 and do not come back. The in-tree component treats reprogramming an already-programmed bit as an error class of its own: `ESP_ERR_EFUSE_REPEATED_PROG`, "Error repeated programming of programmed bits is strictly forbidden." **Source:** `modules/hal/espressif/components/efuse/include/esp_efuse.h:25`.

Espressif says the same three ways. "Each eFuse is a one-bit field which can be programmed to 1 after which it cannot be reverted back to 0", and the tool carries a warning of its own: "Because eFuse is one-time-programmable, it is possible to permanently damage or 'brick' your ESP32-C6 using this tool. Use it with great care." **Source:** [ESP-IDF eFuse Manager, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html) and [espefuse](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/espefuse/index.html).

The ESP32-C6 eFuse table in the pinned tree is the authoritative field list for this part, and it is the same table ESP-IDF generates its accessors from. **Source:** `modules/hal/espressif/components/efuse/esp32c6/esp_efuse_table.csv`.

Three structural facts make eFuse less forgiving than a bit-by-bit reading suggests. Blocks 2 to 10 use a Reed-Solomon coding scheme, and Espressif states that a block already carrying encoded data cannot be written again "without breaking the previous data's checksums", so those blocks are effectively single-shot. A single `WR_DIS` bit often covers several fields at once, so write-protecting one field freezes its neighbours at whatever value they currently hold, permanently. And burning a key block burns its `KEY_PURPOSE` field write-protected whether or not the operator asked for that. **Source:** the eFuse Manager page, and [espefuse burn-key](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/espefuse/burn-key-cmd.html).

### The fields a decommissioning tier would be tempted by

`SPI_BOOT_CRYPT_CNT`, block 0, bit 82, three bits: "Enables flash encryption when 1 or 3 bits are set and disables otherwise", with the value map `{0: Disable; 1: Enable; 3: Disable; 7: Enable}`. **Source:** `esp_efuse_table.csv:126`. Because the bits only accumulate, this counter can be moved at most from 0 to 1 to 3 to 7 and never back, which is three transitions for the life of the part. It is the field a flash-encryption crypto-erase would use, and using it consumes one of those transitions permanently.

`RD_DIS`, block 0, bit 32, seven bits: "Disable reading from BLOCK4-10", with one bit per key block. **Source:** `esp_efuse_table.csv:103-110`. Setting a read-disable bit makes a key block permanently unreadable by software. It is a one-way, and it is the closest thing on this part to a real key destruction, but it applies to eFuse key blocks and not to anything the core course stores.

`WR_DIS`, block 0, bit 0, thirty-two bits, one per protected field or group, "Disable programming of individual eFuses". **Source:** `esp_efuse_table.csv:14-53`. Every field named in this section has a `WR_DIS` bit, so each can be frozen permanently in its current state.

`SECURE_BOOT_EN` at bit 116 and `SECURE_BOOT_KEY_REVOKE0` to `2` at bits 85 to 87. **Source:** `esp_efuse_table.csv:127-138`. Enabling secure boot is irreversible, and revoking a secure boot key is irreversible.

`SECURE_VERSION`, sixteen bits at bit 142, "Represents the version used by ESP-IDF anti-rollback feature". **Source:** `esp_efuse_table.csv:148`. Monotonic by construction.

### The fields that would end the Learner's board

Three fields deserve to be named as hazards rather than as options.

`DIS_DOWNLOAD_MODE`, bit 128: "Represents whether Download mode is disabled or enabled. 1: disabled." **Source:** `esp_efuse_table.csv:141`. Setting it ends serial download mode permanently, which ends `esptool` write-flash, which ends every flash command this course runs.

`DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE`, bit 132, and `DIS_USB_SERIAL_JTAG`, bit 43. **Source:** `esp_efuse_table.csv:115` and `:144`. The same for the USB path the DevKitC-1 is normally used over.

`DIS_PAD_JTAG`, bit 51: "Represents whether JTAG is disabled in the hard way(permanently)." **Source:** `esp_efuse_table.csv:121`. The in-tree description uses the word "permanently" itself. Of the JTAG controls only `SOFT_DIS_JTAG` has a documented way back, through an HMAC key, and it has three bits, so it can be toggled three times in the life of the part.

A fourth deserves naming even though the field list above does not, because it removes the tools rather than a port. `ENABLE_SECURITY_DOWNLOAD` limits ROM download mode to flash read, write and erase, and Espressif's own enablement workflow puts it last with an instruction in bold: "Please perform the following step at the very end. After this eFuse is burned, the espefuse tool can no longer be used to burn additional eFuses." **Source:** [ESP-IDF security features enablement workflows, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/security-features-enablement-workflows.html).

And `CONFIG_SECURE_DISABLE_ROM_DL_MODE`, the application-level way to burn `DIS_DOWNLOAD_MODE`, is described by Espressif in terms the course should quote if it mentions it at all: it "prevents any future use of esptool, espefuse and similar tools". **Source:** the ESP-IDF Kconfig reference. After that, the only update path is OTA from the running application, and a broken application means a scrapped board.

One more hazard has nothing to do with decommissioning and everything to do with a Learner's board: setting `SPI_BOOT_CRYPT_CNT` without matching encrypted content in flash soft-bricks the part into a reboot loop printing `flash read err, 1000`. **Source:** the ESP32-C6 flash encryption page.

### The recommendation this research supports

Nothing eFuse-related should be burned by anything a Learner runs. The specification's own decommissioning requirement asks for erasure "where the hardware permits reliable erasure", and the hardware's one-way operations do not sit inside that permission: they are not erasure of customer data, they are permanent changes to a board's capabilities. Two of them end reflashing, which would end the Learner's course as well as the board.

Tier 8 can still teach eFuse honestly, and Espressif supplies two instruments for doing it without spending anything. `espefuse summary` reads the whole table without burning a bit. And there is a documented dry run: `CONFIG_EFUSE_VIRTUAL` "virtualizes eFuse values inside the eFuse Manager, so writes are emulated and no eFuse values are permanently changed", with `espefuse --virt` and `--path-efuse-file` doing the same from the host, "to test commands without physical access to the chip". **Source:** the eFuse Manager and espefuse pages. A tier that shows which bits a production decommissioning would burn, burns them in the virtual file, and then reads the real summary to show that the board is untouched, teaches irreversibility without spending it.

It is also worth recording that espefuse itself demands the word `BURN` be typed for every burn operation, and that `esptool erase-flash` refuses outright when secure boot or flash encryption is detected, overridable only with `--force`. **Source:** the espefuse page and [esptool basic commands](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/esptool/basic-commands.html). Both are examples of the kind of guard the course's own tooling already imitates.

**The one exception to "nothing eFuse-related is useful here".** `esp_efuse_destroy_block()` is a genuine key-destruction primitive: it burns the unset bits of a key block and then read-protects it, after which software reads it as all zeros. **Source:** the eFuse Manager page. It destroys an eFuse-held key, not a Secure Storage record, so it is useful only to a design that roots its storage key in eFuse, which section 4 describes and which this course does not build. Espressif also documents its failure mode: if the block is write-protected and read protection cannot be set, the data stays readable and the call returns an error.

## 6. What Tier 8 can honestly claim it removed

Stated as a list, because the honest version of this tier is a list and not a sentence.

It can claim the device lost the use of its keys. `psa_destroy_key()` wipes the RAM slot and removes the index entry, and the device cannot load or sign with the key afterwards. **Source:** sections 1 and 2.

It cannot claim the private key is gone from the flash. A superseded, decryptable ITS record remains until NVS garbage collection reaches its sector, and the AEAD key that protects it is derivable from the MAC. **Source:** sections 1 and 2.

It can claim a verified erase of the storage partition, if it performs one. `nvs_clear()` verifies every sector and `flash_read()` lets the application verify anything else, over a path that reads the flash rather than a cache. **Source:** section 4.

It cannot claim that a verified erase is a guaranteed erase, because it cannot speak for the flash die. **Source:** section 4, and the gap named there.

It cannot claim the device removed its Wi-Fi credential. Only a reflash removes it, and only because the host writes a replacement image. The device can at most reduce two copies to one by erasing the secondary slot. **Source:** section 3.

It can claim the services refused the device afterwards, which is where the rest of section 8's decommissioning requirement lives and which owes nothing to the flash.

It cannot claim that the specification it is implementing required any of the erasure. The PSA specifications ask for best effort and do not require erasure at all. **Source:** section 1. Section 8 of the course specification asks for erasure "where the hardware permits reliable erasure", and this report is the answer to where that is.

## 7. Consequences for the map

Three things follow that the map's own text does not yet account for.

**The one-line erase does not exist.** Tier 8's decommissioning cannot be a call to `course_identity_erase()` with a new log line. That function is the right shape for remanufacturing, which is what Tier 6 built it for, and it is the wrong shape for decommissioning, because every one of its four steps is a tombstone. A decommissioning that means anything has to reach `nvs_clear()` or a partition erase, and that takes the Tier 5 records with it and ends in a reboot. The design ticket should know that before it starts.

**The partial erase already happens by accident.** The hazard the map put in scope as settled input 7, `./course device flash --tier 05` destroying an enrolled board's identities, is an erasure event: Tier 5's three-sector NVS instance mounts over the front of the same partition, and mounting erases. The only reliable erase in the course today is the unintended one. That is a good teaching fact and it is already documented in the tree with its issue numbers.

**Wi-Fi credential removal is a host act.** The map's out-of-scope list keeps runtime Wi-Fi provisioning out and keeps credential removal at decommissioning in. Removal is in scope and it is also impossible device-side, so the in-scope work is the claim and the count of copies, not a control. The destination should not promise a closed `T6-W-27`.

**The board Tier 8 validates on has twice the flash the course maps.** Settled input 2 moves hardware validation to the ESP32-C6-DevKitC-1, whose module Espressif documents with 8 MB of flash, while the course builds a 4 MB image against a 4 MB map. It is not an error and nothing breaks, but it bears on this tier specifically, because a decommissioning claim about "the flash" is a claim about a part half of which the course has never addressed. The hardware validation campaign should state which it is claiming.

**Two new questions came out of this research and neither has a ticket.** The first is whether the pending Operational key's slot survives a warm reset in readable SRAM, which matters because the recovery flow is where a half-finished window meets a reset. The second is whether an application can overwrite a single Secure Storage record in place with `flash_fill()` and leave the NVS instance usable, which is the only route to destroying one record without destroying the partition. Both are narrow, both are answerable on the board, and both belong to a design ticket rather than to this one.

## Sources

### Published specifications and vendor documentation

Read on 22 September 2026.

| Source | What it establishes |
| --- | --- |
| [PSA Crypto API 1.2, key management](https://arm-software.github.io/psa-api/crypto/1.2/api/keys/management.html) | `psa_destroy_key()` promises best effort, not erasure |
| [PSA Crypto API 1.2, key lifetimes](https://arm-software.github.io/psa-api/crypto/1.2/api/keys/lifetimes.html) | Volatile key material is guaranteed erased on power reset |
| [PSA Storage API 1.0](https://arm-software.github.io/psa-api/storage/1.0/api/api.html) | `psa_its_remove()` deletes; the medium is not addressed |
| [PSA Storage API 1.0, risk assessment](https://arm-software.github.io/psa-api/storage/1.0/appendix/sra.html) | The medium is out of scope and wear levelling is assumed |
| [ESP-IDF SPI Flash API, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/peripherals/spi_flash/index.html) | Erase alignment and error codes; no data-state guarantee |
| [ESP-IDF SPI flash concurrency, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/peripherals/spi_flash/spi_flash_concurrency.html) | Caches disabled during SPI1 operations; mappings "often" invalidated |
| [ESP-IDF Kconfig reference, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/kconfig-reference.html) | Write verification exists and is off; no erase verification |
| [ESP-IDF wear levelling, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/wear-levelling.html) | The software layer that does relocate sectors |
| [ESP-IDF NVS encryption, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/nvs_encryption.html) | HMAC-derived keys give secure storage without flash encryption |
| [ESP-IDF eFuse Manager, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html) | One-way bits; `esp_efuse_destroy_block()`; virtual eFuse |
| [ESP-IDF flash encryption, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/flash-encryption.html) | The counter disables decryption and erases nothing |
| [ESP-IDF security enablement workflows, esp32c6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/security-features-enablement-workflows.html) | `ENABLE_SECURITY_DOWNLOAD` ends espefuse |
| [esptool basic commands, esp32c6](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/esptool/basic-commands.html) | Erase is to `0xFF`; sector alignment; the secure-boot refusal |
| [espefuse, esp32c6](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/espefuse/index.html) | The bricking warning, the `BURN` confirmation, `--virt` |
| [espefuse burn-key, esp32c6](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/espefuse/burn-key-cmd.html) | Key purpose is burned write-protected regardless |
| [ESP32-C6-DevKitC-1 user guide](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32c6/esp32-c6-devkitc-1/user_guide.html) | The board carries 8 MB of flash |
| [ESP32-C6-WROOM-1/1U datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-c6-wroom-1_wroom-1u_datasheet_en.pdf) | No flash part number; no remapping terms |
| [ESP32-C6 technical reference manual](https://www.espressif.com/sites/default/files/documentation/esp32-c6_technical_reference_manual_en.pdf) | eFuse one-way rule; cache invalidation limits |

### Pinned trees and this repository

Every path below is in the pinned trees this course builds against, read on 22 September 2026.

| Source | What it establishes |
| --- | --- |
| `tf-psa-crypto/core/psa_crypto.c:1135,1208` | `psa_destroy_key()` wipes RAM, and the persistent branch |
| `tf-psa-crypto/core/psa_crypto_storage.c:40,166` | Key id becomes the ITS uid; destroy calls `psa_its_remove` and verifies absence |
| `zephyr/subsys/secure_storage/include/psa/internal_trusted_storage.h:15,121` | `psa_its_remove` goes to the Mbed TLS caller namespace |
| `zephyr/subsys/secure_storage/src/its/implementation.c:242` | ITS remove refuses `WRITE_ONCE`, else calls the store |
| `zephyr/subsys/secure_storage/src/its/store/settings.c` | ITS remove is `settings_delete()`; the name is `its/<caller>/<uid>` |
| `zephyr/subsys/secure_storage/Kconfig.its_store:77` | The `its/` prefix default |
| `zephyr/subsys/secure_storage/include/internal/zephyr/secure_storage/its/common.h:16` | Caller id 2 is Mbed TLS |
| `zephyr/subsys/secure_storage/src/its/transform/aead_get.c` | AEAD key is SHA-256 over device id and uid; the insecure-provider warning |
| `zephyr/drivers/hwinfo/hwinfo_esp32.c` | The device id is six bytes of the factory MAC from eFuse |
| `zephyr/subsys/kvss/nvs/nvs.c:443,809,963,1210,1454` | Verified sector erase; GC erase; mount-time erase; `nvs_clear`; `nvs_delete` |
| `zephyr/include/zephyr/kvss/nvs.h:94,96` | `nvs_clear` is public; a zero-length write is a removal |
| `zephyr/subsys/settings/src/settings_nvs.c:215,384` | Delete writes two tombstones; the backend sizes its ring |
| `zephyr/subsys/settings/include/settings/settings_nvs.h:33` | The `0x8000` and `0x4000` id scheme |
| `zephyr/subsys/settings/Kconfig:201` | Eight sectors by default |
| `zephyr/drivers/flash/flash_esp32.c:111,147,482` | Erase value `0xff`; reads go over SPI; erase is not read back |
| `zephyr/dts/riscv/espressif/esp32c6/esp32c6_common.dtsi:302` | 4096-byte erase block |
| `modules/hal/espressif/components/esp_wifi/esp32c6/esp_adapter.c:545` | The Wi-Fi NVS wrappers are no-ops on this port |
| `modules/hal/espressif/components/esp_wifi/include/esp_wifi.h:1065` | ESP-IDF's default is `WIFI_STORAGE_FLASH` |
| `modules/hal/espressif/components/efuse/include/esp_efuse.h:25` | Reprogramming a programmed bit is forbidden |
| `modules/hal/espressif/components/efuse/esp32c6/esp_efuse_table.csv` | The ESP32-C6 field list, including the three that end reflashing |
| `firmware/tier-07-operational-identity/prj.conf` | The Secure Storage configuration under test |
| `firmware/tier-07-operational-identity/src/identity.c:48,58,663,890` | Key ids, the volatile pending key, `course_identity_erase()` |
| `firmware/tier-07-operational-identity/src/recovery_state.c:20` | Mounting erases; why Tier 6 stopped mounting twice |
| `firmware/tier-07-operational-identity/dts/esp32c6_4m_flash_map.dtsi` | The 192 KiB storage partition at `0x3b0000` |
| `firmware/common/Kconfig`, `firmware/common/src/net_link.c:73` | The passphrase is a Kconfig string passed straight to association |
| `docs/fixture-safety-contract.md`, "Reading the board's flash" | The dump stays inside the storage partition |
| `tf-psa-crypto/include/psa/crypto.h:532-548` | The implementation's own lingering-copies warning |
| `tf-psa-crypto/docs/architecture/psa-thread-safety/psa-thread-safety.md:302` | The project wants a guarantee it does not have |
| `tf-psa-crypto/core/psa_crypto_storage.c:212` | The `PSA\0KEY` record format, one record per key |
| `zephyr/subsys/secure_storage/src/its/transform/aead.c:63` | The leftover record is flags, nonce, ciphertext and tag |
| `zephyr/include/zephyr/drivers/flash.h` | `flash_erase()` does not verify; `flash_fill()` exists |
| `modules/hal/espressif/components/spi_flash/Kconfig:263` | ESP-IDF's dangerous-write guard and its default |
| `/opt/zephyr-workspace/build/tier-07-148/.../zephyr/.config` | Observed: no dangerous-write guard; 4 MB flash size |
