# Research: can Secure Storage and Tier 5's NVS share the `storage` partition

Ticket [#109](https://github.com/tkEmLogic/learning-cyber-security/issues/109), part of map [#104](https://github.com/tkEmLogic/learning-cyber-security/issues/104).
All source reading was done in the pinned workspace inside the `tier2-validate` container, Zephyr 4.4.2
(`/opt/zephyr-workspace/zephyr/VERSION`). Nothing was built and the board was not touched.

## Short answer

No, not as the two are written today. Both land on exactly the same flash.

`SETTINGS_NVS` always mounts its NVS instance at the **start** of the settings partition, and with no
`zephyr,settings-partition` chosen node in this tree that partition **is** `storage_partition`. With the
Zephyr defaults it claims 8 sectors of 4096 bytes, so `0x3b0000` to `0x3b8000`. Tier 5's
`recovery_state.c` mounts its own `nvs_fs` at `PARTITION_OFFSET(storage_partition)` with 3 sectors, so
`0x3b0000` to `0x3b3000`. Tier 5's region sits entirely inside the settings region, starting at the same
byte.

Nothing detects this. `nvs_mount()` never sees a flash area or a partition; it validates only page
alignment, sector size and a sector count of at least 2. Two NVS instances over one region therefore
both mount successfully and then corrupt each other. Worse, the damage does not wait for a write:
`nvs_startup()` erases the sector after the write sector during mount, so the second mount alone can
destroy the first instance's records.

There is good news underneath the collision. The two users do not actually want the same bytes, and
they do not want the same NVS entry IDs either. Settings uses IDs from `0x8000` upward, Tier 5 uses 1,
2 and 3. That makes a shared single instance, or a split by offset, genuinely available, and both avoid
touching the pinned flash map. The decision this forces reaches into how Tier 6 carries Tier 5's code,
not necessarily into Tier 5's published source. The options are in their own section below and this
report does not pick one.

`SECURE_STORAGE_ITS_MAX_DATA_SIZE` needs to be at least 68 for a P-256 private key plus PSA metadata.
The Zephyr default of 128 already covers it, so section 8's instruction to "size" it is satisfied by
leaving it alone, unless Tier 6 also decides to put the Factory certificate through the same API.

## 1. Two NVS users on one partition

`nvs_mount()` takes an `nvs_fs` that the caller has filled in with a flash device, a byte offset, a
sector size and a sector count. It checks four things and none of them is ownership:

| Check | Where |
| --- | --- |
| Write block size is supported | `nvs.c:1248` to `1254` |
| Sector size is not above `NVS_MAX_SECTOR_SIZE` | `nvs.c:1257` to `1261` |
| Sector size is a multiple of the flash page size at that offset | `nvs.c:1264` to `1272` |
| Sector count is at least 2 | `nvs.c:1275` to `1278` |

There is no flash-area lookup, no partition bound, no registry of mounted instances, and no check that
the region `offset + sector_size * sector_count` stays inside anything. Two `nvs_mount()` calls on
overlapping bytes both return 0.

What happens after that is not a race that might be fine. Each instance derives its own `ate_wra` and
`data_wra` from the flash at its own mount time and then keeps them in RAM (`nvs.c:1045` to `1083`).
From that moment each believes it owns the whole region it was given. Two consequences follow, and the
second is the one that bites first.

Writes interleave into the same allocation space. Tier 5's instance appends at its write pointer while
the settings instance appends at its own, which was computed before Tier 5's write existed. Neither
notices the other's entries because each only walks its own sector ring.

Mount itself is destructive. At the end of startup, NVS looks at the sector after its write sector and,
if it is not empty and carries no interrupted-garbage-collection marker, erases it
(`nvs.c:1091` onward, the comment at `1085` to `1090` states the intent). A three-sector instance and an
eight-sector instance disagree about which sector follows which, so the later mount can flatten a sector
the earlier one is using before a single application write happens.

Garbage collection makes it permanent. Tier 5's instance wraps after 3 sectors and the settings instance
after 8, so each will eventually erase a sector the other considers live.

The two do at least agree on the on-flash format, which is why neither mount fails loudly. That is what
makes this dangerous rather than merely broken: the first symptom a Learner would see is a resume record
that has silently gone missing, which is exactly the symptom Tier 5 exists to teach about.

One point that matters for the options below. The NVS entry ID spaces do not overlap:

| User | IDs used | Source |
| --- | --- | --- |
| Settings, name-count entry | `0x8000` | `settings_nvs.h:33` |
| Settings, setting names | `0x8001` upward | `settings_nvs.h:27` to `28` |
| Settings, setting values | name ID plus `0x4000` | `settings_nvs.h:34` |
| Tier 5 | 1, 2, 3 | `recovery_state.c:24` to `26` |

`settings_nvs_load()` walks name IDs downward and stops at `NVS_NAMECNT_ID`, so it never reads or writes
anything below `0x8000` (`settings_nvs.c:140` to `151`). NVS garbage collection copies valid entries
regardless of their ID, so foreign IDs survive a collection intact.

## 2. What `SETTINGS_NVS` does with the partition

It picks the partition at compile time and the geometry at run time, and the application gets no say in
either through Kconfig alone.

The partition is chosen by a preprocessor fallback, not by a Kconfig option:

```c
#if DT_HAS_CHOSEN(zephyr_settings_partition)
#define SETTINGS_PARTITION DT_PARTITION_ID(DT_CHOSEN(zephyr_settings_partition))
#else
#define SETTINGS_PARTITION PARTITION_ID(storage_partition)
#endif
```

That is `settings_nvs.c:20` to `24`. The course tree has no `zephyr,settings-partition` chosen node. The
board's chosen block lists sram, console, shell-uart, flash, code-partition and ieee802154 and nothing
else (`esp32c6_devkitc_hpcore.dts:18` to `25`), Tier 5's overlay adds only console and shell-uart
(`esp32c6_devkitc_esp32c6_hpcore.overlay`), and nothing under `firmware/` mentions a settings partition
at all. So `SETTINGS_PARTITION` resolves to `storage_partition`, the same node Tier 5 names.

The same fallback appears in the Kconfig dependency for the Secure Storage settings store, which accepts
either a `zephyr,settings-partition` chosen node or a plain `storage_partition` node under
`fixed-partitions` (`Kconfig.its_store:29` to `38`). The ESP32-C6 map puts `storage_partition` under a
`compatible = "fixed-partitions"` node (`partitions_0x0_default_4M.dtsi:9` and `43` to `46`), so the
option is selectable here with no devicetree change. That is why this collision is reachable by
configuration alone.

Geometry comes from `settings_backend_init()` at `settings_nvs.c:385` to `441`:

| Field | Value | Line |
| --- | --- | --- |
| `offset` | `fa->fa_off`, the first byte of the partition | `424` |
| `sector_size` | `CONFIG_SETTINGS_NVS_SECTOR_SIZE_MULT * hw_flash_sector.fs_size` | `406` to `407` |
| `sector_count` | counts up while the running total still fits in `fa->fa_size`, capped by `CONFIG_SETTINGS_NVS_SECTOR_COUNT` | `413` to `419`, `423` |

So the count is `min(CONFIG_SETTINGS_NVS_SECTOR_COUNT, floor(partition size / sector size))`. With the
defaults, `SETTINGS_NVS_SECTOR_SIZE_MULT` is 1 (`settings/Kconfig:201` to `203`) and
`SETTINGS_NVS_SECTOR_COUNT` is 8 (`settings/Kconfig:209` to `212`). The ESP32-C6 flash node declares
`erase-block-size = <4096>` (`esp32c6_common.dtsi:302`).

That gives a settings region of 8 times 4096, which is 32 KiB, at `0x3b0000` through `0x3b7fff`. The
remaining 160 KiB of the 192 KiB partition is not touched, not reserved and not recorded anywhere on
flash. Nothing in NVS or in the settings backend writes down how large the instance is, so the only
thing keeping a second user out of those 160 KiB is arithmetic that two pieces of source code have to
agree on independently.

The important half of this answer is the part that is not adjustable. `SETTINGS_NVS_SECTOR_COUNT` lets
you make the settings region **smaller**, and `SETTINGS_NVS_SECTOR_SIZE_MULT` lets you make its sectors
**larger**, but the `offset` is hard-wired to `fa->fa_off` at line 424. There is no Kconfig symbol and no
devicetree property that moves the settings instance off the start of its partition. Whatever else
shares that partition has to be the one that moves.

To answer the sub-question as asked: it claims the first 32 KiB of the fixed-partition region by
default, not the whole of it, and it decides that by reading the first hardware sector's size and
multiplying, bounded by the partition size and by a Kconfig cap.

## 3. Does Tier 6 have to move Tier 5's record onto settings

No. That is one of five ways out, and it is not the cheapest.

The constraint is narrower than it looks. Settings must start at the beginning of its partition, and
that partition is `storage_partition` unless a chosen node says otherwise. Everything else is free:

- Tier 5's offset is a line of C in the tier's own tree, `course_nvs.offset = PARTITION_OFFSET(STORAGE_PARTITION)` at `recovery_state.c:50`, not a devicetree or Kconfig fact.
- The entry ID spaces are already disjoint, as shown in sub-question 1.
- The settings subsystem exposes its `nvs_fs` through the documented public call `settings_storage_get()`, whose doc comment states it returns a pointer to `struct nvs_fs` for this backend (`settings.h:717` to `729`, implementation at `settings_store.c:287` to `300`, and the NVS backend supplies it at `settings_nvs.c:443` to `448`).

So a shared instance and an offset split are both available without adding a partition. Both are listed
with their costs in the next section.

On the flash map specifically, the ticket is right that adding a partition is expensive, and the map is
worse off than "expensive". It is full. The upstream file ends with the comment "Remaining flash size is
0kB / Last used address is 0x3FFFFF" (`partitions_0x0_default_4M.dtsi:60` to `62`), and the course's
pinned copy reproduces every region with no gap (`esp32c6_4m_flash_map.dtsi`). A new partition therefore
cannot be appended; something existing has to shrink. Section 6 calls the map a contract and says an
application that does not fit is a build failure rather than a reason to change the map inside a tier
(`docs/course-specification.md:196`).

One related finding worth recording. Section 6 also says "assert every offset and size in CI". No such
assertion exists yet: searching the repo for `0x3b0000`, for `storage_partition` and for any flash-map
check under `scripts/` and `.github/` returns nothing. So today the pinned map is pinned by one
devicetree include and by review, not by a test. That does not change the answer here, but it means a
map change would not be caught automatically if someone made one.

On whether Tier 5's published source is implicated: under the map's own Tier 5 finding rule, this is a
defect that sits harmlessly in Tier 5 as published. Tier 5 alone is correct. It only becomes wrong when
a second NVS user appears, which is exactly the "why it only surfaced a tier later" shape that the rule
says to teach rather than to retrofit. A Learner following Tier 5 as written reaches no wrong
conclusion, and Tier 6 can be built around it, so the rule's two stated triggers for changing Tier 5
itself are not met by this finding on its own. The judgement that is still open, and it is the human's,
is whether the resolution Tier 6 picks reads as a correction of Tier 5's comment about choosing NVS over
settings, in which case leaving that comment standing in the published tier may mislead.

## 4. `SECURE_STORAGE_ITS_MAX_DATA_SIZE` for a P-256 private key

The value must be at least **68**. The default is 128, which is enough.

PSA persistent keys are stored as a fixed header followed by the key material, in
`psa_persistent_key_storage_format` at `psa_crypto_storage.c:225` to `234`:

| Field | Bytes | Why |
| --- | --- | --- |
| `magic` | 8 | `sizeof("PSA\0KEY")`, `psa_crypto_storage.c:222` to `223` |
| `version` | 4 | fixed array |
| `lifetime` | 4 | `psa_key_lifetime_t` is `uint32_t`, `crypto_types.h:176` |
| `type` | 2 | fixed array |
| `bits` | 2 | fixed array |
| `policy` | 12 | `psa_key_policy_s` is three 32-bit fields, `crypto_struct.h:277` to `282`, with `psa_key_usage_t` and `psa_algorithm_t` both `uint32_t`, `crypto_types.h:127` and `316` |
| `data_len` | 4 | fixed array |
| header total | **36** | every member is a `uint8_t` array, so no padding |
| `key_data` | 32 | P-256 private scalar |
| entry total | **68** | |

The key material is the PSA export representation, which for an ECC key pair is the private scalar
alone, 32 bytes at P-256. The code says so directly at `psa_crypto.c:1889` to `1893`: "Key material is
saved in export representation in the slot, so just pass the slot buffer for storage."

What that 68 turns into on flash, with section 8's AEAD transform:

| Quantity | Value | Source |
| --- | --- | --- |
| ITS entry data | 68 | above |
| Packed create flags | 1 | `secure_storage_packed_create_flags_t` is `uint8_t`, `common.h:11` |
| AEAD overhead | 28 | 16-byte tag plus 12-byte nonce, `Kconfig.its_transform:24` to `26` |
| Bytes written to the settings value | 97 | |
| NVS per-entry ceiling | 4064 | sector size minus 4 ATEs, `nvs.c:1317` to `1326`, with `struct nvs_ate` 8 bytes packed |

So the record fits with a very large margin, and the setting name is short as well: the default scheme
produces `its/<caller>/<hex uid>` bounded by `SECURE_STORAGE_ITS_STORE_SETTINGS_NAME_MAX_LEN`, whose
default of 14 is checked by a `BUILD_ASSERT` against the prefix length and `2 * sizeof(psa_storage_uid_t)`
(`store/settings.c:30` to `33`). That assert passes only because Zephyr narrows `psa_storage_uid_t` to
`uint32_t` when `SECURE_STORAGE_64_BIT_UID` is off (`psa/storage_common.h:24` to `27`), giving
4 + 1 + 1 + 8 = 14. Leave `SECURE_STORAGE_64_BIT_UID` off, which is the default, and this is consistent.

Two things to keep in view rather than change:

The value costs stack, not flash. The Kconfig help says raising it increases stack usage when serving
ITS calls (`secure_storage/Kconfig:59` to `64`), and the code shows why: `get_entry()` and
`store_entry()` each put a `SECURE_STORAGE_ITS_TRANSFORM_MAX_STORED_DATA_SIZE` buffer on the stack
(`implementation.c:84` and `136`) and `keep_stored_entry()` adds a second buffer of
`CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE` on top (`implementation.c:100`), with
`MAX_STORED_DATA_SIZE` defined as `MAX_DATA_SIZE + 1 + 28` (`its/common.h:54` to `57`). At the default
128 that is roughly 285 bytes across nested frames, which Tier 5's 8192-byte main stack absorbs easily.

The number changes completely if the certificate goes through the same API. 68 covers the private key
and its PSA metadata, which is what the sub-question asks and what section 8's sentence says. A DER
ECDSA P-256 certificate is several hundred bytes, so storing the Factory certificate through ITS or PS
would push `MAX_DATA_SIZE` past 128 and raise the stack cost of every ITS call, including the key ones.
Whether Tier 6 stores the certificate on the device at all is not settled on this ticket.

One adjacent fact that saves a later surprise: the PSA key ID must fit the 30-bit ITS UID. Without
`MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER` the UID is the key ID unchanged
(`psa_crypto_storage.c:50` to `56`), the ITS layer rejects anything with bits set above 30
(`implementation.c:27` to `35`), and Zephyr's application range begins at `0x30000000`
(`key_ids.h:48` to `49`), which fits. Take the Factory key ID from that range.

## Options if they cannot share

Five ways out. Costs are stated so the human can choose; this report does not choose.

### A. Move Tier 5's records onto the settings subsystem

Delete the second `nvs_fs` and store the three records as settings entries.

| Cost | Detail |
| --- | --- |
| Code | `recovery_state.c` rewritten around `settings_save_one` and a load handler, in Tier 6's tree |
| Teaching | Directly reverses the reasoning in `prj.conf:131` to `134` and the comment at `recovery_state.c:15` to `23`, both of which argue for seeing the raw write in the one tier about surviving a power cut |
| Data | Records written by a Tier 5 image are not found by a Tier 6 image; a board carried forward loses its resume state once |
| Map | No change |
| Reaches into Tier 5 | Only if the published comment is judged misleading once Tier 6 contradicts it |

### B. Share the one settings-owned NVS instance

Keep raw `nvs_read` and `nvs_write` with IDs 1 to 3, but on the `nvs_fs` that settings already mounted,
obtained through `settings_storage_get()`.

| Cost | Detail |
| --- | --- |
| Code | Smallest delta: `recovery_state_init()` stops mounting and fetches the pointer instead |
| Teaching | Tier 5's point survives intact, the raw write is still visible, and the tier gains an honest lesson about two subsystems sharing one store |
| Ordering | Must run after the Secure Storage `SYS_INIT` at `APPLICATION` priority (`store/settings.c:24`); Tier 5 calls `recovery_state_init()` from `main`, which is after that, but the dependency becomes real and undeclared |
| Risk | Tier 5's records now live inside the settings instance's 32 KiB and are subject to its garbage collection; correct by inspection, unverified on hardware |
| Data | Existing Tier 5 records at the same offset are inside the settings region, so they may be readable, or may already have been erased by the settings mount; do not rely on either |
| Map | No change |

### C. Split the partition by offset in C

Leave settings at the bottom 8 sectors and move Tier 5's instance above it, for example to
`PARTITION_OFFSET(storage_partition) + 8 * 4096`.

| Cost | Detail |
| --- | --- |
| Code | One line in Tier 6's copy of `recovery_state.c`, plus a comment explaining the arithmetic |
| Fragility | The boundary exists only because two numbers in two subsystems agree. Raising `CONFIG_SETTINGS_NVS_SECTOR_COUNT` later silently overruns Tier 5's region, and nothing in NVS or settings would report it |
| Mitigation | A `BUILD_ASSERT` in Tier 6's tree tying the offset to `CONFIG_SETTINGS_NVS_SECTOR_COUNT` times the erase block size would make a future change a build failure instead of a corruption |
| Data | Records written by a Tier 5 image sit at the old offset and are abandoned |
| Map | No change |

### D. Split the partition in devicetree

Either carve `storage` into two sibling `fixed-partitions` entries, or nest `zephyr,mapped-partition`
nodes, and point a `zephyr,settings-partition` chosen node at one of them. The Kconfig dependency accepts
both shapes (`Kconfig.its_store:31` to `37`), and the binding documents nested partitions
(`zephyr,mapped-partition.yaml:4` to `10`).

| Cost | Detail |
| --- | --- |
| Map | This is a change to the pinned map that section 6 calls a contract (`docs/course-specification.md:196`) |
| Structure | The ESP32-C6 map is `fixed-partitions` today; the nested-mapped variant needs `ranges` properties on the flash node, which is a larger devicetree change than it first appears |
| Benefit | The boundary is declared once and both users read it, rather than being an unchecked arithmetic agreement |
| Unverified | Whether `flash_area` and `PARTITION_ID` behave as needed for a nested mapped partition on this SoC was not confirmed; needs a build |

### E. Add a dedicated partition, or use the ZMS store

`SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_ZMS` wants its own `secure_storage_its_partition`
(`Kconfig.its_store:13` to `27`), which is the same requirement as adding a partition.

| Cost | Detail |
| --- | --- |
| Map | The map has no free space at all; the last used address is `0x3FFFFF` and remaining size is 0 kB (`partitions_0x0_default_4M.dtsi:60` to `62`), so something must shrink |
| Spec | Section 8 pins the settings-backed store, so ZMS is a spec change as well as a map change |
| Scope | The most expensive option on this list and the one the ticket already flags as expensive |

## What this could not settle by reading

Everything below is owed to the build ticket or to the board, and none of it is claimed here.

1. **Whether the collision reproduces as described on hardware.** The analysis is from source. The predicted symptom is that a Tier 6 image with both users mounted loses Tier 5's resume record, possibly at mount rather than at write. Reading `recovery_state.c`'s own mount log line and then the stored record is the check, not the serial log alone.
2. **The actual settings region on this board.** 8 sectors of 4096 at `0x3b0000` follows from `flash_area_get_sectors()` returning 4096 for the first sector of this partition and from the Kconfig defaults. `flash_area_get_sectors` was read, not run. Confirm the geometry at run time before any option C offset is trusted.
3. **The exact stored key length.** 68 bytes follows from the header arithmetic plus a 32-byte export representation. The PSA export size for a generated P-256 key pair was taken from the code comment at `psa_crypto.c:1889` to `1890` and the PSA export convention, not measured. A build that logs the ITS data length settles it.
4. **Whether option B's shared instance behaves under garbage collection.** NVS collection is ID-agnostic by construction, so Tier 5's IDs should survive. This needs a power-cut run with enough writes to force a collection before it is stated as fact.
5. **Whether the whole configuration fits.** Adding `SECURE_STORAGE`, `SETTINGS` and the AEAD transform to Tier 5's already large image was not sized. Section 6 makes an image that does not fit its 1792 KiB slot a build failure, not a map change, so this is a real gate and not a formality.
6. **Whether `HWINFO_HAS_DRIVER` is set for this board.** An ESP32 hwinfo driver exists in tree (`drivers/hwinfo/hwinfo_esp32.c`, `drivers/hwinfo/Kconfig:34`), and section 8 requires the device-ID-hash key provider, which the choice defaults to only when that symbol is set (`Kconfig.its_transform:63` to `68`). Whether it resolves to `y` in this build was not confirmed.
7. **Option D's nested mapped-partition variant.** Whether `flash_area_open` and `PARTITION_ID` work against a nested `zephyr,mapped-partition` on the ESP32-C6 flash node was not confirmed and needs a build.

## Sources

Paths inside the container are under `/opt/zephyr-workspace/`. Repository paths are relative to
`/home/tarjeik/dev/emlogic/learning-cyber-security/`.

| What | Path | Lines |
| --- | --- | --- |
| Zephyr version | `zephyr/VERSION` | 1 to 3 |
| Settings partition fallback to `storage_partition` | `zephyr/subsys/settings/src/settings_nvs.c` | 20 to 24 |
| Settings NVS geometry and offset | `zephyr/subsys/settings/src/settings_nvs.c` | 385 to 441, offset at 424 |
| Settings NVS load stops at `NVS_NAMECNT_ID` | `zephyr/subsys/settings/src/settings_nvs.c` | 140 to 151 |
| Settings NVS exposes its `nvs_fs` | `zephyr/subsys/settings/src/settings_nvs.c` | 443 to 448 |
| Settings NVS ID layout | `zephyr/subsys/settings/include/settings/settings_nvs.h` | 18 to 34 |
| `settings_storage_get` public API and doc | `zephyr/include/zephyr/settings/settings.h` | 717 to 729 |
| `settings_storage_get` implementation | `zephyr/subsys/settings/src/settings_store.c` | 287 to 300 |
| `SETTINGS_NVS_SECTOR_SIZE_MULT` default 1 | `zephyr/subsys/settings/Kconfig` | 201 to 203 |
| `SETTINGS_NVS_SECTOR_COUNT` default 8 | `zephyr/subsys/settings/Kconfig` | 209 to 212 |
| `SETTINGS_BACKEND` defaults to NVS when NVS is on | `zephyr/subsys/settings/Kconfig` | 59 to 66 |
| `nvs_mount` checks, no partition awareness | `zephyr/subsys/kvss/nvs/nvs.c` | 1234 to 1297 |
| `nvs_startup` write pointers and sector erase | `zephyr/subsys/kvss/nvs/nvs.c` | 963 to 1100 |
| NVS maximum entry data size | `zephyr/subsys/kvss/nvs/nvs.c` | 1299 to 1326 |
| `struct nvs_ate` is 8 bytes packed | `zephyr/subsys/kvss/nvs/nvs_priv.h` | 98 to 104 |
| ITS store implementation choice and its DT dependency | `zephyr/subsys/secure_storage/Kconfig.its_store` | 4 to 49 |
| ITS settings store name length assert | `zephyr/subsys/secure_storage/src/its/store/settings.c` | 26 to 51 |
| ITS settings store `SYS_INIT` at APPLICATION priority | `zephyr/subsys/secure_storage/src/its/store/settings.c` | 15 to 24 |
| `SECURE_STORAGE_ITS_MAX_DATA_SIZE` default 128 and its stack note | `zephyr/subsys/secure_storage/Kconfig` | 59 to 64 |
| AEAD output overhead default 28 | `zephyr/subsys/secure_storage/Kconfig.its_transform` | 21 to 30 |
| AEAD key provider default needs `HWINFO_HAS_DRIVER` | `zephyr/subsys/secure_storage/Kconfig.its_transform` | 61 to 77 |
| `MAX_STORED_DATA_SIZE` formula | `zephyr/subsys/secure_storage/include/internal/zephyr/secure_storage/its/common.h` | 54 to 57 |
| ITS UID 30-bit limit | `zephyr/subsys/secure_storage/src/its/implementation.c` | 27 to 35 |
| ITS stack buffers | `zephyr/subsys/secure_storage/src/its/implementation.c` | 84, 100, 136 |
| Packed create flags is one byte | `zephyr/subsys/secure_storage/include/internal/zephyr/secure_storage/common.h` | 11 |
| `psa_storage_uid_t` narrowed to `uint32_t` | `zephyr/subsys/secure_storage/include/psa/storage_common.h` | 24 to 27 |
| PSA key storage header layout | `modules/crypto/tf-psa-crypto/core/psa_crypto_storage.c` | 222 to 234 |
| UID is the key ID without owner encoding | `modules/crypto/tf-psa-crypto/core/psa_crypto_storage.c` | 40 to 57 |
| Key material stored in export representation | `modules/crypto/tf-psa-crypto/core/psa_crypto.c` | 1887 to 1894 |
| `psa_key_lifetime_t`, `psa_algorithm_t`, `psa_key_usage_t` are 32-bit | `modules/crypto/tf-psa-crypto/include/psa/crypto_types.h` | 127, 176, 316 |
| `psa_key_policy_s` is three 32-bit fields | `modules/crypto/tf-psa-crypto/include/psa/crypto_struct.h` | 277 to 282 |
| Zephyr application PSA key ID range | `zephyr/include/zephyr/psa/key_ids.h` | 47 to 49 |
| ESP32-C6 erase block size 4096 | `zephyr/dts/riscv/espressif/esp32c6/esp32c6_common.dtsi` | 302 |
| Upstream partition table, `fixed-partitions`, storage at `0x3b0000`, flash full | `zephyr/dts/vendor/espressif/partitions_0x0_default_4M.dtsi` | 9, 43 to 46, 60 to 62 |
| Board chosen nodes, no settings partition | `zephyr/boards/espressif/esp32c6_devkitc/esp32c6_devkitc_hpcore.dts` | 18 to 25 |
| Nested mapped-partition binding | `zephyr/dts/bindings/mtd/zephyr,mapped-partition.yaml` | 4 to 10 |
| Tier 5 chose NVS over settings, with reasons | `firmware/tier-05-recovery/prj.conf` | 124 to 135 |
| Tier 5 NVS IDs 1 to 3 and the same reasoning again | `firmware/tier-05-recovery/src/recovery_state.c` | 15 to 26 |
| Tier 5 mounts at the partition offset with 3 sectors | `firmware/tier-05-recovery/src/recovery_state.c` | 49 to 71 |
| Pinned flash map, storage at `0x3b0000` size `0x30000` | `firmware/tier-05-recovery/dts/esp32c6_4m_flash_map.dtsi` | 29 to 31 |
| Tier 5 overlay adds no settings partition chosen | `firmware/tier-05-recovery/boards/esp32c6_devkitc_esp32c6_hpcore.overlay` | whole file |
| Map is a contract, not fitting is a build failure | `docs/course-specification.md` | 196 |
| Section 8 pins the Secure Storage configuration | `docs/course-specification.md` | 310 to 316 |
