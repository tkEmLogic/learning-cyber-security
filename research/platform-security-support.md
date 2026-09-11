# ESP32-C6, Zephyr, and MCUboot security support

## Research scope

This report answers [GitHub issue 4](https://github.com/tkEmLogic/learning-cyber-security/issues/4).

Research date: 2026-09-11.

The selected Zephyr board target is:

`esp32c6_devkitc/esp32c6/hpcore`

The main versions reviewed are:

- ESP-IDF 6.1 for the ESP32-C6 hardware security reference.
- Zephyr 4.4.2 for the current stable Zephyr code.
- MCUboot 2.4.0 for the current MCUboot release.
- Zephyr `main` only where a change after 4.4.2 affects the result.

The Zephyr board selects the ESP32-C6-WROOM-1U-N8 module. This is an 8 MiB
flash module. The board still includes Zephyr's default 4 MiB partition map.
The default map therefore uses only the first 4 MiB. It gives MCUboot two
1,792 KiB image slots, a 124 KiB scratch area, and other small partitions.
This is usable, but a product must decide whether to keep this layout or define
an explicit 8 MiB layout. [Z17]

## Short answer

The ESP32-C6 has strong hardware security features. Zephyr has TLS, update
APIs, secure storage APIs, and new ESP32-C6 memory protection support. MCUboot
has signed updates, test boot, confirmation, revert, encrypted update images,
and optional hardening.

These parts do not form one fully integrated upstream security stack.

The normal Zephyr sysbuild path builds MCUboot from `boot/zephyr`. Espressif
states that ESP32 secure boot and flash encryption are available only through
the separate MCUboot Espressif port. Zephyr sysbuild does not select that port.
[E1] [Z5]

There is also a critical Zephyr 4.4.2 default. The ESP32-C6 board selects
`BOOT_SIGNATURE_TYPE_NONE`. MCUboot then checks an image hash but does not
authenticate the image with a signing key. A change on Zephyr `main` removes
this board override and restores the normal RSA default. That change is not in
the v4.4.2 tag. A Zephyr 4.4.2 product must select a real MCUboot signature type
explicitly. [Z3] [Z4] [M4]

The strongest practical chain found in official upstream material is a manual
integration:

`ESP ROM -> MCUboot Espressif port -> signed Zephyr application`

In that chain:

- ESP Secure Boot v2 lets the ROM authenticate the MCUboot bootloader.
- MCUboot authenticates the Zephyr application.
- ESP flash encryption protects the bootloader, both image slots, scratch, and
  selected data in off-chip flash.
- The Zephyr application uses MCUboot-compatible flash writes and the same
  partition layout.

MCUboot documents ESP32-C6 as supported by its Espressif port with Zephyr.
However, this is a separate bootloader build with manual layout and toolchain
work. It is not the bootloader built by standard Zephyr sysbuild. No official
end-to-end test result was found for the exact combination of MCUboot 2.4.0,
its Espressif port, Zephyr 4.4.2, ESP Secure Boot v2, and flash encryption on
`esp32c6_devkitc/esp32c6/hpcore`. [M5] [M6] [Z5]

## Terms

**Root of trust** means the first component that must be trusted. On ESP32-C6,
this is code in ROM plus security state stored in eFuses.

**eFuse** means one-time-programmable memory inside the chip. A bit changes
from 0 to 1 and cannot change back. Espressif calls writing an eFuse
"burning." [E4] [E9]

**Primary slot** means the flash area from which MCUboot normally starts the
application.

**Secondary slot** means the staging area for a new application image.

**Image confirmation** means that the new application marks itself as working.
Without confirmation, a test update can revert to the old image.

**Anti-rollback** means rejecting an old but correctly signed image. A signature
alone does not stop an attacker from installing an older signed release.

**PMP** means RISC-V Physical Memory Protection. It limits which memory ranges
code may read, write, or execute.

**FIH** means fault injection hardening. It adds checks that make voltage,
clock, or instruction-skip attacks harder.

## Compatibility result

| Capability | ESP32-C6 hardware | Zephyr 4.4.2 standard path | MCUboot 2.4.0 Espressif path | Practical result |
| --- | --- | --- | --- | --- |
| ROM-authenticated bootloader | Yes, Secure Boot v2 | Not enabled by standard sysbuild | Documented | Use a manual Espressif-port bootloader build |
| Authenticated application | Yes in the native IDF bootloader | Yes with MCUboot, but the board default is unsigned in 4.4.2 | Yes | Set a real MCUboot signature type explicitly |
| Off-chip flash confidentiality | Yes, hardware flash encryption | Application compatibility option exists, but standard sysbuild does not provision it | Documented | Use the Espressif port and test the full layout |
| Encrypted update image | Not the same feature as flash encryption | Generic MCUboot support | Generic MCUboot support | Useful for transport and staging, but not enough for the executable primary slot |
| Hardware anti-rollback | The native ESP-IDF flow has an eFuse secure version | No ESP32-C6 MCUboot counter backend found | No Espressif hardware counter implementation found | MCUboot checks are software-only unless a platform backend is added |
| TLS | Hardware accelerators exist | Native TLS sockets use PSA Crypto and Mbed TLS | Not a bootloader feature | Supported in Zephyr |
| Persistent TLS credential vault | eFuse, HMAC, and RSA_DS hardware exist | Default TLS backend is volatile. Protected Storage backend requires TF-M | Not provided | No upstream hardware-backed vault on this board |
| PSA secure storage | Hardware can help, but integration matters | Functional support exists. Default key derivation is not a hardware secret | Not a bootloader feature | Add a custom key provider and hardware protection, or treat it as limited |
| Userspace isolation | ESP32-C6 has PMP | PMP support is present in 4.4, not 4.3 or LTS 3.7 | MCUboot does not use Zephyr PMP | Promising, but validate on hardware |
| Hardware HMAC and RSA signing | Yes through ESP-IDF | No upstream Zephyr 4.4.2 driver or API integration found | Not used for MCUboot verification keys | Do not plan on these through standard Zephyr without custom work |
| Recovery | ROM download modes exist | Generic MCUboot recovery exists | ESP32-C6 serial and USB Serial/JTAG recovery are documented | Keep a controlled recovery path until production validation |

## The three possible boot chains

### 1. Zephyr Simple Boot

```text
ESP32-C6 ROM
  -> Zephyr application
```

This is the default when the application is built without sysbuild or another
bootloader setup. Zephyr states that Simple Boot provides no security features
and no OTA update support. It is suitable for early development only. [Z2]

### 2. Standard Zephyr sysbuild

```text
ESP32-C6 ROM
  -> MCUboot Zephyr port
  -> Zephyr application in the primary slot
```

Zephyr sysbuild adds `${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/zephyr/`. It does not add
`boot/espressif/`. This path can provide normal MCUboot image authentication,
primary-slot validation, update swaps, test boot, confirmation, revert, generic
image encryption, and software downgrade checks. [Z5] [M2] [M3] [M4]

This path does not, by itself, create a hardware-rooted chain from the ESP ROM.
Espressif says secure boot and flash encryption are only available through the
MCUboot Espressif port. [E1]

Zephyr 4.4.2 has an extra risk. The board file selects no application signature.
With this setting, MCUboot uses only a hash check. A person who can replace the
image can calculate a new hash. This is integrity checking, not proof that the
image came from the product owner. [Z3] [M4]

The fix on Zephyr `main` removes the unsigned override from Espressif boards.
Projects based on 4.4.2 should not wait for a future release. They should set an
explicit signature choice and inspect the generated MCUboot configuration.
[Z4]

### 3. Manual hardware-rooted chain

```text
ESP32-C6 ROM
  -> verifies MCUboot Espressif port
  -> MCUboot verifies the Zephyr application
  -> Zephyr application confirms or manages updates
```

The MCUboot Espressif port documents ESP32-C6 and Zephyr as supported. It can
use Espressif Secure Boot v2 and flash encryption. Its ESP32-C6 default layout
matches the main Zephyr 4 MiB offsets for the bootloader, primary slot,
secondary slot, and scratch area. This reduces integration work. It does not
prove that every security option works together. [M5] [M6] [Z17]

The application must also enable Zephyr's
`CONFIG_ESP_FLASH_ENCRYPTION` compatibility option. That option requires an
MCUboot-loaded application, a 32-byte flash write block, and no Simple Boot.
The option says that hardware flash encryption must be enabled in the MCUboot
Espressif port. [Z6]

When flash encryption is enabled, MCUboot images must use 32-byte alignment and
padding to the slot size. The secondary slot and scratch area must be erased
before first boot. The Zephyr linker layout must not overlap the Espressif
bootloader's RAM areas. Sign an image before applying host-side flash
encryption. [M5] [E8]

## ESP32-C6 hardware security

### Secure Boot v2

ESP32-C6 Secure Boot v2 can use RSA-PSS with RSA-3072 or ECDSA-P256 in the
ESP-IDF 6.1 boot flow. The ROM verifies the second-stage bootloader. The
second-stage bootloader then verifies the application. The chip can store up
to three public-key digests and can permanently revoke individual keys. [E2]

The current MCUboot Espressif-port guide is narrower. It documents RSA-based
hardware secure boot for ESP32-C6. Its ECDSA exception applies to ESP32-C2 and
ESP32-C61. Therefore, RSA-3072 is the established choice for ROM verification
of an ESP32-C6 MCUboot bootloader in this port. Do not assume that the broader
ESP-IDF ECDSA choice is integrated into MCUboot for this target. [M5]

The ROM signature and the MCUboot application signature are separate.
For example, the ROM can verify MCUboot with ESP Secure Boot RSA-3072, while
MCUboot verifies the Zephyr application with ECDSA-P256. This means two key
pairs, two image formats, and two signing steps. [E2] [M4] [M5]

Secure Boot v2 pads an image to the flash MMU page boundary before adding its
signature block. The default page size is 64 KiB. This can increase bootloader
or application size. Espressif also warns that enabling secure boot or flash
encryption can increase bootloader size and may require a partition offset
change. [E2]

### Flash encryption

ESP32-C6 flash encryption protects content in off-chip SPI flash. It uses the
hardware flash encryption block. In release mode, plaintext updates through
the normal UART download path are restricted. Runtime flash reads and writes
are transparently decrypted and encrypted. [E3]

The C6 flash key is stored in an eFuse key block with the
`XTS_AES_128_KEY` purpose. A device-generated key can be created on first boot.
The key block is then read-protected and write-protected. Software cannot read
the key. A host-generated key is also possible, but the owner must protect it
and should use a different key for each device. [E3]

Development mode is not production protection. It allows repeated plaintext
downloads, which can expose plaintext indirectly. Espressif recommends release
mode for production. Release mode also reduces recovery options, so the update
agent and a tested recovery plan must exist before it is enabled. [E3] [M5]

MCUboot encrypted images are a different feature. They protect an image while
it is transported or stored in a secondary slot. MCUboot decrypts the image as
it moves to the primary slot. The primary executable image is normally
plaintext. Since ESP32-C6 executes from off-chip flash, MCUboot image encryption
alone does not give full code confidentiality. Hardware flash encryption is
needed for that goal. [M3] [M5]

### eFuses

ESP32-C6 has 11 eFuse blocks of 256 bits. Blocks 4 through 8 can hold keys for
secure boot, flash encryption, HMAC, and related uses. Block 9 can hold keys
except a flash encryption key because of a hardware erratum. Each key block
has a key-purpose field. [E4]

An eFuse bit can only change from 0 to 1. Key blocks use Reed-Solomon coding.
Each such block can only be written once because the check symbols cover the
whole block. Espressif provides batch writing so related values and protection
bits can be prepared and burned together. [E4] [E9]

The main permanent actions include:

- Burning a secure boot public-key digest.
- Enabling Secure Boot v2.
- Revoking a secure boot key.
- Burning a flash encryption key.
- Setting and locking flash encryption release mode.
- Read-protecting or write-protecting a key block.
- Permanently disabling JTAG.
- Permanently disabling ROM download mode.

These actions can make a board impossible to debug or recover. A wrong key,
wrong image, wrong offset, or missing update agent can make the board unusable.
[E2] [E3] [E4] [E9] [M5]

### HMAC and RSA Digital Signature hardware

The chip has an HMAC engine. It can use a read-protected eFuse key without
exposing that key to software. Supported uses include software HMAC, deriving
the key for the RSA Digital Signature peripheral, and re-enabling
soft-disabled JTAG. [E5]

The RSA Digital Signature peripheral can create RSA signatures without
exposing the HMAC eFuse key or decrypted private-key parameters to software.
The encrypted RSA parameters remain in flash. ESP-IDF 6.1 exposes this through
native and PSA Crypto interfaces. [E6]

These chip features are not the same as Zephyr support. The Espressif HAL
revision pinned by Zephyr 4.4.2 adds AES and SHA source files for
`CONFIG_CRYPTO_ESP32`. It does not add HMAC or RSA Digital Signature source
files there. Searches of the upstream Zephyr tree found no use of
`esp_hmac_calculate()` or `esp_ds_sign()`. Treat HMAC-backed secrets and RSA_DS
TLS client keys as custom integration work, not as a current upstream Zephyr
feature. [Z10]

MCUboot's Espressif guide also states that hardware key storage is not
supported for its image verification key. The MCUboot public verification key
is embedded in the bootloader. The private signing key must stay off the
device. [M5]

### Entropy and random numbers

ESP32-C6 has a hardware random number generator. Its output is guaranteed to
be true random only while a suitable physical noise source is active. Examples
include an active RF subsystem or the internal entropy source. If no main noise
source is active, Espressif says to treat the output as pseudo-random. [E7]

The Zephyr ESP32 entropy driver gives the same warning. With Wi-Fi and Bluetooth
disabled, it produces pseudo-entropy because radio noise is not feeding the
generator. This matters for TLS key generation, secure storage nonces, and the
MCUboot high FIH profile. [Z9] [M4]

A product that turns all radios off must not assume that the default entropy
driver provides a continuous true-random stream. Seed a cryptographic
deterministic random bit generator from verified hardware entropy, or provide
another validated entropy source. Test the exact power and radio state used by
the product. [E7]

### Memory protection

Zephyr 4.4 adds ESP32-C6 PMP support. The board has 16 PMP slots. Zephyr defines
read and execute regions for ROM and for the exact IRAM text range. This avoids
making the shared IRAM and DRAM physical range fully executable. [Z7]

The ESP32-C6 SoC configuration in Zephyr 4.3.0 does not select RISC-V PMP.
Zephyr 3.7 LTS is older still. A product that needs upstream ESP32-C6 userspace
isolation should start from Zephyr 4.4, not 4.3 or 3.7. [Z7] [Z8]

Zephyr user mode runs selected threads with reduced privilege and uses memory
domains and the architecture's protection hardware. It is not automatic
application isolation. The product must enable userspace, place threads in user
mode, assign memory domains, and expose only needed system calls and kernel
objects. [Z19]

The PMP selection is disabled while building MCUboot itself. MCUboot uses its
own boot-stage region protection path. The application and bootloader therefore
need separate review. [Z7]

No official result was found that shows the full Zephyr userspace test suite
passing on physical `esp32c6_devkitc/esp32c6/hpcore`. PMP support is upstream,
but it is new in 4.4. Hardware tests are still required.

### Debug and download controls

ESP32-C6 supports both permanent JTAG disable and soft JTAG disable. Soft
disable can be reversed by a correct HMAC challenge. Permanent disable takes
priority and cannot be reversed. [E5]

The ROM download mode can be left open, changed to a restricted secure download
mode, or permanently disabled. Permanent disable prevents later UART flashing.
The MCUboot Espressif guide recommends keeping debug and virtual eFuses during
development. It recommends `--after no_reset` when flashing a bootloader that
will provision security state on first boot. [M5]

Virtual eFuses reduce risk during testing, but they do not make every command
safe. The MCUboot guide warns that its host key-burning command still burns the
physical eFuse even when virtual eFuse mode is enabled. [M5]

## Zephyr security services

### TLS

Zephyr supports TLS and DTLS through secure sockets. With native networking,
`CONFIG_NET_SOCKETS_SOCKOPT_TLS` selects PSA Crypto and Mbed TLS. The
application can require peer certificate checks, choose ciphersuites, and bind
credentials to a socket through security tags. [Z11] [Z12]

This is software TLS support. Zephyr 4.4.2 does not establish use of the
ESP32-C6 RSA Digital Signature peripheral for TLS client authentication.
Private-key operations therefore use the configured software crypto path unless
the product adds and validates a hardware driver. [Z10] [E6]

The product must also manage trusted time and root certificate updates.
Certificate expiry checks need a trusted clock. A bad root-certificate update
can stop future secure updates. This is an application lifecycle problem, not
only a TLS configuration problem. [E10]

### TLS credential storage

The TLS credentials API supports CA certificates, public certificates, private
keys, pre-shared keys, and pre-shared-key identities. A `sec_tag_t` is only an
integer reference to a registered credential. It is not proof of hardware
protection. [Z12]

The default Zephyr 4.4.2 backend is volatile. It stores credential references in
runtime memory. Persistent Protected Storage is available only when building
with Trusted Firmware-M. ESP32-C6 is RISC-V and this Zephyr board does not use
TF-M. Therefore, the normal TLS credential API does not give this board a
persistent hardware-backed credential vault. [Z12]

Certificates can be compiled into firmware or loaded from storage. A private
key can also be loaded into RAM. Both choices need protection from firmware
readout, debug access, and memory disclosure.

### PSA secure storage

Zephyr 4.4.2 provides a PSA Secure Storage implementation for boards with
non-volatile memory. The documentation calls its main goal functional support.
It does not promise secure data at rest on every board. It also says that the
stored data is not protected from direct software or debugger access at
runtime, and is not protected from replay without hardware support. [Z13]

The default AEAD key provider hashes the device ID when an HWINFO driver is
present. The Kconfig text warns that this may be readable, non-unique, or
guessable. On ESP32-C6, Zephyr's HWINFO device ID is read from MAC-address eFuse
registers. A MAC address is an identifier, not a secret. [Z13] [Z14]

This means that default Zephyr secure storage on this board should not be
treated as a hardware-backed secret store. It can provide encrypted and
authenticated records against simple off-chip inspection. It does not provide
a strong device secret by default.

A stronger design needs a custom secure-storage key provider. That provider
could use a device-specific secret provisioned into protected hardware.
Upstream Zephyr does not provide the needed ESP32-C6 HMAC or RSA_DS integration,
so this remains custom work. [Z10] [Z13]

### Firmware update APIs

Zephyr's DFU subsystem provides a flash image API for writing an image to flash.
Its MCUboot API can inspect image state and request the next boot action. The
main calls include:

- `boot_request_upgrade(BOOT_UPGRADE_TEST)` for a trial update.
- `boot_write_img_confirmed()` after health checks pass.
- `mcuboot_swap_type()` to inspect the next boot action.
- `boot_erase_img_bank()` to erase an image bank.

[Z15]

These APIs do not authenticate a network download. The application must use an
authenticated transport such as TLS, write only to the intended slot, verify
download metadata as needed, and let MCUboot perform final image
authentication before execution.

### Security maintenance

Zephyr 4.4.0 is the latest stable release line on the research date. Zephyr
4.4.2 is its current maintenance tag. Zephyr 3.7 is the current LTS and is
supported until 2029. The project backports security fixes to the current LTS
and the two most recent releases. [Z1] [Z16] [Z18]

The latest LTS is not automatically the best ESP32-C6 security baseline.
ESP32-C6 PMP support arrived after Zephyr 4.3 and is present in 4.4. Espressif
also recommends following a recent upstream commit during development because
its Zephyr support changes quickly. A product should pin a reviewed commit,
track Zephyr advisories, and plan regular upgrades. [E1] [Z7] [Z8]

## MCUboot security behavior

### Signature choices

MCUboot 2.4.0's Zephyr port supports these image authentication choices:

- RSA-2048 or RSA-3072.
- ECDSA-P256.
- Ed25519.
- No signature, with a hash check only.

The default in MCUboot itself is RSA. The ESP32-C6 Zephyr 4.4.2 board overrides
that default to no signature. [M4] [Z3]

RSA has the largest signatures and usually a larger code cost. ECDSA-P256 is a
common size-conscious choice. Ed25519 is also supported by MCUboot. The actual
choice must fit the bootloader partition and must be tested with the selected
crypto backend.

MCUboot 2.4.0 added ECDSA support through Mbed TLS in the Zephyr port. It also
supports TinyCrypt and PSA choices for some algorithms. Availability in Kconfig
does not prove that ESP32-C6 hardware acceleration is used. [M1] [M4]

### Primary-slot validation

`CONFIG_BOOT_VALIDATE_SLOT0` is enabled by default. It validates the primary
slot on every boot. This protects against changes to the stored image when a
real signature type is enabled. [M4]

`CONFIG_BOOT_VALIDATE_SLOT0_ONCE` caches the result after one validation.
MCUboot itself calls this less secure. It should not be used for a product that
must detect later flash modification. [M4]

If `BOOT_SIGNATURE_TYPE_NONE` is selected, primary-slot validation checks only
the hash. It does not authenticate the publisher. This is why the Zephyr 4.4.2
board default must be overridden. [M4] [Z3]

### Confirmation and revert

A test update is installed and booted once. The new application must mark
itself as working. If it does not, MCUboot reverts to the old image at the next
boot. This protects availability when a new image crashes before its health
checks pass. [M2] [Z15]

The application should confirm only after all required checks pass. Typical
checks include:

- The scheduler and watchdog work.
- Required storage can be read and written.
- The network can reach the update service.
- TLS server authentication succeeds.
- The application can load its long-term configuration.

A permanent update skips the automatic revert path. Use it only when another
recovery mechanism exists.

### Encrypted images

MCUboot encrypts the firmware payload with AES-CTR-128 or AES-CTR-256. It can
protect the per-image AES key with RSA-OAEP, AES-KW, ECIES-P256, or
ECIES-X25519. The image header and TLVs remain visible. The signature is over
the plaintext image. [M3]

Each encrypted image needs a unique random content key. During a swap, MCUboot
can save decrypted key material in swap metadata unless
`MCUBOOT_SWAP_SAVE_ENCTLV` is enabled. Enable this option when an attacker can
read the primary slot or scratch storage. [M3] [M4]

For ESP32-C6, both slots are in off-chip flash. Generic MCUboot image encryption
is therefore not a substitute for hardware flash encryption. It protects a
staged image, but the primary image is decrypted for execution. [M3] [M5]

### Security counters and anti-rollback

MCUboot has two different downgrade controls.

Software downgrade prevention compares image versions, or image security
counters in some swap modes. It compares the candidate with the current image.
MCUboot warns that software version checks protect against only some attacks.
For example, a debugger can write an older image. [M2] [M4]

Hardware rollback protection compares the signed image counter with a trusted,
non-volatile counter. The platform must implement
`boot_nv_security_counter_get()`, `boot_nv_security_counter_update()`, and the
related interface. The implementation must remain consistent across power
loss. It may use one-time-programmable fuses. [M2] [M9]

No Espressif implementation of this MCUboot hardware counter interface was
found in MCUboot 2.4.0 or current upstream source. The Espressif port documents
version and image-counter comparisons, but not an eFuse-backed monotonic
counter. Therefore, its documented downgrade prevention must be treated as a
software check. It is not established hardware anti-rollback.

ESP-IDF has its own eFuse secure-version anti-rollback flow. That separate
feature does not prove integration with MCUboot. A product must not claim
hardware anti-rollback until an ESP32-C6 backend is implemented and tested for
the exact MCUboot port.

### Key handling

Keep MCUboot private signing keys outside the device and outside normal
developer workstations. Use controlled signing, access logs, backup, rotation,
and incident procedures.

The verification public key is normally compiled into MCUboot. MCUboot has a
generic hardware-key option, but the Espressif port guide says its hardware key
storage is not supported. [M4] [M5]

Secure Boot v2 can store up to three trusted public-key digests in eFuse and
revoke them. Plan key rotation before burning unused digest slots or revocation
bits. Revocation is permanent. [E2]

Do not use MCUboot sample keys in a product. The Espressif guide explicitly
recommends generating a new signing key. [M5]

### Recovery

MCUboot has a serial recovery server that supports a small set of MCUmgr
commands, including image upload, image list, reset, and echo. Recovery entry
is port-specific. [M7]

The Espressif port documents GPIO-triggered recovery for ESP32-C6. It also
documents use of the chip's USB Serial/JTAG port. Its ESP32-C6 default
configuration includes the relevant options, but they are disabled by default.
[M5] [M6]

The Espressif port uploads recovery data to the primary slot. An interrupted
upload can leave the primary image unable to boot. With hardware flash
encryption enabled, progressive erase must be disabled. These details need
power-failure tests. [M5]

Standard Zephyr MCUboot also has generic serial recovery support. No official
ESP32-C6-specific test result was found for that path. Do not treat generic
documentation as board validation.

### Fault injection hardening

MCUboot provides four FIH profiles: off, low, medium, and high. The default is
off. Low adds a hardened failure loop and control-flow checks. Medium also
duplicates critical values. High also adds random delays and needs entropy.
[M4] [M8]

MCUboot warns that these software constructs are not guaranteed secure for all
compilers. No official ESP32-C6 fault-injection validation was found. FIH is
useful defense in depth. It is not a certification or proof of resistance.
[M8]

## Recommended practical baseline

### For a course or early prototype

Use Zephyr 4.4.2 with standard sysbuild and the exact HP-core board target.
Set the MCUboot signature explicitly. ECDSA-P256 is a reasonable first choice
when bootloader size matters. RSA is the upstream default and is also
reasonable if it fits.

Use:

- Signed application images.
- Primary-slot validation on every boot.
- Test updates.
- Application health checks before confirmation.
- TLS with server certificate validation.
- A protected development signing key.
- Open debug access and no permanent eFuse changes.

Do not call this a hardware-rooted secure boot system. The ROM is not yet
authenticating the standard Zephyr MCUboot image.

### For a production security experiment

Build MCUboot 2.4.0 through its Espressif port for ESP32-C6. Use a pinned,
documented HAL revision. Match the Zephyr partition map and bootloader RAM
layout. Enable Zephyr's flash-encryption compatibility option. Use RSA-3072 for
the documented ESP32-C6 ROM-to-MCUboot secure boot step. Select and test a
separate MCUboot application signature. [M5] [M6] [Z6]

First test with:

- Virtual eFuses.
- A dedicated disposable board.
- JTAG left available.
- UART download mode left available.
- `--after no_reset` during provisioning.
- Full flash erase before the first encrypted boot.
- Power cuts during download, swap, first boot, and confirmation.

Only move to physical eFuses after the exact release images, offsets, signing
keys, recovery method, and update agent have passed the full test plan.

### Before production

The following gaps must be closed:

1. Pin one Zephyr commit. Do not use an unrecorded moving branch.
2. Confirm that the unsigned ESP32 board default is removed or overridden.
3. Reproduce the complete boot chain on physical ESP32-C6-DevKitC hardware.
4. Confirm flash encryption across bootloader, primary, secondary, scratch, and
   product data partitions.
5. Test that old signed images are rejected under the intended threat model.
6. Decide whether software downgrade prevention is enough. If not, implement a
   reviewed eFuse-backed MCUboot security counter.
7. Add a secure-storage key provider based on a protected device secret, or do
   not store high-value long-term secrets with the default provider.
8. Verify entropy while radios are off and during early boot.
9. Test Zephyr userspace and memory domains on the real board.
10. Test the recovery path after a failed and interrupted update.
11. Measure bootloader size with Secure Boot v2, flash encryption, the selected
    MCUboot signature, serial recovery, logging, watchdog, and FIH.
12. Define a key rotation and key revocation procedure.
13. Disable debug and download paths only after recovery and manufacturing
    tests pass.

## What is not supported or not established upstream

- Standard Zephyr sysbuild does not build the MCUboot Espressif port. [Z5]
- Standard Zephyr sysbuild does not establish ESP Secure Boot v2 or hardware
  flash encryption. [E1]
- Zephyr 4.4.2 defaults ESP32-C6 MCUboot to no signature unless the product
  overrides it. [Z3]
- The upstream fix for that unsigned default is later than the v4.4.2 tag. [Z4]
- MCUboot's Espressif port does not document hardware storage for its
  application verification key. [M5]
- No ESP32-C6 MCUboot hardware security-counter backend was found. Hardware
  anti-rollback is therefore not established.
- Zephyr 4.4.2 does not expose the ESP32-C6 HMAC and RSA Digital Signature
  features through its normal Espressif crypto build. [Z10]
- The default Zephyr secure-storage key provider is derived from a public
  device identifier, not from a protected hardware secret. [Z13] [Z14]
- The persistent TLS credential backend depends on TF-M, which is not the
  security environment used by this RISC-V board. [Z12]
- ESP32-C6 PMP support is new in Zephyr 4.4 and is absent in 4.3. [Z7] [Z8]
- No official physical-board result was found for the complete Zephyr
  userspace test suite on this target.
- No official end-to-end result was found for the complete hardware-rooted
  chain described in this report.
- No official size matrix was found for every combination of ESP Secure Boot,
  flash encryption, MCUboot signature algorithm, recovery, and FIH.

## Irreversible-operation checklist

Before any physical eFuse burn:

1. Read and save the full eFuse summary.
2. Confirm the exact chip target is ESP32-C6.
3. Confirm the flash size and every partition offset.
4. Confirm the bootloader binary and its ROM signature.
5. Confirm the MCUboot application public key.
6. Confirm the private keys are backed up and access-controlled.
7. Confirm the application image is signed and fits the slot.
8. Confirm the update agent is present and can write encrypted flash.
9. Confirm at least one tested recovery path remains.
10. Use a stable power supply.
11. Flash with no automatic reset.
12. Review the planned eFuse batch before burning.
13. Burn a disposable board first.
14. Read back all non-secret eFuse state.
15. Boot and run update, revert, confirmation, and recovery tests.

Do not use a physical key-burning command while assuming virtual eFuses will
intercept it. The MCUboot Espressif guide says that this command can still burn
the real device. [M5]

## Conclusion

ESP32-C6 can support a strong chain with ROM secure boot, an authenticated
MCUboot bootloader, authenticated Zephyr updates, and hardware flash
encryption. The chip also has protected HMAC and RSA signing features.

The normal Zephyr 4.4.2 build does not assemble that full chain. It uses the
MCUboot Zephyr port, not the Espressif port. It also defaults this board to
unsigned MCUboot images. The safe conclusion is:

1. Standard Zephyr sysbuild is useful for signed update experiments after the
   signature setting is fixed.
2. A production hardware root of trust needs the separate MCUboot Espressif
   port and careful manual integration.
3. Hardware anti-rollback and hardware-backed application credential storage
   are not established in the upstream combination.
4. Every permanent eFuse action must follow successful physical-board testing.

## Sources

All sources below are primary, official project sources. They were accessed on
2026-09-11.

### Espressif sources

| ID | Version | Source |
| --- | --- | --- |
| E1 | Current page | [Espressif Zephyr support status](https://developer.espressif.com/software/zephyr-support-status/) |
| E2 | ESP-IDF 6.1 | [ESP32-C6 Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/security/secure-boot-v2.html) |
| E3 | ESP-IDF 6.1 | [ESP32-C6 flash encryption](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/security/flash-encryption.html) |
| E4 | ESP-IDF 6.1 | [ESP32-C6 eFuse Manager](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/api-reference/system/efuse.html) |
| E5 | ESP-IDF 6.1 | [ESP32-C6 HMAC](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/api-reference/peripherals/hmac.html) |
| E6 | ESP-IDF 6.1 | [ESP32-C6 RSA Digital Signature peripheral](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/api-reference/peripherals/ds.html) |
| E7 | ESP-IDF 6.1 | [ESP32-C6 random number generation](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/api-reference/system/random.html) |
| E8 | ESP-IDF 6.1 | [Security feature enablement workflows](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/security/security-features-enablement-workflows.html) |
| E9 | Current page | [espefuse for ESP32-C6](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/espefuse/index.html) |
| E10 | ESP-IDF 6.1 | [ESP32-C6 security overview](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/security/security.html) |

### Zephyr sources

| ID | Version | Source |
| --- | --- | --- |
| Z1 | 4.4.2 docs | [Supported releases and maintenance policy](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/doc/releases/index.rst) |
| Z2 | 4.4.2 | [ESP32-C6-DevKitC board documentation](https://docs.zephyrproject.org/4.4.2/boards/espressif/esp32c6_devkitc/doc/index.html) |
| Z3 | 4.4.2 | [ESP32-C6 sysbuild defaults](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/boards/espressif/esp32c6_devkitc/Kconfig.sysbuild) |
| Z4 | Post-4.4.2 main | [Remove unsigned MCUboot default from Espressif boards](https://github.com/zephyrproject-rtos/zephyr/commit/bb6b6ff6c8236bce5cc786617079e82f9d455b33) |
| Z5 | 4.4.2 | [Zephyr sysbuild MCUboot source selection](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/share/sysbuild/images/bootloader/CMakeLists.txt) |
| Z6 | 4.4.2 | [Espressif flash compatibility Kconfig](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/soc/espressif/common/Kconfig.flash#L133-L143) |
| Z7 | 4.4.2 | [ESP32-C6 PMP selection](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/soc/espressif/esp32c6/Kconfig) and [PMP regions](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/soc/espressif/esp32c6/pmp_regions.c) |
| Z8 | 4.3.0 | [ESP32-C6 SoC Kconfig before PMP support](https://github.com/zephyrproject-rtos/zephyr/blob/v4.3.0/soc/espressif/esp32c6/Kconfig) |
| Z9 | 4.4.2 | [ESP32 entropy driver warning](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/drivers/entropy/Kconfig.esp32) |
| Z10 | 4.4.2 manifest revision | [Pinned Espressif HAL crypto build](https://github.com/zephyrproject-rtos/hal_espressif/blob/f07465053c0f24aa254d9fdfd559f06879221073/zephyr/CMakeLists.txt#L36-L40) |
| Z11 | 4.4.2 | [TLS socket Kconfig](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/subsys/net/lib/sockets/Kconfig#L115-L126) |
| Z12 | 4.4.2 | [TLS credential backend Kconfig](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/subsys/net/lib/tls_credentials/Kconfig) and [credential API](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/include/zephyr/net/tls_credentials.h) |
| Z13 | 4.4.2 | [Zephyr secure storage](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/doc/services/storage/secure_storage/index.rst) and [default AEAD key providers](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/subsys/secure_storage/Kconfig.its_transform#L61-L95) |
| Z14 | 4.4.2 | [ESP32 HWINFO device ID source](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/drivers/hwinfo/hwinfo_esp32.c#L16-L55) |
| Z15 | 4.4.2 | [Zephyr DFU overview](https://docs.zephyrproject.org/4.4.2/services/device_mgmt/dfu.html) and [MCUboot application API](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/include/zephyr/dfu/mcuboot.h) |
| Z16 | Current policy | [Zephyr security vulnerability reporting and backports](https://docs.zephyrproject.org/latest/security/reporting.html) |
| Z17 | 4.4.2 | [ESP32-C6 board DTS](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/boards/espressif/esp32c6_devkitc/esp32c6_devkitc_hpcore.dts), [board module choice](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/boards/espressif/esp32c6_devkitc/Kconfig.esp32c6_devkitc), and [default 4 MiB partitions](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/dts/vendor/espressif/partitions_0x0_default_4M.dtsi) |
| Z18 | 4.4.2 | [Zephyr 4.4.2 release notes](https://docs.zephyrproject.org/4.4.2/releases/release-notes-4.4.html) |
| Z19 | 4.4.2 | [Zephyr user mode](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/doc/kernel/usermode/index.rst) |

### MCUboot sources

| ID | Version | Source |
| --- | --- | --- |
| M1 | 2.4.0 | [MCUboot release notes](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/release-notes.md) |
| M2 | 2.4.0 | [MCUboot design](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/design.md) |
| M3 | 2.4.0 | [MCUboot encrypted images](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/encrypted_images.md) |
| M4 | 2.4.0 | [MCUboot Zephyr Kconfig](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/boot/zephyr/Kconfig) |
| M5 | 2.4.0 | [MCUboot Espressif port guide](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/readme-espressif.md) |
| M6 | 2.4.0 | [ESP32-C6 Espressif-port defaults](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/boot/espressif/port/esp32c6/bootloader.conf) |
| M7 | 2.4.0 | [MCUboot serial recovery](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/serial_recovery.md) |
| M8 | 2.4.0 | [MCUboot fault injection hardening](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/boot/bootutil/include/bootutil/fault_injection_hardening.h) |
| M9 | 2.4.0 | [MCUboot security counter interface](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/boot/bootutil/include/bootutil/security_cnt.h) |

## Research uncertainties

1. MCUboot 2.4.0 says its compatible ESP-IDF HAL is v5.1.6. The current rendered
   MCUboot page says v6.0.0 near the top but still contains a command that
   checks out v5.1.6. Use the tagged 2.4.0 source for a reproducible build, and
   resolve this version mismatch before using a newer untagged MCUboot commit.
2. The Zephyr `main` fix for unsigned Espressif MCUboot defaults exists, but a
   future maintenance-release backport was not established.
3. Official documents describe the manual Espressif-port path, but no official
   test report was found for the complete ESP32-C6, Zephyr 4.4.2, MCUboot 2.4.0
   chain with all permanent security settings enabled.
4. No official result was found for full Zephyr userspace validation on the
   physical ESP32-C6-DevKitC.
5. Actual bootloader size depends on the chosen signature backend, logging,
   recovery, watchdog, flash encryption, secure boot, and FIH settings. It must
   be measured from the final build.
