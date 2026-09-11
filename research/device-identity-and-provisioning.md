# Device identity and provisioning patterns

This report answers GitHub issue #6: which factory and first-boot
provisioning patterns are practical for the course hardware (ESP32-C6,
ESP-IDF, Zephyr, MCUboot) and for a small teaching environment.

All web sources in this report were accessed on **2026-09-11**. Product and
document versions are stated next to each claim where the source names one.
The main platform versions used as the baseline for this report are:

- ESP-IDF stable release: **v6.1** (docs path `esp32c6`, `stable`)
- Espressif Network Provisioning component: **v1.2.4**
- Zephyr latest release: **v4.4.2**
- MCUboot latest tagged release: **v2.4.0** (the MCUboot Espressif port
  documentation on the `main` branch lists ESP-IDF `v6.0.0` and Mbed TLS
  `3.6.0` as its tested pairing, which is slightly behind ESP-IDF `v6.1`;
  a course lab should pin exact versions and test them together)

## Short answer

Use shared credentials only for early development. Do not use them as a
device identity in production.

For a small production system, give each device its own asymmetric identity.
Offline factory injection is the simplest method for a small batch. On-device
key generation gives better private-key control, but it needs an enrollment
service. Protect RSA identity keys with the ESP32-C6 DS peripheral. Protect
other stored secrets with flash encryption and NVS encryption.

Use a short-lived bootstrap credential for first boot. Require a unique
proof-of-possession code when the owner claims the device. Replace the
bootstrap credential with a per-device, owner-scoped credential. Keep the
factory identity separate so ownership can change without erasing the
device's manufacturing history.

Plan key changes before shipping. Preload more than one ESP Secure Boot
digest when rotation is required. Build MCUboot with old and new verification
keys during its transition. Treat flash encryption keys and eFuse locks as
one-way choices. Teach them first with virtual eFuses and disposable boards.

## Terms used in this report

**Provisioning**:
The process of giving a device the data and keys it needs to run safely and
to prove who it is. This report splits provisioning into two moments:
factory provisioning (done by the maker, before the device ships) and
first-boot provisioning (done the first time the device powers on for its
owner).

**eFuse**:
A microscopic one-time-programmable bit inside the chip. Once a bit is
burned from 0 to 1, it cannot be reverted. ESP32-C6 uses eFuse bits to store
keys and to lock security settings
([Espressif, eFuse Manager](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html)).

**Secure Boot**:
A boot process that only runs software signed with a trusted key. On
ESP32-C6 this is called Secure Boot v2
([Espressif, Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/secure-boot-v2.html)).

**Flash encryption**:
A feature that encrypts the content of the external flash chip, so reading
the flash chip does not reveal the firmware or stored secrets in plain text
([Espressif, Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/flash-encryption.html)).

**Asymmetric identity**:
A key pair made of a private key and a public key. The private key stays
secret on the device. The public key, often inside a certificate, can be
shared freely to prove the device's identity.

**Certificate**:
A signed document that binds a public key to a name (for example, a device
serial number). An X.509 certificate is the most common format used on the
internet and in embedded devices.

**IDevID (Initial Device Identifier)**:
A certificate and private key installed by the manufacturer at the factory.
It never changes after manufacturing. It proves "this is the device the
factory made," defined by the IEEE 802.1AR standard
([IEEE 802.1 working group, 802.1AR summary](https://grouper.ieee.org/groups/802/1/pages/802.1ar.html)).

**LDevID (Locally significant Device Identifier)**:
A certificate issued later by the device's owner or operator, after the
device proves its IDevID. It can be replaced without touching the
manufacturer identity ([IEEE 802.1 working group, 802.1AR summary](https://grouper.ieee.org/groups/802/1/pages/802.1ar.html)).

**Claiming**:
The act of a specific owner taking control of a specific device, usually by
proving they physically hold it (for example, by reading a QR code) or by
presenting a one-time bootstrap credential.

**Proof of possession**:
A value that shows the claimant can access the physical device or its
packaging. Examples include a one-time code or a secret in a QR code.

**Bootstrap credential**:
A temporary or shared credential used only to get a device started, which is
later exchanged for a permanent, per-device credential.

**Manufacturing record**:
A row of data, kept by the factory or the course, that links one physical
device (by serial number) to the keys, certificates, and settings it
received during provisioning.

## The two moments of provisioning

A device lifecycle has two provisioning moments that need different
treatment:

1. **Factory provisioning.** This happens once, on a production line or a
   lab bench, before the device is given to a learner or a customer. It can
   use special tools, a trusted network, and physical access that will not
   be available later.
2. **First-boot provisioning.** This happens once per device, the first time
   it is powered on by its final owner. The device is now outside the
   factory's trust boundary. It must prove its own identity, and it must
   receive the credentials it needs to reach its owner's network or cloud
   service safely.

Espressif's own security documentation frames this as a step-by-step
workflow: build signed and/or encrypted images, generate or import keys,
burn the matching eFuses, then flash the device, in that order
([Espressif, Security Features Enablement Workflows](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/security-features-enablement-workflows.html)).
The order matters. Some eFuse bits, once burned, forbid later steps (for
example, burning the flash encryption bits in release mode blocks plaintext
firmware updates over the serial port from then on)
([Espressif, Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/flash-encryption.html)).

## Identity and credential patterns compared

This section compares the patterns named in issue #6. For each pattern:
what it is, where it fits, and its main weakness.

### Shared development credentials

**What it is.** Every device in a batch uses the same Wi-Fi password,
the same MQTT username and password, or the same TLS certificate. This is
the fastest way to get many devices talking to a test server.

**Where it fits.** Early development, and a first "hello world" lab, where
the goal is to prove the wiring and the network path work at all.

**Main weakness.** One leaked credential compromises every device that
shares it. There is no way to tell which physical device sent a message,
and there is no way to revoke one device without revoking all of them.
Espressif's own guidance is explicit that flash encryption should be
enabled in release mode only for production, precisely because development
mode allows the same plaintext firmware (and any credentials baked into it)
to be read back out
([Espressif, Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/flash-encryption.html)).

### Per-device asymmetric identity

**What it is.** Each device gets its own private/public key pair. The
private key never leaves the device. The device proves who it is by
signing something with its private key; anyone can check the signature
with the matching public key.

**Where it fits.** Any product that must tell individual devices apart, for
example for TLS client authentication, for per-device access control, or
for audit logs that must name the exact device.

**How ESP32-C6 supports it.** ESP32-C6 has a Digital Signature (RSA_DS)
peripheral. The device's private RSA key parameters are AES-encrypted and
stored in flash; the AES key used to decrypt them is derived, inside
hardware, from an eFuse-stored key using the HMAC peripheral. Neither the
decryption key nor the plaintext private key parameters are ever visible to
software while a signature is calculated
([Espressif, RSA Digital Signature Peripheral](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/peripherals/ds.html)).
The `esp_secure_cert_mgr` component reads a dedicated `esp_secure_cert`
flash partition that holds the device certificate, the issuing CA
certificate, and this encrypted private key material, and the
`configure_esp_secure_cert.py` host tool builds that partition image
([Espressif, esp_secure_cert_mgr README](https://github.com/espressif/esp_secure_cert_mgr/blob/main/README.md)).

**Main weakness.** More setup work than a shared credential. Someone must
run a key-generation and signing pipeline for every device, and must keep a
manufacturing record connecting each device to its key material.

### Certificate enrollment

**What it is.** Instead of pre-loading a finished certificate, the device
generates its own key pair (or uses one already provisioned) and asks a
Certificate Authority (CA) to issue it a certificate. Two standard protocols
matter here:

- **EST (Enrollment over Secure Transport)**, RFC 7030, a simple HTTPS-based
  protocol for a device to request a certificate from a CA, including
  support for a device generating its own key pair
  ([IETF, RFC 7030](https://www.rfc-editor.org/rfc/rfc7030.html)).
- **BRSKI (Bootstrapping Remote Secure Key Infrastructure)**, RFC 8995,
  which layers automatic, zero-touch network enrollment on top of an
  IEEE 802.1AR IDevID. It uses a Manufacturer Authorized Signing Authority
  (MASA) to issue a signed "voucher" that lets a new owner's network trust
  the device
  ([IETF, RFC 8995](https://www.rfc-editor.org/rfc/rfc8995.html)).

**Where it fits.** Products with a real Certificate Authority and a fleet
management backend. This is heavier than a small teaching lab needs on day
one, but the underlying idea (the device proves an IDevID, then receives an
LDevID scoped to one owner) is a useful mental model even when the course
uses a simplified stand-in.

**Main weakness.** Needs infrastructure: a CA, an enrollment server, and (for
BRSKI) a manufacturer voucher service. Espressif's own quick-start tools
(described below) do not implement EST or BRSKI directly.

### Offline factory injection

**What it is.** Per-device secrets and certificates are generated on a
secure host computer, outside the target device, and then written into
flash at manufacturing time. The device never generates its own keys.

**How ESP-IDF supports it.**

- The **Manufacturing Utility** (`mfg_gen.py`) turns a CSV file of per-device
  values (serial numbers, MAC addresses, keys) into one NVS (Non-Volatile
  Storage) partition binary image per device, which is then flashed at the
  factory offset with `esptool`
  ([Espressif, Manufacturing Utility](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/mass_mfg.html)).
- The **`esp_secure_cert` partition** and its `configure_esp_secure_cert.py`
  tool do the same for PKI (Public Key Infrastructure) material: a device
  certificate, a CA certificate, and an encrypted private key, optionally
  bound to the DS peripheral
  ([Espressif, esp_secure_cert_mgr README](https://github.com/espressif/esp_secure_cert_mgr/blob/main/README.md)).
- Espressif also runs a **Pre-Provisioning Service**: you can order modules
  that already contain an encrypted private key and matching certificate
  before they are shipped to you, so the "factory" step is done by
  Espressif itself
  ([Espressif, esp_secure_cert_mgr README](https://github.com/espressif/esp_secure_cert_mgr/blob/main/README.md)).

**Where it fits.** Small and medium batches, and any course lab that wants
a realistic factory step without building a full CA. It gives full control
over manufacturing records, because the CSV input file the tool consumes
already is a manufacturing record.

**Main weakness.** The private key exists, briefly, on a host computer or a
provisioning fixture, before it is written to the device. That host and
that process must be trusted and protected.

### On-device key generation

**What it is.** The device itself generates its own key pair the first time
it boots, using its own random number generator. The private key is never
seen outside the device, not even by a factory tool.

**Where it fits.** Reduces the trust needed in the factory process, because
no outside computer ever holds the private key. Works well when the device
then enrolls its self-generated public key with a CA (see certificate
enrollment above), or when it only needs a local, self-signed identity for
device-to-device pairing.

**Main weakness.** Needs a good hardware random number source. It also needs
an enrollment step afterward, because a self-generated key is not yet trusted
by anyone. ESP32-C6's own flash encryption feature already uses this
pattern internally: if no key is present in eFuse, the second-stage
bootloader generates a 256-bit key using its RNG module and burns it into
`BLOCK_KEYN` on the very first boot, and this key can never be read back
by software afterward
([Espressif, Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/flash-encryption.html)).

### Bootstrap credentials and field claiming

**What it is.** The device ships with a limited-purpose credential that can
only be used once, or only used to ask for a real credential. A concrete,
well-documented first-party example is AWS IoT **fleet provisioning by
claim**: every device in a batch shares one "provisioning claim"
certificate and private key, restricted by policy to only being able to
request a brand-new, unique certificate. On first connection, the device
uses the shared claim credential to request its own permanent certificate,
which it then uses for all normal operation afterward
([AWS, Provisioning devices that don't have device certificates](https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html)).
AWS IoT also supports **just-in-time provisioning (JITP)**: a device
already carries a unique certificate signed by a CA that AWS IoT trusts, and
the device is registered automatically, using a template, the first time it
connects
([AWS, Just-in-time provisioning](https://docs.aws.amazon.com/iot/latest/developerguide/jit-provisioning.html)).

**How ESP-IDF supports the network setup part of field provisioning.**
ESP-IDF v6.0 removed the old `wifi_provisioning` component. Espressif now
ships it as the separate `network_provisioning` component. Version 1.2.4
supports Wi-Fi setup over BLE or SoftAP (a Wi-Fi access point created by the
device). It uses secure Protocol Communication sessions
([Espressif, ESP-IDF v6.0 provisioning migration guide](https://github.com/espressif/esp-idf/blob/v6.1/docs/en/migration-guides/release-6.x/6.0/provisioning.rst);
[Espressif, Network Provisioning component](https://github.com/espressif/idf-extra-components/tree/master/network_provisioning)).

BLE range or access to the SoftAP does not prove ownership by itself. A real
claim flow should also require a unique proof of possession. This can be a
one-time code or secret printed on the device label or in a QR code. After a
successful claim, the service should mark that secret as used and give the
device a new per-device credential.

**Where it fits.** Any product sold to end users who are not the same
people who ran the factory line. This is the normal pattern for consumer
IoT and is directly reusable in a course: the shared "claim" credential
models a classroom set of pre-flashed devices, and the exchange for a
per-device credential models what a learner should implement.

**Main weakness.** The shared claim credential is still a shared secret
until it is used. AWS's own guidance says explicitly: "Provisioning claim
private keys should be secured at all times, including on the device," and
recommends monitoring for misuse and disabling a claim certificate if
misuse is seen
([AWS, Provisioning devices that don't have device certificates](https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html)).

### Ownership transfer

**What it is.** Moving a device from one owner's trust domain to another
(for example, factory to distributor, distributor to end customer, or
customer to a second-hand buyer) without giving the new owner the old
owner's full backend access.

**Standardized approach.** The **FIDO Device Onboard (FDO)** specification
from the FIDO Alliance defines an **Ownership Voucher**: a signed data
structure that records the chain of custody of a device, so that each new
owner can prove they are the current rightful owner before the device
onboards to their platform. FDO 1.1 is the current Proposed Standard
version; FDO 2.0 is a public working draft as of 17 June 2025
([FIDO Alliance, FIDO Device Onboard specifications](https://fidoalliance.org/specifications/download-iot-specifications/)).
BRSKI (RFC 8995) has a related idea: the manufacturer's MASA service can
issue a "nonceless" voucher for disaster-recovery cases, but the RFC itself
warns this creates a risk, because a previous domain's registrar could
reuse an old nonceless voucher to reclaim a device it no longer owns; RFC
8995 mitigates this by logging voucher issuance and only allowing
bootstrapping while a device is in its factory-default state
([IETF, RFC 8995, section 11.1](https://www.rfc-editor.org/rfc/rfc8995.html)).

**Where it fits.** Fleet management at scale. For a small teaching
environment, full FDO or BRSKI is likely too heavy, but the underlying
lesson is directly teachable: an ownership change should be an explicit,
auditable event, not just "whoever has the Wi-Fi password."

For a small lab, ownership transfer can use a simpler flow:

1. The old owner asks the service to release the device.
2. The service revokes the old owner's device certificate or access record.
3. A physical reset puts the device into a short claim window.
4. The new owner presents a one-time proof from the device label or screen.
5. The device generates or receives a new owner credential.
6. The service records both the release and the new claim.

The factory identity can stay unchanged. The owner identity must change.
Recovery must not silently restore the previous owner's access.

## eFuse and irreversible actions on ESP32-C6

ESP32-C6 has 11 eFuse blocks of 256 bits each. Blocks 0 to 2 and block 10
are reserved for system parameters. Block 3 is free for user data. Blocks 4
to 8 (`KEY0` to `KEY4`) hold Secure Boot or flash encryption keys, and block
9 (`KEY5`) can hold any key except a flash encryption key, due to a hardware
errata
([Espressif, eFuse Manager](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html)).

Every eFuse bit can only move from 0 to 1. It can never be reset to 0
([Espressif, eFuse Manager](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html)).
This is what makes the following actions irreversible in practice, even
though the chip itself has no explicit "point of no return" warning built
into the tools:

- **Enabling Secure Boot v2** burns a public key digest into an eFuse key
  block and sets the `SECURE_BOOT_EN` bit. Up to three key digests can be
  stored. Once a key is marked revoked with `KEY_REVOKEX`, that revocation
  cannot be undone
  ([Espressif, Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/secure-boot-v2.html)).
- **Enabling flash encryption in release mode** write-protects the
  `SPI_BOOT_CRYPT_CNT` eFuse bits and sets `DIS_DOWNLOAD_MANUAL_ENCRYPT`,
  which permanently removes the ability to flash new plaintext firmware over
  the serial download port
  ([Espressif, Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/flash-encryption.html)).
- **Disabling the UART ROM download mode** (an option offered directly in
  the Secure Boot v2 menu) can be set to "Permanently disabled" for
  production devices, which is described as the most secure option
  ([Espressif, Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/secure-boot-v2.html)).

There is no Espressif-provided way to undo any of these once burned. A
mistake in key material, key order, or mode selection at this stage is
permanent for that physical chip.

### Teaching irreversible actions safely

ESP-IDF ships a **virtual eFuse mode**, enabled with the Kconfig option
`CONFIG_EFUSE_VIRTUAL`. In this mode, eFuse Manager reads and writes made by
the firmware use a RAM copy. No real eFuse bit is changed. Adding
`CONFIG_EFUSE_VIRTUAL_KEEP_IN_FLASH` keeps the simulated values in a
dedicated flash partition, so the simulated state survives a reset, which
lets a lab exercise "burn" a virtual key, reboot, and see the effect
persist, all without any risk to real hardware
([Espressif, eFuse Manager](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html);
example usage pattern shown in Espressif's `examples/system/efuse` sample).

Virtual mode does not make the host-side `espefuse` tool safe. That tool can
still address real eFuses. Learners should not run eFuse write commands
against normal lab boards. Virtual flash encryption also does not prove that
the hardware encrypted the flash. Espressif states that virtual mode may only
simulate the state and log messages when hardware flash encryption is not
enabled
([Espressif, eFuse Manager](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html)).

For a teaching environment, this suggests a clear, safe progression:

1. Run every eFuse-burning exercise first in virtual mode, so the learner
   sees the eFuse name and the software-visible state change with zero risk.
   Use firmware APIs or a lab wrapper. Do not copy a real `espefuse` write
   command into this step.
2. Only after that, if the course owns sacrificial hardware set aside for
   this purpose, allow one supervised real burn on a labelled "burn
   allowed" board, never on a board that must be reused for other labs.
3. Record the board serial number, planned eFuse values, and expected result.
   A mentor should compare the plan with an eFuse summary before the burn.
4. Follow the course-writing convention already in this repository: explain
   a destructive or irreversible action before showing the command that
   performs it (see `docs/agents/course-writing.md`), and name the exact
   eFuse bits that will change.

## MCUboot: signing keys, rotation, and revocation

MCUboot signs firmware images and checks that signature before booting them.
`imgtool.py`, MCUboot's own key and signing tool, supports `rsa-2048`,
`rsa-3072`, `ecdsa-p256`, and `ed25519` key types
([MCUboot, imgtool.md](https://github.com/mcu-tools/mcuboot/blob/main/docs/imgtool.md)).
A private signing key is generated once with `imgtool keygen` and must be
kept secret; MCUboot ships a well-known development key for testing only,
which the documentation explicitly says "should never be used for
production"
([MCUboot, imgtool.md](https://github.com/mcu-tools/mcuboot/blob/main/docs/imgtool.md)).

**Key rotation.** MCUboot can embed more than one public key in the
bootloader at build time. In Zephyr, this is done through
`SB_CONFIG_BOOT_SIGNATURE_KEY_FILE`, which accepts a comma-separated list
of key files: the first entry signs the image, and every later entry must
be a public-only key of the same type, used only to verify. This lets a
team ship a bootloader that trusts both an old and a new signing key at the
same time, so devices can move to a new signing key over a series of
updates without becoming unbootable
([Zephyr Project, Signing Binaries](https://docs.zephyrproject.org/latest/build/signing/index.html)).

**Downgrade prevention.** Firmware images can carry a **security counter**,
a value separate from the human-readable version number, embedded as an
`IMAGE_TLV_SEC_CNT` field in the signed image
([MCUboot, design.md](https://github.com/mcu-tools/mcuboot/blob/main/docs/design.md)).
MCUboot can be configured to refuse any image whose security counter is
lower than the one already installed, which blocks downgrade attacks even
if an attacker resets or fakes the version number.

**Revocation is limited, by design.** MCUboot's normal model has no
built-in mechanism to revoke one compromised signing key while a device is
already in the field, beyond the multi-key list described above (which
requires a bootloader update first) and beyond the security counter (which
blocks downgrade, not a still-current key). A community proposal for
"decentralized key revocation," where a device automatically distrusts an
older key once it has confirmed booting an image signed by a newer one, was
under discussion as an MCUboot GitHub issue as of this report's access date
and had not shipped as a released feature
([MCUboot GitHub issue #2857, "RFC: Decentralized key revocation for MCUboot"](https://github.com/mcu-tools/mcuboot/issues/2857)).
A course should therefore teach key rotation and the security counter as
the currently-available tools, and describe key revocation as a
forward-looking, not-yet-standard capability.

**ESP32-C6 and MCUboot together.** The MCUboot Espressif port can use
ESP-IDF as its Hardware Abstraction Layer. As of this report's access date,
the `main` branch documentation names ESP-IDF `v6.0.0` as the tested HAL
version, one minor release behind the ESP-IDF `v6.1` stable release used
elsewhere in this report
([MCUboot, readme-espressif.md](https://github.com/mcu-tools/mcuboot/blob/main/docs/readme-espressif.md)).
A course repository should pin and test one specific combination rather
than assuming the newest release of each project works together.

## Zephyr: secure storage, settings, and a caveat for ESP32-C6

Zephyr provides two related but different storage subsystems:

- The **Settings subsystem** stores ordinary key-value configuration (for
  example, a device name or a calibration value) in plain form, in one of
  several backends (NVS, ZMS, a flash circular buffer, or a file system)
  ([Zephyr Project, Settings](https://docs.zephyrproject.org/latest/services/storage/settings/index.html)).
  This is the right place for data that is useful but not secret.
- The **Secure Storage subsystem** implements the Arm PSA (Platform
  Security Architecture) Secure Storage API and is meant for secrets. By
  default it encrypts and authenticates data at rest, using a key derived
  through `CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_PROVIDER`
  ([Zephyr Project, Secure Storage](https://docs.zephyrproject.org/latest/services/storage/secure_storage/index.html)).

**Caveat for this course's hardware.** Zephyr states that Secure Storage
depends on device-specific security features and a secure encryption key
provider
([Zephyr Project, Secure Storage](https://docs.zephyrproject.org/latest/services/storage/secure_storage/index.html)).
The generic default provider hashes a device ID and the entry number. Its
Kconfig text says that the device ID may be readable, repeated, or easy to
guess. The fallback that hashes only the entry number is marked "not secure"
([Zephyr Project, Secure Storage key-provider Kconfig](https://github.com/zephyrproject-rtos/zephyr/blob/main/subsys/secure_storage/Kconfig.its_transform)).

For ESP32-C6, do not treat that generic default as a hardware secret. A
production design must add a custom provider backed by protected hardware,
or use ESP-IDF's flash encryption, eFuse-backed HMAC keys, NVS encryption,
and DS peripheral. Zephyr Settings remains suitable for non-secret
configuration.

ESP-IDF also provides NVS encryption. It encrypts NVS entries with XTS-AES.
The NVS keys can be protected by flash encryption or by a Hash-based Message
Authentication Code (HMAC) key stored in eFuse. Espressif recommends NVS
encryption when flash encryption is enabled
because the Wi-Fi driver stores the SSID and passphrase in the default NVS
partition
([Espressif, NVS Encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/nvs_encryption.html)).
This is a practical store for Wi-Fi credentials and small application
secrets. The DS peripheral remains the stronger choice for an RSA device
private key because normal software never receives that key in plain form.

## Key rotation and recovery: general guidance

**NIST SP 800-57 Part 1** is the standard reference for how long a
cryptographic key should stay in use (its "cryptoperiod") and for planning
key transitions before a key is suspected of compromise, not only after
([NIST, SP 800-57 Part 1 Revision 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)).
Applied to this course's stack:

- A **firmware signing key** (used by MCUboot / `imgtool`) should be
  planned for rotation on a fixed schedule, using the multi-key mechanism
  described above, so a new key can be introduced before the old one is
  ever suspected of leaking.
- A **per-device identity key** (used for TLS client authentication) is
  usually not rotated in the same way. Because it is bound to that one
  physical device's certificate, "rotation" for a device identity normally
  means re-enrollment: the device gets a new certificate for the same key,
  or a new key and certificate together, through the same enrollment path
  it used the first time (see certificate enrollment, above).
- An **ESP Secure Boot signing key** can be rotated only if the device was
  prepared for it. ESP32-C6 can store up to three public key digests. A new
  image can move to another prepared key. The old digest can then be revoked.
  Revocation is permanent
  ([Espressif, Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/secure-boot-v2.html)).
- A **flash encryption key** cannot be rotated on that physical chip after
  its eFuse key block is read-protected. A failed key or configuration may
  require replacing the device.

**Recovery** after a lost or leaked credential differs sharply by layer:

- A **shared network or cloud credential** can be revoked and reissued
  centrally, with no hardware impact, which is one real advantage of
  bootstrap-credential patterns over baking permanent secrets in at the
  factory.
- A **per-device certificate** can be revoked at the CA and reissued
  through the same enrollment path used originally.
- A **flash encryption key** burned into a read-protected eFuse block has no
  software recovery path. A Secure Boot key has a recovery path only when a
  second trusted digest was provisioned before the active key was lost or
  revoked. Espressif frames these settings as choices to test thoroughly in
  development mode because release-mode changes cannot be undone
  ([Espressif, Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/flash-encryption.html)).

## Manufacturing records

A manufacturing record is only useful if it links a physical device to
exactly the keys and certificates that were put on it. The tools already
described in this report double as the source of that record:

- The **Manufacturing Utility**'s master value CSV file is, by definition,
  a manufacturing record: one row per device, with a serial number and
  whatever other per-device keys or values were flashed
  ([Espressif, Manufacturing Utility](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/mass_mfg.html)).
- The `esp_secure_cert` partition tooling, run once per device, is the
  natural point to also log the device's certificate serial number and
  public key fingerprint against its hardware serial number
  ([Espressif, esp_secure_cert_mgr README](https://github.com/espressif/esp_secure_cert_mgr/blob/main/README.md)).
- AWS IoT fleet provisioning by claim keeps its own record automatically:
  every device that provisions itself calls `RegisterThing`, which is
  logged, and provisioning successes and errors are exposed as Amazon
  CloudWatch metrics
  ([AWS, Just-in-time provisioning](https://docs.aws.amazon.com/iot/latest/developerguide/jit-provisioning.html)).

For a small teaching environment, the practical minimum manufacturing
record is a single spreadsheet or CSV file, per teaching cohort or per lab
kit, with one row per device holding: board serial number or MAC address,
the Secure Boot key identifier used (if any), the flash encryption status,
the device certificate serial number (if any), and the date it was
provisioned. Keep the real inventory in access-controlled storage. The public
course repository should contain only the schema and a synthetic example.
Private key material must stay out of both files.

## Development versus production practice: a summary table

| Concern | Development practice | Production practice |
| --- | --- | --- |
| Device credential | Shared credential is acceptable for early bring-up labs | Per-device asymmetric identity or a claim-and-exchange flow |
| Flash encryption | Development mode, so plaintext re-flash stays possible ([Espressif, Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/flash-encryption.html)) | Release mode only, which is irreversible on that chip |
| eFuse operations | Virtual mode (`CONFIG_EFUSE_VIRTUAL`) for every exercise | Real burn, once, after the virtual rehearsal, with a manufacturing record entry |
| Signing key | MCUboot's published development key, never shipped to a learner as if it were secret | A generated, protected production key, rotated on a schedule using the multi-key mechanism |
| UART download mode | Left enabled, or "permanently switch to secure mode," for recovery during labs | "Permanently disabled" for the most secure production option ([Espressif, Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/secure-boot-v2.html)) |
| Secrets at rest | Zephyr Settings for non-secret config; virtual or disposable credentials for labs | ESP-IDF flash and NVS encryption, eFuse-backed keys, and the DS peripheral, with production key material and a manufacturing record |

## A practical pattern for this course

Bringing the comparisons above together, a workable lifecycle for the
course's reference product is:

1. **Factory step (once, by the course maintainer).** Use the Manufacturing
   Utility and the `esp_secure_cert` tooling to give every lab device a
   unique serial number and, once the course reaches that lab, a unique
   per-device key pair and certificate. Record each device in a manufacturing
   CSV file in access-controlled storage. Keep only the schema and a
   synthetic example in the course repository.
2. **First-boot step (once, by the learner).** The learner's device starts
   with a bootstrap credential: a shared, restricted BLE or SoftAP
   provisioning session with a unique proof-of-possession code (modeled on
   Espressif's `network_provisioning` component), or a shared, restricted
   claim certificate (modeled on AWS IoT's provisioning by claim). The
   learner's lab exercise is to show that this bootstrap credential is
   exchanged for a per-device credential, and that the bootstrap credential
   cannot be reused afterward.
3. **Irreversible-action step (taught separately, deliberately).** The
   eFuse state changes for Secure Boot and flash encryption are rehearsed in
   `CONFIG_EFUSE_VIRTUAL` mode. This does not prove real hardware encryption.
   A real eFuse burn, if the course chooses to include one, happens once, on
   hardware set aside for that purpose, as a supervised mentor review gate
   rather than a routine lab step.
4. **Key rotation and revocation step.** MCUboot's multi-key mechanism and
   security counter are used to show a firmware signing key rotation
   end to end, without touching an eFuse. MCUboot verification keys live in
   the MCUboot build. They are separate from ESP Secure Boot key digests
   stored in eFuse.

## Sources

All sources below were accessed on 2026-09-11.

- Espressif, ESP-IDF Programming Guide, "Security Features Enablement
  Workflows," `esp32c6`, `stable` (v6.1):
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/security-features-enablement-workflows.html
- Espressif, ESP-IDF Programming Guide, "Secure Boot v2," `esp32c6`,
  `stable` (v6.1):
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/secure-boot-v2.html
- Espressif, ESP-IDF Programming Guide, "Flash Encryption," `esp32c6`,
  `stable` (v6.1):
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/flash-encryption.html
- Espressif, ESP-IDF Programming Guide, "eFuse Manager," `esp32c6`,
  `stable` (v6.1):
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html
- Espressif, ESP-IDF Programming Guide, "RSA Digital Signature Peripheral
  (RSA_DS)," `esp32c6`, `stable` (v6.1):
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/peripherals/ds.html
- Espressif, ESP-IDF Programming Guide, "Manufacturing Utility," `esp32c6`,
  `stable` (v6.1):
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/mass_mfg.html
- Espressif, ESP-IDF Programming Guide, "NVS Encryption," `esp32c6`,
  `stable` (v6.1):
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/nvs_encryption.html
- Espressif, ESP-IDF v6.0 provisioning migration guide, read at tag v6.1:
  https://github.com/espressif/esp-idf/blob/v6.1/docs/en/migration-guides/release-6.x/6.0/provisioning.rst
- Espressif, `network_provisioning` component README, component v1.2.4:
  https://github.com/espressif/idf-extra-components/tree/master/network_provisioning
- Espressif, `esp_secure_cert_mgr` README, GitHub `main` branch:
  https://github.com/espressif/esp_secure_cert_mgr/blob/main/README.md
- MCUboot project, `imgtool.md`, GitHub `main` branch:
  https://github.com/mcu-tools/mcuboot/blob/main/docs/imgtool.md
- MCUboot project, `design.md`, GitHub `main` branch:
  https://github.com/mcu-tools/mcuboot/blob/main/docs/design.md
- MCUboot project, `readme-espressif.md`, GitHub `main` branch:
  https://github.com/mcu-tools/mcuboot/blob/main/docs/readme-espressif.md
- MCUboot project, GitHub issue #2857, "RFC: Decentralized key revocation
  for MCUboot" (open discussion, not a released feature as of access date):
  https://github.com/mcu-tools/mcuboot/issues/2857
- MCUboot project, latest tagged release `v2.4.0`, GitHub releases API
  (checked 2026-09-11):
  https://api.github.com/repos/mcu-tools/mcuboot/releases/latest
- Zephyr Project, "Signing Binaries," `latest` docs:
  https://docs.zephyrproject.org/latest/build/signing/index.html
- Zephyr Project, "Settings," `latest` docs:
  https://docs.zephyrproject.org/latest/services/storage/settings/index.html
- Zephyr Project, "Secure Storage," `latest` docs:
  https://docs.zephyrproject.org/latest/services/storage/secure_storage/index.html
- Zephyr Project, Secure Storage key-provider Kconfig, GitHub `main` branch:
  https://github.com/zephyrproject-rtos/zephyr/blob/main/subsys/secure_storage/Kconfig.its_transform
- Zephyr Project, "Release Life Cycle and Maintenance," `latest` docs, and
  latest tagged release `v4.4.2`, GitHub releases API (checked 2026-09-11):
  https://docs.zephyrproject.org/latest/releases/index.html
  https://api.github.com/repos/zephyrproject-rtos/zephyr/releases/latest
- IETF, RFC 7030, "Enrollment over Secure Transport" (October 2013):
  https://www.rfc-editor.org/rfc/rfc7030.html
- IETF, RFC 8995, "Bootstrapping Remote Secure Key Infrastructure (BRSKI)"
  (May 2021):
  https://www.rfc-editor.org/rfc/rfc8995.html
- IEEE 802.1 Working Group, "802.1AR - Secure Device Identity" project
  summary page:
  https://grouper.ieee.org/groups/802/1/pages/802.1ar.html
- FIDO Alliance, "FIDO Device Onboard (FDO) Specifications" download page
  (FDO 1.1 Proposed Standard, 19 April 2022; FDO 2.0 Working Draft,
  17 June 2025):
  https://fidoalliance.org/specifications/download-iot-specifications/
- NIST, Special Publication 800-57 Part 1 Revision 5, "Recommendation for
  Key Management":
  https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- AWS, "Just-in-time provisioning," AWS IoT Core Developer Guide:
  https://docs.aws.amazon.com/iot/latest/developerguide/jit-provisioning.html
- AWS, "Provisioning devices that don't have device certificates using
  fleet provisioning," AWS IoT Core Developer Guide:
  https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html
