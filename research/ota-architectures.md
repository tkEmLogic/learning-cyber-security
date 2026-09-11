# Secure Wi-Fi OTA architectures for ESP32-C6, Zephyr, and MCUboot

Access date: 2026-09-11

## Answer

Use a small course-owned HTTPS service as the teaching baseline.

The device should use Zephyr networking and the Zephyr DFU APIs. MCUboot should
verify every firmware image before boot. The service should return a signed
manifest and a signed MCUboot image. The device should download into a second
flash slot. It should boot the new image once as a test. The new application
should confirm itself only after a health check.

This baseline is small enough to understand. It still teaches the main parts of
a production design:

- server authentication with TLS
- device authentication with a unique credential
- signed release metadata
- signed firmware
- anti-rollback rules
- interrupted download recovery
- staged rollout
- update status records
- failed boot recovery

Use Eclipse hawkBit as the main self-hosted comparison. It has a Zephyr client
in the upstream tree. It has strong rollout and fleet management features.

Use Mender MCU as the second self-hosted comparison. It is now an official
Zephyr external module. It uses MCUboot for A/B updates and rollback.

Use Golioth as the managed service comparison. Its firmware SDK supports
Zephyr. Its free usage model is useful for a small class or personal lab.

Do not use UpdateHub Community Edition as the main baseline. Zephyr still has
an UpdateHub client and sample. However, the Community Edition server has not
had a release since 2020 and was last pushed in 2023. Its own feature table
also says that Community Edition does not provide secure HTTPS or CoAP over
DTLS. It is useful as a maintenance and risk review exercise, not as the
recommended path.

## Scope and version snapshot

This report targets an ESP32-C6 that runs Zephyr and boots through MCUboot.

The current upstream release snapshot is:

- Zephyr 4.4.2, released on 2026-08-07:
  [Zephyr 4.4.2 release](https://github.com/zephyrproject-rtos/zephyr/releases/tag/v4.4.2)
- MCUboot 2.4.0, released on 2026-04-23:
  [MCUboot 2.4.0 release](https://github.com/mcu-tools/mcuboot/releases/tag/v2.4.0)
- Eclipse hawkBit 1.1.0, released on 2026-07-03:
  [hawkBit 1.1.0 release](https://github.com/eclipse-hawkbit/hawkbit/releases/tag/1.1.0)
- Mender MCU 1.1.0, published on 2026-09-02:
  [Mender MCU 1.1.0 release](https://github.com/mendersoftware/mender-mcu/releases/tag/v1.1.0)
- Mender Server 4.1.3, released on 2026-07-28:
  [Mender Server 4.1.3 release](https://github.com/mendersoftware/mender-server/releases/tag/v4.1.3)
- Golioth Firmware SDK 0.22.0, released on 2025-12-17:
  [Golioth Firmware SDK 0.22.0 release](https://github.com/golioth/golioth-firmware-sdk/releases/tag/v0.22.0)

Zephyr supports MCUboot on Espressif boards through sysbuild. The Zephyr
Espressif guide says that simple boot has no security features and no OTA
support. It shows how sysbuild creates both MCUboot and application images.
See [Zephyr Espressif build and flash
guide](https://docs.zephyrproject.org/latest/boards/espressif/common/building-flashing.html).

The current ESP32-C6 board documentation includes the
`esp32c6_devkitc/esp32c6/hpcore` target. It also states that Espressif QEMU does
not emulate Wi-Fi for this target. The complete Wi-Fi OTA path must therefore
be tested on hardware. See [ESP32-C6 DevKitC
documentation](https://docs.zephyrproject.org/latest/boards/espressif/esp32c6_devkitc/doc/index.html).

## Terms

**OTA** means over-the-air update. The device receives new software through a
network instead of a debug cable.

**Manifest** means metadata that describes an update. It can contain the
version, device type, image size, image hash, download URL, and expiry time.

**Signed image** means that a private release key signs the firmware. MCUboot
uses the matching public key to reject changed or unauthorized firmware.

**Signed metadata** means that a key signs the manifest itself. This protects
the update decision, not only the image bytes.

**A/B update** means that the device keeps a current image and a candidate
image in separate flash slots.

**Test boot** means that MCUboot starts the candidate image without making it
permanent. The new image must confirm itself. If it does not, MCUboot can
restore the old image.

**Anti-rollback** means that an attacker cannot force the device to install an
old but validly signed image.

## Security model

The design should handle these failures:

- a person listens to or changes Wi-Fi traffic
- a fake server answers the device
- a stolen device credential is used by another device
- the update server or object store is changed
- a release operator uploads the wrong file
- an old signed image is replayed
- power or Wi-Fi fails during download
- the new image starts but is not healthy
- the new image cannot connect to the update service
- the signing key must be replaced

MCUboot provides the final device-side check. Its image format supports hashes,
signatures, protected metadata fields, dependencies, and a security counter.
Its Zephyr integration supports a primary and secondary slot. It can test an
image and revert if the application does not mark the image as good. See the
[MCUboot design](https://docs.mcuboot.com/design.html), [MCUboot image
tool](https://docs.mcuboot.com/imgtool.html), and [MCUboot with
Zephyr](https://docs.mcuboot.com/readme-zephyr.html).

MCUboot 2.4.0 supports RSA-PSS, ECDSA, and Ed25519 image signatures through
`imgtool`. The release also improved Zephyr and Espressif support. See the
[MCUboot 2.4.0 release
notes](https://docs.mcuboot.com/release-notes.html#version-2-4-0).

MCUboot only protects the application if the bootloader and its public key are
also protected. ESP32-C6 silicon supports Secure Boot v2. It can verify the
second-stage bootloader and application against keys rooted in eFuse. The
vendor workflow is documented for ESP-IDF. A production Zephyr product must
validate its own integration and manufacturing flow before programming
irreversible eFuses. See [ESP32-C6 Secure Boot
v2](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c6/security/secure-boot-v2.html).

ESP32-C6 flash encryption protects code and data stored in external flash from
simple physical reading. It does not replace signature checks. It also changes
the manufacturing and recovery process. See [ESP32-C6 flash
encryption](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c6/security/flash-encryption.html).

## What TLS protects

TLS protects one network connection.

When the device validates the server certificate and host name, TLS provides:

- server authentication
- confidentiality while data crosses the network
- integrity while data crosses the network
- replay protection for records inside that connection

TLS can also authenticate the device. Common choices are a client certificate,
a pre-shared key, or an application token sent inside the protected
connection.

TLS does not prove that a firmware release is approved. It does not protect a
file after it leaves the TLS endpoint. It does not protect against a changed
object store, a compromised update server, a stolen server credential, or an
operator mistake. It also does not stop an old valid image from being replayed.

A hash in an unsigned manifest detects accidental corruption. It does not
provide authenticity. An attacker who changes the image can also change the
hash.

An MCUboot image signature proves that the image came from an authorized
signing key and that its covered bytes did not change. It is checked again at
boot. This protection remains useful when the transport or server is
compromised.

A signed manifest protects the release decision. It can bind these values
together:

- hardware type
- firmware version
- image hash and size
- image URL or object name
- minimum security counter
- release time and expiry time
- rollout or channel name

Signed metadata is still useful when images are signed. A valid image may be
wrong for the device, too old, or not yet approved for that fleet. The Update
Framework describes attacks such as rollback, freeze, mix-and-match, and wrong
software installation. It is designed so that update security does not depend
on TLS. See the [TUF
specification](https://theupdateframework.github.io/specification/latest/).

SUIT is an IETF manifest standard for constrained devices. It describes update
metadata and authorization needs. It is a good advanced exercise, but it adds
more format and policy work than the first lab needs. See [RFC
9124](https://datatracker.ietf.org/doc/html/rfc9124).

## Common device design

All serious options should end in the same device-side flow:

1. Connect to Wi-Fi.
2. Set trusted time, or use another safe certificate and expiry policy.
3. Authenticate the update server.
4. Authenticate the device with a unique credential.
5. Fetch release metadata.
6. Verify signed metadata when the service supports it.
7. Check the board, version, size, expiry, and rollback counter.
8. Download into the secondary slot.
9. Save download progress in non-volatile storage.
10. Verify the expected hash.
11. Ask MCUboot for a test boot.
12. Reboot.
13. Run local health checks.
14. Confirm the image only after the health checks pass.
15. Report success, failure, or rollback to the service.

The device must never write a network image directly over the running image.

## Option comparison

| Option | Actual Zephyr support | Main strength | Main gap |
| --- | --- | --- | --- |
| Small HTTPS service | Course code uses Zephyr HTTP, TLS, flash, and MCUboot APIs | Every trust decision is visible | The course must build rollout, audit, and recovery logic |
| Zephyr MCUmgr over SMP | In-tree image management over BLE, serial, or UDP | Very small local recovery and service tool | No fleet service, rollout engine, or built-in secure Internet transport |
| Eclipse hawkBit | In-tree client, API, and sample | Mature self-hosted fleet rollout | No separate signed release metadata in the Zephyr path |
| Mender MCU | Official external Zephyr module | Open server plus device inventory and deployment state | Newer MCU support and fewer MCU features than the Linux client |
| Golioth | Vendor Firmware SDK with Zephyr OTA sample | Fast managed setup and good Zephyr developer flow | Cloud service is not self-hosted |
| UpdateHub CE | In-tree Zephyr client and sample | Easy legacy demonstration | CE server is stale and its own table says secure transport is absent |

## Option 1: Small HTTPS manifest-and-image service

### Shape

Use three endpoints:

```text
GET  /v1/devices/{device-id}/manifest
GET  /v1/images/{sha256}.bin
POST /v1/devices/{device-id}/status
```

The server can be a small Python, Go, or Node.js application behind Caddy or
nginx. SQLite is enough for the lab. Keep image files immutable. Name each file
by its SHA-256 hash.

The manifest should contain:

```json
{
  "schema": 1,
  "device_type": "esp32c6-zephyr",
  "version": "1.2.3",
  "security_counter": 7,
  "size": 481216,
  "sha256": "hex value",
  "image_url": "/v1/images/hex-value.bin",
  "issued_at": "2026-09-11T10:00:00Z",
  "expires_at": "2026-09-18T10:00:00Z",
  "rollout": "class-a"
}
```

Sign the exact manifest bytes with a release metadata key. Store the detached
signature beside the manifest. ECDSA P-256 is a practical choice because
MCUboot and ESP32-C6 already use this family of algorithms. Keep the metadata
key separate from the MCUboot image signing key.

### Authentication

The device should trust only the course certificate authority or a pinned
public key. Do not disable host-name checks.

Give each device a unique bearer token for the first lab. Store only a hash of
the token on the server. A later exercise can replace the token with a client
certificate.

### Signing and rollback

Use MCUboot `imgtool` or Zephyr sysbuild to sign the image. Never use the
public example key in production. MCUboot warns that its example private key is
public. See [MCUboot with
Zephyr](https://docs.mcuboot.com/readme-zephyr.html#signing-the-application-manually).

Set an MCUboot security counter. Reject a manifest whose counter is below the
last accepted counter. Store the accepted counter in protected storage where
possible. A normal version string alone is not a strong anti-rollback control.

### Retry and resume

Use bounded retry with increasing delay and random jitter. Save the current
offset and the expected image hash. Resume with an HTTP Range request only when
the server returns `206 Partial Content` for the same immutable image.

If the server returns a full response, erase the secondary slot and restart.
Verify the whole image hash after the final byte. MCUboot must still verify the
signature at boot.

### Rollout and audit

Start with three server-side channels:

- development
- canary
- stable

Assign devices to one channel. Add a percentage gate and a stop button in the
second lab.

Record manifest decisions, downloads, boot attempts, confirmations, rollbacks,
and operator changes. Use append-only event rows. Include device ID, old
version, target version, result, reason, time, and release identifier.

### Recovery

Keep MCUboot serial recovery enabled for the lab where flash allows it. Keep a
wired recovery procedure even after Wi-Fi OTA works. A network service cannot
repair a device that cannot boot or join Wi-Fi.

### Teaching value

This option is the best baseline. Learners can see the difference between
transport security, metadata authorization, image authenticity, boot
selection, and fleet policy. The server is small enough to inspect in one
session.

## Option 2: Zephyr-native mechanisms

### MCUboot and the DFU APIs

Zephyr's DFU subsystem provides `flash_img` for writing image chunks and an
MCUboot API for selecting and querying images. The subsystem does not provide
the transport or fleet protocol. See the [Zephyr DFU
overview](https://docs.zephyrproject.org/latest/services/device_mgmt/dfu.html).

This is the right base for the small HTTPS service.

### MCUmgr and SMP

Zephyr MCUmgr provides image management over Bluetooth LE, serial, and UDP over
IP. The DFU integration currently supports MCUboot. See the [Zephyr MCUmgr
overview](https://docs.zephyrproject.org/latest/services/device_mgmt/mcumgr.html).

SMP is useful for local service and recovery. It is not a fleet update server.
The basic UDP transport is not a replacement for TLS, device authorization,
rollout policy, or audit storage. Do not expose it directly to an untrusted
network.

### hawkBit client

Zephyr 4.4.2 contains an in-tree hawkBit subsystem and sample. The sample builds
MCUboot and uploads `zephyr.signed.bin`. See the [Zephyr hawkBit
sample](https://docs.zephyrproject.org/latest/samples/subsys/mgmt/hawkbit/README.html).

The client supports target tokens and tenant-wide gateway tokens. Prefer a
unique target token. It also has `CONFIG_HAWKBIT_USE_TLS` for server TLS.
Zephyr 4.4.2 can save download progress and resume with an HTTP Range request.
It verifies the downloaded SHA-256 value before marking the image pending.
These controls are visible in the [Zephyr hawkBit
Kconfig](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/subsys/mgmt/hawkbit/Kconfig)
and [client
source](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/subsys/mgmt/hawkbit/hawkbit.c).

The default `CONFIG_HAWKBIT_CONFIRM_IMG_ON_INIT=y` confirms the image during
hawkBit initialization. For a rollback lesson, disable this default and
confirm only after application health checks.

### UpdateHub client

Zephyr still includes an UpdateHub client and Wi-Fi sample. It can use MCUboot
signed images and can create a rollout. See the [Zephyr UpdateHub
sample](https://docs.zephyrproject.org/latest/samples/subsys/mgmt/updatehub/README.html).

UpdateHub Community Edition is MIT licensed and easy to start with Docker. Its
own table says it supports signed packages, rollouts, and monitored updates.
The same table says it does not support HTTPS or CoAP over DTLS. See the
[UpdateHub CE
repository](https://github.com/UpdateHub/updatehub-ce).

The latest CE release is 20.3.0 from 2020. The repository was last pushed in
2023. This is weak project health for a new course baseline. The Zephyr client
is still useful for code reading and protocol comparison.

### LwM2M

Zephyr supports the LwM2M Firmware Update object and DTLS connections. The
upstream sample does not demonstrate firmware update. This is useful for an
advanced standards exercise, not the first OTA lab. See the [Zephyr OTA
overview](https://docs.zephyrproject.org/latest/services/device_mgmt/ota.html).

## Option 3: Eclipse hawkBit

hawkBit is an update server, not a bootloader. It manages targets,
distribution sets, rollout groups, actions, and status. The device still needs
MCUboot.

### Zephyr support

Zephyr has a direct DDI client and a complete sample. This is the strongest
upstream Zephyr integration among the self-hosted services in this report.

The sample is not listed specifically for ESP32-C6. Porting work is still
needed for the board overlay, flash partitions, Wi-Fi settings, certificate
storage, and memory sizing.

### Security

Use HTTPS and a unique target token. Do not use the shared gateway token for a
large device fleet. A stolen gateway token has a larger impact.

The standard Zephyr path receives an artifact SHA-256 value and verifies it
after download. It then asks MCUboot to boot the candidate image. The uploaded
artifact should therefore be an MCUboot-signed image.

The reviewed Zephyr and hawkBit paths do not provide a separate offline
signature over the deployment metadata. The server, its database, and TLS
endpoint remain trusted for the choice of version and target. Add signed
metadata outside hawkBit if this threat matters.

### Reliability and fleet features

hawkBit supports polling, deployment feedback, rollout groups, action history,
and stopping a rollout. Zephyr 4.4.2 adds persistent download progress and
resume support to its client. hawkBit 1.1.0 also improved range downloads and
fixed rollout and action history issues. See the [hawkBit 1.1.0
notes](https://github.com/eclipse-hawkbit/hawkbit/releases/tag/1.1.0).

### Local setup, license, and health

The project provides Docker images and Docker Compose configurations. The
Zephyr sample starts a local PostgreSQL setup. Default credentials are only
for local evaluation and must be changed. See the [hawkBit
repository](https://github.com/eclipse-hawkbit/hawkbit) and [Zephyr hawkBit
sample](https://docs.zephyrproject.org/latest/samples/subsys/mgmt/hawkbit/README.html).

hawkBit 1.1.0 uses the Eclipse Public License 2.0. The project had a release in
July 2026 and repository activity on the access date. Project health is good
enough for a maintained comparison.

### Teaching value

hawkBit is the best comparison after the small service. Learners can replace a
simple channel table with a real rollout engine. They can also see that a
fleet server does not remove the need for MCUboot signing and safe image
confirmation.

## Option 4: Mender MCU

Mender MCU is a device client for constrained devices. It connects Zephyr
devices to a Mender server. It is different from the full Linux Mender client.

### Zephyr support

Zephyr lists Mender MCU as an external module. The module supplies a
`zephyr-image` Update Module that integrates with MCUboot for atomic A/B
updates and automatic rollback. See the [Zephyr Mender MCU
page](https://docs.zephyrproject.org/latest/develop/manifest/external/mender-mcu.html)
and [Mender MCU
repository](https://github.com/mendersoftware/mender-mcu).

Mender MCU 1.1.0 adds Zephyr 4.4 support, chunked artifact downloads, retry
timing support, and a secondary server URL. These are useful signs of active
work. See the [Mender MCU 1.1.0
notes](https://github.com/mendersoftware/mender-mcu/releases/tag/v1.1.0).

The reference board is ESP32-S3, not ESP32-C6. ESP32-C6 should be treated as a
port and validation task. The learner must verify the flash map, swap mode,
RAM, TLS credentials, and Wi-Fi behavior.

### Authentication and signing

The client supports a user-provided identity key pair or can create an ECDSA
key pair. It uses server CA certificates through Zephyr TLS credentials. The
server accepts and authorizes device identities. See the [Mender MCU
README](https://github.com/mendersoftware/mender-mcu/blob/v1.1.0/README.md).

The `zephyr-image` module packages `zephyr.signed.bin` inside a Mender
Artifact. MCUboot provides the device-side image signature check. Do not assume
that MCUboot signing also signs all Mender deployment metadata.

The MCU client has fewer Artifact features than the Linux client. For example,
its documented build flow requires uncompressed Artifacts. Treat Mender
Artifact signature verification on MCU as unsupported unless a tested release
explicitly proves it.

### Rollback, retry, rollout, and audit

The Zephyr Update Module requires an MCUboot swap mode so it can revert to the
old image. Mender Server records device inventory, deployment state, and
result. Version 1.1.0 has chunked downloads and request retry behavior. Verify
power-loss resume on the target because chunking is not the same as persistent
resume after reboot.

The open server provides deployments and device state. Advanced phased rollout
controls and audit logs depend on the selected Mender plan. Mender documents
audit logs as an Enterprise feature. See [Mender audit
logs](https://docs.mender.io/overview/audit-logs).

### Local setup, license, and health

Mender Server can be self-hosted. The Docker Compose setup is for evaluation.
A production setup needs more services and operating work. See [Mender
evaluation with Docker
Compose](https://docs.mender.io/server-installation/evaluation-with-docker-compose).

The Mender Server repository says its content is Apache License 2.0 unless
marked otherwise. Mender MCU is Apache License 2.0. Enterprise features use
commercial terms. See the [Mender Server
license](https://github.com/mendersoftware/mender-server/blob/main/LICENSE) and
[Mender MCU
license](https://github.com/mendersoftware/mender-mcu/blob/v1.1.0/LICENSE).

Mender MCU 1.1.0, Mender Server 4.1.3, and Mender Artifact 4.4.2 all had 2026
releases. Project health is good, but the MCU client is younger than the Linux
client.

### Teaching value

Mender is a good exercise in separating an update container, a deployment
service, a device identity, and MCUboot image trust. It also shows how product
features can differ between open and paid editions.

## Option 5: Golioth

Golioth is a managed cloud service. Its device SDK is open source. Its backend
is not available as a self-hosted open-source server.

### Zephyr support

Golioth documents full Zephyr support and tests boards from several vendors.
Its firmware update sample uses Zephyr, MCUboot, `zephyr.signed.bin`, and a
test boot followed by confirmation. See the [Golioth platform support
page](https://docs.golioth.io/device-management/ota/firmware/) and [firmware
update
sample](https://github.com/golioth/golioth-firmware-sdk/tree/v0.22.0/examples/zephyr/fw_update).

The continuously verified Espressif board in SDK 0.22.0 is ESP32-S3. ESP32-C6
is not named in that verified set. Treat ESP32-C6 as a target that needs its
own board configuration and test evidence.

### Authentication and signing

The Zephyr sample supports per-device pre-shared keys. The SDK also has
certificate provisioning and rotation examples. The device uses authenticated
DTLS for the CoAP service.

The OTA service sends a manifest with a release sequence number, component
version, SHA-256 hash, size, URI, and type. It also offers a SUIT manifest
endpoint. See the [Golioth device OTA
API](https://docs.golioth.io/reference/device-api/api-docs/ota/).

The normal Zephyr flow uploads `zephyr.signed.bin`. MCUboot verifies the image.
The public OTA API page does not prove that the normal manifest is verified
with a separate offline signature on the device. Treat signed release metadata
as not established until the exact SDK path is tested.

### Rollback, retry, rollout, and audit

The sample uses MCUboot test and confirm behavior. The service supports
packages, deployments, cohorts, and device state reporting. Cohorts give a
clear way to separate canary and stable devices. See the [Golioth OTA
overview](https://docs.golioth.io/device-management/ota/).

The sample shows block-based transfer. Test interruption and reboot cases on
ESP32-C6 before claiming persistent resume. Device state reporting gives
operational history. The reviewed public OTA pages do not describe a
compliance-grade operator audit log.

### Pricing, license, and health

The current pricing page says there are no monthly fees and no device caps, and
that occasional OTA use can be free. See [Golioth
pricing](https://golioth.io/pricing).

A 2024 first-party pricing announcement states that the Individual Developer
plan is free and includes 1 GB of OTA downloads per month. It lists usage
charges after that allowance. These numbers may change, so check the live
pricing page before a class starts. See [Golioth pricing
announcement](https://blog.golioth.io/device-management-should-be-free/).

The Firmware SDK is Apache License 2.0. See the [SDK
license](https://github.com/golioth/golioth-firmware-sdk/blob/v0.22.0/LICENSE).
The latest tag is older than the access date, but the repository had recent
2026 activity. Project health is good.

### Teaching value

Golioth gives the fastest path to a real managed fleet service. It is useful
after learners understand the local baseline. It also creates a useful
discussion about cloud dependency, service cost, data location, and exit
plans.

## Detailed scorecard

| Concern | Small HTTPS service | hawkBit | Mender MCU | Golioth |
| --- | --- | --- | --- | --- |
| Zephyr support | Course code on Zephyr APIs | In-tree subsystem and sample | Official external module | Vendor SDK and sample |
| ESP32-C6 proof | Must build and test | Not a named sample target | Reference target is ESP32-S3 | Verified Espressif target is ESP32-S3 |
| Server authentication | TLS CA or pin | TLS option in Zephyr client | Zephyr TLS CA credentials | DTLS server authentication |
| Device authentication | Unique token, then mTLS exercise | Target or shared gateway token | Device ECDSA identity and server authorization | Per-device PSK or certificate |
| Signed metadata | Yes, by course design | No separate offline signature in reviewed path | Not established for MCU path | Not established for normal manifest path |
| Signed image | MCUboot required | MCUboot signed artifact | `zephyr.signed.bin` | `zephyr.signed.bin` |
| Anti-rollback | Manifest counter plus MCUboot counter | Must configure policy | Must configure policy | Must configure policy |
| Failed boot rollback | MCUboot test and confirm | MCUboot, if confirmation is delayed | MCUboot swap and Update Module | MCUboot test and confirm |
| Retry | Course backoff policy | Polling and request retry | HTTP retry support | SDK handles block transfer |
| Resume after interruption | HTTP Range plus saved offset | Zephyr 4.4.2 supports saved progress | Verify persistent reboot resume | Verify persistent reboot resume |
| Rollout | Small channel and percentage logic | Strong rollout groups and stop controls | Server deployments, plan-dependent phases | Cohorts and deployments |
| Audit records | Must implement append-only events | Action and rollout history | Deployment history, enterprise audit logs | State history, full audit not established |
| Local setup | Very small | Docker Compose plus database | Docker Compose evaluation stack | Device side only, cloud backend |
| License | Course choice | EPL-2.0 | Apache-2.0 open components | Apache-2.0 SDK, proprietary service |
| Best teaching use | Baseline | Fleet comparison | Open server comparison | Managed cloud comparison |

## Recommended teaching baseline

Build the first course path in this order:

### Stage 1: Safe local update

- Build ESP32-C6 firmware with Zephyr 4.4.2 and MCUboot 2.4.0 through sysbuild.
- Define primary and secondary flash slots.
- Sign with a course development key.
- Upload through MCUmgr over serial.
- Show test boot, health failure, and automatic revert.

This stage removes Wi-Fi and server complexity while learners understand the
boot state machine.

### Stage 2: Small HTTPS service

- Add Wi-Fi.
- Add the manifest, image, and status endpoints.
- Validate the server certificate.
- Use one unique token per board.
- Sign the exact manifest bytes.
- Download into the secondary slot.
- Verify size and SHA-256.
- Request an MCUboot test boot.
- Confirm only after health checks.

### Stage 3: Failure handling

- Cut Wi-Fi during download.
- Cut power during download.
- Return a changed image.
- Return a changed manifest.
- Return an expired manifest.
- Return an old signed image.
- Make the new image fail its health check.
- Make the status upload fail after a successful boot.

Each case should have an expected safe result and an audit record.

### Stage 4: Fleet policy

- Add development, canary, and stable channels.
- Roll out to one canary device first.
- Stop a rollout after a simulated failure threshold.
- Separate release approval from server operation.

### Stage 5: Production hardening discussion

- Move private signing keys out of the build machine.
- Plan key rotation.
- Protect the MCUboot public key and bootloader.
- Review ESP32-C6 Secure Boot v2 and flash encryption.
- Decide how to recover a device with no valid application.
- Decide how long an offline device may trust cached time and metadata.

## Comparison exercises

### Exercise 1: TLS is not firmware authorization

Give learners a valid HTTPS server that serves a changed unsigned image. Then
serve an old validly signed image.

Expected result:

- TLS accepts the server.
- MCUboot rejects the changed image.
- Anti-rollback policy rejects the old signed image.

### Exercise 2: Hash versus signature

Change both an image and the hash in an unsigned manifest.

Expected result:

- The hash matches the attacker's image.
- A signed manifest fails verification.
- An MCUboot image signature also prevents the changed code from booting.

### Exercise 3: Recovery timing

Compare three confirmation policies:

- confirm immediately at startup
- confirm after local self-test
- confirm after local self-test and successful cloud contact

Discuss the risk of each policy. A cloud contact requirement can cause a good
image to revert during a service outage.

### Exercise 4: Replace the service with hawkBit

Keep the same MCUboot image and health checks. Replace only the manifest,
download, rollout, and status layer.

Compare code size, setup time, rollout controls, event history, and failure
behavior.

### Exercise 5: Replace the service with Mender MCU

Package the same signed image as a Mender Artifact. Use the open-source server.
Compare device identity, deployment state, rollback, and server operations.

### Exercise 6: Use the Golioth free usage model

Connect a small test fleet to Golioth. Use a development cohort and a stable
cohort. Measure bytes used by one full-fleet update. Compare that result with
the current free allowance and paid usage terms.

### Exercise 7: Review a weak dependency

Inspect UpdateHub CE. Identify the missing secure transport in its own feature
table and the age of its latest release. Decide whether a maintained Zephyr
client is enough when the server project is stale.

## Final decision

The teaching baseline should be:

> Zephyr on ESP32-C6, MCUboot A/B test boot, a small HTTPS
> manifest-and-image service, a signed manifest, a signed MCUboot image, saved
> download progress, delayed confirmation, and an append-only status log.

This design makes each security boundary visible. It runs locally. It has no
service fee. It also maps cleanly to larger systems.

The first comparison should be Eclipse hawkBit. It shows how a real
self-hosted rollout service replaces course-built fleet logic.

The second comparison should be Mender MCU with the open-source Mender Server.
It shows an integrated device identity, inventory, Artifact, and deployment
model.

The managed comparison should be Golioth. It shows a polished Zephyr flow and
a low-cost entry point, but it also adds cloud dependency.

Keep MCUboot signing and health-based confirmation in every comparison.
Changing the server must not change the final boot trust decision.

## Source register

All sources were accessed on 2026-09-11.

| Topic | Primary source |
| --- | --- |
| Zephyr 4.4.2 version | [Zephyr 4.4.2 release](https://github.com/zephyrproject-rtos/zephyr/releases/tag/v4.4.2) |
| Zephyr OTA options | [Zephyr OTA overview](https://docs.zephyrproject.org/latest/services/device_mgmt/ota.html) |
| Zephyr DFU APIs | [Zephyr DFU overview](https://docs.zephyrproject.org/latest/services/device_mgmt/dfu.html) |
| Zephyr MCUmgr transports | [Zephyr MCUmgr overview](https://docs.zephyrproject.org/latest/services/device_mgmt/mcumgr.html) |
| ESP32-C6 board and QEMU limits | [ESP32-C6 DevKitC documentation](https://docs.zephyrproject.org/latest/boards/espressif/esp32c6_devkitc/doc/index.html) |
| Espressif MCUboot build | [Zephyr Espressif build guide](https://docs.zephyrproject.org/latest/boards/espressif/common/building-flashing.html) |
| MCUboot 2.4.0 version | [MCUboot release](https://github.com/mcu-tools/mcuboot/releases/tag/v2.4.0) |
| MCUboot slots and rollback | [MCUboot design](https://docs.mcuboot.com/design.html) |
| MCUboot Zephyr integration | [MCUboot with Zephyr](https://docs.mcuboot.com/readme-zephyr.html) |
| MCUboot keys and security counter | [MCUboot imgtool](https://docs.mcuboot.com/imgtool.html) |
| ESP32-C6 hardware trust | [ESP32-C6 Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c6/security/secure-boot-v2.html) |
| ESP32-C6 flash privacy | [ESP32-C6 flash encryption](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c6/security/flash-encryption.html) |
| Signed metadata model | [TUF specification](https://theupdateframework.github.io/specification/latest/) |
| Constrained manifest model | [IETF SUIT architecture, RFC 9124](https://datatracker.ietf.org/doc/html/rfc9124) |
| hawkBit project, Docker, and license | [hawkBit repository](https://github.com/eclipse-hawkbit/hawkbit) |
| hawkBit 1.1.0 health | [hawkBit 1.1.0 release](https://github.com/eclipse-hawkbit/hawkbit/releases/tag/1.1.0) |
| Zephyr hawkBit flow | [Zephyr hawkBit sample](https://docs.zephyrproject.org/latest/samples/subsys/mgmt/hawkbit/README.html) |
| Zephyr hawkBit auth and resume | [Zephyr 4.4.2 hawkBit Kconfig](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/subsys/mgmt/hawkbit/Kconfig) |
| Zephyr hawkBit hash and Range use | [Zephyr 4.4.2 hawkBit source](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/subsys/mgmt/hawkbit/hawkbit.c) |
| Mender MCU Zephyr status | [Zephyr external module page](https://docs.zephyrproject.org/latest/develop/manifest/external/mender-mcu.html) |
| Mender MCU behavior and license | [Mender MCU README](https://github.com/mendersoftware/mender-mcu/blob/v1.1.0/README.md) |
| Mender MCU 1.1.0 health | [Mender MCU 1.1.0 release](https://github.com/mendersoftware/mender-mcu/releases/tag/v1.1.0) |
| Mender Server version | [Mender Server 4.1.3 release](https://github.com/mendersoftware/mender-server/releases/tag/v4.1.3) |
| Mender Server license | [Mender Server license](https://github.com/mendersoftware/mender-server/blob/main/LICENSE) |
| Mender local evaluation | [Mender Docker Compose evaluation](https://docs.mender.io/server-installation/evaluation-with-docker-compose) |
| Mender audit feature | [Mender audit logs](https://docs.mender.io/overview/audit-logs) |
| Golioth Zephyr support | [Golioth platform support](https://docs.golioth.io/device-management/ota/firmware/) |
| Golioth OTA model | [Golioth OTA overview](https://docs.golioth.io/device-management/ota/) |
| Golioth manifest fields | [Golioth device OTA API](https://docs.golioth.io/reference/device-api/api-docs/ota/) |
| Golioth Zephyr example | [Golioth firmware update sample](https://github.com/golioth/golioth-firmware-sdk/tree/v0.22.0/examples/zephyr/fw_update) |
| Golioth SDK version and health | [Golioth SDK 0.22.0 release](https://github.com/golioth/golioth-firmware-sdk/releases/tag/v0.22.0) |
| Golioth SDK license | [Golioth SDK license](https://github.com/golioth/golioth-firmware-sdk/blob/v0.22.0/LICENSE) |
| Golioth current price statement | [Golioth pricing](https://golioth.io/pricing) |
| Golioth free allowance details | [Golioth pricing announcement](https://blog.golioth.io/device-management-should-be-free/) |
| UpdateHub Zephyr path | [Zephyr UpdateHub sample](https://docs.zephyrproject.org/latest/samples/subsys/mgmt/updatehub/README.html) |
| UpdateHub CE features and license | [UpdateHub CE repository](https://github.com/UpdateHub/updatehub-ce) |
