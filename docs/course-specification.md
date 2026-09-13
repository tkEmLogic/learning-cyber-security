# Course specification: Learning Cyber Security

Status: Implementation ready.

Assembled from Wayfinder map [#1](https://github.com/tkEmLogic/learning-cyber-security/issues/1) and its resolved child tickets [#2](https://github.com/tkEmLogic/learning-cyber-security/issues/2) through [#16](https://github.com/tkEmLogic/learning-cyber-security/issues/16) and [#18](https://github.com/tkEmLogic/learning-cyber-security/issues/18).

Assembly ticket: [#17](https://github.com/tkEmLogic/learning-cyber-security/issues/17).

Assembled on 2026-09-11.

This document is the single implementation-ready specification for the Learning Cyber Security course.

It gives an implementer everything needed to build the course repository, the local services, the learner modules, the mentor material, and the CI checks without re-deciding the architecture, the threat model, the tier order, the assessment style, or the repository layout.

It is a specification, not an implementation. It does not contain firmware source, service source, or finished course prose.

It also does not restate every research report in full. Each section points to the source research report and the resolved ticket that backs it.

## How to read this specification

Every decision in this document carries one of four labels. Use the label to know how much freedom an implementer has.

| Label | Meaning |
| --- | --- |
| Fixed decision | Already decided by the Wayfinder map. Do not redesign it. Implement it as stated. |
| Implementation requirement | A concrete rule the implementation must satisfy. The exact code, file, or tool choice is open where not stated. |
| Validation gate | A check that must pass on real hardware or a real environment before a claim, module, or feature can be published as supported. |
| Known platform uncertainty | An upstream gap or unverified claim. Treat it as unresolved until the stated validation gate passes. |

Terms in this document follow `CONTEXT.md` in the repository root. Use `Learner`, not student or beginner. Use `Mentor`, not instructor. Use `Reference product`, `Hardening tier`, `Weakness ledger`, `Tier checkpoint`, `Course workspace`, `Security evidence pack`, `Security claim`, `Residual risk`, `Factory identity`, `Operational identity`, `Bootstrap credential`, `Claim window`, `Release manifest`, `Update assignment`, `OTA service`, `Secure element`, and `Lab artifact` exactly as defined there.

## Table of contents

1. Audience and course model
2. Reference product and scenario
3. Threat model
4. Legal context: Cyber Resilience Act obligations
5. Platform baseline and versions
6. Boot and firmware trust model
7. OTA architecture
8. Device identity and provisioning lifecycle
9. Secure element advanced module: STSAFE-A120
10. Security evidence model
11. Hardening tier progression
12. Weakness ledger
13. Mentor review gates and assessment
14. Course module format
15. Repository scaffold
16. Command interface
17. Secrets, attack fixtures, and irreversible hardware work
18. Continuous integration
19. Readings and reading plan
20. Docmost formatting rules
21. Safety boundaries summary
22. Acceptance criteria for the finished course package
23. Implementation handoff checklist
24. Source and version register
25. Known ambiguities and unresolved conflicts

## 1. Audience and course model

**Fixed decision.** The Learner is an embedded software engineer who has little or no experience applying cybersecurity in an embedded product context. The Learner may not be a native English speaker, so all learner-facing material uses short sentences, common words, and no idioms.

**Fixed decision.** The course is self-paced. The Learner moves through hardening tiers at their own speed and schedules Mentor review gates when ready.

**Fixed decision.** The course is mentor-supported. A Mentor gives informal coaching at defined milestones. See section 13 for the full model.

**Fixed decision.** The course has no numeric grade, formal certification, or pass or fail assessment. Only safety and dependency prerequisites block progress. See section 13.

**Fixed decision.** The whole course is organized as cumulative hardening tiers. Tier 0 is a completely unsecured but functional reference product. Each later tier adds one focused security control or lifecycle capability and keeps the product runnable. See section 11.

Source: Wayfinder map [#1](https://github.com/tkEmLogic/learning-cyber-security/issues/1), resolved decision ticket [#2](https://github.com/tkEmLogic/learning-cyber-security/issues/2).

## 2. Reference product and scenario

**Fixed decision.** The reference product is an industrial equipment status beacon built around an ESP32-C6 development kit. It is non-actuating. It reports a simulated machine state and never controls real machinery.

### Product behavior

| Behavior | Detail |
| --- | --- |
| Indicator | One monochrome LED. |
| Normal operation | Steady light. |
| Device off | No light. |
| Fictional error state 1 | Fast blinking. |
| Fictional error state 2 | Slow blinking. |
| State change | Caused by software logic or a test input. |
| Status reporting | Over Wi-Fi to a service on the local network. |
| Software updates | Received over Wi-Fi. |

### Protected assets

Firmware authenticity and integrity, the firmware signing key, the device private identity key, trust anchors and update policy, the installed firmware version and anti-rollback state, configuration and reported status integrity, and device availability and recovery access.

Firmware confidentiality is not a core requirement. It is taught as an advanced topic through flash encryption and its operational cost.

### Actors and attackers

| Role | Description |
| --- | --- |
| Manufacturer | Creates releases and supports the product. |
| Provisioning operator | Gives each device its identity. |
| Customer operator | Installs and manages the device. |
| Mentor | Reviews selected Learner results. |
| OTA service | Publishes approved releases. |
| Device | Downloads, verifies, installs, and confirms an update. |
| Remote attacker | Can reach exposed network services. |
| Local attacker | Shares Wi-Fi or the local network. |
| Physical opportunist | Briefly accesses the device, serial port, or flash pins. |
| Thief | Steals a deployed device. |
| Hosting attacker | Compromises OTA hosting but never holds the offline firmware signing key. |
| Operational failure | Operator error, failed download, power loss, or a wrong release, treated as a failure case rather than an attacker. |

**Fixed decision.** The core course excludes invasive chip attacks, advanced fault injection, nation-state attackers, and a fully compromised release-signing system.

### Trust boundaries

The device and the local Wi-Fi network, the device and the OTA service, the release-signing workstation and the OTA service, the provisioning station and the device, MCUboot and the Zephyr application, the ESP32-C6 and an optional STSAFE-A120, and the customer operator and the manufacturer service.

### Lifecycle and recovery

**Fixed decision.** The manufacturer provisions a unique device identity, the customer installs the device on a local Wi-Fi network, a limited Bootstrap credential may support first bring-up, the product receives security updates for at least a five-year support period, credentials can be rotated and revoked, ownership transfer removes the old owner's access and creates new owner credentials, and decommissioning revokes backend access and removes customer credentials where the hardware permits it.

**Fixed decision.** The product uses two MCUboot image slots with test boot, confirmation, and revert. A failed or interrupted update must never leave the device without a bootable image. A physically present operator may use a documented serial recovery path. Irreversible eFuse exercises use virtual eFuses first and labelled disposable hardware only after a Mentor review gate.

### Teaching simplifications

Start with one device and extend selected exercises to a small fleet. Run the OTA and test services on a local development machine. Do not require production backend scale or high availability. Do not simulate a complete factory production line. Do not claim formal CRA conformity. Do not add hazardous physical actuation. Treat firmware confidentiality and the secure element as advanced modules.

Source: resolved decision ticket [#2](https://github.com/tkEmLogic/learning-cyber-security/issues/2).

## 3. Threat model

The threat model is the actor, attacker, trust boundary, and lifecycle content in section 2. The security evidence pack in section 10 turns it into numbered requirements, claims, and residual risks starting in Hardening Tier 1.

**Implementation requirement.** The Tier 1 lab artifact must contain a risk register with likelihood, impact, selected treatment, owner, and residual risk for every asset and attacker listed in section 2. See section 11, Tier 1.

**Fixed decision.** Excluded threats stay excluded for the whole core course: invasive chip attacks, advanced fault injection, nation-state attackers, and a fully compromised release-signing system. Advanced Tier A narrows the physical-attacker exclusion for the boot chain only, under the validation gate in section 6.

Source: resolved decision ticket [#2](https://github.com/tkEmLogic/learning-cyber-security/issues/2).

## 4. Legal context: Cyber Resilience Act obligations

**Fixed decision.** The course teaches the 2026 reporting duties, the 2027 product and lifecycle duties, and the engineering evidence needed to support a product-specific legal review. The course never claims CRA conformity for the reference product.

| Date | Legal effect |
| --- | --- |
| 11 September 2026 | Article 14 manufacturer reporting duty applies. Both reportable event types require an early warning within 24 hours and a notification within 72 hours after awareness. An actively exploited vulnerability has a final report no later than 14 days after a corrective or mitigating measure becomes available. A severe incident has a final report within one month after the 72-hour incident notification. |
| 11 December 2027 | The main product, lifecycle, conformity, support, and user-information duties apply. |

**Implementation requirement.** Support must match expected use and is at least five years unless expected use is shorter. Security fixes must be free. Issued updates need long-term availability. The course reference product uses the five-year scenario stated in section 2.

**Implementation requirement.** The course must produce, as learner artifacts: a risk assessment, an Annex I control map, an SBOM, test evidence, update records, a coordinated vulnerability disclosure process, two timed Article 14 reporting exercises, user instructions, and draft conformity records. One exercise covers an actively exploited vulnerability and one covers a severe incident. Each records the awareness time, classification rationale, competent-CSIRT assumption, 24-hour early warning, 72-hour notification, user communication, mitigation, event-specific final-report deadline, and points that require legal review. These artifacts are defined in full in section 10 and exercised in Hardening Tier 9.

**Known platform uncertainty.** The finished product's legal scope, manufacturer role, product class, support period, interaction with other EU regimes, and reportability decisions all need product-specific legal review. The course states this boundary every time it touches CRA content and never resolves it on the learner's behalf.

Source: resolved research ticket [#3](https://github.com/tkEmLogic/learning-cyber-security/issues/3).

## 5. Platform baseline and versions

**Fixed decision.** The course pins these versions. An implementer keeps readings, driver choices, and course claims aligned to them.

| Component | Version | Note |
| --- | --- | --- |
| Board | ESP32-C6 development kit | Zephyr target `esp32c6_devkitc/esp32c6/hpcore`. |
| Zephyr | 4.4.2 | Core course baseline. |
| MCUboot | 2.4.0 | Core and advanced course baseline. |
| ESP-IDF security docs | v6.1 | Used for ESP32-C6 hardware security features in Advanced Tier A. |

**Known platform uncertainty.** Standard Zephyr 4.4.2 sysbuild uses the MCUboot Zephyr port. It does not establish ESP32-C6 Secure Boot v2 or hardware flash encryption. It also defaults the ESP32-C6 board to unsigned MCUboot images. An implementer must select a real signature type explicitly starting in Hardening Tier 3.

**Known platform uncertainty.** A hardware-rooted chain is practical only through a manually integrated MCUboot Espressif port, followed by signed Zephyr images. The exact full chain still needs physical-board tests before Advanced Tier A can be published as supported rather than experimental.

**Known platform uncertainty.** Hardware MCUboot anti-rollback and hardware-backed Zephyr credential storage are not established upstream as of the research date. The core course therefore uses software-enforced downgrade protection, described honestly as software-enforced, not hardware-enforced. See section 6.

**Validation gate.** Secure boot, flash encryption, key protection, debug disable, and download-mode eFuse changes include irreversible steps. Test recovery on disposable hardware first. Advanced Tier A cannot be published as a supported hands-on module until the checklist in section 17 passes on the pinned physical board.

**Implementation requirement.** Before production-style claims, close these upstream gaps: pin one exact Zephyr commit rather than a moving branch, confirm the unsigned ESP32 board default is overridden, reproduce the complete boot chain on physical ESP32-C6-DevKitC hardware, confirm flash encryption across every partition, test that old signed images are rejected under the intended threat model, decide whether software downgrade prevention is sufficient or an eFuse-backed counter is required, replace the core course's deliberately limited device-ID-derived secure-storage key provider with a provider based on a protected device secret, verify entropy while radios are off and during early boot, test Zephyr userspace and memory domains on the real board, test the recovery path after a failed and interrupted update, measure bootloader size with every enabled security feature, and validate both bootloader-signing-key and firmware-release-key rotation procedures.

Full report: [`research/platform-security-support.md`](https://github.com/tkEmLogic/learning-cyber-security/blob/research/platform-security/research/platform-security-support.md) on branch `research/platform-security`.

Key primary sources: [Espressif security support](https://developer.espressif.com/software/zephyr-support-status/), [Zephyr 4.4.2 ESP32-C6 sysbuild defaults](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/boards/espressif/esp32c6_devkitc/Kconfig.sysbuild), and [MCUboot 2.4.0 Espressif port](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/readme-espressif.md).

Source: resolved research ticket [#4](https://github.com/tkEmLogic/learning-cyber-security/issues/4).

## 6. Boot and firmware trust model

**Fixed decision.** The course uses a staged boot and firmware trust model. The core course teaches a software-rooted chain that works with the standard Zephyr 4.4.2 ESP32-C6 integration. Advanced Tier A adds the manually integrated MCUboot Espressif port, ESP32-C6 Secure Boot v2, and hardware-backed controls.

### Core trust model

The manufacturer owns an offline firmware release-signing key. The OTA service stores signed releases but never holds the release-signing key. MCUboot contains the trusted firmware-verification public key and accepts only correctly signed Zephyr application images. Standard Zephyr MCUboot on ESP32-C6 is not authenticated by a hardware root of trust, and course material must state this limitation every time it describes the core chain. The core model protects the update path from corrupted images, an untrusted OTA host, and remote replacement of the application image. It does not protect against a physical attacker who can replace the bootloader or its embedded verification key. The device identity key is separate from every firmware-signing and boot key and is never used to sign firmware.

### Pinned core boot configuration

**Implementation requirement.** Use the Zephyr 4.4.2 default 4 MiB ESP32-C6 partition map as the core-course flash contract, even when the board module has 8 MiB: 64 KiB MCUboot at `0x000000`, 64 KiB system data at `0x010000`, a 1,792 KiB primary slot at `0x020000`, a 1,792 KiB secondary slot at `0x1e0000`, two reserved 32 KiB LP-core image slots at `0x3a0000` and `0x3a8000`, 192 KiB storage at `0x3b0000`, 124 KiB scratch at `0x3e0000`, and 4 KiB coredump at `0x3ff000`. The course does not use the LP-core slots and must not repurpose them. Keep this map in one checked-in devicetree include and assert every offset and size in CI. A bootloader larger than 64 KiB or an application that does not fit its slot is a build failure, not a reason to change the map inside a tier.

**Implementation requirement.** Use MCUboot swap-with-scratch, not overwrite-only or direct-XIP mode. Enable `BOOT_SWAP_USING_SCRATCH`, `BOOT_VALIDATE_SLOT0`, and one updateable image. Starting in Tier 3, use ECDSA P-256 image signatures. Starting in Tier 4, enable `MCUBOOT_DOWNGRADE_PREVENTION` and `MCUBOOT_DOWNGRADE_PREVENTION_SECURITY_COUNTER`. Put the same security-counter value in the signed MCUboot image TLV and the signed Release manifest. The human-readable firmware version stays separate. A candidate counter may equal the confirmed image counter for an ordinary feature release, but it may never be lower. This is software downgrade prevention because a physical attacker can replace boot state.

**Implementation requirement.** The application writes only to the secondary slot, requests `BOOT_UPGRADE_TEST`, and never requests a permanent upgrade. MCUboot owns the scratch swap, trial boot, and revert state. The application calls `boot_write_img_confirmed()` only after the local health gate passes. There is no separate application-managed accepted-counter database, so a failed trial can revert to the previously confirmed image without a newer counter making that image ineligible. Power-cut tests cover download, trailer update, every swap phase, first boot, health checking, confirmation, and the first reboot after confirmation.

### Advanced hardware-rooted model

**Validation gate.** ESP32-C6 Secure Boot v2 authenticates the manually integrated MCUboot Espressif bootloader, and MCUboot authenticates the signed Zephyr application image. The exact ROM-to-application chain must be tested on the selected physical board before the course calls it supported rather than experimental. Flash encryption uses a separate hardware key and is an advanced confidentiality control that does not replace image signing or secure boot.

**Implementation requirement.** Advanced Tier A treats bootloader signing keys and firmware release-signing keys as two independent rotation exercises. For the Secure Boot v2 bootloader key, provision current and next public-key digests in separate unused eFuse slots, boot a MCUboot image signed by the next key, prove signed recovery with that key, and only then revoke the old digest. For the release key, use a reviewed custom Zephyr `keys.c` that contains the old and next ECDSA P-256 image-verification public keys. First install a Secure Boot v2-authenticated transition MCUboot that accepts images signed by either release key. Then install and confirm a transition application signed by the old key that trusts both old and next Release-manifest verification keys. Publish a migration Release manifest signed by the old key that points to an image signed by the next key. After that image confirms and proves it accepts a manifest signed by the next key, install a Secure Boot v2-authenticated MCUboot that accepts only the next image key and a later application that trusts only the next manifest key. The old key is not revoked from either verifier before both next-key paths pass. These procedures are hands-on only after physical-board validation proves power-loss recovery at each step. Otherwise the module uses captured evidence as a guided analysis and makes no successful-rotation claim.

### Firmware confidentiality

Firmware confidentiality is not required in the core course. Core images may be stored unencrypted but are transferred over authenticated HTTPS and must carry a valid MCUboot signature. The advanced module distinguishes MCUboot encrypted-image transport from ESP32-C6 flash encryption, explains which image copies each mechanism protects, and never describes either mechanism as a substitute for authenticity.

### Anti-rollback

Every release has a monotonically increasing security counter that is separate from its human-readable version. The core course rejects images with a lower security counter through MCUboot and release policy, described as software-enforced downgrade protection, not protection against a physical attacker who can rewrite boot state. Hardware-backed anti-rollback is advanced and remains experimental until the ESP32-C6 eFuse behavior and the complete integrated boot chain have passed physical-board tests. A security counter is increased only when a release closes a security boundary that must not be reopened.

### Image installation and confirmation

A new image is downloaded to the secondary slot and verified before it is selected for test boot. MCUboot starts it as an unconfirmed test image. The application confirms the image only after boot-time integrity checks, required configuration and credentials, reference-product state handling, and a 60-second local health period succeed. A failed check or expired health timer leaves the image unconfirmed and triggers a controlled reboot. A watchdog resets a trial image that hangs before it can report failure. On the next boot, MCUboot reports the revert swap type and restores the last confirmed image. Loss of network service alone must not fail the local health gate or cause an endless revert loop, because local application health is separated from optional backend reachability.

### Recovery

The last confirmed image remains the normal recovery path. Configure MCUboot serial recovery on a dedicated UART with `MCUBOOT_SERIAL`, GPIO entry, `MCUBOOT_SERIAL_DIRECT_IMAGE_UPLOAD`, image-state commands, and no unrestricted network transport. The normal recovery exercise uploads a signed image to the secondary slot, marks it for test boot, and keeps the confirmed primary image available for revert. If no valid primary image remains, allow a physically present operator to upload a signed image to the primary slot; `BOOT_VALIDATE_SLOT0` must authenticate it before execution, and an interrupted upload must leave serial recovery re-enterable so the same operation can be retried. In the hardware-rooted model, recovery accepts only correctly signed artifacts and never requires disabling secure boot. Debug and ROM download restrictions are applied only after signed recovery has been demonstrated on the same disposable board. Signing-key backup and custody are manufacturer responsibilities, not a device feature.

### Irreversible controls

**Implementation requirement.** Learners use simulated or virtual eFuses first. Physical eFuse work requires a Mentor review gate, a labelled disposable board, a recorded pre-change eFuse state, and a command-by-command checklist. The Learner verifies signed boot and recovery before disabling debug access or restricting download modes. Examples use non-production keys generated for the lab. Secret key material is never committed to the repository, copied into course pages, or uploaded to the OTA service. Each irreversible exercise states the expected post-change state and the failure mode if a wrong value is burned.

Source: resolved decision ticket [#8](https://github.com/tkEmLogic/learning-cyber-security/issues/8), research ticket [#4](https://github.com/tkEmLogic/learning-cyber-security/issues/4).

## 7. OTA architecture

**Fixed decision.** The main OTA path is a small course-owned HTTPS service that runs on the Learner's computer. It teaches the complete update flow. It is not a production backend. The course compares it with Eclipse hawkBit, Mender MCU, and Golioth without requiring those services for the main labs.

### Release process and trust

The manufacturer creates a versioned firmware image on a release workstation. The offline firmware release-signing key signs the MCUboot image and the exact bytes of an immutable release manifest. The OTA service holds neither signing capability. The release manifest and its detached signature are uploaded together with the signed image. The service may choose which existing release a device receives but cannot create or modify a trusted release. TLS authenticates endpoints and protects data in transit, and it does not replace the release manifest signature, the MCUboot image signature, the image digest, or the anti-rollback policy. A compromised OTA service can deny updates or replay an old signed release, but it cannot forge a new accepted release, because the device's security counter prevents an accepted downgrade.

### Protocol and authentication

**Implementation requirement.** Use a small pull protocol over HTTPS 1.1 with these steps: the device requests an update assignment at boot, on a bounded schedule, and after a local manual request; the OTA service authenticates the device and returns either no update or a reference to an immutable release manifest and detached signature; the device downloads and verifies the release manifest before accepting its contents; the device streams the image to the secondary MCUboot slot using HTTP range requests for resume; the device verifies the completed image digest and lets MCUboot verify the image signature during the test-boot flow; the device reports update events and the final confirmed or reverted result.

**Fixed decision.** The final course path uses mutual TLS with one credential per device. The server certificate chains to a course-specific root installed during provisioning. The device certificate identifies the device to the service. A limited Bootstrap credential may be used only during the earlier enrollment exercise and is never the normal OTA credential. The service hostname and trust anchor are configured during provisioning. Certificate or hostname validation failures stop the update, and examples must never disable TLS verification.

### Status reporting path

**Implementation requirement.** The status beacon and update client use the same local service and one explicit event endpoint: `POST /v1/devices/{device_id}/events`. The JSON body contains `device_id`, `event_type`, `boot_id`, `event_sequence`, firmware version, security counter, simulated machine state, result, reason code, release identifier when applicable, and device-observed time when available. `boot_id` is a fresh random value for each boot and `event_sequence` increases during that boot. The service stores the authenticated identity, service receive time, and duplicate or out-of-order result with the append-only JSON Lines record. Device time is evidence, not an authorization input.

**Implementation requirement.** The status path hardens with the rest of the product. Tier 0 sends plaintext HTTP and the service trusts the body `device_id`, so interception and identity spoofing are demonstrable. Tier 2 adds server-authenticated HTTPS but still has no client identity. After Tier 6, the Factory identity is accepted only by claiming and controlled-recovery endpoints, not by normal status or update endpoints. Tier 7 requires an Operational identity for assignments, image downloads, and event submission. The service derives the authenticated device from the client certificate, requires it to equal the path and body identifier, checks the certificate and device record are active and in the expected ownership context, and rejects mismatches, revoked identities, replayed event tuples, and factory-only credentials with distinct reason codes.

### Release manifest

**Implementation requirement.** The release manifest is JSON. Its exact downloaded bytes are verified against a detached signature before parsing, avoiding a custom JSON canonicalization scheme. It contains at least a unique release identifier, the target board and hardware revision range, the human-readable firmware version, the monotonically increasing security counter, the image size and SHA-256 digest, the immutable image path, the release channel, and creation and support information needed by later evidence work. The device rejects an invalid signature, incompatible hardware, a lower security counter, an unexpected size, a digest mismatch, or an image it has already confirmed. The human-readable version never overrides the security counter.

### Discovery and rollout

Devices pull update assignments. The course does not require inbound device connections or push messaging. The service assigns releases by device identity and release channel. The course starts with one device, then demonstrates a small canary group followed by the remaining classroom devices. Rollout selection is deterministic and reviewable, and a device receives only one active target release at a time. Pausing a rollout prevents new assignments but does not revoke an image a device has already verified and started installing. Emergency withdrawal stops new assignments, and devices that must move away from a vulnerable version receive a newer signed release with a higher security counter.

### Download and failure handling

The image is streamed directly to the secondary slot and is not buffered fully in RAM. Download progress and the expected release identity are stored so a power or network interruption can resume safely. A resumed request uses an HTTP range and verifies that it still refers to the same immutable image. A changed release, invalid range response, excessive retry count, size mismatch, or digest mismatch discards the partial download and records a failure. Retry uses bounded exponential backoff with jitter, and normal reference-product behavior continues while no valid update is ready. After download, the existing boot trust decision controls test boot, bounded health checks, confirmation, and revert. A reverted device reports the failure after returning to the last confirmed image, and serial recovery remains the physically present fallback.

### Status and audit records

The device sends periodic `status.observed` events and update events for assignment received, download started, resumed, verified, rejected, test boot started, confirmed, and reverted. The local service stores append-only JSON Lines records for teaching and lab review. These records support investigation and course evidence, but the course does not claim they are tamper-proof production audit logs or a source of trusted device time.

### Local classroom setup

**Implementation requirement.** The OTA service runs locally in a container on the Learner's computer. The first release supports current Linux distributions with either Docker or Podman. Ubuntu 24.04 is the CI and reference environment, not the only supported host. The Learner's computer and the ESP32-C6 join the same Wi-Fi network. Setup includes a course-local certificate authority, server certificate, sample releases, and deterministic test data. The service binds only to the configured classroom interface by default. After dependencies and container images are installed, the core update exercises do not depend on an external cloud service. Test cases include a corrupted image, modified release manifest, expired or untrusted server certificate, interrupted download, replayed release, failed health check, and successful revert.

### Production features intentionally omitted

The teaching service omits high availability, multi-region distribution, large-fleet scheduling, multi-tenancy, billing, a production signing service, HSM integration, remote attestation, complex policy engines, bandwidth optimization, long-term analytics, regulatory reporting workflows, and production-grade disaster recovery. The course explains these omissions and never asks Learners to turn the small service into a production fleet-management backend.

### Comparison services

**Fixed decision.** Use Eclipse hawkBit and Mender MCU as self-hosted comparisons and Golioth as a managed free-usage comparison. Keep MCUboot verification in every comparison, because TLS protects the connection but does not replace signed images, signed release metadata, or anti-rollback policy.

| Option | Teaching value | Course role |
| --- | --- | --- |
| Eclipse hawkBit | Shows how a real self-hosted rollout service replaces course-built fleet logic. | Comparison exercise, not required for core labs. |
| Mender MCU with open-source Mender Server | Shows an integrated device identity, inventory, Artifact, and deployment model. | Comparison exercise, not required for core labs. |
| Golioth | Shows a polished Zephyr flow and a low-cost entry point, with an added cloud dependency. | Comparison exercise, not required for core labs. |

Full reports: [`research/ota-architectures.md`](https://github.com/tkEmLogic/learning-cyber-security/blob/research/ota-architectures/research/ota-architectures.md) on branch `research/ota-architectures`.

Key primary sources: [Zephyr OTA overview](https://docs.zephyrproject.org/latest/services/device_mgmt/ota.html), [MCUboot design](https://docs.mcuboot.com/design.html), [Zephyr hawkBit sample](https://docs.zephyrproject.org/latest/samples/subsys/mgmt/hawkbit/README.html), [Zephyr Mender MCU module](https://docs.zephyrproject.org/latest/develop/manifest/external/mender-mcu.html), and [Golioth OTA documentation](https://docs.golioth.io/device-management/ota/).

Source: resolved research ticket [#5](https://github.com/tkEmLogic/learning-cyber-security/issues/5), decision ticket [#9](https://github.com/tkEmLogic/learning-cyber-security/issues/9).

## 8. Device identity and provisioning lifecycle

**Fixed decision.** The course teaches a staged identity model. Shared credentials appear only in an explicit insecure development exercise in Hardening Tier 6. The core course ends with on-device key generation, a persistent Factory identity, and a separate rotatable Operational identity. Hardware-backed key isolation remains an advanced option in section 9.

### Identity roles

| Role | Purpose |
| --- | --- |
| Factory identity | Identifies one physical device to the manufacturer after Bootstrap-authorized enrollment. Used only for claiming and controlled recovery. |
| Operational identity | Authenticates the device to the OTA service with mutual TLS. Belongs to the current ownership context and can be rotated without changing the Factory identity. |
| Bootstrap credential | Authorizes only initial enrollment. Cannot download firmware or use normal device APIs. |
| Firmware signing key, boot key, server TLS key, CA key | Separate roles from every device identity key. |
| Owner credential | Authorizes a person. Not a device identity and never stored as the device's private key. |

### Teaching progression

**Implementation requirement.** Learners first observe why a shared credential permits cloning and fleet-wide compromise, using a credential generated locally for the exercise and never committed to the repository. The device then generates a unique private key with the platform random-number generator and proves possession through a certificate request. A provisioning station issues the Factory certificate after checking physical connection, device metadata, and a unique Bootstrap credential. At first installation, a physical action opens a short claim window. The device generates a separate operational key and requests an owner-scoped certificate while authenticated with its Factory identity. Normal OTA access uses only the operational certificate, and the Factory identity is not sent to the ordinary firmware-download endpoint. An advanced module may replace software-held private keys with a hardware-backed provider without changing the certificate and lifecycle model.

**Fixed decision.** Core certificate examples use ECDSA P-256, because it is widely supported by TLS tooling and can later map to an ECC secure element. An advanced hardware provider may use another supported algorithm, such as the ESP32-C6 Digital Signature peripheral's RSA path, if the same lifecycle and separation of roles are preserved.

### Key generation and storage

Factory and operational private keys are generated on the device, and only public keys and certificate requests leave it. The core course stores them through Zephyr 4.4.2 PSA Secure Storage. Enable `SECURE_STORAGE`, `SECURE_STORAGE_ITS_IMPLEMENTATION_ZEPHYR`, `SECURE_STORAGE_ITS_TRANSFORM_IMPLEMENTATION_AEAD`, `SECURE_STORAGE_ITS_TRANSFORM_AEAD_SCHEME_AES_GCM`, `SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_PROVIDER_DEVICE_ID_HASH`, `SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS`, `SETTINGS`, and `SETTINGS_NVS`, and size `SECURE_STORAGE_ITS_MAX_DATA_SIZE` for the encoded P-256 private key and metadata. Use the fixed `storage` partition from section 6. NVS supplies persistence; the Secure Storage transform supplies encryption and authentication. The course never calls NVS itself encrypted.

**Fixed limitation.** On ESP32-C6, the default device-ID-hash provider derives from a readable MAC-based identifier. It can deter casual offline inspection and detect unauthenticated record changes, but it is not a protected root secret, does not prevent record replay, and does not protect keys from privileged firmware, a debugger, or a capable flash attacker. The Tier 6 Weakness ledger keeps these risks open. Private keys are marked non-exportable at the course API boundary even though the core storage cannot enforce that property against compromised privileged firmware. Advanced Tier B replaces this boundary with STSAFE-A120 key isolation. A production design must instead validate a custom provider rooted in protected device-specific hardware or another reviewed secure-storage design.

No private key, Bootstrap secret, or reusable development credential is written to source control, course pages, OTA logs, or manufacturing records.

### Trust anchors and certificate authorities

**Implementation requirement.** Use three distinct trust relationships: a manufacturer device CA that signs Factory identities and is trusted by the enrollment and recovery service; an operational device CA that signs Operational identities and is trusted by the OTA service, which checks the device record and certificate status on every connection; and a service CA that signs the OTA service certificate, whose trust anchor is provisioned on the device. For local labs, course setup creates throwaway local CAs and records their fingerprints. The local course CA is never presented as a production certificate authority.

Server trust-anchor rotation uses an overlap: a signed firmware release installs the current and next service roots, the service moves to a certificate under the next root, devices demonstrate successful connection, and a later signed release removes the retired root. The device never disables certificate or hostname verification to recover from a trust-anchor error.

### Manufacturing record

The provisioning record contains the device identifier and hardware revision, the Factory certificate serial number, fingerprint, and public key, provisioning time, station identity, and result, the Bootstrap credential state stored as a verifier rather than plaintext, and the current lifecycle state: manufactured, claimed, active, transferred, revoked, or decommissioned. It never contains device private keys, and each provisioning attempt and state change is append-only for the course evidence exercises.

### Initial enrollment and claiming

Each device receives a unique, high-entropy Bootstrap credential through a channel separate from its normal network traffic. The service stores only the verifier needed to check it. The credential is limited to one device, the Factory-enrollment purpose, a short validity period, and one successful use. At the provisioning station, the device generates its Factory key and submits a certificate request with the Bootstrap credential. The station checks physical connection and device metadata, verifies proof of possession, issues the Factory certificate, and atomically marks the Bootstrap credential consumed. A consumed Bootstrap credential can never authorize claiming, recovery, firmware download, or a second enrollment.

**Implementation requirement.** Claiming is a separate two-party transition. A documented physical action opens a ten-minute Claim window and causes the device to generate a random one-use claim nonce and a new Operational key. The device authenticates to the claim endpoint with its Factory identity and submits the Operational certificate request plus the nonce. The Customer operator authenticates to the local service with an Owner credential and submits the matching device identifier and nonce. The service binds the nonce to the Factory certificate, device lifecycle state, and owner session, rejects expired, replayed, mismatched, already-owned, revoked, or decommissioned claims, and records every result. Only when both halves match does it issue the owner-scoped Operational certificate, record the owner association, and close the Claim window. Repeated failures trigger bounded backoff and a visible error rather than a silent fallback to a shared credential.

### Rotation and renewal

Operational certificates are short-lived relative to the five-year support period and are renewed before expiry. Renewal creates a new key pair and certificate, and the current operational identity authenticates the request. The old and new certificates overlap for a bounded period, and the device proves the new identity works before the old certificate is revoked. If routine renewal fails, the device keeps its current valid identity, reports the failure, and retries with bounded backoff. The Factory identity is long-lived but not assumed permanent, and its replacement requires the controlled recovery flow and an updated manufacturing record.

### Revocation

The OTA service rejects a revoked operational certificate and a device marked revoked, even if the certificate has not expired. Revoking an operational identity stops normal OTA access but does not erase the persistent Factory identity. A stolen or hostile device can have both its operational and Factory identities blocked by policy. The course uses server-side certificate status for device credentials and does not require the constrained device to operate a full public PKI revocation client.

### Recovery

Loss or corruption of the operational identity requires physical presence, the Factory identity, and explicit service authorization to open a recovery claim window. Recovery generates a new operational key and never restores a copied private key from the backend. Loss or compromise of the Factory identity requires authorized serial re-provisioning, and there is no universal remote recovery credential. If neither identity can be trusted and authorized re-provisioning is unavailable, the device is decommissioned rather than silently admitted with a shared secret. Firmware recovery and identity recovery are separate procedures.

### Ownership transfer

**Implementation requirement.** Revoke the old operational certificate and remove the old owner's authorization, clear owner-specific configuration and queued owner data, require physical action to open a new claim window, generate a new operational key pair rather than reusing the old owner's key, issue a certificate bound to the new ownership context, and keep the Factory identity and manufacturing history unchanged. A transfer never resets firmware anti-rollback state or permits installation of an older release.

### Decommissioning

**Implementation requirement.** Revoke operational and Factory access at the services, mark the device identifier as decommissioned so old certificates and Bootstrap credentials cannot enroll it again, remove operational keys, owner configuration, Wi-Fi credentials, and customer data where the hardware permits reliable erasure, and retain only the manufacturing, support, vulnerability, and decommissioning records required by policy. Re-entry requires an explicit remanufacturing process with a new lifecycle record. A normal factory reset is not enough.

### Development and production boundary

The repository may include scripts that create disposable local CAs, Bootstrap credentials, and sample device records. Generated secrets stay outside version control and are resettable for labs. A defensible production process additionally needs controlled manufacturing stations, protected CA keys, operator authorization, hardware-backed storage where justified, issuance monitoring, certificate inventory, revocation operations, disaster recovery, and audited handling of rejected or scrapped devices. Those operational systems are explained but not implemented by this course.

Full report: [`research/device-identity-and-provisioning.md`](https://github.com/tkEmLogic/learning-cyber-security/blob/research/provisioning/research/device-identity-and-provisioning.md) on branch `research/provisioning`.

Key primary sources: [ESP32-C6 Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/security/secure-boot-v2.html), [ESP32-C6 eFuse Manager](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html), [Zephyr binary signing](https://docs.zephyrproject.org/latest/build/signing/index.html), [MCUboot imgtool](https://github.com/mcu-tools/mcuboot/blob/main/docs/imgtool.md), [EST, RFC 7030](https://www.rfc-editor.org/rfc/rfc7030.html), and [BRSKI, RFC 8995](https://www.rfc-editor.org/rfc/rfc8995.html).

Source: resolved research ticket [#6](https://github.com/tkEmLogic/learning-cyber-security/issues/6), decision ticket [#10](https://github.com/tkEmLogic/learning-cyber-security/issues/10).

## 9. Secure element advanced module: STSAFE-A120

**Fixed decision.** STSAFE-A120 is an optional advanced hands-on module, not a core-course dependency. If the pinned hardware and integration scaffold have not passed course validation, the module becomes a guided comparison exercise instead of asking Learners to debug an unproven port.

### Why it is advanced

The secure element lets the operational identity private key be generated and used inside a separate component without exporting it to ESP32-C6 flash or application memory. This reduces copied-key cloning, accidental key disclosure, and some key-extraction risks after MCU or flash access. It is not suitable for the core path because upstream Zephyr has no STSAFE-A120 driver, the available third-party driver needs an ESP32-C6 port, and mutual TLS needs a bridge between the TLS stack and secure-element signing operations.

### Prerequisites

A Learner starts this module only after completing the software-protected identity path with a working Operational identity in the limited PSA Secure Storage configuration from section 8, mutual TLS authentication to the local OTA service, a documented identity lifecycle covering enrollment, rotation, revocation, recovery, transfer, and decommissioning, and an explanation of the software-held key's security boundary. The advanced module reuses the same Operational identity lifecycle and changes only the private-key provider.

### Required hardware and scaffold

**Implementation requirement.** One ESP32-C6 development kit, one STSAFE-A120 board or module with documented wiring and power requirements, a pinned STSAFE-A120 middleware or library version and its license information, a pinned Zephyr-compatible driver layer for I2C transport, initialization, zones, key slots, and signing, a TLS private-key provider bridge that lets the selected TLS stack request signatures without receiving private-key bytes, provisioning and inspection tools that expose public metadata without printing secrets, and known-good certificates, service configuration, failure fixtures, and cleanup instructions.

### Hands-on learning sequence

**Implementation requirement.** Capture a baseline showing where the software-protected operational key is stored and which privileged software can access it. Connect and identify STSAFE-A120 over I2C and record its identity, lifecycle state, and configured access conditions. Generate a new operational identity key inside STSAFE-A120, never returning the private key to the ESP32-C6. Export only the public key or certificate request and enroll it through the existing operational identity flow. Configure the TLS private-key provider and authenticate to the OTA service with mutual TLS. Rotate from the software-held operational certificate to the secure-element-backed certificate with a bounded overlap. Attempt the extraction exercise and show the application can retrieve or misuse the software-held key in the baseline while it cannot export the STSAFE-A120 private key. Demonstrate that authorized application code can still ask the secure element to sign, and explain why private-key isolation does not stop a compromised application from abusing the signing interface. Trigger I2C disconnection, denied-slot access, invalid certificate, and revoked-certificate cases, confirming that failures are visible and do not fall back to the old software key. Revoke the advanced operational certificate and return the device to a known lifecycle state.

### Completion evidence

The module's lab artifact must include a trust-boundary diagram before and after the change, the secure-element slot and access policy without secret material, proof that the public key in the operational certificate matches the key used by STSAFE-A120, a successful mutual TLS session whose private-key operation used the secure element, the blocked private-key export attempt, evidence that a compromised or authorized application can still request a signature, results from I2C loss, authorization failure, certificate revocation, and no-fallback tests, and a short threat comparison stating which risks were reduced, unchanged, or added.

### Security claims permitted and prohibited

**Fixed decision.** The course may say that STSAFE-A120 isolates selected private keys from normal MCU flash and application memory, performs supported cryptographic operations without exporting those private keys, makes simple copied-key cloning and accidental key leakage harder, and creates a separate hardware and I2C trust boundary that can be inspected and tested. The course must never say that STSAFE-A120 establishes the ESP32-C6 secure-boot chain, protects firmware integrity or replaces MCUboot image verification, prevents compromised firmware from requesting signatures, authenticates the OTA server or authorizes a device by itself, solves certificate issuance, rotation, revocation, ownership transfer, or backend compromise, or protects against every invasive physical or fault-injection attack.

### New risks and operational costs

The module explicitly covers additional hardware cost, board availability, wiring errors, I2C fault handling, middleware and licensing constraints, provisioning complexity, key-slot exhaustion, access-condition mistakes, certificate-to-slot inventory, and secure-element replacement or failure. The course never presents separate hardware as automatically more secure in every product.

### Validation gate and fallback

**Validation gate.** Before publishing the module as hands-on, course maintainers must validate the pinned scaffold on the exact ESP32-C6 and STSAFE-A120 hardware, including key generation, certificate enrollment, mutual TLS, repeated reboot, credential rotation, revocation, I2C failure, and cleanup or repeatability on fresh hardware. If any required path is unreliable, undocumented, legally unsuitable for redistribution, or cannot be reproduced from a clean setup, the course publishes the same material as a guided comparison using captured traces and artifacts from a known-good run, without requiring Learners to complete the custom integration.

Full report: [`research/stsafe-a120.md`](https://github.com/tkEmLogic/learning-cyber-security/blob/research/stsafe-a120/research/stsafe-a120.md) on branch `research/stsafe-a120`.

Key primary sources: ST data sheet DS14164 Rev. 2, STSELib v1.1.9, STSAFE-A SDK v1.0.4, Zephyr v4.4.2 secure sockets, ESP-IDF v5.5.2 ESP32-C6 security docs, CATIE driver commit `5b7f1243`, and wolfSSL example commit `407922b`.

Source: resolved research ticket [#7](https://github.com/tkEmLogic/learning-cyber-security/issues/7), decision ticket [#11](https://github.com/tkEmLogic/learning-cyber-security/issues/11).

## 10. Security evidence model

**Fixed decision.** The course uses a living security evidence pack. Each lab adds or updates versioned engineering artifacts in one connected record. The pack links security claims to requirements, controls, tests, results, residual risks, and primary-source references. It supports engineering and Mentor review. It never proves CRA conformity, replaces legal review, or claims certification.

### Evidence model

Use five linked concepts: a security claim states a specific property or lifecycle behavior that reviewers can challenge; a security requirement states what the reference product must do to support one or more claims; a control describes the design or process selected to meet a requirement; evidence records what was inspected, executed, or observed and the result; and a residual risk records what remains, why it remains, who owns it, and its planned treatment or acceptance.

Every claim has one status: supported, when the required evidence exists and passed its acceptance criteria; partly supported, when some evidence exists but a stated gap remains; unsupported, when evidence failed or has not been produced; or not applicable, when the claim is outside the reference product scope with a recorded reason. A document's existence is not evidence that its claims are true.

### Required artifact set

| Group | Contents |
| --- | --- |
| Product and risk definition | Product description, asset and actor model, misuse and failure scenarios, risk register, explicit scope and assumptions. |
| Security requirements and architecture | Numbered requirements with rationale and acceptance criteria, trust-boundary and data-flow diagrams, control rationale, boot and firmware trust model, OTA architecture, identity and key-management design, advanced-module boundary. |
| Software and dependency evidence | Machine-generated SBOM, human-readable dependency inventory, build manifest, known-vulnerability scan result, review of unresolved matches and exceptions. |
| Release and update evidence | Approved release manifest and signature, MCUboot signature-verification result, image digest and size, release approval record, update-assignment and download and test-boot and confirmation and revert records, negative-test results, proof the OTA service cannot create a newly trusted release. |
| Identity and lifecycle evidence | Manufacturing and provisioning record, certificate inventory, proof-of-possession and mutual TLS records, Bootstrap credential consumption result, renewal and rotation and revocation evidence, ownership-transfer and decommissioning records, recovery test evidence. |
| Security verification evidence | Security test plan linking tests to requirements and claims, automated test results, manual inspection checklists, negative tests, Mentor review findings, hardware-validation records. |
| Vulnerability and support evidence | Coordinated vulnerability disclosure policy, intake and triage workflow, timed Article 14 reporting exercise, support statement, security-update policy, user security information, decommissioning statement. |
| CRA traceability | Matrix linking CRA duties and Annex I topics to product assumptions, requirements, controls, evidence, status, residual risks, responsible role, legal source, and whether legal review is required. |

### Artifact format and metadata

**Implementation requirement.** Each artifact has a stable path and identifier, an owner and reviewer, a product or release scope, a revision and status, creation and last-review dates, source versions and access dates where external facts are used, links to upstream and downstream artifacts, and known limitations and open findings. Markdown is the reviewable source for human-authored material. Diagrams use a text-based source where practical. Generated SBOMs, signatures, manifests, test reports, and logs remain machine-readable. Secrets, private keys, live Bootstrap credentials, access tokens, and personal data are excluded. Evidence uses fingerprints, redacted examples, synthetic identifiers, or locally generated disposable credentials.

### Traceability rules

**Implementation requirement.** Every in-scope security requirement links to at least one security claim and one verification method. Every implemented control links to its requirements and threat or risk rationale. Every supported claim links to passing evidence. Every failed or missing result creates an open finding or residual risk and cannot be omitted. Every release links to its exact source revision, build manifest, SBOM, release manifest, signature evidence, test results, and approval record. Changes to threats, requirements, controls, dependencies, keys, update behavior, or support policy trigger review of affected links. Advanced experimental claims remain partly supported until physical-hardware validation passes.

### Lab and Mentor review use

Each lab produces a small lab artifact and updates only the affected parts of the security evidence pack. Learners do not rewrite a final report after every exercise. A Mentor review gate samples both a successful claim and an uncomfortable edge case. The Learner explains the evidence chain, reproduces or interprets a failure, identifies the security boundary, and states residual risk. Mentor approval records that the review occurred and its findings. It is not a legal sign-off. See section 13.

### Quality checks

**Implementation requirement.** The scaffold requires automated checks where practical for missing artifact identifiers or required metadata, broken internal links, requirements without verification methods, supported claims without passing evidence, evidence without a recorded source revision or environment, releases without an SBOM or build manifest, CRA traceability rows without a source and access date, and secret patterns or accidental private-key files. Automated checks improve consistency but never replace technical review.

### Legal and assurance boundary

The security evidence pack shows how the reference product was reasoned about and tested. It is a useful input to a product-specific conformity process. It does not establish the finished product's legal classification, identify every applicable EU regime, select a conformity-assessment route, validate production controls, prove completeness, or authorize an EU declaration of conformity.

Source: resolved decision ticket [#12](https://github.com/tkEmLogic/learning-cyber-security/issues/12).

## 11. Hardening tier progression

**Fixed decision.** The whole course is cumulative hardening tiers. The Learner first builds and attacks a completely unsecured but functional reference product. Each later tier adds one focused security control or lifecycle capability, repeats relevant attacks, records what changed, and updates the security evidence pack. The insecure baseline runs only on an isolated local lab network with disposable credentials and synthetic data, and course text labels unsafe configurations clearly and never presents them as deployment defaults.

### Progression rules

**Implementation requirement.** Control tiers use this loop: start from the runnable result of the previous tier; predict one or more attacks or failures that should still succeed; run the attack and capture the insecure behavior; add one focused control or lifecycle capability; rerun the original attack and verify the new rejection or recovery behavior; try at least one bypass, misuse, or operational failure; state what the control does not protect; update the security claim, requirement, test evidence, and residual risk in the security evidence pack. Each tier is a stable runnable state, not a collection of unrelated exercises. Later tiers retain the controls from earlier tiers unless the lab explicitly demonstrates a rollback or misconfiguration.

**Fixed decision.** Tier 0 is the baseline variant: it builds the insecure product and proves that the selected attacks succeed, without claiming an after-hardening result. Tier 1 is the analysis variant: it reruns selected Tier 0 observations, converts them into threats, requirements, claims, and planned controls, and records no runtime security improvement. Tiers 2 through 9 and Advanced Tiers A and B are control or lifecycle variants and use the full before-and-after loop. Tier 10 is the integration variant: it validates and repairs the accumulated controls rather than introducing one new control. The module and acceptance rules in sections 12, 14, and 22 use these four variants explicitly.

### Core hardening tiers

#### Tier 0: Build the unsecured reference product

| Field | Detail |
| --- | --- |
| Prerequisites | Embedded C experience, basic Zephyr build and flash skills, ESP32-C6 development kit, local Wi-Fi. |
| Learning result | Establish a working baseline and identify that functional behavior is not secure behavior. |
| Threat shown | Any local network actor can inspect traffic, impersonate the service, and provide arbitrary firmware. Any device can claim another device's identifier. |
| Hands-on task | Build the status beacon, run a local HTTP OTA service, use unsigned MCUboot images, disable image-signature checks, release-manifest signatures, anti-rollback checks, TLS, server authentication, device authentication, secure credential storage, test-boot confirmation, and security event records. Use a mutable version record and a shared development identifier. Install an altered image supplied by the attack fixture. |
| Success criteria | Beacon behavior and an OTA update work. Captured traffic is readable. The altered unsigned image is accepted and runs. |
| Failure criteria | The Learner cannot reproduce the insecure update, or hidden security defaults prevent the baseline from showing the intended failure. |
| Mentor review gate | None. The environment remains isolated and disposable. |
| Lab artifact | Baseline architecture diagram, captured HTTP exchange, accepted-image record, and list of deliberately absent controls. |
| Expected time | 3 hours. |

**Implementation requirement.** The scaffold keeps the later slot layout and protocol shape where practical so Learners harden the same product instead of rebuilding it. The baseline may use MCUboot's unsigned mode for update mechanics but makes no authenticity claim and is described as having no trusted boot or firmware-verification boundary.

#### Tier 1: Model the product and its risks

| Field | Detail |
| --- | --- |
| Prerequisites | Tier 0. |
| Learning result | Connect observed insecure behavior to assets, actors, trust boundaries, requirements, and residual risk. |
| Threat shown | Teams add controls without agreeing on what they protect or which attacker they address. |
| Hands-on task | Build the threat model, misuse scenarios, initial risk register, security claims, and numbered requirements from the Tier 0 observations. |
| Success criteria | Each selected future control has a threat and requirement rationale. Scope and excluded threats are explicit. |
| Failure criteria | Requirements name technologies without describing a security property or observable acceptance criterion. |
| Mentor review gate | Required readiness gate before implementation-heavy tiers. See section 13. |
| Lab artifact | Initial security evidence pack with product definition, threat model, risks, claims, and requirements. |
| Expected time | 3 hours. |

#### Tier 2: Authenticate and encrypt the server connection

| Field | Detail |
| --- | --- |
| Prerequisites | Tier 1. |
| Learning result | Explain exactly what authenticated HTTPS protects and what it does not. |
| Threat shown | Local eavesdropping, network modification, and service impersonation. |
| Hands-on task | Add HTTPS, a course-local service CA, server certificate validation, and hostname validation. Keep device authentication, release metadata, and firmware images otherwise unsecured. |
| Success criteria | Normal update discovery works over HTTPS. Packet capture no longer reveals the firmware or metadata. Untrusted and hostname-mismatched service certificates are rejected. |
| Failure criteria | Examples disable certificate verification, or the Learner claims TLS makes an image authentic after a trusted service is compromised. |
| Mentor review gate | None. |
| Lab artifact | Before-and-after packet evidence, certificate-validation tests, updated trust-boundary diagram, and residual risk for a compromised trusted service. |
| Expected time | 3 hours. |

#### Tier 3: Require authentic firmware images

| Field | Detail |
| --- | --- |
| Prerequisites | Tier 2. |
| Learning result | Separate transport trust from firmware publisher trust. |
| Threat shown | A compromised or misconfigured trusted OTA service supplies an altered or unsigned image. |
| Hands-on task | Create an offline course release-signing key, configure a real MCUboot signature type, sign images, and reject unsigned, modified, and incorrectly signed images. Keep the core course's software-rooted bootloader limitation explicit. |
| Success criteria | Correctly signed images install. Altered, unsigned, wrong-key, and truncated images do not boot. |
| Failure criteria | The signing key is placed on the OTA service or committed to Git, or the Learner describes standard Zephyr MCUboot as a hardware-rooted chain on ESP32-C6. |
| Mentor review gate | Required firmware-trust gate. |
| Lab artifact | Key-role diagram, signing and verification records, negative-test results, and updated claim status. |
| Expected time | 4 hours. |

#### Tier 4: Protect release metadata and block downgrade

| Field | Detail |
| --- | --- |
| Prerequisites | Tier 3. |
| Learning result | Explain why an authentic image can still be the wrong image. |
| Threat shown | Replay of an old signed image, incompatible hardware assignment, mutable metadata, and version-policy mistakes. |
| Hands-on task | Add the offline-signed immutable release manifest, image digest and size, hardware compatibility, version, security counter, and device-side downgrade policy. |
| Success criteria | A valid current release installs. Modified manifests, replayed lower counters, incompatible hardware, digest mismatch, and unexpected size are rejected with distinct reasons. |
| Failure criteria | Human-readable versions override the security counter or the OTA service can modify trusted release metadata. |
| Mentor review gate | None. |
| Lab artifact | Release manifest and signature, version-policy decision table, rejection records, and traceability updates. |
| Expected time | 4 hours. |

#### Tier 5: Make installation recoverable

| Field | Detail |
| --- | --- |
| Prerequisites | Tier 4. |
| Learning result | Treat update availability and safe recovery as security properties. |
| Threat shown | Power loss, network loss, corrupted partial download, crashing release, premature confirmation, and unrecoverable installation. |
| Hands-on task | Add resumable range downloads to the secondary slot, persisted progress, bounded retry, MCUboot test boot, a 60-second local health gate, watchdog reset for a hung trial image, controlled reboot on failed or expired health, confirmation, revert, and serial recovery instructions. |
| Success criteria | Interrupted downloads resume safely. A healthy release confirms. A crashing, hung, failed-health, or health-timeout release reboots and then reverts to the last confirmed image. Network loss alone does not cause an endless revert loop. |
| Failure criteria | Partial data is accepted, an image confirms before required checks, or recovery disables signature checks. |
| Mentor review gate | Required update-recovery gate. |
| Lab artifact | Update state diagram, interruption matrix, confirmation and revert logs, recovery record, and residual availability risks. |
| Expected time | 4 hours. |

#### Tier 6: Replace shared identity with per-device factory identity

| Field | Detail |
| --- | --- |
| Prerequisites | Tier 5. |
| Learning result | Show why a shared fleet credential permits cloning and why possession must be device-specific. |
| Threat shown | One extracted shared credential impersonates every device. |
| Hands-on task | First clone the shared development identity. Then generate a device key on the ESP32-C6, enroll a Factory certificate with a unique Bootstrap credential, store the key through the limited PSA Secure Storage configuration in section 8, consume the Bootstrap credential, and record the manufacturing state without private-key material. |
| Success criteria | The cloned shared identity works before hardening. After hardening, the duplicate is rejected and the enrolled device proves possession of its unique key. |
| Failure criteria | The backend stores the private key, a reusable default credential remains active, or failed enrollment silently falls back to shared identity. |
| Mentor review gate | None. |
| Lab artifact | Clone demonstration, provisioning record, certificate fingerprint, proof-of-possession evidence, and storage-boundary analysis. |
| Expected time | 4 hours. |

#### Tier 7: Add owner-scoped operational identity and mutual TLS

| Field | Detail |
| --- | --- |
| Prerequisites | Tier 6. |
| Learning result | Separate manufacturer recovery identity, routine device identity, and human authorization. |
| Threat shown | Factory credentials are overused for normal service access, or an unclaimed device joins the OTA service without physical authorization. |
| Hands-on task | Authenticate the Customer operator with an Owner credential, open a physical Claim window, match the owner request to the device's one-use claim nonce and Factory-authenticated request, generate an Operational key, issue an owner-scoped Operational certificate, configure mutual TLS, and restrict assignment, image-download, and status-event endpoints to valid Operational identities. |
| Success criteria | The claimed device receives update assignments and submits status events. An unclaimed device, replayed or expired claim nonce, revoked certificate, Factory-only identity, body or path identifier mismatch, and wrong-owner claim are rejected. |
| Failure criteria | The Factory identity can use the ordinary download endpoint or certificate and hostname validation are disabled. |
| Mentor review gate | Required identity-boundary gate. |
| Lab artifact | Claim sequence, certificate-role inventory, mutual TLS evidence, authorization tests, and updated lifecycle model. |
| Expected time | 4 hours. |

#### Tier 8: Operate the credential lifecycle

| Field | Detail |
| --- | --- |
| Prerequisites | Tier 7. |
| Learning result | Treat identity as an operational lifecycle rather than a one-time provisioning task. |
| Threat shown | Expired, stolen, copied, old-owner, or undecommissioned credentials retain access. |
| Hands-on task | Renew with a new key, overlap and rotate certificates, revoke an operational identity, recover through physical presence and Factory identity, transfer ownership, and decommission a device. |
| Success criteria | The new identity works before the old one is retired. Revoked and old-owner certificates fail. Transfer preserves Factory history and anti-rollback state. Decommissioned identities cannot re-enroll normally. |
| Failure criteria | Recovery uses a universal secret, restores a copied backend key, or a factory reset silently reverses decommissioning. |
| Mentor review gate | None unless combined with Tier 7 by course scheduling. |
| Lab artifact | Lifecycle event records, rotation and revocation tests, transfer record, decommissioning statement, and residual risks. |
| Expected time | 4 hours. |

#### Tier 9: Manage dependencies, vulnerabilities, and support

| Field | Detail |
| --- | --- |
| Prerequisites | Tier 8. |
| Learning result | Connect product security to dependencies, vulnerability response, security updates, support commitments, and CRA-related engineering evidence. |
| Threat shown | Unknown components, unreviewed vulnerabilities, delayed reporting, unsupported devices, and unavailable fixes. |
| Hands-on task | Generate and review the firmware and OTA-service SBOMs, scan known vulnerabilities, triage a prepared report, create a signed remediation release, exercise release withdrawal and canary rollout, draft the coordinated vulnerability disclosure process, run separate timed Article 14 scenarios for an actively exploited vulnerability and a severe incident, and complete support and user-security statements. |
| Success criteria | The release links to source, build manifest, SBOM, tests, signatures, and approval. For both reporting scenarios, the Learner records awareness and classification, produces the 24-hour and 72-hour submissions, selects the correct event-specific final deadline, drafts user communication, and marks legal-review boundaries. |
| Failure criteria | Scanner output is accepted without triage, a fix is shipped outside the signed release path, or the evidence claims conformity. |
| Mentor review gate | Required lifecycle and evidence gate. |
| Lab artifact | SBOM review, vulnerability record, remediation release evidence, reporting exercise, support statement, user information, and CRA traceability update. |
| Expected time | 5 hours. |

#### Tier 10: Defend the integrated reference product

| Field | Detail |
| --- | --- |
| Prerequisites | Tiers 0 through 9. |
| Learning result | Demonstrate the complete security architecture, diagnose failures, and explain remaining limits. |
| Threat shown | A mixed attack campaign combines service impersonation, malicious hosting, replay, interruption, credential misuse, bad release health, and operator error. |
| Hands-on task | Start from the hardened device and process a prepared scenario containing both real attacks and operational failures. Produce and deploy one corrected release through a canary assignment, confirm healthy devices, recover a failed test boot, and update the evidence pack. |
| Success criteria | The Learner identifies each security boundary, predicts the responsible control, gathers evidence, avoids unsafe bypasses, restores a known-good state, and states residual risks. |
| Failure criteria | The Learner treats all failures as TLS problems, bypasses verification to recover, loses the last confirmed image, or hides failed evidence. |
| Mentor review gate | Required core-course completion gate. |
| Lab artifact | Incident timeline, diagnostic evidence, corrected release record, canary result, recovery proof, final claim matrix, and residual-risk summary. |
| Expected time | 5 hours. |

**Fixed decision.** The expected core hands-on time is about 43 hours. Reading, setup variation, Mentor scheduling, and optional extension work are additional.

### Advanced hardening tiers

#### Advanced Tier A: Add a hardware-rooted boot chain and confidentiality

| Field | Detail |
| --- | --- |
| Prerequisites | Core Tier 10 and disposable hardware. |
| Learning result | Compare software-rooted image verification with ESP32-C6 Secure Boot v2 and flash encryption. |
| Threat shown | A physical attacker replaces the software-rooted bootloader or reads flash contents. |
| Hands-on task | Use virtual eFuses first, then the validated manually integrated MCUboot Espressif port on labelled disposable hardware. Enable signed recovery before restricting debug or download modes. Add flash encryption as a separate confidentiality control. Run the separate bootloader-signing-key and firmware-release-key rotation sequences from section 6. |
| Success criteria | The exact ROM-to-application chain and signed recovery pass on physical hardware. Invalid boot components fail. Flash contents are not directly readable as plaintext through the tested path. Both key rotations preserve a bootable signed recovery path, and the retired key is rejected only after the next key is proven. |
| Failure criteria | Irreversible controls are applied before recovery is proven or the course claims unvalidated upstream support. |
| Mentor review gate | Mandatory before and after physical eFuse changes. |
| Lab artifact | Pre-change eFuse state, approved checklist, boot-chain evidence, recovery proof, confidentiality test, and remaining physical-attack limits. |
| Expected time | 6 to 8 hours after the scaffold is validated. |

#### Advanced Tier B: Isolate operational identity in STSAFE-A120

| Field | Detail |
| --- | --- |
| Prerequisites | Core Tier 10 and the validated secure-element scaffold. |
| Learning result | Compare software-held private keys with a non-exportable secure-element key while recognizing signing-oracle limits. |
| Threat shown | Key extraction from MCU storage and misuse by compromised application code. |
| Hands-on task | Follow the sequence in section 9: generate the key inside STSAFE-A120, enroll it, use it for mutual TLS, test extraction, request authorized signatures, handle I2C failures, rotate, and revoke. |
| Success criteria | Mutual TLS uses the secure element. Private-key export fails. Signing requests still work. Service revocation and no-fallback behavior pass. |
| Failure criteria | The software key remains as a silent fallback or the Learner claims the secure element prevents compromised firmware from signing. |
| Mentor review gate | Required advanced-module completion gate. |
| Lab artifact | Before-and-after boundary diagrams, secure-element evidence, failure records, and threat comparison. |
| Expected time | 6 to 8 hours. Use the guided comparison fallback when hardware validation has not passed. |

### Course and repository implications

**Implementation requirement.** Course pages, code states, fixtures, tests, and evidence templates use the same hardening-tier names and order. The Learner can reset any software-only tier to a known starting state without exposing production credentials. Unsafe Tier 0 material is visually marked, bound to the isolated local environment, and separated from final configuration examples. Each control or lifecycle tier states the starting state, exact delta, expected insecure observation, expected hardened observation, and residual risk. Tier 0 states the observed insecure baseline. Tier 1 states the analysis and evidence delta. Tier 10 states the integrated response and regression result. Solutions never skip directly to the final architecture and preserve the reasoning and evidence transition between adjacent tiers. Optional advanced tiers never block core-course completion.

Source: resolved decision ticket [#13](https://github.com/tkEmLogic/learning-cyber-security/issues/13).

## 12. Weakness ledger

**Fixed decision.** Every hardening tier maintains a weakness ledger. It records weaknesses inherited from the preceding tier, the attack vectors that expose each weakness, the controlled attack demonstration used in the lab, the observable insecure result before the new control, the control introduced by the tier, the observable result after hardening, whether the weakness is closed, reduced, transferred, accepted, or deliberately left for a later tier, and evidence links and residual risk.

**Implementation requirement.** Each tier demonstrates at least one realistic attack or failure where this can be done safely and repeatably. Tier 0 records the successful baseline attack. Tier 1 reuses selected Tier 0 evidence to build the threat model and planned controls without pretending that analysis alone blocks the attack. Control and lifecycle tiers perform the attack, observe why it works, predict which control should stop it, apply that control, and rerun the same attack. Tier 10 reruns the integrated fixture set and records diagnosis, repair, recovery, and regression results. Later tiers repeat relevant earlier attacks to detect regressions.

**Fixed decision.** Attack fixtures run only in the isolated course environment against the reference product and synthetic services. Instructions define the permitted target, expected effect, reset procedure, and safety boundary, and they never direct Learners toward third-party or production systems. The security evidence pack carries the weakness ledger across tiers so Learners can see the security posture change from the unsecured baseline to the integrated hardened product.

Source: resolved decision ticket [#13](https://github.com/tkEmLogic/learning-cyber-security/issues/13), addendum comment.

## 13. Mentor review gates and assessment

**Fixed decision.** Use live Mentor review gates at security-boundary milestones, with asynchronous checks between them. Reviews are informal coaching conversations. They never produce grades, percentages, certification, or a pass-fail judgment. The Mentor's main job is to help the Learner understand the security boundary, diagnose problems, complete the course, and leave accurate evidence.

### Review cadence

**Fixed decision.** Live Mentor review gates occur after Tier 1, before implementation-heavy hardening begins; after Tier 3, when signed firmware first creates a publisher-trust boundary; after Tier 5, when download, test boot, confirmation, revert, and recovery form one update system; after Tier 7, when per-device operational identity and mutual TLS replace shared or factory-only access; after Tier 9, when dependency, vulnerability, support, and CRA-related evidence is assembled; after Tier 10, for the integrated defense scenario and core-course completion conversation; before and after physical eFuse changes in Advanced Tier A; and at the end of Advanced Tier B when the STSAFE-A120 hands-on path is used. Other tiers use lightweight asynchronous artifact review. The Mentor may add a live session when the Learner is blocked, a safety boundary is unclear, or evidence contradicts the claimed result.

### Purpose of a Mentor review gate

Each gate helps the Learner demonstrate the current reference-product behavior, show the relevant attack or failure evidence, walk through the weakness ledger entries changed by the tier, explain what the current control or analysis protects and what it does not protect, present the linked lab artifact and security evidence pack updates, diagnose a prepared failure or unexpected observation with the Mentor, and identify gaps and agree on the smallest useful next action. For a control tier, the Learner shows the attack before and after hardening. For Tier 1, the Learner shows how Tier 0 evidence became requirements and claims. For Tier 10, the Learner shows integrated diagnosis, repair, recovery, and regression evidence. The Mentor asks questions and supplies hints. The review is not designed to catch the Learner out.

### Informal review outcome

**Implementation requirement.** Record one of three lightweight outcomes: ready to continue, meaning the Learner and Mentor agree that the next tier has a usable foundation; continue with notes, meaning the Learner may proceed while keeping named gaps or questions visible in the weakness ledger or evidence pack; or resolve safety prerequisite first, meaning a narrow issue must be corrected before a dependent or irreversible activity starts. Only safety and dependency prerequisites block progress, such as an exposed signing key, a missing recovery path before eFuse changes, an inability to restore the last confirmed image, an attack fixture targeting the wrong network, or evidence that the Learner is about to rely on a false trust assumption. An incomplete explanation, imperfect document, or failed first attempt is never itself a reason to stop the Learner.

### Published review prompts

**Implementation requirement.** Each gate publishes prompts under four headings. Show: run the current reference product, demonstrate the intended control, demonstrate one relevant attack or bypass attempt or failure, show the resulting device, service, and evidence records. Explain: which asset and threat are involved, which trust boundary changed, why the attack worked before the change, which control changed the result, and what weakness remains. Diagnose: the Mentor selects one prepared failure from the tier, such as a wrong trust anchor, modified image, replayed security counter, interrupted download, unconfirmed image, revoked certificate, stale owner identity, or misleading vulnerability scan match, and the Learner may use course documentation, logs, and Mentor hints. Plan: update the weakness ledger and residual risk, record corrections or open questions, and confirm the starting state for the next tier.

### Evidence recorded

A Mentor review record contains the hardening tier and date, Learner and Mentor identifiers appropriate for the local training setting, demonstrations and artifacts reviewed, the prepared failure used and the diagnostic path taken, important Mentor hints or explanations, weakness-ledger entries changed, agreed corrections, open questions, and next step, and one informal outcome. The record contains no numeric score and never claims independent assessment, professional certification, legal conformity, or production approval.

### Course completion

Core-course completion means the Learner has worked through all core hardening tiers, attempted the required attack demonstrations, maintained the security evidence pack and weakness ledger, and held the final Mentor conversation. Open residual risks and documented gaps may remain and should be visible rather than hidden. The Mentor records completion as an in-house learning milestone, not proof that the Learner or reference product meets an external standard.

### Resuming after difficulty

**Implementation requirement.** When a Learner is not ready for the next dependency or safety boundary, the Mentor records a short recovery plan: name the misunderstood boundary or failed behavior, return to the last known runnable tier, reproduce one focused attack or failure, review the relevant reading or diagram, apply or repair the control with Mentor guidance, and rerun the demonstration and update the evidence. A full gate does not need to be repeated unless the Learner or Mentor finds it useful.

Source: resolved decision ticket [#14](https://github.com/tkEmLogic/learning-cyber-security/issues/14).

## 14. Course module format

**Fixed decision.** Each hardening-tier module uses an incident-driven opening, a linear work procedure, and an evidence-first close, in this exact order: tier title; scenario; learning result; safety boundary; starting state; weakness ledger before the work; controlled attack or failure reproduction; investigation questions and trust-boundary explanation; ordered work procedure with commands and expected results; replay or re-analysis of the original observation; bypass and failure tests where applicable; weakness ledger after the work; security claim and evidence status; security evidence pack update; troubleshooting; informal Mentor conversation; transition and attack preview for the next tier; primary references.

**Implementation requirement.** The headings stay consistent, but their expected content follows the tier variant from section 11. Tier 0 uses the procedure to build the baseline and records the successful attack as its result; its replay section says that no control exists yet and links forward to Tier 1. Tier 1 uses the procedure to create analysis artifacts and reclassifies the same observation against threats, requirements, and planned controls; it does not claim technical rejection. Tiers 2 through 9 and Advanced Tiers A and B use the full attack, control, replay, and bypass sequence. Tier 10 uses the procedure for integrated diagnosis and remediation, then reruns the affected fixture set as regression evidence.

**Naming note.** The opening section was called the incident brief until the Tier 0 module was written. A baseline tier has no incident yet, and an analysis tier has none either, so the heading is `## Scenario` in every variant. The validated prototype still shows the old heading, because it is a record of what was tested. The section also grew: it now sets the situation and says what the Learner will do and have at the end, rather than opening on the problem.

**Implementation requirement.** Use plain English, one source line per prose paragraph, simple pipe tables, fenced text blocks, and descriptive links. Use Mermaid diagrams, plain-text diagrams, or imported images.

### Validated prototype

**Fixed decision.** The selected module structure is validated by a prototype comparing three variants on the same Tier 3 content: an incident-driven mission, a linear procedure, and an evidence-first review sheet. The chosen combination uses the incident opening and attack narrative from the incident-driven variant, the linear hardening procedure from the linear-procedure variant, and the evidence board and weakness-ledger delta from the evidence-first variant. The validated file is [`selected-cab.md`](../prototypes/docmost-hardening-tier/selected-cab.md), originally validated on branch `prototype/docmost-hardening-tier` at commit `7988ef5351059a2d6c688206ab047305e5c5f13b`. Treat this file as the reference example for every core and advanced module. Its content is throwaway prototype text and must not be copied verbatim into the final course, but its structure, tone, table shapes, and command-and-expected-result pattern are the pattern to reuse.

### Docmost round-trip validation

**Implementation requirement.** The selected file was imported into a local Docmost sandbox, inspected, exported as Markdown, and compared with the source. Heading hierarchy, four pipe tables, fourteen fenced code blocks, a plain-text trust-boundary diagram, three external reference links, lists, blockquotes, bold text, and section order all survived correctly. Docmost normalized table separator spacing and whitespace in empty table cells, and it omitted the final newline. Neither change altered meaning or readability. A fenced Mermaid block survived export but rendered as source code rather than a diagram in the first import attempt into the sandbox, so the validated prototype uses a plain-text diagram. That finding is superseded: the live Docmost instance renders a fenced `mermaid` block as a diagram, so Mermaid is permitted. Source line wrapping becomes a visible hard break on import, so every module keeps each prose paragraph on one source line.

Source: resolved prototype ticket [#15](https://github.com/tkEmLogic/learning-cyber-security/issues/15).

## 15. Repository scaffold

**Fixed decision.** Use one repository for course material, firmware, bootloader configuration, the local OTA service, provisioning tools, attack fixtures, tests, evidence templates, and Mentor material. Preserve the reference implementation as one cumulative Git history. Publish immutable annotated tier checkpoints. Learners work on their own branches or generated worktrees based on those checkpoints. Do not maintain a permanent branch or copied source tree for every tier.

### Repository layout

```text
/
|-- README.md
|-- AGENTS.md
|-- CONTEXT.md
|-- course.yml
|-- course/
|   |-- index.md
|   |-- setup/
|   |-- tiers/
|   |   |-- tier-00-unsecured/
|   |   |-- tier-01-threat-model/
|   |   `-- ...
|   |-- advanced/
|   `-- references/
|-- firmware/
|   |-- app/
|   |-- bootloader/
|   |-- boards/
|   `-- config/
|-- services/
|   `-- ota/
|-- provisioning/
|-- attack-fixtures/
|   |-- shared/
|   `-- tiers/
|-- evidence/
|   |-- templates/
|   |-- examples/
|   `-- schemas/
|-- tests/
|   |-- host/
|   |-- integration/
|   `-- hardware/
|-- mentor/
|   |-- review-prompts/
|   |-- prepared-failures/
|   `-- troubleshooting/
|-- tools/
|   `-- course/
|-- hardware/
|   `-- irreversible/
`-- .github/
    `-- workflows/
```

**Implementation requirement.** The final scaffold may adjust names to match the selected implementation tools, but it preserves these responsibilities and boundaries.

### Course material

**Implementation requirement.** Each `course/tiers/<tier>/` directory contains `index.md`, the Learner-facing module using the format in section 14; `objectives.md`, concise learning results when they need separate reuse; `weakness-ledger.md`, the tier's starting and ending weakness state; `evidence.md`, required security evidence pack updates; `references.md`, required, recommended, and optional readings for that tier; and `assets/`, imported images and other non-secret teaching assets.

### Tier checkpoints and learner workspaces

**Implementation requirement.** Use immutable annotated tags with a course-version prefix:

```text
course-v1.0-tier-00-start
course-v1.0-tier-00-complete
course-v1.0-tier-01-complete
...
course-v1.0-tier-10-complete
```

The start of a tier normally equals the preceding tier's completion checkpoint. A separate start tag is used only when the course must add non-solution fixtures or instructions between tiers. Published checkpoint tags are never moved. A corrected course release gets a new course-version prefix.

A Learner creates a Course workspace from a checkpoint:

```text
./course tier start 03 --workspace ../cybersec-tier-03
```

The command checks the repository version and required tools, refuses to modify a dirty working tree, creates a new Git worktree and Learner branch from the correct checkpoint, generates local disposable configuration and secrets outside tracked paths, and prints the module path and first command. Learners commit their own work on that branch, never directly on a checkpoint or shared tier branch.

Use these comparisons:

```text
./course tier diff 03
./course tier verify 03
```

`diff` shows the Learner's changes from the starting checkpoint and, after the Learner chooses to reveal it, the reference delta between the start and completion checkpoints. `verify` runs the tests and evidence checks for the current tier.

### Tier manifest

**Implementation requirement.** `course.yml` is the machine-readable index. For each tier it records the stable tier identifier and title, start and completion checkpoint names, module path, prerequisite tiers, required hardware and services, build and verification commands, attack fixture identifiers, expected evidence artifacts, Mentor review requirement, whether the tier is core, advanced, or a comparison fallback, and whether any step is destructive or irreversible. The command wrapper and CI read this file. The course pages remain the Learner-facing explanation.

### Source and configuration strategy

**Implementation requirement.** Keep one evolving firmware and service source tree. Each tier changes that tree through normal commits. Checkpoint tags preserve the runnable historical states. Use explicit configuration overlays for differences that are teaching inputs rather than source evolution, such as unsigned versus signed MCUboot configuration, TLS and mutual TLS settings, test certificates and trust anchors, attack-fixture endpoints, and hardware and advanced-module options. Do not hide the tier's teaching change behind a large generated file. The adjacent checkpoint diff must show the security-relevant delta clearly.

Source: resolved decision ticket [#16](https://github.com/tkEmLogic/learning-cyber-security/issues/16).

## 16. Command interface

**Fixed decision.** Provide one repository-root command named `./course`. It is a thin, documented wrapper around existing ecosystem tools such as West, CMake, certificate tools, and test runners. It also supervises the local OTA service process. An earlier version of this decision named a selected Docker or Podman compose command; the service moved inside the dev container in issue #38, which removed the compose file and the runtime choice.

**Implementation requirement.** Required command groups are:

```text
./course doctor
./course setup
./course tier list
./course tier start <id>
./course tier status
./course tier diff <id>
./course build [component]
./course service start|stop|status
./course device flash|logs|update|recover
./course attack list|run <fixture>
./course verify <tier-id>
./course evidence check
./course clean
```

Commands print the underlying command or configuration they use. The wrapper reduces setup friction but never hides the mechanism being taught. Destructive commands name the exact target and require explicit confirmation. They never use broad process termination, directory deletion, or implicit reset of Learner work.

Source: resolved decision ticket [#16](https://github.com/tkEmLogic/learning-cyber-security/issues/16).

## 17. Secrets, attack fixtures, and irreversible hardware work

### Secrets and generated state

**Implementation requirement.** Use these untracked locations:

```text
.course-secrets/
.course-state/
build/
artifacts/generated/
```

The repository contains `.example` files, schemas, and generation scripts, not live credentials. Generate disposable local certificate authorities and credentials during setup. Mount secrets into containers or pass file paths, never place secrets in images or source configuration. Keep firmware release-signing keys outside the OTA service directory and container. Store only public certificates, fingerprints, synthetic identifiers, and redacted examples in evidence committed to Git. Include secret scanning in local checks and CI. Make cleanup target only the named course-generated directories after showing what will be removed.

### Attack fixtures

**Implementation requirement.** Each `attack-fixtures/tiers/<tier>/` fixture includes the weakness and attack vector it demonstrates, the permitted target and network boundary, preconditions and expected insecure effect, the command to run it, the expected result for that tier variant, evidence to capture, a reset procedure, and a machine-readable identifier used by `course.yml` and tests. Tier 0 expects the insecure effect. Tier 1 links selected Tier 0 fixtures to analysis artifacts. Control and lifecycle tiers define both the before-control and after-control results. Tier 10 defines integrated diagnosis, recovery, and regression results. Fixtures default to local addresses and synthetic data. They fail closed when the target does not identify itself as the course environment. No fixture scans arbitrary networks or accepts an unrestricted target range. Later tier verification reruns relevant earlier fixtures, and the weakness ledger records whether each result is closed, reduced, transferred, accepted, or still open.

### Mentor material

Mentor review prompts and prepared failures live in the same repository because this is informal in-house training. They are clearly separated from Learner instructions. The Learner may read them. The course does not depend on secrecy for assessment, because prepared failures still provide value from when and how the Mentor introduces them and helps the Learner diagnose the result.

### Irreversible hardware work

**Implementation requirement.** Keep physical eFuse and other irreversible operations under `hardware/irreversible/`. They are excluded from normal setup, build, and verification commands. An irreversible command requires Advanced Tier A context, a labelled disposable board identifier, a saved pre-change eFuse report, successful virtual-eFuse practice, successful signed recovery on the same board, recorded Mentor approval, and an explicit command flag with typed confirmation containing the board identifier. Dry-run is the default. CI never invokes physical irreversible commands.

Source: resolved decision ticket [#16](https://github.com/tkEmLogic/learning-cyber-security/issues/16).

## 18. Continuous integration

**Implementation requirement.** Run on every pull request where practical: course Markdown and internal-link checks; plain-English and forbidden-format checks, including em dashes, raw HTML, and hard-wrapped prose; schema and cross-reference checks for `course.yml`, weakness ledgers, requirements, claims, and evidence metadata; secret scanning and checks for forbidden private-key files; firmware and bootloader builds for the changed configuration; OTA service tests; provisioning-tool tests with disposable keys; host-side attack-fixture and negative tests; and SBOM generation and known-vulnerability scan with recorded database time.

**Implementation requirement.** A checkpoint-validation workflow reads `course.yml`, checks out each published checkpoint, and runs that tier's declared host-side build and verification commands. This proves that historical states remain reproducible without duplicating their source trees.

**Implementation requirement.** Hardware jobs run separately because runners and boards are limited. They include ESP32-C6 flash and smoke tests; interrupted OTA, test boot, confirmation, and revert; physical recovery; mutual TLS and credential lifecycle tests; and advanced secure-boot, flash-encryption, and STSAFE-A120 validation on dedicated disposable hardware. Hardware results attach the board identifier, firmware revision, configuration, and logs to the security evidence pack. A skipped hardware job cannot support a hardware-dependent security claim.

**Implementation requirement.** The core boot matrix verifies the fixed flash map, swap-with-scratch mode, primary-slot signature validation, software security-counter downgrade prevention, secondary-slot test upgrade, confirmation, health failure and timeout reset, watchdog reset of a hung trial image, revert, and signed serial recovery. Power is cut at each download, swap, first-boot, and confirmation transition. The device must either boot the last confirmed image or remain in the documented serial-recovery state. Advanced Tier A separately verifies bootloader-signing-key rotation and firmware-release-key rotation, including both image and Release-manifest verification; passing one never counts as evidence for the other.

### Documentation and evidence checks

**Implementation requirement.** The scaffold validates that every tier has a starting weakness ledger and ending ledger update, every attack fixture is linked from a tier and has a permitted target, every supported security claim links to passing evidence, every release links to a source revision, build manifest, SBOM, signatures, and tests, required Mentor review records exist where the course calls for them, and experimental advanced claims remain partly supported until physical-hardware validation passes.

### Initial scaffold scope

This specification defines the repository structure, commands, metadata, and checkpoint policy. Building the complete firmware, service, attack fixtures, and CI remains outside this Wayfinder map and is a later implementation effort.

Source: resolved decision ticket [#16](https://github.com/tkEmLogic/learning-cyber-security/issues/16).

## 19. Readings and reading plan

**Fixed decision.** Use a small tier-specific set of versioned primary sources. Each source is required, recommended, or optional, and is tied to one learning question and an exact section to read. Treat laws, standards-track RFCs, IEEE and ISO standards, and the SUIT and TUF specifications as normative. Treat vendor documents, project guides, ENISA guidance, and blog posts as explanatory. Include the Latacora post-quantum article only as a discussion of cryptographic agility and product lifetime, never to justify inventing post-quantum cryptography for the course.

**Implementation requirement.** Do not copy the full reading report into course pages. Each `course/tiers/<tier>/references.md` file lists only that tier's readings, drawn from the full report, with the reading, its level, its type, the learning question it answers, and the exact section to read.

### Reading plan pointer

The complete, versioned reading list with every required, recommended, and optional source, exact sections, and a maintenance policy lives in [`research/course-readings.md`](../research/course-readings.md), originally published on branch `research/course-readings`. An implementer copies each tier's relevant rows from that report into the matching `course/tiers/<tier>/references.md` file rather than re-deriving the list.

The table below is a compact pointer, not the full list. It names the required readings and their learning question so an implementer can start each tier's `references.md` without opening the full report first.

| Tier | Required reading | Learning question it answers |
| --- | --- | --- |
| T0 | Zephyr device management, OTA overview; MCUboot readme for Zephyr | What are the parts of an OTA update path, and what does an unsigned configuration allow? |
| T1 | Course-owned threat model process, no external reading required | How do assets, actors, and trust boundaries connect to requirements? |
| T2 | Zephyr networking and TLS documentation for the pinned version | What does authenticated HTTPS protect, and what does it leave open? |
| T3 | MCUboot design document; MCUboot imgtool | How does MCUboot verify a signature, and how do I sign an image offline? |
| T4 | RFC 9124, firmware update manifest information model; MCUboot design document, security counter | Which fields must signed metadata carry to resist tampering and downgrade? |
| T5 | MCUboot design document, swap and revert; MCUboot serial recovery, pinned to v2.4.0 | How do test boot, confirm, automatic revert, and serial recovery work together? |
| T6 | ESP32-C6 Secure Boot v2 overview, used here only for the eFuse and identity model, not for hardware secure boot; MCUboot imgtool | How is a unique per-device identity generated and proven at enrollment? |
| T7 | Zephyr mutual TLS and credential documentation for the pinned version | How does mutual TLS bind an operational identity to service access? |
| T8 | Course-owned lifecycle process, cross-referenced with RFC 7030 EST and RFC 8995 BRSKI | How do renewal, rotation, revocation, transfer, and decommissioning stay safe? |
| T9 | CRA, Regulation (EU) 2024/2847, Article 14; CRA, Article 13 and Annex I Part II; NTIA minimum elements for an SBOM | What must a manufacturer report, and what must an SBOM contain? |
| T10 | RFC 9019, firmware update architecture, whole document as a system review | How do the update controls fit together against a realistic attacker? |
| Advanced A | Espressif ESP32-C6 Secure Boot v2, flash encryption, and eFuse Manager, ESP-IDF v6.1 | How does hardware-rooted secure boot verify the bootloader, and why is eFuse burning permanent? |
| Advanced B | STMicroelectronics STSAFE-A120 datasheet; catie-aq Zephyr STSAFE-A1xx driver | What does the secure element do, and how does the community driver expose it? |

**Fixed decision.** Re-check the reading list on each course release and at least every six months. Watch the pinned Zephyr, MCUboot, and ESP-IDF versions, re-validate URLs, and update the "where to read" pointers if section numbers move. ST.com PDFs and ISO catalogue pages need manual link checks during maintenance, and the community STSAFE Zephyr driver remains a validation risk to re-check at each review.

Source: resolved research ticket [#18](https://github.com/tkEmLogic/learning-cyber-security/issues/18).

## 20. Docmost formatting rules

**Fixed decision.** All learner-facing and mentor-facing Markdown in the repository follows these rules, validated by importing the selected module prototype into a Docmost sandbox and exporting it back to Markdown.

**Implementation requirement.** Use short, direct sentences, common words, active voice, and one main idea per sentence. Define a necessary technical term before using it without explanation. Avoid idioms, jokes, culture-specific references, and esoteric language. Do not use em dashes. Use a full stop, comma, colon, or a new sentence instead. Do not use a complex word when a simple word has the same meaning.

**Implementation requirement.** Keep each prose paragraph on one source line, because the tested Docmost importer preserves source line wraps as visible hard breaks. Use normal headings, paragraphs, links, blockquotes, lists, and fenced code blocks. Use simple pipe tables. Avoid raw HTML, MDX, GitHub alert syntax, and deeply nested lists. Use a fenced `mermaid` block for flow and trust boundary diagrams, because the live Docmost instance renders Mermaid. A plain-text diagram, a simple table, or an imported image remains acceptable where it reads better. Put essential meaning in text, even when a diagram also shows it. Use descriptive link text and relative links for repository content.

**Implementation requirement.** Give procedure steps in the order the Learner performs them. State where to run each command. Show the expected result after important steps. Explain destructive or irreversible actions before the command. Separate required work from optional exploration. Use the same name for a concept in every module, matching the terms in `CONTEXT.md`.

Source: `docs/agents/course-writing.md`, resolved prototype ticket [#15](https://github.com/tkEmLogic/learning-cyber-security/issues/15).

## 21. Safety boundaries summary

**Fixed decision.** The following boundaries apply across every hardening tier and every advanced module.

**Implementation requirement.** All attack demonstrations and insecure baselines run only on an isolated local lab network, using disposable credentials and synthetic data, and are never presented as deployment defaults. Attack fixtures fail closed when a target does not identify itself as the course environment, and no fixture scans arbitrary networks or accepts an unrestricted target range.

**Implementation requirement.** Every physical eFuse or other irreversible hardware operation follows this order, without exception: practice with virtual eFuses first, use a labelled disposable board, save a pre-change eFuse report, prove signed recovery works on the same board before restricting debug or download modes, obtain a recorded Mentor review gate approval, and require an explicit command flag with typed confirmation naming the board identifier. Dry-run is the default, and CI never invokes a physical irreversible command.

**Implementation requirement.** No private key, Bootstrap credential, bearer token, or other secret is ever committed to the repository, printed in course pages, or uploaded to the OTA service. Generated secrets live only in the untracked locations named in section 17.

**Implementation requirement.** Only safety and dependency prerequisites block Learner progress, as defined in section 13. Course material never asks a Learner to disable certificate or hostname verification, disable image-signature checks outside the Tier 0 baseline, or bypass a security boundary to work around a course defect.

Source: resolved decision tickets [#2](https://github.com/tkEmLogic/learning-cyber-security/issues/2), [#8](https://github.com/tkEmLogic/learning-cyber-security/issues/8), [#13](https://github.com/tkEmLogic/learning-cyber-security/issues/13), [#14](https://github.com/tkEmLogic/learning-cyber-security/issues/14), and [#16](https://github.com/tkEmLogic/learning-cyber-security/issues/16).

## 22. Acceptance criteria for the finished course package

**Implementation requirement.** The finished course package is accepted when all of the following are true.

| Area | Acceptance criterion |
| --- | --- |
| Reference product | The status beacon builds and runs on the pinned ESP32-C6 target with the behavior in section 2. |
| Boot state machine | The fixed flash map and swap-with-scratch configuration in section 6 pass power-cut, test-boot, confirmation, revert, downgrade, and signed serial-recovery tests without accepting an unsigned image or losing the documented recovery path. |
| Status path | The event endpoint in section 7 shows plaintext interception and identifier spoofing at Tier 0, server-authenticated transport at Tier 2, and Operational-identity binding, authorization, and replay detection at Tier 7. |
| Identity lifecycle | Factory enrollment consumes its unique Bootstrap credential once. Claiming separately requires Factory authentication, physical presence, a fresh claim nonce, and an authenticated Owner credential. Replay, wrong-owner, revoked, and decommissioned cases are rejected. |
| Credential storage | Tier 6 uses the exact PSA Secure Storage configuration and records all limitations in section 8. Course material never describes the default device-ID-derived key provider as hardware-backed or sufficient against privileged software or a capable flash attacker. |
| Tier progression | All eleven core tiers, Tier 0 through Tier 10, are implemented in the exact order and content of section 11, each with a passing `./course verify <tier>` run. |
| Tier checkpoints | Every tier has a published, immutable, annotated checkpoint tag, and the checkpoint-validation workflow in section 18 passes for every tag. |
| Attack fixtures | Tier 0 has a working fixture that produces the insecure baseline. Tier 1 links at least one Tier 0 fixture to its threat, requirement, and claim analysis. Every control or lifecycle tier has a fixture that reproduces the insecure behavior before hardening and the stated rejection or recovery after hardening. Tier 10 reruns the integrated fixture set and records diagnosis, recovery, and regression results. |
| Weakness ledger | Every tier has a starting and ending weakness ledger, and later tiers rerun relevant earlier fixtures with recorded results. |
| Security evidence pack | Every artifact group in section 10 exists with a stable path, required metadata, and passing automated quality checks. |
| Mentor material | Published review prompts and prepared failures exist for every required gate in section 13. |
| Module format | Every tier module follows the eighteen-step order and the correct baseline, analysis, control, lifecycle, or integration variant in section 14, and passes a Docmost import and export check with no loss of headings, tables, code blocks, links, or paragraph structure. |
| Readings | Every tier has a `references.md` populated from the pointer in section 19, with required readings present. |
| Command interface | Every command listed in section 16 is implemented, documented, and prints its underlying mechanism. |
| Secrets and fixtures | No secret pattern, private key, or live credential exists in the committed repository, confirmed by the CI secret scan in section 18. |
| Advanced Tier A | Either published as hands-on after passing the validation gate in section 6, including separate bootloader-signing-key and firmware-release-key rotation tests for both image and Release-manifest verification, or clearly marked experimental with the specific failing checks named. |
| Advanced Tier B | Either published as hands-on after passing the validation gate in section 9, or published as the guided comparison fallback. |
| CRA evidence | The Tier 9 artifacts distinguish the 11 September 2026 reporting duties from the 11 December 2027 product duties, include separate actively-exploited-vulnerability and severe-incident scenarios with the correct 24-hour, 72-hour, and event-specific final deadlines, and state the product-specific legal review boundary from section 4. |
| Formatting | No em dash, no raw HTML, and no multi-line prose paragraph exists in any learner-facing or mentor-facing Markdown file. |

Source: synthesized from resolved decision tickets [#2](https://github.com/tkEmLogic/learning-cyber-security/issues/2) through [#16](https://github.com/tkEmLogic/learning-cyber-security/issues/16) and [#18](https://github.com/tkEmLogic/learning-cyber-security/issues/18).

## 23. Implementation handoff checklist

**Implementation requirement.** Complete these steps in order to begin implementation from this specification.

1. Create the repository scaffold in section 15, including `course.yml` with placeholder entries for every tier named in section 11.
2. Set up the reference firmware and bootloader source tree with the Tier 0 insecure baseline from section 11, using the platform baseline in section 5.
3. Implement the local OTA service described in section 7, including the status-event endpoint, starting with the HTTP-only Tier 0 shape, then adding HTTPS, signed images, signed manifests, and Operational-identity authorization as later tiers require them.
4. Implement the provisioning tools and identity lifecycle described in section 8, starting with the shared-credential exercise in Tier 6, consuming the Bootstrap credential during Factory enrollment, and ending with the separate owner-authorized claiming and full lifecycle in Tier 8.
5. Implement the `./course` command wrapper from section 16, backed by the tier manifest and checkpoint tags from section 15.
6. Write each tier module using the format in section 14 and the validated prototype at `prototypes/docmost-hardening-tier/selected-cab.md` as the structural reference.
7. Build the attack fixtures and weakness ledger entries for each tier from section 11 and section 12, and verify each fixture fails closed outside the isolated lab network.
8. Build the security evidence pack templates and schemas from section 10, and wire the CI quality checks from section 18 to them.
9. Write the Mentor review prompts and prepared failures for every gate in section 13, and store them under `mentor/` as specified in section 15.
10. Populate each tier's `references.md` from the pointer table in section 19 and the full report at `research/course-readings.md`.
11. Publish the Tier 0 through Tier 10 checkpoint tags, then run the checkpoint-validation workflow from section 18 against all of them.
12. Attempt the Advanced Tier A validation gate from section 6 and section 17 on disposable hardware. Publish it as hands-on only if every check passes, otherwise mark it experimental with the specific gaps named.
13. Attempt the Advanced Tier B validation gate from section 9 on the pinned STSAFE-A120 hardware. Publish it as hands-on only if every check passes, otherwise publish the guided comparison fallback.
14. Run the full acceptance criteria list in section 22 against the finished package before declaring the course ready for Learners.

Source: synthesized from resolved decision tickets [#2](https://github.com/tkEmLogic/learning-cyber-security/issues/2) through [#16](https://github.com/tkEmLogic/learning-cyber-security/issues/16) and [#18](https://github.com/tkEmLogic/learning-cyber-security/issues/18).

## 24. Source and version register

**Implementation requirement.** Keep this register aligned with `research/course-readings.md`. Update it whenever a pinned version changes.

| Component | Version | Role |
| --- | --- | --- |
| Board | ESP32-C6 development kit | Reference product target, `esp32c6_devkitc/esp32c6/hpcore`. |
| Zephyr | 4.4.2 | Core and advanced course RTOS baseline. |
| MCUboot | 2.4.0 | Core and advanced course bootloader baseline. |
| ESP-IDF security docs | v6.1 | Advanced Tier A hardware security reference. |
| STSAFE-A120 middleware | STSELib v1.1.9, STSAFE-A SDK v1.0.4 | Advanced Tier B secure-element libraries. |
| Community STSAFE Zephyr driver | catie-aq commit `5b7f1243` | Advanced Tier B comparison-fallback scaffold, not an ST product. |

### Research report register

| Ticket | Report | Branch and path |
| --- | --- | --- |
| [#3](https://github.com/tkEmLogic/learning-cyber-security/issues/3) | CRA obligations | `research/cra-obligations`, `research/cra-obligations.md` |
| [#4](https://github.com/tkEmLogic/learning-cyber-security/issues/4) | Platform security support | `research/platform-security`, `research/platform-security-support.md` |
| [#5](https://github.com/tkEmLogic/learning-cyber-security/issues/5) | OTA architectures | `research/ota-architectures`, `research/ota-architectures.md` |
| [#6](https://github.com/tkEmLogic/learning-cyber-security/issues/6) | Device identity and provisioning | `research/provisioning`, `research/device-identity-and-provisioning.md` |
| [#7](https://github.com/tkEmLogic/learning-cyber-security/issues/7) | STSAFE-A120 integration | `research/stsafe-a120`, `research/stsafe-a120.md` |
| [#18](https://github.com/tkEmLogic/learning-cyber-security/issues/18) | Course readings | `research/course-readings`, `research/course-readings.md` |
| [#15](https://github.com/tkEmLogic/learning-cyber-security/issues/15) | Docmost module prototype | `prototype/docmost-hardening-tier`, `prototypes/docmost-hardening-tier/selected-cab.md`, validated at commit `7988ef5351059a2d6c688206ab047305e5c5f13b` |

All research access dates recorded in the source reports are 2026-09-11. Re-verify every external link and version at the maintenance cadence in section 19 before relying on this specification for a new course release.

Source: all resolved research and decision tickets referenced above.

## 25. Known ambiguities and unresolved conflicts

**Known platform uncertainty.** Advanced Tier A's hardware-rooted boot chain is fully specified in section 6, but no physical-board validation result exists yet. An implementer must run the validation gate before publishing the module as hands-on, and must not assume the platform research report's practical baseline guidance is itself proof of a working integration.

**Known platform uncertainty.** Advanced Tier B's STSAFE-A120 hands-on path depends on the community `catie-aq` Zephyr driver, which is not an ST product and is pinned to one commit. This is a genuine, currently open risk rather than a resolved decision. The fallback path in section 9 is fully specified and usable immediately if the pinned scaffold does not validate.

**Known platform uncertainty.** The exact algorithm used by an advanced hardware identity provider is left open by decision ticket [#10](https://github.com/tkEmLogic/learning-cyber-security/issues/10): it may be ECDSA P-256, matching the core course, or the ESP32-C6 Digital Signature peripheral's RSA path. This is a deliberate implementation choice, not an unresolved conflict, and either is acceptable if the certificate lifecycle and role separation in section 8 are preserved.

**Not a conflict, but worth flagging for the implementer.** The Tier reading report and validated Docmost prototype are integrated into the first-release implementation branch. The other research reports referenced in section 24 remain on their named research branches. Preserve the exact commit and branch references in the source register if those reports are later merged or archived.

**No unresolved conflict was found between issue 13's tier list, issue 14's gate cadence, issue 15's module format, issue 16's `course.yml` tier identifiers, and issue 18's per-tier reading list.** All five use the same Tier 0 through Tier 10 and Advanced A and B structure, and this specification preserves that alignment throughout.

The map's "Not yet specified" section was empty at assembly time, and no child ticket left an open question that this specification could not resolve using its resolution comment. The single remaining open item is Wayfinder ticket [#17](https://github.com/tkEmLogic/learning-cyber-security/issues/17) itself, which the parent agent closes after reviewing this document.
