# Learning Cyber Security

This course teaches embedded and IoT cybersecurity by building one product and then hardening it, one control at a time.

You do not read about security here. You build a device that is deliberately insecure, attack it yourself, watch the attack succeed, and then close the hole and watch the same attack fail.

## Who this course is for

This course is written for embedded software engineers who have little or no experience applying cybersecurity in product development.

You need to be comfortable building embedded software. You do not need any security background.

## The Reference product

Every tier works on the same device, called the Reference product.

It is an industrial equipment status beacon built around an ESP32-C6. It shows a simulated machine state with one RGB LED. Solid green means normal operation. Off means the device is off. Red blinking, fast or slow, shows two fictional error states.

The device reports its status over Wi-Fi and receives software updates over Wi-Fi. Those two paths are where almost every attack in this course happens.

## How the course works

The course is a sequence of Hardening tiers. Each tier is one runnable state of the Reference product, created by adding one focused security control to the state before it.

Tier 0 builds the product with no security at all. Every later tier adds exactly one control and proves that it works.

Each tier follows the same shape. You read an incident, reproduce the attack, find the missing trust boundary, add the control, replay the attack, and record what changed.

You keep two records as you go. The Weakness ledger lists what is still broken. The Security evidence pack links every Security claim to the evidence that supports it.

A Security claim is only as good as its evidence. When you did not observe something, you record it as pending. You never write down a result you did not see.

## The tiers

The core course is eleven tiers and about 60 hours of work. Two advanced tiers follow it for teams with disposable hardware.

**The linked tiers are written and ready to work through. The rest is the course plan**, here so you can see where the work goes rather than because you can start it yet.

Three short names run through the table below and through the whole course. TLS is short for Transport Layer Security, the protocol that authenticates and encrypts a connection. HTTPS is ordinary HTTP carried over TLS. OTA is short for over the air, which is how a software update reaches a device across a network. The [cryptography primer](cryptography-primer.md#names-you-will-meet) lists these beside the other short names you will meet.

| Tier | What you add | The attack it answers | Time |
| --- | --- | --- | --- |
| [Tier 0: Build the unsecured reference product](tiers/tier-00-unsecured/index.md) | Nothing. This is the baseline with no security at all | Any local actor can read the traffic, imitate the service, and supply any firmware | 3 hours |
| [Tier 1: Model the product and its risks](tiers/tier-01-threat-model/index.md) | Analysis only. Assets, actors, trust boundaries, and a risk register | Teams add controls without agreeing what they protect or who they defend against | 3 hours |
| [Tier 2: Authenticate and encrypt the server connection](tiers/tier-02-authenticated-https/index.md) | HTTPS, a course-local service certificate authority, certificate and hostname validation | Local eavesdropping, network modification, and service impersonation | 3 hours |
| [Tier 3: Require authentic firmware images](tiers/tier-03-signed-images/index.md) | An offline release-signing key and real MCUboot signature checking | A trusted but compromised OTA service supplies an altered or unsigned image | 4 hours |
| [Tier 4: Protect release metadata and block downgrade](tiers/tier-04-release-policy/index.md) | Signed release metadata and a security counter | Replay of an old signed image, and mutable metadata | 4 hours |
| [Tier 5: Make installation recoverable](tiers/tier-05-recovery/index.md) | Test boot, confirmation, and rollback | Power loss, a corrupted download, or a release that crashes on boot | 4 hours |
| [Tier 6: Replace shared identity with per-device factory identity](tiers/tier-06-factory-identity/index.md) | On-device key generation and a per-device Factory identity | One extracted shared credential impersonates every device | 4 hours |
| [Tier 7: Add owner-scoped operational identity and mutual TLS](tiers/tier-07-operational-identity/index.md) | A rotatable Operational identity and mutual TLS | Factory credentials overused for daily access, or an unclaimed device joining | 8 hours |
| [Tier 8: Operate the credential lifecycle](tiers/tier-08-credential-lifecycle/index.md) | Rotation, renewal, revocation, ownership transfer, decommissioning | Expired, stolen, copied, or old-owner credentials that still work | 12 hours |
| [Tier 9: Manage dependencies, vulnerabilities, and support](tiers/tier-09-vulnerability-support/index.md) | A software bill of materials, or SBOM, with vulnerability handling, disclosure, and reporting exercises | Unknown components, unreviewed vulnerabilities, and late reporting | 10 hours |
| Tier 10: Defend the integrated reference product | No new control. Diagnose and repair the whole product under attack | A mixed campaign combining impersonation, replay, and interruption | 5 hours |
| Advanced Tier A: Add a hardware-rooted boot chain and confidentiality | ESP32-C6 Secure Boot v2 and flash encryption | A physical attacker replaces the bootloader or reads flash | 6 to 8 hours |
| Advanced Tier B: Isolate operational identity in STSAFE-A120 | A secure element that never exports its private keys | Key extraction from MCU storage, and misuse by compromised application code | 6 to 8 hours |

Tier 7, Tier 8 and Tier 9 are the longest tiers in the course. Tier 7 is about twice the size of any other tier, so plan two sessions for it. Tier 8 is about three times the size, so plan three. Tier 9 is about two and a half times the size, and it also asks you to write more records than any other tier, so plan three sessions for it too.

The two advanced tiers make irreversible hardware changes. They require disposable boards and a Mentor before and after the change.

## Mentor review gates

A Mentor review gate is a scheduled conversation where you demonstrate a result, explain the security reasoning, and answer a prepared failure case. There is no grade.

Six tiers end at a required gate:

| After | Gate |
| --- | --- |
| Tier 1 | Readiness, before the implementation-heavy tiers begin |
| Tier 3 | Firmware trust |
| Tier 5 | Update recovery |
| Tier 7 | Identity boundary |
| Tier 9 | Lifecycle and evidence |
| Tier 10 | Core course completion |

Tier 0 has no gate. You may still ask a Mentor to look at your work.

Completing the core course is an in-house learning milestone. It is not proof that you or the Reference product meet any external standard. Open risks may remain, and they should be visible rather than hidden.

## Words this course uses

The course uses these words in one fixed meaning. Every tier uses them the same way.

This table holds the course's own roles and records. The security words themselves, such as key pair, signature, digest, certificate, certificate authority and nonce, are defined in the [cryptography primer](cryptography-primer.md).

| Word | Meaning |
| --- | --- |
| Learner | You. An embedded engineer new to applying security |
| Mentor | An experienced engineer who reviews your work at defined points |
| Mentor review gate | A scheduled review where you demonstrate a result and answer a failure case |
| Reference product | The ESP32-C6 status beacon that every tier works on |
| Hardening tier | One runnable state of the Reference product, adding one focused control |
| Weakness ledger | Your record of what is still broken, what proves it, and which tier will fix it |
| Security evidence pack | Your versioned set of claims, controls, tests, results, and residual risks |
| Security claim | A specific, reviewable statement about a security property. Supported, partly supported, unsupported, or not applicable |
| Residual risk | A risk that remains after the controls are applied, with its rationale and owner |
| Lab artifact | A reviewable result showing what you designed, observed, or concluded |
| Course workspace | Your own Git branch or worktree, created from a tier checkpoint |
| Tier checkpoint | A fixed Git tag marking a tested runnable state at the start or end of a tier |
| Course environment marker | A disposable identifier shared by the local service and the attack fixtures. A fixture refuses to run unless it matches |
| OTA service | The local service that hands out update assignments, release metadata, and firmware images |
| Update assignment | The OTA service's choice of which release, if any, a specific device should install. It refers to a Release manifest and does not change the signed release |
| Release manifest | Metadata describing one firmware release: its hardware, version, size, and digest |
| Factory identity | A permanent, manufacturer-issued identity for one physical device |
| Operational identity | A rotatable per-device identity used for normal service access |
| Bootstrap credential | A unique, short-lived or one-time credential that permits only initial enrollment. It cannot authorize normal device operation or firmware download |
| Owner credential | A credential that authorizes a person rather than a device. The holder presents it on every operator request, and it is never a device identity |
| Claim window | A ten-minute period opened by a physical action, a ten-second hold of the BOOT button, during which a device may be assigned to a new owner and receive a new operational identity |
| Claim nonce | A one-use secret that the device generates when its Claim window opens and prints on its console. Giving it to the service is how a claim proves that someone is physically at that device |
| Device lifecycle state | Where one device stands in its life: manufactured, claimed, active, transferred, revoked, or decommissioned. It is worked out from the Provisioning record, which is the authority |
| Renewal | Replacing a device's Operational identity with one on a new key, for the same owner, before the old one expires. The service decides when it is due, and no person takes part |
| Renewal candidate | The new key and certificate a device holds during a renewal, beside its current identity, until the service has seen them used |
| Recovery | Replacing a lost Operational identity for the device's current owner. It is a claim with the same press and nonce, and it always uses a new key |
| Recovery authorization | The owner's recorded statement that a device's Operational identity is lost. It revokes that certificate and allows one recovery within a limited time |
| Certificate revocation | Stopping one certificate, so the service refuses it everywhere. It stops a credential, not a device, and nothing cancels it |
| Device revocation | Stopping one device, so it can neither use nor obtain an Operational identity. Only a remanufacture undoes it |
| Ownership transfer | Moving a device to a new owner in two acts: the current owner gives it up, then a new owner claims it with an ordinary press |
| Remanufacture | The manufacturer enrolling a board again under a new identifier. It is the only way out of revoked and decommissioned |
| Decommissioning | The manufacturer retiring a board for good. What stops the board coming back is the service's record, not the erase |
| Factory loss | A board enrolling again while the record still shows a live identity for it, which means the old identity was lost with no record of why. It is recorded, not refused |
| Time floor | The latest moment the device has signed proof that the time has reached. It only rises, and it can prove a certificate expired but never that one is still valid |
| Fleet baseline | The release a device is offered when no rollout covers it. It is normally the release the device already runs, so the device refuses it as already confirmed |
| Rollout | The manufacturer's offer of one release to the fleet in two stages: first the Canary group, then every other claimed, active device. Moving to the second stage is a separate step |
| Canary group | The devices a rollout names to receive its release first, so the result can be reviewed before the rest of the fleet receives it |
| Release withdrawal | Closing a rollout and never offering its release again, because the release is vulnerable. Devices already running it move away only through a newer release at a higher security counter |
| Release approval | The manufacturer's recorded decision that one release, identified by the digests of its files, may be offered to devices. The device never checks it |
| Vulnerability report | A description of a suspected vulnerability that an outside party sends to the manufacturer. It is a claim to be triaged, not a finding |
| Vulnerability record | The manufacturer's record of one vulnerability: its triage, affected versions, reproduction, decision and remediation |
| Scanner match | A scanner's claim that a component version in an SBOM is covered by a published advisory. It can be false, and a scanner cannot match code that has no identity in its database |
| VEX statement | A machine-readable statement of whether one product version is affected by one vulnerability, and why not if it is not. It is true as of the date it was made |
| Unsupported component | A component whose supplier no longer publishes security fixes for the version in use |
| Remediation release | A signed release at a higher security counter that moves devices off a vulnerable version through the ordinary release path |
| Actively exploited vulnerability | A vulnerability for which there is reliable evidence that someone has exploited it without the owner's permission. A vulnerability report alone does not make it one |
| Severe incident | An incident that harms, or can harm, the product's ability to protect its data or functions, or that lets malicious code into the product or its user's network |
| Awareness time | The moment, recorded in UTC, when the manufacturer has a reasonable degree of certainty, after a prompt assessment, that a reportable event has happened |
| Scenario clock | A script of timestamped events that a reporting exercise follows instead of the wall clock |
| Support period | The fixed span, counted from when the product is first placed on the market, during which the manufacturer handles vulnerabilities and issues free security updates |
| Annex I control map | One row per Annex I requirement of the CRA, naming the controls that address it, the evidence and a status. It shows where the product stands, not that it meets the requirement |
| CRA traceability matrix | One row per CRA duty, linking it to requirements, controls, evidence, status, residual risk, the responsible role and a dated legal source |
| Coordinated vulnerability disclosure policy | The manufacturer's public statement of how outside parties report a suspected vulnerability, how it responds, and when the vulnerability is disclosed |
| Secure element | A separate security component that generates or stores private keys and performs cryptographic operations without exporting those private keys |

## Safety

The Tier 0 environment is intentionally unsafe. It uses plain HTTP, a shared device identity, and unsigned firmware.

Use only synthetic data. Use an isolated lab network or a phone hotspot. Never point a course attack at a network, a service, or a device that you do not own.

Every attack in this course runs against your own Reference product and your own local service. The course refuses to run a fixture against anything else.

## Set up the development environment

All course work happens inside a dev container. The container carries the pinned Zephyr toolchain, the SDK, Go, and the course commands, so you do not have to install or match any of them yourself.

This means your own machine needs almost nothing.

### What you install on your machine

| You need | Linux | macOS | Windows |
| --- | --- | --- | --- |
| A container engine | Podman | Podman Desktop | Podman Desktop |
| An editor | VS Code with the Dev Containers extension | The same | The same |

Nothing else. No Go, no Python, no Zephyr, no CMake.

The course uses Podman and not Docker. Docker Desktop is not free for company use above a small size threshold, and this course is taken at work. Podman Desktop carries no such condition. On Windows and macOS, Podman Desktop installs Podman and sets up the small Linux virtual machine that runs the containers.

You do not build the container image. The course publishes it, and your machine downloads it the first time you open the repository. Building it took several minutes and produced the same result on every machine.

[devcontainers/cli](https://github.com/devcontainers/cli) can open the same container without VS Code. The course does not claim it works, because the course has not tested it.

### Which platforms can use a physical board

You can build the firmware, run the local update service, and run every Tier 0 attack on Linux, macOS, and Windows.

The board this course targets is one development kit, the Espressif ESP32-C6-DevKitC-1. Tiers 0, 2, 3, 4, 5, 6 and 7 are validated on it. Tier 1 is analysis only and has no hardware results. `course.yml` records each result. The Zephyr board target is `esp32c6_devkitc/esp32c6/hpcore`.

Flashing a physical ESP32-C6 and reading its serial output need a Linux machine. macOS cannot pass a USB device into the Podman virtual machine, and Windows would need extra tooling that this course has not tested.

If you are on macOS or Windows, you can still complete the work. The course records the hardware results as pending, which is a normal and honest state.

### Steps

1. Install Podman and VS Code with the Dev Containers extension. On Windows and macOS, start the Podman machine from Podman Desktop and wait until it reports running.

2. Tell the extension to use Podman. Add this to your VS Code user `settings.json`:

```text
{
  "dev.containers.dockerPath": "podman"
}
```

3. Fork this repository on GitHub, then clone your fork. The course is written for you to change: you will edit firmware, write evidence records, and keep a Weakness ledger in your own copy. Your fork is your workbook.

4. If you have a board, attach it now, before you open the editor. The container reads the device path when it starts and refuses to start if the path is missing. Set the path first:

```text
export ESP32_SERIAL_DEVICE=/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_<your-serial>-if00
code .
```

5. Open the repository in the container. VS Code offers this when it sees the configuration, then asks which of the two configurations you want.

| Choose | When |
| --- | --- |
| Board attached | You are on Linux and a board is plugged in |
| No board | You are on macOS or Windows, or on Linux with no board |

Choose "No board" if you are unsure. You can switch later without downloading anything again. You do not have to edit any file to start.

6. Wait for the first start to finish. It downloads the container image, then the Zephyr workspace and the SDK, which takes a while. Later starts reuse both.

7. Run every command from here on inside the container, from the repository root.

### Check the environment

```text
./course doctor
```

Expected result:

```text
+ git --version
  available
+ go version
  available
+ curl --version
  available
Result: the course toolchain is available
Next: ./course setup
```

The command also lists any serial device it can see. A listed device does not prove that an ESP32-C6 is attached.

### Create the course environment

The Reference product reaches the local update service over your network, so the service needs an address the board can actually use. Give it your machine's private address, and name your lab Wi-Fi network at the same time:

```text
./course setup --bind 192.168.0.10 --wifi-ssid course-lab --wifi-psk <passphrase>
```

Use your own values. Expected result:

```text
+ mkdir -p .course-state
+ mkdir -p .course-secrets
+ mkdir -p build
+ mkdir -p artifacts/generated
Result: created synthetic Tier 0 environment <identifier>
State: .course-state, artifacts/generated
Next: ./course service start
```

The Wi-Fi network must meet these conditions:

| Condition | Reason |
| --- | --- |
| 2.4 GHz | The ESP32-C6 radio used here does not support 5 GHz |
| WPA2-PSK | Tier 0 supports no other Wi-Fi security type |
| Same Layer 2 network as your machine | The device connects by address, with no routing |
| Client isolation switched off | The device must be allowed to reach your machine |

The passphrase is written to `.course-secrets/wifi.conf`. Git ignores that directory. Never commit it.

Do not use a network that carries real traffic.

If you have no board, you can leave out the address and the network:

```text
./course setup
```

### Start the local update service

```text
./course service start
```

Expected result:

```text
Result: OTA service is healthy
Reachable by the Reference product at http://192.168.0.10:8080
```

The service runs inside the container as an ordinary process. The container publishes its port, so the board reaches it at the address shown.

Check it at any time:

```text
./course service status
```

Stop it when you are finished for the day:

```text
./course service stop
```

### Remove the generated state

This deletes generated course state. It does not touch your own work.

```text
./course service stop
./course clean --confirm "REMOVE COURSE GENERATED STATE"
```

The command removes only the exact list of paths named in `course.yml`.

## Where to go next

Open **[Tier 0: Build the unsecured reference product](tiers/tier-00-unsecured/index.md)** and work through it from the top.

When you finish it, you will have a working, deliberately insecure device, four demonstrated attacks, and the first entries in your Weakness ledger and Security evidence pack.

Then **[Tier 1: Model the product and its risks](tiers/tier-01-threat-model/index.md)**, which adds no control and changes no code. It turns what you observed in Tier 0 into a model of the product, its assets, its actors, and its risks, and it ends at the first Mentor review gate.

Before Tier 2, read the **[cryptography primer](cryptography-primer.md)**. It takes about twenty minutes and it defines the words every tier from Tier 2 onward uses without stopping to explain them: key pair, signature, certificate, certificate authority, chain, trust anchor, certification request and nonce.

Then **[Tier 2: Authenticate and encrypt the server connection](tiers/tier-02-authenticated-https/index.md)**, the first tier that stops an attack. The device learns to check who answered before it believes anything.

Then **[Tier 3: Require authentic firmware images](tiers/tier-03-signed-images/index.md)**, which takes the uncomfortable half of Tier 2 and closes it. You publish hostile firmware through your own fully trusted service and watch the device refuse it anyway. It ends at a required Mentor review gate.

Then **[Tier 4: Protect release metadata and block downgrade](tiers/tier-04-release-policy/index.md)**, which asks the question Tier 3 cannot. An image can be perfectly authentic and still be the wrong one, and a correctly signed release from last year is still correctly signed. You publish a signed Release manifest, and watch your device refuse seven releases that Tier 3 would have installed without complaint, five of them signed by your own key.

Then **[Tier 5: Make installation recoverable](tiers/tier-05-recovery/index.md)**, which is the first tier where the question is not whether to accept an image but whether it works. Your device installs on trial, judges itself for sixty seconds, and puts the old image back on its own when the new one cannot prove itself. You will revert a device four different ways, resume a download across a hard reset, and find the one place in this course where adding a control creates new attack surface rather than removing it.

Then **[Tier 6: Replace shared identity with per-device factory identity](tiers/tier-06-factory-identity/index.md)**, which has to make the product vulnerable before it can harden it. You give the whole fleet one shared credential, extract it from an image you built, register devices that were never manufactured, and only then replace it with a key the device generates for itself. It ends with the private key read back out of a flash dump, because the honest version of that tier says exactly what the new storage does and does not do.

Then **[Tier 7: Add owner-scoped operational identity and mutual TLS](tiers/tier-07-operational-identity/index.md)**, where the identity your device has been carrying since Tier 6 is finally checked. One `curl` writes a line into your board's history and takes your firmware, because the service has never asked who is calling. You give the connection an identity, claim the device with a physical press and an owner who authenticates as themselves, and then read thirteen refusals by name. It ends at a required Mentor review gate.
