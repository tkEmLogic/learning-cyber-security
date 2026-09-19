# Learning Cyber Security

This course teaches embedded and IoT cybersecurity by building one product and then hardening it, one control at a time.

You do not read about security here. You build a device that is deliberately insecure, attack it yourself, watch the attack succeed, and then close the hole and watch the same attack fail.

## Who this course is for

This course is written for embedded software engineers who have little or no experience applying cybersecurity in product development.

You need to be comfortable building embedded software. You do not need any security background.

## The Reference product

Every tier works on the same device, called the Reference product.

It is an industrial equipment status beacon built around an ESP32-C6. It shows a simulated machine state with one monochrome LED. On means normal operation. Off means the device is off. Fast and slow blinking show two fictional error states.

The device reports its status over Wi-Fi and receives software updates over Wi-Fi. Those two paths are where almost every attack in this course happens.

## How the course works

The course is a sequence of Hardening tiers. Each tier is one runnable state of the Reference product, created by adding one focused security control to the state before it.

Tier 0 builds the product with no security at all. Every later tier adds exactly one control and proves that it works.

Each tier follows the same shape. You read an incident, reproduce the attack, find the missing trust boundary, add the control, replay the attack, and record what changed.

You keep two records as you go. The Weakness ledger lists what is still broken. The Security evidence pack links every Security claim to the evidence that supports it.

A Security claim is only as good as its evidence. When you did not observe something, you record it as pending. You never write down a result you did not see.

## The tiers

The core course is eleven tiers and about 43 hours of work. Two advanced tiers follow it for teams with disposable hardware.

**The linked tiers are written and ready to work through. The rest is the course plan**, here so you can see where the work goes rather than because you can start it yet.

| Tier | What you add | The attack it answers | Time |
| --- | --- | --- | --- |
| [Tier 0: Build the unsecured reference product](tiers/tier-00-unsecured/index.md) | Nothing. This is the baseline with no security at all | Any local actor can read the traffic, imitate the service, and supply any firmware | 3 hours |
| [Tier 1: Model the product and its risks](tiers/tier-01-threat-model/index.md) | Analysis only. Assets, actors, trust boundaries, and a risk register | Teams add controls without agreeing what they protect or who they defend against | 3 hours |
| [Tier 2: Authenticate and encrypt the server connection](tiers/tier-02-authenticated-https/index.md) | HTTPS, a course-local service CA, certificate and hostname validation | Local eavesdropping, network modification, and service impersonation | 3 hours |
| [Tier 3: Require authentic firmware images](tiers/tier-03-signed-images/index.md) | An offline release-signing key and real MCUboot signature checking | A trusted but compromised OTA service supplies an altered or unsigned image | 4 hours |
| [Tier 4: Protect release metadata and block downgrade](tiers/tier-04-release-policy/index.md) | Signed release metadata and a security counter | Replay of an old signed image, and mutable metadata | 4 hours |
| [Tier 5: Make installation recoverable](tiers/tier-05-recovery/index.md) | Test boot, confirmation, and rollback | Power loss, a corrupted download, or a release that crashes on boot | 4 hours |
| [Tier 6: Replace shared identity with per-device factory identity](tiers/tier-06-factory-identity/index.md) | On-device key generation and a per-device Factory identity | One extracted shared credential impersonates every device | 4 hours |
| Tier 7: Add owner-scoped operational identity and mutual TLS | A rotatable Operational identity and mutual TLS | Factory credentials overused for daily access, or an unclaimed device joining | 4 hours |
| Tier 8: Operate the credential lifecycle | Rotation, renewal, revocation, ownership transfer, decommissioning | Expired, stolen, copied, or old-owner credentials that still work | 4 hours |
| Tier 9: Manage dependencies, vulnerabilities, and support | An SBOM, vulnerability handling, disclosure, and reporting exercises | Unknown components, unreviewed vulnerabilities, and late reporting | 5 hours |
| Tier 10: Defend the integrated reference product | No new control. Diagnose and repair the whole product under attack | A mixed campaign combining impersonation, replay, and interruption | 5 hours |
| Advanced Tier A: Add a hardware-rooted boot chain and confidentiality | ESP32-C6 Secure Boot v2 and flash encryption | A physical attacker replaces the bootloader or reads flash | 6 to 8 hours |
| Advanced Tier B: Isolate operational identity in STSAFE-A120 | A secure element that never exports its private keys | Key extraction from MCU storage, and misuse by compromised application code | 6 to 8 hours |

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
| Release manifest | Metadata describing one firmware release: its hardware, version, size, and digest |
| Factory identity | A permanent, manufacturer-issued identity for one physical device |
| Operational identity | A rotatable per-device identity used for normal service access |

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

The board this course targets is one development kit, the Espressif ESP32-C6-DevKitC-1. No tier has been validated on it yet: the hardware results `course.yml` records were observed on the board the course used before, a nanoESP32-C6 1.0, and they are owed a run on the DevKitC-1. The Zephyr board target is `esp32c6_devkitc/esp32c6/hpcore`, which is the target the earlier board used as well, so the firmware is built the same way for both.

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

Then **[Tier 2: Authenticate and encrypt the server connection](tiers/tier-02-authenticated-https/index.md)**, the first tier that stops an attack. The device learns to check who answered before it believes anything.

Then **[Tier 3: Require authentic firmware images](tiers/tier-03-signed-images/index.md)**, which takes the uncomfortable half of Tier 2 and closes it. You publish hostile firmware through your own fully trusted service and watch the device refuse it anyway. It ends at a required Mentor review gate.

Then **[Tier 4: Protect release metadata and block downgrade](tiers/tier-04-release-policy/index.md)**, which asks the question Tier 3 cannot. An image can be perfectly authentic and still be the wrong one, and a correctly signed release from last year is still correctly signed. You publish a signed Release manifest, and watch your device refuse seven releases that Tier 3 would have installed without complaint, five of them signed by your own key.

Then **[Tier 5: Make installation recoverable](tiers/tier-05-recovery/index.md)**, which is the first tier where the question is not whether to accept an image but whether it works. Your device installs on trial, judges itself for sixty seconds, and puts the old image back on its own when the new one cannot prove itself. You will revert a device four different ways, resume a download across a hard reset, and find the one place in this course where adding a control creates new attack surface rather than removing it.
