# Learning Cyber Security

A hands-on embedded and IoT security course. You build one deliberately insecure product, attack it yourself, watch the attacks succeed, and then close each hole and watch the same attack fail.

The product is an industrial status beacon on an ESP32-C6. It reports a machine state over Wi-Fi and takes its software updates over Wi-Fi, which is where almost every attack in this course happens.

## Start here

**[Fork this repository](https://github.com/tkEmLogic/learning-cyber-security/fork), clone your fork, then open [the course](course-material/index.md) and work through it from the top.**

Fork rather than clone, because the course is written for you to change: you will edit firmware, write evidence records, and keep a Weakness ledger in your own copy. Your fork is your workbook.

Everything runs in a dev container. Your own machine needs a container engine and an editor, and nothing else. The course page explains the rest.

## What is published

| Tier | What you add |
| --- | --- |
| [Tier 0: Build the unsecured reference product](course-material/tiers/tier-00-unsecured/index.md) | Nothing. The baseline, with no security at all |
| [Tier 1: Model the product and its risks](course-material/tiers/tier-01-threat-model/index.md) | Analysis only. Assets, actors, trust boundaries, and a risk register |
| [Tier 2: Authenticate and encrypt the server connection](course-material/tiers/tier-02-authenticated-https/index.md) | HTTPS, a course-local certificate authority, certificate and hostname validation |
| [Tier 3: Require authentic firmware images](course-material/tiers/tier-03-signed-images/index.md) | Your own signing key, and a bootloader that refuses any image it did not sign |

Eleven core tiers and two advanced tiers are planned. [The course page](course-material/index.md) lists all of them, so you can see where the work goes.

## Hardware

A physical ESP32-C6 development kit is optional for most work and required for flashing, serial output, Wi-Fi behavior, and anything the device itself must prove.

Tier 0, Tier 2, and Tier 3 are validated on a nanoESP32-C6 1.0. `course.yml` records exactly which hardware results the course claims, and which it does not. A skipped hardware check never supports a hardware claim.

Flashing needs a Linux machine. You can complete every other part of the course on macOS or Windows with the hardware results recorded as pending, which is a normal and honest state.

## What is in this repository

| Path | What it holds |
| --- | --- |
| `course-material/` | The course itself. Start at `index.md` |
| `firmware/common/` | Beacon and Wi-Fi code shared by every tier |
| `firmware/tier-*/` | One firmware application per tier, so a published tier never changes underneath you |
| `services/ota/` | The local update service |
| `internal/`, `tools/course` | The `./course` command |
| `evidence/` | Schemas, templates, and your own evidence under `evidence/learner/` |
| `docs/` | The specification, the build baseline, and the safety contract |
| `course.yml` | The manifest. Tiers, fixtures, ports, safety rules, and hardware claims |

## Safety

Every attack in this course runs against your own device on your own isolated network, using synthetic data.

The fixtures refuse to point anywhere else: one literal private or loopback target, an exact Course environment marker, no discovery, no redirects, and no DNS names. `docs/fixture-safety-contract.md` states the rules and where each one is enforced.

Never point a course attack at a network, a service, or a device you do not own.

## Generated state

`./course setup` writes only to these ignored paths:

- `.course-state/`
- `.course-secrets/`
- `build/`
- `artifacts/generated/`

`.course-secrets/` holds your Wi-Fi passphrase and the disposable certificate authority the course generates for you. Git ignores it. Never commit it.

To remove generated state, stop the service, read the printed allowlist, and type the exact phrase:

```text
./course service stop
./course clean --confirm "REMOVE COURSE GENERATED STATE"
```

The command never runs `git clean`, resets Git, uses wildcards, or removes anything outside the manifest allowlist.

## Contributing to the course itself

`docs/agents/course-writing.md` holds the writing rules and `docs/agents/course-module-template.md` fixes the shape of a tier module. Run `scripts/verify-tier-00.sh` before every commit.
