# Learning Cyber Security

This repository contains the first runnable Tier 0 state of an embedded cybersecurity course.

Tier 0 is intentionally unsecured. It uses synthetic data, a local HTTP OTA service, a shared development identifier, mutable release data, and unsigned MCUboot images.

## Supported host

Use a current Linux distribution with Go, Git, curl, Python 3 with virtual environment support, and either Docker Compose or Podman Compose.

Ubuntu 24.04 is the CI reference environment. It is not the only supported Linux host.

The firmware build uses the external pinned workspace described in [`docs/esp32c6-build-baseline.md`](docs/esp32c6-build-baseline.md).

## Start Tier 0

Run:

```text
python3 -m venv build/python
build/python/bin/pip install -r requirements.txt
./course doctor
./course setup --runtime docker
./course service start
./course attack list
./course verify 00
```

Use `--runtime podman` when Podman is the selected runtime.

If both runtimes qualify, setup requires an explicit choice.

The Python packages are required by `./course verify 00`. The doctor command reports them as missing when they are not installed.

Read [`course-material/tiers/tier-00-unsecured/index.md`](course-material/tiers/tier-00-unsecured/index.md) before executing a fixture.

## Generated state

Setup writes only to these ignored paths:

- `.course-state/`
- `.course-secrets/`
- `build/`
- `artifacts/generated/`

Learner evidence belongs under `evidence/learner/` and stays distinct from generated course examples.

## Build

Build the Go helper and OTA service:

```text
./course build host
```

Build the pinned ESP32-C6 Zephyr sysbuild:

```text
ZEPHYR_WORKSPACE=/path/to/zephyr-v4.4.2 ./course build firmware
```

## Service

The OTA service binds to loopback by default:

```text
./course service start
./course service status
./course service stop
```

An explicit literal private or link-local bind address is allowed for a selected classroom interface:

```text
./course setup --runtime docker --bind 192.168.1.20
```

## Hardware status

No physical ESP32-C6 was available for this implementation.

The Zephyr sysbuild is validated.

Physical flash, serial output, LED behavior, Wi-Fi communication, OTA installation, recovery, and altered-image execution remain pending.

No hardware-dependent claim is made.

## Cleanup

Stop the service, inspect the printed allowlist, and type the exact phrase:

```text
./course service stop
./course clean --confirm "REMOVE COURSE GENERATED STATE"
```

The command does not run `git clean`, reset Git, use wildcards, or remove any path outside the manifest allowlist.
