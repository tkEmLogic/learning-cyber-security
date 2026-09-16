# Dev container: Zephyr / ESP32-C6 toolchain

This dev container gives every course session (host build, on-device flash,
`./course` workflow) the same pinned Ubuntu 24.04 toolchain, instead of
depending on whatever Python, CMake, or west versions happen to be on the host.

It is the development environment, not an option. Everything runs inside it,
including the OTA service, so the host needs only Podman and VS Code. See
[issue #37](https://github.com/tkEmLogic/learning-cyber-security/issues/37).

## Podman, not Docker

This course uses Podman on every platform. An earlier version of the
implementation stack decision
([issue #21](https://github.com/tkEmLogic/learning-cyber-security/issues/21))
allowed either Docker or Podman. It is Podman now, for two reasons.

Docker Desktop is not free for company use above a small size threshold, and
this course is taken at work. Podman Desktop carries no such condition.

Podman also runs the container engine rootless, under the same user account
already used to develop, so bind mounts and USB device access line up with
normal file and group permissions. There is no daemon running as root in the
background.

Nothing here uses `docker compose`. The OTA service runs as a plain process
inside the container, so there is no compose file and no runtime choice to
make.

## The image is published, so do not build it

CI builds `Dockerfile` and publishes it on every change that reaches `main`:

```text
ghcr.io/tkemlogic/learning-cyber-security-devcontainer:latest
```

The package is public, so no `podman login` is needed. Both `devcontainer.json`
files name that image, so opening the container pulls it. Building it from
source took several minutes on every machine for a byte-identical result.

The image holds the Ubuntu host packages and Go. It does not hold the Zephyr
workspace, the SDK, or any build output: those are multi-gigabyte and pinned
separately, and `post-create.sh` provisions them onto a named volume the first
time the container starts. That first start still takes a while. Later starts
reuse the volume.

Two tags are published:

| Tag | Use it for |
| --- | --- |
| `latest` | Normal work. Tracks the current `Dockerfile` on `main`. |
| `sha-<short commit>` | Reproducing an old result. Immutable, so it never moves under you. |

To pin an exact image, replace `latest` in your `devcontainer.json` with a
`sha-` tag from the
[package page](https://github.com/tkEmLogic/learning-cyber-security/pkgs/container/learning-cyber-security-devcontainer).

### Building it yourself

Only needed when you change `Dockerfile`, because your change is not published
until it reaches `main`. Build it and point the configuration at your build:

```bash
podman build -f .devcontainer/Dockerfile -t localhost/lcs-devcontainer:dev .devcontainer
```

Then set `"image": "localhost/lcs-devcontainer:dev"` in the `devcontainer.json`
you are using. Change it back before you commit, or your fork stops tracking
the published image.

## Which configuration to open

There are two, and VS Code asks which one you want when it opens the
repository.

| Configuration | Open it when | What it cannot do |
| --- | --- | --- |
| `devcontainer.json`, "board attached" | You are on Linux with an ESP32-C6 plugged in | Nothing |
| `no-board/devcontainer.json`, "no board" | You are on macOS or Windows, or on Linux with no board plugged in | Flash a board, read serial output |

Pick "no board" if you are unsure. It builds firmware, runs the local update
service, and runs every attack fixture. Switching later costs nothing: both
configurations use the same image and the same `zephyr-workspace` volume, so
the toolchain is not downloaded twice.

You do not have to edit either file to get started. That was true before this
was split in two, and it was the main thing newcomers got wrong.

## One-time host setup

### Linux

1. Install Podman: `sudo dnf install podman` or `sudo apt install podman`.
2. Install VS Code and the Dev Containers extension.
3. Tell the extension to use Podman. Add this to your user `settings.json`:

   ```json
   {
     "dev.containers.dockerPath": "podman"
   }
   ```

4. Nothing else.

### Windows

1. Install [Podman Desktop](https://podman-desktop.io/). It installs Podman and
   sets up the WSL2 virtual machine that runs the containers.
2. Start the Podman machine from Podman Desktop and wait until it reports
   running.
3. Install VS Code and the Dev Containers extension.
4. Set `"dev.containers.dockerPath": "podman"` in your user `settings.json`, as
   for Linux.
5. Open the repository and choose the "no board" configuration.

Flashing a board from Windows would need usbipd-win to pass the USB device into
WSL2. Nothing in this course has tested that, so the course does not claim it
works.

### macOS

1. Install [Podman Desktop](https://podman-desktop.io/), or
   `brew install podman`.
2. Run `podman machine init` and `podman machine start` if Podman Desktop has
   not already done it.
3. Install VS Code and the Dev Containers extension.
4. Set `"dev.containers.dockerPath": "podman"` in your user `settings.json`, as
   for Linux.
5. Open the repository and choose the "no board" configuration.

The published image is `linux/amd64` only. On Apple Silicon, Podman runs it
under emulation. It works and it is slower. macOS cannot pass a USB device into
the Podman virtual machine, so flashing a board is not possible there either
way.

## Other ways to open it

[devcontainers/cli](https://github.com/devcontainers/cli) can open the same
container without VS Code:

```bash
devcontainer up --docker-path podman --workspace-folder .
```

The course does not claim this works, because the course has not tested it.

## The published service port

`--publish=0.0.0.0:8080:8080` exposes the OTA service on every host address, so
a physical ESP32-C6 can reach it over the host's private network. Tell the
course which address the board should use:

```bash
./course setup --bind <this host's private address>
```

That address is what gets compiled into the firmware image. It is not where the
service listens: the service always listens on every address inside the
container, and the published port is what carries it to the host network.

Tier 0 uses 8080 alone. Tier 2 moves release records, firmware, and events to
8443 and leaves health and the course marker on 8080.

## What is persisted, and where

| Data | Location | Why |
| --- | --- | --- |
| Git checkout | bind-mounted workspace folder (default) | Your commits and working tree; lost only if you delete the clone. |
| Zephyr workspace (`west` modules, SDK, build output) | named volume `zephyr-workspace`, mounted at `$ZEPHYR_WORKSPACE` (`/opt/zephyr-workspace`) | Kept off the image and off the repo checkout on purpose (see `docs/esp32c6-build-baseline.md`); it is a multi-gigabyte third-party tree that is slow to re-fetch. Pulling a new image does not touch this volume. |

To fully reset the toolchain, for example to move to a new Zephyr or SDK
version, delete the volume explicitly: `podman volume rm zephyr-workspace`.
`post-create.sh` is idempotent and re-runs on every container creation, but it
skips any step whose completion marker already exists on the volume.

## Flashing the physical board

Plug the ESP32-C6-DevKitC in before you open or rebuild the container. The
board configuration passes it through with `--device`, resolved from the
`ESP32_SERIAL_DEVICE` host environment variable, which defaults to
`/dev/ttyACM0`. Set it to your board's stable path before launching VS Code:

```bash
export ESP32_SERIAL_DEVICE=/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_<your-serial>-if00
code .
```

Podman resolves `--device` when the container starts and refuses to start at
all if the path does not exist. If no board is attached, open the "no board"
configuration instead of editing this one.

`--group-add=keep-groups` carries your host user's supplementary groups, such
as `dialout`, into the container, so the mapped user can open the device
without running the container as root. It is a Podman flag with no Docker
equivalent, which is one more reason this course settled on Podman.

`--security-opt=label=disable` is needed on SELinux hosts such as Fedora.
Without it the container is denied access to `tty_device_t` and every flash
attempt fails with a permission error that looks like a missing group.

## Building and flashing inside the container

```bash
./scripts/build-zephyr-baseline.sh
"$ZEPHYR_WORKSPACE/.venv/bin/west" flash -d "$ZEPHYR_WORKSPACE/build/reference-product-baseline"
```

The course wraps both as `./course build firmware` and `./course device flash`.
`ZEPHYR_WORKSPACE` needs no prefix, because `containerEnv` already sets it.

Pass the sysbuild top-level build directory, the one containing
`domains.yaml`, not the nested per-domain directory. Passing the wrong one
silently skips flashing MCUboot. See `docs/esp32c6-build-baseline.md` for the
full flash map, the safety notes (unsigned MCUboot only; no eFuse, secure boot,
or flash-encryption commands), and the board-specific findings from validating
this setup end to end against a nanoESP32-C6 1.0 (Muse Lab) board.
