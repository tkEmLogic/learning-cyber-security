# Dev container: Zephyr / ESP32-C6 toolchain

This dev container gives every Tier 0 course session (host build, on-device
flash, `./course` workflow) the same pinned Ubuntu 24.04 toolchain, instead of
depending on whatever Python/CMake/west versions happen to be on the host.

It is the development environment, not an option. Everything runs inside it,
including the OTA service, so the host needs only a container engine and
VS Code. See
[issue #37](https://github.com/tkEmLogic/learning-cyber-security/issues/37).

## Why Podman

The course's implementation stack decision
([issue #21](https://github.com/tkEmLogic/learning-cyber-security/issues/21))
allows Docker or Podman. This setup targets Podman: it runs the container
engine rootless, under the same Linux user account already used to develop,
so bind mounts and USB device access line up with normal file/group
permissions without a Docker daemon running as root in the background.

## One-time host setup

1. Install Podman (`sudo dnf install podman` / `sudo apt install podman`).
2. Point the VS Code Dev Containers extension at Podman instead of Docker.
   Add to your user `settings.json`:

   ```json
   {
     "dev.containers.dockerPath": "podman"
   }
   ```

3. Nothing else. The OTA service runs as a plain process inside the
   container, so there is no compose file and no Docker or Podman runtime
   choice to make.

## Other platforms

The default configuration targets Linux with Podman and an attached board,
because that is the setup validated against hardware. The container still
builds firmware and runs the OTA service and all four Tier 0 fixtures
elsewhere, but physical flashing and serial logs are Linux only: macOS has no
USB passthrough into the container engine's virtual machine, and Windows would
need usbipd-win with WSL2, which nothing here has tested.

Remove these `runArgs` from `devcontainer.json` first:

| Platform | Remove |
| --- | --- |
| macOS | `--group-add=keep-groups`, `--security-opt=label=disable`, `--device=...`, both `/dev` volumes |
| Windows | The same five lines |
| Linux with Docker rather than Podman | `--group-add=keep-groups`, which is Podman-only on every platform |

Keep `--publish`. The OTA service needs it everywhere.

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

## What's persisted, and where

| Data | Location | Why |
| --- | --- | --- |
| Git checkout | bind-mounted workspace folder (default) | Your commits and working tree; lost only if you delete the clone. |
| Zephyr workspace (`west` modules, SDK, build output) | named volume `zephyr-workspace`, mounted at `$ZEPHYR_WORKSPACE` (`/opt/zephyr-workspace`) | Kept off the image and off the repo checkout on purpose (see `docs/esp32c6-build-baseline.md`); it's a multi-GB third-party tree that's slow to re-fetch. Rebuilding or updating the container image does not touch this volume. |

To fully reset the toolchain (for example, to move to a new Zephyr/SDK
version), delete the volume explicitly: `podman volume rm zephyr-workspace`.
The `.devcontainer/post-create.sh` provisioning script is idempotent and
re-runs on every container (re)creation, but it skips any step whose
completion marker already exists on the volume.

## Flashing the physical board

Plug the ESP32-C6-DevKitC in before opening or rebuilding the container.
`devcontainer.json` passes the board through with `--device`, resolved from
the `ESP32_SERIAL_DEVICE` host environment variable (defaulting to
`/dev/ttyACM0`). Set it to your board's stable path before launching VS Code:

```bash
export ESP32_SERIAL_DEVICE=/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_<your-serial>-if00
code .
```

`--group-add=keep-groups` is Podman-specific and carries your host user's
supplementary groups (e.g. `dialout`) into the container, so the mapped user
can open the device without running the container as root. There is no
direct Docker equivalent; a Docker-based fallback would need to run as root
or add a matching GID inside the image instead.

Podman resolves `--device` at container start and refuses to start at all if
the referenced path does not exist. If no board is attached, comment out the
`--device` line in `devcontainer.json` before opening/rebuilding; the
container still builds and runs everything except the physical flash step
without it.

## Building and flashing inside the container

```bash
./scripts/build-zephyr-baseline.sh
"$ZEPHYR_WORKSPACE/.venv/bin/west" flash -d "$ZEPHYR_WORKSPACE/build/reference-product-baseline"
```

The course wraps both as `./course build firmware` and `./course device flash`.
`ZEPHYR_WORKSPACE` needs no prefix, because `containerEnv` already sets it.

Pass the sysbuild top-level build directory (containing `domains.yaml`), not
the nested per-domain directory — passing the wrong one silently skips
flashing MCUboot. See `docs/esp32c6-build-baseline.md` for the full flash
map, safety notes (unsigned MCUboot only; no eFuse, secure boot, or
flash-encryption commands), and the board-specific findings from validating
this setup end-to-end against a nanoESP32-C6 1.0 (Muse Lab) board.
