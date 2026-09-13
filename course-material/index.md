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

| Tier | What it adds |
| --- | --- |
| Tier 0 | The unsecured baseline. Nothing is protected |
| Tier 1 | Analysis only. A model of the product, its assets, and its risks |
| Tier 2 and later | One security control each, with the attack that proves it |

Each tier follows the same shape. You read an incident, reproduce the attack, find the missing trust boundary, add the control, replay the attack, and record what changed.

You keep two records as you go. The Weakness ledger lists what is still broken. The Security evidence pack links every Security claim to the evidence that supports it.

A Security claim is only as good as its evidence. When you did not observe something, you record it as pending. You never write down a result you did not see.

## Safety

The Tier 0 environment is intentionally unsafe. It uses plain HTTP, a shared device identity, and unsigned firmware.

Use only synthetic data. Use an isolated lab network or a phone hotspot. Never point a course attack at a network, a service, or a device that you do not own.

Every attack in this course runs against your own Reference product and your own local service. The course refuses to run a fixture against anything else.

## Set up the development environment

All course work happens inside a dev container. The container carries the pinned Zephyr toolchain, the SDK, Go, and the course commands, so you do not have to install or match any of them yourself.

This means your own machine needs almost nothing.

### What you install on your machine

| You need | Linux | macOS and Windows |
| --- | --- | --- |
| A container engine | Podman | Docker Desktop |
| An editor | VS Code with the Dev Containers extension | The same |

Nothing else. No Go, no Python, no Zephyr, no CMake.

[devcontainers/cli](https://github.com/devcontainers/cli) can open the same container without VS Code. The course does not claim it works, because the course has not tested it.

### Which platforms can use a physical board

You can build the firmware, run the local update service, and run every Tier 0 attack on Linux, macOS, and Windows.

Flashing a physical ESP32-C6 and reading its serial output need a Linux machine. macOS cannot pass a USB device into the container engine, and Windows would need extra tooling that this course has not tested.

If you are on macOS or Windows, you can still complete the work. The course records the hardware results as pending, which is a normal and honest state.

### Steps

1. Install your container engine and VS Code with the Dev Containers extension.

2. On Linux with Podman, tell the extension to use Podman. Add this to your VS Code user `settings.json`:

```text
{
  "dev.containers.dockerPath": "podman"
}
```

3. Clone the course repository.

4. If you have a board, attach it now, before you open the editor. The container reads the device path when it starts and refuses to start if the path is missing. Set the path first:

```text
export ESP32_SERIAL_DEVICE=/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_<your-serial>-if00
code .
```

5. If you have no board, open `.devcontainer/devcontainer.json` and remove the `--device` line before you continue. On macOS and Windows, remove the other platform-specific lines listed in `.devcontainer/README.md`.

6. Open the repository in the container. VS Code offers this when it sees the configuration. The first start downloads the Zephyr workspace and the SDK, which takes a while. Later starts reuse it.

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

Open the page named Tier 0: Build the unsecured reference product, and work through it from the top.
