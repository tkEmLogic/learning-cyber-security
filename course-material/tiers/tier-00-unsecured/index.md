# Tier 0: Build the unsecured reference product

## Incident brief

An industrial status beacon downloads firmware and reports a machine state over the local network.

The product works, but the network and update path have no security controls.

A local actor can read the HTTP exchange, claim another synthetic device identifier, imitate the OTA service, and provide an altered unsigned image.

Your task is to build this baseline, reproduce each safe fixture, and record what is absent.

## Learning result

After this tier, you can:

- Build the ESP32-C6 Reference product with unsigned MCUboot.
- Run the local HTTP OTA service.
- Explain why functional behavior is not secure behavior.
- Demonstrate four controlled Tier 0 weaknesses.
- Keep hardware-only results pending when no physical board is available.
- Create the first Lab artifacts and Weakness ledger.

## Safety boundary

Run this tier only against the disposable Course environment created by `./course setup`.

Use only synthetic identifiers and generated firmware.

The fixtures default to loopback and refuse public addresses, ranges, wildcards, discovery, redirects, and DNS names other than `localhost`.

Every fixture is a dry run unless you provide `--execute` with the exact fixture identifier.

## Starting state

You need a current Linux host with Go, Git, curl, Python 3 with virtual environment support, and Docker Compose or Podman Compose.

Ubuntu 24.04 is the CI reference environment.

The pinned Zephyr workspace uses Zephyr 4.4.2, MCUboot 2.4.0, and Zephyr SDK 1.0.1.

A physical ESP32-C6 is optional for host work and required for flash, serial, LED, Wi-Fi, and altered-image execution evidence.

## Weakness ledger before the work

| Weakness | Attack vector | Expected Tier 0 result | Later treatment |
| --- | --- | --- | --- |
| HTTP has no confidentiality | Read the local release and firmware response | Fields and bytes are readable | Tier 2 |
| The service trusts the body device identifier | Submit the second manifest-owned identifier | Spoofed status is accepted | Tier 7 |
| The device has no authenticated service | Use the marker-matching local impersonation service | Hostile release data is accepted | Tier 2 |
| MCUboot accepts unsigned images | Serve the generated altered image | The device installs and runs the altered image | Tier 3 |
| Release metadata is mutable | Replace the current release record | New record is served | Tier 4 |

## Reproduce the controlled attacks

### Predict

Write down which asset is exposed by each fixture.

State which observation needs a physical device.

### Inspect the fixture plan

Run from the repository root:

```text
./course attack list
./course attack run tier-00/plaintext-inspection
./course attack run tier-00/device-id-spoofing
./course attack run tier-00/service-impersonation
./course attack run tier-00/altered-image
```

Expected result:

```text
Marker matched
Result: dry run only
Execute: ./course attack run <fixture> --execute <fixture>
```

## Investigate the missing boundaries

Answer:

1. Which component supplies firmware bytes?
2. Which component decides whether those bytes may run?
3. What proves the service identity?
4. What proves the device identity?
5. What proves the firmware publisher identity?
6. Which result cannot be claimed without physical hardware?

Use this baseline architecture:

```text
Synthetic device status
        |
        | plaintext HTTP with shared identifier
        v
Local OTA service <---- mutable release record
        |
        | plaintext HTTP firmware bytes
        v
ESP32-C6 secondary slot ---> unsigned MCUboot ---> Zephyr application
```

No authenticated trust boundary exists in this Tier 0 path.

## Build and run the baseline

### Check the host

Install the pinned Python packages in generated state:

```text
python3 -m venv build/python
build/python/bin/pip install -r requirements.txt
```

The Tier 0 verification command uses these packages to validate JSON and YAML files.

Then run:

```text
./course doctor
```

Expected result:

```text
Go, Git, and curl are available
At least one compose runtime qualifies
Hardware is pending when no stable serial path exists
```

### Create generated state

If both runtimes qualify, choose one explicitly:

```text
./course setup --runtime docker
```

Use `podman` instead of `docker` when needed.

Expected result:

```text
created synthetic Tier 0 environment
Next: ./course service start
```

### Start the OTA service

```text
./course service start
./course service status
```

Expected result:

```text
OTA service is healthy
```

### Build the host components

```text
./course build host
```

Expected result:

```text
Go helper and OTA service build successfully
```

### Give the device a network and a service address

The Reference product joins one Wi-Fi network and talks to one OTA service address. Both values are compiled into the firmware image. Tier 0 has no way to change them on the device.

A physical board cannot reach a service bound to loopback. Run setup again with the private address of this host, and name the course Wi-Fi network at the same time:

```text
./course setup --runtime podman --bind 192.168.0.10 --wifi-ssid course-lab --wifi-psk <passphrase>
```

Use your own values. The network must meet these conditions:

| Condition | Reason |
| --- | --- |
| 2.4 GHz | The ESP32-C6 radio used here does not support 5 GHz |
| WPA2-PSK | Tier 0 supports no other Wi-Fi security type |
| Same Layer 2 network as this host | The device connects to the host by address, with no routing |
| Client isolation switched off | The device must be allowed to reach the host |

The passphrase is written to `.course-secrets/wifi.conf`. Git ignores that directory. Never commit it.

Do not use a network that carries real traffic. Use a disposable lab network or a phone hotspot.

### Build the pinned firmware

```text
ZEPHYR_WORKSPACE=/path/to/zephyr-v4.4.2 ./course build firmware
```

Expected result:

```text
Generated: .course-state/firmware/baseline.conf for 192.168.0.10:8080, network "course-lab"
Build completed: /path/to/zephyr-v4.4.2/build/reference-product-baseline
Result: built baseline release tier-00-baseline, 590396 bytes
```

The build copies the finished image to `artifacts/generated/releases/tier-00-baseline.bin` and makes it the release the service assigns.

The firmware models steady, fast-blink, and slow-blink states. It reports the state on the serial console. The onboard LED of the validated board cannot be driven, so there is no LED output to observe.

The firmware joins the Wi-Fi network, reports its status over plain HTTP, reads its update assignment, and installs any release the service names.

Flash, serial logs, and OTA installation remain pending until tested on a physical ESP32-C6.

### Flash the board and watch it work

Attach one ESP32-C6 board. Then run:

```text
./course device flash
```

The command refuses to continue when no board is attached, or when more than one Espressif board is attached. It writes normal flash only. It runs no eFuse, secure boot, or flash encryption command.

Watch the device with:

```text
./course device logs
```

Press the board's reset button. Expected result:

```text
ESP32-C6 Reference product: intentionally unsecured Tier 0
Image label: baseline
Running release: tier-00-baseline
wifi.connecting ssid=course-lab security=wpa2-psk band=2.4GHz
wifi.association succeeded ssid=course-lab
wifi.address 192.168.0.34 assigned by DHCP
ota.assignment release_id=tier-00-baseline version=0.0.0-insecure image=tier-00-baseline.bin
ota.assignment matches the running release, nothing to install
```

Leave the log view with Ctrl-].

The device repeats this exchange every 30 seconds. Every status report crosses the network in plain text and names the shared device identifier.

## Run the fixtures

Run:

```text
./course attack run tier-00/plaintext-inspection --execute tier-00/plaintext-inspection
./course attack run tier-00/device-id-spoofing --execute tier-00/device-id-spoofing
./course attack run tier-00/service-impersonation --execute tier-00/service-impersonation
./course attack run tier-00/altered-image --execute tier-00/altered-image
```

Expected host results:

| Fixture | Expected result |
| --- | --- |
| Plaintext inspection | Release fields and firmware bytes are readable |
| Device-ID spoofing | The service accepts the second synthetic identifier from the body |
| Service impersonation | Generated device configuration accepts the marker-matching HTTP service |
| Altered image | The altered unsigned image is generated and served |

Each run writes JSON under `artifacts/generated/attacks/`.

Each run resets the service to the Tier 0 seed.

Without a board, the altered-image record must state that physical acceptance and execution are pending.

### Watch the device accept the altered image

This step needs a physical ESP32-C6. Skip it when you have no board, and keep the hardware fields pending.

Build the altered image. It is a complete, runnable firmware image that reports a different label and a different machine state:

```text
./course build firmware --variant altered
```

Start the log view in a second terminal:

```text
./course device logs
```

Then publish the altered image as the current release:

```text
./course attack run tier-00/altered-image --execute tier-00/altered-image --hold 200
```

Within one poll interval the device reads the new assignment and installs it. Expected result:

```text
ota.assignment release_id=tier-00-altered version=0.0.0-altered image=tier-00-altered.bin
ota.assignment differs from running release tier-00-baseline, installing without any check
ota.install starting release_id=tier-00-altered version=0.0.0-altered size=590396
ota.install declared_sha256=... (Tier 0 does not check it)
ota.install wrote 590396 bytes to the secondary slot
ota.upgrade requested permanent overwrite, no test boot, no rollback
Rebooting into the newly installed image
```

MCUboot then overwrites the running image with the downloaded one:

```text
I: Image index: 0, Swap type: perm
I: Image 0 upgrade secondary slot -> primary slot
I: Erasing the primary slot
I: Image 0 copying the secondary slot to the primary slot: 0x90240 bytes
I: Jumping to the first image slot
```

After the reboot the board runs the altered image:

```text
Image label: altered
Running release: tier-00-altered
Beacon state: fast, toggle period: 200 ms
```

The device accepted firmware from an unauthenticated service, with no signature and no publisher identity. Nothing in Tier 0 could have stopped it.

Return the device to the baseline:

```text
./course attack reset tier-00/altered-image
```

The service assigns the baseline release again. The device installs it on its next poll and reports `Image label: baseline`. Note what this shows: Tier 0 also accepts an older release, because it has no anti-rollback policy. That weakness is `T0-W-06`.

The fixture holds the insecure state only while it runs. Give the device time to poll by adding `--hold <seconds>`, for example `--hold 200`. Without a hold, the fixture restores the baseline release before any device can read the altered one.

Record what you observed in the accepted-image record. Set `device_flash`, `device_boot`, and `serial_record` to your observation. Keep `led_behavior` pending, because the validated board cannot drive its onboard LED.

## Replay the original observation

No security control is added in Tier 0.

The same host fixtures still produce the insecure effects after reset.

Tier 1 will turn these observations into threats, requirements, claims, and planned controls.

## Test safety and failure behavior

Run:

```text
./course attack run tier-00/plaintext-inspection --target http://example.com --execute tier-00/plaintext-inspection
```

Expected result:

```text
refused: DNS names other than localhost are refused
```

Run a fixture with the wrong execution identifier.

Expected result:

```text
refused: --execute value must exactly match the fixture identifier
```

If reset fails, the fixture is blocked.

Run the exact reset command before another attempt.

## Weakness ledger after the work

| Weakness | Observed result | Status | Evidence |
| --- | --- | --- | --- |
| HTTP has no confidentiality | Metadata and image bytes are readable | Open | Plaintext fixture JSON |
| Body device identifier is trusted | Spoofed identifier is accepted | Open | Device-ID fixture JSON |
| Service is not authenticated | Impersonation record is accepted | Open | Impersonation fixture JSON |
| Firmware has no authenticity check | Altered image is delivered | Open | Altered-image fixture JSON |
| Physical altered-image execution | The board ran the altered image | Open | Accepted-image record |

## Security claim and evidence status

Tier 0 makes no positive security claim.

The supported statement is limited to what you observed: the local service and fixtures reproduce the intended insecure effects.

Without a board, the firmware build supports only a build claim for the pinned target, and physical flash, serial output, Wi-Fi behavior, and altered-image execution stay pending.

With a board, you can record flash, serial output, Wi-Fi association, the HTTP exchange, the OTA download, and altered-image execution as observed. LED behavior stays pending, because the validated board cannot drive its onboard LED.

Run `./course device status` to see which hardware results the course currently claims.

## Update the Security evidence pack

Create the Learner evidence directory and copy the four templates:

```text
mkdir -p evidence/learner/tier-00
cp evidence/templates/tier-00/*.json evidence/learner/tier-00/
./course evidence context
```

The context command prints the current source revision, Course environment identifier, marker fingerprint, and latest fixture evidence paths.

Do not edit the files under `evidence/examples/`.

Update:

- The baseline architecture.
- The captured HTTP exchange.
- The accepted-image record with hardware fields still pending when not observed.
- The deliberately absent controls.
- `created_at`, `source_revision`, `environment.environment_id`, and `environment.marker_fingerprint` in every record.
- The fixture evidence paths.

Set the architecture, HTTP exchange, and absent-controls records to `observed`. Keep the accepted-image record `pending` when no physical ESP32-C6 was used. Do not replace a pending hardware field with a host-only result.

Run:

```text
./course evidence check
```

Expected result:

```text
Learner Tier 0 evidence is complete and bound to the current revision and Course environment
```

## Troubleshooting

| Observation | First check |
| --- | --- |
| Both runtimes qualify | Repeat setup with `--runtime docker` or `--runtime podman` |
| The service does not start | Run `./course service status` and inspect the printed compose command |
| Marker mismatch | Stop the service, run setup again, then start the service |
| A fixture stays blocked | Run `./course attack reset <fixture>` |
| Firmware build cannot find West | Set `ZEPHYR_WORKSPACE` to the pinned external workspace |
| No serial device exists | Keep hardware results pending |

## Informal Mentor conversation

Tier 0 has no required Mentor review gate.

You may still ask a Mentor to review the architecture and one uncomfortable limitation.

Show the host fixture evidence and explain why it does not prove physical device behavior.

## Transition to Tier 1

Keep this Course workspace.

Tier 1 will continue on the same Learner branch and workspace after the Tier 0 completion checkpoint is published.

The checkpoint names are `course-v1.0-tier-00-start` and `course-v1.0-tier-00-complete`.

Issue 28 owns checkpoint publication, so this implementation does not create or move those tags.

Next: **Model the product and its risks**.

## Primary references

- [Zephyr device management OTA overview](https://docs.zephyrproject.org/4.4.2/services/device_mgmt/ota.html), required explanatory reading, whole page.
- [MCUboot readme for Zephyr](https://docs.mcuboot.com/readme-zephyr.html), required explanatory reading, the Building and Signing the application sections.
- [Zephyr device firmware upgrade with MCUboot](https://docs.zephyrproject.org/4.4.2/services/device_mgmt/dfu.html), optional explanatory reading, the MCUboot and image management sections.
