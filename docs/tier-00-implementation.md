# Tier 0 implementation

Tier 0 implements the unsecured Reference product as a host-validated course state.

## Repository responsibilities

| Path | Responsibility |
| --- | --- |
| `course.yml` | Versioned runtime, path, component, service, device, fixture, evidence, safety, checkpoint, and verification contract |
| `course` | Thin Bash dispatcher |
| `tools/course/` and `internal/courseapp/` | Structured command behavior and guardrails |
| `services/ota/` | Intentionally insecure local HTTP OTA service |
| `firmware/reference-product-baseline/` | Pinned ESP32-C6 Zephyr sysbuild and status beacon boundary |
| `attack-fixtures/` | Fixture safety explanation, with execution owned by the Go helper and manifest |
| `course-material/` | Learner-facing Tier 0 module and planned Tier 1 transition |
| `evidence/` | Versioned schemas, Learner templates, and separate generated examples |
| `tests/` and Go test files | Host, integration, safety, schema, and verification checks |

## Service protocol

The service preserves the later pull protocol shape through release lookup, manifest serving, firmware serving with HTTP range support, and `POST /v1/devices/{device_id}/events`.

Tier 0 trusts the JSON body `device_id` even when it differs from the path.

The current release record is mutable and unsigned.

The service exposes an exact Course environment marker and explicit seed and reset endpoints.

The service uses HTTP. It runs as a process inside the dev container, listening on every address there, and the container publishes the port to the host. `./course setup --bind` chooses the address the Reference product uses to reach it.

## Firmware boundary

The firmware builds with Zephyr 4.4.2 and MCUboot 2.4.0 in unsigned swap-with-scratch mode.

The source models steady, fast-blink, and slow-blink states and names the prepared HTTP assignment and status endpoints.

The selected development board has no checked-in LED alias, and no physical board is available.

The implementation therefore does not invent a GPIO or claim LED, Wi-Fi, flash, serial, update, or recovery behavior.

## Checkpoints

The manifest names `course-v1.0-tier-00-start` and `course-v1.0-tier-00-complete`.

Issue 28 owns checkpoint publication.

This ticket does not create or move tags.
