# Tier 0 fixture safety contract

Status: Resolved design for the first runnable course release.

This contract lets a Learner demonstrate insecure behavior without turning a course fixture into a general network attack tool.

## Safety boundary

Tier 0 fixtures act only on the disposable course environment created by `./course setup`.

Setup generates a random Course environment marker and writes it to `.course-state/environment.json`.

The same marker is passed to the local OTA service through generated runtime configuration.

The marker is not a security credential. It is a fail-closed identity check that prevents accidental targeting.

All device identifiers, firmware images, status values, and service records are synthetic and disposable.

## Target rules

A fixture accepts one literal target.

It never accepts a CIDR block, address range, wildcard, broadcast address, multicast address, or URL obtained through network discovery.

The default target is loopback.

A non-loopback target must be a literal RFC 1918 IPv4 address, IPv6 unique-local address, or IPv6 link-local address on an interface selected by the Learner.

DNS names other than `localhost` are refused because they can resolve outside the lab boundary.

The fixture never scans for targets and never enables promiscuous capture.

## Marker handshake

The OTA service exposes `GET /.well-known/course-environment`.

The response is JSON with this shape:

```json
{
  "schema_version": 1,
  "course_id": "learning-cyber-security",
  "environment_id": "generated-uuid",
  "tier": "00",
  "synthetic_data": true
}
```

Before any attack action, the fixture reads the expected marker from the validated Course workspace and fetches the target marker.

The fixture continues only when `course_id`, `environment_id`, `tier`, and `synthetic_data` match exactly.

The fixture refuses a missing, malformed, redirected, expired, or mismatched marker.

HTTP redirects are disabled for the marker request.

## Invocation

Every fixture supports a dry run that prints:

1. The fixture identifier.
2. The exact target and interface.
3. The marker fields that matched.
4. The expected insecure effect.
5. The files and service state that may change.
6. The reset action.
7. The evidence path.

A side-effecting run requires `--execute` and the exact fixture identifier.

The wrapper does not accept arbitrary commands, packet filters, firmware paths, device identifiers, or output paths from the Learner.

All mutable inputs come from allowlisted records in `course.yml` and generated state under `.course-state/` or `artifacts/generated/`.

## First-release fixtures

| Fixture | Permitted action | Refused behavior |
| --- | --- | --- |
| `tier-00/plaintext-inspection` | Capture or record only traffic to the configured local OTA service port and show that its HTTP fields and firmware bytes are readable. | Arbitrary packet filters, promiscuous mode, unrelated ports, or capture from another interface. |
| `tier-00/device-id-spoofing` | Submit a status event using a second synthetic device identifier from the manifest and show that Tier 0 accepts the body identifier. | Learner-supplied identifiers, owner data, or targets without the matching marker. |
| `tier-00/service-impersonation` | Start the manifest-owned impersonation service on an allowlisted local port and point only the generated course configuration at it. | ARP spoofing, DNS poisoning, gateway changes, privileged ports, or binding beyond the selected local interface. |
| `tier-00/altered-image` | Serve the generated altered Tier 0 image from the manifest-owned release directory and record that unsigned MCUboot accepts it. | Arbitrary firmware files, arbitrary upload destinations, or execution without the hardware-specific preconditions. |

The altered-image effect requires physical ESP32-C6 hardware.

Until hardware is available, host validation may prove only fixture guardrails, image generation, service delivery, and the expected command sequence.

It must record image acceptance as pending and must not claim that the image ran.

## Reset contract

Every fixture declares an idempotent reset command.

Reset stops only manifest-owned services, restores generated synthetic service state from the Tier 0 seed, removes only the fixture's named generated artifacts, and leaves Learner-authored evidence intact.

The fixture runner invokes reset after success, failure, interruption, or timeout.

If automatic reset fails, the run is marked failed and prints the exact manual reset command.

The next fixture run is refused until `./course attack reset <fixture>` restores the known state.

## Evidence record

Each run writes one JSON record under `artifacts/generated/attacks/<fixture>/<run-id>.json`.

The record contains the fixture identifier, Course environment marker fingerprint, target, selected interface, start and end times, exact command, expected effect, observed effect, result, reset result, relevant artifact hashes, and any hardware-validation limitation.

The record never contains secrets, live credentials, arbitrary packet payloads, or unrelated traffic.

Tier 0 records the insecure effect.

Tier 1 links the same record to threats, requirements, planned controls, and Residual risks without claiming the weakness is closed.

## Failure behavior

Every unmet safety precondition is a refusal before side effects.

The fixture exits nonzero and names the failed check.

It never falls back to a weaker target check, a wider address scope, a default device, or an unrestricted command.

Source: [Define the Tier 0 fixture safety contract](https://github.com/tkEmLogic/learning-cyber-security/issues/24).
