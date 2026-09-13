# Fixture safety contract

Status: Resolved design. Tier 0 rules are from the first runnable course release. Tier 2 rules extend them without weakening any of them.

This contract lets a Learner demonstrate insecure behavior, and later watch a control refuse it, without turning a course fixture into a general network attack tool.

It covers every tier. A rule written here holds for every fixture unless a later section names a narrower case.

## Safety boundary

Fixtures act only on the disposable course environment created by `./course setup`.

Setup generates a random Course environment marker and writes it to `.course-state/environment.json`.

The same marker is passed to the local OTA service through generated runtime configuration.

The marker is not a security credential. It is a fail-closed identity check that prevents accidental targeting.

All device identifiers, firmware images, status values, and service records are synthetic and disposable.

## Target rules

A fixture accepts one literal target.

A fixture's target is always the plain endpoint that serves the Course environment marker. It is never an HTTPS URL, in any tier.

This is stronger than the rule first written here, and it came out of building Tier 2. A fixture that needs the TLS endpoint derives it from the manifest: the same host, and the port and service name recorded in `course.yml`. Nothing about a TLS endpoint is ever supplied on a command line, so `validateTarget` keeps refusing every scheme but `http` and the guardrail loses nothing.

A fixture that uses the TLS endpoint says so in `course.yml` with `uses_tls_port`. That flag decides which transport its reset travels over. It is an allowlisted manifest input like every other mutable value, never a Learner-supplied one.

It never accepts a CIDR block, address range, wildcard, broadcast address, multicast address, or URL obtained through network discovery.

The default target is loopback.

A non-loopback target must be a literal RFC 1918 IPv4 address, IPv6 unique-local address, or IPv6 link-local address on an interface selected by the Learner.

DNS names other than `localhost` are refused because they can resolve outside the lab boundary. This rule does not change when the course adds TLS. See the service name rules below.

The fixture never scans for targets and never enables promiscuous capture.

## Service name rules

From Tier 2 the device verifies the service certificate against a name. That name is a verification input, never a resolution input.

The target of a connection stays one literal loopback or private address, exactly as the target rules require. The name the certificate must match is a separate allowlisted field in `course.yml`, passed to the TLS layer as the value to check.

No resolver is consulted. The device passes the name through `TLS_HOSTNAME` while connecting to the literal address. Host-side tools pin the same mapping instead of resolving the name.

The consequence is that adding TLS costs the contract no ground. No target is ever a name, so the rule refusing DNS names stands unchanged, and the firmware needs no resolver.

A fixture that tests a name mismatch uses a second manifest-owned certificate carrying a different name. It never accepts a name from the Learner.

## Transport rules

The OTA service runs in one of two modes, recorded per tier in `course.yml` and selected by a `--https` switch that `./course service start` passes.

Without the switch, every endpoint is served over plain HTTP on the HTTP port. This is the Tier 0 service, and it does not change, because the Tier 0 module is published and describes it exactly.

With the switch, release records, firmware bytes, and status events move to TLS on the TLS port. Health and the environment marker stay on the HTTP port in the clear.

The marker and health endpoints are plain HTTP in every mode and every tier. That is deliberate, and the reason is in the next section.

The impersonation service follows the same rule: it presents its own untrusted certificate on its TLS port and answers marker requests in the clear.

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

The marker request is always plain HTTP, in every tier, including tiers whose data endpoints are protected by TLS.

A safety check must not depend on the control it is being used to test. If the marker were fetched over TLS, a fixture would either have to verify a certificate before it is allowed to find out whether it is pointed at the lab, which makes the control a precondition for testing the control, or skip verification, which would ship the one example this course tells Learners never to write. The impersonation fixture settles it: its imposter presents a deliberately untrusted certificate, so a TLS marker check would refuse the very fixture it is meant to guard.

The marker is not a security credential. It carries only synthetic identifiers, it is a fail-closed check against accidental targeting, and it is the one thing a Tier 2 packet capture still shows in the clear. The Tier 2 module says so rather than leaving a Learner to discover it in a capture and draw the wrong conclusion.

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

## Tier 0 fixtures

| Fixture | Permitted action | Refused behavior |
| --- | --- | --- |
| `tier-00/plaintext-inspection` | Capture or record only traffic to the configured local OTA service port and show that its HTTP fields and firmware bytes are readable. | Arbitrary packet filters, promiscuous mode, unrelated ports, or capture from another interface. |
| `tier-00/device-id-spoofing` | Submit a status event using a second synthetic device identifier from the manifest and show that Tier 0 accepts the body identifier. | Learner-supplied identifiers, owner data, or targets without the matching marker. |
| `tier-00/service-impersonation` | Start the manifest-owned impersonation service on an allowlisted local port and point only the generated course configuration at it. | ARP spoofing, DNS poisoning, gateway changes, privileged ports, or binding beyond the selected local interface. |
| `tier-00/altered-image` | Serve the generated altered Tier 0 image from the manifest-owned release directory and record that unsigned MCUboot accepts it. | Arbitrary firmware files, arbitrary upload destinations, or execution without the hardware-specific preconditions. |

The altered-image effect requires physical ESP32-C6 hardware.

Until hardware is available, host validation may prove only fixture guardrails, image generation, service delivery, and the expected command sequence.

It must record image acceptance as pending and must not claim that the image ran.

## Tier 2 fixtures

These rules bind the fixtures that Tier 2 will add, before they are written.

| Fixture | Permitted action | Refused behavior |
| --- | --- | --- |
| Plaintext inspection, replayed | Ask the HTTP port for the release record and show that it is no longer served there, and capture the device's traffic on the TLS port to show that nothing after the handshake is readable. | Any attempt to recover plaintext by downgrading the service, disabling verification, or capturing outside the manifest-owned ports. |
| Service impersonation, replayed | Start the manifest-owned impersonation service holding a certificate for the right name from an authority the device does not trust, and point only the generated course configuration at it. This is also the untrusted-authority test: the two were separate rows here until building them showed they are one attack. | Supplying a certificate from outside the manifest, or installing any certificate into a trust store the Learner did not generate for this Course environment. |
| Name mismatch | Offer a certificate issued by the trusted course authority that carries a different manifest-owned name, and record the refusal. | Learner-supplied names, wildcard names, or a name that resolves anywhere. |

Every Tier 2 fixture keeps the Tier 0 guarantees without exception: one literal target, dry run first, exact execution identifier, marker match over plain HTTP, idempotent reset, and a machine-readable evidence record.

A fixture that reports a refusal without showing which check ran, what it compared, and what it rejected fails this contract, because the course's evidence value is in the mechanism and not in the verdict.

Private key material for every certificate above lives only under `.course-secrets/`. It is never committed, never copied into `artifacts/generated/`, and never written into an evidence record.

The two refusals require the physical ESP32-C6, because the refusal under test is the device's. Host validation may prove that a fixture offers the right certificate and that the guardrails hold. It may not claim that the device refused anything it was never offered.

## Capture rules

A fixture may capture traffic only under these bounds.

One interface, which is the interface already selected for the target.

Only the ports the manifest records for the OTA service and the impersonation service. No other port, and no unrelated traffic.

A filter the course builds from manifest values. The Learner never supplies a filter, and the fixture prints the exact filter it used, so the bound is visible rather than merely stated.

A bounded duration, declared by the fixture and enforced by the runner.

No promiscuous mode, ever.

The capture is written under `artifacts/generated/attacks/<fixture>/` like any other evidence, and the evidence record names it.

A capture never contains a live credential, because the lab holds none. It may contain the environment marker, which is synthetic by construction.

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

Sources: [Define the Tier 0 fixture safety contract](https://github.com/tkEmLogic/learning-cyber-security/issues/24) for the Tier 0 rules, and [Extend the fixture safety contract to HTTPS and a named service](https://github.com/tkEmLogic/learning-cyber-security/issues/41) for the transport, service name, and capture rules.

## Where each rule is enforced

A rule with no named enforcement point is a wish. This table says where each rule lives, and it distinguishes what the code does today from what a named ticket still owes.

| Rule | Enforced in | State |
| --- | --- | --- |
| One literal target, no DNS name but `localhost`, no wildcard or multicast, private or loopback only | `validateTarget` in `internal/courseapp/app.go` | Enforced |
| Interface selection matches the target | `validateSelectedInterface` in `internal/courseapp/app.go` | Enforced |
| Dry run by default, exact execution identifier | the attack runner in `internal/courseapp/app.go`, with `safety.dry_run_default` and `safety.execute_identifier_required` in `course.yml` | Enforced |
| Marker handshake, and that it is plain HTTP | the attack runner, against `services.ota.marker` in `course.yml` | Enforced, and already plain HTTP because no other transport exists yet |
| Idempotent reset and refusal after a failed reset | the attack runner, with `safety.refuse_after_failed_reset` in `course.yml` | Enforced |
| Evidence record contents | `writeAttackEvidence` in `internal/courseapp/app.go` | Enforced |
| Targets are always plain, TLS endpoints are derived from the manifest | `validateTarget` in `internal/courseapp/app.go`, unchanged, plus `uses_tls_port` in `course.yml` | Enforced |
| Service name as a verification input | `coursepki.ServiceName`, the firmware build, and `verifyingClient` in `internal/courseapp/tier02.go` | Enforced |
| Transport mode per tier | the `--https` switch on the OTA service | Enforced |
| Capture bounds | `captureExchange` in `internal/courseapp/tier02.go`, from manifest ports only, with the filter printed | Enforced, and skipped with an explanation when the container has no capture tool |
| Private keys confined to `.course-secrets/` | `internal/coursepki`, `scripts/check-secrets.sh`, and `.gitignore` | Enforced |

When a rule moves, this table moves with it.
