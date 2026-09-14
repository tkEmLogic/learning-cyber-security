# Fixture safety contract

Status: Resolved design. Tier 0 rules are from the first runnable course release. Tier 2, Tier 3 and Tier 4 rules extend them without weakening any of them.

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

## Key material

Every private key the course generates lives only under `.course-secrets/`. That covers the Course certificate authority, the Service certificate, the two Tier 2 bypass certificates, the Release signing key, and the attacker signing key.

A private key is never committed, never copied into `artifacts/generated/`, never written into an evidence record, and never named by a firmware build command.

The last clause is new at Tier 3 and it is deliberate. MCUboot's default is to read the public half out of the private key file at build time, which would put the Release signing key into the firmware build. The course extracts the public half once with `imgtool getpub`, and the bootloader build reads only that.

The two Tier 3 signing keys are made by the same command and are cryptographically identical. Only their names separate them. That is the lesson, so the course does not hide it behind two different generation paths, and every command that signs prints the fingerprint of the key it used.

From Tier 4 the Release signing key signs two kinds of thing, and the enumeration above covers both. It signs the MCUboot image through `imgtool`, as it has since Tier 3, and it signs the exact bytes of a Release manifest through the course helper, because `imgtool` is image shaped and a detached signature over arbitrary bytes is not an image operation. The private key is named by `./course release sign` and `./course release hostile` and by nothing else. No firmware build command names it, no service holds it, and the manifest verification key compiled into the application is the public half only, extracted the same way the bootloader's is.

These rules are hygiene. They are not the boundary that makes a firmware image authentic. The signature check is, and the Tier 3 attack proves it by publishing hostile firmware through a service that passes every check Tier 2 added.

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

Private key material for every certificate above is covered by the key material rules, which hold for every tier.

The two refusals require the physical ESP32-C6, because the refusal under test is the device's. Host validation may prove that a fixture offers the right certificate and that the guardrails hold. It may not claim that the device refused anything it was never offered.

The device's own refusal is produced by `./course service start --https --present untrusted` or `--present wrong-name`, which makes the real service hold one of the two failing certificates so a board can be watched refusing it. The service says loudly that it is doing so, and starting it again without `--present` restores the genuine certificate. Neither certificate is ever installed into any trust store.

## Tier 3 fixtures

Tier 3 publishes hostile firmware through the genuine OTA service. That is not a new mechanism. `tier-00/altered-image` already points the current release record at a manifest-owned bad image and lets the real service serve it. Tier 3 keeps the mechanism, adds four images, and adds a control that refuses them.

One fixture covers all four. The image is chosen by a manifest-owned selector, never by a Learner-supplied path, in the same way Tier 2 put its two failing certificates behind `--present`. Four separate fixtures would be four copies of one set of guardrails.

| Fixture | Permitted action | Refused behavior |
| --- | --- | --- |
| `tier-03/hostile-image` | Point the current release record at one of four manifest-owned hostile images, each built from the Learner's own good image, and let the genuine service serve it. Record what the bootloader did. | A Learner-supplied image path, a selector outside the manifest, an image not generated by this Course environment, or publishing without the matching marker. |

Every hostile image is generated at build time from the Learner's own good image. None of them is committed. This repository never carries a pre-made attack payload, because a fork would carry it too.

The four images are an unsigned image, a correctly signed image modified after signing, an image signed by a different and equally valid key, and a truncated image.

The refusal under test is the bootloader's, so it requires the physical ESP32-C6. Host validation may prove that the service offers the right bytes and that the guardrails hold. It may not claim that the device refused anything.

Reset restores the good release record and leaves the built images in place, exactly as `tier-00/altered-image` does.

## Tier 4 fixtures

Tier 4 publishes hostile release metadata through the genuine OTA service. No fixture here publishes a firmware image at all: every hostile release points at the Learner's own good image, and what is wrong with it is the signed description of that image.

Two fixtures, and they are separate on purpose. Six of the seven attacks publish wrong metadata: two of them forged, and four signed by the key holder and wrong anyway. The seventh forges nothing, because it does not need to. It is a genuinely signed older release, replayed. Burying that one among the other six would teach that the manifest signature is the control, and it is not: the replay is the one attack that survives a perfect signature.

| Fixture | Permitted action | Refused behavior |
| --- | --- | --- |
| `tier-04/hostile-release` | Point the Update assignment at one of six manifest-owned hostile releases, each derived at request time from the Learner's own signed release, and let the genuine service serve its stored manifest and detached signature unchanged. Record what was published. | A Learner-supplied manifest, release identifier, or path, a selector outside the manifest, a release not generated by this Course environment, or publishing without the matching marker. |
| `tier-04/replay-release` | Re-assign a release this Course environment actually produced, whose signed security counter is strictly lower than the one currently assigned, with its manifest and its signature untouched. | Editing a manifest or a signature, naming a release this environment did not produce, naming one of the hostile releases, or naming a release whose counter is not lower. |

**A fixture may sign a hostile Release manifest with the Release signing key.** It has to. Nobody without the key can produce a manifest that verifies, so an incompatible hardware range, a wrong channel, an unexpected size and a digest mismatch are only reachable through the Learner's own key. Those four are not outsider attacks at all: they are whoever holds the key publishing something wrong, which is what the specification's Tier 4 threat list means by "incompatible hardware assignment" and "version-policy mistakes". Signing them with any other key would have the device refuse them at the signature and never reach the check each one exists to demonstrate.

The permission is bounded exactly as Tier 3 bounds hostile images. Every hostile manifest is derived at request time from the Learner's own good manifest, none is ever committed, each carries its own release identifier, and every signing operation prints the fingerprint of the key it used.

**A fixture signing something hostile with the Release signing key must say so while doing it.** A Learner watching their own key sign a hostile manifest, with no narration, will reasonably conclude the key has leaked. The fixture says what it is signing, that the key is theirs, and why it has to be: the four valid-signature variants exist to reach the checks that run after the signature has already passed. It also says which two of the six are forgeries anyone could have made, so the Learner can tell a manufacturer mistake from an outsider attack. The device cannot tell them apart, and refuses either way, which is the lesson rather than a gap.

**The replay fixture may only name a release this Course environment actually produced, and it never edits the manifest or the signature.** It forges nothing, which is the point of it. The candidate set is the manifest-owned list of good Tier 4 releases and nothing else, because the hostile manifests live in the same directory and four of them carry a perfectly valid signature.

The replay also has a precondition no fixture can witness. MCUboot's downgrade check allows the swap outright when the image in the primary slot carries no security counter, and every image built before Tier 4 is like that. So downgrade prevention is inert until a counter-carrying image is already primary, and a replay onto a pre-Tier-4 device installs and looks like the control failing. The fixture refuses when the currently assigned release is not a signed Tier 4 release, refuses when no produced release carries a lower counter, and states the primary-slot precondition in full before it publishes anything. It never claims the precondition is met, because it cannot see the board.

Both fixtures test a refusal that only the physical ESP32-C6 can produce, because the refusal under test is the device's. Host validation may prove that a fixture published the right bytes and that the guardrails hold. It may not claim that the device refused anything.

Reset restores the assignment the Learner last signed and leaves the generated manifests in place, exactly as Tier 3 leaves its images.

## Tier 5 fixtures

**Tier 5 has no attack fixture, and that is a finding rather than an omission.**

Every other control tier needed one because something had to be made to behave badly: Tier 2 needed a service holding the wrong certificate, Tier 3 needed hostile images published, Tier 4 needed hostile metadata signed. Tier 5's five prepared releases need none of that. They are correctly signed by the Learner's own key, published through the genuine service by the ordinary `./course release sign --tier 05` path, and served unchanged. Four of them simply do not work.

There is nothing for a fixture to narrate. A fixture whose whole story is "a valid release was published normally" would be a wrapper around the command a Learner already runs, and `docs/fixture-safety-contract.md` exists to stop fixtures claiming refusals they did not see, not to require one per tier.

What an unhealthy release demonstrates is not an attack at all. Nobody without the Release signing key can produce one, so a release that crashes, hangs, fails its health checks or never reaches a verdict is the manufacturer publishing something broken, which section 11 names beside the attacks in its threat list. The device cannot tell a broken release from a leaked key, and it recovers from either the same way.

**The service may answer a firmware download badly, on request, following Tier 2's precedent.** `./course service start --range ignore` makes the genuine service answer `200` with the whole body to a request that asked for part of it, and `--range interrupt:<bytes>` makes it begin answering correctly and then drop the connection.

Both are options on the real service, exactly as `--present untrusted` is, and both are bound by the same rules. The service says loudly on every affected request what it is doing. Starting it again without the option restores correct behaviour. Neither mode alters a stored image, a manifest or a signature, and neither touches key material: the bytes served are the Learner's own signed release either way, and what is wrong is the shape of the answer rather than its content.

`--range ignore` exists because it is the failure most likely to be got wrong. It looks like success while restarting an image from byte zero underneath a device that believes it is appending, and a device that checks only whether bytes arrived will build a corrupt image out of two overlapping copies. A check that has never been observed firing has not been taught.

`--range interrupt:<bytes>` is how a Learner produces a genuine partial download without pulling power. It is deliberately not the same as serving a short file: the response headers promise the whole image and the connection then dies, which is a partial transfer the device is supposed to resume, where a short file is a size mismatch the device is supposed to refuse. Both cases exist in Tier 5 and they must not be confused, because they have opposite correct outcomes.

Neither mode can claim the device did anything. Host validation may prove the service answered badly. Only the physical ESP32-C6 can show a download resuming, an image being refused, or a trial being reverted.

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

Sources: [Define the Tier 0 fixture safety contract](https://github.com/tkEmLogic/learning-cyber-security/issues/24) for the Tier 0 rules, [Extend the fixture safety contract to HTTPS and a named service](https://github.com/tkEmLogic/learning-cyber-security/issues/41) for the transport, service name, and capture rules, [Extend the fixture safety contract to hostile firmware images and signing keys](https://github.com/tkEmLogic/learning-cyber-security/issues/53) for the key material and Tier 3 rules, and [What does the fixture safety contract need for Tier 4?](https://github.com/tkEmLogic/learning-cyber-security/issues/70) for the manifest signing and replay rules.

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
| Signing keys confined to `.course-secrets/signing`, and no build command names one | `./course keys`, `scripts/check-secrets.sh`, and `.gitignore` | Hygiene, not a boundary, and the contract says so above. Owed by [Build the Tier 3 signed release path and the four hostile images](https://github.com/tkEmLogic/learning-cyber-security/issues/56) |
| Hostile images generated at build time and never committed | the Tier 3 build path and `.gitignore` | Owed by [Build the Tier 3 signed release path and the four hostile images](https://github.com/tkEmLogic/learning-cyber-security/issues/56) |
| Hostile image chosen by manifest selector only | the attack runner, against `fixtures` in `course.yml` | Owed by [Build the Tier 3 signed release path and the four hostile images](https://github.com/tkEmLogic/learning-cyber-security/issues/56) |
| Hostile manifest signed with the Release signing key, derived at request time, its own release identifier, fingerprint printed | `releaseHostileTier04` in `internal/courseapp/tier04.go`, and `.gitignore` | Enforced |
| A fixture signing something hostile with the Release signing key says so | `releaseHostileTier04` and `tier04HostileRelease` in `internal/courseapp/tier04.go` | Enforced |
| Hostile release chosen by manifest selector only | the attack runner, against `releases` in `course.yml` | Enforced |
| The replay names only a release this environment produced, and edits nothing | `goodReleases` and `tier04ReplayRelease` in `internal/courseapp/tier04.go` | Enforced |
| The replay states the primary-slot precondition it cannot witness | `tier04ReplayRelease` in `internal/courseapp/tier04.go` | Enforced |

When a rule moves, this table moves with it.
