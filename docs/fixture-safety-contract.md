# Fixture safety contract

Status: Resolved design. Tier 0 rules are from the first runnable course release. Tier 2, Tier 3, Tier 4, Tier 6 and Tier 7 rules extend them. Tier 6 is the first to carry a named exception rather than only additions, and it is bounded in the section that takes it. Tier 7 takes no new exception, and it writes the tightest bounds in this document, because its adversary holds a signing key that a correctly configured service obeys.

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

Every private key the course generates lives only under `.course-secrets/`. That covers the Course certificate authority, the Service certificate, the two Tier 2 bypass certificates, the Release signing key, the attacker signing key, and, from Tier 7, the Operational Device CA.

A private key is never committed, never copied into `artifacts/generated/`, never written into an evidence record, and never named by a firmware build command.

**Tier 6 takes one bounded exception to the last two clauses and nothing else takes any.** One throwaway credential, the shared development identity, is compiled into one firmware variant so that a Learner can extract it from an image they built themselves, which means a firmware build command names it and the built image is key material while it exists. The bound is written out in "Tier 6 fixtures" below, and it is enforced rather than only stated: `scripts/check-secrets.sh` refuses a tracked anchor include that carries a byte list, which is the shape a committed key would take. Every other clause holds unchanged for every tier, including Tier 6.

The last clause is new at Tier 3 and it is deliberate. MCUboot's default is to read the public half out of the private key file at build time, which would put the Release signing key into the firmware build. The course extracts the public half once with `imgtool getpub`, and the bootloader build reads only that.

The two Tier 3 signing keys are made by the same command and are cryptographically identical. Only their names separate them. That is the lesson, so the course does not hide it behind two different generation paths, and every command that signs prints the fingerprint of the key it used.

From Tier 4 the Release signing key signs two kinds of thing, and the enumeration above covers both. It signs the MCUboot image through `imgtool`, as it has since Tier 3, and it signs the exact bytes of a Release manifest through the course helper, because `imgtool` is image shaped and a detached signature over arbitrary bytes is not an image operation. The private key is named by `./course release sign` and `./course release hostile` and by nothing else. No firmware build command names it, no service holds it, and the manifest verification key compiled into the application is the public half only, extracted the same way the bootloader's is.

From Tier 7 a course service holds a CA signing key for the first time, and that is recorded rather than slipped in. Started with `--mutual-tls`, the OTA service reads the Operational Device CA private key and issues Operational certificates with it. The material reaches it as one `COURSE_PKI_DIR` rather than as separate variables naming separate files. In a defensible process an operational CA signs for a service and is not the service, so this is a Weakness the module names rather than a property the course claims. The Tier 7 fixture reads the same key by the same route, and the bounds on what it may sign with it are in "Tier 7 fixtures" below.

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

## Tier 6 fixtures

These rules bind the fixture Tier 6 will add, before it is written, following the
Tier 2 precedent above.

Tier 6 adds two pieces of Learner-facing machinery and **only one of them is a
fixture**. That distinction is the first rule here, because getting it wrong in
either direction is a real cost: machinery on something that needs none implies
a check happened, and no machinery on something that changes shared state
removes the guardrail that matters.

**Extraction is an ordinary `./course` command, not a fixture.** It reads the
Learner's own built shared identity image, finds the credential compiled into
it, and reports it. It has no target, opens no socket, and changes no service
state, so target validation, the marker handshake and a reset would guard
nothing while implying a marker check had happened. This is the same reading
that made Tier 5 record having no attack fixture: the contract exists to stop
fixtures claiming refusals they did not see, not to require one per tier.

**The extraction command takes no path.** It derives the image it reads from the
manifest, the same way every other mutable input is derived, and it accepts no
file name on the command line. A command that searched any binary a Learner
named would be a general-purpose key-recovery tool wearing a course label, and
this contract exists precisely to keep the course from shipping one. It reads
one manifest-named image or it refuses.

**The extraction command prints a fingerprint and never the key.** It narrates
what it searched for, where it found it, and what that means, because a command
that prints `Result: key extracted` teaches nothing. The evidence record carries
the fingerprint only, exactly as every other record carries hashes rather than
contents.

**The clone is a fixture**, and its target is the provisioning station and the
manufacturing record rather than the OTA service. It keeps every Tier 0
guarantee, including the marker handshake, even though it opens no socket to do
its work. The handshake is about which environment a fixture may act in, not
about which socket it opens, and a fixture that appends to a manufacturing
record is acting on shared state whether or not a packet leaves the host.

| Fixture | Permitted action | Refused behavior |
| --- | --- | --- |
| `tier-06/clone-shared-identity` | Extract the fleet credential from the Learner's own manifest-named shared image, and use it to answer the station's nonce, twice: once under an identifier the manufacturing record already holds, and once for each manifest-owned identifier that was never manufactured. Record every request and every answer. | A Learner-supplied image path, identifier, or count. An identifier that this Course environment's station never issued and that the manifest does not name. Acting without the matching marker. Writing to any store other than the manufacturing record. |

The identifier it takes over is read **from the manufacturing record itself**,
never from the command line, so the clone can only impersonate a device this
Course environment actually manufactured. The identifiers it invents come from a
manifest-owned list of a fixed length. An unbounded loop appending to a file is
not a demonstration of scale, it is a way to fill a disk.

### One credential is deliberately compiled into firmware

This is the one place in the entire course where a private key reaches a
firmware build, and it breaks the key material rule that has held since Tier 3.
The exception is bounded, and the bound is written here rather than left to be
inferred, because the next reader will otherwise take it as the rule relaxing.

The exception covers **one credential and no other**: the shared development
identity in `.course-secrets/pki/shared-identity.key.pem`, generated locally by
`./course keys create shared-identity`, never committed, used by nothing except
the Tier 6 shared image and the clone fixture, and trusted by nothing except the
provisioning station's own record of it. It signs no firmware, authorizes no
release, and is not in any trust store.

It exists because a credential a Learner cannot extract from their own image
cannot teach why shared credentials fail. A tier that asserted the problem
instead of handing them the key would be teaching the conclusion rather than the
mechanism.

Everything else about the key material rules holds unchanged. The Release
signing key is still named by `./course release sign` and `./course release
hostile` and by nothing else. The device CA's private half is named only by the
provisioning station. No firmware build command names either of them.

Two consequences follow and both are stated rather than hidden:

- **The build environment variable is set for the shared variant only.** The
  factory build does not have the key on its include path at all, which is a
  stronger statement than "it does not include it" and is checkable: the SEC1
  structure appears in the shared image and its scalar appears nowhere in the
  factory one.
- **The built shared image is key material.** `artifacts/generated/releases/`
  and the Zephyr build tree hold a private key while that image exists, so the
  rule that private keys live only under `.course-secrets/` gains its one named
  exception here. Both directories are already ignored, and the image is
  regenerated rather than kept.

### What the clone's reset restores, and what it cannot

**The manufacturing record is append only, so the clone's reset does not remove
what the clone wrote, and must not be made able to.**

Append-only is not an implementation detail of the record, it is the property
that makes the station's central claim true: a credential is consumed and a
certificate is recorded in one write, so nothing ever leaves the station that
the record does not already contain. A reset that deleted lines would make the
store mutable, and the claim would quietly stop being true for the sake of
tidying up after a fixture.

So reset **appends**. It writes one `fixture_reset` entry naming the run and the
entries that run produced, and `./course provision record` shows it in place, in
order, beside them. The phantom devices stay in the record forever.

That is the finding, not a limitation of the tooling. A cloned credential's
damage to a manufacturing record is not reversible by the party who discovers
it, and the fixture that ends by admitting it cannot undo itself teaches more
than one that pretends it can.

This narrows one promise the general reset contract makes above, and the
narrowing is deliberate:

- The general rule says reset "restores the known state". For this fixture the
  known state of the record cannot be restored, and reset restores the station's
  operational state instead, which is the absence of a transaction in flight.
  There is nothing else it touched.
- The rule refusing the next run until reset has succeeded still holds, and the
  `fixture_reset` entry is what satisfies it.
- A Learner who wants the record empty again discards the whole Course
  environment with the existing cleanup path. That is an environment reset, not
  a fixture reset, and the contract does not let a fixture reach for it.

### Reading the board's flash

Tier 6 is the first tier that tells a Learner to read their own device's flash,
so it gets a rule rather than an assumption.

**The dump is bounded to the `storage` partition.** That partition holds the PSA
Secure Storage record and Tier 5's resume records and nothing else. Reading it
demonstrates everything the tier needs: the device's private key is in there,
encrypted with a key derived from a value the device broadcasts. Reading the
whole flash would additionally copy the Wi-Fi credentials compiled into the
application image, which are the Learner's real network and not synthetic, and
the tier gains nothing by it.

**A dump is key material and is treated as such.** It contains the device's
Factory private key in a form the module then decrypts on purpose. It is written
under `artifacts/generated/`, which is ignored, it is never committed, and the
evidence record names its hash rather than its contents.

This is a named exception to the capture rule above, which says a capture never
contains a live credential because the lab holds none. A storage-partition dump
does contain one. The difference is that a capture observes a network the course
does not own, while a dump reads a disposable board the Learner provisioned two
commands ago, and the credential in it is one this Course environment generated
for the purpose.

**`esptool` leaves the chip in ROM download mode after a dump**, where the
application never runs and the console is silent, which looks exactly like a
board the Learner has broken. Any command that dumps flash follows it with the
reset that pulses RTS, and says it is doing so.

### Manifest entries these read

Every mutable input stays allowlisted, so both pieces of machinery read the
manifest and nothing else.

| Entry | Read by | For |
| --- | --- | --- |
| `fixtures.tier-06/clone-shared-identity.target`, `.interface` | the clone | the marker handshake and interface check, unchanged from Tier 0 |
| `fixtures.tier-06/clone-shared-identity.image` | the clone and the extraction command | which built image the credential is taken from, so no path is ever supplied |
| `fixtures.tier-06/clone-shared-identity.phantom_ids` | the clone | the fixed list of never-manufactured identifiers, so the count is bounded and the names are not invented at run time |
| `fixtures.tier-06/clone-shared-identity.changes`, `.reset`, `.hardware_required` | the runner | the standard dry-run disclosure and reset path |
| `paths.state`, `paths.generated_artifacts` | both | where the record and the evidence live |

The clone is `hardware_required: false`. It runs entirely on the host, and that
is the lesson rather than a compromise forced by owning one board: a copied
credential does not need the hardware it was copied from. What it may not claim
is anything about a board, and the refusal it produces after hardening is the
station's own.

## Tier 7 fixtures

These rules bind the adversary Tier 7 will add, before it is written, following the Tier 2 and Tier 6 precedent above.

Tier 7's adversary is sharper than every fixture before it, and the section says so first rather than last. Tier 3 and Tier 4 published bytes a control was built to refuse. Tier 6's clone answered a station's nonce with a credential a Learner had already extracted. Tier 7's adversary mints certificates that a correctly configured service accepts, holds a legitimate owner account, and holds the private half of the authority that issues operational identity. Its power is not a trick the course invented. It is the Operational CA key having leaked, which is the threat the module names.

**The adversary is one actor, not a set of fixtures, and it is not registered in `course.yml`.** It lives under `./course service bypass e-7-NN`, a sibling of `./course service start`, in the same way Tier 6's five station refusals were plain runners beside one registered fixture. This contract exists to stop fixtures claiming refusals they did not see, not to require a registered fixture per tier. So Tier 7 gets written rules instead of a manifest fixture entry, and every rule in this section binds every `./course service bypass` runner. Where this section says "the fixture", it means that one adversary.

**The runners open sockets and write shared state, so they keep the Tier 0 guarantees that matter.** Dry run first, exact row identifier to execute, marker handshake over plain HTTP, bounded and manifest-owned inputs, an idempotent reset, and a machine-readable evidence record. Tier 6's extraction command was exempted from the handshake because it had no target and opened no socket. Nothing in Tier 7 is in that position.

| Fixture | Permitted action | Refused behavior |
| --- | --- | --- |
| The Tier 7 adversary, `./course service bypass e-7-NN` | Enroll a bounded list of manifest-owned synthetic devices through the real provisioning station, drive both halves of a claim for them against the Learner's own running service, mint hostile Operational certificates from the local Operational CA, present them as a client to the Learner's own listeners, and record which check refused each one. | A Learner-supplied device identifier, owner slug, serial, certificate, endpoint, port or count. An identifier outside the manifest list. Acting without the matching marker. Starting, stopping or reconfiguring the service it is testing. Writing to any store other than the manufacturing record, the owner store, the revoked-serial store and its own state. Signing anything other than an Operational leaf certificate. |

**The fixture requires the Learner's own service to be running under `--https --mutual-tls`, and refuses with a precise message when it is not.** It never starts a service of its own and never reaches inside one. It is a client, with no privileged access to the thing refusing it. An ephemeral service started per run would also throw away the refusal trail in the service's own `events.jsonl`, and that trail is the lab artifact the tier produces.

### Synthetic identities are minted locally and never leave the lab

Every identity the fixture holds is issued by a local disposable authority in `.course-secrets/pki`, created by this Course environment and trusted by nothing outside it.

Synthetic Factory identities are enrolled through the real provisioning station, in process, exactly as Tier 6's runners do. The station signs them with the Manufacturer Device CA, which is the same authority that signed the Learner's own board. The fixture does not hold that CA key and does not need it.

Hostile Operational certificates are signed by the Operational Device CA, whose key the fixture does hold. The bounds on that are in the next subsection, because they are the sharpest rules in this section.

The one foreign client certificate, the one that fails at the handshake, comes from the existing Untrusted CA. That authority already means "an authority nothing here trusts" in the Tier 2 module's vocabulary, and Tier 7 adds no fifth authority.

Device identifiers come from a bounded manifest-owned list in the `beacon-bypass-e7-NN` shape. They are never supplied on a command line and never invented at run time. An unbounded loop enrolling devices is not a demonstration of scale, it is a way to fill a disk.

Private keys the fixture generates for synthetic devices live in generated state under `.course-state/`, which is ignored and never committed. They are never printed, never written to an evidence record, and never named by a firmware build command. Tier 6's compiled-in credential exception is not widened by one byte: no Tier 7 key reaches a firmware build.

None of this material is ever presented to a host, a service, a device or a network outside this Course environment. The only endpoints a runner connects to are the Learner's own listeners, on this host, at manifest-owned ports.

### The marker check, stated concretely

Before any side effect, every runner performs the marker handshake with `matchMarker` in `internal/courseapp/app.go`, unchanged from Tier 0.

It reads the expected marker from `.course-state/environment.json`, the path recorded as `safety.marker_path` in `course.yml`, and refuses when that file is missing or when the expected marker has expired.

It then fetches `/.well-known/course-environment` over plain HTTP from the address the manifest gives, with redirects disabled, and continues only when `course_id`, `environment_id` and `tier` match exactly and `synthetic_data` is true on both sides.

The address is derived from `runtime.bind_default` and `services.ota.port`, never from a command line. The standing target rules therefore hold unchanged: one literal loopback or private address, no DNS name but `localhost`, no wildcard, no range, no discovery.

**The marker is never fetched over the mutual-TLS port, and Tier 7 is the tier where that rule earns its keep.** The reason is already written in the "Marker handshake" section: a safety check must not depend on the control it is being used to test. Here the point is sharper, because the fixture holds a key that would let a mutual-TLS marker fetch succeed. A check the adversary can satisfy with its own forged credential is not a check.

A missing marker, a malformed marker, a redirected marker, an expired marker, a mismatched marker, or any failure to reach the plain endpoint is a refusal before side effects, and the runner exits nonzero naming the failed check.

### The Operational CA signing key the fixture holds

This is the most authority any fixture in this course is given, and the bound is written here rather than left to be inferred.

The fixture reads the Operational Device CA private key from `.course-secrets/pki`, through the single `COURSE_PKI_DIR` variable, exactly as the service reads it. It does not copy it anywhere, and it does not write it to state, to evidence or to output.

**The Operational Device CA is a local disposable authority.** It is a self-signed root created by the Learner with `./course keys create operational-ca`. It is trusted only by the Learner's own device listener, through the client pool that service builds. No device holds it as a trust anchor. Nothing outside this Course environment trusts it, and nothing outside this Course environment ever sees a certificate it signed.

**What the key may sign is exactly one thing: an Operational leaf certificate for a device identifier this Course environment holds a record for.** That covers the bounded list of synthetic identifiers and, for the ownership-context row, an identifier the Learner's own claim produced. It signs nothing else. It signs no intermediate authority, no server certificate, no Factory identity, no Release manifest and no firmware image. It creates no new authority and it never replaces the one on disk.

The forgeable issuing variant that these rows need takes a chosen serial and a chosen `NotAfter`, which the ordinary issuing path does not. That variant exists for this fixture and the module says why it exists. It stays bounded by the same rule: an Operational leaf certificate for a recorded identifier, and nothing else.

**A fixture signing with the Operational CA key must say so while it is doing it**, exactly as Tier 4 requires of a fixture signing with the Release signing key. It names the row, states that the key is the Learner's own Operational CA, prints the fingerprint of the key it signed with, and says plainly that the capability under test is a leaked CA key. It also labels which rows need the key and which need only what a real outsider could plausibly hold, so a Learner can tell an insider failure from an outsider attack.

Without that narration a Learner watching their own authority sign a certificate that the service then refuses would draw the wrong conclusion twice: first that the key had escaped the lab, and then that the refusal proves a CA signature is worthless. Neither is what the row shows.

### Fixture-created records, and the tell that does not exist

**Synthetic devices land in the real `.course-state/provisioning/records.jsonl`, through the real `enroll()`, with no marker field.** This is the same shape Tier 6's `beacon-bypass-*` devices already have. `provisionRecord` in `internal/courseapp/tier06.go` has no such field and does not gain one.

**So the naming convention is the only tell, and this contract will not claim more than that.** A reader must not take "distinguishable" here to mean the record can prove which entries a fixture wrote. It cannot. A `beacon-bypass-e7-NN` identifier is a convention this course follows, not a property the station verifies, and anyone who can write the record can pick any name.

That absence is a stated lesson rather than a gap, and it is the honest position. The station genuinely cannot tell a synthetic device from a real one, which is the fact that Tier 6's first two rows already turn on. A marker field would have the record assert knowledge the station does not have, which is worse than the record being silent. It is carried as a Weakness ledger row, in the words "the manufacturing record distinguishes fixture devices by naming convention alone".

What can be reconstructed reliably is what each run did while it ran. The service appends every result to its own `events.jsonl`, and reset appends a `fixture_reset` entry naming the run and the entries that run produced. That trail, not a field in the device record, is where the honest account of the fixture's activity lives.

### What reset clears, and what it must not

Tier 6's rule continues and gains one exact boundary: **reset is append only wherever it can be, and it clears only live authorization state.**

Reset removes nothing from `records.jsonl` and nothing from the service's `events.jsonl`. It writes one `fixture_reset` entry naming the run and what that run produced. The synthetic devices stay in the manufacturing record forever, for the reason Tier 6 already gives: a store that can be edited to tidy up after a fixture is no longer the append-only store the station's claim depends on.

Reset clears exactly two things, and both are stores that decide what happens next rather than records of what happened:

- The adversary owner's entry in `.course-state/provisioning/owners.jsonl`. Left behind, it is a live account that can authenticate to the operator listener after the lab is over.
- The serials the fixture marked revoked. Left behind, they change how the service answers a later honest request.

The distinction is the lesson and it fits in one sentence: **a record of what happened is never rewound, and a store that decides what happens next is.**

Reset may not remove the Learner's own owner, the Learner's own claim records, or any serial the fixture did not mark. It names what it removed. It never touches key material, never removes an authority, and never stops or reconfigures the Learner's service.

**Key material includes the fixture's own.** The adversary keeps the private keys of the synthetic devices it enrolled, because those enrollments are in the append-only record and reset cannot take them back. Deleting the keys strands the identities: the station refuses a second certificate under an identifier that already holds one, so the next run of almost every row is refused at Tier 6's `identifier-unused` rather than at the check the row exists to show. This was a real defect, found while writing the Tier 7 module and fixed there. One row is still spent by a first run, because `E-7-11` replays a nonce it watched being spent and ownership is first come; reset says so instead of letting that row fail somewhere else.

This narrows the general reset contract in the same way Tier 6 narrowed it. The known state of the manufacturing record cannot be restored, and reset restores live authorization state instead. The rule refusing the next run until reset has succeeded still holds, and the `fixture_reset` entry is what satisfies it. A Learner who wants an empty record discards the whole Course environment through the existing cleanup path, which is an environment reset and not something a fixture may reach for.

### The second owner is a real account, and it is bounded

**The adversary owner is a genuine entry in the real owner store, beside the Learner's own.** It has to be. An account that could not authenticate would be refused at the bearer checks and would never reach the authorization decision the rows exist to show. That is the lesson the tier is built on: the adversary is correctly authenticated, and every refusal it collects is an authorization decision rather than an authentication one.

The bound is that there is exactly one. The slug is fixed in the manifest, never supplied by the Learner, minted idempotently by the first runner that needs it, and minted by nothing else. `./course setup` does not create it, and the Learner still mints their own owner as a lab step.

Its credential is thirty-two random bytes. It is held in fixture state under `.course-state/`, which is ignored, and it is never printed, never written to evidence, never written to a course page and never committed. The store holds a `sha256:` verifier and never the credential itself. Reset removes the entry.

### No credential, private key or nonce reaches a page, a log or the repository

Tier 7 introduces three kinds of secret, and the rule for all three is the same.

| Secret | Lives only in | What a record may hold |
| --- | --- | --- |
| Owner credential, thirty-two random bytes | printed once to the Learner for their own owner, held in fixture state for the adversary owner | a `sha256:` verifier in `owners.jsonl` |
| Claim nonce, fifteen bytes as twenty-four characters | the device's RAM for the length of its window, or the fixture's memory when the fixture is both ends of a synthetic claim | a verifier in the service's trail and in the `claim` record |
| Operational private keys, the CA's and each device's | `.course-secrets/pki` for the authority, PSA Secure Storage on the board, generated state under `.course-state/` for synthetic devices | a fingerprint |

None of these is written to a course page, to a module, to an evidence record, to the service's `events.jsonl`, to a fixture's output, or to the repository. Records and evidence carry fingerprints and verifiers, exactly as every earlier tier carries hashes rather than contents.

The owner credential travels only as an `Authorization: Bearer` header and never in a request body, so it does not land in any log that records bodies.

A module that shows what a nonce or a credential looks like uses an illustrative value that no Course environment issued, and says that is what it is. A transcript in a course page never carries a live value from a real run.

The fixture is both ends of a synthetic device's claim, so it generates and consumes nonces itself. It holds them in memory for the length of one run and prints none of them. This is also the honest reason the claim-window rows are labelled `host, board required` rather than pure host rows: for a real device the nonce leaves through a person reading a console, and when the fixture is both ends that property is simply absent.

### It never targets anything the Learner does not own

The standing rule holds without exception and Tier 7 states its concrete shape, because this is the first fixture that speaks to three listeners.

Every connection a runner makes is to the Learner's own service, on this host, at a port the manifest records: the public port, the mutual-TLS device port, and the operator port. No other address, no other port, no second host, no scan, no discovery and no promiscuous capture.

The fixture talks to no board. Two of the tier's rows are successes the board produces on the genuine path, and the fixture takes no part in them.

**A host result never stands in for a device result, and the third witness value does not weaken that.** A row marked `host, board required` means a board opened a claim window and printed a nonce, and the refusal was then read on the host. The label records that a device made the result possible. It never lets a host runner claim that a device refused anything.

`E-7-15` is the row whose result is an absence: the handshake closes and there is no status, no body, no check and no entry in the service's trail. The runner records the absence as an absence. It may not report a refusal it did not see, and it may not invent a reason code for a layer that emits none.

### The minimal revoke command

Nothing else in Tier 7 can make a serial revoked, so the tier adds one small host command that writes a `revoked.jsonl` under `.course-state/`, which the service reads live.

It is a lab control and not a fixture. It opens no socket, has no target, and changes no service configuration, so a marker handshake and a reset would guard nothing while implying a check had happened. That is the same reading that kept Tier 6's extraction command out of the fixture rules.

It accepts only a serial this Course environment issued and can show in its own records. It takes no arbitrary value, and it revokes nothing it cannot name a record for. Tier 8 owns the operator workflow around revocation. Tier 7 owns only the file, and a Learner can read that file, which is the point of putting the authority there rather than behind a request.

### Manifest entries the runners read

Every mutable input stays allowlisted. The exact manifest block is for the build ticket to place, but these values come from the manifest and never from a Learner.

| Value | Read by | For |
| --- | --- | --- |
| The plain target and the selected interface | every runner | the marker handshake and the interface check, unchanged from Tier 0 |
| The device port, the operator port and the service name | every runner that connects | so no endpoint, port or name is ever supplied on a command line |
| The bounded list of synthetic device identifiers | the enrolling runners | so the count is bounded and the names are not invented at run time |
| The single adversary owner slug | the runners that authenticate as the second owner | so there is exactly one, and it is not Learner-supplied |
| The declared changes and the reset path | the runner wrapper | the standard dry-run disclosure and the reset it must invoke |
| `paths.state`, `paths.secrets`, `paths.generated_artifacts` | every runner | where the records, the fixture state, the authorities and the evidence live |

The fixture requires no hardware of its own. That is the lesson rather than a compromise: a forged certificate does not need the device it impersonates. What it may not claim is anything about a board.

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

Sources: [Define the Tier 0 fixture safety contract](https://github.com/tkEmLogic/learning-cyber-security/issues/24) for the Tier 0 rules, [Extend the fixture safety contract to HTTPS and a named service](https://github.com/tkEmLogic/learning-cyber-security/issues/41) for the transport, service name, and capture rules, [Extend the fixture safety contract to hostile firmware images and signing keys](https://github.com/tkEmLogic/learning-cyber-security/issues/53) for the key material and Tier 3 rules, [What does the fixture safety contract need for Tier 4?](https://github.com/tkEmLogic/learning-cyber-security/issues/70) for the manifest signing and replay rules, [Write the Tier 6 section of the fixture safety contract](https://github.com/tkEmLogic/learning-cyber-security/issues/122) for the compiled-in credential exception, the append-only reset, and the flash dump rules, and [Write the Tier 7 section of the fixture safety contract](https://github.com/tkEmLogic/learning-cyber-security/issues/149) for the Operational CA signing bounds, the reset split between history and live authorization state, and the naming-convention limitation.

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
| No tracked anchor include carries a byte list, which is how a compiled-in key would be committed | `scripts/check-secrets.sh`, wired into `scripts/verify-tier-00.sh` | Enforced |
| The fleet private key reaches the shared variant only, and the factory build never has it on its include path | `buildFirmware` in `internal/courseapp/app.go`, which sets `COURSE_SHARED_IDENTITY_INC_DIR` only when `variant.identityModel` is `shared` | Enforced |
| The fleet key is written to generated state, never to the repository | `writeSharedIdentityInc` in `internal/courseapp/tier06.go`, and `.gitignore` | Enforced |
| The manufacturing record never contains private key material | `writeRecord` in `internal/courseapp/tier06.go`, which refuses rather than trusting callers | Enforced |
| Extraction takes no Learner-supplied path, and prints a fingerprint rather than the key | `provisionExtract` in `internal/courseapp/tier06.go`, reading the image named in `course.yml` | Enforced |
| The clone takes the identifier it impersonates from the manufacturing record, and its invented identifiers from a bounded manifest list | `cloneSharedIdentity` in `internal/courseapp/tier06.go`, reading `phantom_ids` from `course.yml` | Enforced |
| The clone's reset appends and never deletes | `resetClone` in `internal/courseapp/tier06.go`, wired into `resetFixtureState` | Enforced |
| A flash dump is bounded to the `storage` partition and followed by the RTS reset | `deviceDump` in `internal/courseapp/tier06.go`, which takes no range and reads only `0x3b0000`,`0x030000` before pulsing RTS | Enforced |
| The Operational CA private key is confined to `.course-secrets/pki` and reaches the service and the fixture only as `COURSE_PKI_DIR` | `./course keys create operational-ca`, `internal/coursepki`, `scripts/check-secrets.sh`, and `.gitignore` | Owed by [Build the Operational CA, the Owner credential store and the claim endpoints](https://github.com/tkEmLogic/learning-cyber-security/issues/146) and [Add client-certificate authentication to the OTA service](https://github.com/tkEmLogic/learning-cyber-security/issues/147) |
| The forgeable issuing variant signs only an Operational leaf certificate for a recorded identifier, and prints the fingerprint of the key it used | `IssueOperationalCertificateAs` in `internal/coursepki/operational.go`, which sets no basic constraints and no certificate-sign usage, reached only through `signWithOperationalCA` in `internal/courseapp/tier07_adversary.go`, which refuses an identifier the record does not hold and prints the fingerprint | Enforced |
| Every `./course service bypass` runner performs the marker handshake over plain HTTP before any side effect | `runBypassRow` in `internal/courseapp/tier07_bypass.go`, calling `matchMarker` against `bypass.tier-07.target` in `course.yml` before the row runs | Enforced |
| A runner requires the Learner's own `--mutual-tls` service and never starts, stops or reconfigures it | `requireLearnerService` in `internal/courseapp/tier07_bypass.go`, which reads the PID and mode files `./course service start` writes and starts nothing | Enforced |
| Synthetic device identifiers and the single adversary owner slug come from a bounded manifest list, never from a Learner | `allowedIdentifier` and `ensureOwner` in `internal/courseapp/tier07_adversary.go`, against `bypass.tier-07.synthetic_ids` and `bypass.tier-07.adversary_owner` in `course.yml` | Enforced |
| A runner signing with the Operational CA key says so, names the row, and prints the key fingerprint | `signWithOperationalCA` in `internal/courseapp/tier07_adversary.go`, the only caller of the forgeable variant | Enforced |
| Reset appends a `fixture_reset` entry, deletes nothing from `records.jsonl` or `events.jsonl`, keeps the fixture's own key material, and clears only the adversary owner entry and the serials the fixture marked | `bypassReset`, `removeOwnerEntries` and `removeRevokedSerials` in `internal/courseapp/tier07_bypass.go` | Enforced |
| No owner credential, private key or claim nonce is printed, written to evidence, written to a course page, or committed | `adversaryState` in `internal/courseapp/tier07_adversary.go`, held at 0600 under `.course-state/bypass/tier-07`, with the evidence record carrying no secret, plus `scripts/check-secrets.sh` and `.gitignore` | Enforced |
| The revoke command accepts only a serial this Course environment issued and can show a record for | the Tier 7 revoke command | Owed by [Build the Operational CA, the Owner credential store and the claim endpoints](https://github.com/tkEmLogic/learning-cyber-security/issues/146) |

When a rule moves, this table moves with it.
