# Tier 3 mission: The trusted server served hostile firmware

> Prototype variant C: incident-driven mission. This is throwaway course
> material.

## Incident brief

The status beacon uses HTTPS. The device trusts the OTA server certificate.

An attacker gains access to the OTA service storage. The attacker replaces the
firmware image with a build that always shows the fast-blink error state.

The TLS connection is valid. The server certificate is valid. The device
downloads and runs the hostile image.

Your task is to reproduce the incident, find the missing trust boundary, and
make the same attack fail.

## Mission boundary

Attack only:

- The local course OTA service.
- The course ESP32-C6 reference product.
- Disposable images and credentials created for this mission.

Keep the lab network isolated. Do not scan or target other systems.

## Starting checkpoint

You start from Tier 2:

- HTTPS is enabled.
- The device validates the OTA server.
- The application image is unsigned.
- MCUboot does not enforce image authenticity.
- The OTA service can replace the image it hosts.

Start the mission:

```text
./course tier start 3
```

Expected result:

```text
tier: 3-start
transport: HTTPS with server validation
image signature enforcement: disabled
```

## Phase 1: Reproduce the attack

Create the hostile image:

```text
./course attack unsigned-image
```

Publish and request it:

```text
./course device update --release attack-unsigned
```

Expected result:

```text
TLS peer: trusted course OTA service
download: complete
image authentication: not configured
boot result: attack image running
```

Observe the LED. Capture the service log and device boot log.

## Investigation notebook

Answer before continuing:

1. Which actor authenticated the network connection?
2. Which actor authorized the firmware?
3. Where is that authorization checked?
4. Why can a valid TLS session carry hostile firmware?
5. Which secret must never exist on the OTA service?

## Phase 2: Draw the missing boundary

```mermaid
flowchart LR
    W[Release workstation] -->|must authorize image| S[OTA service]
    S -->|distributes bytes| D[Device]
    D --> B[MCUboot]
    B --> A[Application]
```

Add these labels to your diagram:

- Offline firmware release-signing key.
- MCUboot verification public key.
- Trusted and untrusted components.
- Software-rooted limit on the ESP32-C6 core path.

## Phase 3: Add publisher authorization

Create a disposable release-signing key:

```text
./course keys create firmware-release
```

Expected result:

```text
private key location: .course-secrets/firmware-release.pem
public key location: build/firmware-release-public.pem
```

Enable signature enforcement:

```text
./course harden signed-images
./course build
```

Publish a manufacturer-approved image:

```text
./course release publish tier-3-signed
./course device update --release tier-3-signed
```

Expected result:

```text
image signature: valid
boot result: signed image running
```

## Phase 4: Replay the incident

Request the original hostile image again:

```text
./course device update --release attack-unsigned
```

Expected result:

```text
image signature: missing
boot result: rejected
active image: last accepted signed image
```

The attacker still controls the OTA service. The device now rejects the
attacker's unsigned application image.

## Phase 5: Try bypasses

Run:

```text
./course verify tier-3
```

The fixture tries:

- An unsigned image.
- A modified signed image.
- An image signed by another key.
- A truncated image.
- A valid signed image.

Do not continue until you can explain every result.

## Debrief: What changed?

| Question | Before | After |
|---|---|---|
| Does the device trust the connection? | Yes | Yes |
| Does the device verify the firmware publisher? | No | Yes |
| Can the OTA host create a trusted image? | Yes in practice | No |
| Can an old valid signed image replay? | Yes | Yes, until Tier 4 |
| Can a physical attacker replace software-rooted MCUboot? | Yes | Yes, until Advanced Tier A |

## Weakness ledger

Mark each item:

- **Closed**: unsigned application images on the tested path.
- **Reduced**: image replacement by a compromised OTA host.
- **Open for Tier 4**: replay of older signed images and mutable release
  metadata.
- **Open for Advanced Tier A**: physical replacement of the software-rooted
  bootloader.

Link each status to the captured command output or device log.

## Security evidence pack

Add:

- Incident timeline.
- Before-and-after trust-boundary diagram.
- Public-key fingerprint.
- Build manifest and source revision.
- Accepted signed-image result.
- Rejected unsigned, modified, wrong-key, and truncated results.
- Residual-risk statement for the software-rooted bootloader.

## If the mission does not behave as expected

| Observation | First check |
|---|---|
| Every image is rejected | Compare the signing and verification keys |
| The hostile image still boots | Confirm that the Tier 3 bootloader is active |
| The service contains the private key | Stop, remove it, and review key roles |
| A clean build changes the result | Compare saved build manifests |

Ask the mentor to work through the logs with you. This is a coaching
conversation, not an examination.

## Mentor debrief

Demonstrate the incident before and after hardening.

Explain:

- Why HTTPS succeeded during the attack.
- Why MCUboot now rejects the hostile image.
- Why the core chain is software-rooted.
- Which attack remains possible at the next checkpoint.

Record mentor notes and agreed next actions.

## Mission handoff

The attacker can still replay an older valid signed image. Tier 4 adds signed
release metadata and a security counter.

## References

- [Zephyr binary signing](https://docs.zephyrproject.org/latest/build/signing/index.html)
- [MCUboot design](https://docs.mcuboot.com/design.html)
- [MCUboot image tool](https://docs.mcuboot.com/imgtool.html)
