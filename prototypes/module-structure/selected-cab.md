# Tier 3: Require authentic firmware images

> Prototype candidate selected as the module structure reference. This is throwaway course material.

## Incident brief

The status beacon uses HTTPS. The device validates the OTA service certificate.

An attacker gains access to the OTA service storage. The attacker replaces the firmware image with a build that always shows the fast-blink error state.

The TLS connection is valid. The server certificate is valid. The device downloads and runs the hostile image.

Your task is to reproduce the incident, find the missing trust boundary, and make the same attack fail.

## Learning result

After this tier, you can:

- Explain the difference between transport trust and firmware authenticity.
- Sign a firmware image away from the OTA service.
- Configure MCUboot to reject unsigned and modified images.
- Test common image-signature bypass attempts.
- Explain the software-rooted limit of the core ESP32-C6 boot path.
- Update the weakness ledger and security evidence pack.

## Safety boundary

Run the attack only against the local reference product and course OTA service. Keep the lab network isolated.

Use only disposable course credentials and images. Do not use a production signing key. Do not commit the course signing key.

## Starting state

You need:

- A working Tier 2 device.
- The local HTTPS OTA service.
- The isolated course network.
- The Tier 2 security evidence pack.

The device validates the server connection but still accepts unsigned firmware images.

## Weakness ledger before hardening

| Weakness | Attack vector | Current result | Planned treatment |
| --- | --- | --- | --- |
| The device accepts unsigned firmware | Replace the hosted image | The hostile image boots | Add MCUboot image signatures |
| The OTA host can change image bytes | Modify an image after upload | The changed image boots | Sign offline and verify during boot |
| An older valid image can replay | Serve an older signed release | Not controlled by this tier | Add signed metadata and a security counter in Tier 4 |
| MCUboot is not hardware-authenticated | Replace MCUboot through physical flash access | Outside the core software-rooted boundary | Add hardware-rooted boot in Advanced Tier A |

## Reproduce the attack

### Predict

Before you run the attack, write down:

1. Which asset is at risk?
2. Why does HTTPS not stop this attack?
3. Which component currently decides whether the image may run?
4. What result do you expect after reboot?

### Prepare the hostile image

Run from the course repository root:

```text
./course tier start 3
./course attack unsigned-image
```

Expected result:

```text
ATTACK IMAGE READY
signature: absent
payload: status beacon reports fictional error state
```

### Install the hostile image

```text
./course device update --release attack-unsigned
```

Expected result before hardening:

```text
TLS peer: trusted course OTA service
download: complete
image authentication: not configured
boot result: attack image running
```

Record:

- The active firmware version.
- The LED behavior.
- The TLS result.
- The download result.
- The boot result.

## Investigate the missing boundary

Answer:

1. Which actor authenticated the network connection?
2. Which actor authorized the firmware?
3. Where should firmware authorization be checked?
4. Why can a valid TLS session carry hostile firmware?
5. Which private key must never exist on the OTA service?

Update the trust-boundary diagram:

```text
Offline release workstation
    |
    | signed image
    v
OTA service -- HTTPS download --> ESP32-C6 --> MCUboot
                                             |       |
                               valid image --+       +-- invalid image
                                    |                     |
                                    v                     v
                            Zephyr application       Reject image

Verification public key --------------------> MCUboot
```

The release workstation authorizes firmware. The OTA service distributes firmware. MCUboot verifies the image before the application runs.

## Add firmware publisher authentication

### Create a disposable offline signing key

```text
./course keys create firmware-release
```

Expected result:

```text
private key: .course-secrets/firmware-release.pem
public key: build/firmware-release-public.pem
OTA service received private key: no
```

### Enable signed images

```text
./course harden signed-images
./course build
```

Expected result:

```text
MCUboot signature verification: enabled
application image: signed
unsigned image: not generated
```

### Publish and install an approved release

```text
./course release publish tier-3-signed
./course device update --release tier-3-signed
```

Expected result:

```text
image signature: valid
boot result: signed image running
```

## Replay the attack

Request the hostile image again:

```text
./course device update --release attack-unsigned
```

Expected hardened result:

```text
image signature: missing
boot result: rejected
active image: last accepted signed image
```

The attacker still controls the OTA service. The device now rejects the attacker's unsigned application image.

## Test bypass attempts

Run:

```text
./course verify tier-3
```

Record the results:

| Evidence ID | Test | Expected result | Actual result |
| --- | --- | --- | --- |
| E-3-01 | Approved signed image | Boot | |
| E-3-02 | Unsigned image | Reject | |
| E-3-03 | Modified signed image | Reject | |
| E-3-04 | Image signed by another key | Reject | |
| E-3-05 | Truncated image | Reject | |
| E-3-06 | Search OTA service for the private signing key | Key not found | |

If a test produces another result, record the actual result before you troubleshoot it. Do not mark the security claim as supported.

## Weakness ledger after hardening

| Weakness | Result after Tier 3 | Status | Evidence or next action |
| --- | --- | --- | --- |
| Unsigned application image | Rejected on the tested path | Closed | E-3-02 |
| OTA host changes image bytes | Modified image is rejected | Reduced | E-3-03 |
| Wrong release-signing authority | Wrong-key image is rejected | Closed on the tested path | E-3-04 |
| Older valid signed image replay | Still possible | Open | Tier 4 |
| Mutable release metadata | Still trusted through the service | Open | Tier 4 |
| Physical MCUboot replacement | Still possible | Open | Advanced Tier A |

Later tiers rerun the relevant Tier 3 tests to detect regressions.

## Security claim

**FW-AUTH-1**: The tested update path rejects an application image that does not have a valid manufacturer signature.

Set the status:

- **Supported** when E-3-01 through E-3-06 match the expected results.
- **Partly supported** when signature enforcement works but a documented test or environment gap remains.
- **Unsupported** when an invalid image boots or required evidence is missing.

Do not describe this claim as hardware-rooted. Standard Zephyr MCUboot is not authenticated by ESP32-C6 Secure Boot v2 in the core course.

## Update the security evidence pack

Add:

- The before-and-after trust-boundary diagram.
- Firmware signing and verification key roles.
- The verification public-key fingerprint.
- Build manifest and source revision.
- Signed image digest.
- E-3-01 through E-3-06 results.
- Proof that the OTA service has no private signing key.
- Updated security claim status.
- Weakness-ledger changes.
- Residual risk for physical replacement of the software-rooted bootloader.

## Troubleshooting

| Observation | First check |
| --- | --- |
| Every image is rejected | Compare the signing key with the MCUboot verification key |
| The hostile image still boots | Confirm that the Tier 3 MCUboot build is active |
| The OTA service contains the private key | Stop, remove it, and review the key roles |
| A clean build changes the result | Compare the saved build manifests |
| The wrong-key test passes | Confirm that the fixture did not reuse the approved key |

Ask the mentor to inspect the logs and trust boundary with you when the result is unclear.

## Mentor conversation

Show:

- The hostile image running before hardening.
- An approved signed image running after hardening.
- The same hostile image being rejected after hardening.
- The completed evidence table and weakness-ledger changes.

Explain:

- Why HTTPS succeeded during the attack.
- Why image signing changes the result.
- Why the OTA service does not hold the signing key.
- Why the core chain remains software-rooted.
- Which weaknesses remain for Tier 4 and Advanced Tier A.

Diagnose one prepared wrong-key or stale-bootloader case with the mentor. Record notes and the agreed next action. There is no grade.

## Continue

Save the Tier 3 runnable state. Continue to Tier 4:

**Protect release metadata and block downgrade**

The next attack uses an older valid signed image. Its signature is correct, but the release is no longer acceptable.

## References

- [Zephyr binary signing](https://docs.zephyrproject.org/latest/build/signing/index.html)
- [MCUboot design](https://docs.mcuboot.com/design.html)
- [MCUboot image tool](https://docs.mcuboot.com/imgtool.html)
