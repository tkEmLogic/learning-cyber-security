# Tier 3: Require authentic firmware images

> Prototype variant A: linear procedure. This is throwaway course material.

## Why this tier matters

Tier 2 protects the network connection with HTTPS. It does not prove that the
firmware came from the manufacturer.

A trusted or compromised OTA service can still provide an altered image. This
tier adds an offline firmware release-signing key and MCUboot image
verification.

## Learning result

After this tier, you can:

- Explain the difference between transport trust and firmware authenticity.
- Sign a firmware image away from the OTA service.
- Configure MCUboot to reject unsigned and modified images.
- Show the limits of a software-rooted boot chain on ESP32-C6.
- Update the weakness ledger and security evidence pack.

## Starting state

You need:

- A working Tier 2 device.
- The local HTTPS OTA service.
- An isolated course network.
- Disposable course credentials.

The device still accepts unsigned firmware images.

## Safety boundary

Run the attack only against the local reference product and course OTA service.
Do not expose the insecure service to another network.

Do not use a production signing key. Do not commit the course signing key.

## Weakness ledger before hardening

| Weakness | Attack vector | Current result | Planned control |
|---|---|---|---|
| The device accepts unsigned firmware | Upload an attacker-built image through the trusted OTA service | The image boots | MCUboot image signature |
| The OTA host can replace an image | Modify the image after upload | The changed image boots | Offline signing and boot verification |
| The bootloader is not hardware-authenticated | Replace MCUboot through physical flash access | Not tested in the core tier | Advanced hardware-rooted boot |

## Attack demonstration

### Predict

Before you run the attack, write down:

- Which asset is at risk?
- Why does HTTPS not stop this attack?
- What result do you expect after reboot?

### Prepare the altered image

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

### Install the altered image

```text
./course device update --release attack-unsigned
```

Expected result before hardening:

```text
download: complete
image authentication: not configured
boot result: attack image running
```

Record the running firmware version and LED behavior.

## Add the control

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

### Publish a signed release

```text
./course release publish tier-3-signed
./course device update --release tier-3-signed
```

Expected result:

```text
image signature: valid
boot result: signed image running
```

## Verify the changed boundary

Run all Tier 3 checks:

```text
./course verify tier-3
```

Expected result:

```text
PASS signed image
PASS reject unsigned image
PASS reject modified image
PASS reject wrong signing key
PASS reject truncated image
PASS OTA service has no signing key
```

## Try the attack again

```text
./course device update --release attack-unsigned
```

Expected hardened result:

```text
image signature: missing
boot result: rejected
active image: last accepted signed image
```

## What this control does not protect

This tier does not authenticate MCUboot with an ESP32-C6 hardware root of
trust. A person with physical flash access may still replace the software-rooted
bootloader and its public key.

This tier also does not prevent replay of an older valid signed image. Tier 4
adds signed release metadata and downgrade policy.

## Update the evidence

Add these items to the security evidence pack:

- Firmware signing key-role diagram.
- Public-key fingerprint.
- Signed-image verification record.
- Negative-test output.
- Source revision and build configuration.
- Updated security claim status.

Update the weakness ledger:

| Weakness | Status after Tier 3 | Evidence | Next action |
|---|---|---|---|
| Unsigned image accepted | Closed for the tested update path | Tier 3 negative tests | Rerun in later regression tests |
| OTA host modifies image | Reduced | Modified image rejected | Add signed metadata in Tier 4 |
| Older signed image replays | Open | Not controlled by image signature alone | Tier 4 |
| Bootloader replacement through physical access | Open | Software-rooted chain documented | Advanced Tier A |

## Troubleshooting

| Problem | Check |
|---|---|
| Signed image is rejected | Confirm that MCUboot contains the matching public key |
| Unsigned image still boots | Confirm that the device runs the Tier 3 bootloader |
| Signing key appears in the service container | Stop and remove it before continuing |
| Results change after a clean build | Record the build manifest and compare configuration |

## Mentor conversation

Show:

- A valid signed image booting.
- An unsigned or modified image being rejected.
- The signing key stored outside the OTA service.

Explain:

- Why HTTPS and image signing protect different boundaries.
- Why this is still a software-rooted chain.
- Which weaknesses remain for Tier 4 and Advanced Tier A.

The mentor helps diagnose problems and records notes. There is no grade.

## Continue

Save the Tier 3 runnable state. Continue to Tier 4, **Protect release metadata
and block downgrade**.

## References

- [Zephyr binary signing](https://docs.zephyrproject.org/latest/build/signing/index.html)
- [MCUboot design](https://docs.mcuboot.com/design.html)
- [MCUboot image tool](https://docs.mcuboot.com/imgtool.html)
