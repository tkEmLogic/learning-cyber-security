# Revalidating Tiers 2 to 5 after the RNG fix

Issue #126 found that the ESP32-C6 hardware random number generator was never clocked in the pinned Zephyr build, so every "random" value on the board was the RTC timer's low byte XORed with a constant. The fix is a `SYS_INIT` in `firmware/common` that enables the generator's clock, and because every tier from Tier 2 on builds `firmware/common` in, rebuilding a tier picks it up.

That left an owed question and an owed board run: does the fix change any published Tier 2 to Tier 5 result, and are those results still true on the rebuilt firmware. This records both.

## What a frozen generator actually falsified

The generator feeds two kinds of value on this device: long-lived key material, and TLS session material. The distinction is what decides which claims moved.

**No refusal, recovery, downgrade or authentication outcome depends on the generator.** A certificate is refused because its issuer does not match the trust anchor. An image is refused because its signature does not verify against the key in the bootloader. A downgrade is refused because the security counter is lower. A revert happens because a trial image failed its health gate. None of these read a random value, so a frozen generator changes none of them, and no Tier 3, Tier 4 or Tier 5 claim was falsified by it. Server authentication in Tier 2 is the same: the certificate check is deterministic.

**Confidentiality did depend on it, and was undermined.** Tier 2's module says the connection is "encrypted so that nobody in the canteen can read it", and closes `T0-W-01`, "HTTP has no confidentiality", with "Encrypted transport in this tier". That claim rests on the TLS key exchange being unpredictable. The ephemeral key-agreement scalar and the client random are drawn from the same generator that #126 found frozen, and a frozen generator's output has about four bytes of entropy followed by a counter ramp, exactly the shape of the Factory key that issue recovered from flash. An attacker who captured a Tier 2 handshake could brute-force that small entropy, recover the ephemeral scalar, derive the shared secret, and decrypt the session. So on the unfixed firmware the confidentiality half of `SC-03` was violable, even though every device still authenticated the server correctly and still refused every bad certificate.

The module text is right as written. It was describing a confidentiality that the unfixed firmware did not actually deliver. The fix is what makes the sentence true, rather than the sentence being wrong. No Tier 2 to Tier 5 module needs its wording changed; this note records why the fix matters to a claim that reads as unrelated to a random number generator.

## What was re-observed on the board

Each tier was rebuilt with the fix, reflashed, and booted on the nanoESP32-C6 1.0 board (MAC `40:4c:ca:5e:a9:fc`), which is the board the course used at that time. The RNG-affected path, TLS, was confirmed working on every one, and the load-bearing outcome of each tier was re-observed. The RNG-independent refusal and recovery rows are rebound to the new binary by that rebuild and boot, on the reasoning above that the fix cannot change them; the physically destructive Tier 5 rows (power cut, hard reset during download) stay as `course.yml` already records them.

| Tier | Re-observed on the fixed firmware |
| --- | --- |
| Tier 2 | Boots, Wi-Fi associates, `ota.tls verified ... connection established`. With the service forced to present the untrusted certificate, the device refused: `verification flags 0x00000008`, `the certificate was not issued by the trust anchor`, and `the running image is unchanged` |
| Tier 3 | Boots, `slot=primary header=ok tlv=ok signature=present key=match`, trust anchor reported at boot, TLS verified |
| Tier 4 | Boots, `key=match counter=1`, security counter reported by the bootloader hook, TLS verified |
| Tier 5 | Boots, `key=match counter=3`, `recovery.state mounted the storage partition at 0x3b0000`, watchdog armed, TLS verified, and a device confirmed its running image |

The course has since moved to the Espressif ESP32-C6-DevKitC-1. The results in the table above were observed on the nanoESP32-C6 and stay recorded against it, and they are owed a repeat run on the ESP32-C6-DevKitC-1. Nothing in the reasoning above depends on the board, because the fix is a clock enable in `firmware/common` and the refusal outcomes do not read a random value.

The build is a revision-bound artifact, so a `./course verify N` receipt taken on the new revision is the durable record. This note is the written check #126 asked for; the upstream Zephyr report and the teaching of the finding in a module are separate owed items on that issue.
