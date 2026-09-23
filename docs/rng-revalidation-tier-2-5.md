# Revalidating Tiers 2 to 5 after the RNG fix

Issue #126 found that the ESP32-C6 hardware random number generator was never clocked in the pinned Zephyr build, so every "random" value on the board was the RTC timer's low byte XORed with a constant. The fix is a `SYS_INIT` in `firmware/common` that enables the generator's clock, and because every tier from Tier 2 on builds `firmware/common` in, rebuilding a tier picks it up.

That left an owed question and an owed board run: does the fix change any published Tier 2 to Tier 5 result, and are those results still true on the rebuilt firmware. This records both.

## What a frozen generator actually falsified

The generator feeds two kinds of value on this device: long-lived key material, and TLS session material. The distinction is what decides which claims moved.

**No refusal, recovery, downgrade or authentication outcome depends on the generator.** A certificate is refused because its issuer does not match the trust anchor. An image is refused because its signature does not verify against the key in the bootloader. A downgrade is refused because the security counter is lower. A revert happens because a trial image failed its health gate. None of these read a random value, so a frozen generator changes none of them, and no Tier 3, Tier 4 or Tier 5 claim was falsified by it. Server authentication in Tier 2 is the same: the certificate check is deterministic.

**Confidentiality did depend on it, and was undermined.** Tier 2's module says the connection is "encrypted so that nobody in the canteen can read it", and closes `T0-W-01`, "HTTP has no confidentiality", with "Encrypted transport in this tier". That claim rests on the TLS key exchange being unpredictable. The ephemeral key-agreement scalar and the client random are drawn from the same generator that #126 found frozen, and a frozen generator's output has about four bytes of entropy followed by a counter ramp, exactly the shape of the Factory key that issue recovered from flash. An attacker who captured a Tier 2 handshake could brute-force that small entropy, recover the ephemeral scalar, derive the shared secret, and decrypt the session. So on the unfixed firmware the confidentiality half of `SC-03` was violable, even though every device still authenticated the server correctly and still refused every bad certificate.

The module text is right as written. It was describing a confidentiality that the unfixed firmware did not actually deliver. The fix is what makes the sentence true, rather than the sentence being wrong. No Tier 2 to Tier 5 module needs its wording changed; this note records why the fix matters to a claim that reads as unrelated to a random number generator.

## What was re-observed on the board

Every tier from Tier 2 on builds `firmware/common` in, so every Tier 2 to Tier 5 firmware the course builds now carries the fix.

Tiers 2, 3 and 4 were revalidated on the ESP32-C6-DevKitC-1 with firmware that has the fix, in #225, #226 and #227. Every download in those runs went over the RNG-affected path, TLS. The Tier 2 run also saw the device refuse a certificate from an untrusted issuer and a certificate with the wrong name, and recover once the real certificate was back. The refusal rows of Tiers 3 and 4 were each observed through the real update path.

Tier 5 was revalidated on the ESP32-C6-DevKitC-1 with the fix in #228, with TLS on every download, every revert, and every interrupted download. Nothing in the reasoning above depends on the board, because the fix is a clock enable in `firmware/common` and the refusal outcomes do not read a random value.

The build is a revision-bound artifact, so a `./course verify N` receipt taken on the new revision is the durable record. This note is the written check #126 asked for; the upstream Zephyr report and the teaching of the finding in a module are separate owed items on that issue.
