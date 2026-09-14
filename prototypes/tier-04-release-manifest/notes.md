# Release manifest prototype

Throwaway prototype for [#67](https://github.com/tkEmLogic/learning-cyber-security/issues/67). Not course material. Not a schema document. Something to react to.

`tier-04-baseline.manifest.json` carries every field section 7 requires. Its digest and size are stood in from the current Tier 3 image, because no Tier 4 image exists yet.

## The round trip works

Signed with the real Release signing key and verified with the public half alone:

```text
openssl dgst -sha256 -sign .course-secrets/signing/release.pem -out m.sig manifest.json
openssl dgst -sha256 -verify artifacts/generated/signing/release.pub.pem -signature m.sig manifest.json
Verified OK
```

The signature is 71 bytes of ASN.1 DER, the same length as the ECDSA signature TLV already in the signed Tier 3 image.

Raising `security_counter` from 1 to 2 fails verification, as it must.

**Reformatting the JSON without changing a single value also fails verification.** That is not a flaw, it is the whole reason section 7 says the exact downloaded bytes are verified before parsing, "avoiding a custom JSON canonicalization scheme". The bytes are the artifact. The service must store and serve them verbatim, and the device must verify before it parses, because a parse-then-reserialize anywhere on the path destroys the signature.

## Three things that need deciding

### 1. Most of the six are not attacks

An outsider cannot forge a valid signature, so the six hostile variants split into three kinds that behave differently:

| Variant | Signature | Who can produce it | Which check refuses |
| --- | --- | --- | --- |
| Edited after signing | invalid | anyone | signature |
| Signed with the attacker key | invalid | anyone | signature |
| Incompatible hardware | valid | only the key holder | hardware |
| Wrong channel | valid | only the key holder | channel |
| Unexpected size | valid | only the key holder | size |
| Digest mismatch | valid | only the key holder | digest |
| Lower security counter | valid | anyone, by replaying an older release | counter |

The four in the middle can only exist if they are signed with the Learner's own key. They are not outsider attacks: they are the manufacturer publishing something wrong. The specification's Tier 4 threat list already says so, naming "incompatible hardware assignment" and "version-policy mistakes" beside replay.

That is a better tier than six forgeries. It means the Learner signs bad releases with their own key and watches their own device refuse them, which is what actually happens in a real release process.

The consequence for the fixtures is that a hostile-release fixture must be allowed to sign with the release key. `docs/fixture-safety-contract.md` should say that deliberately rather than by omission. That belongs to #70.

### 2. Creation and support information, on a device with no clock

`T2-W-09` records that this device cannot check certificate dates because it has no clock. The same is true of `created_at` and `supported_until`.

Proposal: they are carried and signed so they cannot be edited later, the device reports them in its status event without acting on them, and Tier 9 consumes them for support statements. The module must say plainly that the device does not and cannot validate them, rather than leaving a Learner to assume a date field implies a check.

### 3. Shapes

- **Hardware revision as an integer.** A range needs ordering, and `rev-a` does not order. The manifest and the Kconfig carry an integer; the boot banner can render it for humans.
- **Flat, not nested.** Matches the existing `Release` struct and keeps `DisallowUnknownFields` manageable.
- **`signed` and `mutable` are gone.** They were the service describing itself. The signature describes the manifest now, and `mutable` belongs to the Update assignment, which is a different object.
