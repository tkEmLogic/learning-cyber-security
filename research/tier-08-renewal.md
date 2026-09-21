# Certificate renewal with a bounded overlap, and what this tree can carry

**Research question:** [GitHub issue #207](https://github.com/tkEmLogic/learning-cyber-security/issues/207), part of map [#203](https://github.com/tkEmLogic/learning-cyber-security/issues/203)

**Access and review date:** 22 September 2026

**Status:** Research. Every claim about this repository is read from the source files named, at their state on `main` at commit `d1411d0`. Every claim about Zephyr, Mbed TLS or TF-PSA-Crypto is read from the tree pinned in the container `tier2-validate`. Every claim about a standard is read from the RFC text fetched from `rfc-editor.org`. Nothing here has been run on the board, and nothing here has been built.

## Short answer

The standards give this tier less than the ticket hopes and one thing more than expected.

EST (RFC 7030) defines the re-enrollment exchange precisely and defines nothing at all about overlap, expiry timing or revocation. What section 8 of the specification calls "renewal" is EST's **rekey**, not EST's **renew**: the two are distinguished only by whether the certification request carries a new public key, and section 8 requires a new key pair. BRSKI (RFC 8995) adds nothing to renewal, because it is a bootstrap protocol and says so. But BRSKI section 5.9.4 contains, almost word for word, the control section 8 asks for: the client proves a newly issued credential works by closing the TLS connection and opening a new one with the new credential, and posting its success over that connection, and the server records whether that connection carried a matching client certificate. That is "the device proves the new identity works" as a standardized exchange rather than a date check, and it is written for TLS 1.2 specifically, which is the only TLS version this tree has.

Overlap is not in EST at all. Where it is standardized it is a **service-side timer with a floor** (RFC 6489: a staging period the CA chooses, "SHOULD be no less than 24 hours") or a **service-side publication deadline pegged to a fraction of the lifetime** (RFC 8739: the next certificate is available "halfway through the lifetime of the currently active certificate at the latest"). In both, the service decides retirement, not the device. RFC 8739 also states the price of an overlap plainly, which this course should quote rather than discover: from the moment the next certificate exists, "the cancellation is not completely effective until the 'next' certificate also expires".

In this tree, the answers to the three device questions are yes, yes, and yes-with-one-new-branch.

The application-owned socket can present a different client certificate on a later connection without a reboot, and Tier 7 **already does it every boot**: `run_request()` takes the identity as an argument and the same board alternates its Factory certificate at the claim endpoint and its Operational certificate at the download endpoints inside one run of `main`. The limit is not the socket. It is that `enum course_tls_identity` has two members and `course_identity_operational_credentials()` returns one fixed key identifier.

Two PSA key slots can hold two Operational keys at once, and again Tier 7 already proves the mechanism: `0x00000601` and `0x00000701` are two persistent keys alive at the same time, and during an open Claim window a third volatile key is alive beside them. `psa_copy_key()` landed and is in the shipped Tier 7 firmware. One thing it does here matters for renewal and is easy to miss: the key it writes into the persistent slot **deliberately does not carry `PSA_KEY_USAGE_COPY`**, so the current Operational key cannot be relocated to another identifier. A renewal cannot move the old key aside; it can only put the new key somewhere else.

The storage question is the least interesting of the three. `cert_settings_set()` no longer ignores `name` — that was found while settling #140 and **fixed in Tier 7**. Two entries under `course/identity` work today and the shipped firmware depends on it. A third entry needs one new branch in the existing whitelist. There is one trap: a third name chosen as `operational-cert/next` would match the existing `operational-cert` branch and load into the current certificate's buffer, because `settings_name_steq()` with a NULL `next` accepts a `/` at the match point. A name like `operational-cert-next` does not collide.

There is one gap that would quietly cost the tier its central piece of evidence. A successful device event records the certificate's **subject** and not its serial; the serial is recorded only when a request is refused. Two overlapping Operational certificates carry the same subject, so nothing in the log distinguishes a request made with the new certificate from one made with the old. The proof of "the new identity works" would happen and leave no trace. It is one field on one success path, and it is the difference between a demonstrable control and an assertion.

The sharpest finding is on the service side and it is good news. Two concurrently accepted Operational certificates need **no change** to `certificate-active`, because `provisioningState.serials` is a cumulative set over every claim record and is never pruned, and `ownership-context` compares the certificate's OU against the device's owner, which both certificates share. The overlap is already expressible. What is not expressible is the renewal itself: `provisioningState()` switches on `kind` and only `claim` adds a serial to that set, and the claim path is closed to an owned device by the `device-unowned` check. So renewal needs its own route, its own record kind, and a new `case` in `provisioningState()`. Without that `case`, a renewed certificate is refused at `certificate-active` with "the service has no record of issuing certificate serial ...".

## Versions, and where they were read

The Zephyr workspace is not on the host. It lives at `/opt/zephyr-workspace` **inside** the long-lived podman container `tier2-validate`, which was running and was not restarted. Every path below prefixed `/opt/zephyr-workspace` was read with `podman exec tier2-validate ...`.

| Component | Version | How it was confirmed |
| --- | --- | --- |
| Zephyr | 4.4.2 | `git -C /opt/zephyr-workspace/zephyr describe --tags` prints `v4.4.2`, at commit `dccb0959963`. `zephyr/VERSION` reads major 4, minor 4, patchlevel 2. |
| Mbed TLS | 4.1.0 | `modules/crypto/mbedtls/include/mbedtls/build_info.h` line 39 defines `MBEDTLS_VERSION_STRING "4.1.0"`. |
| TF-PSA-Crypto | 1.1.0 | `modules/crypto/tf-psa-crypto/include/tf-psa-crypto/build_info.h` line 37 defines `TF_PSA_CRYPTO_VERSION_STRING "1.1.0"`. |
| This repository | `main` at `d1411d0` | Read on the branch `research/tier-08-renewal` cut from it. |

The ticket's warning holds and was re-checked rather than assumed. `mbedtls_pk_setup_opaque` appears in this tree only in `modules/crypto/mbedtls/ChangeLog`, as history. It is declared nowhere and defined nowhere. `MBEDTLS_USE_PSA_CRYPTO` appears nowhere in `zephyr/modules/mbedtls/` or in the Mbed TLS public headers. `mbedtls_pk_wrap_psa()` is declared in `modules/crypto/tf-psa-crypto/include/mbedtls/pk.h` and implemented in `modules/crypto/tf-psa-crypto/extras/pk.c` line 158. Any advice naming the first two symbols is Mbed TLS 3.x and does not apply here.

## 1. EST re-enrollment, from RFC 7030

RFC 7030 section 4.2.2 is two short paragraphs and they are the whole of the mechanism.

> EST clients renew/rekey certificates with an HTTPS POST using the operation path value of "/simplereenroll".

> A certificate request employs the same format as the "simpleenroll" request, using the same HTTP content-type. The request Subject field and SubjectAltName extension MUST be identical to the corresponding fields in the certificate being renewed/rekeyed. The ChangeSubjectName attribute, as defined in [RFC6402], MAY be included in the CSR to request that these fields be changed in the new certificate.

> If the Subject Public Key Info in the certification request is the same as the current client certificate, then the EST server renews the client certificate. If the public key information in the certification request is different than the current client certificate, then the EST server rekeys the client certificate.

That last paragraph is the one this course has to get right in its wording. Section 8 of the specification says renewal "creates a new key pair and certificate". In EST's vocabulary that is a **rekey**, and it is requested by the same `/simplereenroll` endpoint with a different public key in the request. There is no separate rekey endpoint and no flag: the server decides which of the two it is doing by comparing the request's SubjectPublicKeyInfo against the certificate on the TLS connection. RFC 7030 section 3.2.2 notes that this distinction "is explicitly indicated by the HTTP URI" only in the sense that enroll and re-enroll are different URIs; renew and rekey share one.

On authenticating with the certificate being replaced, section 3.3.2 is a MUST with a narrow escape:

> Generally, the client will use an existing certificate for renew or rekey operations. If the certificate to be renewed or rekeyed is appropriate for the negotiated cipher suite, then the client MUST use it for the TLS handshake, otherwise the client SHOULD use an alternate certificate that is suitable for the cipher suite and contains the same subject identity information.

Section 2.3 says the same thing from the client's side and names the fallback:

> When the current EST client certificate can be used for TLS client authentication (Section 3.3.2), the client presents this certificate to the EST server for client authentication. When the to be reissued EST client certificate cannot be used for TLS client authentication, any of the authentication methods used for initial enrollment can be used.

This is exactly section 8's "the current operational identity authenticates the request", and RFC 7030 is the citation for it. Note what the escape hatch means for this course: the "any of the authentication methods used for initial enrollment" fallback is, here, the Factory identity, and section 8 deliberately reserves the Factory identity for claiming and controlled recovery. So this tree should take the MUST and refuse the fallback, and say that it is refusing it.

Three things RFC 7030 does **not** contain, checked by grepping the whole RFC text rather than by memory:

- **No overlap period.** The words overlap, grace and staging do not appear in a renewal context anywhere in the document.
- **No certificate lifetime guidance.** Nothing says when a client should begin renewing, how short a client certificate should be, or how expiry relates to the renewal schedule. Section 3.7 says only that "the decision to issue a certificate to a client is always controlled by local CA policy" and "this document does not specify any constraints on such policy".
- **No revocation mechanism.** CRLs are mentioned only as something a client may receive in a `/cacerts` response and use when validating peers. There is no endpoint, no status check and no procedure for withdrawing a certificate EST issued.

What RFC 7030 does give, in section 4.2.3, is a bounded-retry pattern for a renewal the server cannot answer yet: an HTTP 202 with a `Retry-After` header, and the client "MUST wait at least the specified 'retry-after' time before repeating the same request", with the server responsible for all the state because "the client is stateless in this regard; it simply sends the same request repeatedly until it receives a different response code". That is a server-driven delay rather than a client-side backoff curve, and it is a different shape from the four-slot table this repository already shares between the two halves of the claim.

## 2. What BRSKI adds, from RFC 8995

For renewal, nothing, and the RFC says why. Section 1.3.4:

> Bootstrapping occurs only infrequently such as when a device is transferred to a new owner or has been reset to factory default settings.

Section 5.9.3 is one sentence long and hands enrollment straight back to EST:

> The pledge MUST request a new Client Certificate; see [RFC7030], Section 4.2.

`/simplereenroll` is not mentioned anywhere in RFC 8995. There is no BRSKI renewal flow to copy.

Two BRSKI sections are directly useful anyway, and they are the reason this ticket should not close as "BRSKI adds nothing".

**Section 2.6.1, "Lack of Real-Time Clock".** This is the standards-track sentence that licenses what this course's device does:

> When bootstrapping, many devices do not have knowledge of the current time. Mechanisms such as Network Time Protocols cannot be secured until bootstrapping is complete. Therefore, bootstrapping is defined with a framework that does not require knowledge of the current time. A pledge MAY ignore all time stamps in the voucher and in the certificate validity periods if it does not know the current time.

> A pledge with a real-time clock in which it has confidence MUST check the above time fields in all certificates and signatures that it processes.

And the substitute for a date check is a challenge-response freshness value:

> If the voucher contains a nonce, then the pledge MUST confirm the nonce matches the original pledge voucher-request. This ensures the voucher is fresh.

That is `T2-W-09` with a specification behind it. The device ignoring validity periods is a permitted configuration, not a defect, provided the freshness it cannot get from a clock comes from an exchange. Tier 7's claim nonce is already the same move.

**Section 5.9.4, "Enrollment Status Telemetry".** This is the important find. The whole section is worth having, because four of its sentences are the control section 8 asks for:

> The client MUST send an indicator to the registrar about its enrollment status. It does this by using an HTTP POST of a JSON dictionary with the attributes described below to the new EST endpoint at "/.well-known/brski/enrollstatus".

> When indicating a successful enrollment, the client SHOULD first re-establish the EST TLS session using the newly obtained credentials. TLS 1.3 supports doing this in-band, but TLS 1.2 does not. The client SHOULD therefore always close the existing TLS connection and start a new one, using the same Join Proxy.

> In the case of a failed enrollment, the client MUST send the telemetry information over the same TLS connection that was used for the enrollment attempt, with a Reason string indicating why the most recent enrollment failed.

> Within the server logs, the server MUST capture if this message was received over a TLS session with a matching Client Certificate.

The payload is a small JSON object with a mandatory `version` and `status`, an optional `reason` that SHOULD be present when `status` is false, and an optional free-form `reason-context`. The server "SHOULD respond with an HTTP 200 but MAY simply fail with an HTTP 404 error".

Read against this tree, that section says four things at once. The proof of a working new identity is a fresh TLS connection presenting the new certificate. In TLS 1.2 it has to be a fresh connection, because 1.2 cannot re-authenticate in band — and this tree is TLS 1.2 by a build assertion in `firmware/tier-07-operational-identity/src/opaque_tls.c`, which stops the build if `CONFIG_MBEDTLS_SSL_PROTO_TLS1_3` is ever turned on. A success report belongs on the new connection and a failure report belongs on the old one, which is a distinction worth teaching because it is the difference between proving a thing and reporting about it. And the server's record of the proof is a log line saying which client certificate the connection carried, which is what makes the proof auditable afterwards.

This tree's socket is already shaped for it. `run_request()` in `ota_client.c` is one connect, one `http_client_req()`, one close, and it takes the identity to present as its fourth argument. "Close the existing TLS connection and start a new one" is not a change to make; it is the only thing this socket can do.

## 3. How an overlap is represented and bounded, and who retires the old certificate

EST has no answer, so the primary sources are elsewhere. Two standards define a bounded overlap explicitly, and they agree on the part the ticket asks about: the **service** decides, on a timer, and the device's successful use of the new credential is not what retires the old one.

**RFC 6489, CA key rollover in the RPKI.** Three CA instances exist during a rollover: CURRENT, NEW and OLD. The NEW instance is created with a different key pair, reissues every product under the new key without publishing them, and then waits. Section 2, step 4:

> The duration of the Staging Period is determined by the CA, but it SHOULD be no less than 24 hours.

The purpose is stated: it is "intended to afford an opportunity for all RPs to download the NEW CA certificate prior to publication". The stage ends on a clock, not on an acknowledgement — step 5 begins "Upon expiration of the Staging Period". Retirement is then an explicit act by the rolling CA, which per step 6 must "generate a certificate revocation request for the OLD CA certificate and submit it to the issuer".

So: overlap represented as a named period with a floor, bounded by a timer the issuing side owns, and retirement performed by an explicit revocation request rather than by expiry.

**RFC 8739, STAR certificates in ACME.** This is the closer analogue, because it is about a series of short-lived end-entity certificates rather than a CA key change. The series is described by an `auto-renewal` object carrying a `lifetime` in seconds, an `end-date` past which nothing is issued, and an optional `lifetime-adjust`, "the amount of 'left pad' added to each STAR certificate", which pre-dates each certificate's `notBefore`. Overlap is created by a publication deadline, in section 3.3:

> the next certificate MUST be made available by the ACME CA at the URL indicated by "star-certificate" halfway through the lifetime of the currently active certificate at the latest.

> To avoid the client accidentally entering a broken state, the notBefore of the "next" certificate MUST be set so that the certificate is already valid when it is published at the "star-certificate" URL.

The overlap is therefore a fraction of the lifetime, not an absolute duration, and the mechanism that makes both certificates simultaneously valid is backdating the new one's `notBefore`. Section 3.5 formalises the padding as `f * T` with `.5 <= f < 1`.

RFC 8739 also names the cost, in the same paragraph, and this is the sentence Tier 8 should put in front of a Learner before it builds anything:

> It is worth noting that this has an implication in case of cancellation; in fact, from the time the next certificate is made available, the cancellation is not completely effective until the "next" certificate also expires.

That is the whole tension of this tier in one line. An overlap is a deliberate widening of the window in which a withdrawn authorization still works. A tier that builds renewal with an overlap and revocation in the same module has to say that the first control weakens the second, and by exactly how long.

Who ends the series: section 2.3 gives it to the identifier owner, by "sending a cancellation request to the Order resource", after which the server "MUST NOT issue any additional certificates for this Order". Neither RFC gives the end entity a way to retire its own old credential.

## 4. What "proves the new identity works" can mean here

The device cannot evaluate a validity window, and this is stronger than "it has no clock". Both halves were read in the pinned tree.

`firmware/tier-07-operational-identity/prj.conf` sets `CONFIG_MBEDTLS_HAVE_TIME_DATE=n`. In `modules/crypto/mbedtls/library/x509.c`, `mbedtls_x509_time_is_past()` and `mbedtls_x509_time_is_future()` have two definitions, and the one compiled without `MBEDTLS_HAVE_TIME_DATE` is `((void) to); return 0;`. In `library/x509_crt.c` the only places that set `MBEDTLS_X509_BADCERT_EXPIRED` and `MBEDTLS_X509_BADCERT_FUTURE` are inside `#if defined(MBEDTLS_HAVE_TIME_DATE)` at line 2536. So the device does not merely lack a trustworthy date: the code that would compare one is not in the image.

The only time source in the Tier 7 firmware is `k_uptime_get()`, monotonic milliseconds since boot, used by `health_gate.c` for its deadline and by `claim.c` for the Claim window and the retry delays. There is no RTC node, no SNTP client and no POSIX clock in the build. A grep of `firmware/tier-07-operational-identity/src` for `time(`, `gettimeofday`, `clock_gettime`, `sntp` and `rtc` finds nothing but a comment in `health_gate.c`.

So a renewal trigger cannot be "my certificate expires in fourteen days". Everything the device can know is an uptime, a boot count, or something the service told it. Three shapes are available and each is a real option rather than a hedge:

1. **The service tells the device to renew.** The assignment response already comes back on every poll and is already parsed by `ota_client_fetch_assignment()`. A field saying "renew now" makes the service the only holder of the schedule, which is consistent with `certificate-active` already being the only enforcer of expiry anywhere in the course. It also means a device cut off from the service never renews, which is the same blind spot `T7-W-20` already records, not a new one.
2. **The device renews on an uptime cadence.** Cheap, needs nothing from the service, and drifts: a device rebooted often renews constantly and a device up for a year renews once. It teaches the wrong lesson about what a lifetime is.
3. **The service hands the device a countdown it can hold.** A number of seconds remaining, turned into a `k_uptime_get()` deadline at the moment it arrives. This is what BRSKI's nonce does for freshness and what RFC 8739's `lifetime` does for scheduling, and it survives a disconnection for exactly as long as the device stays up.

Whichever trigger is chosen, the **proof** is the same and it is BRSKI's: open a new TLS connection presenting the new certificate, make a real request on it, and have the service record that the connection carried that certificate. In this tree the first two thirds of that are already built and the last third is missing by one field.

An event POST to `POST /v1/devices/{device_id}/events` on the Operational role runs `identity-operational`, `certificate-active`, `identifier-consistent`, `device-claimed` and `ownership-context`, in that order, before any handler sees the request. So a renewal that ends with an event posted under the new certificate has genuinely proved the new identity against all five checks, and it is a request the device already knows how to make.

But the log cannot tell afterwards which certificate did it, and during an overlap that is the only question the log is being asked. `deviceEvent()` in `services/ota/server.go` line 426 writes `certificate_device_id` and `accepted_from: "client_certificate"` on the success path and does **not** write the serial. The serial is written only on a refusal, by `recordRefusal()` in `services/ota/identity.go` line 380, whose own comment explains that the service's trail keeps "the subject and serial the caller presented, recorded as presented rather than as established". During an overlap both Operational certificates carry the same CN, because `issueOperational()` sets the CN from the device identifier and both certificates name the same device. So `certificate_device_id` is identical for the old and the new certificate, and a successful event row cannot distinguish them.

This is exactly the requirement BRSKI section 5.9.4 ends on — "within the server logs, the server MUST capture if this message was received over a TLS session with a matching Client Certificate" — and it is a one-field change on the success path rather than a design problem. It is worth naming as a finding because without it the tier's central claim, that the device proved the new identity before the old one was retired, is not evidenced by anything a Learner can grep.

One caution on the shape of the proof. A proof that only reaches the handshake proves less than it looks. `opaque_tls.c` reports a handshake failure as `ECONNABORTED` from `connect()`, and the map's own trap note says `err=-113` is transport or buffer — a refusal inside the handshake arrives with no status, no body and no check name. So a renewal that declares success on a completed handshake would be unable to distinguish "the service accepted this identity" from "the service accepted the chain and would have refused the request". The proof has to be a request that gets a status back.

## 5. This tree: can the socket present a different client certificate without a reboot

Yes, and Tier 7 already does it on every claimed board within a single boot.

`course_opaque_tls_set_identity()` writes a module-static `next_identity`, which `opaque_socket()` copies into the context at socket creation. `configure()` then runs inside `opaque_connect()`, fetches the certificate and key identifier from `identity.h` at that moment, parses the certificate into a per-connection `mbedtls_x509_crt`, and wraps the key identifier with `mbedtls_pk_wrap_psa()`. `context_free()` on close frees the certificate and the `mbedtls_pk_context` and leaves the PSA key alive, which the code comment says was verified on the board in #157 by reading the key back after every handshake. Nothing about the identity survives the close.

`run_request()` in `ota_client.c` takes the identity as a parameter, and the call sites prove the alternation rather than merely permitting it: four call sites pass `COURSE_TLS_IDENTITY_OPERATIONAL` and one at line 771 passes `COURSE_TLS_IDENTITY_FACTORY`, for the claim exchange. `main.c` runs both in one loop — a live Claim window takes the thread and runs `course_claim_step()`, and when no window is open the same loop runs `poll_once()`. A device claimed on Monday and polling on Tuesday has presented both certificates from one boot, repeatedly.

So the certificate presented is decided per connection, from a fresh read of `identity.h`, with no reboot and no `setsockopt()`. What blocks a *second Operational* certificate is not the socket. It is two narrower things:

- `enum course_tls_identity` in `opaque_tls.h` has exactly two members, and the header's comment is emphatic that they are roles rather than a ranking. A third member, or a second parameter naming which Operational certificate, is a deliberate change to that vocabulary and not a widening of it.
- `course_identity_operational_credentials()` in `identity.c` returns the constant `COURSE_OPERATIONAL_KEY_ID` and the single `stored_op_cert` buffer. There is exactly one Operational identity a device can describe.

One real constraint does travel with the socket and it bounds the shape of any renewal exchange. `opaque_socket()` refuses a second concurrent socket with `ENOMEM`, and the comment records that as the decision #158 made rather than a shortage. Every exchange is one socket on `main`. So a renewal cannot hold the old connection open while opening the new one, and BRSKI's "close the existing TLS connection and start a new one" is not just permitted here, it is compulsory. The BRSKI rule that a *failure* report goes back over the connection that failed is therefore not implementable in this tree as written, because that connection is closed by the time the failure is known. The honest local version is a failure report on a new connection under the **old** certificate, which the device still holds and which section 8 requires it to keep.

## 6. This tree: two PSA keys at once, and what `psa_copy_key()` did

`psa_copy_key()` landed. It is in the shipped Tier 7 firmware at `identity.c` line 857, inside `course_identity_store_operational_certificate()`, and #151 found a live defect in how it was called, which is the strongest evidence that it runs on the board rather than merely compiling.

What it does here, in order: the pending key is volatile, generated by `course_identity_generate_operational_key()` with usage `SIGN_HASH | SIGN_MESSAGE | COPY` and algorithm `PSA_ALG_ECDSA(PSA_ALG_SHA_256)`. On an accepted certificate, `psa_destroy_key(COURSE_OPERATIONAL_KEY_ID)` clears any prior occupant, tolerating `PSA_ERROR_INVALID_HANDLE`; then the target attributes are set with the fixed id `0x00000701`, `PSA_KEY_LIFETIME_PERSISTENT`, usage `SIGN_HASH | SIGN_MESSAGE` and the same algorithm; then `psa_copy_key()` copies the pending key into that slot; then the certificate is written to settings, and a settings failure destroys the key again rather than leaving a key with no certificate.

Three facts from this that a renewal design has to carry.

**The destroy-then-copy is why renewal cannot reuse this function.** The old Operational key is destroyed before the new one exists. There is no window in which both are alive, so calling this path for a renewal would end the overlap before it began. The `PSA_ERROR_ALREADY_EXISTS` return documented in `psa/crypto.h` for `psa_copy_key()` — "this is an attempt to create a persistent key, and there is already a persistent key with the given identifier" — is what the destroy is avoiding, and a renewal avoids it instead by naming a different identifier.

**The persistent Operational key cannot be relocated.** `psa_set_key_usage_flags()` at line 854 omits `PSA_KEY_USAGE_COPY`, and the comment above it at line 836 says so on purpose: "What is deliberately dropped is `PSA_KEY_USAGE_COPY`, which the pending key needed only to become this one. The Operational key is the end of that chain and does not get to start another." The implementation enforces it: `psa_copy_key()` in `modules/crypto/tf-psa-crypto/core/psa_crypto.c` line 2057 calls `psa_get_and_lock_key_slot_with_policy(source_key, &source_slot, PSA_KEY_USAGE_COPY, 0)` and fails otherwise. So "move the old key to a spare slot and put the new one in `0x701`" is not available. The new key must take a new identifier and something persistent must say which identifier is current.

**Two persistent keys at once are already proven, and three live keys are already proven.** `0x00000601` and `0x00000701` are two persistent keys on a claimed board. During an open Claim window on an already-claimed board — which #135 explicitly requires to still generate — a third, volatile key is alive beside them. `MBEDTLS_PSA_KEY_SLOT_COUNT` governs volatile keys and loaded persistent keys together; `prj.conf` does not set it, so the Zephyr default of 16 from `zephyr/modules/mbedtls/Kconfig.tf-psa-crypto` line 330 applies. Four live keys against sixteen slots is not close to a limit. `PSA_KEY_ID_USER_MAX` is `0x3fffffff`, so an identifier in the `0x0000070x` range is ordinary.

`CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE` is not set anywhere in `firmware/`, so the Zephyr default of 128 bytes per ITS entry applies. That is a per-entry bound, not a total, and it already holds two P-256 key pairs on a working board, so a third entry of the same shape needs nothing changed. This was not measured here and is an inference from the two entries that already work.

## 7. This tree: the storage question

The ticket's premise is half stale. `cert_settings_set()` ignoring `name` was a Tier 6 defect, it was **found while settling #140 and fixed in Tier 7**, and the fix is the reason two entries work today. The current handler dispatches on `settings_name_steq(name, "factory-cert", NULL)` and `settings_name_steq(name, "operational-cert", NULL)`, and refuses anything else with `-ENOENT` after printing `identity.load unknown settings entry course/identity/%s, ignored`. The comment records exactly what the bug would have done: "the moment a second entry exists, an Operational certificate loads into `stored_cert` and the device reports its Operational fingerprint as its Factory one."

So two concurrent entries under `course/identity` work, and a third is one new branch. Four supporting facts, each read rather than assumed.

An unknown name does not break the load. `settings_call_set_handler()` in `zephyr/subsys/settings/src/settings.c` line 226 calls `ch->h_set(...)` and, on a non-zero return, logs `set-value failure` and continues, with the comment "Ignoring the error". A `-ENOENT` from this handler costs a log line, not a failed boot.

The name matching does not prefix-collide, with one exception that is a genuine trap. `settings_name_steq()` at line 75 walks both strings, returns 0 if the key is not exhausted, returns 1 if `*name` is then `/` (filling `next` when asked), and returns 1 if `*name` is then `=` or `\0`. So `operational-cert-next` against key `operational-cert` leaves `*name == '-'` and returns 0, which is safe. But `operational-cert/next` leaves `*name == '/'` and returns **1**, which means a hierarchical third name would load the next certificate into `stored_op_cert` and silently overwrite the current one — the #140 defect in a new costume. A third entry should be a sibling name, not a child.

Space is not a constraint. `COURSE_CERT_MAX` is 800 bytes, the build asserts it against `erase_block_size - 4 * 8` for one NVS entry, and the storage partition in `dts/esp32c6_4m_flash_map.dtsi` is `0x030000`, 192 KiB, at `0x3b0000`. A third 800-byte entry is not a question. The RAM cost is another 800-byte static buffer beside `stored_cert` and `stored_op_cert`, against a 48 KiB mbedTLS heap and a measured `main` high-water of 3224 of 8192 bytes.

`course_identity_erase()` already argues the invariant a third entry inherits. Its comment says the four places exist as one call because "erasing one and not the others leaves a certificate for a key that no longer exists". A renewal adds a fifth and a sixth place, and the same reasoning says they join that one call rather than getting their own.

## 8. This tree: what the service already carries, and what it refuses

This is where the research changed its own mind, so it is worth stating precisely.

**An overlap of two accepted Operational certificates needs no change to `certificate-active`.** Clause 3 joins on `provisioningState.serials`, and `services/ota/provisioning.go` builds that set by replaying every record: `case recordKindClaim` adds `record.CertSerial` to `state.serials` and never removes one. The comment already defends the width of that join — "the record binds a serial, and a serial is not a certificate". `case recordKindRemanufacture` deletes from `state.devices` and leaves `state.serials` untouched. So once a serial has been recorded as issued, it stays issued forever, and the **only** thing that stops it is an append to `revoked.jsonl`, which `revokedSerials()` reads live on every request. Two live serials for one device is the default behaviour of this store, not a feature to add.

**`ownership-context` passes for both certificates.** `state.devices[deviceID]` holds only `{owner, claimed}`, and `authorizeDevice()` compares `identity.OwnerScope != claim.owner`. Both the old and new Operational certificates carry the same owner slug in their subject OU, because `issueOperational()` puts the owner there and a renewal does not change owners. Neither certificate is preferred and neither is refused.

**Retirement is already a built command.** `./course claim revoke --serial ...` exists in `internal/courseapp/tier07.go`, refuses any serial it cannot find a claim record for, appends one line to `revoked.jsonl`, and prints why the device is never told. Its own help text contains the sentence this tier should reuse: "a device that cannot check a date cannot check a list." It is described in the source as a lab control rather than an operator workflow, with "Tier 8 owns revocation as something an owner does" written into the comment. So the retirement mechanism exists and the operator-facing wrapper around it is Tier 8's.

**The renewal itself is refused three ways.** This is the part that needs building.

The claim route will not carry it. `POST /v1/devices/{device_id}/claim` is `RoleFactory` in `deviceRoutes()`, so an Operational certificate is refused at `identity-factory` before any handler runs, and the operator half refuses an owned device at `device-unowned` with "that device is already owned, and ownership is first come in this course". Section 8's renewal is authenticated by the Operational identity and involves no physical action, so it is a different route by construction rather than by preference.

`provisioningState()` will not see a new record kind. It switches on `record.Kind` and only `claim` adds a serial. A record written as `kind: "renewal"` is read by `readProvisioningRecords()`, matches no case, and contributes nothing — so the renewed certificate is refused at `certificate-active` clause 3 with "the service has no record of issuing certificate serial ...". One new `case` fixes it. Writing the renewal as another `claim` line would work today and would be wrong: it would make the record log unable to distinguish a first claim from a renewal, which is the log Tier 8's evidence work reads.

**A successful exchange does not record which certificate made it.** Set out in section 4 above, and repeated here because it belongs to the service rather than the device: `deviceEvent()` records the certificate's subject on success and its serial only on a refusal. Two overlapping certificates share a subject, so the evidence that the new identity worked is not in the log today.

There is a latent asymmetry worth a note even though nothing exploits it today. A remanufacture deletes the device from `state.devices` but leaves its serials in `state.serials`, so an old certificate from before a remanufacture still passes clause 3 and is caught one check later by `device-claimed`. That is fine while remanufacture is the only eraser. Decommissioning, which this map also builds, states in section 8 that old certificates must not be able to enroll the device again, and it will be looking at the same two structures.

## 9. What is not established

Stated plainly, because a labelled unknown is worth more here than a confident guess.

- **Nothing here was built or run.** Every device-side claim in sections 5 to 7 is read from source. The three that most want a board are: that a second persistent PSA key at a new identifier is created and survives a reset; that `configure()` presents the second certificate correctly when handed the second key identifier; and that the RAM cost of a third 800-byte buffer plus a second parsed certificate leaves `main`'s stack where #158 measured it.
- **How long the overlap should be, in this course, is not determined by anything found here.** RFC 6489's 24-hour floor is about relying parties polling a repository and does not transfer. RFC 8739's "halfway through the lifetime" is a publication deadline for an automated CA, and half of this course's 90-day `operationalLifetime` is 45 days, which is longer than any lab session. The overlap bound is a course design decision and a decision ticket's subject, not a fact to be looked up.
- **Whether the device should hold two certificates at all, or only two keys, was not settled here.** An alternative shape exists in which the device keeps one certificate and the *service* keeps both serials valid for the overlap. That is cheaper on the device and it does not satisfy section 8's "the old and new certificates overlap", so it is a specification question rather than an implementation one.
- **The ninety-day `operationalLifetime` is a constant in two places and was not traced to a third.** `services/ota/claim.go` line 73 defines it with the comment that it is "spelled here as well as in coursepki", and this research did not read the `coursepki` copy. A renewal exercise that has to complete inside one lab session will want a shorter lifetime, and that is two constants to move, or three.
- **Whether the ESP32-C6-DevKitC-1 behaves identically to the nanoESP32-C6 for any of this was not examined.** Everything above is board-independent source reading. Settled input 2 of the map puts the hardware results on the DevKitC-1 and none exist yet.

## Primary sources

| Source | Used for |
| --- | --- |
| [RFC 7030, EST](https://www.rfc-editor.org/rfc/rfc7030.txt) | Sections 2.3, 3.2.2, 3.3.2, 4.2.2, 4.2.3, 3.7. Re-enrollment, the renew/rekey distinction, authenticating with the certificate being replaced, the 202 plus Retry-After pattern, and the absence of overlap, lifetime guidance and revocation. |
| [RFC 8995, BRSKI](https://www.rfc-editor.org/rfc/rfc8995.txt) | Sections 1.3.4, 2.6.1, 2.6.2, 5.9.3, 5.9.4, 5.9.5. Bootstrap scope, the clockless pledge, and enrollment status telemetry as an exchange-based proof. |
| [RFC 6489, CA key rollover in the RPKI](https://www.rfc-editor.org/rfc/rfc6489.txt) | Section 2. A named staging period with a 24-hour floor, ended by a timer, retirement by explicit revocation request. |
| [RFC 8739, STAR certificates in ACME](https://www.rfc-editor.org/rfc/rfc8739.txt) | Sections 3.1.1, 3.3, 3.5, 2.3. Overlap as a fraction of the lifetime, backdated `notBefore`, and the cost an overlap imposes on cancellation. |
| Zephyr 4.4.2 at `dccb0959963` | `subsys/settings/src/settings.c`, `subsys/secure_storage/Kconfig`, `modules/mbedtls/Kconfig.tf-psa-crypto`. |
| Mbed TLS 4.1.0 and TF-PSA-Crypto 1.1.0 | `library/x509.c`, `library/x509_crt.c`, `include/psa/crypto.h`, `core/psa_crypto.c`, `include/mbedtls/pk.h`, `extras/pk.c`. |
| This repository at `d1411d0` | `firmware/tier-07-operational-identity/src/{identity.c,identity.h,opaque_tls.c,opaque_tls.h,ota_client.c,claim.c,main.c}`, `firmware/tier-07-operational-identity/{prj.conf,Kconfig,dts/esp32c6_4m_flash_map.dtsi}`, `services/ota/{identity.go,listeners.go,provisioning.go,claim.go,server.go}`, `internal/courseapp/tier07.go`, `docs/course-specification.md` sections 7 and 8. |
