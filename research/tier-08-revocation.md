# Certificate status when the verifier is also the issuer

Research for issue [#208](https://github.com/tkEmLogic/learning-cyber-security/issues/208), under the Tier 8 map [#203](https://github.com/tkEmLogic/learning-cyber-security/issues/203). Sources read on 2026-09-21 and 2026-09-22.

This is research and not design. It reports what the repository already does, what the standards say, and what real fleets do. Decision ticket [#213](https://github.com/tkEmLogic/learning-cyber-security/issues/213) owns the choices that follow from it.

The short answer to the ticket's question is that the course has already built the mechanism real fleets use, and has not yet built the operation around it. A private CA that is also the only verifier does not need a revocation protocol, because it can read its own record. AWS and Microsoft both say so in their own documentation. What the course is missing is not a CRL. It is a revoke operation, a way for the device to read the refusal it already receives, and an honest account of what a serial blocklist cannot do.

## 1. What Tier 7 built, read from the source

### The check

`certificate-active` is in `services/ota/listeners.go`, in `(*Server).certificateActive`. It has three clauses and they run in this order.

Clause 1 compares `now` from `MutualTLS.Now` against the leaf's `NotAfter`, then against `NotBefore`. The clock is the service's. `MutualTLS.Now` is documented in `services/ota/identity.go` as "the only enforcer of certificate expiry anywhere in the course".

Clause 2 looks the leaf's serial up in the set returned by `(*Server).revokedSerials()`, which reads `.course-state/provisioning/revoked.jsonl` on every request.

Clause 3 asks whether the serial appears in `provisioningState().serials`, and it applies to Operational certificates only, because a Factory certificate arriving at the claim endpoint is by definition asking to be given its first claim record.

The source comment on clause 3 states the argument the tier rests on: a CA signature is not an authorization, the record is. It also claims clause 3 is "strictly stronger than the CRL this course deliberately does not build, because a CRL catches only what was explicitly withdrawn while the record catches everything never issued". That claim holds, with one qualification given in section 5 below.

### The order the checks run in

`(*Server).authorizeDevice` runs the role check, then `certificateActive`, then `identifierConsistent`, then `device-claimed` and `ownership-context`. The order matters for revocation, because it decides which check name a Learner sees, and section 5 shows a case where the name is not the one you would expect.

### What revocation is today

`revoked.jsonl` is written by exactly one thing: `(*app).claimRevoke` in `internal/courseapp/tier07.go`, reached as `./course claim revoke --serial`. It appends one line of `{"certificate_serial": ..., "revoked_at": ...}` and nothing else. There is no status field, no reason, no revoking party and no device identifier in the record.

The command refuses any serial that does not already appear in a `claim` record. That bound comes from constraint 14 of the fixture safety contract, and its stated purpose is that the command "cannot become a general revocation tool a tier early". Two consequences follow for Tier 8, and both are facts about the code rather than opinions.

First, the command cannot revoke a Factory certificate, because Factory serials are written into `enrollment` records and the command searches `claim` records only.

Second, the service does not share that bound. `revokedSerials()` returns a flat set of strings with no notion of role, issuer or kind, and clause 2 is checked before the role-specific clause 3 and for every role. So if any writer put a Factory serial into `revoked.jsonl`, the service would already refuse that Factory certificate at `certificate-active`, including at the claim endpoint. The enforcement for blocking a Factory identity exists. Only the operation that writes it is missing. This is the single most useful thing this research found, and section 6 returns to it.

### What the device is told, today

`./course claim revoke` prints the honest sentence itself: "The device is never told: it holds no revocation client in any tier, because a device that cannot check a date cannot check a list."

That sentence is true about revocation checking and it overstates the silence. The wire already carries the reason. Every authorization refusal on the device listener is HTTP 403 with a `Refusal` body of `check` and `reason`, and the reason for a revoked certificate is the literal string `certificate serial NNN is marked revoked`. The service is telling the device. The Tier 7 firmware is not reading it on the route where it matters, and that is a firmware gap rather than a protocol one.

### Three levels of refusal literacy in the Tier 7 firmware

This is the part of the ticket's question that the repository answers most precisely, so it is worth being exact. `firmware/tier-07-operational-identity/src/ota_client.c` has three response callbacks and they capture different things.

`capture_claim` fills a `struct claim_capture`, which holds both a body and an `int status`. The claim route therefore reads both. `claim.c`'s `handle_reply` branches on the body's `check` field, treats any `check` at all as terminal, closes the window and prints `claim.refused status=%d check=%s` followed by the reason. The comment says the firmware branches on `check` and not on the status because every authorization refusal is 403. The claim path is fully refusal-literate.

`capture_status` fills a `struct status_capture`, which holds only `int code`. The status-event route reads the status and throws the body away: it prints `ota.report rejected status=%d` and returns `-EIO`. It knows it was refused and cannot say why.

`capture_body` fills a `struct body_capture`, which has `buf`, `len`, `used` and `overflow`, and no status field at all. It never touches `rsp->http_status_code`. The source comment at the top of `capture_claim` states the design plainly: "capture_body() throws the status away and capture_status() throws the body away". Two call sites use it, covering three routes: `ota_client_fetch_assignment` for the assignment, and `ota_fetch_release_artifact` for the manifest and the manifest signature.

`write_image` handles the image download and is the interesting case. It reads `rsp->http_status_code`, but only to require 206 on a resumed transfer: the check is inside `if (writer->resume_offset > 0 ...)`, so a fresh download never looks at the status. What saves it is unrelated to authorization. It compares the declared content length against the size in the signed manifest before any byte reaches flash, and a 403 refusal body is nowhere near the right size, so the refusal is caught as a size violation.

So the answer to the module's own closing question, counted from the source, is this. Of the six device routes, one reads the refusal fully, one reads the status and discards the reason, three read neither, and one is caught by a signed size check that was put there for a different threat. The exact count matters because #213 has to decide what to repair, and "four routes are blind" would have been wrong in a way that hides the most reassuring finding: the image path already refuses, for a reason worth teaching.

`ota_client_fetch_assignment` is where the failure shows. It calls `run_request`, which returns 0 whenever `http_client_req` succeeded at the transport level, then parses whatever body arrived and reports `-EINVAL` with `ota.assignment missing release_id or image_path` when `release_id` or `image_path` is absent. A 403 refusal body is well-formed JSON with neither field, so it lands in exactly that branch.

That is the Tier 7 gate failure, and the published module already teaches it at `course-material/tiers/tier-07-operational-identity/index.md`.

### The clock

`CONFIG_MBEDTLS_HAVE_TIME_DATE=n` in every tier from 2 to 7. The `prj.conf` comment gives the reason: with it on and no time source, the clock reads 1970, every certificate is "not yet valid", and every handshake fails forever.

This is not merely a weaker check. Mbed TLS documents that when time and date are unavailable the validity check is skipped entirely, so no `MBEDTLS_X509_BADCERT_EXPIRED` is ever produced. Section 4 has the quote. The device is not lenient about expiry; it is blind to it.

The Tier 7 module argues the three options for a device with no trusted time, and the course takes the third consistently: decline to make time-based decisions and let the party with a trustworthy clock make them. Section 7 of the specification already states the rule as device time being evidence and not an authorization input.

### The Operational certificate's shape

`internal/coursepki/operational.go` sets `OperationalLifetime = 90 * 24 * time.Hour`, against the Factory identity's ten years, and its comment says outright that ninety days is enforceable only because the service is the sole enforcer, and that renewal is Tier 8's opening argument.

Serials are 128-bit random values from `newSerial()` in `internal/coursepki/pki.go`. They are unique in practice, but `revoked.jsonl` keys on the serial string alone with no issuer, so the record is issuer-ambiguous by construction. Nothing exploits that today because the two device CAs' serials will not collide, and it is worth writing down because the file's key is the thing Tier 8 may extend.

### What a Learner observes

`E-7-06` in `evidence/templates/tier-07/authorization-tests.md` is the revocation row. Its `Observed on` value is `host`, and its `CA key` column is empty, because the fixture revokes a serial the service genuinely issued to a synthetic device. The runner is `rowRevokedCertificate` in `internal/courseapp/tier07_bypass.go`. It claims a synthetic device, calls `claimRevoke` on the recorded serial, and prints the sentence that carries the lesson: "the certificate is unexpired and correctly signed. Only the record changed."

Revocation has no board witness in Tier 7. No row in the fifteen observes a real board losing access. That is a gap Tier 8's hardware campaign can close cheaply, and it is the only way the gate failure becomes something a Learner sees rather than reads about.

## 2. How a private CA that is also the verifier represents status, and what each form costs

Four forms are available. The repository already uses two of them and the course teaches with both.

| Form | What it is | What it costs | What it cannot do |
| --- | --- | --- | --- |
| Status field on the device record | One field, the six lifecycle states in `internal/courseapp/tier06.go` | Nothing new. The record is already read on every request | Says nothing about a specific certificate. A device with two certificates has one status |
| Serial blocklist | `revoked.jsonl` today | One file, one live read per request | Does not survive re-issuance. A new serial is not on the list |
| Issued-serial allowlist | Clause 3 today | Nothing new, the claim record already carries the serial | Catches only certificates, not devices. See section 5 |
| Short-lived certificate that expires | `OperationalLifetime`, ninety days | A renewal path, and a hard dependency on it | Leaves a window equal to the certificate lifetime |
| Signed status assertion | Not built. An OCSP response or equivalent | A responder, and a device that can date-check it | Unavailable to this device at all, because of the clock |

The allowlist form is the one the course invented and it is the interesting one. An issuance record is a positive list, and a positive list is closed by default: everything not on it is refused. A CRL is a negative list and is open by default: everything not on it is accepted. When the verifier is also the issuer it can afford the positive list, because it knows the whole of what it issued. A public CA cannot, because its verifiers are strangers who have no access to its issuance database. That is the whole reason CRLs and OCSP exist, and it is the sentence the course already carries in `provisioning.go`: "every real complication in CRLs comes from the day those two are different machines."

### The case the ticket asks about

The certificate is valid, the CA signature checks out, and the authorization is gone anyway. All three clauses of `certificate-active` are about this case and they catch three different versions of it.

Clause 1 catches authorization that ran out on its own. Clause 2 catches authorization that was taken away. Clause 3 catches authorization that was never granted, for a certificate that is cryptographically perfect. Clause 3 is the one that has no equivalent in public PKI, and it is the one that would survive an attacker who obtained the CA key but could not write the record.

The general shape is that a signature answers "did the authority sign this", and only a record answers "does the authority still stand behind it". Those are different questions and a verifier that conflates them has one control where it needs two.

## 3. What the standards say, and whether a client can be told

### There is a TLS alert for exactly this, and it is not usable here

RFC 8446 section 6.2 defines `certificate_revoked`: "A certificate was revoked by its signer." It sits alongside `certificate_expired` ("A certificate has expired or is not currently valid"), `certificate_unknown` ("Some other (unspecified) issue arose in processing the certificate, rendering it unacceptable"), `bad_certificate`, `unknown_ca` and `access_denied`. None of these is marked as client-only or server-only, so a server may send any of them about a client's certificate during client-certificate authentication.

Three facts make the alert the wrong instrument for this course.

It is at the wrong layer. The alert is sent during the handshake, and in Tier 7 the handshake deliberately does not decide revocation. `VerifyClientCertificate` in `identity.go` asks only which authority signed, one `CheckSignatureFrom` per self-signed root, and has no opinion about time or records. That change was made in #150 precisely so clause 1 would be reachable over the wire with a check name attached. Moving revocation back into the handshake would undo it and would put the refusal back in the layer the module calls the one with no vocabulary.

A client cannot rely on which alert it gets. RFC 8446 section 6.2 says an implementation "SHOULD send an appropriate fatal alert", and section 6 says a receiving implementation "SHOULD indicate an error to the application". Both are SHOULD and not MUST, and `certificate_unknown` exists as a catch-all for any unspecified certificate problem. So nothing requires a server to distinguish a revoked client certificate from a merely bad one, and a device that branched on `certificate_revoked` would be depending on behavior no peer owes it. Worth being precise about what the research did and did not find: RFC 8446 contains no articulated guidance that implementations should deliberately obscure which certificate alert they send. The unreliability is structural, from the SHOULD and the catch-all, rather than a stated privacy rule. The one place the specification explicitly licenses collapsing two causes into one alert is unrelated, where sending `unknown_psk_identity` is OPTIONAL and a server MAY send `decrypt_error` instead.

The record check has no alert at all. There is no alert description meaning "I have no record of issuing this", which is clause 3, the course's strongest clause. An alert vocabulary fixed in 2018 cannot name a check invented for this service.

### Revocation status is defined in a way this device cannot use

RFC 5280 section 5.3.1 defines `CRLReason`: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn` and `aACompromise`. The names map onto the course's own cases, with `privilegeWithdrawn` reading as ownership transfer and `cessationOfOperation` as decommissioning. Note honestly that RFC 5280 gives no prose definition for either of those two beyond the enum name, so the mapping is the course's reading and not the specification's.

Two of the values carry a lesson worth more than the vocabulary. `certificateHold` is a reversible state, a suspension rather than a revocation. `removeFromCRL` is the value that cancels it. RFC 5280: "the removeFromCRL (8) reasonCode value may only appear in delta CRLs and indicates that a certificate is to be removed from a CRL because either the certificate expired or was removed from hold." So public PKI has a standard notion of a hold that can be lifted, and the course's append-only `revoked.jsonl` has no such notion. Section 6 shows why that matters for the Factory identity, where an irreversible block is the difference between a stolen device and a bricked one.

RFC 6960 defines OCSP, whose `revoked` status carries a mandatory `revocationTime` and an optional `revocationReason` drawn from the same `CRLReason` enum.

Both mechanisms are anchored to the verifier's clock, and OCSP says so directly. RFC 6960 section 4.2.2.1: "Responses whose nextUpdate value is earlier than the local system time value SHOULD be considered unreliable. Responses whose thisUpdate time is later than the local system time SHOULD be considered unreliable." There is no clock-independent alternative in the specification. CRLs are anchored the same way, and RFC 5280 section 5.1.2.5 requires it: "Conforming CRL issuers MUST include the nextUpdate field in all CRLs."

That is the formal version of #139's reasoning that a device that cannot check a date cannot check a list. The research confirms it rather than undermining it, and it now has a citable sentence behind it.

There is one correction to make to a natural assumption about stapling, because the mechanism exists and runs in the unhelpful direction. RFC 8446 section 4.4.2.1: "A server MAY request that a client present an OCSP response with its certificate by sending an empty 'status_request' extension in its CertificateRequest message." So TLS 1.3 does let a server demand that a client prove its own certificate's status. That makes the device's problem worse rather than better, because the device would have to obtain a signed status response about itself from somewhere, and it still could not evaluate the time fields it carries. It is a good thing for the module to name in one sentence: the standard way to solve this exists, it puts the work on the device, and the device cannot do the work.

### At the HTTP layer the answer is yes, and the course already does it

RFC 9110 section 15.5.4: "A server that wishes to make public why the request has been forbidden can describe that reason in the response content (if any)." That is exactly what the `Refusal` body of `check` and `reason` does. Tier 7's design is not a workaround for a missing standard mechanism. It is the mechanism the HTTP specification points at, and the specification also anticipates the device's correct behavior: "The client SHOULD NOT automatically repeat the request with the same credentials."

RFC 9457 Problem Details for HTTP APIs offers a standard shape for the same job, with `type`, `title`, `status`, `detail` and `instance` under `application/problem+json`. Two of its rules validate Tier 7's field split rather than challenging it. `detail` is "a human-readable explanation specific to this occurrence" and "Consumers SHOULD NOT parse the 'detail' member for information", while `type` is the stable URI a consumer is meant to branch on. That is precisely the division between `reason` and `check`, and #136 already settled that the firmware branches on `check`. So the recommendation is to cite RFC 9457 in the module as the standard form of what `Refusal` does, and not to adopt it: renaming `check` to `type` would cost the course its central word for no teaching gain.

### The protocols that could tell a client refuse to, on purpose

This is the strongest finding in the standards review and it changes the tone the module should take.

RFC 6750 defines `invalid_token` as covering a token that "is expired, revoked, malformed, or invalid for other reasons". RFC 6749 defines `invalid_grant` the same way, for a grant that "is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client". In both cases revoked is folded into one undifferentiated code, and the holder cannot tell revocation from any other failure.

RFC 7009, which defines token revocation as an operation, goes further and says why. Section 2.2: "The authorization server responds with HTTP status code 200 if the token has been revoked successfully or if the client submitted an invalid token. Note: invalid tokens do not cause an error response since the client cannot handle such an error in a reasonable way."

So the answer to the ticket's question is that the mature credential-revocation standards deliberately decline to tell a client that its credential was revoked as against merely bad, and the stated reason is that the client can do nothing differently with the distinction. That is a real argument and the course should meet it rather than ignore it. The counter-argument the course can make is about diagnosis rather than device behavior: a device that reports the check it was refused at makes a fleet debuggable, and the Tier 7 gate failure is the cost of not having it. The device still does the same thing either way, which is to stop and report.

The oracle trade sits alongside it. A refusal that distinguishes revoked from unknown tells an attacker which credentials exist. `T7-W-23` already ruled on that, keeping refusals distinguishable and recording the consequence, and the same ruling covers revocation.

### The enrollment protocols do not solve it either

RFC 7030 (EST) defines `/simpleenroll` and `/simplereenroll`, and re-enrollment is entirely client-initiated. There is no server-initiated way to tell a client its certificate is dead or that it must re-enroll. Section 4.2.3 specifies only a generic failure: "The server MUST answer with a suitable 4xx or 5xx HTTP error code when a problem occurs", with an optional "plaintext human-readable error message". A client that has lost authorization discovers it by being refused.

RFC 8995 (BRSKI) has no voucher-revocation push to a pledge either. Its only status telemetry runs the other way, pledge to registrar, where "the pledge MUST indicate its pledge status regarding the voucher". Where BRSKI needs a voucher to stop being valid it uses a bounded lifetime, the `expires-on` field on nonceless vouchers, rather than a revocation message. The revocation checking BRSKI does require is for the registrar's certificate, which the pledge is shown, and not for the pledge's own identity.

Both specifications are already cited in section 8 of the specification, so the course can state this with sources it already carries. The pattern across EST, BRSKI, OAuth and token revocation is consistent: no constrained-device standard proactively tells a client that its own credential has been withdrawn.

### The standards do bless short-lived certificates as the substitute

RFC 8739 is the primary-source anchor, and its abstract states the argument outright: "Public key certificates need to be revoked when they are compromised, that is, when the associated private key is exposed to an unauthorized entity. However, the revocation process is often unreliable. An alternative to revocation is issuing a sequence of certificates, each with a short validity period, and terminating the sequence upon compromise."

That is a standards-track document rather than a vendor opinion, and it is the same argument smallstep and Golioth make in section 4. It also names the mechanism that Tier 8's renewal ticket creates: the sequence is terminated rather than any single certificate being revoked mid-flight, which is passive revocation under another name.

## 4. What real fleets do

Two of the three largest device platforms say in their own documentation that they do not check PKI revocation for device certificates, and that the control is the registry record.

Microsoft is the most direct. The IoT Hub documentation for X.509 authentication states: "IoT Hub doesn't check certificate revocation lists from the certificate authority when authenticating devices with certificate-based authentication. If you have a device that needs to be blocked from connecting to IoT Hub because of a potentially compromised certificate, disable the device in the identity registry." That is `certificate-active` clause 2 and the lifecycle state, described by a hyperscaler as the recommended mechanism. The newer Azure Device Registry preview goes further in an instructive direction: revoking a certificate there does not by itself block the device, because "the device identity stays enabled, so the device can reconnect after it gets a new certificate", and blocking requires separately disabling the identity. That is the same distinction #213 has to make between revoking a certificate and marking a device revoked, found in a shipping product.

AWS IoT Core keeps certificate status as a field on its own registry: `UpdateCertificate` takes `ACTIVE`, `INACTIVE` or `REVOKED`, and "AWS IoT verifies that a client certificate is active when it authenticates a connection". CRL and OCSP checking is not native. It is something a customer builds with a pre-authentication Lambda that runs "for every client connect attempt", which is first-party confirmation that the platform's own path does not consult either. AWS also treats an externally-issued CRL as an auditing input rather than an enforcement one: Device Defender has a check that flags a certificate that "is in its CA's certificate revocation list, but it is still active in AWS IoT".

Mender uses authentication sets that an administrator authorizes or deauthorizes, with no PKI revocation mechanism documented. hawkBit's documented model is server-side tokens. Neither documents a device-certificate revocation story.

One AWS behavior is worth copying into the module because it corrects a natural assumption. Deactivating a certificate does not merely refuse the next connection: "Within a few minutes of updating a certificate from the ACTIVE state to any other state, AWS IoT disconnects all devices that used that certificate to connect." A long-lived MQTT session would otherwise outlive its own authorization. This course's device opens a fresh connection per poll, so the question does not arise on the wire, and it is exactly the kind of thing a Learner should be told does arise elsewhere.

### What those platforms tell the device

Not much, and deliberately. AWS IoT's lifecycle events carry `AUTH_ERROR` ("The client failed to authenticate or authorization failed") and `FORBIDDEN_ACCESS`, and a failed connect reports `connectFailureReason` with the single value `AUTHORIZATION_FAILED`. Those events go to backend subscribers rather than to the refused device, which at the wire level sees a connection failure with no semantic reason.

So the course's `Refusal` body is more informative than AWS's, not less. Tier 7 gives a refused device the name of the check that refused it and a human-readable reason. That is a genuine and defensible teaching point, and it is worth stating in the module rather than apologizing for the absence of a CRL.

### Short-lived credentials as the substitute, and the trade

smallstep names the pattern and has the clearest first-party statement of it. Their term is passive revocation: "the CA will block the certificate's future renewal. This is called passive revocation." They are equally clear about what it does not do: "A certificate that has been passively revoked will still be valid for the remainder of it's validity period." They are explicit that it is not a full substitute: "Passive revocation is a good option for internal PKI, because it avoids the complexity of relying on centralized third parties", but "You may require active revocation if you need immediate certificate revocation, or if you are issuing long-lived certificates."

Three costs come with it and all three land on Tier 8.

The compromise window equals the remaining certificate lifetime. Ninety days is a long window by the standards of the fleets above. This is the coupling with the renewal ticket and it runs in the direction of shorter certificates, which is a design choice #213 and the renewal decision share.

The renewal path becomes load-bearing. smallstep's own reasoning is that a certificate lifetime sets a ceiling on tolerable CA downtime, because once the certificate expires the device is locked out. A renewal outage becomes a fleet outage. Section 8 already anticipates this by requiring that a device whose renewal fails keeps its current valid identity and retries with bounded backoff.

Renewal traffic needs jitter. smallstep renews at two thirds of the lifetime and adds jitter explicitly "to prevent a thundering herd of renewals sent to the CA by many VMs that were provisioned at the same time". A fleet provisioned on one day renews on one day. Tier 7 already shares one backoff cadence between the two halves of the claim from #148 and #148's cadence is retry-on-failure rather than schedule spreading, so this is a distinct thing and a cheap one.

Golioth states the same short-lived-certificate rationale for devices specifically: compromise is time-bounded, rotation becomes routine rather than exceptional.

The important honesty is that passive revocation does not fit the course's current shape at all. Passive revocation works by refusing to renew. Tier 7 has no renewal, so there is nothing to withhold, and revocation has to be active. Once Tier 8 builds renewal, passive revocation becomes available as a second mechanism, and the two are different in a way the module can show: an active revocation refuses the next request, a passive one refuses the next renewal and lets the current certificate run out.

## 5. Two findings about the existing code that change what revocation can be built on

Both of these were found by reading the code and neither is written down anywhere in the repository.

### The issued-serial set never shrinks

`(*Server).provisioningState()` in `services/ota/provisioning.go` replays the record log. A `claim` record adds the device to `state.devices` and its serial to `state.serials`. A `remanufacture` record does `delete(state.devices, record.DeviceID)` and nothing else. The serial stays in `state.serials` forever.

So after a remanufacture the old Operational certificate still passes all three clauses of `certificate-active`: unexpired, not in `revoked.jsonl`, and still in the issued-serial set. It is refused, but one check later and under a different name, at `device-claimed`, because the device no longer has a claim.

Two consequences for Tier 8. Decommissioning cannot rely on clause 3 to forget a certificate, because clause 3 has no forgetting in it. And any evidence row that expects `certificate-active` after a remanufacture or a decommissioning will observe `device-claimed` instead. That is a concrete trap for the hardware campaign, which the map already flags as fog for a different reason.

### A serial blocklist is not device revocation, and the code shows why

Revoking a serial revokes one certificate. Whether that amounts to revoking the device depends entirely on whether the device can get a different certificate, and in Tier 7 the answer is currently no, for a reason that has nothing to do with revocation.

A re-claim would issue a new serial, which would not be on the blocklist and would be in a claim record, so it would pass `certificate-active` cleanly. What stops it today is `device-unowned`: the claim record persists and a claimed device cannot be claimed again. First-come ownership, which #148 recorded as a consequence of the shared-image scope call, is what makes the serial blocklist look like device revocation.

The escape is `remanufacture`, the Tier 6 erase path, which deletes the claim state and reopens the claim. The module already names it as "the only escape from an expired Operational identity", and it is equally the only escape from a revoked one.

So the statement "revoked that a BOOT press undoes is not revocation" from #213 is correct as a design worry and not yet true as a defect. A BOOT press alone does not undo revocation. A remanufacture does, and a remanufacture is a host-side command rather than a physical action. Tier 8 has to decide whether a decommissioned identifier blocks remanufacture, which section 8 already requires when it says a decommissioned device needs "an explicit remanufacturing process with a new lifecycle record" and that a normal factory reset is not enough.

### One qualification on clause 3's strength

The claim that clause 3 is strictly stronger than a CRL holds against an outsider and weakens against the insider `T7-W-22` names. Clause 3 joins on the serial and on any claim record rather than this device's, which #142 narrowed deliberately so that `device-claimed` stays reachable. An attacker holding the Operational CA key can therefore mint a certificate bearing an already-issued serial, as `E-7-08` does, and pass clause 3. `identifier-consistent` and `device-claimed` re-tighten what clause 3 stops enforcing, and the source comment says so. The claim is worth keeping and worth stating against a named adversary rather than absolutely.

## 6. Revoking the Factory identity

Section 8 says a stolen or hostile device "can have both its operational and Factory identities blocked by policy", and that revoking an operational identity "does not erase the persistent Factory identity". `T7-W-24` records that the Factory credential reopens the claim path forever, by design, and accepts it because that is what re-claim and recovery need.

The research establishes three things about what blocking it would mean.

The enforcement already exists and is untested. As section 1 showed, `revokedSerials()` and clause 2 are role-agnostic, and clause 2 runs before the Operational-only clause 3, so a Factory serial in `revoked.jsonl` would refuse that Factory certificate at `certificate-active` on every route including the claim endpoint. No command writes such a line and no test covers it. Tier 8 gets the enforcement for free and owes it an operation, an evidence row and a test.

Blocking it closes the recovery door, and that is the point rather than a bug. Section 8's recovery flow needs physical presence, the Factory identity and explicit service authorization. If the Factory identity is refused at `certificate-active`, recovery through it is impossible and the only remaining path is the authorized serial re-provisioning that section 8 already names, with no universal remote recovery credential. So blocking the Factory identity converts a recoverable device into one that needs a manufacturing station. That is the correct answer for a stolen device and a catastrophic one for a device blocked by mistake.

It is also irreversible as the record stands. `revoked.jsonl` is append-only with one field, and nothing reads a later line as cancelling an earlier one. Public PKI has the shape the course would need here, in RFC 5280's reversible `certificateHold` and the `removeFromCRL` value that lifts it, and the course has no equivalent. Tier 8 does not have to build a hold, and if it decides not to, the module should say that blocking a Factory identity is one-way rather than let a Learner discover it on a board they then cannot recover. This is the strongest argument found for giving the revocation record a state field rather than treating presence in a file as the whole of the state.

Blocking the identity and blocking the identifier are different operations. Blocking the Factory serial stops that certificate. Marking the identifier decommissioned stops any certificate for that device, including a newly issued one, which is what section 8's decommissioning subsection requires when it says old certificates and Bootstrap credentials must not be able to enroll it again. The first is keyed on a serial and the second on a device identifier. Azure's preview behavior described in section 4 is the same distinction shipped in a product, where revoking the certificate leaves the identity enabled and the device reconnects with a new one.

## 7. What this means for Tier 8, stated as facts rather than decisions

The revocation mechanism the course chose is the one real fleets use, and the module can say so with Microsoft's and AWS's own words rather than as a course simplification. #139's reasoning survives the research intact.

The gap is not a CRL. It is four things: an operation that writes status, a record shape richer than a bare serial, a device that reads the refusal it is already sent, and a statement of what a serial blocklist does not do.

The device can be told, and over HTTP it already is. Making the assignment path read the status before parsing the body is a small firmware change with a large teaching return, and it does not give the device a revocation client or a clock. The device would not be checking status. It would be reading an answer it already receives. That distinction is worth making explicitly in the module, because a reader who misses it will think the course reversed #139.

The honest counterweight is that the standards disagree about whether this is worth doing, and RFC 7009 says so in as many words: a revoked credential gets the same answer as an invalid one "since the client cannot handle such an error in a reasonable way". The course's answer is that a device's behavior and a fleet's diagnosability are different goods. The refused device stops and reports either way. What changes is whether the engineer holding the board can tell revocation from a broken release record, and Tier 7 measured that cost as half an hour of looking in the wrong file.

The renewal coupling runs in one direction: shorter certificates shrink the revocation window and enlarge the dependency on renewal working. Both halves need to be argued in the same place or the tier will look like it is contradicting itself.

## Sources

Primary sources read for this note. Repository files were read at commit `d1411d0`.

| Source | Used for |
| --- | --- |
| `services/ota/listeners.go`, `identity.go`, `provisioning.go` | The three clauses, the refusal shape, the check order, the serial set that never shrinks |
| `internal/courseapp/tier07.go`, `tier07_bypass.go`, `tier06.go` | `./course claim revoke`, `E-7-06`, the record shape, the six lifecycle states |
| `internal/coursepki/operational.go`, `pki.go` | Ninety-day lifetime, 128-bit random serials |
| `firmware/tier-07-operational-identity/src/ota_client.c`, `claim.c`, `prj.conf` | The three capture callbacks, the gate failure, `MBEDTLS_HAVE_TIME_DATE=n` |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) section 6.2 | `certificate_revoked` and the other alert descriptions |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) section 5.3.1 | `CRLReason` values, CRL time anchoring |
| [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html) | OCSP `revoked` status, `revocationTime`, the time fields |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) section 15.5.4 | 403 describing the reason for refusal |
| [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html) | Problem Details. `type` is branched on, `detail` is not parsed |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) section 3.1, [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html) section 5.2 | Revoked folded into `invalid_token` and `invalid_grant` |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) section 2.2 | Token revocation answers 200 either way, and says why |
| [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030.html), [RFC 8995](https://www.rfc-editor.org/rfc/rfc8995.html) | No server-to-client revocation signal in EST or BRSKI |
| [RFC 8739](https://www.rfc-editor.org/rfc/rfc8739.html) | Short-term certificates as the alternative to revocation checking |
| [Azure IoT Hub X.509 authentication](https://learn.microsoft.com/en-us/azure/iot-hub/authenticate-authorize-x509) | "IoT Hub doesn't check certificate revocation lists" |
| [Azure Device Registry certificate revocation](https://learn.microsoft.com/en-us/azure/iot/how-to-revoke-certificate-delete-policy) | Revoking the certificate leaves the identity enabled. Public preview |
| [AWS IoT `UpdateCertificate`](https://docs.aws.amazon.com/iot/latest/apireference/API_UpdateCertificate.html) | Certificate states, forced disconnect within minutes |
| [AWS IoT activate or deactivate a client certificate](https://docs.aws.amazon.com/iot/latest/developerguide/activate-or-deactivate-device-cert.html) | "AWS IoT verifies that a client certificate is active" |
| [AWS IoT custom client certificate validation](https://docs.aws.amazon.com/iot/latest/developerguide/customize-client-auth.html) | CRL and OCSP checking is a customer-built Lambda |
| [AWS IoT lifecycle events](https://docs.aws.amazon.com/iot/latest/developerguide/life-cycle-events.html) | `AUTH_ERROR`, `AUTHORIZATION_FAILED`, what the device is not told |
| [AWS Device Defender revoked certificate check](https://docs.aws.amazon.com/iot/latest/developerguide/audit-chk-revoked-device-cert.html) | The CA's CRL as an audit input |
| [smallstep revocation](https://smallstep.com/docs/step-ca/revocation/) | Passive revocation, and where it is not enough |
| [smallstep renewal](https://smallstep.com/docs/step-ca/renewal/) | Two-thirds renewal, jitter against a thundering herd |
| [Mbed TLS porting guide](https://mbed-tls.readthedocs.io/en/latest/kb/how-to/how-do-i-port-mbed-tls-to-a-new-environment-OS/) | "If time and date are not available, then this check is skipped" |
| [ESP-TLS](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/protocols/esp_tls.html) | Time validation needs SNTP, and the offline-expiry warning |
| [Golioth certificate rotation](https://blog.golioth.io/introducing-certificate-rotation-with-hosted-pki-providers/) | Short-lived certificates for devices. Vendor blog, not documentation |
| [Mender device authentication](https://docs.mender.io/overview/device-authentication) | Authentication sets, no PKI revocation documented |

## What could not be established

No first-party SPIFFE or SPIRE documentation page states a deliberate "no CRL because SVIDs are short-lived" policy. The X509-SVID standard is silent on revocation. The behavior is visible in SPIRE's rotation defaults and in maintainer discussion, which is weaker sourcing than the rest of this note, so SPIFFE is not used as evidence here.

No AWS document says in those words that AWS IoT Core publishes no CRL for device certificates. It is inferred from the Device Defender check treating the CRL as belonging to the CA rather than to AWS, and from CRL checking being a customer-built Lambda.

RFC 5280 states the CRL freshness requirement less crisply than RFC 6960 states the OCSP one. The `nextUpdate` quote from section 5.1.2.5 is verified. A further passage in section 3.3 about acquiring a "suitably recent" CRL and leaving the meaning to local policy was not verified against the text directly, so it is not quoted or relied on here.

RFC 8446 contains no articulated guidance that a server should deliberately obscure which certificate alert it sends. Section 3 says so explicitly rather than implying one, because the difference matters: the alert is unreliable by construction, not by design intent.

hawkBit has no revocation documentation page. The conclusion that its model is server-side token deactivation is drawn from the absence of one plus its documented token authentication, and is weaker than the AWS and Azure statements.

Whether the status-blind routes should be repaired in the published Tier 7 image, or only in `firmware/tier-08`, is a decision and not a fact. #213 owns it. This note establishes only which routes are affected: three read neither the status nor the reason, one reads the status and discards the reason, and the image route is caught by a size check rather than by an authorization one.
