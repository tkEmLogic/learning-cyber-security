# Whether a device-side notion of certificate validity is reachable on this board

**Research question:** [GitHub issue #210](https://github.com/tkEmLogic/learning-cyber-security/issues/210), part of map [#203](https://github.com/tkEmLogic/learning-cyber-security/issues/203)

**Access and review date:** 22 September 2026

**Status:** Research, not design. Whether Tier 8 builds any of this is issue [#217](https://github.com/tkEmLogic/learning-cyber-security/issues/217) and is deliberately not settled here. Every claim about the build is read from the pinned Zephyr 4.4.2 tree, from the Mbed TLS and TF-PSA-Crypto modules that tree pins, or from the source in this repository. Nothing here was run on the board, and no build was performed, so no byte cost is stated.

## Short answer

A trusted wall clock is not reachable in this course, and nothing in the pinned tree has changed that since Tier 7 judged it three days ago.

A **bounded, monotonic, device-side floor on time** is reachable, and it is cheaper than Tier 7's note suggests. Mbed TLS compiles `mbedtls_x509_time_cmp()` unconditionally and parses `valid_from` and `valid_to` into every certificate it parses whether `CONFIG_MBEDTLS_HAVE_TIME_DATE` is on or off. The comparison is already in the image. The only missing input is a value for "now", and the course already carries one: `created_at` inside the signed release manifest, authenticated by the offline release verification key compiled into the image rather than by any certificate with a validity window.

That matters for one specific clause. `T7-W-20` asserts that a device cut off from the service cannot know it has lost authorization. With a monotonic floor persisted in NVS, a cut-off device **can** know, for any credential that expired before the last floor it learned. It still cannot know about a credential that expired after that point, and it still learns nothing about revocation. So the clause is not a permanent truth; it is a consequence of a control the course has not built.

`T2-W-09` is different and harder. It is about a certificate the device is *shown*, and a floor catches only a certificate that expired long ago, not one that expired last week. `T2-W-09` cannot be closed without a real clock.

## What Tier 7 already settled, and what it did not cover

The authenticated-time note lives in [`research/course-readings.md`](https://github.com/tkEmLogic/learning-cyber-security/blob/main/research/course-readings.md) under the heading "Note: why the device has no authenticated time", inside the Tier 7 reading section. It was added on 19 September 2026 in commit `0593124` under issue #161, three days before this report.

The note establishes four things, and all four hold. The device cannot be handed the time by the OTA service, because section 6 treats that service as untrusted and a bare timestamp is not a byte string the device can verify. Taking the time from the party whose certificate is about to be validated is circular, because that party then chooses a moment at which its own certificate passes. Plain SNTP carries no authentication, so it moves the decision to whoever answers first on the classroom network. NTS (RFC 8915) and Roughtime both answer the problem and both were ruled out of scope.

Five things the note does not cover, and this report adds them. It does not say what `CONFIG_MBEDTLS_HAVE_TIME_DATE` expands to in this tree or what the failure mode actually is. It does not notice that the comparison primitive is compiled regardless of the option, so only "now" is missing. It does not cite RFC 8915's own admission of the circularity in section 8.5, nor the mitigation that section recommends, which is a monotonic floor in persistent storage. It does not cite RFC 8995 section 2.6.1, which is already in the Tier 7 reading list and is the standard's own answer for a device with no clock. And it does not evaluate any non-clock alternative, because Tier 7 had no lifecycle operation that needed one.

## Versions, and where they were read

The Zephyr workspace is **not** on the host at `/opt/zephyr-workspace`. It lives at that path inside the long-lived podman container `tier2-validate`. Every path below prefixed `/opt/zephyr-workspace` was read with `podman exec tier2-validate ...`.

| Component | Version | How it was confirmed |
| --- | --- | --- |
| Zephyr | 4.4.2 | `git -C /opt/zephyr-workspace/zephyr describe --tags` prints `v4.4.2` at commit `dccb09599635bdff17633fa7e9dab014b91dce90`, and `zephyr/VERSION` reads major 4, minor 4, patchlevel 2. |
| Mbed TLS | 4.1.0 | `modules/crypto/mbedtls/include/mbedtls/build_info.h` line 39 defines `MBEDTLS_VERSION_STRING "4.1.0"`. The module checkout is commit `a3e190fe44c78d1ba67f55979e1257328cc7d0d8`. |
| TF-PSA-Crypto | 1.1.0 | `modules/crypto/tf-psa-crypto/include/tf-psa-crypto/build_info.h` line 37 defines `TF_PSA_CRYPTO_VERSION_STRING "1.1.0"`. |
| Board target | `esp32c6_devkitc/esp32c6/hpcore` | The only ESP32-C6 board directory in the tree is `zephyr/boards/espressif/esp32c6_devkitc`. |

**Nothing has changed.** This is the same commit of the same tree that Tier 7 built against. The question "whether anything in the pinned versions now makes device-side validity checking cheaper" has a plain answer: the tree is identical, so nothing in it has changed. What has changed is what was read out of it, which is section 1 below.

## 1. What CONFIG_MBEDTLS_HAVE_TIME_DATE actually pulls in

### The option expands to three macros and nothing else

`zephyr/modules/mbedtls/configs/config-tf-psa-crypto.h` lines 53 to 57:

```c
#if defined(CONFIG_MBEDTLS_HAVE_TIME_DATE)
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_MS_TIME_ALT
#endif
```

`MBEDTLS_PLATFORM_MS_TIME_ALT` is already satisfied. `zephyr/modules/mbedtls/zephyr_init.c` lines 73 to 76 implement `mbedtls_ms_time()` as `(mbedtls_ms_time_t)k_uptime_get()`, which is a monotonic uptime value and not a wall clock. That function is used by `tf-psa-crypto/core/psa_crypto_random.c` line 106 to personalise the DRBG, and it has nothing to do with certificate dates.

The Kconfig help text states the requirement plainly. `zephyr/modules/mbedtls/Kconfig.mbedtls` lines 182 to 188:

```
config MBEDTLS_HAVE_TIME_DATE
	bool "Date/time validation in mbed TLS"
	help
	  System has time.h, time(), and an implementation for gmtime_r().
	  There also need to be a valid time source in the system, as mbedTLS
	  expects a valid date/time for certificate validation.
```

### The build already warns that the option is off

`zephyr/modules/mbedtls/CMakeLists.txt` lines 103 to 112 emit a CMake warning whenever TLS 1.2 or TLS 1.3 is enabled and `CONFIG_MBEDTLS_HAVE_TIME_DATE` is not: "The option CONFIG_MBEDTLS_HAVE_TIME_DATE is required for proper certificate validation. If it is not enabled, certificates will not be checked for expiration or validity dates, which may lead to security vulnerabilities."

Every course build from Tier 2 onward therefore already prints this warning. It is upstream Zephyr's own text and it is the single most quotable sentence in the tree for teaching `T2-W-09`.

### Where "now" would come from, and why it reads 1970

With the option on, `mbedtls_time` resolves to the plain libc `time`. `tf-psa-crypto/include/mbedtls/platform_time.h` lines 56 to 73 select between three forms, and neither `MBEDTLS_PLATFORM_TIME_ALT` nor `MBEDTLS_PLATFORM_TIME_MACRO` is defined anywhere in the Zephyr configuration headers, so the `#define mbedtls_time time` branch is taken. There is no Kconfig knob in this tree that would let an application substitute its own time function through `mbedtls_platform_set_time()`.

`zephyr/lib/libc/common/source/time/time.c` implements `time()` as `sys_clock_gettime(SYS_CLOCK_REALTIME, &ts)` and returns `ts.tv_sec`.

`zephyr/lib/os/clock.c` implements that clock as uptime plus a stored offset. Its comment at lines 20 to 26 says `k_uptime_get()` is an always-increasing value from system start and that `rt_clock_offset` "records the time that the system was started", which "can either be set via 'sys_clock_settime', or could be set from a real time clock, if such hardware is present". Lines 76 to 89 compute `SYS_CLOCK_REALTIME` as `timespec_from_ticks(k_uptime_ticks(), ts)` plus that offset. The offset is a file-scope `static struct timespec` at line 27, so it is zero until something sets it, and nothing in the course firmware calls `sys_clock_settime()` or `clock_settime()`. Section 2 establishes that there is no real-time-clock hardware driver for this part either.

So with the option on and no time source, "now" is 1 January 1970 plus seconds since boot.

### The failure mode is "not yet valid", not "expired"

`modules/crypto/mbedtls/library/x509_crt.c` line 2499 declares `mbedtls_x509_time now`, line 2502 fills it with `mbedtls_x509_time_gmtime(mbedtls_time(NULL), &now)` and bails out of verification if that fails, and lines 2536 to 2545 are the whole of the date decision:

```c
#if defined(MBEDTLS_HAVE_TIME_DATE)
        /* Check time-validity (all certificates) */
        if (mbedtls_x509_time_cmp(&child->valid_to, &now) < 0) {
            *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
        }

        if (mbedtls_x509_time_cmp(&child->valid_from, &now) > 0) {
            *flags |= MBEDTLS_X509_BADCERT_FUTURE;
        }
#endif
```

With "now" in 1970 and a course certificate whose `notBefore` is in 2026, the second comparison fires and the first does not. Every certificate is flagged `MBEDTLS_X509_BADCERT_FUTURE` and every handshake fails, forever, with no path out that does not involve setting the clock first. This confirms the comment in `firmware/tier-07-operational-identity/prj.conf` lines 100 to 110 exactly, with one refinement worth carrying into any teaching text: the refusal reason a Learner would see is "not yet valid", not "expired".

### With the option off, the two predicates are hardwired to zero

`modules/crypto/mbedtls/library/x509.c` lines 1169 to 1181:

```c
#else  /* MBEDTLS_HAVE_TIME_DATE */

int mbedtls_x509_time_is_past(const mbedtls_x509_time *to)
{
    ((void) to);
    return 0;
}

int mbedtls_x509_time_is_future(const mbedtls_x509_time *from)
{
    ((void) from);
    return 0;
}
#endif /* MBEDTLS_HAVE_TIME_DATE */
```

Nothing is silently approximated. The library states that it does not know, by answering "not past" and "not future" to every question.

### The finding Tier 7's note missed: the comparison is already compiled in

Two things in that same file and header are **not** behind the option.

`mbedtls_x509_time_cmp()` is compiled unconditionally at `x509.c` lines 1108 to 1122, and it is declared unconditionally at `include/mbedtls/x509.h` line 389. It compares two `mbedtls_x509_time` values by packing year, month, day and then hour, minute, second into integers and subtracting. It needs no clock, no libc time and no `gmtime_r`.

`valid_from` and `valid_to` are parsed into every certificate regardless. `include/mbedtls/x509_crt.h` lines 56 and 57 declare them as ordinary members of `mbedtls_x509_crt`, and the course firmware already populates them: `firmware/tier-07-operational-identity/src/identity.c` calls `mbedtls_x509_crt_parse_der()` at lines 228, 261, 588 and 785 to read subject fields out of the Factory and Operational certificates it holds.

So a device-side validity comparison against **any** value the device is willing to call "now" costs no new Kconfig symbol, no new library code and no clock. `CONFIG_MBEDTLS_HAVE_TIME_DATE` buys one thing only: it wires the comparison into the TLS chain verification automatically, using libc `time()` as the source. An application that has its own notion of "now" does not need the option at all, and turning the option on without a time source is strictly worse than leaving it off.

The one library cost the option does add is the civil-calendar conversion. `tf-psa-crypto/platform/platform_util.c` lines 157 to 192 implement `mbedtls_platform_gmtime_r()` as a direct call to libc `gmtime_r()` on this platform, and that whole function is itself compiled only when `MBEDTLS_HAVE_TIME_DATE` is defined, which pulls that function and its tables into the image. No byte figure is given here because no twin build was run.

## 2. What this board has instead of a clock

There is no real-time-clock device driver for Espressif in the pinned tree. `zephyr/drivers/rtc/` holds 82 entries and none of them is an Espressif part.

There is a counter. `zephyr/dts/riscv/espressif/esp32c6/esp32c6_common.dtsi` lines 231 to 235 declare a node `rtc_timer@600b0c00` with compatible `espressif,esp32-rtc-timer`. Its binding is filed under `dts/bindings/counter/` and its driver is `zephyr/drivers/counter/counter_esp32_rtc.c`, enabled by `CONFIG_COUNTER_RTC_ESP32`, which defaults to `y`. The driver reports `max_top_value = UINT32_MAX`, so it is a 32-bit counter.

The binding text is the interesting part, quoted in full from `dts/bindings/counter/espressif,esp32-rtc-timer.yaml`:

> ESP32 Counter Driver based on RTC Main Timer.
>
> Any reset/sleep mode, except for the power-up reset, will not stop or reset the RTC Timer. This behavior may be handy when supporting applications that need to keep a timing baseline on such situations.
>
> There is also no need to enable the RTC Timer node, it starts running from power-up.

So the board can measure elapsed time across a software reboot or a sleep, but not across a power cycle, and it can never say what time it is. Whether the DevKitC-1 exposes any battery-backed supply that would change this is **not established** in this report.

Zephyr does ship an SNTP client, at `zephyr/subsys/net/lib/sntp/`, behind `menuconfig SNTP`. Its public header `include/zephyr/net/sntp.h` contains no authentication of any kind, no key identifier and no message authentication code. A grep of the whole Zephyr tree for Roughtime, Network Time Security, RFC 8915 and RFC 9769 returns nothing. Either protocol would be new code written inside the course.

## 3. Why authenticated time is hard, stated precisely enough to teach

### The circularity, named exactly

Call it the **validity-window bootstrap circularity**. It has three steps and the third is the one that closes the loop.

To decide whether a certificate is inside its validity window, the device needs a trusted value for the current time.

Every channel that can deliver a trusted current time is itself authenticated, and in practice it is authenticated by a certificate, which has its own validity window.

Checking that second window needs a trusted current time. The device needs the answer in order to obtain the answer.

There is a second, narrower circle which is the one an attacker actually walks. If the time comes from the same party whose certificate is being validated, that party chooses the time, and it will choose a moment at which the certificate it holds is still valid. The check then passes every time, for any certificate, including one that was revoked or that expired years ago. This is the circle Tier 7's note names, and it is a special case of the first.

The escape from the outer circle is always the same shape, and it is worth teaching as a shape rather than as a list of protocols. Trust has to enter through a channel whose validity does not itself depend on a time. There are exactly three such channels in this course: a raw public key compiled into a signed firmware image, a nonce the device generated itself, and a human standing at the board. Every workable answer below is built from one of those three.

### The standard admits the circularity in its own words

RFC 8915, Network Time Security, section 8.5, "Initial Verification of Server Certificates":

> NTS's security goals are undermined if the client fails to verify that the X.509 certificate chain presented by the NTS-KE server is valid and rooted in a trusted certificate authority. RFC 5280 [RFC5280] and RFC 6125 [RFC6125] specify how such verification is to be performed in general. However, the expectation that the client does not yet have a correctly-set system clock at the time of certificate verification presents difficulties with verifying that the certificate is within its validity period, i.e., that the current time lies between the times specified in the certificate's notBefore and notAfter fields. It may be operationally necessary in some cases for a client to accept a certificate that appears to be expired or not yet valid. While there is no perfect solution to this problem, there are several mitigations the client can implement to make it more difficult for an adversary to successfully present an expired certificate:

This is the sentence to teach from. A standards-track RFC whose entire purpose is authenticated time says there is no perfect solution, and that a client may operationally have to accept a certificate that appears expired.

The third mitigation it then lists is the one this report builds on:

> Once the clock has been synchronized, periodically write the current system time to persistent storage. Do not accept any certificate whose notAfter field is earlier than the last recorded time.

That is a monotonic floor in non-volatile storage, recommended by a normative RFC, and it needs no clock to enforce once the floor exists.

### SNTP is an attacker input, not a time source

Zephyr's SNTP client has no authentication, as established in section 2. An SNTP answer is a UDP datagram from whoever replies first. That is precisely the attacker Tier 0 and Tier 2 already teach, the one on the classroom network who reads and rewrites traffic, and a device that trusts an SNTP reply has handed that attacker the power to make any certificate valid or invalid at will. This is not a weakness in Zephyr's client; RFC 4330 SNTP has no security mechanism to implement.

### NTS moves the problem, and brings two more

NTS-KE runs over TLS and requires ordinary certificate validation. RFC 8915 section 3 requires conformance to BCP 195 and requires implementations to "follow the rules in RFC 5280 and RFC 6125 for the representation and verification of the application's service identity". So an NTS client needs its own trust anchor, installed out of band, and that anchor's own certificate has its own expiry. The circularity is not broken, it is relocated to a party the device was not already talking to.

Two residual attacks survive even a correct NTS client, and both are worth a sentence in any module that mentions NTS. Section 8.6, the delay attack: "an adversary with the ability to act as a man-in-the-middle delays time synchronization packets between client and server asymmetrically", and "cryptographic means do not provide a feasible way to mitigate this attack. However, the maximum error that an adversary can introduce is bounded by half of the round-trip delay." Section 8.7, NTS stripping: "Implementations SHOULD NOT revert from NTS-protected to unprotected NTP with any server without explicit user action."

Cost here: a full NTS client, written from scratch, for a course whose subject is not time.

### Roughtime is not yet an RFC and needs a trust list the draft declines to define

The current document is draft-ietf-ntp-roughtime-19, dated 17 March 2026. It is an active Internet-Draft of the NTP working group, intended status Experimental, submitted to the IESG and in the RFC Editor queue with status "In Final Review". It is **not** an RFC as of 22 September 2026, and its final RFC number is not established.

Its design goal is exactly the clockless case: "secure rough time synchronization even for clients without any idea of what time it is". It achieves that by having the client query several independent servers, chaining each query's nonce to the previous response so the answers are causally ordered, and checking the responses for mutual consistency. Section 8.2 states the check: for each pair of responses received in order, the client "MUST check that `MIDP_i-RADI_i` is less than or equal to `MIDP_j+RADI_j`", and "if at least one check fails, there has been a malfeasance".

The cost is in the configuration. Section 8.1 requires "a list of servers, a minimum of three of which are operational and not run by the same parties", and section 1 describes the configuration as "a list of servers and their associated long-term keys, which ideally remain unchanged throughout a server's lifetime". The draft states no rotation or revocation mechanism for those long-term keys, and section 9.6 explicitly hands the trust problem back to the operator:

> The infrastructure and procedures for maintaining a list of trusted servers and adjudicating violations of the rules by servers is not discussed in this document and is essential for security.

So Roughtime exchanges a certificate-validity problem for a raw-public-key distribution problem with no defined revocation story, and a requirement for three independently operated servers that a classroom lab on an isolated network does not have. It does not solve the course's problem; it replaces it with a different one.

## 4. The bounded alternatives that are not a clock

### 4.1 A monotonic counter

**The ticket's premise is wrong on one point, and it matters.** Tier 4's security counter is not persistent device state and the repository says so in its own words. `firmware/tier-04-release-policy/bootloader/mcuboot.conf` lines 45 to 49:

```
# Nothing is remembered. The reference value lives in the same flash an
# attacker would be attacking, which is exactly what section 6 means by
# "software downgrade prevention, because a physical attacker can rewrite boot
# state". Never say this device remembers a counter, and never call it
# monotonic on this part.
```

MCUboot compares the candidate image's `IMAGE_TLV_SEC_CNT` against the counter in the image already in the primary slot, and the application compares a manifest's counter against `CONFIG_COURSE_SECURITY_COUNTER`, a build-time integer defaulting to 1 (`firmware/tier-04-release-policy/Kconfig` lines 46 to 53, and `src/release_policy.c` line 388). Hardware rollback protection is off, because `boot_nv_security_counter_get` and `_update` are implemented nowhere in the Zephyr port and enabling them fails at link, verified under issue #66. So there is no monotonic counter on this device today, and Tier 8 cannot inherit one.

What the course does have is persistent storage. `recovery_state.c` writes through NVS at line 122 of the Tier 6 and Tier 7 copies, `identity.c` stores certificates through the settings subsystem at lines 595 and 865, and Tier 6 stores keys through PSA ITS. A monotonic counter would be new code on storage that already exists and is already shared carefully, which Tier 6 learned the hard way when two NVS instances landed on the same bytes.

**What a counter buys.** Ordering. A counter can express "this credential generation supersedes that one" and "state may not go backwards", and it can be checked with no clock and no network.

**What it does not buy.** Duration. A counter says nothing about elapsed time, because it moves only when something makes it move.

**Cut-off notice: no.** A device with no contact has nothing to advance the counter, so the counter cannot tell it that time has passed. On its own, a counter is the wrong tool for expiry. Combined with a signed time value it becomes the right one, which is section 4.3.

### 4.2 A freshness value the service supplies

**Mechanism.** The device generates a nonce, sends it, and requires the answer to be bound to that nonce. The answer then demonstrably postdates the moment the device invented the nonce, whatever either party believes the date to be.

This is the standard's own answer for a clockless device. RFC 8995, BRSKI, section 2.6.1, "Lack of Real-Time Clock", quoted in full:

> When bootstrapping, many devices do not have knowledge of the current time. Mechanisms such as Network Time Protocols cannot be secured until bootstrapping is complete. Therefore, bootstrapping is defined with a framework that does not require knowledge of the current time. A pledge MAY ignore all time stamps in the voucher and in the certificate validity periods if it does not know the current time.
>
> The pledge is exposed to dates in the following five places: registrar certificate notBefore, registrar certificate notAfter, voucher created-on, and voucher expires-on. Additionally, Cryptographic Message Syntax (CMS) signatures contain a signingTime.
>
> A pledge with a real-time clock in which it has confidence MUST check the above time fields in all certificates and signatures that it processes.
>
> If the voucher contains a nonce, then the pledge MUST confirm the nonce matches the original pledge voucher-request. This ensures the voucher is fresh. See Section 5.2.

Two sentences there are directly quotable in a Tier 8 module. A clockless pledge **MAY ignore all timestamps**, and freshness is then carried by a nonce instead. This is not a compromise the course invented; it is BRSKI's design, and BRSKI is already a recommended reading at Tier 7.

**What it buys.** Liveness. It answers "is this authorization current, right now" — which is, in fact, the question authorization asks.

**What it does not buy.** Anything about a moment when the device is not talking to anybody. A nonce cannot be answered by an absent service.

**Cut-off notice: no, and structurally no.** This alternative is defined by contact with the service. It is the opposite of what a cut-off device needs.

**Cost here: already paid, twice over.** The course has the nonce shape in two places. Tier 6's `sharedRegistrationNonce()` is 32 station-generated random bytes, one-shot, never stored. Tier 7's claim nonce is device-generated, human-transcribed and replay-tracked by the service. More to the point, the Tier 7 design already has the strongest possible freshness signal: the mutual TLS handshake itself. Every successful connection proves that the service, at that moment, regarded this device's Operational certificate as active, because `services/ota/listeners.go` lines 292 to 303 check `NotAfter` and `NotBefore` against the service's own clock on every request and refuse with `certificate-active` and a named reason. There is nothing left to add here. The gap this alternative cannot close is the only gap that remains.

### 4.3 A signed timestamp in an update assignment

**This is the one that changes something, and the course already carries the value.**

Every release manifest is signed over its exact bytes with the offline release verification key, and every manifest contains two date fields. `artifacts/generated/releases/tier-07-operational-identity.manifest.json` lines 13 and 14 carry `created_at` and `supported_until`. The firmware already parses them. `firmware/tier-04-release-policy/src/release_policy.h` lines 48 to 53 declare them and state the current position:

```c
	/* Carried, signed, and never acted on. This device has no clock, and
	 * every time source it can reach is controlled by something Tier 4
	 * assumes hostile. Signing these means they cannot be edited after the
	 * fact; it does not mean the device can check them. Tier 9 consumes
	 * them. See the Weakness ledger beside T2-W-09.
	 */
```

That comment is right that the device cannot *check* them. It is too strong in one respect, and the distinction is the whole finding. The device cannot use `created_at` as the current time, because a compromised service can withhold new manifests and hold the value arbitrarily far in the past. But `created_at` is a valid **lower bound**: whatever the real time is, it is at least `created_at`, because this manifest existed and was signed. And a lower bound is exactly what expiry detection needs, because expiry is the question "is now already past `notAfter`".

The trust here does not travel through any certificate. The manifest's signature is checked against the release verification key compiled into the signed firmware image. That is the first of the three escape channels named in section 3: a raw public key inside a signed image, with no validity window to check. The circularity does not apply.

**What it buys.** A monotonic, authenticated floor under the current time, maintained as `floor = max(floor, created_at of every manifest whose signature verified)`, persisted in NVS. Then, with the comparison primitive that is already compiled in, the device can refuse any certificate whose `valid_to` is below the floor — including its own. This is RFC 8915 section 8.5's third mitigation, with a signed manifest standing in for a synchronised clock.

**What it does not buy.** An upper bound, which means no notion of "not yet valid" and no protection against a certificate that has *just* expired. The floor's staleness grows exactly with time since the last update, so the devices most likely to hold a dead credential are the ones whose floor is furthest behind. And it is silent on revocation: a certificate revoked well inside its validity window is indistinguishable from a live one under any floor.

**Cut-off notice: yes, partially, and this is the report's main finding.** A device disconnected today, holding an Operational certificate whose `notAfter` has already passed the last floor it stored, can conclude on its own that it has lost authorization, with no network and no clock. That is the last clause of `T7-W-20`, and it is reachable. A device whose credential expires *after* the last floor still cannot know.

**Cost here.** Three small pieces, and no new dependency. The manifest fields are parsed already. The device's own certificate's `valid_to` is parsed already, into the `mbedtls_x509_crt` that `identity.c` builds at lines 261, 588 and 785. `mbedtls_x509_time_cmp()` is compiled already, as section 1 established, independent of `CONFIG_MBEDTLS_HAVE_TIME_DATE`. What is new is parsing the RFC 3339 `created_at` string into an `mbedtls_x509_time` or an equivalent comparable form, persisting the floor monotonically in the NVS instance Tier 6 and Tier 7 share, and one comparison with a refusal that names itself. No Kconfig symbol changes, no clock, no new library, and no CMake warning is silenced.

One consequence to state plainly: the same floor could be seeded at build time. The firmware image is itself signed, so a release timestamp compiled into it is a signed lower bound available at the very first boot, before any network. That makes a floor available even to a device that has never received an update, which is otherwise the case with no floor at all.

### 4.4 k_timer

**Mechanism.** `firmware/tier-07-operational-identity/src/claim.c` defines `K_TIMER_DEFINE(window_timer, window_timer_expired, NULL)` at line 123, starts it at line 250 with `K_SECONDS(CONFIG_COURSE_CLAIM_WINDOW_SECONDS)`, prints the remaining seconds from `k_timer_remaining_get()` at line 280, and stops it at lines 127 and 432. The Kconfig at `firmware/tier-07-operational-identity/Kconfig` lines 344 to 352 sets the default to 600 seconds with a range of 60 to 3600, and its help text says "The device times this itself with a k_timer and closes its own window by destroying the nonce and the pending Operational key."

The doctrine is already written down, at `claim.c` lines 297 to 302. The service sends `claim_window_expires_at` and `not_after` and the device parses neither, because "the two time fields are the service's clock, and this device has no wall clock to compare them against; its own k_timer closes its own window and that is the only duration it is entitled to act on." That sentence is the best short statement of the rule in the repository and Tier 8 should reuse it rather than reinvent it.

**What it buys.** A bounded duration measured from an event the device itself caused. It cannot be lengthened or shortened over the network, which is why a ten-minute claim window is trustworthy in a way that a ten-minute deadline announced by the service is not.

**What it does not buy.** Any absolute instant, and nothing that survives a reboot. `k_timer` is driven by the kernel uptime clock, which restarts at zero on every boot. A device that reboots weekly never accumulates the 90 days that `internal/coursepki/operational.go` line 59 gives an Operational certificate. For the claim window this loss is in the safe direction, because a reboot destroys the pending key and the window with it. For a credential lifetime it is simply unusable.

**Cut-off notice: no**, except for windows the device opened itself and is still awake for.

**A nuance worth teaching.** The distinction between "uptime" and "elapsed real time" is visible on this exact part. The ESP32 RTC counter of section 2 survives every reset and sleep except a power-up reset, so a warm-reboot-surviving duration is reachable on this board while a power-cycle-surviving one is not without writing to flash. That is a concrete, board-level illustration of why duration and time are different problems.

### 4.5 Summary of the four

| Alternative | Buys | Does not buy | Cut-off notice | New code needed here |
| --- | --- | --- | --- | --- |
| Monotonic counter | Ordering, supersession, no-going-backwards | Duration, any date | No | A counter, in NVS. Tier 4's security counter is not one and cannot be reused. |
| Service-supplied freshness value | Liveness of a live answer | Any statement while offline | No, structurally | None. Mutual TLS plus `certificate-active` already does this. |
| Signed timestamp in an assignment | A monotonic authenticated lower bound on now | An upper bound; revocation; recency | **Yes, for credentials that died before the last floor** | Parse `created_at`, persist a floor, one comparison. No new dependency. |
| `k_timer` | A bounded duration from a self-caused event | Absolute time; anything across a reboot | No | None. Tier 7 already has it. |
| Full clock (`HAVE_TIME_DATE` plus a time source) | Everything, including "not yet valid" | Nothing, but requires an authenticated time source that does not exist here | Yes | An NTS or Roughtime client, written from scratch, plus a trust anchor with its own expiry. |

## 5. What a device is supposed to do when its credential is dead

The course specification already answers most of this, and the answer is neither "fail every request" nor "carry on as if valid".

Section 8, "Rotation and renewal", is explicit about the failure path: "If routine renewal fails, the device keeps its current valid identity, reports the failure, and retries with bounded backoff." The same subsection says Operational certificates "are renewed before expiry", that "the old and new certificates overlap for a bounded period", and that "the device proves the new identity works before the old certificate is revoked".

Section 8, "Revocation", settles the revocation-client question at specification level rather than merely at map level: "The course uses server-side certificate status for device credentials and does not require the constrained device to operate a full public PKI revocation client." Two clauses of `T7-W-20` — no CRL and no OCSP — are therefore a documented scope boundary and not an accidental debt.

Section 8, "Recovery", gives the fallback: loss or corruption of the Operational identity "requires physical presence, the Factory identity, and explicit service authorization to open a recovery claim window", and if neither identity can be trusted "the device is decommissioned rather than silently admitted with a shared secret".

Section 7 gives the availability rule: "normal reference-product behavior continues while no valid update is ready." And section 3 lists "device availability and recovery access" among the assets the course protects, which means a device that bricks itself on discovering a dead credential has attacked an asset its own threat model names.

Standard practice outside the course agrees, from three directions.

RFC 7030, EST, section 2.3: a client "can renew/rekey its existing client certificate by submitting a re-enrollment request to an EST server", and where the current certificate cannot be used for TLS client authentication, "any of the authentication methods used for initial enrollment can be used". Translated into this course's vocabulary, the fallback from a dead Operational identity is the credential that did the initial enrollment, which is the Factory identity. It is worth recording an absence as well: RFC 7030 does not address expired certificates, clock accuracy, or validity checking by constrained clients. It assumes renewal happens in time.

NIST SP 800-57 Part 1 Revision 5 distinguishes dead from destroyed, and the distinction is exactly the right one to teach. Section 7.4, Deactivated State: "Keys in the deactivated state shall not be used to apply cryptographic protection but, in some cases, may be used to process cryptographically protected information. If the key has been revoked (i.e., for reasons other than a compromise), then the key may continue to be used for processing." Section 7.5, Compromised State: "A compromised key shall not be used to apply cryptographic protection to information." Section 7.6 notes that even a destroyed key's metadata "may be retained for audit purposes". The asymmetry is: stop applying new protection, keep processing what is already protected, keep the record.

RFC 8995 section 2.6.1, quoted in full in section 4.2 above, permits a clockless pledge to ignore every timestamp and substitute nonce freshness.

**Synthesis, as a rule a module could state.** On learning that its credential is dead, a device stops using that credential to authenticate anything new, keeps performing the product function that does not depend on it, reports the fact through whatever channel it still has, and routes recovery through a credential that is not the dead one — here, the Factory identity, behind physical presence. It does not brick, it does not fall back to a shared secret, and it does not keep presenting the dead credential as though it were live.

**One consequence for the decision ticket.** Section 8 requires renewal "before expiry". A device that cannot evaluate its own validity window cannot know when "before" is. Today that is consistent, because nothing in the course renews. Tier 8 has to resolve it one of two ways: renewal is service-triggered, so the assignment tells the device to renew and the device never reasons about dates; or the device gets the floor of section 4.3 and can reason about its own expiry. That choice belongs to #217, but the specification's wording presumes an ability the device does not have, and one of the two readings will need an amendment.

## 6. What is not established

No byte cost. No build was run, so the ROM and RAM delta of enabling `CONFIG_MBEDTLS_HAVE_TIME_DATE`, or of a floor module, is unknown. The only firm statement is which symbols and functions are pulled in, in section 1.

No board observation. The claim that a clock reading 1970 makes every handshake fail with `BADCERT_FUTURE` is read from source and is internally consistent across four files, but it has not been observed on hardware. The repository's own rule is that firmware defects hide in the source and show on the device.

Whether the ESP32-C6-DevKitC-1 exposes a battery-backed supply that would let the RTC counter survive a power cycle. Section 2 quotes only what the binding says.

Roughtime's final RFC number and publication date. The draft was in the RFC Editor queue on 22 September 2026.

Whether teaching any of this fits Tier 8's time budget. Tier 7 spent 13,511 words on one transition, and this map already carries five.

## 7. What this means for the two ledger rows

Reported, not decided. The disposition is #217's.

`T2-W-09` — the device checks no dates on a certificate it is *shown*. A floor reduces this row and cannot close it. An expired-long-ago server certificate would be caught; one that expired last week would not, and a certificate that is not yet valid would never be caught, because a floor has no upper bound. Closing this row needs a real clock, which needs an authenticated time source, which this course does not have and section 3 explains why.

`T7-W-20` — authorization lifetime is enforced only by the service. The row has three clauses and they have different fates. No CRL and no OCSP is settled scope, stated in section 8 of the specification, and the honest disposition is "transferred to the service by design" rather than "open". The device cannot evaluate its own certificate's validity window is reducible: the device holds the certificate, the certificate's `valid_to` is already parsed, and the comparison is already compiled in. And a device cut off from the service cannot know it has lost authorization is **not** a permanent truth. It is reachable for any credential that expired before the last signed timestamp the device saw, at the cost described in section 4.3.

## Source register

| Source | Type | What was taken from it |
| --- | --- | --- |
| [RFC 8915, Network Time Security](https://www.rfc-editor.org/rfc/rfc8915.html) | Normative, standards track | Section 3 on TLS and certificate validation, section 8.5 on the circularity and its mitigations including the persistent floor, section 8.6 on the delay attack, section 8.7 on NTS stripping. Read as plain text from `rfc-editor.org`. |
| [RFC 8995, BRSKI](https://www.rfc-editor.org/rfc/rfc8995.html) | Normative, standards track | Section 2.6.1, "Lack of Real-Time Clock", quoted in full. Read as plain text from `rfc-editor.org`. |
| [draft-ietf-ntp-roughtime-19](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/) | Internet-Draft, Experimental, in RFC Editor final review on 22 September 2026 | Section 1 on the clockless design goal and long-term keys, section 8.1 on necessary configuration, section 8.2 on the consistency check, section 9.6 on the undefined trust infrastructure. |
| [RFC 7030, EST](https://www.rfc-editor.org/rfc/rfc7030.txt) | Normative, standards track | Sections 2.3 and 4.2.2 on renewal, rekey and fallback to the initial enrollment credential, and the established absence of any text on expired certificates or clockless clients. |
| [NIST SP 800-57 Part 1 Revision 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) | Normative guidance | Sections 7.3 to 7.6 on the suspended, deactivated, compromised and destroyed key states, and the apply-new versus process-old asymmetry. |
| Zephyr 4.4.2 at commit `dccb0959963`, inside container `tier2-validate` | Pinned source | `modules/mbedtls/Kconfig.mbedtls`, `modules/mbedtls/CMakeLists.txt`, `modules/mbedtls/configs/config-tf-psa-crypto.h`, `modules/mbedtls/zephyr_init.c`, `lib/libc/common/source/time/time.c`, `lib/os/clock.c`, `subsys/net/lib/sntp/`, `include/zephyr/net/sntp.h`, `drivers/rtc/`, `drivers/counter/counter_esp32_rtc.c`, `dts/bindings/counter/espressif,esp32-rtc-timer.yaml`, `dts/riscv/espressif/esp32c6/esp32c6_common.dtsi`. |
| Mbed TLS 4.1.0 and TF-PSA-Crypto 1.1.0, same workspace | Pinned source | `mbedtls/library/x509.c`, `mbedtls/library/x509_crt.c`, `mbedtls/include/mbedtls/x509.h`, `mbedtls/include/mbedtls/x509_crt.h`, `mbedtls/include/mbedtls/build_info.h`, `tf-psa-crypto/include/mbedtls/platform_time.h`, `tf-psa-crypto/platform/platform_util.c`. |
| This repository | Own source | `docs/course-specification.md` sections 3, 7 and 8; `firmware/tier-0*/prj.conf`; `firmware/tier-04-release-policy/bootloader/mcuboot.conf`, `Kconfig` and `src/release_policy.{c,h}`; `firmware/tier-07-operational-identity/src/{claim.c,identity.c}` and `Kconfig`; `services/ota/{identity.go,listeners.go}`; `internal/coursepki/operational.go`; `artifacts/generated/releases/*.manifest.json`; `research/course-readings.md`. |
