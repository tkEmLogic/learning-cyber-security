# What TLS costs and refuses on the pinned ESP32-C6 stack

**Research date:** 2026-09-14
**Ticket:** [#40](https://github.com/tkEmLogic/learning-cyber-security/issues/40), child of map #39
**Question:** What does TLS on the Reference product actually cost and refuse, on Zephyr 4.4.2 with MCUboot 2.4.0 on the validated nanoESP32-C6, and can the dev container capture loopback traffic?

## Versions this note is about

Every claim below is against the exact tree the course pins. Where a claim comes from source, the file path is given relative to the workspace root and was read on 2026-09-14.

| Component | Version | How established |
| --- | --- | --- |
| Zephyr | `v4.4.2` | `git -C $ZEPHYR_WORKSPACE/zephyr describe --tags` |
| MCUboot | `v2.4.0` | `git -C $ZEPHYR_WORKSPACE/bootloader/mcuboot describe --tags` |
| Mbed TLS | **4.1.0**, commit `a3e190fe44c78d1ba67f55979e1257328cc7d0d8` | `MBEDTLS_VERSION_STRING` in `modules/crypto/mbedtls/include/mbedtls/build_info.h` |
| TF-PSA-Crypto | commit `dc575a2ddcc8cb16275d24c42a52eaf79ebe2231` | `git describe` (no tag reachable) |
| Zephyr SDK | 1.0.1 | `.devcontainer/post-create.sh` |
| Board target | `esp32c6_devkitc/esp32c6/hpcore` | `course.yml` |

The Mbed TLS major version matters. This is **Mbed TLS 4.x, not 3.x**, split into an Mbed TLS repository plus a separate `tf-psa-crypto` repository, with PSA Crypto as the crypto API. Advice written for Mbed TLS 2.x or 3.x — including most of what is on the public web — does not reliably transfer. `CONFIG_MBEDTLS_VERSION_4_x=y` appears in the generated `.config` of the current Tier 0 build.

> **Surprise worth stating up front:** `CONFIG_MBEDTLS=y` is *already* set in the Tier 0 baseline. The ESP32 Wi-Fi driver pulls in Mbed TLS and PSA Crypto (`.devcontainer/post-create.sh` already notes that `tf-psa-crypto` must be fetched for this reason). Tier 2 is therefore not "add a TLS library". It is "turn on the TLS record layer, X.509 parsing, a key exchange, and a heap that the library can actually allocate from".

## 1. Certificate validity dates on a device with no clock

### What Mbed TLS does with no time

Date checking in Mbed TLS is a compile-time switch, and Zephyr exposes it as exactly one Kconfig symbol:

```
config MBEDTLS_HAVE_TIME_DATE
	bool "Date/time validation in mbed TLS"
```
`zephyr/modules/mbedtls/Kconfig.mbedtls:182`. It defaults to **n**, and it is **not** set in either the current Tier 0 build or in the TLS build measured in section 2.

When it is off, `zephyr/modules/mbedtls/configs/config-tf-psa-crypto.h:53-57` does not define `MBEDTLS_HAVE_TIME` / `MBEDTLS_HAVE_TIME_DATE`, and Mbed TLS compiles these stubs instead of the real comparisons (`modules/crypto/mbedtls/library/x509.c:1169-1182`):

```c
int mbedtls_x509_time_is_past(const mbedtls_x509_time *to)   { ((void) to);   return 0; }
int mbedtls_x509_time_is_future(const mbedtls_x509_time *from){ ((void) from); return 0; }
```

Those two functions are the only callers that can raise `MBEDTLS_X509_BADCERT_EXPIRED` and `MBEDTLS_X509_BADCERT_FUTURE` (`modules/crypto/mbedtls/library/x509_crt.c:2539,2543`). So with the default configuration:

- `notBefore` and `notAfter` are still *parsed*, and are still *rejected as malformed* if malformed.
- They are never *compared to anything*. An expired certificate and a certificate dated for the year 3000 both pass.
- Nothing else is weakened. Signature-chain verification, key-algorithm and key-size profile checks, basic-constraints, extended key usage and hostname matching all run exactly as they would with a clock.

**So yes: date checking is configurable separately, and `CONFIG_MBEDTLS_HAVE_TIME_DATE` is the exact symbol.** It is orthogonal to `CONFIG_MBEDTLS_X509_CRT_PARSE_C` (the chain) and to `ZSOCK_TLS_HOSTNAME` (the name).

### What happens if you turn it on without a time source

This is the failure mode Tier 2 will hit if it naively sets the symbol to `y`.

With `CONFIG_MBEDTLS_HAVE_TIME_DATE=y`, `x509_get_current_time()` calls `mbedtls_time(NULL)`, which is the libc `time()`. Zephyr's `time()` is `zephyr/lib/libc/common/source/time/time.c:12`:

```c
time_t time(time_t *tloc)
{
	struct timespec ts;
	int ret = sys_clock_gettime(SYS_CLOCK_REALTIME, &ts);
	...
}
```

and `sys_clock_gettime(SYS_CLOCK_REALTIME, ...)` is uptime plus a static offset (`zephyr/lib/os/clock.c:27`):

```c
static struct timespec rt_clock_offset;
```

`rt_clock_offset` is zero-initialised and is only ever changed by `sys_clock_settime()`. There is no RTC on this board and nothing in the baseline calls `sys_clock_settime()`. So an unconfigured board believes the date is **1970-01-01 plus a few seconds of uptime**. Every real certificate's `notBefore` is then in the future, `mbedtls_x509_time_is_future()` returns 1, and verification fails with `MBEDTLS_X509_BADCERT_FUTURE`. Every TLS handshake fails, on every server, forever.

This is a good Tier 2 teaching moment but a terrible accident.

### A real trap in Zephyr 4.4.2

`zephyr/modules/mbedtls/CMakeLists.txt:103-110` emits a build warning when TLS is enabled without date checking:

```cmake
if(CONFIG_MBEDTLS_TLS_VERSION_1_2 OR CONFIG_MBEDTLS_TLS_VERSION_1_3)
  if(NOT CONFIG_MBEDTLS_HAVE_TIME_DATE)
    message(WARNING "... certificates will not be checked for expiration or validity dates ...")
```

But `MBEDTLS_TLS_VERSION_1_2` and `MBEDTLS_TLS_VERSION_1_3` are the **deprecated** symbol names (`zephyr/modules/mbedtls/Kconfig.deprecated:36,50`); the current names are `MBEDTLS_SSL_PROTO_TLS1_2` / `MBEDTLS_SSL_PROTO_TLS1_3`, and the deprecated ones only `select` the current ones, never the other way round. A project that uses the current names — or that gets TLS 1.2 pulled in by a ciphersuite symbol, as the measured build in section 2 does — **gets no warning at all**. This was confirmed empirically: the TLS build in section 2 enables TLS 1.2, leaves `MBEDTLS_HAVE_TIME_DATE` off, and CMake prints nothing.

Do not rely on the build telling you. Assert the posture in the course material instead.

### The three real options, ranked for this course

1. **Long-lived course CA, date checking off (`CONFIG_MBEDTLS_HAVE_TIME_DATE=n`).** Simplest, and it is what Tier 2 should start with. The honest framing for the Weakness ledger: *this device cannot tell an expired certificate from a valid one, and cannot benefit from certificate expiry as a revocation mechanism.* That is a real and nameable weakness, which is exactly the shape the course wants.
2. **SNTP at boot, then `sys_clock_settime()`, then date checking on.** Zephyr has the client already: `CONFIG_SNTP=y` and `sntp_simple_addr(struct net_sockaddr *addr, ..., struct sntp_time *ts)` (`zephyr/include/zephyr/net/sntp.h:187`), which takes a socket address and so needs no DNS — matching the course's existing "literal address, no name lookup" style. Set the clock with `sys_clock_settime(SYS_CLOCK_REALTIME, &ts)` (`zephyr/include/zephyr/sys/clock.h:472`). The catch to teach: **SNTP is unauthenticated**, so an attacker who controls time can make an expired certificate valid again, or make a valid one refuse to work. Bootstrapping trust in time from the network you are trying to authenticate is circular. This is an excellent Tier 3+ exercise and a poor Tier 2 dependency.
3. **Build-time baked time.** Call `sys_clock_settime()` once at boot with a constant generated by `./course build firmware` into the existing `COURSE_FIRMWARE_CONF` fragment. Gives a usable floor ("no certificate issued before this firmware was built is acceptable") with no network dependency. Costs nothing and is monotonic only in the sense that reflashing moves it forward. Worth mentioning; not worth building for Tier 2.

**Recommendation:** Tier 2 uses option 1 and says so loudly. Option 2 belongs in a later tier where "who tells the device what time it is" is the lesson.

## 2. Cost: heap, stack, flash, and whether it still fits

### This was measured, not estimated

Two pristine sysbuild builds of `firmware/reference-product-baseline` for `esp32c6_devkitc/esp32c6/hpcore` were run in the repo's own dev container on 2026-09-14, using `scripts/build-zephyr-baseline.sh` with `ZEPHYR_BUILD_DIR` pointed at scratch directories. The only difference is one extra Kconfig fragment.

The fragment (a plausible Tier 2 shape: TLS 1.2, one ECDHE-ECDSA suite, PEM certificates):

```
CONFIG_NET_SOCKETS_SOCKOPT_TLS=y
CONFIG_TLS_CREDENTIALS=y
CONFIG_MBEDTLS_CIPHERSUITE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256=y
CONFIG_MBEDTLS_PEM_PARSE_C=y
CONFIG_MBEDTLS_BASE64_C=y
CONFIG_MBEDTLS_ENABLE_HEAP=y
CONFIG_MBEDTLS_HEAP_SIZE=49152
CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN=2048
CONFIG_NET_SOCKETS_TLS_MAX_CONTEXTS=2
```

Linker memory report for the application image (`zephyr/zephyr.elf`):

| Region | Tier 0 baseline | Baseline + TLS | Delta |
| --- | --- | --- | --- |
| `FLASH` | 589 972 B | 661 588 B | **+71 616 B (+12.1 %)** |
| `sram0_0_seg` | 181 296 B / 488 976 B (37.08 %) | 242 624 B / 488 976 B (**49.62 %**) | **+61 328 B** |
| `irom0_0_seg` | 435 648 B | 513 984 B | +78 336 B |
| `drom0_0_seg` | 65 812 B | 71 892 B | +6 080 B |

`riscv64-zephyr-elf-size` on the same ELFs:

| | text | data | bss |
| --- | --- | --- | --- |
| Baseline | 548 844 | 13 168 | 148 888 |
| + TLS | 633 260 | 13 224 | 197 312 |
| Delta | **+84 416** | +56 | **+48 424** |

`zephyr.bin` grew from 590 100 B to 661 716 B.

### Does it still fit the 4 MiB flash map

Yes, comfortably, and **no change to `dts/esp32c6_4m_flash_map.dtsi` is needed.**

`slot0_partition` is `0x1c0000` = 1 835 008 B. The TLS image is 661 716 B, which is **36 %** of the slot; 1 173 292 B remain. `slot1_partition` is the same size. MCUboot itself did not change (it is not built with TLS).

One caveat on reading the table: the linker's `FLASH` region is reported as 4 194 176 B, i.e. the whole chip, not the slot. **The link will not fail if the image outgrows `slot0`.** The binding constraint is the partition, and it must be checked by hand or by a build-time assertion. Nothing in the current build does that.

### Heap: the part that will actually bite

Almost all of the +48 424 B of `bss` is one chosen constant. `CONFIG_MBEDTLS_HEAP_SIZE` becomes a static array (`zephyr/modules/mbedtls/zephyr_init.c:31`):

```c
static unsigned char _mbedtls_heap[CONFIG_MBEDTLS_HEAP_SIZE] HEAP_MEM_ATTRIBUTES;
```

handed to `mbedtls_memory_buffer_alloc_init()` at boot. Three things follow, in order of how much trouble they cause:

1. **`CONFIG_MBEDTLS_ENABLE_HEAP=y` is mandatory, not optional.** `zephyr/modules/mbedtls/configs/config-tf-psa-crypto.h:24-25` defines `MBEDTLS_PLATFORM_MEMORY` and `MBEDTLS_MEMORY_BUFFER_ALLOC_C` **unconditionally**. So `mbedtls_calloc` always routes to the buffer allocator — but that allocator is only *initialised* when `CONFIG_MBEDTLS_ENABLE_HEAP=y` (with `CONFIG_MBEDTLS_INIT=y`, which defaults on). Enable TLS without enabling the heap and every allocation inside the handshake fails.
2. **The default heap size is 512 bytes** (`zephyr/modules/mbedtls/Kconfig:165-169`, `default 512`). Setting `CONFIG_MBEDTLS_ENABLE_HEAP=y` and forgetting `CONFIG_MBEDTLS_HEAP_SIZE` produces a build that links cleanly and fails every handshake.
3. **The sizing input is `CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN`**, because Mbed TLS allocates input *and* output record buffers of that size from this heap, per session (`zephyr/modules/mbedtls/Kconfig.mbedtls:77-89`: *"mbedTLS uses this value separate for input and output buffers, so twice this value will be allocated"*). At 2048 that is ~4 KiB before the certificate chain, the ECDHE state and the PSA key slots. Zephyr's own `samples/net/sockets/http_client/overlay-tls.conf` uses `CONFIG_MBEDTLS_HEAP_SIZE=60000` with `MAX_CONTENT_LEN=2048`. The Kconfig help text says *"For streaming communication with arbitrary (HTTPS) servers on the Internet, 32KB + overheads (up to another 20KB) may be needed."* 48 KiB is a defensible starting point for a course-local server with a short chain; it is a starting point, not a measured requirement.

The remaining ~13 KiB of the SRAM delta beyond `data + bss` is thread stack and no-init allocation for the TLS socket layer; `CONFIG_NET_SOCKETS_TLS_MAX_CONTEXTS` (default **1**, set to 2 here) scales part of it.

### The RAM number that is not established

`sram0_0_seg` going from 37 % to 50 % is the static picture. What it does **not** show is the runtime system heap, which is what is left of SRAM after static allocation and which the ESP32 Wi-Fi stack draws on heavily during association and while a connection is open. Static headroom dropped from ~307 KiB to ~246 KiB, a 20 % cut in the pool Wi-Fi shares with everything else.

**I could not establish whether the board still associates and completes a handshake with this configuration**, because that needs hardware. The smallest experiment that settles it: flash the TLS build to the nanoESP32-C6, print `sys_heap_usage`/`esp_get_free_heap_size` right after `wifi.association succeeded` and again immediately after the handshake, and watch for allocation failures in the Mbed TLS error path. If it is tight, the first lever is `CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN` (the course server controls its own record sizes, so 1024 may be enough), then `CONFIG_NET_SOCKETS_TLS_MAX_CONTEXTS=1`, then `CONFIG_MBEDTLS_HEAP_SIZE`.

### Is this socket options plus credentials, or something larger?

**Socket options plus credentials.** `firmware/reference-product-baseline/src/ota_client.c` needs a genuinely small change:

- `ota_connect()` at `ota_client.c:83` changes `zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)` to `IPPROTO_TLS_1_2` (`NET_IPPROTO_TLS_1_2 = 258`, `zephyr/include/zephyr/net/net_ip.h:81`; `IPPROTO_TLS_1_3 = 259`).
- Two `zsock_setsockopt()` calls on the new socket before `zsock_connect()`: `TLS_SEC_TAG_LIST` and `TLS_HOSTNAME` (section 3).
- One `tls_credential_add()` at startup, once, not per connection.

`run_request()` and every `http_client` call site are **unchanged**. `zephyr/subsys/net/lib/http/http_client.c` talks to the fd through `zsock_send`, `zsock_recv` and `zsock_poll` only (lines 38, 49, 500, 522), and Zephyr's TLS layer is implemented as a socket vtable underneath exactly those calls. `http_client` never sees TLS.

The `zsock_close(sock)` in `run_request()` already does the right thing: it tears the TLS context down. Note that the current code opens a **fresh connection per request** (`ota_connect()` is called from `run_request()` every time). Under TLS that means a full handshake for every status report and every firmware download — with software ECDHE P-256 on a 160 MHz RISC-V core. Handshake latency was not measured here; see "Not established".

### Hardware crypto acceleration: none, on this stack

The Zephyr 4.4.2 device tree for this SoC exposes two crypto peripherals, `sha@60089000` (`espressif,esp32-sha`) and `aes@60088000` (`espressif,esp32-aes`) — `zephyr/dts/riscv/espressif/esp32c6/esp32c6_common.dtsi:440-452`. They are driven by `zephyr/drivers/crypto/crypto_esp32_{aes,sha}.c` behind Zephyr's **crypto device API**. A grep of `zephyr/modules/mbedtls/` and `modules/hal/espressif/zephyr/` for `MBEDTLS_AES_ALT`, `MBEDTLS_SHA256_ALT`, `MBEDTLS_ECP_ALT` or any PSA driver wiring returns **nothing**, and `CONFIG_CRYPTO` is not even set in the Tier 0 build.

**Mbed TLS on this target does all TLS crypto in software.** Do not budget for hardware acceleration, and do not claim it in course material. (What the ESP32-C6 silicon offers beyond those two blocks — an ECC or RSA accelerator, HMAC, digital signature peripheral — is not established in this note; it is moot, because nothing in this stack routes Mbed TLS through any of it.)

## 3. Credentials: installing a trust anchor, and what the hostname is checked against

### The credential store is runtime-only, and it stores a pointer

`CONFIG_NET_SOCKETS_SOCKOPT_TLS` implies `CONFIG_TLS_CREDENTIALS` (`zephyr/subsys/net/lib/sockets/Kconfig`). The store has exactly two backends (`zephyr/subsys/net/lib/tls_credentials/Kconfig`):

- `CONFIG_TLS_CREDENTIALS_BACKEND_VOLATILE` (the default) — RAM, lost on reboot.
- `CONFIG_TLS_CREDENTIALS_BACKEND_PROTECTED_STORAGE` — `depends on BUILD_WITH_TFM`, which is TrustZone-M. **Not available on an ESP32-C6.**

So there is no persistent credential store on this target, and **the CA must be registered at every boot**.

The API is `zephyr/include/zephyr/net/tls_credentials.h`:

```c
int tls_credential_add(sec_tag_t tag, enum tls_credential_type type,
                       const void *cred, size_t credlen);
```

with `TLS_CREDENTIAL_CA_CERTIFICATE` for a trust anchor (and `TLS_CREDENTIAL_PUBLIC_CERTIFICATE` + `TLS_CREDENTIAL_PRIVATE_KEY` if client certificates are ever added). `sec_tag_t` is a plain `int` the application picks. `CONFIG_TLS_MAX_CREDENTIALS_NUMBER` defaults to 4.

**The volatile backend does not copy the buffer** (`zephyr/subsys/net/lib/tls_credentials/tls_credentials.c`):

```c
credential->buf = cred;
credential->len = credlen;
```

The certificate array must therefore outlive every socket that uses it. A `static const` array is exactly right, and — because it is `const` — it lives in `drom0_0_seg` (flash), not RAM. That is why the flash cost in section 2 is where the certificate would land.

### Yes, it can be compiled in, the way the Wi-Fi credentials are

Not *literally* the same way. `CONFIG_COURSE_WIFI_PSK` is a Kconfig `string`, and a Kconfig string cannot hold a multi-line PEM. The right mechanism is already in Zephyr and already used by the sample:

`zephyr/samples/net/sockets/http_client/CMakeLists.txt:12` calls `generate_inc_file_for_target()` (defined at `zephyr/cmake/modules/extensions.cmake:726`) to turn `https-cert.der` into `https-cert.der.inc`, and `src/ca_certificate.h` does:

```c
#define CA_CERTIFICATE_TAG 1
static const unsigned char ca_certificate[] = {
#include "https-cert.der.inc"
};
```

then registers it once:

```c
tls_credential_add(CA_CERTIFICATE_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
                   ca_certificate, sizeof(ca_certificate));
```

This slots into the course's existing generated-artifact flow: `./course build firmware` already writes a generated Kconfig fragment and passes it as `reference-product-baseline_EXTRA_CONF_FILE` (`scripts/build-zephyr-baseline.sh:40-47`, `internal/courseapp/app.go:629`). The course CA becomes a second generated artifact — a DER file written next to the fragment and pulled in by `generate_inc_file_for_target()`.

**Format.** DER is supported out of the box. PEM needs `CONFIG_MBEDTLS_PEM_PARSE_C=y` **and** `CONFIG_MBEDTLS_BASE64_C=y` (`zephyr/modules/mbedtls/configs/config-tf-psa-crypto.h:91-96`); the Zephyr 4.4.2 socket docs say the same: *"By default certificates in DER format are supported. PEM support can be enabled in mbedTLS settings."* If PEM is used, the length passed to `tls_credential_add()` **must include the terminating NUL** — `sizeof(array)` on a string literal does this; `strlen()` does not. DER avoids the whole question and is smaller. Use DER; enable PEM only if the course wants Learners to see a readable certificate in the image.

`ZSOCK_TLS_CERT_NOCOPY` (option 10) lets Mbed TLS reference a DER certificate in place rather than copying it into the heap (`sockets_tls.c:1378-1384`, `mbedtls_x509_crt_parse_der_nocopy`). Worth knowing if heap gets tight; it is silently ignored for PEM, which always gets copied.

### Socket options, exactly

From `zephyr/include/zephyr/net/socket.h`:

| Constant | Value | Purpose |
| --- | --- | --- |
| `ZSOCK_SOL_TLS` | 282 | the option level |
| `ZSOCK_TLS_SEC_TAG_LIST` | 1 | array of `sec_tag_t` naming which credentials this socket uses |
| `ZSOCK_TLS_HOSTNAME` | 2 | NUL-terminated name the peer certificate must match |
| `ZSOCK_TLS_CIPHERSUITE_LIST` | 3 | restrict the offered suites |
| `ZSOCK_TLS_PEER_VERIFY` | 5 | `NONE` 0 / `OPTIONAL` 1 / `REQUIRED` 2 |
| `ZSOCK_TLS_CERT_VERIFY_RESULT` | 19 | read back the verify flags after an `OPTIONAL` handshake |
| `ZSOCK_TLS_CERT_VERIFY_CALLBACK` | 20 | needs `CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK` |

`ZSOCK_TLS_CERT_VERIFY_RESULT` is worth building into Tier 2's console output. It returns the raw Mbed TLS `MBEDTLS_X509_BADCERT_*` bitmask, which lets the device print *why* it refused — expired, wrong name, unknown issuer — instead of one opaque error. That is the difference between a lesson and a shrug.

### What the hostname is checked against, and the fail-closed default

Three findings here, all verified in source, and the third is the important one.

**Peer verification defaults to REQUIRED for a client.** `sockets_tls.c:1859-1865`: *"If verification level was specified explicitly, set it. Otherwise, use mbedTLS default values (required for client, none for server)."* A TLS client socket on Zephyr 4.4.2 verifies the chain by default. `ZSOCK_TLS_PEER_VERIFY` is how you *weaken* that, which makes it a good deliberate-weakness knob for a course fixture.

**Hostname verification is also on by default — and it fails closed.** In Mbed TLS 4.x, a client with `MBEDTLS_SSL_VERIFY_REQUIRED` that never called `mbedtls_ssl_set_hostname()` aborts with `MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME` (`modules/crypto/mbedtls/library/ssl_tls.c:8676-8684`). The 3.x escape hatch `MBEDTLS_SSL_CLI_ALLOW_WEAK_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME` **was removed in 4.0** and now raises a hard `#error` (`library/mbedtls_config_check_user.h:1676`).

Zephyr handles that by setting the hostname to the empty string when the application did not set one (`sockets_tls.c:1721-1731`):

```c
/* For TLS clients, set hostname to empty string to enforce it's
 * verification - only if hostname option was not set. */
if (!is_server && !tls_ctx->options.is_hostname_set) {
	ret = mbedtls_ssl_set_hostname(&session_ctx->ssl, "");
```

`""` is non-NULL, so `x509_crt_verify_name()` *does* run, with `cn = ""`, and no real certificate's SAN or CN matches the empty string. The result is `MBEDTLS_X509_BADCERT_CN_MISMATCH` and a failed handshake.

**So: forget `TLS_HOSTNAME` and the connection fails, loudly.** It does not silently accept any name. That is the correct posture and it is worth demonstrating rather than just asserting.

**Behaviour on a certificate with no matching name** (`modules/crypto/mbedtls/library/x509_crt.c:2958-2980`): if the certificate carries a `subjectAltName` extension, **only the SANs are consulted** and the CN is ignored entirely. If there is no SAN extension at all, the CN is used as a fallback. Either way a miss sets `MBEDTLS_X509_BADCERT_CN_MISMATCH`, which with `VERIFY_REQUIRED` aborts the handshake, and with `VERIFY_OPTIONAL` is readable through `ZSOCK_TLS_CERT_VERIFY_RESULT`.

### The IP-address problem Tier 2 has to decide

`CONFIG_COURSE_OTA_HOST` is an IPv4 literal today and `ota_connect()` calls `net_addr_pton()` on it; `CONFIG_DNS_RESOLVER` is **not** enabled in either measured build. So there is no name to check.

Mbed TLS 4.1.0 *can* match an IP literal, against an `iPAddress` SAN specifically (`x509_crt_check_san_ip()`, `x509_crt.c:2878-2896`): it runs `mbedtls_x509_crt_parse_cn_inet_pton()` on the string and compares the raw 4 or 16 bytes. It will **not** match an IP literal against a `dNSName` SAN or against the CN. Note also `x509_crt.c:2941`: if the certificate has *any* `iPAddress` SAN, only the IP path is tried.

That leaves Tier 2 three routes, and the choice should be deliberate:

1. **Issue the course server certificate with an `iPAddress` SAN** for the OTA service's address, and pass that same literal as `TLS_HOSTNAME`. Keeps the "no DNS, no name lookup" property of Tier 0. The cost: the address is baked into the certificate, so a Learner whose host gets a different LAN address needs a reissued certificate — which the course's generated-artifact flow can do, since it already regenerates the firmware per Learner.
2. **Add a name.** `CONFIG_DNS_RESOLVER=y` plus a `dNSName` SAN. More realistic, more moving parts, and it makes DNS part of the attack surface the course then has to talk about.
3. **`TLS_PEER_VERIFY_NONE` or a wildcard certificate.** Only as a named, ledgered weakness fixture — never as the default.

Route 1 is the smallest honest step from Tier 0 and is what I would build.

## 4. Capture: can the Podman dev container sniff loopback?

**No, not as configured, and the fix is one line.** All of the following was verified by running it, on this host, on 2026-09-14: Podman 5.8.4 (`podman-5.8.4-1.fc44`), rootless, Fedora host, kernel 7.1.13.

### What is missing

Packet capture needs `CAP_NET_RAW` and only that. `man 7 capabilities` (Linux man-pages 6.13, 2024-06-13): *"CAP_NET_RAW: Use RAW and PACKET sockets."* libpcap's own manual is explicit — *"you must have CAP_NET_RAW in order to capture"* (https://www.tcpdump.org/manpages/pcap.3pcap.html, accessed 2026-09-14). `CAP_NET_ADMIN` is **not** needed; `man 7 capabilities` lists promiscuous mode under it, but modern libpcap uses `PACKET_ADD_MEMBERSHIP`/`PACKET_MR_PROMISC` on the packet socket rather than `SIOCSIFFLAGS`, and capture on `lo` was confirmed working with `NET_RAW` alone. Promiscuous mode is meaningless on loopback anyway.

Podman's default capability set, observed rather than assumed:

```
$ podman run --rm docker.io/library/ubuntu:24.04 grep -E '^Cap' /proc/self/status
CapBnd: 00000000800405fb
$ capsh --decode=00000000800405fb
cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,
cap_setpcap,cap_net_bind_service,cap_sys_chroot,cap_setfcap
```

Eleven capabilities, and `cap_net_raw` is absent from the **bounding** set, not merely the effective set. The same holds inside the repo's own built image. `CAP_NET_RAW` was removed from `containers/common`'s `DefaultCapabilities` by https://github.com/containers/common/pull/1240 and shipped in **Podman 4.4.0** (https://github.com/containers/podman/issues/17504, both accessed 2026-09-14). On this host `~/.config/containers/containers.conf` and `/etc/containers/containers.conf` do not exist, and the `default_capabilities` list in `/usr/share/containers/containers.conf` is commented out, so the compiled-in default applies.

Observed failure in the repo's image:

```
$ podman run --rm $IMG tcpdump -i lo -c 1
tcpdump: lo: You don't have permission to perform this capture on that device
(socket: Operation not permitted)
```

A trap for whoever debugs this: `tcpdump -D` still **lists** `lo` successfully, because it enumerates interfaces over netlink rather than opening a packet socket. A working `-D` is not evidence that capture works.

`--security-opt=label=disable` is irrelevant here — it controls SELinux labelling and neither grants nor blocks capabilities; the failure is `EPERM` from `socket(AF_PACKET, ...)`, not an AVC. Rootless user namespaces do not block `--cap-add=NET_RAW`: the container's netns is owned by the userns Podman creates, so the capability is fully effective inside it. Being uid 0 in the container grants nothing; a `--user 1000` run and a uid-0 run failed identically.

### The fix

One line in `.devcontainer/devcontainer.json` `runArgs`:

```json
"--cap-add=NET_RAW",
```

and one line in the `.devcontainer/Dockerfile` apt list:

```
        tcpdump \
```

`setcap` is **not** a workaround and actively makes things worse. With `NET_RAW` outside the bounding set, `setcap` reports success but the binary then refuses to `execve` at all:

```
$ setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump ; echo rc=$?   # rc=0
$ tcpdump -i lo -c 1
bash: /usr/bin/tcpdump: Operation not permitted
```

### With the fix, loopback capture works completely

Verified end to end inside the repo's image with `--cap-add=NET_RAW`, a `python3 -m http.server 8080 --bind 127.0.0.1`, and a `curl`:

```
IP 127.0.0.1.36492 > 127.0.0.1.8080: Flags [S], ...
IP 127.0.0.1.8080 > 127.0.0.1.36492: Flags [S.], ...
IP 127.0.0.1.36492 > 127.0.0.1.8080: Flags [P.], length 77:  HTTP: GET / HTTP/1.1
IP 127.0.0.1.8080 > 127.0.0.1.36492: Flags [P.], length 155: HTTP: HTTP/1.0 200 OK
```

Full request and response bodies; `link-type EN10MB`, so Wireshark and tshark read the pcap normally.

### Two facts that change how the Tier 2 exercise must be written

1. **Traffic from a physical board does not appear on `lo`.** The container has its own network namespace (`/proc/1/ns/net:[4026532450]` vs the host's `[4026531833]`). With `--publish`, external traffic arrives inside the container on the **pasta** interface, which pasta names after the host's NIC. Capture there, or with `-i any` — not `lo`.
2. **pasta rewrites the source address.** An external client appeared as `169.254.1.2` (pasta's gateway address), with the destination as the host's LAN address. If the exercise wants Learners to see the board's real IP, capture on the **host** instead: `sudo tcpdump -i <nic> -n port 8080`. (Host `lo` will not show container loopback traffic — separate namespaces — and host `tcpdump` has no file capabilities here, so it needs `sudo`.)

### Packages

Ubuntu 24.04 (noble), versions read from the live archive and cross-checked against packages.ubuntu.com on 2026-09-14:

| Package | Version | Installed-Size | Real cost with `--no-install-recommends` |
| --- | --- | --- | --- |
| `tcpdump` | `4.99.4-3ubuntu4.24.04.1` | 1 313 kB | 6 packages, 1 044 kB download, 3 200 kB disk |
| `tshark` | `4.2.2-1.1build3` | 406 kB (+ `wireshark-common` 1 625 kB) | 33 packages, ~27.9 MB download |
| `openssl` | `3.0.13-0ubuntu3.15` | 1 885 kB | **already installed — 0** |

**The ticket's premise about `openssl` is wrong, in the course's favour.** `/usr/bin/openssl` is already present in the built dev container: `ca-certificates`, which *is* in the Dockerfile's install list, `Depends: openssl (>= 1.1.1)`. Confirmed with `dpkg -S /usr/bin/openssl` in the repo's image, and confirmed absent from a bare `ubuntu:24.04`. **Tier 2 `openssl s_client` work needs no new package at all.**

`tshark` costs ~27 MB and 33 packages against `tcpdump`'s 1 MB and 6. For a course image, add `tcpdump`, write a pcap, and let Learners open it in Wireshark on the host.

### Two capture routes that need no `devcontainer.json` change

1. **Sidecar sniffer**, verified working against a container started with no `--cap-add`:
   ```bash
   podman run --rm -it --cap-add=NET_RAW --network=container:<devcontainer-name> \
       docker.io/library/ubuntu:24.04 \
       bash -c 'apt-get update && apt-get install -y tcpdump && tcpdump -i lo -n -w /tmp/lo.pcap'
   ```
2. **Key logging instead of sniffing**, which is the better answer for Tier 2 specifically. Go's `crypto/tls` does **not** honour `SSLKEYLOGFILE` automatically; the OTA service must set `tls.Config.KeyLogWriter` explicitly — *"KeyLogWriter optionally specifies a destination for TLS master secrets in NSS key log format that can be used to allow external programs such as Wireshark to decrypt TLS connections… Use of KeyLogWriter compromises security and should only be used for debugging"* (https://pkg.go.dev/crypto/tls#Config, accessed 2026-09-14). Put it behind an env-var check. Combined with the already-present `openssl s_client`, this covers "show me the encrypted bytes and then show me inside them" with no capability change at all.

## What Tier 2 should do, in one list

- `CONFIG_NET_SOCKETS_SOCKOPT_TLS=y`; leave `CONFIG_MBEDTLS_HAVE_TIME_DATE=n` and ledger the resulting weakness explicitly.
- `CONFIG_MBEDTLS_ENABLE_HEAP=y` **and** an explicit `CONFIG_MBEDTLS_HEAP_SIZE` (start at 49152). Never one without the other.
- Pick one ciphersuite symbol (`CONFIG_MBEDTLS_CIPHERSUITE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256=y`) and let it `select` the key exchange, X.509 parsing and PSA algorithms.
- Generate the course CA as DER, embed it with `generate_inc_file_for_target()`, register it once at boot with `tls_credential_add(tag, TLS_CREDENTIAL_CA_CERTIFICATE, ...)` from a `static const` array.
- In `ota_connect()`: `IPPROTO_TLS_1_2`, then `setsockopt(SOL_TLS, TLS_SEC_TAG_LIST, ...)` and `setsockopt(SOL_TLS, TLS_HOSTNAME, ...)`. Leave `http_client` alone.
- Issue the server certificate with an `iPAddress` SAN for the OTA service address, and pass that literal as `TLS_HOSTNAME`.
- Read `ZSOCK_TLS_CERT_VERIFY_RESULT` and print the `BADCERT_*` reason on the console. It is what makes the refusals teachable.
- Add `"--cap-add=NET_RAW"` to `runArgs` and `tcpdump` to the Dockerfile. Do not add `openssl`; it is already there.
- Add a build-time check that the signed image fits `slot0_partition`. The linker does not do it.

## Not established

Stated plainly, with the experiment that would settle each.

1. **Whether the board still works.** No hardware was used. The measured build links and fits flash, but SRAM headroom drops ~20 % and the ESP32 Wi-Fi stack is a heavy runtime heap consumer. *Experiment:* flash the section-2 configuration, print free heap after association and after the first handshake, and watch for Mbed TLS allocation failures.
2. **Whether 48 KiB of Mbed TLS heap is enough.** 49152 is a plausible figure derived from Zephyr's own sample (60000) and the Kconfig help text, not a measurement against the course's actual certificate chain. *Experiment:* build with `CONFIG_MBEDTLS_MEMORY_DEBUG` and read the buffer allocator's max-used figure after a handshake against the real course server.
3. **Handshake latency and its effect on the OTA loop.** All crypto is software (no accelerator wiring exists) and `ota_connect()` opens a fresh connection per request, so every status report pays a full ECDHE P-256 handshake. *Experiment:* bracket `zsock_connect()` with `k_uptime_get()` and log the delta; if it is bad, either keep one connection open or enable `ZSOCK_TLS_SESSION_CACHE`.
4. **What crypto the ESP32-C6 silicon actually has.** Only `sha` and `aes` nodes exist in Zephyr's device tree, and nothing routes Mbed TLS through them. The Espressif documentation pages I fetched did not give a clean accelerator list. Moot for Tier 2; worth settling from the ESP32-C6 Technical Reference Manual before any claim about hardware crypto appears in course material.
5. **Whether VS Code's Dev Containers extension injects capabilities beyond `runArgs`.** All capability measurements used bare `podman run`. *Experiment:* open the dev container in VS Code and run `grep ^CapEff /proc/self/status`; `00000000800405fb` confirms the bare-podman result holds.
6. **Whether the missing CMake warning is a known upstream issue.** `zephyr/modules/mbedtls/CMakeLists.txt` gates its "certificates will not be checked for expiration" warning on the deprecated `MBEDTLS_TLS_VERSION_1_2`/`_1_3` symbols, so projects using the current `MBEDTLS_SSL_PROTO_TLS1_*` names get no warning. I did not search the Zephyr issue tracker. It looks like a genuine upstream bug and is worth reporting.

## Reproducing the measurements

```bash
IMG=localhost/vsc-learning-cyber-security-<hash>   # from `podman images`
podman run --rm \
  -v zephyr-workspace:/opt/zephyr-workspace \
  -v "$PWD":/workspaces/repo:ro \
  -e ZEPHYR_WORKSPACE=/opt/zephyr-workspace "$IMG" bash -lc '
    cd /workspaces/repo
    ZEPHYR_BUILD_DIR=/opt/zephyr-workspace/build/research-base \
      bash scripts/build-zephyr-baseline.sh
    COURSE_FIRMWARE_CONF=/opt/zephyr-workspace/research-tls.conf \
      ZEPHYR_BUILD_DIR=/opt/zephyr-workspace/build/research-tls \
      bash scripts/build-zephyr-baseline.sh'
```

The "Memory region" table printed at each link is the figure quoted in section 2; `riscv64-zephyr-elf-size` from `$ZEPHYR_WORKSPACE/zephyr-sdk-1.0.1/gnu/riscv64-zephyr-elf/bin/` gives text/data/bss. The `research-tls.conf` fragment is reproduced in full in section 2.

## Sources

Source files were read on 2026-09-14 from the pinned workspace at `$ZEPHYR_WORKSPACE` (the `zephyr-workspace` Podman volume provisioned by `.devcontainer/post-create.sh`); paths are given inline above and are stable for Zephyr `v4.4.2` and the Mbed TLS commit recorded in the version table.

- Zephyr 4.4.2, secure sockets and TLS credentials — https://docs.zephyrproject.org/4.4.2/connectivity/networking/api/sockets.html (accessed 2026-09-14)
- `man 7 capabilities`, Linux man-pages 6.13 (2024-06-13), read locally on 2026-09-14
- libpcap `pcap(3PCAP)` — https://www.tcpdump.org/manpages/pcap.3pcap.html (accessed 2026-09-14)
- `tcpdump(8)` — https://www.tcpdump.org/manpages/tcpdump.1.html (accessed 2026-09-14)
- containers/common default capability list — https://github.com/containers/common/blob/main/pkg/config/default.go (accessed 2026-09-14)
- Removal of `CAP_NET_RAW` from Podman's defaults — https://github.com/containers/common/pull/1240 and https://github.com/containers/podman/issues/17504 (accessed 2026-09-14)
- Ubuntu noble package versions — https://packages.ubuntu.com/noble/tcpdump, https://packages.ubuntu.com/noble/tshark, https://packages.ubuntu.com/noble/openssl (accessed 2026-09-14)
- Go `crypto/tls.Config.KeyLogWriter` — https://pkg.go.dev/crypto/tls#Config (accessed 2026-09-14)
