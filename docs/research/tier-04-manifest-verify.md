# Verifying a detached ECDSA P-256 signature in the application

Research for issue #65, under Wayfinder map #64. Settled by building it, not by
reading about it.

**Short answer.** The application calls the PSA crypto interface
(`psa_hash_compute`, `psa_import_key`, `psa_verify_hash`). It needs **no new
Kconfig symbols at all** on top of what `firmware/tier-03-signed-images/prj.conf`
already sets. The compiled-in public key is carried as the bare 65-byte
uncompressed EC point, extracted from the SPKI at build time exactly the way
`writeTrustAnchor()` already emits the Course certificate authority as DER.
The measured cost against the Tier 3 baseline is **+416 bytes of flash and
0 bytes of static RAM**.

The reason it is that cheap is the finding underneath the finding: the ECDSA
P-256 and SHA-256 machinery is already linked into the Tier 3 image, because
the TLS handshake pays for it. The application is only adding glue.

---

## 1. What this build actually is

| Item | Value | Where |
| --- | --- | --- |
| Zephyr | 4.4.2 | `/opt/zephyr-workspace/zephyr/VERSION` |
| Mbed TLS | 4.1.0 | `modules/crypto/mbedtls/include/mbedtls/build_info.h:39` |
| Crypto module | `tf-psa-crypto` | `modules/crypto/tf-psa-crypto`, a separate west project |
| Board | `esp32c6_devkitc/esp32c6/hpcore` | |
| Container | `tier2-validate` | repo bind-mounted at `/workspaces/learning-cyber-security` |

Mbed TLS 4.x split all crypto out of the `mbedtls` repository into
`tf-psa-crypto`. Three consequences decide this ticket before any code is
written:

1. **`mbedtls_ecdsa_verify` is not a public API here.** Its header lives at
   `modules/crypto/tf-psa-crypto/drivers/builtin/include/mbedtls/private/ecdsa.h`.
   The word `private` in that path is the whole answer. The symbol is in the
   image, but calling it means reaching into a private header.
2. **`CONFIG_MBEDTLS_ECDSA_C`, `CONFIG_MBEDTLS_ECP_C`, `CONFIG_MBEDTLS_SHA256`
   and `CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED` do not exist as Kconfig
   symbols in this tree.** Curves and algorithms are selected only through
   `PSA_WANT_*`. `zephyr/modules/mbedtls/legacy_support.cmake:121-123` says so
   directly: those C defines are "auto-derived from PSA_WANT_* by
   crypto_adjust_config_enable_builtins.h".
3. **`mbedtls_pk_verify` survives**, declared at
   `modules/crypto/tf-psa-crypto/include/mbedtls/pk.h:528`, but in 4.x the PK
   layer is a shim that dispatches into PSA. It buys nothing that avoids PSA.

So the real choice is PSA versus the PK compatibility shim over PSA. It is not
PSA versus "the mbedTLS way", because there is no longer an mbedTLS way.

## 2. The Tier 3 baseline already contains the verifier

`nm` on the unmodified Tier 3 image, before a single line was added:

```
4203445a T mbedtls_pk_verify
4203647c T psa_import_key
42036714 T psa_hash_compute
42036af6 T psa_verify_hash
42037a42 T mbedtls_ecdsa_der_to_raw
4203cb96 T mbedtls_ecdsa_verify
```

Every function a manifest verifier needs is already linked. It arrives through
one line of `prj.conf`,
`CONFIG_MBEDTLS_CIPHERSUITE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256=y`, whose
definition at `zephyr/modules/mbedtls/Kconfig.ciphersuites:4-19` selects
`PSA_WANT_ALG_ECDSA`, `PSA_WANT_ALG_SHA_256`,
`PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT/EXPORT/GENERATE`, and implies
`PSA_WANT_ECC_SECP_R1_256`.

The Tier 3 `.config` confirms all of it:

```
CONFIG_PSA_CRYPTO=y
CONFIG_PSA_CRYPTO_PROVIDER_MBEDTLS=y
CONFIG_MBEDTLS_PSA_CRYPTO_C=y
CONFIG_PSA_WANT_ALG_ECDSA=y
CONFIG_PSA_WANT_ALG_SHA_256=y
CONFIG_PSA_WANT_ECC_SECP_R1_256=y
CONFIG_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC=y
CONFIG_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG=y
CONFIG_MBEDTLS_PK_PARSE_C=y
CONFIG_MBEDTLS_ASN1_PARSE_C=y
```

`CONFIG_PSA_CRYPTO` is not set by hand anywhere in the course tree. It arrives
from `CONFIG_NET_SOCKETS_SOCKOPT_TLS`, which does `select PSA_CRYPTO if
NET_NATIVE` at `zephyr/subsys/net/lib/sockets/Kconfig:133`. Tier 2 turned on
PSA crypto when it turned on TLS sockets, and nobody noticed.

### The one symbol that looks missing, and is not

`CONFIG_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY` does not appear in the Tier 3
`autoconf.h`, and importing a public key is exactly what `psa_import_key()`
does. It turns out not to be needed, because Mbed TLS derives it in C, at
`modules/crypto/tf-psa-crypto/include/tf-psa-crypto/private/crypto_adjust_config_key_pair_types.h:53-55`:

```c
#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY 1
#endif
```

`PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC` is already y. This is a trap worth
naming: `psa_import_key()` always links, and returns `PSA_ERROR_NOT_SUPPORTED`
at run time when the driver is absent. A build that links proves nothing about
key-type support on its own. The spike therefore carries compile-time `#error`
probes on `PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY`, `PSA_WANT_ALG_ECDSA`,
`PSA_WANT_ECC_SECP_R1_256` and `PSA_WANT_ALG_SHA_256`, and they all pass. Tier 4
should keep those probes.

### `psa_crypto_init()` is already called

`zephyr/modules/mbedtls/zephyr_init.c:50-54` calls `psa_crypto_init()` from a
`SYS_INIT` at `POST_KERNEL`, under `CONFIG_MBEDTLS_INIT`, which defaults to y.
The application does not have to. The spike calls it anyway because it is
idempotent and because a Tier 4 module that shows the call is clearer than one
that relies on an init hook the Learner cannot see.

The RNG behind it needs no configuration either: the esp32c6 device tree
declares `trng0` and sets `zephyr,entropy = &trng0`
(`zephyr/dts/riscv/espressif/esp32c6/esp32c6_common.dtsi:27,240-241`), which
makes the `MBEDTLS_PSA_CRYPTO_RNG_SOURCE` choice at
`zephyr/modules/mbedtls/Kconfig.tf-psa-crypto:226-230` resolve to
`MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` on its own.

## 3. The chosen API, and why not the other one

**Chosen: `psa_hash_compute` + `mbedtls_ecdsa_der_to_raw` + `psa_import_key` +
`psa_verify_hash`.**

Both candidates were built and both were run. The deciding argument is not size,
which is within 96 bytes either way. It is that **PSA lets the application name
the algorithm and the PK shim does not.**

`psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), ...)` states the
algorithm at the call site, and the key was imported with that algorithm as its
policy. `mbedtls_pk_verify()` has no algorithm argument; `pk.h:508-512` says the
algorithm "will be the one that would be selected by
`mbedtls_pk_get_psa_attributes()` called with a usage of
`PSA_KEY_USAGE_VERIFY_HASH`". For a signature check that is a security
boundary, the verifier should decide what it is verifying, not the key it was
handed. That is a Tier 4 teaching point as much as an engineering one.

Two secondary reasons:

- PSA speaks raw `r||s`, so the DER signature has to be converted. That is not a
  cost: `mbedtls_ecdsa_der_to_raw()` is public API in
  `modules/crypto/tf-psa-crypto/include/mbedtls/psa_util.h:192`, and it is
  **already in the Tier 3 image** (see the `nm` output above). It is one call.
- Mbed TLS 4.x is actively moving callers off the legacy surface
  (`Kconfig.tf-psa-crypto:363-369`). Building Tier 4 on the shim means building
  on the thing being removed.

`mbedtls_ecdsa_verify` is rejected outright: private header.

### What the PK route would have needed

Nothing extra either, as it happens. `CONFIG_MBEDTLS_PK_PARSE_C` and
`CONFIG_MBEDTLS_ASN1_PARSE_C` are already selected, through
`MBEDTLS_X509_CRT_PARSE_C` → `MBEDTLS_X509_USE_C`
(`zephyr/modules/mbedtls/Kconfig.mbedtls:248-250`,
`Kconfig.tf-psa-crypto:211-214`). The only new function it pulls in is
`mbedtls_pk_parse_public_key`, a wrapper over `mbedtls_pk_parse_subpubkey`,
which the baseline already links. That is where its 320 bytes go.

## 4. Kconfig required

**None.** The exact `prj.conf` delta over
`firmware/tier-03-signed-images/prj.conf` is empty. The PSA image in the table
below was built with no extra fragment and no extra symbol.

Two symbols are worth adding anyway, as assertions rather than as
enablement, so that a future edit to the ciphersuite line cannot silently take
the verifier's curve away:

```conf
# Manifest verification. Both are already set: the TLS ciphersuite selects
# PSA_WANT_ALG_ECDSA and only *implies* PSA_WANT_ECC_SECP_R1_256, and an imply
# can be overridden without an error. Stating them here means a change to the
# ciphersuite cannot quietly remove the curve the manifest verifier needs.
CONFIG_PSA_WANT_ALG_ECDSA=y
CONFIG_PSA_WANT_ECC_SECP_R1_256=y
```

Neither changes a single byte of the image; they are already y.

`CONFIG_MBEDTLS_PEM_PARSE_C=n` stays as it is. See section 5.

## 5. How the compiled-in public key is parsed

**It is not parsed. It is converted at build time, the way the Course
certificate authority already is.**

`artifacts/generated/signing/release.pub.pem` is a 178-byte PEM wrapper around a
91-byte SubjectPublicKeyInfo DER, which is a 26-byte header followed by the
65-byte uncompressed point `04 || X || Y`. PSA imports that 65-byte point
directly, with no ASN.1 at all:

```c
psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
psa_set_key_bits(&attr, 256);
psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
psa_import_key(&attr, release_pub, sizeof(release_pub), &key);
```

So the build step is the same shape as `writeTrustAnchor()` in
`internal/courseapp/app.go:437-460`: read the generated material, emit a `.inc`
of `0x..,` bytes into generated state, pass the directory in the environment,
`#include` it into a `static const unsigned char[]`. The only difference is that
the anchor emits all of the DER and the release key emits the DER from offset 26.

A `writeReleaseKey()` beside `writeTrustAnchor()` is the right home, with the
same two properties the anchor already has: the file lands in generated state
and is never committed, and a build with no key produces an image that verifies
nothing and says so, rather than an image that verifies anything.

### Why not just turn the PEM parser back on

Because it costs about 1.9 KiB of flash to do at run time what the build can do
for free, and because it puts a text parser on the path to a trust decision.
Measured, as the fourth row of the table below: `CONFIG_MBEDTLS_PEM_PARSE_C=y`
plus `CONFIG_MBEDTLS_BASE64_C=y` (the former selects the latter,
`Kconfig.tf-psa-crypto:150-152`) adds **1696 bytes of `.text` and 228 bytes of
`.flash.rodata`** over the DER route. The key itself also grows from 65 bytes to
178. Tier 3's existing comment, "The trust anchor is compiled in as DER, so the
PEM parser is not needed", stands unchanged for Tier 4.

## 6. Measured cost

All four images built in the same container, same board target, same toolchain,
`--pristine=always`, sysbuild. The baseline is the unmodified Tier 3
application built in a scratch directory, not the shared
`tier-03-signed-images-baseline` tree.

| Section | Tier 3 baseline | PSA verify | PK verify | PK verify + PEM |
| --- | ---: | ---: | ---: | ---: |
| `.text` | 496320 | 496736 | 496640 | 498336 |
| `.flash.rodata` | 67124 | 67532 | 67532 | 67760 |
| `.flash.align_rom` (padding) | 27968 | 27552 | 27648 | 25952 |
| `.dram0.data` | 12196 | 12196 | 12196 | 12196 |
| `.dram0.bss` | 87152 | 87152 | 87152 | 87152 |
| `.dram0.noinit` | 93900 | 93900 | 93900 | 93900 |
| `.iram0.text` | 47348 | 47348 | 47348 | 47348 |
| `zephyr.bin` | 657524 | 657940 | 657940 | 658164 |

Deltas against the baseline:

| | `.text` | `.flash.rodata` | static RAM | `zephyr.bin` |
| --- | ---: | ---: | ---: | ---: |
| **PSA verify** | **+416** | **+408** | **0** | **+416** |
| PK verify | +320 | +408 | 0 | +416 |
| PK verify + PEM | +2016 | +636 | 0 | +640 |

Read these three ways.

- **Static RAM is unchanged. Zero bytes.** `.data`, `.bss` and `.noinit` are
  byte-identical across all four images. The verifier holds no static state; the
  key is `const` and lives in flash, and PSA's key slot table
  (`CONFIG_MBEDTLS_PSA_KEY_SLOT_COUNT=16`) is already allocated for TLS.
- **Flash is +416 bytes in the image**, and the section deltas add to more than
  that because `.flash.align_rom` padding absorbs the difference. `.text` and
  `.flash.rodata` together are the honest figure for what was added; `zephyr.bin`
  is the honest figure for what lands on the device.
- **Most of the 408 rodata bytes are the spike's own test vectors, not Tier 4's
  cost.** The spike compiles in the 65-byte release key plus a second 65-byte
  throwaway public key, a 54-byte demo manifest and a 71-byte demo signature,
  which is 255 bytes of arrays; the rest is printk format strings. Tier 4 ships
  only the release key: **65 bytes** on the PSA route, 91 on the PK route. So a
  realistic Tier 4 figure is roughly **+416 bytes of `.text` and +65 bytes of
  rodata**, call it half a kilobyte of flash and nothing at all of RAM.

The reason the number is this small is section 2: the P-256 field arithmetic,
the ECDSA verifier and SHA-256 are already in the image for TLS. A Tier that had
no TLS would pay tens of kilobytes for the same feature. **Tier 4's signature
verification is nearly free only because Tier 2 already bought the crypto.**
That is worth saying in the module text, because it is not obvious and it is the
kind of thing a Learner would otherwise assume does not scale.

What is *not* measured here: peak stack and peak mbedTLS heap during a verify.
Static RAM being unchanged does not mean run-time RAM is. The verify runs on the
main thread (`CONFIG_MAIN_STACK_SIZE=8192`) and the P-256 point arithmetic
allocates from the 48 KiB mbedTLS heap that TLS also uses. On the Tier 4 path a
verify happens after the download, not during a handshake, so the two peaks do
not coincide; that is an assumption Tier 4 should confirm on the board rather
than inherit from this note.

## 7. It was run, not only linked

A build that links is not evidence that PSA accepts a bare EC point or that
`mbedtls_ecdsa_der_to_raw` produces what `psa_verify_hash` wants. Both were
therefore run on `native_sim`, in the same container, against the same Mbed TLS
4.1.0 sources. Two vectors are compiled in: a 54-byte manifest and a genuine
detached DER signature over it, made with a throwaway P-256 key. Verifying
against that key must succeed; verifying the same bytes against the real release
public key must fail.

PSA route:

```
*** Booting Zephyr OS build v4.4.2 ***
research-65 native_sim: exercising the PSA verify path
manifest.verify accept-path err=0 cycles=0
manifest.verify refuse-path err=-4 cycles=0
research-65 done
```

PK route:

```
manifest.verify accept-path err=0 cycles=0
manifest.verify refuse-path err=-3 cycles=0
```

`err=0` is a valid signature accepted. `err=-4` is `psa_verify_hash` returning
`PSA_ERROR_INVALID_SIGNATURE`; `err=-3` is the PK route's equivalent. Both
routes accept the good signature and refuse the wrong key.

`cycles=0` in both runs: `k_cycle_get_32()` does not advance usefully under
`native_sim`. **No timing figure is claimed.** How long a verify takes on the
real ESP32-C6 is not answered here and needs the board.

The throwaway signing key was generated in a scratch directory outside the
repository. Nothing wrote to `.course-secrets`, no release private key was
touched, and `./course keys create` was not run.

## 8. The spike source

One file, built for both routes. `CONFIG_COURSE_VERIFY_WITH_PK` selects the PK
route; unset selects PSA. Tier 4 would ship only the PSA half.

```c
#include "manifest_verify.h"

#include <string.h>
#include <zephyr/kernel.h>

#if defined(CONFIG_COURSE_VERIFY_WITH_PK)
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#else
#include <psa/crypto.h>
#include <mbedtls/psa_util.h>

/* Prove the key type and algorithm are actually built in, rather than only
 * that the call links. psa_import_key() is always linkable and returns
 * PSA_ERROR_NOT_SUPPORTED at run time when the driver is absent.
 */
#if !defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#error "PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY is not built in"
#endif
#if !defined(PSA_WANT_ALG_ECDSA)
#error "PSA_WANT_ALG_ECDSA is not built in"
#endif
#if !defined(PSA_WANT_ECC_SECP_R1_256)
#error "PSA_WANT_ECC_SECP_R1_256 is not built in"
#endif
#if !defined(PSA_WANT_ALG_SHA_256)
#error "PSA_WANT_ALG_SHA_256 is not built in"
#endif
#endif

/* The release verification key, compiled in the same way the Course
 * certificate authority already is. Nothing is fetched.
 *
 * The PSA path wants the bare uncompressed point, so the build strips the
 * 26-byte SubjectPublicKeyInfo wrapper that a P-256 SPKI carries. The PK path
 * wants the SPKI DER itself, because mbedtls_pk_parse_public_key() reads that
 * wrapper to learn the curve. Neither wants PEM: CONFIG_MBEDTLS_PEM_PARSE_C
 * is off in this tree and stays off.
 */
#if defined(CONFIG_COURSE_VERIFY_WITH_PK)
static const uint8_t release_pub[] = {
#include "release_pub_der.inc"
};
#else
static const uint8_t release_pub[] = {
#include "release_pub_point.inc"
};
#endif

static int verify_against(const uint8_t *pub, size_t pub_len,
			  const uint8_t *body, size_t body_len,
			  const uint8_t *sig_der, size_t sig_len)
{
#if defined(CONFIG_COURSE_VERIFY_WITH_PK)
	mbedtls_pk_context pk;
	uint8_t digest[32];
	int err;

	err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			 body, body_len, digest);
	if (err != 0) {
		return -1;
	}

	mbedtls_pk_init(&pk);
	err = mbedtls_pk_parse_public_key(&pk, pub, pub_len);
	if (err != 0) {
		mbedtls_pk_free(&pk);
		return -2;
	}

	/* mbedtls_pk_verify() takes the ASN.1 DER signature as it arrived. It
	 * takes no algorithm argument: the algorithm comes from the key.
	 */
	err = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest, sizeof(digest),
				sig_der, sig_len);
	mbedtls_pk_free(&pk);
	return err == 0 ? 0 : -3;
#else
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key = PSA_KEY_ID_NULL;
	uint8_t digest[32];
	uint8_t sig_raw[64];
	size_t digest_len = 0;
	size_t raw_len = 0;
	psa_status_t st;
	int err;

	st = psa_hash_compute(PSA_ALG_SHA_256, body, body_len,
			      digest, sizeof(digest), &digest_len);
	if (st != PSA_SUCCESS) {
		return -1;
	}

	/* PSA speaks raw r||s. The manifest signature arrives as ASN.1 DER,
	 * which is what every offline signer emits, so it is converted here.
	 * mbedtls_ecdsa_der_to_raw() is public API in mbedtls/psa_util.h and is
	 * already linked into the Tier 3 image.
	 */
	err = mbedtls_ecdsa_der_to_raw(256, sig_der, sig_len,
				       sig_raw, sizeof(sig_raw), &raw_len);
	if (err != 0 || raw_len != sizeof(sig_raw)) {
		return -2;
	}

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

	st = psa_import_key(&attr, pub, pub_len, &key);
	if (st != PSA_SUCCESS) {
		return -3;
	}

	st = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
			     digest, digest_len, sig_raw, raw_len);
	(void)psa_destroy_key(key);
	return st == PSA_SUCCESS ? 0 : -4;
#endif
}

int manifest_verify(const uint8_t *body, size_t body_len,
		    const uint8_t *sig_der, size_t sig_len)
{
	return verify_against(release_pub, sizeof(release_pub),
			      body, body_len, sig_der, sig_len);
}
```

The `.inc` files are produced from `artifacts/generated/signing/release.pub.pem`
with the same byte-list shape `writeTrustAnchor()` emits:

```
openssl pkey -pubin -in release.pub.pem -outform DER   # 91 bytes, SPKI
# PSA route: drop the first 26 bytes, keep the 65-byte point starting 0x04
```

## 9. What Tier 4 should take from this

1. Call PSA. `psa_hash_compute`, `mbedtls_ecdsa_der_to_raw`, `psa_import_key`,
   `psa_verify_hash`, in that order.
2. Add no Kconfig for it. Add `CONFIG_PSA_WANT_ALG_ECDSA=y` and
   `CONFIG_PSA_WANT_ECC_SECP_R1_256=y` as assertions if you want the
   dependency stated, but know they are already y.
3. Keep the `#error` probes. They are the only thing standing between "it
   linked" and "the driver is there".
4. Compile the key in as the 65-byte point, emitted by a `writeReleaseKey()`
   beside `writeTrustAnchor()`, into generated state, never committed.
5. Leave `CONFIG_MBEDTLS_PEM_PARSE_C=n`.
6. Budget half a kilobyte of flash and no static RAM, and say in the module why
   it is that cheap: Tier 2's TLS already paid for the curve.
7. Still unanswered, and needing the board: how long a verify takes, and the
   peak stack and mbedTLS heap it reaches.

---

## Reproducing

Inside the `tier2-validate` container, with the Zephyr workspace at
`/opt/zephyr-workspace`:

```sh
west build --sysbuild --pristine=always --board esp32c6_devkitc/esp32c6/hpcore \
  --build-dir <scratch>/research-65-base <scratch-src>/firmware/base
```

where `firmware/base` is a copy of `firmware/tier-03-signed-images` and
`firmware/verify` is the same copy plus `src/manifest_verify.c`, a `keys/`
directory of `.inc` files, and two lines in `CMakeLists.txt`. The PK variant
adds `-Dverify_EXTRA_CONF_FILE=.../pk.conf` with
`CONFIG_COURSE_VERIFY_WITH_PK=y`; the PEM variant adds
`CONFIG_MBEDTLS_PEM_PARSE_C=y` and `CONFIG_MBEDTLS_BASE64_C=y`.

Sizes come from
`riscv64-zephyr-elf-size -A <build>/verify/zephyr/zephyr.elf` and
`stat -c %s <build>/verify/zephyr/zephyr.bin`.

The board was not flashed, `/dev/ttyACM0` was not opened, and no existing
`tier-03-signed-images-*` build directory was written to.
