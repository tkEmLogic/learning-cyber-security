# Can a persistent PSA key sign an X.509 certificate request in Zephyr 4.4.2

Research for ticket #108, on map #104. All paths are inside the `tier2-validate`
podman container. The repo is bind-mounted there at
`/workspaces/learning-cyber-security`.

## Short answer

Yes. The bridge exists, but it is not called `mbedtls_pk_setup_opaque()` any
more, and the ticket's premise is one release out of date.

The pinned workspace is Mbed TLS 4.1.0 with the TF-PSA-Crypto 1.0 split. In that
split `mbedtls_pk_setup_opaque()` was renamed to `mbedtls_pk_wrap_psa()`. The
function is present, is declared in a public header with no `#if` guard around
it, and the file that defines it is compiled into the Zephyr build. So the path
the ticket hoped for is real: generate a persistent key with `psa_generate_key()`,
wrap the key id in an `mbedtls_pk_context` with `mbedtls_pk_wrap_psa()`, hand
that context to `mbedtls_x509write_csr_set_key()`, and call
`mbedtls_x509write_csr_der()`.

There is no Kconfig symbol that switches the bridge on or off. `MBEDTLS_USE_PSA_CRYPTO`,
the symbol that gated this in Mbed TLS 3.x, no longer exists anywhere in the
Zephyr tree. In Mbed TLS 4.x the PK module is always PSA-backed, so there is
nothing to enable.

The real risk is not the bridge. It is four config symbols that Tier 6 has to add
and that nothing auto-selects for it:

| Symbol | Why Tier 6 needs it |
|---|---|
| `CONFIG_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY` | Without it the PK context's public-key buffer is a **zero-length array** and the whole path fails |
| `CONFIG_MBEDTLS_PK_WRITE_C` | The CSR writer calls `mbedtls_pk_write_pubkey_der()`, and `MBEDTLS_X509_CSR_WRITE_C` does not select it |
| `CONFIG_MBEDTLS_X509_CSR_WRITE_C` | Compiles the CSR writer at all |
| `CONFIG_SECURE_STORAGE` | The only thing in the tree that selects the promptless `MBEDTLS_PSA_CRYPTO_STORAGE_C`, which persistent keys need |

A persistent key can be created without `PSA_KEY_USAGE_EXPORT`, and
`psa_export_key()` then returns `PSA_ERROR_NOT_PERMITTED`, which is -133. The
demonstration section 8 wants works exactly as the module intends. Wrapping such
a key still succeeds, because the wrap only exports the **public** key, and
public-key export deliberately requires no usage flag.

## 1. Is `mbedtls_pk_setup_opaque()` present, and which Kconfig turns it on

Not present, and not needed. It was renamed.

The rename is recorded in the TF-PSA-Crypto changelog at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/ChangeLog:162`, which reads
"Rename mbedtls_pk_setup_opaque to mbedtls_pk_wrap_psa."

The migration guide states the same at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/docs/1.0-migration-guide.md:891`,
adding that the PSA key is not necessarily opaque in PSA terminology, which is
why the old name was dropped.

The workspace pins Mbed TLS 4.1.0, released 2026-03-31, per the first line of
`/opt/zephyr-workspace/modules/crypto/mbedtls/ChangeLog`.

The replacement is declared at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/mbedtls/pk.h:239`
as `int mbedtls_pk_wrap_psa(mbedtls_pk_context *ctx, const mbedtls_svc_key_id_t key);`.

I checked the surrounding region rather than the matching line: the declaration
sits in open code between `mbedtls_pk_free()` and `mbedtls_pk_get_bitlen()`, with
no `#if` guard around it, so no config symbol hides the prototype.

The definition is at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk.c:158`, and it too
carries no enclosing `#if`.

The file lives under `extras/`, which looked at first like a directory that might
not be built. It is built.
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/CMakeLists.txt:425` does
`add_subdirectory(extras)`, and
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/CMakeLists.txt:1`
globs every `*.c` in that directory into an object library.

Zephyr then links it: `/opt/zephyr-workspace/zephyr/modules/mbedtls/CMakeLists.txt:42`
lists `extras` among the libraries it wires to `zephyr_interface`.

**No Kconfig symbol enables the bridge.** A search for `USE_PSA_CRYPTO` across
`/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig*` returns nothing, so the
Mbed TLS 3.x gate `MBEDTLS_USE_PSA_CRYPTO` is gone from this tree entirely.

There is one genuine config dependency, and it is easy to miss. The ECC branch of
`mbedtls_pk_wrap_psa()` is guarded at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk.c:178` by
`#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)`, and without it an ECC key pair
falls through to the RSA test and returns `MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE` at
line 186.

That guard matters more than it looks. `MBEDTLS_PK_MAX_PUBKEY_RAW_LEN` is defined
as `0` at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/mbedtls/pk.h:91`, and
is only raised to the EC size by the `#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)`
block at lines 92 to 96. That constant sizes the `pub_raw` buffer inside every PK
context, at line 124 of the same header, so without the symbol the context
carries a zero-byte public-key buffer.

Nothing selects that symbol from the key-pair symbols. The Zephyr PSA logic file
`/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.psa.logic:37` derives only
`PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC` from the import, export, generate and
derive symbols, and never mentions the public-key type.

`PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY` is an ordinary standalone symbol at
`/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.psa.auto:279`, whose only
default is `default y if PSA_CRYPTO_ENABLE_ALL` at line 280.

It happens to be selected today by the ESP32 Wi-Fi driver at
`/opt/zephyr-workspace/zephyr/drivers/wifi/esp32/Kconfig.esp32:400`, but that
select sits inside the WPA3-Personal option alongside `select PSA_WANT_ALG_ECDH`
and friends, so it is a side effect of a Wi-Fi feature and not a guarantee Tier 6
should lean on. Tier 6's `prj.conf` should set it explicitly.

## 2. Is the CSR produced correctly, and what is the signing chain

The chain is sound, and every step has an opaque-key branch that handles a
wrapped PSA key.

`mbedtls_x509write_csr_set_key()` still takes a plain `mbedtls_pk_context *`,
unchanged by the split, at
`/opt/zephyr-workspace/modules/crypto/mbedtls/include/mbedtls/x509_csr.h:248`.

The work happens in `x509write_csr_der_internal()` at
`/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:132`. I read
the whole function, lines 132 to 275, rather than the matching lines.

The chain is:

| Step | Call | Location |
|---|---|---|
| 1 | `mbedtls_pk_write_pubkey_der()` embeds the SubjectPublicKeyInfo | `x509write_csr.c:186` |
| 2 | `mbedtls_x509_write_names()` writes the Subject | `x509write_csr.c:194` |
| 3 | `psa_hash_compute()` hashes the CertificationRequestInfo | `x509write_csr.c:212` |
| 4 | `mbedtls_pk_sign_ext(MBEDTLS_PK_SIGALG_ECDSA, ...)` signs it | `x509write_csr.c:229` |
| 5 | `mbedtls_x509_write_sig()` appends signature and OID | `x509write_csr.c:252` |

The algorithm is chosen by key type at `x509write_csr.c:223`, where
`PSA_KEY_TYPE_IS_ECC(key_type)` selects `MBEDTLS_PK_SIGALG_ECDSA`. `key_type`
comes from `mbedtls_pk_get_key_type(ctx->key)` at line 147, which for a wrapped
key returns the PSA type recorded by `mbedtls_pk_wrap_psa()` at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk.c:198`.

`mbedtls_pk_sign_ext()` is at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk.c:1358`. For
anything that is not RSA-PSS it delegates straight to `mbedtls_pk_sign()` at line
1373, so the ECDSA path never touches the RSA-only code below it.

Before delegating, line 1368 calls `mbedtls_pk_can_do(ctx, (mbedtls_pk_type_t) pk_type)`.
That cast between two different enums looked like a bug worth checking. It is
deliberate and safe: `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/mbedtls/private/pk_private.h:24`
defines `MBEDTLS_PK_ECDSA = MBEDTLS_PK_SIGALG_ECDSA`, pinning the two enums to
the same values.

The wrapped key's `can_do` accepts it, at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_wrap.c:569`, which
returns true for `MBEDTLS_PK_ECKEY` and `MBEDTLS_PK_ECDSA`.

Signing lands on `ecdsa_opaque_sign_wrap()` at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_wrap.c:303`,
registered as the `.sign_func` of `mbedtls_ecdsa_opaque_info` at line 585, which
forwards to the shared helper `ecdsa_sign_psa()` at line 265.

**This is the place where reading one line would have produced a wrong answer.**
Line 290 of `pk_wrap.c` calls `psa_sign_hash()` with `PSA_ALG_ECDSA(...)`,
randomized ECDSA. Quoting only that line gives the conclusion "the key policy must
permit randomized ECDSA". That is wrong. Lines 281 to 288, immediately above, try
`PSA_ALG_DETERMINISTIC_ECDSA(...)` **first**, and fall through to the randomized
call at line 290 only when the first attempt returns `PSA_ERROR_NOT_PERMITTED`.
The comment at lines 261 to 263 says so outright: "we try both deterministic and
non-deterministic". So **either** policy algorithm works, and Tier 6 does not have
to guess which one to set on the key. This is the same shape of error the ticket
warned about, and it caught me mid-read.

The signature is converted from PSA's raw r||s to the ASN.1 form X.509 needs by
`mbedtls_ecdsa_raw_to_der()` at `pk_wrap.c:298`.

The public key embedded in the CSR is correct for a wrapped key.
`mbedtls_pk_write_pubkey()` has an explicit opaque branch at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pkwrite.c:362`, which
calls `pk_write_opaque_pubkey()` at line 288, which exports through
`psa_export_public_key()` at line 298.

The curve OID is also correct. `mbedtls_pk_write_pubkey_der()` at
`pkwrite.c:370` calls `pk_get_type_ext()`, defined at `pkwrite.c:316`, which
re-queries PSA for an opaque key and maps an ECC key to `MBEDTLS_PK_ECKEY` at line
331, so the named-curve parameter gets written at line 415.

One thing I chased and cleared: `mbedtls_pk_wrap_psa()` never assigns
`ctx->ec_family`, which is zeroed at `pk.c:49`, and the curve lookup
`mbedtls_pk_get_ec_group_id()` reads that field. It is not a bug. That helper, at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_internal.h:72`,
takes a separate branch for `MBEDTLS_PK_OPAQUE` at line 75 that re-reads the
family from PSA attributes and never touches `pk->ec_family`.

Two build-config notes for this path. `MBEDTLS_X509_CSR_WRITE_C` at
`/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.mbedtls:234` selects nothing
at all, yet the writer calls `mbedtls_pk_write_pubkey_der()`, whose definition is
inside `#if defined(MBEDTLS_PK_WRITE_C)` at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pkwrite.c:10`. So
`CONFIG_MBEDTLS_PK_WRITE_C` must be set by hand, at
`/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.tf-psa-crypto:206`. Setting
it also brings in `MBEDTLS_ASN1_WRITE_C` automatically, at
`/opt/zephyr-workspace/zephyr/modules/mbedtls/configs/config-tf-psa-crypto.h:119`.

`mbedtls_x509write_csr_der()` allocates its signature buffer with
`mbedtls_calloc()` at
`/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:282`, so it
needs the heap. Tier 5 already sets `CONFIG_MBEDTLS_ENABLE_HEAP=y` at
`/workspaces/learning-cyber-security/firmware/tier-05-recovery/prj.conf:42`.

If Tier 6 wants PEM rather than DER output, `mbedtls_x509write_csr_pem()` is
behind `#if defined(MBEDTLS_PEM_WRITE_C)` at `x509write_csr.c:297`, whose Kconfig
is at `/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.tf-psa-crypto:156`.
Note that Tier 5 deliberately turned PEM **parsing** off at
`firmware/tier-05-recovery/prj.conf:67` for size reasons, so adding PEM writing
would partly reverse a size decision the course already made and explained. DER
over the wire avoids that.

## 3. The fallback, and what it would cost

The fallback is not needed, since the bridge exists. Recording the cost anyway,
because the ticket asked and because it sets the price of the bridge breaking.

Hand-rolling the CSR means building the `CertificationRequestInfo` SEQUENCE,
hashing it, signing the hash with `psa_sign_hash()`, and wrapping both in the
outer `CertificationRequest` SEQUENCE. Most of the pieces are public API:

| Piece | Available as | Location |
|---|---|---|
| ASN.1 primitives | public header | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/mbedtls/asn1write.h` |
| SubjectPublicKeyInfo | `mbedtls_pk_write_pubkey_der()` | `.../extras/pkwrite.c:370` |
| raw r\|\|s to ASN.1 | `mbedtls_ecdsa_raw_to_der()` | `.../include/mbedtls/psa_util.h:167` |
| Subject Name encoding | **internal only** | `/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509_internal.h:52` |

The expensive item is the last row. `mbedtls_x509_write_names()` is declared in
`library/x509_internal.h`, a private header inside the library directory, not in
`include/mbedtls/`. A fallback would have to either reimplement RDNSequence
encoding or reach into a private header, and the course would then own and have
to explain DER name encoding, which is fiddly and teaches nothing about device
identity.

There is also a subtlety the course would inherit: writing ASN.1 backwards from
the end of a buffer, which is how every one of these helpers works, as
`x509write_csr.c:150` shows with its `c = buf + size`. That idiom is a
constant source of off-by-one errors and is exactly the kind of accidental
complexity a teaching module should not take on.

My judgement: the fallback is a poor trade here, and the bridge is the right
path. Since `mbedtls_pk_wrap_psa()` is unguarded public API compiled into the
build, the fallback should be treated as a contingency to document, not a design
to write.

## 4. Non-exportable persistent keys and what `psa_export_key()` returns

This works exactly as the module wants, and the refusal is a clean, specific
error code.

A key is made persistent by `psa_set_key_id()`, at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/psa/crypto_struct.h:334`.
Reading the body rather than the signature matters: lines 341 to 347 show it
promotes a volatile lifetime to `PSA_KEY_LIFETIME_PERSISTENT` automatically while
preserving the location, so setting an id is sufficient and no separate lifetime
call is required.

`PSA_KEY_LIFETIME_PERSISTENT` is defined at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/psa/crypto_values.h:2347`.

Non-exportable simply means omitting `PSA_KEY_USAGE_EXPORT` from the usage flags.
There is no separate "non-exportable" attribute, so the demonstration is a matter
of what the course does **not** set.

`psa_export_key()` is at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/core/psa_crypto.c:1364`. Its
comment at lines 1387 to 1390 states that export requires the EXPORT flag, and
line 1391 enforces it by passing `PSA_KEY_USAGE_EXPORT` to
`psa_get_and_lock_key_slot_with_policy()`.

That policy check is at `psa_crypto.c:1028`. The refusal is at lines 1051 to 1054:
when `(slot->attr.policy.usage & usage) != usage` it returns
`PSA_ERROR_NOT_PERMITTED`.

`PSA_ERROR_NOT_PERMITTED` is `-133`, at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/psa/crypto_values.h:87`.
Worth writing into the module, since the course already has to keep `err=-113`
and its two causes straight, and `-133` is one transposed digit away from it.

Reading the surrounding function matters here too. Lines 1045 to 1050 of
`psa_crypto.c` strip the EXPORT requirement for keys whose **type** is a public
key. That exemption is keyed on `PSA_KEY_TYPE_IS_PUBLIC_KEY(slot->attr.type)`, and
an ECC **key pair** is not a public key type, so it does not apply. The refusal
stands for the device's private key, which is what section 8 wants to show.

The two halves fit together without conflict. `psa_export_public_key()`, at
`psa_crypto.c:1479`, passes usage `0` at line 1504 under the comment "Exporting a
public key doesn't require a usage flag." This is what makes the whole design
coherent: `mbedtls_pk_wrap_psa()` reaches the public key through
`mbedtls_pk_set_pubkey_from_prv()` at
`/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk.c:141`, which calls
`psa_export_public_key()` at line 150. **So a key with no EXPORT flag can still be
wrapped and still sign a CSR, while refusing to give up its private bytes.** That
is precisely the pairing the module wants to demonstrate.

Persistent keys need storage, and the enabling symbol is not directly settable.
`MBEDTLS_PSA_CRYPTO_STORAGE_C` at
`/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.tf-psa-crypto:313` is a bare
`bool` with no prompt, so putting it in `prj.conf` does nothing. The only thing in
the tree that selects it is `/opt/zephyr-workspace/zephyr/subsys/secure_storage/Kconfig:7`,
`select MBEDTLS_PSA_CRYPTO_STORAGE_C if MBEDTLS_PSA_CRYPTO_C`, under
`menuconfig SECURE_STORAGE` at line 4. So `CONFIG_SECURE_STORAGE=y` is what
actually makes persistent PSA keys work, which lines up with section 8 already
naming the Secure Storage symbols.

Note `SECURE_STORAGE` depends on `!BUILD_WITH_TFM` at line 6, which is fine for
this board but worth knowing before anyone reaches for TF-M.

## What this could not settle by reading

These are owed to the build ticket. I am naming them rather than guessing.

**Whether the config combination actually builds and links.** Everything above is
source and Kconfig reading. `PSA_WANT_*` symbols pass through a generated header,
`/opt/zephyr-workspace/zephyr/modules/mbedtls/configs/config-psa.h:275`, and the
interaction of the Wi-Fi driver's selects with Tier 6's own settings is the kind
of thing only a real `menuconfig` output settles. The build ticket should dump
the resolved `.config` and confirm all four symbols in the Short answer table are
`y`.

**The actual flash and RAM cost.** I found no numbers by reading, and the map's
own rule says a size change is a question and not a saving. Compare `.text`, not
the `.bin`.

**Whether a produced CSR verifies.** I traced the encoder and it looks correct,
but no amount of reading proves the DER on the wire parses. The provisioning
station should run the real CSR through `openssl req -verify` before the course
claims the path works.

**Which ECDSA variant the board actually uses.** Since `ecdsa_sign_psa()` tries
deterministic then randomized, which one succeeds depends on the key policy the
firmware sets and on whether `PSA_WANT_ALG_DETERMINISTIC_ECDSA` is in the build.
That is observable only on the device. It does not affect correctness, but it
does affect whether two CSRs over the same data come out byte-identical, which
the module might want to mention.

**Whether `psa_generate_key()` with a persistent id survives reboot on this flash
map.** That is a Secure Storage and partition question, not an Mbed TLS one, and
the map already flags the `storage` partition as shared with Tier 5's
resume-progress record. Board work.

## Sources

All paths below are inside the `tier2-validate` container.

| Claim | Path and line |
|---|---|
| Workspace pins Mbed TLS 4.1.0 | `/opt/zephyr-workspace/modules/crypto/mbedtls/ChangeLog:3` |
| `setup_opaque` renamed to `wrap_psa` | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/ChangeLog:162` |
| Rename rationale | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/docs/1.0-migration-guide.md:891` |
| `mbedtls_pk_wrap_psa()` declared, unguarded | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/mbedtls/pk.h:239` |
| `mbedtls_pk_wrap_psa()` defined | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk.c:158` |
| ECC branch guarded on `ECC_PUBLIC_KEY` | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk.c:178` |
| Returns `FEATURE_UNAVAILABLE` otherwise | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk.c:186` |
| `extras/` added to build | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/CMakeLists.txt:425` |
| `extras/` globs all `*.c` | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/CMakeLists.txt:1` |
| Zephyr links `extras` | `/opt/zephyr-workspace/zephyr/modules/mbedtls/CMakeLists.txt:42` |
| `pub_raw` sized 0 by default | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/mbedtls/pk.h:91` |
| Raised only under `ECC_PUBLIC_KEY` | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/mbedtls/pk.h:92` |
| `pub_raw` field in context | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/mbedtls/pk.h:124` |
| Keypair logic omits public-key type | `/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.psa.logic:37` |
| `ECC_PUBLIC_KEY` standalone symbol | `/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.psa.auto:279` |
| Wi-Fi driver selects it under WPA3 | `/opt/zephyr-workspace/zephyr/drivers/wifi/esp32/Kconfig.esp32:400` |
| `csr_set_key()` takes a pk context | `/opt/zephyr-workspace/modules/crypto/mbedtls/include/mbedtls/x509_csr.h:248` |
| CSR encoder function | `/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:132` |
| Backwards buffer idiom | `/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:150` |
| SPKI embedded | `/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:186` |
| Subject written | `/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:194` |
| Hash computed | `/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:212` |
| ECDSA chosen by key type | `/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:223` |
| Signing call | `/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:229` |
| Signature buffer uses heap | `/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:282` |
| PEM output gated | `/opt/zephyr-workspace/modules/crypto/mbedtls/library/x509write_csr.c:297` |
| `pk_sign_ext()` delegates non-PSS | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk.c:1373` |
| Enums pinned equal | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/mbedtls/private/pk_private.h:24` |
| Opaque `can_do` accepts ECDSA | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_wrap.c:569` |
| Opaque sign wrapper | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_wrap.c:303` |
| "try both" comment | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_wrap.c:261` |
| Deterministic tried first | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_wrap.c:281` |
| Randomized fallback | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_wrap.c:290` |
| raw to DER conversion | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_wrap.c:298` |
| `.sign_func` registration | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_wrap.c:585` |
| Opaque pubkey branch | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pkwrite.c:362` |
| Opaque pubkey export | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pkwrite.c:298` |
| `pk_get_type_ext()` maps opaque ECC | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pkwrite.c:331` |
| Curve param written | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pkwrite.c:415` |
| `pkwrite.c` gated on `PK_WRITE_C` | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pkwrite.c:10` |
| Opaque branch ignores `ec_family` | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk_internal.h:75` |
| `set_pubkey_from_prv()` exports public only | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/extras/pk.c:150` |
| `CSR_WRITE_C` selects nothing | `/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.mbedtls:234` |
| `PK_WRITE_C` symbol | `/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.tf-psa-crypto:206` |
| `ASN1_WRITE_C` implied | `/opt/zephyr-workspace/zephyr/modules/mbedtls/configs/config-tf-psa-crypto.h:119` |
| `PEM_WRITE_C` symbol | `/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.tf-psa-crypto:156` |
| `psa_set_key_id()` promotes lifetime | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/psa/crypto_struct.h:341` |
| `PSA_KEY_LIFETIME_PERSISTENT` | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/psa/crypto_values.h:2347` |
| `psa_export_key()` | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/core/psa_crypto.c:1364` |
| EXPORT flag required | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/core/psa_crypto.c:1391` |
| Policy check returns NOT_PERMITTED | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/core/psa_crypto.c:1051` |
| Public-key-type exemption only | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/core/psa_crypto.c:1045` |
| `PSA_ERROR_NOT_PERMITTED` is -133 | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/include/psa/crypto_values.h:87` |
| `psa_export_public_key()` needs no flag | `/opt/zephyr-workspace/modules/crypto/tf-psa-crypto/core/psa_crypto.c:1504` |
| `PSA_CRYPTO_STORAGE_C` promptless | `/opt/zephyr-workspace/zephyr/modules/mbedtls/Kconfig.tf-psa-crypto:313` |
| Only `SECURE_STORAGE` selects it | `/opt/zephyr-workspace/zephyr/subsys/secure_storage/Kconfig:7` |
| Tier 5 heap already on | `/workspaces/learning-cyber-security/firmware/tier-05-recovery/prj.conf:42` |
| Tier 5 PEM parsing off | `/workspaces/learning-cyber-security/firmware/tier-05-recovery/prj.conf:67` |
| Tier 5 ECDSA and P-256 on | `/workspaces/learning-cyber-security/firmware/tier-05-recovery/prj.conf:89` |
