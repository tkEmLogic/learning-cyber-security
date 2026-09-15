# Presenting a TLS client certificate from a non-exportable PSA key on Zephyr 4.4.2

**Research question:** [GitHub issue #138](https://github.com/tkEmLogic/learning-cyber-security/issues/138), part of map [#132](https://github.com/tkEmLogic/learning-cyber-security/issues/132)

**Access and review date:** 16 September 2026

**Status:** Research. Every claim below is read from the pinned Zephyr 4.4.2 tree, from the Mbed TLS and TF-PSA-Crypto modules that tree pins, or from the firmware in this repository. Nothing here has been run on the board yet.

## Short answer

Yes, with one piece of plumbing that Zephyr does not provide.

The cryptography works and this repository already proves it on the board. `mbedtls_pk_wrap_psa()` builds an Mbed TLS private key context that holds only a PSA key identifier, signs through `psa_sign_hash()`, never exports the private half, and never destroys the key when the context is freed. Tier 6 already calls it to sign the certification request with key `0x00000601`, the same non-exportable key Tier 7 wants to authenticate with.

What does not work is Zephyr's socket TLS layer. `TLS_CREDENTIAL_PRIVATE_KEY` is fed straight to `mbedtls_pk_parse_key()` as a byte buffer, there is no credential type and no socket option that accepts a key identifier, and the credential type switch ends in `default: return -EINVAL`. A PSA key id handed to `tls_credential_add()` is rejected at `setsockopt()` time, before any handshake starts.

So the Operational key does **not** have to become exportable. Tier 7 keeps the Tier 6 property. The cost is moving off `zsock` TLS for the mutually authenticated connection, and the cheapest honest way to do that is an application-registered socket implementation, described as option A in section 6.

One constraint travels with that answer. In TLS 1.2 the client signs the CertificateVerify with the negotiated ciphersuite's own hash, so a SHA-384 ciphersuite would ask a key whose policy says SHA-256 to do something it is not permitted to do, and the handshake would fail with no retry. Section 4 gives the evidence and the two ways to prevent it.

## Versions, and where they were read

The Zephyr workspace is **not** on the host at `/opt/zephyr-workspace`. It lives at that path **inside the long-lived podman container** `tier2-validate`. Every path below prefixed `/opt/zephyr-workspace` was read with `podman exec tier2-validate ...`.

| Component | Version | How it was confirmed |
| --- | --- | --- |
| Zephyr | 4.4.2 | `git -C /opt/zephyr-workspace/zephyr describe --tags` prints `v4.4.2` at commit `dccb0959963`, and `zephyr/VERSION` reads major 4, minor 4, patchlevel 2. |
| Mbed TLS | 4.1.0 | `modules/crypto/mbedtls/include/mbedtls/build_info.h` defines `MBEDTLS_VERSION_STRING "4.1.0"`. |
| TF-PSA-Crypto | 1.1.0 | `modules/crypto/tf-psa-crypto/include/tf-psa-crypto/build_info.h` defines `TF_PSA_CRYPTO_VERSION_STRING "1.1.0"`. |

The public `v4.4.2` tag was checked independently against GitHub. `https://api.github.com/repos/zephyrproject-rtos/zephyr/git/ref/tags/v4.4.2` resolves, and `https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v4.4.2/include/zephyr/net/tls_credentials.h` is byte-identical to the copy in the container.

This version split matters more than it looks. Zephyr 4.4 moved crypto out of Mbed TLS into a separate TF-PSA-Crypto module, and the 4.4 migration guide (`doc/releases/migration-guide-4.4.rst`, lines 1446 to 1455 and 1528) records both that move and the removal of `CONFIG_MBEDTLS_USE_PSA_CRYPTO`. Any article that tells you to set `MBEDTLS_USE_PSA_CRYPTO` or to call `mbedtls_pk_setup_opaque()` is describing Mbed TLS 3.x and does not apply here. `mbedtls_pk_setup_opaque` does not exist in this tree at all, in either the library or Zephyr.

## 1. Does Zephyr 4.4.2 support client certificate authentication, and under which options

Yes, through the ordinary credential store, with no new socket option.

`include/zephyr/net/tls_credentials.h` defines the complete credential type list: `TLS_CREDENTIAL_NONE`, `TLS_CREDENTIAL_CA_CERTIFICATE`, `TLS_CREDENTIAL_PUBLIC_CERTIFICATE`, `TLS_CREDENTIAL_PRIVATE_KEY`, `TLS_CREDENTIAL_PSK` and `TLS_CREDENTIAL_PSK_ID`. `TLS_CREDENTIAL_SERVER_CERTIFICATE` is a plain alias of `TLS_CREDENTIAL_PUBLIC_CERTIFICATE`, kept for compatibility, and the header's own comment on the public type says "A public **client** or server certificate. Use this to register your own certificate."

The mechanism is: register the certificate as `TLS_CREDENTIAL_PUBLIC_CERTIFICATE` and the key as `TLS_CREDENTIAL_PRIVATE_KEY` under the **same** secure tag, then name that tag in `TLS_SEC_TAG_LIST`. `tls_mbedtls_set_credentials()` in `subsys/net/lib/sockets/sockets_tls.c` (line 1524) walks every credential on every tag in the list, records whether an own certificate was seen, and afterwards calls `tls_set_own_cert()`, which is a one-line wrapper around `mbedtls_ssl_conf_own_cert()` (line 1434).

| Kconfig symbol | Needed for | State in Tier 6 |
| --- | --- | --- |
| `CONFIG_NET_SOCKETS_SOCKOPT_TLS` | The secure socket layer itself. | Already `y`. |
| `CONFIG_TLS_CREDENTIALS` | The credential store `tls_credential_add()` writes into. | Already `y`. |
| `CONFIG_MBEDTLS_X509_CRT_PARSE_C` | Every certificate path in `sockets_tls.c` is inside `#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)`. Without it the own-certificate and private-key functions return `-ENOTSUP`. | Already `y`. |
| `CONFIG_MBEDTLS_PK_PARSE_C` | The private key parser. Selected automatically by `MBEDTLS_X509_USE_C`, which `MBEDTLS_X509_CRT_PARSE_C` selects. | Already `y` by selection. |
| `CONFIG_TLS_MAX_CREDENTIALS_NUMBER` | Total credentials in the store. Tier 7 needs three: CA, own certificate, private key. Default is 4. | Fine at the default, but it is now load bearing. |
| `CONFIG_NET_SOCKETS_TLS_MAX_CREDENTIALS` | Credentials attachable to one socket. Default 4. | Fine at the default. |

Two practical notes on that path. First, credentials are validated eagerly: `tls_check_credentials()` runs at `setsockopt(TLS_SEC_TAG_LIST)` time and calls `mbedtls_pk_parse_key()` on the key there, so a malformed key fails at `setsockopt()` with `-EINVAL`, not at `connect()`. Second, the default volatile backend in `subsys/net/lib/tls_credentials/tls_credentials.c` stores the caller's **pointer**, not a copy, so whatever buffer Tier 7 hands it must outlive the connection.

No socket option is involved. `TLS_PEER_VERIFY` controls whether *we* verify the peer; it does not control whether we send a certificate. On the client, mbedTLS sends the configured own certificate when the server asks for one.

## 2. Can the private key be a PSA key identifier instead of key bytes

Through `tls_credential_add()`, no. Four independent facts, all from the 4.4.2 tree.

The credential type enum has no opaque, PSA, handle or key-id member. The list in section 1 is the whole of it.

`tls_set_private_key()` in `sockets_tls.c` is the only consumer of `TLS_CREDENTIAL_PRIVATE_KEY`, and it is unconditional:

```c
static int tls_set_private_key(struct tls_context *tls,
			       struct tls_credential *priv_key)
{
#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	int err;

	err = mbedtls_pk_parse_key(&tls->priv_key, priv_key->buf,
				   priv_key->len, NULL, 0);
	if (err != 0) {
		return -EINVAL;
	}
```

There is no branch on length, no "this is a key id" special case, and the `switch` in `tls_set_credential()` ends `default: return -EINVAL;`, so a hypothetical new type would be rejected rather than ignored.

None of the twenty `ZSOCK_TLS_*` socket options in `include/zephyr/net/socket.h` takes a key. They are the secure tag list, hostname, ciphersuite list and used ciphersuite, peer verify, DTLS role, ALPN list, two DTLS handshake timeouts, certificate no-copy, native, session cache and session cache purge, four DTLS connection-id options, DTLS handshake on connect, certificate verify result and certificate verify callback.

`psa_key_id_t`, `mbedtls_svc_key_id_t` and `mbedtls_pk_wrap_psa` appear nowhere in `subsys/net/lib/tls_credentials/`, `subsys/net/lib/sockets/` or `include/zephyr/net/`. The only PSA key id users under `subsys/net` are WireGuard, Wi-Fi credentials and IPv6 privacy extensions.

`CONFIG_TLS_CREDENTIALS_BACKEND_PROTECTED_STORAGE` is not the answer either, on two counts. It `depends on BUILD_WITH_TFM`, which an ESP32-C6 cannot satisfy, and it is storage at rest only: `tls_credentials_trusted.c` calls `psa_ps_get()` into a freshly `k_malloc`'d buffer and the raw private key bytes sit in application RAM for the whole handshake. It is a byte blob store, not a key store.

## 3. But the library underneath can, and this firmware already does it

The capability Tier 7 needs exists one layer down, in TF-PSA-Crypto 1.1.0.

`mbedtls_pk_setup_opaque()` was removed in the 4.0 rework. The design note that records this is in the tree at `modules/crypto/tf-psa-crypto/docs/architecture/pk-4.md`, under "Functionality that is removed from PK": "Direct support for opaque keys (`mbedtls_pk_setup_opaque()`, `mbedtls_pk_setup_rsa_alt()`, etc.). Go via PSA instead."

The replacement is `mbedtls_pk_wrap_psa()`, declared in `modules/crypto/tf-psa-crypto/include/mbedtls/pk.h` at line 239:

```c
/**
 * \brief Populate a PK context by wrapping a PSA key pair.
 *
 * The PSA key must be an EC or RSA key pair (FFDH is not suported in PK).
 *
 * The resulting context can only perform operations that are allowed by the
 * key's policy. Additionally, it currently has the following limitations:
 * - restartable operations can't be used;
 * - for RSA keys, signature verification is not supported.
 *
 * \warning The PSA wrapped key must remain valid as long as the wrapping PK
 *          context is in use ...
 */
int mbedtls_pk_wrap_psa(mbedtls_pk_context *ctx,
                        const mbedtls_svc_key_id_t key);
```

Four things make it safe for a factory-provisioned key.

It never reads the private half. The implementation in `extras/pk.c` reads the key's attributes, selects `mbedtls_ecdsa_opaque_info`, stores the identifier in `ctx->priv_id`, and calls `mbedtls_pk_set_pubkey_from_prv()`, which is `psa_export_public_key()`. The PSA Crypto API documents that as always allowed: `modules/crypto/tf-psa-crypto/include/psa/crypto.h` line 797 reads "Exporting a public key object or the public part of a key pair is always permitted, regardless of the key's usage flags."

It does not take ownership. The doc comment on `mbedtls_pk_free()` in `pk.h` line 190 says so outright: "For contexts that have been populated with `mbedtls_pk_wrap_psa()`, this does not free the underlying PSA key and you still need to call `psa_destroy_key()` independently if you want to destroy that key." The implementation in `extras/pk.c` line 56 matches, with the comment "The ownership of the priv_id key for opaque keys is external of the PK module" and a guard on `pk_info->type != MBEDTLS_PK_OPAQUE`. A wrapped persistent key survives the context being freed. This is the single most dangerous thing that could have gone wrong and it does not.

There is a neighbouring function that would destroy the key, and Tier 7 must not use it. `mbedtls_pk_copy_from_psa()` looks like a reasonable alternative and is not: its own doc comment says it "only copies the key material but discards policy information entirely", so the resulting context is **not** opaque, and `mbedtls_pk_free()` therefore falls into the branch that calls `psa_destroy_key()`. Copying also requires an exportable key, so it would fail on `0x00000601` anyway, but the failure mode if the key were ever made exportable is the loss of the factory key. Use `mbedtls_pk_wrap_psa()` and nothing else.

Signing goes through PSA. `ecdsa_opaque_sign_wrap()` in `extras/pk_wrap.c` calls `ecdsa_sign_psa()`, which calls `psa_sign_hash()` on the key id, first with `PSA_ALG_DETERMINISTIC_ECDSA(hash)` and, on `PSA_ERROR_NOT_PERMITTED`, again with `PSA_ALG_ECDSA(hash)`. Tier 6's key policy is `PSA_ALG_ECDSA(PSA_ALG_SHA_256)`, so the second attempt is the one that succeeds.

`mbedtls_ssl_conf_own_cert()` accepts it without inspection. Its doc comment in `modules/crypto/mbedtls/include/mbedtls/ssl.h` line 3550 states it performs no check that the key matches the certificate, so it certainly performs no export. Its only client-side note is that "only the first call has any effect", which is exactly the one-certificate case Tier 7 has.

The decisive corroboration is in this repository. `firmware/tier-06-factory-identity/src/identity.c` lines 296 to 298 already do it:

```c
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	int err = mbedtls_pk_wrap_psa(&pk, key_id);
```

and then `mbedtls_x509write_csr_set_key(&csr, &pk)`. The certification request Tier 6 ships is signed by key `0x00000601` through this exact wrapper, on the board, with no export. Zephyr 4.4.2 contains one other use of the same call, `samples/tfm_integration/psa_crypto/src/psa_crypto.c` line 415, and it is also a certification request rather than a handshake.

So the gap between where Tier 6 is and where Tier 7 needs to be is not cryptographic. It is the four-line body of `tls_set_private_key()`.

## 4. The handshake path, checked end to end for TLS 1.2

The pinned build is TLS 1.2 only. `CONFIG_MBEDTLS_SSL_PROTO_TLS1_3` is not set in the generated configuration for either the baseline or the TLS research build, and the firmware opens `IPPROTO_TLS_1_2`. Everything below is the TLS 1.2 client path.

The client's CertificateVerify is written by `ssl_write_certificate_verify()` in `modules/crypto/mbedtls/library/ssl_tls12_client.c`. It picks the hash from the negotiated ciphersuite's MAC rather than by consulting the key, which for `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` means SHA-256 and matches the Tier 6 policy exactly. It writes the signature algorithm byte with `mbedtls_ssl_sig_from_pk()`, which in Mbed TLS 4.1 reads `mbedtls_pk_get_key_type()`; for a wrapped context that is the stored `psa_type`, an ECC key pair, so the byte is ECDSA. It then calls `mbedtls_pk_sign_restartable()`, which falls through to the ordinary sign when `MBEDTLS_ECP_RESTARTABLE` is off, as it is here, and so reaches the opaque wrapper.

Nothing in that path exports anything and nothing calls `mbedtls_pk_check_pair()`.

There is a hard constraint on the ciphersuite list, and it is the most likely way to break this in practice. The shortcut quoted above means the client signs the CertificateVerify with **SHA-384 whenever the negotiated ciphersuite's MAC is SHA-384**, even for a P-256 key, and the comment in the source admits it is a shortcut. The Tier 6 key policy is `PSA_ALG_ECDSA(PSA_ALG_SHA_256)`, so `psa_sign_hash()` would return `PSA_ERROR_NOT_PERMITTED` for both the deterministic and the randomised attempt, and TLS 1.2 has no fallback loop: the handshake dies. Today this cannot happen, because `prj.conf` enables exactly one ciphersuite, `CONFIG_MBEDTLS_CIPHERSUITE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, whose MAC is SHA-256. Tier 7 has two ways to keep it that way, and should do both: keep the ciphersuite list pinned to SHA-256 suites, and provision the Operational key with `PSA_ALG_ECDSA(PSA_ALG_ANY_HASH)` rather than a single hash. The PSA Crypto API permits `PSA_ALG_ANY_HASH` in a key policy but not in an operation call, and it is the same wildcard Mbed TLS itself chooses when it synthesises a policy for an EC signing key (`extras/pk.c` line 620). Widening the hash does not widen what the key can do: it still signs only, and it still cannot be exported.

The narrower policy is also what Tier 6 taught with, so if Tier 7 widens it, that is a change the module has to explain rather than make quietly. Note that `PSA_ALG_ECDSA(PSA_ALG_ANY_HASH)` is still a signing-only ECDSA policy; the alternative of leaving it at SHA-256 is defensible as long as the ciphersuite pin is treated as a control and asserted at build time.

There is one further fragility worth writing into the firmware as an assertion rather than discovering later. Mbed TLS decides elsewhere whether a key *can* do a given signature algorithm using `mbedtls_pk_can_do_psa()`, which for an opaque context calls `is_psa_key_compatible_with_alg_usage()` and finally `is_alg_compatible_with_key()` in `extras/pk.c`. That last function requires an exact algorithm match, and its only wildcard is `PSA_ALG_ANY_HASH`, which bridges hashes but not deterministic against randomised ECDSA. The algorithm it checks is `MBEDTLS_PK_ALG_ECDSA(hash)`, defined in `pk.h` line 158 as `PSA_ALG_DETERMINISTIC_ECDSA(hash)` when `PSA_WANT_ALG_DETERMINISTIC_ECDSA` is defined and `PSA_ALG_ECDSA(hash)` otherwise. In the current build `CONFIG_PSA_WANT_ALG_DETERMINISTIC_ECDSA is not set`, so it resolves to `PSA_ALG_ECDSA(SHA_256)` and matches the Tier 6 policy. If any future tier, or a Wi-Fi or supplicant option, turns deterministic ECDSA on, that match silently becomes false. It would not break today's TLS 1.2 CertificateVerify, which never asks, but it would break TLS 1.3, a server role, and any signature-algorithm negotiation that does ask. Tier 7 should carry a compile-time probe, in the same spirit as the `release_policy.c` probes Tier 4 added.

Budget the stack. Tier 6 already had to raise `CONFIG_SHELL_STACK_SIZE` to 8192 because loading this key out of Secure Storage and signing a certification request overran 2 KiB, and the symptom read as a fault inside the crypto library. The handshake performs the same load and sign, on whichever thread calls `connect()`.

## 5. Does `CONFIG_MBEDTLS_HAVE_TIME_DATE=n` affect presenting a client certificate

No. It affects nothing on the sending side, and it would affect nothing even if it were `y`.

A grep for `valid_to`, `valid_from`, `time_is_past` and `time_is_future` across `modules/crypto/mbedtls/library/ssl_*.c` returns no matches at all. Mbed TLS never checks the validity dates of the certificate it is about to present. `mbedtls_ssl_conf_own_cert()` performs no checks either, as quoted in section 3.

What the symbol does control is verification of certificates we *receive*. With it off, `mbedtls_x509_time_is_past()` and `mbedtls_x509_time_is_future()` in `library/x509.c` are compiled as unconditional `return 0`, and in `library/x509_crt.c` the block that sets `MBEDTLS_X509_BADCERT_EXPIRED` and `MBEDTLS_X509_BADCERT_FUTURE` during chain verification sits inside `#if defined(MBEDTLS_HAVE_TIME_DATE)` and is compiled out.

Two consequences for Tier 7, both belonging in the weakness ledger rather than in the design.

The server validates our client certificate against the **server's** clock, not ours. Our configuration is irrelevant to that. The certificate the Tier 7 CA issues must carry a validity window the service accepts, and if the service enforces it, a device with a stale certificate is refused at the handshake with no local explanation.

The device cannot notice that its own Operational certificate has expired. It will keep presenting it until the service refuses. It equally cannot reject an expired service certificate. The Tier 6 `prj.conf` already states this and names Tier 8 as where credential lifetime becomes the subject; Tier 7 adds a second certificate to the same blind spot and should say so.

`CONFIG_MBEDTLS_PEM_PARSE_C=n` is likewise not an obstacle. Everything on this path is DER, the certificate the station returns is DER, and `mbedtls_x509_crt_parse_der_nocopy()` is what `tls_add_own_cert()` uses for a non-PEM buffer anyway.

## 6. The real options, and what each costs

| Option | Keeps the key non-exportable | Forks Zephyr | Keeps Zephyr's `http_client` | Rough cost |
| --- | --- | --- | --- | --- |
| A. Application-registered socket implementation | Yes | No | Yes | A few hundred lines of firmware, written once. |
| B. Patch `sockets_tls.c` out of tree | Yes | Yes | Yes | Roughly twenty lines of diff, but the Learner forks a patched RTOS. |
| C. Drive mbedTLS directly on a plain TCP socket | Yes | No | No | Similar to A, plus hand-rolled HTTP. |
| D. Make the Operational key exportable | **No** | No | Yes | Small code change, large teaching loss. |
| E. Keep the Factory key opaque, give the Operational key export | **No, dishonestly** | No | Yes | Worse than D, because it looks like the property was kept. |

**Option A, recommended.** Zephyr's socket layer is extensible from the application. `NET_SOCKET_REGISTER` is a public macro in `include/zephyr/net/socket.h` line 1216, and `zsock_socket()` dispatches by walking the registered implementations in priority order and asking each one's `is_supported(family, type, proto)`. Zephyr's own TLS layer is registered exactly this way, at the end of `sockets_tls.c`: `NET_SOCKET_REGISTER(tls, CONFIG_NET_SOCKETS_TLS_PRIORITY, NET_AF_UNSPEC, tls_is_supported, ztls_socket)`. In the pinned build `CONFIG_NET_SOCKETS_TLS_PRIORITY` is 45 and `CONFIG_NET_SOCKETS_PRIORITY_DEFAULT` is 50. Zephyr's `protocol_check()` claims only `IPPROTO_TLS_1_0` through `IPPROTO_TLS_1_3` and the DTLS range, so a course-specific protocol number outside those ranges does not collide at all and does not even need to win on priority. The implementation supplies a `socket_op_vtable`, owns its own `mbedtls_ssl_context`, calls `mbedtls_pk_wrap_psa()` and `mbedtls_ssl_conf_own_cert()`, and hands back an ordinary file descriptor. Because `http_client_req()` works on a descriptor through `zsock_send()` and `zsock_recv()`, it continues to work unchanged. This is the honest option: it uses a documented extension point, it changes no Zephyr source, and the code that makes the key opaque is code the Learner can read.

**Option B.** Add a `TLS_CREDENTIAL_PSA_KEY_ID` type and a `mbedtls_pk_wrap_psa()` branch in `tls_set_private_key()`, `tls_check_priv_key()` and the `tls_set_credential()` switch. It is by far the smallest diff and it is the change that should eventually go upstream. It is a poor fit for this course, because the deliverable is a repository the Learner forks and builds, and a patched Zephyr means the Learner's build no longer matches the pinned baseline. Worth filing upstream regardless; the capability is there and only the wiring is missing.

**Option C.** Skip `zsock` TLS and run `mbedtls_ssl_*` over a plain TCP socket with `mbedtls_ssl_set_bio()` callbacks. Cryptographically identical to A. The difference is that Zephyr's `http_client` cannot be used, because it sends and receives on a descriptor, so Tier 7 would write its own request and response handling. Option A is this option plus a descriptor wrapper, which is why A is preferred.

**Option D.** Add `PSA_KEY_USAGE_EXPORT` to the Operational key, export it with `mbedtls_pk_copy_from_psa()` and `mbedtls_pk_write_key_der()`, and register the DER as `TLS_CREDENTIAL_PRIVATE_KEY`. This works today with no new plumbing. It also directly contradicts section 8 of the specification, invalidates exercise `E-6-04`, and puts the plaintext private key in a heap buffer for the lifetime of the credential, since the volatile backend keeps the caller's pointer. If the course takes this option it has to say out loud that Tier 7 undid Tier 6, which is a bad lesson to teach in the tier about device identity.

**Option E.** Keeping the Factory key opaque while quietly making the Operational key exportable is worse than D. The Learner sees "non-exportable" in Tier 6 and a working mutual TLS in Tier 7 and concludes the two are compatible, which is the opposite of what the code does.

## ESP32-C6 specifics

There is no TF-M and no secure element on this part. PSA is TF-PSA-Crypto in software, and persistent keys live in Zephyr's `SECURE_STORAGE` with the `DEVICE_ID_HASH` AEAD key provider, whose limits the Tier 6 `prj.conf` already documents at length: the identifier hashed is the factory MAC, which the device broadcasts. "Non-exportable" here is an API-boundary property, not a hardware one. Nothing in this research changes that, and Tier 7 should not let a working mutual TLS handshake imply otherwise.

`CONFIG_TLS_CREDENTIALS_BACKEND_PROTECTED_STORAGE` is unavailable, because it `depends on BUILD_WITH_TFM`.

The board has no real-time clock, which is why `CONFIG_MBEDTLS_HAVE_TIME_DATE=n`; see section 5.

The build is TLS 1.2 only. If Tier 7 or a later tier enables `CONFIG_MBEDTLS_SSL_PROTO_TLS1_3`, re-check section 4: TLS 1.3 signs through `mbedtls_pk_sign_ext()`, which for ECDSA simply forwards to `mbedtls_pk_sign()` and stays opaque, but its signature algorithm selection does consult the certificate, and `pk-4.md` records a known upstream defect (Mbed TLS issue 10233) where TLS 1.3 checks only the certificate's public key and not the private key's policy.

## What was not verified

Nothing here has been built or run. The claim that option A works is read from the dispatch code and the registration macro; it has not been compiled. A spike that registers a trivial implementation and completes one mutually authenticated handshake against the course service is the next step, and it is small.

Vendor and downstream forks were not examined. Some vendor SDKs map secure tags onto modem- or radio-held key stores where the key genuinely never enters Zephyr memory. That is not available here and is mentioned only so the option is not confused with upstream behaviour.

`CONFIG_TLS_CREDENTIAL_FILENAMES` was read but is not an option: it `depends on NET_SOCKETS_OFFLOAD`, which this build does not use, and it names files in a vendor filesystem rather than PSA keys.

## Source register

| Source | Type | Where |
| --- | --- | --- |
| Zephyr 4.4.2 tree, tag `v4.4.2`, commit `dccb0959963` | Primary source code | `/opt/zephyr-workspace/zephyr` inside the podman container `tier2-validate`; mirrored at `https://github.com/zephyrproject-rtos/zephyr/tree/v4.4.2` |
| `include/zephyr/net/tls_credentials.h` | Primary source code | Credential type enum and `tls_credential_add()` |
| `include/zephyr/net/socket.h` | Primary source code | `ZSOCK_TLS_*` option list, `NET_SOCKET_REGISTER` at line 1216 |
| `subsys/net/lib/sockets/sockets_tls.c` | Primary source code | `tls_set_private_key()` 1449, `tls_set_own_cert()` 1434, `tls_set_credential()` 1486, `tls_mbedtls_set_credentials()` 1524, `tls_check_priv_key()` 1954, `protocol_check()` 2749, registration at end of file |
| `subsys/net/lib/tls_credentials/Kconfig` and `tls_credentials.c` and `tls_credentials_trusted.c` | Primary source code | Backends, `TLS_MAX_CREDENTIALS_NUMBER`, pointer-not-copy storage |
| `doc/releases/migration-guide-4.4.rst` | Primary, normative for this version | Mbed TLS 4.1.0 and TF-PSA-Crypto 1.1.0 move, removal of `CONFIG_MBEDTLS_USE_PSA_CRYPTO` |
| `https://docs.zephyrproject.org/4.4.2/connectivity/networking/api/sockets.html` | Primary documentation | TLS credentials subsystem section; says DER by default, PEM optional, and says nothing about PSA keys. There is no separate `tls_credentials.html` page in 4.4.2; that URL returns 404. |
| Mbed TLS 4.1.0, `include/mbedtls/ssl.h` | Primary source code | `mbedtls_ssl_conf_own_cert()` at 3550 |
| Mbed TLS 4.1.0, `library/ssl_tls12_client.c`, `library/x509.c`, `library/x509_crt.c` | Primary source code | CertificateVerify signing, validity-date handling |
| TF-PSA-Crypto 1.1.0, `include/mbedtls/pk.h`, `extras/pk.c`, `extras/pk_wrap.c` | Primary source code | `mbedtls_pk_wrap_psa()` 239, `mbedtls_pk_free()` ownership, `is_alg_compatible_with_key()`, opaque ECDSA sign wrapper |
| TF-PSA-Crypto 1.1.0, `docs/architecture/pk-4.md` | Primary design document | Removal of `mbedtls_pk_setup_opaque()`, TLS 1.3 own-key defect |
| TF-PSA-Crypto 1.1.0, `include/psa/crypto.h` | Primary, PSA Crypto API | Public key export always permitted regardless of usage flags, line 797 |
| `https://arm-software.github.io/psa-api/crypto/1.5/api/keys/policy.html` | Primary, normative specification | Key policies: permitted algorithm must match exactly, `PSA_ALG_ANY_HASH` wildcard is legal in a policy but not in an operation call, `PSA_ALG_ECDSA` and `PSA_ALG_DETERMINISTIC_ECDSA` are equivalent for verification but not for signing, public key export always permitted |
| `firmware/tier-06-factory-identity/src/identity.c` and `prj.conf` | This repository | Existing `mbedtls_pk_wrap_psa()` use, key policy, `HAVE_TIME_DATE` and stack-size reasoning |
