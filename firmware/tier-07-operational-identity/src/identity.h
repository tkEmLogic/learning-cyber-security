/*
 * Tier 7 device identity.
 *
 * Tier 6 put two identity models behind this interface, selected by a Kconfig
 * choice: a shared key compiled into every image, and a key generated on the
 * device whose private half never leaves. Tier 7 builds only the second. It
 * takes a per-device Factory identity as given and asks what that identity is
 * allowed to authorize, and a shared image has nothing it can prove is its own
 * to claim with. Tier 6 still publishes both halves of that comparison.
 *
 * Tier 7 adds a second identity to the factory model, settled on issue #140.
 * The device keeps its Factory key and certificate for life and gains an
 * Operational key and certificate that name an owner. The two are different
 * roles rather than a ranking: the claim endpoint takes only the Factory
 * identity and the download endpoints take only the Operational one.
 *
 * Nothing about *timing* lives here. The Claim window, its nonce and its poll
 * are claim.h, which calls down into the primitives below. That boundary is
 * the module's too: the nonce and the window are the claim, the key and the
 * certificate are the identity.
 */

#ifndef COURSE_IDENTITY_H
#define COURSE_IDENTITY_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* The longest device identifier the course issues, plus a terminator. */
#define COURSE_DEVICE_ID_MAX 64

/*
 * Bring up the identity subsystem.
 *
 * For the factory build this mounts settings, which is also what the PSA
 * Secure Storage ITS store writes through, and loads any certificate already
 * held. It reports success even when the device is unprovisioned: having no
 * identity is a state, not a failure.
 */
int course_identity_init(void);

/* Whether this device holds a usable identity. */
bool course_identity_is_provisioned(void);

/*
 * The identifier this device reports.
 *
 * For the factory build it is read out of the subject of the stored Factory
 * certificate, so the certificate is the one source of truth and the device
 * cannot report a name it cannot prove. For the shared build it is the
 * compiled-in name that every image shares.
 *
 * Returns NULL when the device is unprovisioned. A caller that treats NULL as
 * "use the old shared name" has reintroduced the fallback section 11 forbids,
 * so every caller is expected to handle it as a refusal to speak.
 */
const char *course_identity_device_id(void);

/*
 * Fingerprint of the Factory certificate, for the boot banner.
 *
 * Tier 6 called this course_identity_fingerprint(), when there was one
 * certificate and no question to answer. Tier 7 splits it in two rather than
 * growing a parameter, because the banner is its only caller and a banner that
 * printed the wrong one would be the exact defect #140 found in
 * cert_settings_set().
 */
const char *course_identity_factory_fingerprint(void);

/*
 * Fingerprint of the Operational certificate, for the boot banner. Empty when
 * this device holds none.
 */
const char *course_identity_operational_fingerprint(void);

#ifdef CONFIG_COURSE_IDENTITY_FACTORY

/*
 * Generate the device key, if there is not one already.
 *
 * The key is marked non-exportable at the PSA boundary. That marking is real
 * and it is not a boundary against a flash attacker: see
 * course_identity_try_export(), which exists so a Learner can watch both
 * halves of that sentence being true at once.
 */
int course_identity_generate_key(void);

/*
 * Build a certification request for the device key, carrying the Bootstrap
 * credential inside the signed structure.
 *
 * The credential goes inside rather than beside it so that it is covered by
 * the request's own self-signature and cannot be lifted onto another key.
 */
int course_identity_build_csr(const char *credential, unsigned char *out,
			      size_t out_size, size_t *out_len);

/* Store a Factory certificate issued by the provisioning station. */
int course_identity_store_certificate(const unsigned char *der, size_t len);

/*
 * Ask the course API to hand over the device private key.
 *
 * This always fails, and it is here to be run rather than to be useful. It is
 * evidence row E-6-04, and it is read beside E-6-05, which reads the same key
 * out of a flash dump and succeeds.
 */
int course_identity_try_export(void);

/*
 * The stored Factory certificate, to present as a TLS client certificate at
 * the claim endpoint. Carried across from the #157 spike.
 *
 * Borrowed, not copied: the buffer is static and outlives the connection,
 * which matters because mbedTLS parses it without copying.
 */
int course_identity_certificate(const unsigned char **der, size_t *len);

/*
 * The PSA identifier of the Factory key. Carried across from the #157 spike.
 *
 * A uint32_t rather than psa_key_id_t so this header stays free of
 * psa/crypto.h. It is an identifier, not key material: opaque_tls.c hands it
 * to mbedtls_pk_wrap_psa() and no private byte is ever read.
 */
uint32_t course_identity_key_id(void);

/*
 * The six Tier 7 primitives, settled on issue #140.
 */

/*
 * Generate the pending Operational key.
 *
 * VOLATILE. It has no persistent identifier, it lives in RAM for the life of
 * one Claim window, and PSA destroys it on reset. That is not tidiness: #135
 * requires that the pending key dies with the window and that a reset kills
 * the window, and making the key volatile turns both rules from cleanup code
 * this firmware has to get right into properties PSA enforces. It also gives
 * E-6-05 its counterpoint, a key a flash dump cannot find because it was never
 * written.
 *
 * Generating straight into the persistent slot was never available: it would
 * destroy a working identity on every button press, which is what #135 forbids.
 *
 * The key carries PSA_KEY_USAGE_COPY and deliberately not PSA_KEY_USAGE_EXPORT.
 * A copy cannot gain usage flags the source did not have, so the key that lands
 * in the persistent slot is non-exportable too and E-6-04 is untouched.
 *
 * A second call supersedes: the previous pending key is destroyed first.
 */
int course_identity_generate_operational_key(void);

/*
 * Destroy the pending Operational key, when the window closes without a
 * certificate.
 *
 * #140 listed six primitives and this is a seventh. The volatile lifetime
 * covers a reset; it does not cover a k_timer firing on a board that stays
 * powered, and #135 requires the key to die then too.
 */
void course_identity_discard_operational_key(void);

/*
 * Build a certification request for the pending Operational key.
 *
 * Like Tier 6's, minus the Bootstrap credential extension: this request is
 * carried on a connection the Factory key already authenticated, so there is
 * nothing left for a credential inside the signature to prove.
 *
 * The subject CN is the identifier read out of the Factory certificate, not
 * the build-time one. That makes the request's own subject the third source
 * #137's identifier-consistent check compares, and it means a device cannot
 * ask to be issued a certificate naming a neighbour.
 */
int course_identity_build_operational_csr(unsigned char *out, size_t out_size,
					  size_t *out_len);

/*
 * Accept the Operational certificate the service issued.
 *
 * Two refusals before anything is written. The certificate must carry the
 * public half of the pending key, or it describes someone else's key; and its
 * CN must match the Factory certificate's, or this device has accepted a
 * certificate naming another device. Both are refusals and not warnings.
 *
 * Only then does psa_copy_key() move the pending key into the persistent slot,
 * destroying any prior occupant, and the certificate go into settings.
 */
int course_identity_store_operational_certificate(const unsigned char *der, size_t len);

/* Whether this device holds an issued Operational certificate. */
bool course_identity_has_operational(void);

/*
 * The owner this device belongs to, read out of the Operational certificate's
 * subject OU. NULL when unclaimed.
 *
 * The device stores no owner slug of its own, by the same one-source-of-truth
 * rule that makes the identifier come from the CN. An owner held separately
 * could disagree with the certificate the device presents.
 */
const char *course_identity_operational_owner(void);

/*
 * What opaque_tls.c presents on a restricted-endpoint connection: the
 * Operational key identifier and the Operational certificate bytes.
 *
 * Returns -ENOENT on an unclaimed device, which is a refusal to connect and
 * not an invitation to fall back to the Factory identity.
 */
int course_identity_operational_credentials(uint32_t *key_id,
					    const unsigned char **der, size_t *len);

/*
 * Erase the identity, for remanufacturing.
 *
 * Four places now, because there are two keys in Secure Storage and two
 * certificates in settings. Erasing one and not the others leaves a
 * certificate for a key that no longer exists, which is why this is one call
 * rather than four.
 */
int course_identity_erase(void);

#endif /* CONFIG_COURSE_IDENTITY_FACTORY */

/*
 * Decide whether the provisioning interface runs at all, and start it if so.
 *
 * Open when the device holds no identity, or when the BOOT button is held at
 * reset. Closed otherwise, and closed again the moment enrollment succeeds.
 */
void course_identity_gate(void);

#endif /* COURSE_IDENTITY_H */
