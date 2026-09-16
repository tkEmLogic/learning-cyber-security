/*
 * Tier 6 device identity.
 *
 * Two identity models live behind this interface, selected by the Kconfig
 * choice in Kconfig. The shared model carries one key compiled into every
 * image; the factory model generates a key on the device and never lets the
 * private half leave. Everything above this header asks the same questions of
 * both, which is what makes the two builds comparable.
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

/* Fingerprint of the identity's certificate, for the boot banner. */
const char *course_identity_fingerprint(void);

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
 * PROTOTYPE, issue #157. The stored Factory certificate, for the spike to
 * present as a TLS client certificate. Borrowed, not copied: the buffer is
 * static and outlives the connection, which matters because mbedTLS parses it
 * without copying.
 */
int course_identity_certificate(const unsigned char **der, size_t *len);

/*
 * PROTOTYPE, issue #157. The PSA identifier of the Factory key.
 *
 * A uint32_t rather than psa_key_id_t so this header stays free of psa/crypto.h,
 * the way it was before the spike.
 */
uint32_t course_identity_key_id(void);

/*
 * Erase the identity, for remanufacturing.
 *
 * Two places, because the key lives in Secure Storage and the certificate does
 * not. Erasing one and not the other leaves a certificate for a key that no
 * longer exists, which is why this is one call rather than two.
 */
int course_identity_erase(void);

#endif /* CONFIG_COURSE_IDENTITY_FACTORY */

#ifdef CONFIG_COURSE_IDENTITY_SHARED

/*
 * The fleet certificate this image carries, for the station to check the nonce
 * signature against.
 *
 * Every image built in this variant returns the same bytes, which is the whole
 * argument of the tier.
 */
int course_shared_certificate(const unsigned char **der, size_t *len);

/*
 * Sign a station nonce with the compiled-in fleet key.
 *
 * This is a real proof of possession and it is not weaker than the one the
 * factory build performs. It is the same question, asked of a key every device
 * in the fleet already knows the answer to.
 *
 * The signature comes back as the ASN.1 sequence the station's verifier
 * expects, not as the raw r||s pair PSA produces.
 */
int course_shared_sign_nonce(const unsigned char *nonce, size_t nonce_len,
			     unsigned char *out, size_t out_size, size_t *out_len);

#endif /* CONFIG_COURSE_IDENTITY_SHARED */

/*
 * Decide whether the provisioning interface runs at all, and start it if so.
 *
 * Open when the device holds no identity, or when the BOOT button is held at
 * reset. Closed otherwise, and closed again the moment enrollment succeeds.
 */
void course_identity_gate(void);

#endif /* COURSE_IDENTITY_H */
