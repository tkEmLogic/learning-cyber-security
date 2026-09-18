/*
 * The opaque-key TLS socket.
 *
 * Tier 7 has to present a client certificate whose private half is a PSA key
 * identifier and not a byte buffer, and Zephyr's socket TLS layer cannot carry
 * one: tls_set_private_key() feeds TLS_CREDENTIAL_PRIVATE_KEY straight to
 * mbedtls_pk_parse_key(), the credential enum has no opaque member, and a key
 * identifier is rejected at setsockopt() time. Issue #138 established that, and
 * established that the library underneath can do it, because Tier 6 already
 * signs its certification request through mbedtls_pk_wrap_psa().
 *
 * So this file is the four-line body of tls_set_private_key() written the other
 * way round: an application-owned socket implementation, registered with
 * NET_SOCKET_REGISTER on a protocol number Zephyr does not claim, owning its
 * own mbedtls_ssl_context and reaching the key through mbedtls_pk_wrap_psa().
 * No Zephyr source changes and no module is forked, which matters because the
 * Learner forks this repository and builds the pinned baseline.
 *
 * Issue #157 proved the handshake on the board. Issue #158 proved that
 * http_client_req() runs on the descriptor it returns, which is why
 * ota_client.c keeps its request and response handling unchanged.
 */

#ifndef COURSE_OPAQUE_TLS_H
#define COURSE_OPAQUE_TLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The protocol number this socket implementation answers on.
 *
 * Outside the 256 to 259 and 272 to 273 ranges Zephyr's own protocol_check()
 * claims, so zsock_socket() reaches this implementation and not that one, and
 * this one does not have to win on priority to be reached.
 */
#define IPPROTO_COURSE_OPAQUE_TLS 260

/*
 * Which identity the next connection presents.
 *
 * Not a preference and not a ranking. #137 split the service into two
 * listeners and gave each route exactly one acceptable role: the claim
 * endpoint takes the Factory certificate and refuses an Operational one at the
 * identity-factory check, and the download and event endpoints take the
 * Operational certificate and refuse a Factory one at identity-operational.
 * Choosing wrongly here earns a 403 with a reason code, not a fallback.
 */
enum course_tls_identity {
	COURSE_TLS_IDENTITY_FACTORY,
	COURSE_TLS_IDENTITY_OPERATIONAL,
};

struct course_opaque_tls_result {
	bool completed;
	int mbedtls_error;
	uint32_t verify_flags;
	char ciphersuite[64];
	char version[16];
};

/*
 * Which branch of the poll implementation fired, and how often.
 *
 * Kept from the #158 spike because the two counts that matter are the two a
 * forwarding-only poll gets wrong, and they are the difference between a
 * download that completes and one that hangs. update_buffered counts polls
 * answered from plaintext mbedTLS had already decrypted, which the TCP
 * descriptor can no longer signal; update_partial_record counts polls where the
 * TCP descriptor was readable and no record completed. #151 reads these off the
 * board on a real image download.
 */
struct course_opaque_tls_poll_stats {
	unsigned int prepare_forwarded;
	unsigned int prepare_already;
	unsigned int update_decrypted;
	unsigned int update_buffered;
	unsigned int update_partial_record;
};

/* The name to require of the service, set before connect(). */
void course_opaque_tls_set_hostname(const char *name);

/* Which certificate and key the next connection presents. */
void course_opaque_tls_set_identity(enum course_tls_identity identity);

/* What the last handshake attempt did, for the refusal to be read out loud. */
const struct course_opaque_tls_result *course_opaque_tls_last_result(void);

const struct course_opaque_tls_poll_stats *course_opaque_tls_poll_stats(void);
void course_opaque_tls_reset_poll_stats(void);

/* True when a Course certificate authority is compiled into this image. An
 * image without one trusts nothing and says so, which is the right failure.
 */
bool course_opaque_tls_has_trust_anchor(void);

/* The compiled-in trust anchor, so nothing else has to hold a second copy. */
int course_opaque_tls_trust_anchor(const unsigned char **der, size_t *len);

#endif /* COURSE_OPAQUE_TLS_H */
