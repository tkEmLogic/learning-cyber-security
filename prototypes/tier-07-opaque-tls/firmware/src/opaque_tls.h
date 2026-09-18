/*
 * PROTOTYPE. Throwaway spike code for issue #157. Not production firmware.
 */

#ifndef COURSE_OPAQUE_TLS_H
#define COURSE_OPAQUE_TLS_H

#include <stdbool.h>
#include <stdint.h>

/*
 * The protocol number this socket implementation answers on.
 *
 * Outside the 256 to 259 and 272 to 273 ranges Zephyr's own protocol_check()
 * claims, so zsock_socket() reaches this implementation and not that one.
 */
#define IPPROTO_COURSE_OPAQUE_TLS 260

struct course_opaque_tls_result {
	bool completed;
	int mbedtls_error;
	uint32_t verify_flags;
	char ciphersuite[64];
	char version[16];
};

/* The name to require of the service, set before connect(). */
void course_opaque_tls_set_hostname(const char *name);

/* What the last handshake attempt did. */
const struct course_opaque_tls_result *course_opaque_tls_last_result(void);

/*
 * Issue #158. Which branch of the poll implementation fired, and how often.
 *
 * The two cases that matter are the two a naive forwarding poll gets wrong:
 * update_buffered counts the polls answered from bytes mbedTLS had already
 * decrypted, which the TCP descriptor can no longer signal and which hang a
 * forwarding-only poll forever, and update_partial_record counts the polls
 * where the TCP descriptor was readable but no record completed, which a
 * forwarding-only poll reports as readable and sends the caller into a
 * blocking read.
 */
struct course_opaque_tls_poll_stats {
	unsigned int prepare_forwarded;
	unsigned int prepare_already;
	unsigned int update_decrypted;
	unsigned int update_buffered;
	unsigned int update_partial_record;
};

const struct course_opaque_tls_poll_stats *course_opaque_tls_poll_stats(void);
void course_opaque_tls_reset_poll_stats(void);

/* Run the spike: one mutually authenticated connection, then report. */
void course_opaque_tls_spike(void);

#endif /* COURSE_OPAQUE_TLS_H */
