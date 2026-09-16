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

/* Run the spike: one mutually authenticated connection, then report. */
void course_opaque_tls_spike(void);

#endif /* COURSE_OPAQUE_TLS_H */
