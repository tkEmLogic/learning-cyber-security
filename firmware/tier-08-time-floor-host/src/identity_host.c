/*
 * The host's stand-in for identity.c, and the only Tier 8 file this build
 * replaces.
 *
 * identity.c keeps the Operational key in the ESP32-C6's Secure Storage and
 * its certificate in settings, and a host has neither. This file keeps one
 * certificate in RAM instead and answers the same questions time_floor.c asks,
 * with identity.c's own semantics: valid_to comes from mbedtls_x509_crt_parse_der()
 * over the stored DER, exactly as describe_slot() takes it; a refused
 * certificate is still held; and the credential accessor then answers
 * -EKEYEXPIRED, which is what stops ota_connect() presenting it on the board.
 *
 * It holds no candidate. The floor's candidate branch is not what this row is
 * about, and a stand-in that invented one would be testing itself.
 */

#include "identity.h"
#include "identity_host.h"

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>

#include <mbedtls/x509_crt.h>

static const uint8_t *held_cert;
static size_t held_len;
static mbedtls_x509_time held_valid_to;
static bool operational_expired;

int host_identity_load(const uint8_t *der, size_t len)
{
	mbedtls_x509_crt cert;
	int err;

	held_cert = NULL;
	held_len = 0;
	operational_expired = false;

	mbedtls_x509_crt_init(&cert);
	err = mbedtls_x509_crt_parse_der(&cert, der, len);
	if (err != 0) {
		printk("identity.load the synthetic Operational certificate will not parse err=%d\n",
		       err);
		mbedtls_x509_crt_free(&cert);
		return err;
	}
	held_valid_to = cert.valid_to;
	mbedtls_x509_crt_free(&cert);
	held_cert = der;
	held_len = len;
	return 0;
}

int host_identity_present(const unsigned char **der, size_t *len)
{
	if (held_len == 0) {
		return -ENOENT;
	}
	if (operational_expired) {
		return -EKEYEXPIRED;
	}
	*der = held_cert;
	*len = held_len;
	return 0;
}

int course_identity_operational_valid_to(struct mbedtls_x509_time *out)
{
	if (held_len == 0) {
		return -ENOENT;
	}
	*out = held_valid_to;
	return 0;
}

int course_identity_candidate_valid_to(struct mbedtls_x509_time *out)
{
	ARG_UNUSED(out);
	return -ENOENT;
}

void course_identity_discard_candidate(void)
{
}

void course_identity_refuse_expired_operational(void)
{
	operational_expired = true;
}

bool course_identity_operational_expired(void)
{
	return operational_expired && held_len > 0;
}
