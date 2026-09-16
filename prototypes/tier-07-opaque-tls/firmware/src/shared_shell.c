/*
 * The registration interface on the shared image.
 *
 * This is the before state's console, and the counterpart of
 * provisioning_shell.c on the factory image. Read the two side by side: they
 * are the same shell, reduced the same way, started by the same application
 * decision, and they differ in what the device can prove.
 *
 * The factory image proves possession of a key it generated and that nothing
 * else holds. This one proves possession of a key compiled into every image
 * built the same way. Both proofs are real ECDSA signatures over a station
 * nonce, and the station verifies both the same way. Nothing here is weaker
 * cryptographically, which is the point: the weakness is not in the proof, it
 * is in how many devices can produce it.
 *
 * There is no `request` and no `certificate` step, because there is nothing to
 * enroll. The device arrived already holding the fleet identity, so
 * registration is one exchange rather than two, and there is no Bootstrap
 * credential to consume. That absence is what section 11 means by a reusable
 * default credential remaining active.
 */

#include "identity.h"

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>
#include <string.h>
#include <stdlib.h>

#ifdef CONFIG_COURSE_SHARED_SHELL

/* Chunked for the same reason the factory image chunks its certification
 * request: a certificate does not fit one console line, and printk from the
 * rest of the application shares this console and will interleave.
 */
#define CHUNK 64

#define NONCE_MAX 64
#define SIGNATURE_MAX 96
#define HEX_MAX 1024

void course_shared_shell_open(void)
{
	shell_start(shell_backend_uart_get_ptr());
}

static void print_hex_chunks(const struct shell *sh, const char *tag,
			     const unsigned char *data, size_t len)
{
	static char hex[HEX_MAX * 2 + 1];
	static const char digits[] = "0123456789abcdef";

	if (len > HEX_MAX) {
		shell_error(sh, "%s too long: %zu bytes", tag, len);
		return;
	}
	for (size_t i = 0; i < len; i++) {
		hex[i * 2] = digits[data[i] >> 4];
		hex[i * 2 + 1] = digits[data[i] & 0x0f];
	}
	hex[len * 2] = '\0';

	shell_print(sh, "%s begin %zu", tag, len);
	for (size_t offset = 0; offset < len * 2; offset += CHUNK) {
		char line[CHUNK + 1];
		size_t n = len * 2 - offset;

		if (n > CHUNK) {
			n = CHUNK;
		}
		memcpy(line, &hex[offset], n);
		line[n] = '\0';
		shell_print(sh, "%s data %s", tag, line);
	}
	shell_print(sh, "%s end", tag);
}

static int unhex(const char *text, unsigned char *out, size_t out_size, size_t *out_len)
{
	size_t len = strlen(text);

	if (len % 2 != 0 || len / 2 > out_size) {
		return -EINVAL;
	}
	for (size_t i = 0; i < len; i += 2) {
		char pair[3] = { text[i], text[i + 1], '\0' };
		char *end = NULL;
		long value = strtol(pair, &end, 16);

		if (end != pair + 2) {
			return -EINVAL;
		}
		out[i / 2] = (unsigned char)value;
	}
	*out_len = len / 2;
	return 0;
}

static int cmd_status(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!course_identity_is_provisioned()) {
		shell_print(sh, "provision.status no fleet credential is compiled into this image");
		return 0;
	}
	shell_print(sh, "provision.status shared identity %s", course_identity_device_id());
	shell_print(sh, "provision.status fingerprint=sha256:%s", course_identity_fingerprint());
	shell_print(sh, "provision.status every image built this way reports exactly this");
	return 0;
}

/*
 * Registration, in one exchange.
 *
 * The station issues a nonce, the device signs it with the compiled-in key and
 * returns the signature beside the certificate that key belongs to. The station
 * checks the signature against that certificate, and it verifies: the device
 * does hold the private half. What the station cannot tell, and this is the
 * whole tier, is which device it is talking to, because the answer to its
 * question is in every image.
 */
static int cmd_register(const struct shell *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		shell_error(sh, "usage: provision register <nonce-hex>");
		return -EINVAL;
	}

	unsigned char nonce[NONCE_MAX];
	size_t nonce_len = 0;
	int err = unhex(argv[1], nonce, sizeof(nonce), &nonce_len);

	if (err != 0 || nonce_len == 0) {
		shell_error(sh, "provision.register nonce is not valid hex, or too long");
		return -EINVAL;
	}

	const unsigned char *cert = NULL;
	size_t cert_len = 0;

	if (course_shared_certificate(&cert, &cert_len) != 0) {
		shell_error(sh, "provision.register this image carries no fleet certificate");
		shell_error(sh, "provision.register build it with --variant shared after");
		shell_error(sh, "provision.register ./course keys create shared-identity");
		return -ENOENT;
	}

	unsigned char signature[SIGNATURE_MAX];
	size_t signature_len = 0;

	err = course_shared_sign_nonce(nonce, nonce_len, signature, sizeof(signature),
				       &signature_len);
	if (err != 0) {
		shell_error(sh, "provision.register could not sign the nonce err=%d", err);
		return err;
	}

	shell_print(sh, "provision.register signed a %zu byte nonce with the compiled-in key",
		    nonce_len);
	print_hex_chunks(sh, "provision.cert", cert, cert_len);
	print_hex_chunks(sh, "provision.sig", signature, signature_len);
	shell_print(sh, "provision.register the station can now check that signature against");
	shell_print(sh, "provision.register that certificate. It will verify. So would the same");
	shell_print(sh, "provision.register answer from any other board flashed with this image.");
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(provision_commands,
	SHELL_CMD_ARG(status, NULL, "Report the identity this image carries", cmd_status, 1, 0),
	SHELL_CMD_ARG(register, NULL, "Prove possession of the fleet key", cmd_register, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(provision, &provision_commands,
		   "Fleet registration, using the credential compiled into this image", NULL);

#endif /* CONFIG_COURSE_SHARED_SHELL */
