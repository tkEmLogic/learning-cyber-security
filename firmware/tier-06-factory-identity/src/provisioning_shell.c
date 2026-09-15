/*
 * The provisioning interface.
 *
 * Settled on issue #113. A Zephyr shell rather than a private protocol,
 * because a hidden framing is obscurity and not security, and both are exposed
 * on exactly the same terms once the gating is in place. What makes this
 * defensible is that it is reduced and closed:
 *
 *   SHELL_MINIMAL   turns off the kernel module, the built-in commands,
 *                   history, tab completion and VT100 handling, so an attacker
 *                   who finds this shell finds these commands and nothing else
 *   SHELL_AUTOSTART is off, so main() decides when the shell runs at all
 *   shell_stop()    is called the moment enrollment succeeds
 *
 * A Learner can check both halves by typing a command after enrolling and
 * watching nothing happen.
 */

#include "identity.h"

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>
#include <string.h>
#include <stdlib.h>

#ifdef CONFIG_COURSE_PROVISIONING_SHELL

/*
 * A P-256 certification request is 300 to 500 bytes of DER, so 600 to 1000 hex
 * characters, which will not fit one line. It is printed in fixed width chunks
 * with a prefix the station filters on, because printk from the rest of the
 * application shares this console and will interleave.
 */
#define CHUNK 64

#define CSR_MAX 768
#define CERT_MAX 800

static bool provisioning_open;

void course_provisioning_open(void)
{
	provisioning_open = true;
	shell_start(shell_backend_uart_get_ptr());
}

void course_provisioning_close(void)
{
	if (!provisioning_open) {
		return;
	}
	provisioning_open = false;
	shell_stop(shell_backend_uart_get_ptr());
	printk("provision.closed the provisioning interface is no longer listening\n");
}

static void print_hex_chunks(const struct shell *sh, const char *tag,
			     const unsigned char *data, size_t len)
{
	static char hex[CSR_MAX * 2 + 1];
	static const char digits[] = "0123456789abcdef";

	if (len > CSR_MAX) {
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
	if (course_identity_is_provisioned()) {
		shell_print(sh, "provision.status provisioned device_id=%s",
			    course_identity_device_id());
		shell_print(sh, "provision.status fingerprint=sha256:%s",
			    course_identity_fingerprint());
	} else {
		shell_print(sh, "provision.status unprovisioned, no Factory certificate held");
	}
	return 0;
}

/*
 * Step one of enrollment. The station hands over the Bootstrap credential, the
 * device generates its key if it has none, and returns a certification request
 * carrying that credential inside the signature.
 */
static int cmd_request(const struct shell *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		shell_error(sh, "usage: provision request <credential>");
		return -EINVAL;
	}
	if (course_identity_is_provisioned()) {
		shell_error(sh, "provision.request this device already holds a Factory certificate");
		shell_error(sh, "provision.request erase it first if you are remanufacturing");
		return -EEXIST;
	}

	int err = course_identity_generate_key();
	if (err != 0) {
		shell_error(sh, "provision.request could not generate a key err=%d", err);
		return err;
	}

	static unsigned char csr[CSR_MAX];
	size_t csr_len = 0;
	err = course_identity_build_csr(argv[1], csr, sizeof(csr), &csr_len);
	if (err != 0) {
		shell_error(sh, "provision.request could not build a request err=%d", err);
		return err;
	}
	print_hex_chunks(sh, "provision.csr", csr, csr_len);
	return 0;
}

/* Step two. The station returns the certificate it issued. */
static int cmd_certificate(const struct shell *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		shell_error(sh, "usage: provision certificate <hex>");
		return -EINVAL;
	}
	static unsigned char der[CERT_MAX];
	size_t len = 0;
	int err = unhex(argv[1], der, sizeof(der), &len);
	if (err != 0) {
		shell_error(sh, "provision.certificate not valid hex, or too long");
		return err;
	}
	err = course_identity_store_certificate(der, len);
	if (err != 0) {
		shell_error(sh, "provision.certificate refused err=%d", err);
		return err;
	}
	shell_print(sh, "provision.certificate stored, device_id=%s",
		    course_identity_device_id());
	shell_print(sh, "provision.certificate closing the provisioning interface");
	course_provisioning_close();
	return 0;
}

/* Evidence row E-6-04. It always fails, and that is the point. */
static int cmd_export(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_print(sh, "provision.export asking the course API for the private key");
	int err = course_identity_try_export();
	if (err != 0) {
		shell_error(sh, "provision.export the key was exportable. That is a defect.");
		return err;
	}
	return 0;
}

/* Remanufacturing. The old record stands; this appends nothing and erases
 * only what is on the device. */
static int cmd_erase(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_print(sh, "provision.erase destroying the device key and deleting the certificate");
	int err = course_identity_erase();
	if (err != 0) {
		shell_error(sh, "provision.erase failed err=%d", err);
		return err;
	}
	shell_print(sh, "provision.erase done. The manufacturing record is append only and");
	shell_print(sh, "provision.erase still holds every entry, including this device's.");
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(provision_commands,
	SHELL_CMD_ARG(status, NULL, "Report whether this device holds an identity", cmd_status, 1, 0),
	SHELL_CMD_ARG(request, NULL, "Generate a key and return a certification request", cmd_request, 2, 0),
	SHELL_CMD_ARG(certificate, NULL, "Store the Factory certificate the station issued", cmd_certificate, 2, 0),
	SHELL_CMD_ARG(export, NULL, "Try to export the private key. It refuses.", cmd_export, 1, 0),
	SHELL_CMD_ARG(erase, NULL, "Erase the identity for remanufacturing", cmd_erase, 1, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(provision, &provision_commands,
		   "Factory provisioning, available only while unprovisioned", NULL);

#endif /* CONFIG_COURSE_PROVISIONING_SHELL */
