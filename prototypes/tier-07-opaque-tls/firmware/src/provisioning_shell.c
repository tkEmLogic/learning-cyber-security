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
	/* Idempotent, because the button can be held long enough to reopen an
	 * interface that is already listening, and restarting the shell under
	 * itself is not something to find out about later.
	 */
	if (provisioning_open) {
		return;
	}
	provisioning_open = true;
	shell_start(shell_backend_uart_get_ptr());
}

/*
 * Closing is deferred off the shell thread, and it has to be.
 *
 * shell_stop() sets the shell state to SHELL_STATE_INITIALIZED, which stops it
 * processing input. But the shell loop sets SHELL_STATE_ACTIVE unconditionally
 * on the line straight after a command handler returns, so that it can print
 * the next prompt (shell.c, "Command execution" then state_set(ACTIVE)). A
 * shell_stop() called from inside a command is therefore undone by the shell
 * itself before the next character arrives, and it returns 0 while doing it.
 *
 * The board is what said so. The source reads correctly, the call succeeds, the
 * console prints "the provisioning interface is no longer listening", and then
 * answers the next command anyway.
 *
 * Submitting to the system workqueue puts the stop after the shell loop has
 * finished restoring ACTIVE, on a thread that is not the one being stopped.
 */
static void close_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	shell_stop(shell_backend_uart_get_ptr());
	printk("provision.closed the provisioning interface is no longer listening\n");
#ifdef CONFIG_COURSE_PROVISIONING_BUTTON_HOLD_SECONDS
	printk("provision.closed type a command and watch nothing happen. Hold BOOT for %d\n",
	       CONFIG_COURSE_PROVISIONING_BUTTON_HOLD_SECONDS);
	printk("provision.closed seconds to reopen it deliberately. No reset is needed.\n");
#else
	printk("provision.closed type a command and watch nothing happen. This device\n");
	printk("provision.closed cannot be reopened without erasing and reflashing it.\n");
#endif
}

static K_WORK_DEFINE(close_work, close_work_handler);

void course_provisioning_close(void)
{
	if (!provisioning_open) {
		return;
	}
	provisioning_open = false;
	k_work_submit(&close_work);
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

/*
 * Step two. The station returns the certificate it issued, in chunks.
 *
 * Chunked because it does not fit. A Factory certificate is around 528 bytes,
 * which is 1056 hex characters, and CONFIG_SHELL_CMD_BUFF_SIZE is 256. Sending
 * it as one argument silently truncated at the buffer length and the device
 * then refused a certificate that was never wrong, which reads like the station
 * having issued a bad one.
 *
 * It mirrors the way the request is printed out, so the two halves of the
 * exchange have the same shape: begin with the expected length, some data, then
 * end. The length is declared first so that a transfer which stops early is
 * refused as short rather than parsed as far as it got.
 */
static unsigned char incoming_cert[CERT_MAX];
static size_t incoming_cert_len;
static size_t incoming_cert_expected;

static int cmd_certificate_begin(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	long expected = strtol(argv[1], NULL, 10);

	if (expected <= 0 || expected > (long)sizeof(incoming_cert)) {
		shell_error(sh, "provision.certificate length %ld is out of range", expected);
		return -EINVAL;
	}
	incoming_cert_len = 0;
	incoming_cert_expected = (size_t)expected;
	shell_print(sh, "provision.certificate expecting %ld bytes", expected);
	return 0;
}

static int cmd_certificate_data(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	if (incoming_cert_expected == 0) {
		shell_error(sh, "provision.certificate no transfer has begun");
		return -EINVAL;
	}
	unsigned char chunk[CHUNK];
	size_t chunk_len = 0;

	if (unhex(argv[1], chunk, sizeof(chunk), &chunk_len) != 0) {
		shell_error(sh, "provision.certificate chunk is not valid hex, or too long");
		incoming_cert_expected = 0;
		return -EINVAL;
	}
	if (incoming_cert_len + chunk_len > incoming_cert_expected) {
		shell_error(sh, "provision.certificate more bytes than were declared");
		incoming_cert_expected = 0;
		return -EINVAL;
	}
	memcpy(&incoming_cert[incoming_cert_len], chunk, chunk_len);
	incoming_cert_len += chunk_len;
	return 0;
}

static int cmd_certificate_end(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	if (incoming_cert_expected == 0) {
		shell_error(sh, "provision.certificate no transfer has begun");
		return -EINVAL;
	}
	if (incoming_cert_len != incoming_cert_expected) {
		shell_error(sh, "provision.certificate got %zu bytes of %zu declared",
			    incoming_cert_len, incoming_cert_expected);
		incoming_cert_expected = 0;
		return -EINVAL;
	}
	incoming_cert_expected = 0;

	int err = course_identity_store_certificate(incoming_cert, incoming_cert_len);

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

SHELL_STATIC_SUBCMD_SET_CREATE(certificate_commands,
	SHELL_CMD_ARG(begin, NULL, "Declare the certificate length", cmd_certificate_begin, 2, 0),
	SHELL_CMD_ARG(data, NULL, "One chunk of certificate hex", cmd_certificate_data, 2, 0),
	SHELL_CMD_ARG(end, NULL, "Finish and store the certificate", cmd_certificate_end, 1, 0),
	SHELL_SUBCMD_SET_END
);

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
	SHELL_CMD(certificate, &certificate_commands, "Store the Factory certificate the station issued", NULL),
	SHELL_CMD_ARG(export, NULL, "Try to export the private key. It refuses.", cmd_export, 1, 0),
	SHELL_CMD_ARG(erase, NULL, "Erase the identity for remanufacturing", cmd_erase, 1, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(provision, &provision_commands,
		   "Factory provisioning, available only while unprovisioned", NULL);

#endif /* CONFIG_COURSE_PROVISIONING_SHELL */
