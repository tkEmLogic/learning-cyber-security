/*
 * Renewal, the device's half. See renewal.h for the sequence and the reset
 * cases.
 */

#include "renewal.h"
#include "health_gate.h"
#include "identity.h"
#include "ota_client.h"

#include <zephyr/kernel.h>
#include <zephyr/data/json.h>
#include <zephyr/sys/base64.h>
#include <stdio.h>
#include <string.h>

/*
 * Buffers, static for claim.c's reason: this runs on main's stack beside a TLS
 * session. The sizes are claim.c's too, because the reply is the same shape, a
 * PEM certificate with its newlines escaped and a handful of fields beside it.
 */
#define RENEWAL_CSR_MAX 768
#define RENEWAL_REQUEST_MAX 1200
#define RENEWAL_RESPONSE_MAX 2048
#define RENEWAL_CERT_MAX 1024
#define RENEWAL_CERT_PEM_MAX 1536

static unsigned char csr_der[RENEWAL_CSR_MAX];
static char request_body[RENEWAL_REQUEST_MAX];
static char response_body[RENEWAL_RESPONSE_MAX];
static unsigned char issued_cert[RENEWAL_CERT_MAX];

/*
 * What the service can say back. check and reason on a refusal, certificate on
 * success. result, renewed_from_serial, certificate_serial and the rest are not
 * read: identity.c reads what matters out of the certificate itself, and
 * certificate is JSON_TOK_STRING_BUF for the reason claim.c spells out, which
 * is that only a buffer gets its escapes undone.
 */
struct renewal_reply {
	const char *check;
	const char *reason;
	char certificate[RENEWAL_CERT_PEM_MAX];
};

static const struct json_obj_descr renewal_reply_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct renewal_reply, check, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct renewal_reply, reason, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct renewal_reply, certificate, JSON_TOK_STRING_BUF),
};

/* PEM armour off, then base64 off. claim.c does the same, for the same reply. */
static int decode_certificate(const char *encoded, size_t *decoded)
{
	static const char pem_begin[] = "-----BEGIN CERTIFICATE-----";
	static const char pem_end[] = "-----END CERTIFICATE-----";
	const char *armoured = strstr(encoded, pem_begin);
	const char *start = encoded;
	size_t len = strlen(encoded);

	if (armoured != NULL) {
		const char *footer = strstr(armoured, pem_end);

		start = armoured + sizeof(pem_begin) - 1;
		if (footer == NULL || footer < start) {
			return -EBADMSG;
		}
		len = (size_t)(footer - start);
	}
	return base64_decode(issued_cert, sizeof(issued_cert), decoded,
			     (const uint8_t *)start, len);
}

static int build_request(void)
{
	static char csr_b64[RENEWAL_CSR_MAX * 4 / 3 + 8];
	size_t csr_len = 0;
	size_t encoded = 0;
	int err;
	int len;

	err = course_identity_generate_renewal_key();
	if (err != 0) {
		return err;
	}
	err = course_identity_build_renewal_csr(csr_der, sizeof(csr_der), &csr_len);
	if (err != 0) {
		return err;
	}
	err = base64_encode((uint8_t *)csr_b64, sizeof(csr_b64), &encoded, csr_der, csr_len);
	if (err != 0) {
		return err;
	}
	csr_b64[encoded] = '\0';

	/* One field. The service decodes with DisallowUnknownFields, and the
	 * path and the certificate on the connection already name the device.
	 */
	len = snprintf(request_body, sizeof(request_body), "{\"csr\":\"%s\"}", csr_b64);
	if (len < 0 || len >= (int)sizeof(request_body)) {
		return -ENOMEM;
	}
	return len;
}

int course_renewal_prove_candidate(const char *machine_state)
{
	char detail[96];
	int err;

	if (!course_identity_has_candidate()) {
		return 0;
	}

	snprintf(detail, sizeof(detail), "candidate sha256:%.16s",
		 course_identity_candidate_fingerprint());
	printk("renewal.prove presenting the Renewal candidate on an ordinary event\n");
	err = ota_client_report_as(COURSE_TLS_IDENTITY_CANDIDATE, "renewal.activated",
				   machine_state, CONFIG_COURSE_RELEASE_ID, detail);
	if (err == 0) {
		printk("renewal.activated the service accepted a request on the new identity. That\n");
		printk("renewal.activated first use is its activation record, and on it the service\n");
		printk("renewal.activated retires the old certificate as superseded. This device\n");
		printk("renewal.activated gives up the old identity now, and not before.\n");
		err = course_identity_promote_candidate();
		return err == 0 ? 1 : err;
	}
	if (err == -EACCES) {
		printk("renewal.failed check=%s attempt=proof\n", ota_client_last_check());
		printk("renewal.failed the candidate was refused, so it is discarded and this device\n");
		printk("renewal.failed stays on the identity it had.\n");
		course_identity_discard_candidate();
		return -EACCES;
	}
	printk("renewal.prove no answer err=%d; the candidate is kept and presented again on\n",
	       err);
	printk("renewal.prove the next poll\n");
	return 0;
}

/*
 * One attempt. Returns 0 when a candidate was stored and was either promoted or
 * got no answer: a candidate that could not be proved yet is proved on the
 * next poll, and asking for another would only make the service retire this
 * one unused. A candidate the service refused has been discarded, and that is
 * a failed attempt like any other.
 */
static int attempt(const char *machine_state)
{
	static struct renewal_reply reply;
	size_t body_len = 0;
	size_t decoded = 0;
	int status = 0;
	int len;
	int err;

	len = build_request();
	if (len < 0) {
		course_identity_discard_renewal_key();
		return len;
	}

	err = ota_client_renewal_exchange(request_body, (size_t)len, response_body,
					  sizeof(response_body), &body_len, &status);
	if (err != 0) {
		course_identity_discard_renewal_key();
		return err;
	}
	if (status < 200 || status >= 300) {
		course_identity_discard_renewal_key();
		return -EACCES;
	}

	memset(&reply, 0, sizeof(reply));
	err = json_obj_parse(response_body, body_len, renewal_reply_descr,
			     ARRAY_SIZE(renewal_reply_descr), &reply);
	if (err < 0 || reply.certificate[0] == '\0') {
		printk("renewal.reply status=%d carried no certificate err=%d\n", status, err);
		course_identity_discard_renewal_key();
		return -EBADMSG;
	}
	err = decode_certificate(reply.certificate, &decoded);
	if (err != 0) {
		printk("renewal.reply the certificate will not decode err=%d\n", err);
		course_identity_discard_renewal_key();
		return err;
	}
	err = course_identity_store_candidate(issued_cert, decoded);
	course_identity_discard_renewal_key();
	if (err != 0) {
		return err;
	}

	err = course_renewal_prove_candidate(machine_state);
	return err < 0 ? err : 0;
}

void course_renewal_run(const char *machine_state)
{
	/*
	 * #148's table, the claim's table, spelled out for the same reason: the
	 * delay belongs to the attempt it precedes, and a Learner reads one
	 * cadence in three files rather than three that happen to agree.
	 */
	static const int backoff_seconds[] = { 0, 2, 4, 8 };

	if (course_identity_has_candidate()) {
		/* A candidate that has not been proved is still the renewal in
		 * progress. Asking for another would retire it unused.
		 */
		printk("renewal.pending a candidate is already held and waits for its proof\n");
		return;
	}

	printk("renewal.due the service says this certificate should renew. The device does\n");
	printk("renewal.due not decide that itself: the service holds the schedule.\n");

	for (int n = 1; n <= CONFIG_COURSE_RENEWAL_ATTEMPTS; n++) {
		size_t slot = MIN((size_t)(n - 1), ARRAY_SIZE(backoff_seconds) - 1);
		int delay = backoff_seconds[slot];
		int err;

		for (int waited = 0; waited < delay; waited++) {
			k_sleep(K_SECONDS(1));
			health_gate_feed();
		}

		err = attempt(machine_state);
		if (err == 0) {
			return;
		}
		if (err == -EACCES) {
			printk("renewal.failed check=%s attempt=%d of %d\n", ota_client_last_check(), n,
			       CONFIG_COURSE_RENEWAL_ATTEMPTS);
		} else {
			printk("renewal.failed check=none err=%d attempt=%d of %d\n", err, n,
			       CONFIG_COURSE_RENEWAL_ATTEMPTS);
		}
		printk("renewal.failed this device keeps the identity it has\n");
	}
	printk("renewal.waiting %d attempts failed. The next poll asks again if the service\n",
	       CONFIG_COURSE_RENEWAL_ATTEMPTS);
	printk("renewal.waiting still says renew; the poll interval is the outer backoff.\n");
}
