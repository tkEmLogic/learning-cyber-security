/*
 * The Claim window. See claim.h for the boundary and the two clocks.
 */

#include "claim.h"
#include "health_gate.h"
#include "identity.h"
#include "ota_client.h"

#include <zephyr/kernel.h>
#include <zephyr/data/json.h>
#include <zephyr/sys/base64.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

#ifdef CONFIG_COURSE_CLAIM

/*
 * The nonce. Fifteen bytes, twenty-four Crockford base32 characters, six
 * groups of four.
 *
 * 120 bits divides evenly by five, so the encoding has no padding and the
 * group boundaries are real rather than cosmetic. Crockford drops I, L, O and
 * U, so 0/O and 1/l never bite a person moving this from a serial console to a
 * shell. The entropy is not the offline question: this nonce guards one device
 * for ten minutes behind a bounded attempt budget, and 120 bits was chosen for
 * the clean encoding rather than because 80 would have been weak.
 *
 * Tier 6's 32-byte hex station nonce is deliberately not the model. That one is
 * never touched by a human, so its encoding is free. This one is transcribed,
 * which makes the alphabet a design decision — and a 64-character hex string
 * does not invite transcription, it invites copy-paste, and a claim the Learner
 * copy-pastes teaches nothing about why a person is in this loop at all.
 */
#define CLAIM_NONCE_BYTES 15
#define CLAIM_NONCE_CHARS 24
#define CLAIM_NONCE_GROUPS 6
#define CLAIM_NONCE_TEXT_MAX (CLAIM_NONCE_CHARS + CLAIM_NONCE_GROUPS)

BUILD_ASSERT(CLAIM_NONCE_BYTES * 8 == CLAIM_NONCE_CHARS * 5,
	     "the nonce length no longer divides evenly into base32 characters, so the "
	     "encoding would need padding and the groups would stop being real");

static const char crockford[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/*
 * Buffers, static for the reason ota_client.c's are static: this runs on
 * main's stack, and a kilobyte of certification request plus a kilobyte of
 * reply is not what that stack is sized for. A kilobyte of .bss is visible in
 * the map file; a stack overflow during a handshake is not.
 */
#define CLAIM_CSR_MAX 768
#define CLAIM_REQUEST_MAX 1400
/*
 * The reply is the larger of the two, because #146 settled that the service
 * PEM-encodes the issued certificate and sends six fields beside it. PEM costs
 * a third over the DER and then the armour and the line breaks on top, and
 * every one of those newlines arrives as a two-character JSON escape. A little
 * over a kilobyte is what that measures out to; the rest is the margin that
 * keeps a longer device identifier or owner slug from turning into -EMSGSIZE
 * on the one exchange in this tier that cannot be retried into working.
 */
#define CLAIM_RESPONSE_MAX 2048
/* A certificate, unarmoured. Not CLAIM_RESPONSE_MAX: the decoded DER is
 * roughly three quarters of its own encoding and none of the fields around it.
 */
#define CLAIM_CERT_MAX 1024
/* The same certificate as it arrives: PEM armoured, and with every newline
 * still spelled as a two-character JSON escape. Base64 is four characters for
 * every three of DER, the armour is another fifty-two, and each of the line
 * breaks costs two rather than one. Half again over the DER covers all of it
 * with room left, and it has to: Zephyr refuses a JSON_TOK_STRING_BUF field
 * whose escaped form does not fit rather than truncating it.
 */
#define CLAIM_CERT_PEM_MAX 1536

static unsigned char csr_der[CLAIM_CSR_MAX];
static size_t csr_der_len;
static char request_body[CLAIM_REQUEST_MAX];
static char response_body[CLAIM_RESPONSE_MAX];
static unsigned char issued_cert[CLAIM_CERT_MAX];

static char nonce_text[CLAIM_NONCE_TEXT_MAX + 1];

/*
 * Where the device is in its own half of the claim.
 *
 * SUBMIT and POLL look alike on the wire — #137 settled that the poll re-sends
 * the identical POST rather than opening with a POST and polling a GET — and
 * they are separate states here because they bound different things. SUBMIT
 * bounds a thing that either lands or does not, with four attempts on the 0,
 * 2, 4 and 8 second cadence the operator half at the service shares. POLL is
 * the waiting state, and it retries at its own cadence for as long as the
 * window lives.
 */
enum claim_state {
	CLAIM_IDLE,
	CLAIM_SUBMIT,
	CLAIM_POLL,
};

static enum claim_state state;
static int submit_attempts;
static int64_t next_exchange_ms;

/*
 * The timer only ever raises this flag.
 *
 * Closing the window destroys a PSA key, and a k_timer callback runs in the
 * system clock's context where that is not a thing to do. main notices the
 * flag on its next step, which is at most a few seconds later and is the same
 * thread every other piece of claim work runs on.
 */
static volatile bool window_expired;

static void window_timer_expired(struct k_timer *timer)
{
	ARG_UNUSED(timer);
	window_expired = true;
}

static K_TIMER_DEFINE(window_timer, window_timer_expired, NULL);

static void close_window(const char *why)
{
	k_timer_stop(&window_timer);
	window_expired = false;
	state = CLAIM_IDLE;
	submit_attempts = 0;
	csr_der_len = 0;
	memset(nonce_text, 0, sizeof(nonce_text));
	memset(csr_der, 0, sizeof(csr_der));
	course_identity_discard_operational_key();
	printk("claim.window closed: %s\n", why);
	printk("claim.window the nonce and the pending key are gone. Nothing resumes a window;\n");
	printk("claim.window hold BOOT for %d seconds to open a new one.\n",
	       CONFIG_COURSE_PROVISIONING_BUTTON_HOLD_SECONDS);
}

/* Crockford base32, most significant bit first, no padding. */
static void encode_nonce(const uint8_t *raw, char *out)
{
	unsigned int acc = 0;
	int bits = 0;
	int written = 0;
	size_t at = 0;

	for (size_t i = 0; i < CLAIM_NONCE_BYTES; i++) {
		acc = (acc << 8) | raw[i];
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			if (written > 0 && written % 4 == 0) {
				out[at++] = '-';
			}
			out[at++] = crockford[(acc >> bits) & 0x1f];
			written++;
		}
	}
	out[at] = '\0';
}

static int generate_nonce(void)
{
	uint8_t raw[CLAIM_NONCE_BYTES];
	psa_status_t status;

	/*
	 * psa_generate_random(), not sys_csrand_get(), and that is a teaching
	 * decision as much as an engineering one. The same physical action
	 * generates the Operational key through psa_generate_key(), so the
	 * nonce and the key share one DRBG and one fate. The generator #126
	 * fixed would have produced a guessable nonce *and* a guessable key,
	 * and hanging both off one fix is what makes that story land.
	 */
	status = psa_generate_random(raw, sizeof(raw));
	if (status != PSA_SUCCESS) {
		printk("claim.nonce psa_generate_random failed status=%d\n", (int)status);
		return (int)status;
	}
	encode_nonce(raw, nonce_text);
	memset(raw, 0, sizeof(raw));
	return 0;
}

static void print_nonce(void)
{
	printk("claim.nonce %s\n", nonce_text);
	printk("claim.nonce Read that to whoever is claiming this device. They present it with\n");
	printk("claim.nonce their own Owner credential, from a machine this device never talks\n");
	printk("claim.nonce to. Both halves have to arrive inside the same window.\n");
	printk("claim.nonce A real product prints this on a label or a small screen. A serial\n");
	printk("claim.nonce console is a weaker stand-in, not an equivalent one: a label needs\n");
	printk("claim.nonce eyes on the device, and this needs a cable that grants far more\n");
	printk("claim.nonce than the nonce.\n");
}

void course_claim_open_window(void)
{
	int err;

	if (!course_identity_is_provisioned()) {
		/*
		 * Tier 6's behaviour exactly, and for a reason rather than by
		 * omission: a claim is carried on a connection the Factory key
		 * authenticates, and there is no identity here to authenticate
		 * it with. The provisioning interface still opens.
		 */
		printk("claim.window this device holds no Factory identity, so no window opens\n");
		printk("claim.window and no key is generated. Enroll it first.\n");
		return;
	}

	if (state != CLAIM_IDLE) {
		printk("claim.window a second press supersedes the window that was open\n");
		close_window("superseded by a new press");
	}

	if (course_identity_has_operational()) {
		printk("claim.window this device already holds an Operational certificate for\n");
		printk("claim.window owner %s, and a press still generates.\n",
		       course_identity_operational_owner() == NULL
			       ? "unreadable" : course_identity_operational_owner());
		printk("claim.window The issued identity is not touched by this. The service is\n");
		printk("claim.window the authority on who owns this device, and it will say so.\n");
	}

	err = generate_nonce();
	if (err != 0) {
		return;
	}
	err = course_identity_generate_operational_key();
	if (err != 0) {
		memset(nonce_text, 0, sizeof(nonce_text));
		return;
	}
	csr_der_len = 0;
	err = course_identity_build_operational_csr(csr_der, sizeof(csr_der), &csr_der_len);
	if (err != 0) {
		course_identity_discard_operational_key();
		memset(nonce_text, 0, sizeof(nonce_text));
		return;
	}

	submit_attempts = 0;
	next_exchange_ms = k_uptime_get();
	window_expired = false;
	state = CLAIM_SUBMIT;
	k_timer_start(&window_timer, K_SECONDS(CONFIG_COURSE_CLAIM_WINDOW_SECONDS), K_NO_WAIT);

	printk("claim.window open for %d seconds. This device times its own window and closes\n",
	       CONFIG_COURSE_CLAIM_WINDOW_SECONDS);
	printk("claim.window it by destroying the nonce and the key. The service times its own,\n");
	printk("claim.window starting when the request reaches it, and the service alone decides\n");
	printk("claim.window that a claim has expired. A reset kills this window.\n");
	print_nonce();
}

bool course_claim_window_open(void)
{
	return state != CLAIM_IDLE;
}

void course_claim_print_status(void)
{
	if (state == CLAIM_IDLE) {
		printk("claim.status no claim window is open\n");
		if (course_identity_has_operational()) {
			printk("claim.status this device holds an Operational certificate, owner=%s\n",
			       course_identity_operational_owner() == NULL
				       ? "unreadable" : course_identity_operational_owner());
		} else {
			printk("claim.status this device holds no Operational certificate\n");
		}
		return;
	}

	printk("claim.status window open, %u seconds remaining\n",
	       (unsigned int)(k_timer_remaining_get(&window_timer) / 1000U));
	printk("claim.status %s, submit attempts used %d of %d\n",
	       state == CLAIM_SUBMIT ? "submitting the request" : "waiting for the operator half",
	       submit_attempts, CONFIG_COURSE_CLAIM_SUBMIT_ATTEMPTS);
	print_nonce();
}

/* What the service can say back. json_obj_parse skips every key not named
 * here, so the service can add fields without breaking the device.
 *
 * check and reason are #136's two words, the same two enrollmentOutcome has
 * carried since Tier 6, so "refused at check <check>" is one sentence in both
 * tiers. device_id is deliberately absent: #136 adds it only when the service
 * knows it, and a field the device does not need is a field it should not
 * require.
 *
 * The service also sends result, claim_window_expires_at, poll_after_seconds,
 * owner_id, certificate_serial, certificate_fingerprint and not_after, and
 * none of them is named here. result would be a second way to ask a question
 * check already answers. The two time fields are the service's clock, and this
 * device has no wall clock to compare them against; its own k_timer closes its
 * own window and that is the only duration it is entitled to act on. The three
 * certificate fields describe the certificate that arrived in the same body,
 * and identity.c reads them out of the certificate itself rather than out of
 * the sentence next to it.
 *
 * check and reason are JSON_TOK_STRING, which costs nothing: that token type
 * hands back a pointer into the response buffer with the escapes left exactly
 * as they arrived, and both fields are prose this device only ever prints.
 *
 * certificate is JSON_TOK_STRING_BUF, and the difference is the whole reason
 * this device can be claimed at all. Zephyr unescapes only into a buffer:
 * JSON_TOK_STRING null-terminates the raw token in place and never touches a
 * backslash. A PEM block arrives with its newlines written as the two
 * characters that spell one, base64_decode has no idea what a backslash is,
 * and the certificate this device had just earned failed to decode with
 * -EINVAL. The service was correct, every host test was correct, and the
 * board threw the certificate away. Found on the board in #151, which is
 * where it could be found.
 */
struct claim_reply {
	const char *check;
	const char *reason;
	char certificate[CLAIM_CERT_PEM_MAX];
};

static const struct json_obj_descr claim_reply_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct claim_reply, check, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct claim_reply, reason, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct claim_reply, certificate, JSON_TOK_STRING_BUF),
};

static int build_request(void)
{
	size_t encoded = 0;
	int err;
	int len;
	static char csr_b64[CLAIM_CSR_MAX * 4 / 3 + 8];

	err = base64_encode((uint8_t *)csr_b64, sizeof(csr_b64), &encoded,
			    csr_der, csr_der_len);
	if (err != 0) {
		printk("claim.post cannot encode the certification request err=%d\n", err);
		return err;
	}
	csr_b64[encoded] = '\0';

	/*
	 * Two fields, and the absence of a third is the decision.
	 *
	 * This device used to send device_id as well. It cannot: the service
	 * decodes the body with DisallowUnknownFields, so a third field is a
	 * 400 and the claim never starts. #137 named three sources for the
	 * device's identifier — the client certificate, the request path, and
	 * the certification request's subject — and a fourth would only be a
	 * fourth thing that can disagree with the other three. The path already
	 * carries it, and the Factory certificate on this connection is what
	 * actually establishes it.
	 *
	 * The nonce goes out in the grouped form it was printed in. The service
	 * canonicalises before it hashes — upper case, hyphens dropped, and
	 * Crockford's I, L, O and U folded — so the spelling a person reads off
	 * this console and the spelling they type hash to the same verifier.
	 *
	 * The certification request goes out as base64 DER, which is what this
	 * device has. The service takes PEM or base64 DER and checks the
	 * signature either way.
	 */
	len = snprintf(request_body, sizeof(request_body),
		       "{\"nonce\":\"%s\",\"csr\":\"%s\"}",
		       nonce_text, csr_b64);
	if (len < 0 || len >= (int)sizeof(request_body)) {
		printk("claim.post the request body does not fit\n");
		return -ENOMEM;
	}
	return len;
}

/*
 * Accept the certificate the service issued, and stop.
 *
 * It arrives PEM armoured. This device used to assume bare base64 DER, on the
 * reasoning that Go's encoding/json produces exactly that for a []byte; #146
 * settled it the other way and the service encodes a PEM block, so the armour
 * is stripped here. The two spellings are told apart by the header rather than
 * by a content type, which is the same thing the service does in the other
 * direction with the certification request, and means neither side breaks if
 * the other changes its mind.
 *
 * Zephyr's base64_decode skips newlines but refuses the hyphens in the
 * BEGIN and END lines, so the armour has to come off before it rather than be
 * tolerated by it.
 *
 * identity.c refuses the result if it is not for the key this device is
 * holding or does not carry this device's name, and those refusals are the
 * reason the window can be closed either way afterwards.
 */
static void accept_certificate(const char *encoded)
{
	static const char pem_begin[] = "-----BEGIN CERTIFICATE-----";
	static const char pem_end[] = "-----END CERTIFICATE-----";
	const char *armoured = strstr(encoded, pem_begin);
	const char *base64_start = encoded;
	size_t base64_len = strlen(encoded);
	size_t decoded = 0;
	int err;

	if (armoured != NULL) {
		const char *footer = strstr(armoured, pem_end);

		base64_start = armoured + sizeof(pem_begin) - 1;
		if (footer == NULL || footer < base64_start) {
			printk("claim.issued the certificate opens a PEM block and never closes it\n");
			close_window("the issued certificate could not be read");
			return;
		}
		base64_len = (size_t)(footer - base64_start);
	}

	err = base64_decode(issued_cert, sizeof(issued_cert), &decoded,
			    (const uint8_t *)base64_start, base64_len);
	if (err != 0) {
		printk("claim.issued the certificate will not decode err=%d\n", err);
		close_window("the issued certificate could not be read");
		return;
	}
	err = course_identity_store_operational_certificate(issued_cert, decoded);
	if (err != 0) {
		close_window("the issued certificate was refused by this device");
		return;
	}

	k_timer_stop(&window_timer);
	window_expired = false;
	state = CLAIM_IDLE;
	submit_attempts = 0;
	csr_der_len = 0;
	memset(nonce_text, 0, sizeof(nonce_text));
	memset(csr_der, 0, sizeof(csr_der));
	/* The pending key is not discarded here: storing the certificate copied
	 * it into its persistent slot and dropped the pending handle already.
	 */
	printk("claim.window closed: this device is claimed\n");
	printk("claim.window it now presents its Operational certificate on every connection\n");
	printk("claim.window to a restricted endpoint, and its Factory certificate only when\n");
	printk("claim.window it claims or recovers.\n");
}

/* Wait out one poll interval before asking again.
 *
 * Every path that decides "no answer yet" goes through this, because the one
 * that did not was a busy loop: an exchange that completes without moving
 * next_exchange_ms is re-sent on the very next pass through course_claim_step,
 * which is a TLS handshake and a certification request every few milliseconds
 * for as long as the window lives.
 */
static void wait_one_poll(void)
{
	next_exchange_ms = k_uptime_get() + CONFIG_COURSE_CLAIM_POLL_SECONDS * 1000;
}

static void handle_reply(int status_code, size_t body_len)
{
	/* Static, and cleared on the way in rather than initialized on the
	 * stack: the certificate field carries a kilobyte and a half, and this
	 * runs on the claim thread beside a TLS session. The claim state
	 * machine is one thread doing one exchange at a time, which is what
	 * makes one buffer enough, and every other buffer in this file is
	 * static for the same reason.
	 */
	static struct claim_reply reply;
	int err;

	memset(&reply, 0, sizeof(reply));

	/*
	 * 400 is the one answer on this route that is not an authorization
	 * decision, and #146 is explicit that it never borrows a check name: it
	 * means the service could not read the request. The body is plain text
	 * rather than JSON, so there is nothing here to parse.
	 *
	 * It is terminal. Every poll re-sends identical bytes, so asking again
	 * cannot change the answer, and a claim that kept asking would open a
	 * mutually authenticated connection every few seconds until the window
	 * closed. It is also the one reply on this route that says the fault is
	 * on this side of the wire, so it says so.
	 */
	if (status_code == 400) {
		printk("claim.refused status=400, the service could not read this request\n");
		if (body_len > 0) {
			printk("claim.refused %.*s\n", (int)body_len, response_body);
		}
		printk("claim.refused that is this device failing to say what it meant, not the\n");
		printk("claim.refused service refusing the claim. Re-sending the same bytes cannot\n");
		printk("claim.refused change it, so the window closes.\n");
		close_window("the service could not read the claim request");
		return;
	}

	if (body_len == 0) {
		printk("claim.reply status=%d with no body, treating it as pending\n", status_code);
		wait_one_poll();
		return;
	}

	err = json_obj_parse(response_body, body_len, claim_reply_descr,
			     ARRAY_SIZE(claim_reply_descr), &reply);
	if (err < 0) {
		printk("claim.reply unreadable status=%d err=%d\n", status_code, err);
		wait_one_poll();
		return;
	}

	/*
	 * The device's whole rule, and it is deliberately not a list of names.
	 *
	 * #136 settled that every authorization refusal is 403 and the status is
	 * therefore never the reason, so the firmware branches on check and not
	 * on the status. It also settled that "pending" is simply a body without
	 * a check: the six required codes all mean no, and "not yet" is the
	 * ordinary state of a live window.
	 *
	 * So any check at all is terminal and stops the poll dead, and this code
	 * needs to know none of their names. That matters more than it looks:
	 * #135's prose named three terminal rejections that are not check names
	 * at all — already-owned is the check device-unowned, revoked is
	 * certificate-active, and decommissioned does not exist in Tier 7
	 * because decommissioning is Tier 8. A branch on a string the service
	 * never emits is a branch that never fires. Branching on the presence of
	 * the field cannot drift that way.
	 */
	if (reply.check != NULL) {
		printk("claim.refused status=%d check=%s\n", status_code, reply.check);
		if (reply.reason != NULL) {
			printk("claim.refused reason: %s\n", reply.reason);
		}
		printk("claim.refused that is a decision and not a delay, so this device stops\n");
		printk("claim.refused asking. Which component refused it is half of what this\n");
		printk("claim.refused check name tells you.\n");
		close_window("the service refused the claim");
		return;
	}

	/* An array is never NULL, so presence is an empty first byte. The parse
	 * cleared the whole struct above, so a body without the field leaves
	 * this empty and the poll carries on.
	 */
	if (reply.certificate[0] != '\0') {
		printk("claim.issued the operator half landed and the service issued a certificate\n");
		accept_certificate(reply.certificate);
		return;
	}

	if (state == CLAIM_SUBMIT) {
		printk("claim.pending the request is with the service. Waiting for the operator\n");
		printk("claim.pending half, polling every %d seconds on a fresh connection.\n",
		       CONFIG_COURSE_CLAIM_POLL_SECONDS);
	}
	state = CLAIM_POLL;
	wait_one_poll();
}

static void exchange_failed(int err)
{
	if (state == CLAIM_POLL) {
		/*
		 * Polling is the waiting state, so a transport failure is not
		 * an attempt spent. It retries at the same cadence until the
		 * window closes, and the k_timer is the only thing that bounds
		 * it.
		 */
		printk("claim.poll the exchange failed err=%d, retrying in %d seconds\n",
		       err, CONFIG_COURSE_CLAIM_POLL_SECONDS);
		next_exchange_ms = k_uptime_get() + CONFIG_COURSE_CLAIM_POLL_SECONDS * 1000;
		return;
	}

	/*
	 * Submitting is bounded, because it is a thing that either lands or
	 * does not. Four attempts on one cadence: the delay belongs to the
	 * attempt it precedes, so the first goes out at once and the three
	 * after it wait two, four and eight seconds. The fourth failure closes
	 * the device's own window and says the button must be pressed again,
	 * rather than holding a nonce open on a console indefinitely.
	 *
	 * A table rather than a shift, because the operator half at the
	 * service spells the same 0, 2, 4 and 8 seconds as a table, and the
	 * two are meant to be read side by side without deriving either of
	 * them. The shift that stood here also never reached eight: the budget
	 * ran out one attempt before the exponent got there, so the sequence a
	 * Learner saw was not the sequence the comment described.
	 */
	static const int backoff_seconds[] = { 0, 2, 4, 8 };

	submit_attempts++;
	printk("claim.submit attempt %d of %d failed err=%d\n", submit_attempts,
	       CONFIG_COURSE_CLAIM_SUBMIT_ATTEMPTS, err);
	if (submit_attempts >= CONFIG_COURSE_CLAIM_SUBMIT_ATTEMPTS) {
		close_window("the request could not be submitted");
		return;
	}
	/*
	 * The budget is a Kconfig value and the table is not, so a budget
	 * raised past four repeats the last delay instead of reading off the
	 * end of the table.
	 */
	size_t slot = (size_t)submit_attempts;

	if (slot >= ARRAY_SIZE(backoff_seconds)) {
		slot = ARRAY_SIZE(backoff_seconds) - 1;
	}
	int delay = backoff_seconds[slot];

	printk("claim.submit retrying in %d seconds\n", delay);
	next_exchange_ms = k_uptime_get() + delay * 1000;
}

void course_claim_step(void)
{
	size_t body_len = 0;
	int status_code = 0;
	int len;
	int err;

	if (state == CLAIM_IDLE) {
		return;
	}
	if (window_expired) {
		close_window("the ten minutes ran out");
		return;
	}
	if (k_uptime_get() < next_exchange_ms) {
		/* Short slices, because main is the thread the watchdog vouches
		 * for and waiting is still main doing its job.
		 */
		health_gate_feed();
		k_sleep(K_MSEC(500));
		return;
	}

	len = build_request();
	if (len < 0) {
		close_window("the request could not be built");
		return;
	}

	err = ota_client_claim_exchange(request_body, (size_t)len, response_body,
					sizeof(response_body), &body_len, &status_code);
	if (err != 0) {
		exchange_failed(err);
		return;
	}
	handle_reply(status_code, body_len);
}

#endif /* CONFIG_COURSE_CLAIM */
