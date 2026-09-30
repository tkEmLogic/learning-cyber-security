/*
 * The Claim window.
 *
 * Settled on issues #134, #135, #136, #137 and #140. This is the timed
 * protocol half of Tier 7: a nonce, a ten-minute window, a bounded submit and
 * a poll. The key and the certificate it produces are identity.h's, and the
 * boundary is deliberate — the nonce and the window are the *claim*, the key
 * and the certificate are the *identity*. identity.h carries no timing at all.
 *
 * Both parties time ten minutes and they are not the same ten minutes. This
 * device arms a k_timer on the physical action and closes its own window by
 * destroying the nonce and the pending Operational key. It never reports a
 * time to the service and the service is the only party that decides a claim
 * is expired. Device time stays evidence and never becomes an authorization
 * input, which is the rule the whole course has been holding since Tier 0 and
 * which CONFIG_MBEDTLS_HAVE_TIME_DATE=n keeps the device honest about.
 */

#ifndef COURSE_CLAIM_H
#define COURSE_CLAIM_H

#include <stdbool.h>

/*
 * Open a Claim window: generate the nonce and the pending Operational key,
 * print the nonce, and start the timer.
 *
 * Called from the ten-second BOOT hold, which #135 kept unchanged and which
 * now opens the provisioning interface and this window in one act. The press
 * generates; nothing is typed to cause it.
 *
 * A press on an already-claimed device still opens a window. The device is not
 * the authority on who owns it, and a device that answers that question by
 * itself has quietly become one — so the refusal comes back from the service as
 * a named check, and the board earns that rejection itself instead of borrowing
 * it from a host fixture.
 *
 * A press never touches an already-issued Operational identity. It creates a
 * pending key that dies with the window. An issued identity is only ever
 * replaced by a certificate that actually arrives. That is an invariant, not an
 * intention.
 *
 * A second press supersedes the first: the old nonce and old pending key are
 * destroyed before new ones are made. Two live nonces for one device would be
 * two ways in.
 */
void course_claim_open_window(void);

/* Whether a Claim window is open on this device right now. */
bool course_claim_window_open(void);

/*
 * One unit of claim work, on main.
 *
 * Called from main's loop while a window is open. It performs at most one
 * exchange with the service — one run_request(), on a fresh connection, per
 * #158's one-at-a-time decision — and returns. It sleeps only in short slices
 * and feeds the watchdog, because main is the thread the watchdog vouches for.
 */
void course_claim_step(void);

/*
 * Reprint the nonce, the time remaining and the attempt state.
 *
 * #135 allows this: withholding the nonce from a shell on the same wire that
 * already printed it buys nothing and costs the Learner a walk back to the
 * button. It is safe because the control is the ten-minute window, not the
 * nonce staying secret over time — a label, which this console stands in for,
 * is also always readable.
 */
void course_claim_print_status(void);

#endif /* COURSE_CLAIM_H */
