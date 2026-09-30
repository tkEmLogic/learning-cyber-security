/*
 * Renewal, the device's half. Settled on #207 and #212; the service's half is
 * services/ota/renewal.go (#251).
 *
 * The service decides when a renewal is due and says so with renew in the
 * assignment. The device never reasons about dates to decide it, and its Time
 * floor is not a trigger. When it is told:
 *
 *   1. a new volatile key, with PSA_KEY_USAGE_COPY;
 *   2. POST /v1/devices/{id}/renewal with a certification request for it,
 *      presented with the CURRENT Operational identity;
 *   3. the certificate comes back, the key is copied into the other slot and
 *      the certificate written beside it: the Renewal candidate;
 *   4. an ordinary renewal.activated event, presented with the candidate,
 *      which is the service's first sight of the new serial and so its
 *      activation record;
 *   5. only on a 2xx, the pointer flips, and the old key and certificate are
 *      destroyed together.
 *
 * A reset anywhere in that leaves a device that still works. Before 3 it holds
 * only its old identity. Between 3 and 5 it holds both, and the next poll
 * presents the candidate first: accepted, and it is promoted; refused, and it
 * is discarded and the device stays where it was.
 *
 * A failed attempt keeps the current identity, prints
 * renewal.failed check=<name> attempt=<n>, and retries on #148's 0, 2, 4 and 8
 * seconds over four attempts. After the fourth it waits for a later poll that
 * still says renew: the poll interval is the outer backoff, and there is no
 * third cadence. There is no failure record either. The service's refusal
 * trail already holds every refused attempt with its serial and its check.
 */

#ifndef COURSE_RENEWAL_H
#define COURSE_RENEWAL_H

#include <stdbool.h>

/*
 * If a Renewal candidate is held, present it now with an ordinary event.
 * Promotes it on a 2xx and returns 1. Discards it on a refusal and returns
 * -EACCES. A transport failure keeps it for the next poll and returns 0, as
 * does having no candidate.
 */
int course_renewal_prove_candidate(const char *machine_state);

/*
 * The assignment said renew. Run up to CONFIG_COURSE_RENEWAL_ATTEMPTS
 * attempts, and stop at the first that leaves a candidate behind.
 */
void course_renewal_run(const char *machine_state);

#endif /* COURSE_RENEWAL_H */
