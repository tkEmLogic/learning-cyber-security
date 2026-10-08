/*
 * The Time floor. Settled on #210 and #217.
 *
 * The latest moment this device has authenticated proof that the time has
 * reached. It is seeded from a build time compiled into the signed image, and
 * it rises, and only rises, to the created_at of every Release manifest whose
 * signature verifies against the release key compiled into the same image.
 * The signature is the evidence, not the install: a manifest that is then
 * refused by policy has still proved what time it is at least.
 *
 * It is not a clock and it is not the current time. It is a lower bound, so it
 * can prove that a certificate expired and can never prove that one is still
 * valid. It is not called monotonic either: it only rises against this
 * firmware, and someone who can rewrite the flash can write an older value
 * back (T6-W-17 widens to say so).
 *
 * It judges exactly one thing, the device's own Operational certificate, with
 * mbedtls_x509_time_cmp(), which is compiled whether or not
 * CONFIG_MBEDTLS_HAVE_TIME_DATE is set. It never judges the Factory
 * certificate: a release dated after 2036 would otherwise make every board
 * unrecoverable. It never judges a certificate the device is shown, because
 * Zephyr's TLS layer gives no tier a verify callback, and it is not a renewal
 * trigger, because it moves only when someone publishes a release.
 *
 * When the floor passes the Operational certificate's valid_to, the device
 * stops presenting that certificate, keeps running the product, prints why,
 * and stores an event to report once it holds a live identity again. It does
 * not change its own lifecycle state: the service's record is the authority
 * on that. The way back is recovery.
 */

#ifndef COURSE_TIME_FLOOR_H
#define COURSE_TIME_FLOOR_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Read the persisted floor, raise it to the build seed if the seed is later,
 * and judge the Operational identity against it. Call after identity and
 * recovery state are up.
 */
int time_floor_init(void);

/*
 * A manifest's signature has verified. Raise the floor to its created_at if
 * that is later, persist it, and judge again. created_at is RFC 3339 in UTC
 * with a Z, which is what ./course release sign writes; anything else is
 * refused as unreadable and the floor stays where it was.
 */
void time_floor_observe(const char *created_at, const char *release_id);

/* The floor as RFC 3339, for the banner and the event. */
const char *time_floor_text(void);

/*
 * The expiry event, if the floor refused an Operational certificate and the
 * event has not been delivered yet. It is kept in NVS, because the refused
 * certificate was the only way to deliver it: it goes out when a recovery has
 * given the device a live identity again.
 */
bool time_floor_expiry_pending(char *detail, size_t detail_size);
void time_floor_expiry_delivered(void);

#endif /* COURSE_TIME_FLOOR_H */
