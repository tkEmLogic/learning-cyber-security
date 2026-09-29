/* The host stand-in's two extra calls. See identity_host.c. */

#ifndef COURSE_IDENTITY_HOST_H
#define COURSE_IDENTITY_HOST_H

#include <stddef.h>
#include <stdint.h>

/* Hold this DER as the current Operational certificate, as a boot or a
 * recovery would, with no refusal yet.
 */
int host_identity_load(const uint8_t *der, size_t len);

/* What identity.c's credential accessor answers: the certificate, -ENOENT with
 * none, or -EKEYEXPIRED once the Time floor has refused it.
 */
int host_identity_present(const unsigned char **der, size_t *len);

#endif /* COURSE_IDENTITY_HOST_H */
