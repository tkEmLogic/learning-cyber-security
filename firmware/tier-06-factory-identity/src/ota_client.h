/*
 * The Tier 4 OTA client.
 *
 * Tier 2 and Tier 3 shared one byte-identical client. It asked the service
 * which release to run, and the whole install decision was one strcmp on
 * release_id: everything else in that record was believed because it arrived
 * over a verified connection from a service with the right certificate.
 *
 * Tier 4 keeps the same Update assignment, byte for byte, and stops believing
 * it. GET /v1/releases/current is unchanged from Tier 0 and still says
 * "signed": true about whatever it is pointing at. The device now reads one
 * field out of it, the release identifier, and then goes and fetches signed
 * metadata about that release: a Release manifest and its detached signature.
 *
 * Everything that decides whether an image is installed comes from the
 * manifest. See release_policy.h for the checks and the order they run in.
 */

#ifndef COURSE_OTA_CLIENT_H
#define COURSE_OTA_CLIENT_H

#include "release_policy.h"

#include <stdbool.h>
#include <stddef.h>

#define OTA_FIELD_MAX 64
#define OTA_DIGEST_MAX 72

/* The Update assignment, exactly as Tier 0 read it.
 *
 * The digest and size in this record are still read and still printed, and
 * Tier 4 no longer acts on either: they are the service's claim about itself,
 * and a service that has been taken over writes them as happily as one that
 * has not. Only release_id is used, to learn which release to ask about.
 */
struct ota_release {
	char release_id[OTA_FIELD_MAX];
	char version[OTA_FIELD_MAX];
	char image_path[OTA_FIELD_MAX];
	char image_sha256[OTA_DIGEST_MAX];
	int image_size;
};

/* Reads the update assignment from GET /v1/releases/current. */
int ota_client_fetch_assignment(struct ota_release *release);

/* Fetches GET /v1/releases/{release_id}/manifest and its detached signature
 * from GET /v1/releases/{release_id}/manifest.sig, verifies the signature over
 * the manifest bytes exactly as they arrived, parses them only then, and runs
 * the metadata checks.
 *
 * Returns 0 only when the manifest is signed by the key this image carries,
 * describes the release that was asked about, and passes every check. The
 * refusal is printed by whichever check made it.
 */
int ota_client_fetch_manifest(const char *release_id, struct release_manifest *manifest);

/* Posts one status event to POST /v1/devices/<id>/events.
 *
 * The body names this device with the compiled-in identifier. The service
 * trusts that name, which is weakness T0-W-02.
 */
int ota_client_report(const char *event, const char *machine_state,
		      const char *release_id, const char *detail);

/* Downloads the image the manifest describes and asks MCUboot to swap it in
 * permanently. Returns 0 when the device is ready to reboot.
 *
 * The image path, the size and the digest all come from the verified
 * manifest, never from the Update assignment. The transfer is refused if the
 * length it declares does not match the manifest before a byte reaches flash,
 * and the upgrade is refused if the delivered bytes do not hash to the digest
 * the manifest declared.
 *
 * The upgrade stays permanent. Test boot, the health gate, confirmation and
 * revert are Tier 5's subject.
 */
int ota_client_install(const struct release_manifest *manifest);

/* True when the service assigned a release other than the one built into
 * this image.
 */
bool ota_release_differs(const struct ota_release *release);


/* True when this image was built with a Course certificate authority compiled
 * in. The build allows an image without one on purpose, so the repository
 * still builds standalone, and such an image trusts nothing and says so. The
 * health gate treats that as unhealthy: an image that cannot verify the
 * service it talks to must not confirm itself.
 */
bool ota_client_has_trust_anchor(void);

/* True when the update client came up.
 *
 * Deliberately says nothing about whether the service can be reached. Section 6
 * forbids loss of network service alone from failing the health gate, and this
 * is the predicate that would otherwise violate it.
 */
bool ota_client_ready(void);

/* A short fingerprint of the trust anchor compiled into this image, printed
 * at boot so a stale anchor diagnoses itself instead of looking like a
 * broken network. Compare it with ./course service certificate.
 */
const char *ota_client_anchor_description(void);
#endif /* COURSE_OTA_CLIENT_H */
