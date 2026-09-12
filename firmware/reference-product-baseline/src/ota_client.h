/*
 * The Tier 0 OTA client.
 *
 * It asks the local OTA service which release it should run, reports its own
 * status, and installs whatever image the service hands back. Tier 0 checks
 * nothing about the service or the image: that absence is the point of the
 * tier, and the Weakness ledger records it as T0-W-03 and T0-W-04.
 */

#ifndef COURSE_OTA_CLIENT_H
#define COURSE_OTA_CLIENT_H

#include <stdbool.h>
#include <stddef.h>

#define OTA_FIELD_MAX 64
#define OTA_DIGEST_MAX 72

struct ota_release {
	char release_id[OTA_FIELD_MAX];
	char version[OTA_FIELD_MAX];
	char image_path[OTA_FIELD_MAX];
	char image_sha256[OTA_DIGEST_MAX];
	int image_size;
};

/* Reads the update assignment from GET /v1/releases/current. */
int ota_client_fetch_assignment(struct ota_release *release);

/* Posts one status event to POST /v1/devices/<id>/events.
 *
 * The body names this device with the compiled-in identifier. The service
 * trusts that name, which is weakness T0-W-02.
 */
int ota_client_report(const char *event, const char *machine_state,
		      const char *release_id, const char *detail);

/* Downloads the release image into the secondary slot and asks MCUboot to
 * swap it in permanently. Returns 0 when the device is ready to reboot.
 *
 * No signature, publisher, or digest check happens here. Tier 3 adds the
 * first one.
 */
int ota_client_install(const struct ota_release *release);

/* True when the service assigned a release other than the one built into
 * this image.
 */
bool ota_release_differs(const struct ota_release *release);

#endif /* COURSE_OTA_CLIENT_H */
