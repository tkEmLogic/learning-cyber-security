/*
 * The Tier 4 release policy.
 *
 * Tier 3 taught the device to care who signed an image. It still learned what
 * to install from one mutable record the service was free to rewrite, and the
 * whole install decision was one strcmp on release_id.
 *
 * Tier 4 moves the decision onto a Release manifest: signed metadata that
 * describes exactly one firmware release, whose exact bytes are verified
 * before anything parses them. Everything this module does is a refusal it is
 * willing to explain.
 *
 * The order matters and it is the order of the functions below. A manifest is
 * verified before it is parsed, because parsing is the first thing that acts
 * on attacker-supplied bytes. The policy checks then run against values that
 * are known to have been signed, rather than against whatever the service
 * happened to say.
 */

#ifndef COURSE_RELEASE_POLICY_H
#define COURSE_RELEASE_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RELEASE_FIELD_MAX 64
#define RELEASE_DIGEST_MAX 72

/* The Release manifest, after its bytes have been verified and parsed.
 *
 * Every field here was covered by the signature. Nothing in this struct came
 * from the Update assignment, and nothing in it can be changed by the service
 * without the signature failing.
 */
struct release_manifest {
	int schema_version;
	char release_id[RELEASE_FIELD_MAX];
	char version[RELEASE_FIELD_MAX];
	int security_counter;
	char channel[RELEASE_FIELD_MAX];
	char board[RELEASE_FIELD_MAX];
	int hardware_revision_min;
	int hardware_revision_max;
	char image_path[RELEASE_FIELD_MAX];
	int image_size;
	char image_sha256[RELEASE_DIGEST_MAX];
	/* Carried, signed, and never acted on. This device has no clock, and
	 * every time source it can reach is controlled by something Tier 4
	 * assumes hostile. Signing these means they cannot be edited after the
	 * fact; it does not mean the device can check them. Tier 9 consumes
	 * them. See the Weakness ledger beside T2-W-09.
	 */
	char created_at[RELEASE_FIELD_MAX];
	char supported_until[RELEASE_FIELD_MAX];
};

/* Verify the detached signature over the exact manifest bytes.
 *
 * Check 1 of six, and the only one that runs before anything parses the
 * bytes. ECDSA P-256 over SHA-256, against the release verification key
 * compiled into this image. Returns 0 when the signature is good.
 */
int release_policy_verify(const uint8_t *body, size_t body_len,
			  const uint8_t *sig_der, size_t sig_len);

/* Parse verified manifest bytes into the struct above.
 *
 * Only ever called on bytes release_policy_verify() has already accepted. The
 * JSON parser writes into the buffer it is given, so calling this first would
 * mean verifying something other than what arrived.
 */
int release_policy_parse(char *body, size_t body_len, struct release_manifest *manifest);

/* Checks 2, 3 and 4: hardware compatibility, security counter, release
 * channel. Every one compares a signed manifest value against a value this
 * build asserts about itself, and every refusal says which.
 *
 * expected_release_id is the release the Update assignment named. A manifest
 * that describes a different release is refused before any policy check runs:
 * a manifest is only evidence about the release it names.
 */
int release_policy_admit(const struct release_manifest *manifest,
			 const char *expected_release_id);

/* Check 5: the delivered image is the size the manifest declared.
 *
 * declared is the manifest's image_size, delivered is what the transfer
 * actually produced. Called twice on the install path: once against the
 * Content-Length before a single byte reaches flash, and once against the
 * byte count after the transfer, because a header is a promise and a count is
 * a fact.
 */
int release_policy_check_size(const struct release_manifest *manifest,
			      size_t delivered, const char *when, bool before_write);

/* Check 6: the SHA-256 of the delivered bytes is the digest the manifest
 * declared. digest_hex is lower-case hex, NUL terminated.
 */
int release_policy_check_digest(const struct release_manifest *manifest,
				const char *digest_hex);

/* The running SHA-256 over the delivered image bytes, for check 6.
 *
 * Three calls rather than one, because the image is streamed straight into
 * flash and never exists anywhere this device could hash in one piece: the
 * secondary slot is 1.75 MiB and there is nothing like that much RAM. So the
 * digest is accumulated as the bytes go past.
 *
 * That is also the honest limit of check 6. The bytes are in flash by the time
 * the digest is known, so what this check protects is the upgrade request, not
 * the flash write. An image that fails it is never asked for, never swapped in
 * and never booted, and MCUboot would refuse it independently anyway.
 *
 * One download at a time, so the state is file-static and this header stays
 * free of PSA types.
 */
int release_digest_begin(void);
int release_digest_update(const uint8_t *data, size_t len);
int release_digest_finish(char *hex, size_t hex_len);

/* A short description of the release verification key compiled into this
 * image, for the boot banner. Says so plainly when there is none.
 */
const char *release_policy_key_description(void);

#endif /* COURSE_RELEASE_POLICY_H */
