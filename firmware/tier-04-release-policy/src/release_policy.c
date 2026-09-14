#include "release_policy.h"

#include <stdio.h>
#include <string.h>
#include <zephyr/data/json.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <psa/crypto.h>
#include <mbedtls/psa_util.h>

/* Prove the algorithms are built in, rather than only that the calls link.
 *
 * psa_import_key() always links and returns PSA_ERROR_NOT_SUPPORTED at run
 * time when the driver behind it is absent, so linking proves nothing. These
 * four probes fail the build instead of the board.
 *
 * None of them needs a Kconfig symbol of its own. They arrive through
 * CONFIG_MBEDTLS_CIPHERSUITE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 and
 * CONFIG_NET_SOCKETS_SOCKOPT_TLS, which does "select PSA_CRYPTO". This tree is
 * Mbed TLS 4.1.0 with the separate tf-psa-crypto module: CONFIG_MBEDTLS_ECDSA_C,
 * CONFIG_MBEDTLS_ECP_C and CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED do not
 * exist here at all, and curves and algorithms are selected only through
 * PSA_WANT_*. See issue #65.
 */
#if !defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#error "PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY is not built in"
#endif
#if !defined(PSA_WANT_ALG_ECDSA)
#error "PSA_WANT_ALG_ECDSA is not built in"
#endif
#if !defined(PSA_WANT_ECC_SECP_R1_256)
#error "PSA_WANT_ECC_SECP_R1_256 is not built in"
#endif
#if !defined(PSA_WANT_ALG_SHA_256)
#error "PSA_WANT_ALG_SHA_256 is not built in"
#endif

/* The release verification key, compiled into this image.
 *
 * ./course build firmware writes release_pubkey.inc from the public half of
 * the Learner's Release signing key, exactly the way it writes the Course
 * certificate authority beside it. Nothing is fetched, and no build command
 * ever names the private half.
 *
 * These are the bare 65 bytes of an uncompressed P-256 point. The build strips
 * the 26-byte SubjectPublicKeyInfo wrapper, because PSA imports the point
 * directly and this image therefore carries no ASN.1 parser for it.
 * CONFIG_MBEDTLS_PEM_PARSE_C stays off for the same reason: turning it on
 * costs 1696 bytes of .text to do at run time what the build does for free.
 *
 * The trailing zero keeps the array from being zero length when the key is
 * absent, so the length is one less than the array. Without it the standalone
 * build would not compile; with it, the standalone build produces an image
 * that verifies nothing and says so.
 */
static const uint8_t release_pubkey[] = {
#include "release_pubkey.inc"
	0x00
};

#define RELEASE_PUBKEY_LEN (sizeof(release_pubkey) - 1)

/* An uncompressed P-256 point: one 0x04 tag and two 32-byte coordinates. */
#define RELEASE_PUBKEY_EXPECTED_LEN 65

/* Every refusal in this module says the same three things: which check ran,
 * what it compared, and what it rejected. A device that stops without
 * explaining teaches nothing, and the Learner has to be able to tell six
 * different refusals apart from the console alone.
 *
 * The fourth line is the consequence, which is not the same for every check.
 * The metadata checks refuse before a byte is requested. The size and digest
 * checks can only refuse after the bytes have arrived, so what they protect is
 * the upgrade request, not the flash write. Saying so is the honest version.
 */
static void refuse(const char *check, const char *compared, const char *rejected,
		   const char *consequence)
{
	printk("release.refused check=%s\n", check);
	printk("release.refused   compared: %s\n", compared);
	printk("release.refused   rejected: %s\n", rejected);
	printk("release.refused   consequence: %s\n", consequence);
}

#define REFUSED_BEFORE_DOWNLOAD \
	"no image bytes were requested, and the running image is unchanged"

#define REFUSED_AFTER_DOWNLOAD \
	"no upgrade was requested, so the bytes in the secondary slot are never " \
	"booted, and the running image is unchanged"

/* Tier 4 does not implement the sixth condition section 7 lists, "an image it
 * has already confirmed".
 *
 * This is where a reader would look for it, so this is where it is named. That
 * condition needs a confirmation flow: an image that has been booted once,
 * proved itself, and been marked confirmed, so that a later offer of the same
 * image can be recognised as one already settled. Tier 4 requests
 * BOOT_UPGRADE_PERMANENT and has no test boot, no health gate and no confirm
 * step, so it has nothing to compare against and would have to invent a memory
 * it does not keep. Test boot, confirmation and revert are Tier 5's subject,
 * and the condition arrives with them.
 *
 * The security counter check below covers the part of that ground Tier 4 can
 * actually stand on: a release that would take the device backwards is refused
 * whether or not it was ever confirmed.
 */

int release_policy_verify(const uint8_t *body, size_t body_len,
			  const uint8_t *sig_der, size_t sig_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key = PSA_KEY_ID_NULL;
	uint8_t digest[32];
	uint8_t sig_raw[64];
	char compared[160];
	char rejected[160];
	size_t digest_len = 0;
	size_t raw_len = 0;
	psa_status_t status;
	int err;

	if (RELEASE_PUBKEY_LEN != RELEASE_PUBKEY_EXPECTED_LEN) {
		snprintf(compared, sizeof(compared),
			 "the release verification key compiled into this image, %zu bytes, "
			 "against the %d bytes an uncompressed P-256 point takes",
			 RELEASE_PUBKEY_LEN, RELEASE_PUBKEY_EXPECTED_LEN);
		refuse("manifest-signature", compared,
		       "this image carries no usable release verification key, so it can "
		       "verify nothing; run ./course keys create release and build again",
		       REFUSED_BEFORE_DOWNLOAD);
		return -ENOENT;
	}

	/* Zephyr already calls psa_crypto_init() from its own SYS_INIT under
	 * CONFIG_MBEDTLS_INIT. It is idempotent, and stating the requirement
	 * here costs nothing: a control that depends on a default is a control
	 * nobody can see.
	 */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		snprintf(rejected, sizeof(rejected),
			 "the cryptography subsystem would not start, status=%d", (int)status);
		refuse("manifest-signature", "nothing; the check could not run", rejected,
		       REFUSED_BEFORE_DOWNLOAD);
		return -EIO;
	}

	status = psa_hash_compute(PSA_ALG_SHA_256, body, body_len,
				  digest, sizeof(digest), &digest_len);
	if (status != PSA_SUCCESS) {
		snprintf(rejected, sizeof(rejected),
			 "the manifest bytes could not be hashed, status=%d", (int)status);
		refuse("manifest-signature", "nothing; the check could not run", rejected,
		       REFUSED_BEFORE_DOWNLOAD);
		return -EIO;
	}

	/* PSA speaks raw r||s. A detached signature arrives as ASN.1 DER,
	 * which is what every offline signer emits, so it is converted here.
	 * A signature that is not well-formed DER is refused at this step and
	 * never reaches the verifier.
	 */
	err = mbedtls_ecdsa_der_to_raw(256, sig_der, sig_len,
				       sig_raw, sizeof(sig_raw), &raw_len);
	if (err != 0 || raw_len != sizeof(sig_raw)) {
		snprintf(compared, sizeof(compared),
			 "the %zu detached signature bytes against the shape of an "
			 "ASN.1 DER ECDSA P-256 signature", sig_len);
		snprintf(rejected, sizeof(rejected),
			 "the signature is not a well-formed P-256 signature, err=%d", err);
		refuse("manifest-signature", compared, rejected, REFUSED_BEFORE_DOWNLOAD);
		return -EINVAL;
	}

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
	/* The algorithm is named here and again at the call site below. PSA
	 * lets the verifier say what it is verifying; mbedtls_pk_verify() takes
	 * no algorithm argument and lets the key decide. For a check that is a
	 * security boundary, the verifier should be the one deciding.
	 */
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

	status = psa_import_key(&attr, release_pubkey, RELEASE_PUBKEY_LEN, &key);
	if (status != PSA_SUCCESS) {
		snprintf(rejected, sizeof(rejected),
			 "the compiled-in key could not be imported as a P-256 public key, "
			 "status=%d", (int)status);
		refuse("manifest-signature", "nothing; the check could not run", rejected,
		       REFUSED_BEFORE_DOWNLOAD);
		return -EIO;
	}

	status = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				 digest, digest_len, sig_raw, raw_len);
	(void)psa_destroy_key(key);

	if (status != PSA_SUCCESS) {
		snprintf(compared, sizeof(compared),
			 "the detached signature against SHA-256 of the %zu manifest bytes "
			 "exactly as they arrived, using the key compiled into this image",
			 body_len);
		snprintf(rejected, sizeof(rejected),
			 "the signature does not verify, status=%d; either these bytes are "
			 "not what was signed, or they were signed by another key",
			 (int)status);
		refuse("manifest-signature", compared, rejected, REFUSED_BEFORE_DOWNLOAD);
		return -EACCES;
	}

	printk("release.verified signature over %zu manifest bytes, ECDSA P-256 over SHA-256\n",
	       body_len);
	printk("release.verified nothing has parsed these bytes yet; that is the point\n");
	return 0;
}

/* The JSON parser stores each string as a pointer into the buffer it was
 * given, and rewrites that buffer in place while it works: it unescapes
 * strings and writes terminators over the bytes that separated them. That is
 * the concrete reason the signature is checked first and never again. After
 * this runs, the buffer no longer holds what arrived, so verifying it later
 * would be verifying something else.
 */
struct manifest_json {
	int schema_version;
	const char *release_id;
	const char *version;
	int security_counter;
	const char *channel;
	const char *board;
	int hardware_revision_min;
	int hardware_revision_max;
	const char *image_path;
	int image_size;
	const char *image_sha256;
	const char *created_at;
	const char *supported_until;
};

static const struct json_obj_descr manifest_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct manifest_json, schema_version, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, release_id, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, version, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, security_counter, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, channel, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, board, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, hardware_revision_min, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, hardware_revision_max, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, image_path, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, image_size, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, image_sha256, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, created_at, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct manifest_json, supported_until, JSON_TOK_STRING),
};

#define MANIFEST_FIELDS_REQUIRED ((1 << ARRAY_SIZE(manifest_descr)) - 1)

#define MANIFEST_SCHEMA_VERSION 1

static void copy_field(char *target, size_t len, const char *value)
{
	if (value == NULL) {
		target[0] = '\0';
		return;
	}
	strncpy(target, value, len - 1);
	target[len - 1] = '\0';
}

int release_policy_parse(char *body, size_t body_len, struct release_manifest *manifest)
{
	struct manifest_json parsed = {0};
	char compared[160];
	char rejected[160];
	int found;

	memset(manifest, 0, sizeof(*manifest));

	found = json_obj_parse(body, body_len, manifest_descr,
			       ARRAY_SIZE(manifest_descr), &parsed);
	if (found < 0) {
		snprintf(rejected, sizeof(rejected),
			 "the verified bytes are not readable JSON, err=%d", found);
		refuse("manifest-shape", "the manifest bytes against the JSON grammar",
		       rejected, REFUSED_BEFORE_DOWNLOAD);
		return -EINVAL;
	}
	if (found != MANIFEST_FIELDS_REQUIRED) {
		snprintf(compared, sizeof(compared),
			 "the fields present against the %d this device requires",
			 (int)ARRAY_SIZE(manifest_descr));
		snprintf(rejected, sizeof(rejected),
			 "a signed manifest is missing fields, found mask 0x%04x of 0x%04x",
			 found, MANIFEST_FIELDS_REQUIRED);
		refuse("manifest-shape", compared, rejected, REFUSED_BEFORE_DOWNLOAD);
		return -EINVAL;
	}
	if (parsed.schema_version != MANIFEST_SCHEMA_VERSION) {
		snprintf(compared, sizeof(compared),
			 "schema_version %d against the version %d this build understands",
			 parsed.schema_version, MANIFEST_SCHEMA_VERSION);
		refuse("manifest-shape", compared,
		       "a manifest written to a schema this image cannot read, which it "
		       "must not guess at", REFUSED_BEFORE_DOWNLOAD);
		return -EINVAL;
	}

	manifest->schema_version = parsed.schema_version;
	copy_field(manifest->release_id, sizeof(manifest->release_id), parsed.release_id);
	copy_field(manifest->version, sizeof(manifest->version), parsed.version);
	manifest->security_counter = parsed.security_counter;
	copy_field(manifest->channel, sizeof(manifest->channel), parsed.channel);
	copy_field(manifest->board, sizeof(manifest->board), parsed.board);
	manifest->hardware_revision_min = parsed.hardware_revision_min;
	manifest->hardware_revision_max = parsed.hardware_revision_max;
	copy_field(manifest->image_path, sizeof(manifest->image_path), parsed.image_path);
	manifest->image_size = parsed.image_size;
	copy_field(manifest->image_sha256, sizeof(manifest->image_sha256), parsed.image_sha256);
	copy_field(manifest->created_at, sizeof(manifest->created_at), parsed.created_at);
	copy_field(manifest->supported_until, sizeof(manifest->supported_until),
		   parsed.supported_until);
	return 0;
}

int release_policy_admit(const struct release_manifest *manifest,
			 const char *expected_release_id)
{
	char compared[200];
	char rejected[200];

	/* Binding, before any policy check. A manifest is evidence about the
	 * release it names and about nothing else, so a correctly signed
	 * manifest for a different release is not an answer to the question
	 * that was asked. Without this, a service could hand back last year's
	 * genuine manifest for this year's image.
	 */
	if (strcmp(manifest->release_id, expected_release_id) != 0) {
		snprintf(compared, sizeof(compared),
			 "the manifest's release_id %s against the release the assignment "
			 "named, %s", manifest->release_id, expected_release_id);
		refuse("manifest-binding", compared,
		       "a signed manifest that describes a different release than the one "
		       "this device was offered", REFUSED_BEFORE_DOWNLOAD);
		return -EINVAL;
	}

	/* Check 2: incompatible hardware.
	 *
	 * Two comparisons, because a release targets a board and a range of
	 * product hardware revisions. The revision this device asserts is
	 * compiled in and signed into nothing it reads: the chip can report its
	 * silicon stepping, but nothing on this part reports the product's
	 * hardware revision. Product identity is asserted and protected, never
	 * read. The boot banner prints both so the difference is visible.
	 */
	if (strcmp(manifest->board, CONFIG_BOARD_TARGET) != 0) {
		snprintf(compared, sizeof(compared),
			 "the manifest's board %s against this build's board %s",
			 manifest->board, CONFIG_BOARD_TARGET);
		refuse("hardware-compatibility", compared,
		       "a release built for another board", REFUSED_BEFORE_DOWNLOAD);
		return -ENOTSUP;
	}
	if (CONFIG_COURSE_HARDWARE_REVISION < manifest->hardware_revision_min ||
	    CONFIG_COURSE_HARDWARE_REVISION > manifest->hardware_revision_max) {
		snprintf(compared, sizeof(compared),
			 "this product's asserted hardware revision %d against the "
			 "manifest's hardware_revision_min..max %d..%d",
			 CONFIG_COURSE_HARDWARE_REVISION,
			 manifest->hardware_revision_min, manifest->hardware_revision_max);
		snprintf(rejected, sizeof(rejected),
			 "a release that does not cover this hardware revision");
		refuse("hardware-compatibility", compared, rejected, REFUSED_BEFORE_DOWNLOAD);
		return -ENOTSUP;
	}

	/* Check 3: security counter lower than the running one.
	 *
	 * Equal is allowed, lower never is. This check saves a wasted download
	 * and install; it is not the boundary. The bootloader is what actually
	 * stops a downgrade, by comparing this image's counter TLV against the
	 * candidate's. An attacker who rewrites this application's flash
	 * rewrites this check with it.
	 */
	if (manifest->security_counter < CONFIG_COURSE_SECURITY_COUNTER) {
		snprintf(compared, sizeof(compared),
			 "the manifest's security_counter %d against the counter %d this "
			 "running image was built with",
			 manifest->security_counter, CONFIG_COURSE_SECURITY_COUNTER);
		snprintf(rejected, sizeof(rejected),
			 "a release that would take this device backwards, version %s",
			 manifest->version);
		refuse("security-counter", compared, rejected, REFUSED_BEFORE_DOWNLOAD);
		printk("release.refused   note: the bootloader refuses this too, and its "
		       "refusal is the one that counts\n");
		return -EPERM;
	}

	/* Check 4: a release channel this device was not configured for. */
	if (strcmp(manifest->channel, CONFIG_COURSE_RELEASE_CHANNEL) != 0) {
		snprintf(compared, sizeof(compared),
			 "the manifest's channel %s against the channel %s this device was "
			 "configured for", manifest->channel, CONFIG_COURSE_RELEASE_CHANNEL);
		refuse("release-channel", compared,
		       "a release published to a channel this device does not follow",
		       REFUSED_BEFORE_DOWNLOAD);
		return -EPERM;
	}

	printk("release.admitted release_id=%s version=%s counter=%d channel=%s\n",
	       manifest->release_id, manifest->version, manifest->security_counter,
	       manifest->channel);
	printk("release.admitted board=%s hardware_revision %d..%d covers this product's %d\n",
	       manifest->board, manifest->hardware_revision_min,
	       manifest->hardware_revision_max, CONFIG_COURSE_HARDWARE_REVISION);
	printk("release.admitted created_at=%s supported_until=%s, carried and signed, "
	       "not checked: this device has no clock\n",
	       manifest->created_at, manifest->supported_until);
	return 0;
}

int release_policy_check_size(const struct release_manifest *manifest,
			      size_t delivered, const char *when, bool before_write)
{
	char compared[200];
	char rejected[200];

	if (delivered == (size_t)manifest->image_size) {
		return 0;
	}
	snprintf(compared, sizeof(compared),
		 "the %s, %zu bytes, against the manifest's signed image_size of %d bytes",
		 when, delivered, manifest->image_size);
	snprintf(rejected, sizeof(rejected),
		 "an image that is not the size the signed manifest declared, for release %s",
		 manifest->release_id);
	refuse("image-size", compared, rejected,
	       before_write ? REFUSED_BEFORE_DOWNLOAD : REFUSED_AFTER_DOWNLOAD);
	return -EMSGSIZE;
}

int release_policy_check_digest(const struct release_manifest *manifest,
				const char *digest_hex)
{
	char compared[200];
	char rejected[200];

	if (strcmp(digest_hex, manifest->image_sha256) == 0) {
		printk("release.accepted sha256=%s matches the signed manifest\n", digest_hex);
		return 0;
	}
	snprintf(compared, sizeof(compared),
		 "SHA-256 of the delivered bytes, %s, against the manifest's signed "
		 "image_sha256", digest_hex);
	snprintf(rejected, sizeof(rejected),
		 "bytes that are not the image the manifest describes; it declared %s",
		 manifest->image_sha256);
	refuse("image-digest", compared, rejected, REFUSED_AFTER_DOWNLOAD);
	return -EBADMSG;
}

/* The running digest. psa_hash_update() over each fragment as it is written
 * costs one pass over bytes that have to be copied anyway.
 */
static psa_hash_operation_t image_hash = PSA_HASH_OPERATION_INIT;

int release_digest_begin(void)
{
	psa_status_t status;

	(void)psa_hash_abort(&image_hash);
	image_hash = (psa_hash_operation_t)PSA_HASH_OPERATION_INIT;
	status = psa_hash_setup(&image_hash, PSA_ALG_SHA_256);
	if (status != PSA_SUCCESS) {
		printk("release.digest could not start SHA-256 status=%d\n", (int)status);
		return -EIO;
	}
	return 0;
}

int release_digest_update(const uint8_t *data, size_t len)
{
	psa_status_t status = psa_hash_update(&image_hash, data, len);

	if (status != PSA_SUCCESS) {
		printk("release.digest could not hash %zu bytes status=%d\n", len, (int)status);
		return -EIO;
	}
	return 0;
}

int release_digest_finish(char *hex, size_t hex_len)
{
	uint8_t digest[32];
	size_t digest_len = 0;
	psa_status_t status;

	if (hex_len < sizeof(digest) * 2 + 1) {
		return -ENOMEM;
	}
	status = psa_hash_finish(&image_hash, digest, sizeof(digest), &digest_len);
	if (status != PSA_SUCCESS) {
		printk("release.digest could not finish SHA-256 status=%d\n", (int)status);
		return -EIO;
	}
	for (size_t i = 0; i < digest_len; i++) {
		snprintf(&hex[i * 2], 3, "%02x", digest[i]);
	}
	hex[digest_len * 2] = '\0';
	return 0;
}

const char *release_policy_key_description(void)
{
	if (RELEASE_PUBKEY_LEN != RELEASE_PUBKEY_EXPECTED_LEN) {
		return "none compiled in, this image can verify no manifest";
	}
	return CONFIG_COURSE_SIGNING_KEY_FINGERPRINT;
}
