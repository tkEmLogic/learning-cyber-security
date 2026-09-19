/*
 * Tier 7 device identity.
 *
 * Settled on issues #105, #112, #113, #114, #120 and #140.
 *
 * The factory build generates a P-256 key with the platform random number
 * generator, keeps it through the PSA Secure Storage configuration section 8
 * fixes, and proves possession of it in a certification request. Only the
 * public half ever leaves the device.
 *
 * Read the limitation with the code. The Secure Storage AEAD key is SHA-256
 * over a device identifier and the entry uid, and on this part that identifier
 * is six bytes of the factory MAC, which the device broadcasts in every Wi-Fi
 * frame. The key is encrypted at rest against casual inspection and its record
 * is authenticated against unauthenticated change. It is not protected against
 * anyone who can read the flash and run a hash.
 *
 * Tier 7 adds the Operational identity beside the Factory one. The shape is
 * Tier 6's, deliberately: key in Secure Storage, certificate in settings, and
 * the owner read out of the certificate rather than stored beside it. The one
 * departure is the pending key, which is volatile. See #140 and the comment
 * above course_identity_generate_operational_key().
 */

#include "identity.h"

#include <zephyr/kernel.h>
#include <zephyr/devicetree.h>
#include <zephyr/settings/settings.h>
#include <zephyr/kvss/nvs.h>
#include <string.h>
#include <stdio.h>

#ifdef CONFIG_COURSE_IDENTITY_FACTORY

#include <psa/crypto.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>

/*
 * The persistent PSA key identifier for the Factory key.
 *
 * Fixed rather than allocated. The device has exactly one Factory key for its
 * life, and a key whose identifier moved would be a key the next boot could
 * not find.
 */
#define COURSE_FACTORY_KEY_ID ((psa_key_id_t)0x00000601)

/*
 * The persistent PSA key identifier for the Operational key.
 *
 * The scheme is the Factory one continued, and it is chosen to be greppable.
 * A flash dump of a claimed Tier 7 device shows its/2/601 and its/2/701 side by
 * side, and the identifiers say which tier put each one there without anyone
 * having to consult a table.
 */
#define COURSE_OPERATIONAL_KEY_ID ((psa_key_id_t)0x00000701)

/* Where the certificate is kept. Settings, not Secure Storage.
 *
 * A certificate is public by construction: the device hands it to anyone who
 * connects. Putting it inside a store whose purpose is confidentiality would
 * blur the distinction this tier exists to draw, and a Learner who saw the key
 * and the certificate handled identically would learn that "secure storage"
 * means "important storage".
 */
#define COURSE_CERT_SETTINGS_KEY "course/identity/factory-cert"

/*
 * The Operational certificate shares the cap, and sharing it is the point.
 *
 * An Operational certificate is a Factory certificate with a different issuer
 * and one extra subject field, the owner slug in the OU. It is not larger, so
 * one cap stays one number to reason about.
 */
#define COURSE_OPERATIONAL_CERT_SETTINGS_KEY "course/identity/operational-cert"
#define COURSE_CERT_MAX 800

/*
 * Neither certificate may outgrow what one NVS entry can hold.
 *
 * nvs_write() refuses data larger than sector_size - 4 * ate_size, and an
 * entry that is refused at write time looks exactly like a device that was
 * never issued a certificate. #140 measured the numbers and found ample room;
 * this states the bound so the cap cannot drift past it silently. The ATE size
 * is eight bytes on this build and four of them are held back, which is the
 * subtraction nvs_sector_max_data_size() performs.
 */
#define COURSE_NVS_SECTOR_SIZE DT_PROP(DT_NODELABEL(flash0), erase_block_size)
BUILD_ASSERT(COURSE_CERT_MAX < COURSE_NVS_SECTOR_SIZE - 4 * 8,
	     "COURSE_CERT_MAX has grown past what one NVS entry can hold");

/*
 * The Bootstrap credential extension.
 *
 * OID 1.3.6.1.4.1.99999.6.1, a synthetic identifier under a private enterprise
 * arc that belongs to nobody, invented for the same reason Tier 5 invented a
 * custom image TLV tag: the value has to live somewhere the signature covers
 * and no standard attribute means what this one means.
 *
 * The bytes below are the OID's content octets, and they must agree with
 * courseCredentialOID in internal/courseapp/tier06.go. They were taken from
 * that encoder rather than worked out by hand.
 */
static const char credential_oid[] = {
	0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x06, 0x01
};

static unsigned char stored_cert[COURSE_CERT_MAX];
static size_t stored_cert_len;
static char device_id[COURSE_DEVICE_ID_MAX];
static char fingerprint[2 * 32 + 1];

static unsigned char stored_op_cert[COURSE_CERT_MAX];
static size_t stored_op_cert_len;
static char operational_owner[COURSE_DEVICE_ID_MAX];
static char operational_fingerprint[2 * 32 + 1];

/* The pending Operational key, for the life of one Claim window. Volatile, so
 * it has no identifier to remember across a boot and nothing to clean up after
 * a reset.
 */
static mbedtls_svc_key_id_t pending_key;
static bool pending_key_held;

/*
 * The argument stopped being unused in Tier 7, and that is a Tier 6 defect
 * rather than a Tier 7 addition.
 *
 * The handler is registered on the prefix "course/identity", so settings hands
 * it the remainder of every key under that prefix. Tier 6 had exactly one, so
 * ignoring the name was harmless; the moment a second entry exists, an
 * Operational certificate loads into stored_cert and the device reports its
 * Operational fingerprint as its Factory one. Found while settling #140, fixed
 * here, and an unrecognised name is now refused rather than silently absorbed.
 */
static int cert_settings_set(const char *name, size_t len,
			     settings_read_cb read_cb, void *cb_arg)
{
	unsigned char *target;
	size_t *target_len;

	if (settings_name_steq(name, "factory-cert", NULL)) {
		target = stored_cert;
		target_len = &stored_cert_len;
	} else if (settings_name_steq(name, "operational-cert", NULL)) {
		target = stored_op_cert;
		target_len = &stored_op_cert_len;
	} else {
		printk("identity.load unknown settings entry course/identity/%s, ignored\n",
		       name == NULL ? "(null)" : name);
		return -ENOENT;
	}

	if (len > COURSE_CERT_MAX) {
		printk("identity.load certificate is %zu bytes, larger than %d\n",
		       len, COURSE_CERT_MAX);
		return -EINVAL;
	}
	ssize_t got = read_cb(cb_arg, target, len);
	if (got < 0) {
		return (int)got;
	}
	*target_len = (size_t)got;
	return 0;
}

static struct settings_handler cert_handler = {
	.name = "course/identity",
	.h_set = cert_settings_set,
};

/* Read the identifier and the fingerprint out of the certificate itself.
 *
 * One source of truth. A device that held its identifier separately could
 * report a name its certificate does not carry, which is the gap this tier is
 * closing rather than one to reopen.
 */
/* Attribute OIDs, as their content octets. 2.5.4.3 is CN, 2.5.4.11 is OU. */
static const unsigned char oid_cn[] = { 0x55, 0x04, 0x03 };
static const unsigned char oid_ou[] = { 0x55, 0x04, 0x0B };

static void copy_attribute(const mbedtls_x509_name *subject, const unsigned char *oid,
			   char *out, size_t out_size)
{
	out[0] = '\0';
	for (const mbedtls_x509_name *name = subject; name != NULL; name = name->next) {
		if (name->oid.len != 3 || memcmp(name->oid.p, oid, 3) != 0) {
			continue;
		}
		size_t len = name->val.len;

		if (len >= out_size) {
			len = out_size - 1;
		}
		memcpy(out, name->val.p, len);
		out[len] = '\0';
		return;
	}
}

static void hex_fingerprint(const unsigned char *der, size_t len, char *out)
{
	uint8_t digest[32];
	size_t digest_len = 0;

	out[0] = '\0';
	if (psa_hash_compute(PSA_ALG_SHA_256, der, len, digest, sizeof(digest),
			     &digest_len) != PSA_SUCCESS) {
		return;
	}
	for (size_t i = 0; i < digest_len; i++) {
		snprintf(&out[i * 2], 3, "%02x", digest[i]);
	}
}

static int describe_certificate(void)
{
	device_id[0] = '\0';
	fingerprint[0] = '\0';
	if (stored_cert_len == 0) {
		return 0;
	}

	mbedtls_x509_crt cert;
	mbedtls_x509_crt_init(&cert);
	int err = mbedtls_x509_crt_parse_der(&cert, stored_cert, stored_cert_len);
	if (err != 0) {
		printk("identity.load stored certificate will not parse err=%d\n", err);
		mbedtls_x509_crt_free(&cert);
		stored_cert_len = 0;
		return err;
	}

	copy_attribute(&cert.subject, oid_cn, device_id, sizeof(device_id));
	hex_fingerprint(stored_cert, stored_cert_len, fingerprint);

	mbedtls_x509_crt_free(&cert);
	return 0;
}

/*
 * The same, for the Operational certificate, and it reads one extra field.
 *
 * The owner is the subject OU and it is never stored separately. One source of
 * truth: an owner slug held beside the certificate could disagree with the
 * certificate the device actually presents, and the device would then report a
 * scope it cannot prove.
 */
static int describe_operational_certificate(void)
{
	operational_owner[0] = '\0';
	operational_fingerprint[0] = '\0';
	if (stored_op_cert_len == 0) {
		return 0;
	}

	mbedtls_x509_crt cert;
	mbedtls_x509_crt_init(&cert);
	int err = mbedtls_x509_crt_parse_der(&cert, stored_op_cert, stored_op_cert_len);
	if (err != 0) {
		printk("identity.load stored Operational certificate will not parse err=%d\n", err);
		mbedtls_x509_crt_free(&cert);
		stored_op_cert_len = 0;
		return err;
	}

	copy_attribute(&cert.subject, oid_ou, operational_owner, sizeof(operational_owner));
	hex_fingerprint(stored_op_cert, stored_op_cert_len, operational_fingerprint);

	mbedtls_x509_crt_free(&cert);
	return 0;
}

/*
 * Print the settings NVS geometry actually in use, and how much of it is free.
 *
 * #109 and #120 were both one fault: a tier mounting a second NVS instance on
 * bytes another tier already owned, with nothing detecting it. #140 measured
 * that Tier 7 does not repeat it, and this line is what makes the next tier's
 * mistake show up on a console at boot rather than in a corrupted record six
 * months later. It reports rather than enforces, on purpose: the numbers are
 * what a future reader needs, and a device that refused to boot over them
 * would be worse than one that says what it found.
 */
static void announce_storage(void)
{
	void *backend = NULL;
	struct nvs_fs *fs;

	if (settings_storage_get(&backend) != 0) {
		printk("identity.storage settings would not say what it is backed by\n");
		return;
	}
	fs = backend;

	if (fs == NULL) {
		printk("identity.storage settings reports no backing store\n");
		return;
	}
	printk("identity.storage settings NVS at offset 0x%08lx, %u byte sectors, %u of them\n",
	       (unsigned long)fs->offset, (unsigned int)fs->sector_size,
	       (unsigned int)fs->sector_count);
	printk("identity.storage %ld bytes free. The storage partition is 0x%x bytes at 0x%x,\n",
	       (long)nvs_calc_free_space(fs), DT_REG_SIZE(DT_NODELABEL(storage_partition)),
	       DT_REG_ADDR(DT_NODELABEL(storage_partition)));
	printk("identity.storage so everything above the first %u bytes of it is unclaimed\n",
	       (unsigned int)(fs->sector_size * fs->sector_count));
	printk("identity.storage ground. A later tier that mounts its own NVS instance there\n");
	printk("identity.storage will move these numbers, which is the whole reason to print them.\n");
}

int course_identity_init(void)
{
	int err = settings_subsys_init();
	if (err != 0) {
		printk("identity.init settings would not start err=%d\n", err);
		return err;
	}
	err = settings_register(&cert_handler);
	if (err != 0 && err != -EEXIST) {
		printk("identity.init settings handler refused err=%d\n", err);
		return err;
	}
	err = settings_load();
	if (err != 0) {
		printk("identity.init settings would not load err=%d\n", err);
		return err;
	}
	(void)describe_certificate();
	(void)describe_operational_certificate();
	announce_storage();

	if (stored_cert_len == 0) {
		printk("identity.state unprovisioned, no Factory certificate held\n");
		return 0;
	}

	printk("identity.state provisioned device_id=%s\n", device_id);
	printk("identity.state factory certificate fingerprint=sha256:%s key=0x%08x\n",
	       fingerprint, (unsigned int)COURSE_FACTORY_KEY_ID);

	if (stored_op_cert_len > 0) {
		printk("identity.state operational certificate fingerprint=sha256:%s "
		       "key=0x%08x owner=%s\n",
		       operational_fingerprint, (unsigned int)COURSE_OPERATIONAL_KEY_ID,
		       operational_owner[0] == '\0' ? "unreadable" : operational_owner);
	} else {
		/*
		 * The sharpest line in the tier, stated before the Learner tries
		 * a download rather than after it fails. #135.
		 */
		printk("identity.state no operational certificate held, owner unknown\n");
		printk("identity.state this device will not download. It does not fall back to its factory\n");
		printk("identity.state identity, which claims and recovers and does not authorize updates.\n");
	}
	return 0;
}

bool course_identity_is_provisioned(void)
{
	return stored_cert_len > 0 && device_id[0] != '\0';
}

const char *course_identity_device_id(void)
{
	if (!course_identity_is_provisioned()) {
		return NULL;
	}
	return device_id;
}

const char *course_identity_factory_fingerprint(void)
{
	return fingerprint;
}

const char *course_identity_operational_fingerprint(void)
{
	return operational_fingerprint;
}

/* Two accessors carried across from the #157 spike: the certificate bytes to
 * present as a TLS client certificate, and the identifier of the key that signs
 * for them. Neither hands out private key material, which is the whole point.
 */
int course_identity_certificate(const unsigned char **der, size_t *len)
{
	if (stored_cert_len == 0) {
		return -ENOENT;
	}
	*der = stored_cert;
	*len = stored_cert_len;
	return 0;
}

uint32_t course_identity_key_id(void)
{
	return (uint32_t)COURSE_FACTORY_KEY_ID;
}

bool course_identity_has_operational(void)
{
	return stored_op_cert_len > 0;
}

const char *course_identity_operational_owner(void)
{
	if (stored_op_cert_len == 0 || operational_owner[0] == '\0') {
		return NULL;
	}
	return operational_owner;
}

int course_identity_operational_credentials(uint32_t *key_id,
					    const unsigned char **der, size_t *len)
{
	if (stored_op_cert_len == 0) {
		return -ENOENT;
	}
	*key_id = (uint32_t)COURSE_OPERATIONAL_KEY_ID;
	*der = stored_op_cert;
	*len = stored_op_cert_len;
	return 0;
}

static psa_status_t open_key(mbedtls_svc_key_id_t *out)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(COURSE_FACTORY_KEY_ID, &attributes);
	psa_reset_key_attributes(&attributes);
	if (status == PSA_SUCCESS) {
		*out = COURSE_FACTORY_KEY_ID;
	}
	return status;
}

int course_identity_generate_key(void)
{
	mbedtls_svc_key_id_t existing;
	if (open_key(&existing) == PSA_SUCCESS) {
		printk("identity.key already present id=0x%08x, keeping it\n",
		       (unsigned int)COURSE_FACTORY_KEY_ID);
		return 0;
	}

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_id(&attributes, COURSE_FACTORY_KEY_ID);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256);
	/*
	 * Signing only, and deliberately no PSA_KEY_USAGE_EXPORT.
	 *
	 * Section 8 asks for private keys to be marked non-exportable at the
	 * course API boundary while saying plainly that the core storage cannot
	 * enforce that against compromised privileged firmware. Both halves are
	 * true and the tier shows both: this flag makes psa_export_key() refuse,
	 * and a flash dump reads the key anyway.
	 */
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

	mbedtls_svc_key_id_t key_id;
	psa_status_t status = psa_generate_key(&attributes, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		printk("identity.key generation failed status=%d\n", (int)status);
		return (int)status;
	}
	printk("identity.key generated P-256 on this device id=0x%08x\n",
	       (unsigned int)COURSE_FACTORY_KEY_ID);
	printk("identity.key the private half has not left and cannot be exported\n");
	printk("identity.key stored through PSA Secure Storage, see the boot warning above\n");
	return 0;
}

int course_identity_try_export(void)
{
	uint8_t buffer[128];
	size_t length = 0;
	psa_status_t status = psa_export_key(COURSE_FACTORY_KEY_ID, buffer,
					     sizeof(buffer), &length);
	printk("identity.export asked PSA for the private key\n");
	if (status == PSA_SUCCESS) {
		printk("identity.export SUCCEEDED, %zu bytes. This is a defect.\n", length);
		memset(buffer, 0, sizeof(buffer));
		return -EPERM;
	}
	printk("identity.export refused status=%d (PSA_ERROR_NOT_PERMITTED is -133)\n",
	       (int)status);
	printk("identity.export the key has no PSA_KEY_USAGE_EXPORT flag, so the API will not\n");
	printk("identity.export hand it over. Read this beside E-6-05, which reads the same\n");
	printk("identity.export key out of a flash dump and succeeds.\n");
	return 0;
}

int course_identity_build_csr(const char *credential, unsigned char *out,
			      size_t out_size, size_t *out_len)
{
	if (credential == NULL || out == NULL || out_len == NULL) {
		return -EINVAL;
	}
	size_t credential_len = strlen(credential);
	if (credential_len == 0 || credential_len > 127) {
		printk("identity.csr credential length %zu is out of range\n", credential_len);
		return -EINVAL;
	}

	mbedtls_svc_key_id_t key_id;
	if (open_key(&key_id) != PSA_SUCCESS) {
		printk("identity.csr no device key yet\n");
		return -ENOENT;
	}

	/*
	 * The extension value is a DER PrintableString holding the credential.
	 *
	 * Two bytes of header then the text. It must match what the station's
	 * Go decoder expects, which marshals a Go string as a PrintableString,
	 * so the tag is 0x13 and the length is a single byte for anything under
	 * 128 characters.
	 */
	unsigned char value[2 + 128];
	value[0] = 0x13;
	value[1] = (unsigned char)credential_len;
	memcpy(&value[2], credential, credential_len);

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	int err = mbedtls_pk_wrap_psa(&pk, key_id);
	if (err != 0) {
		printk("identity.csr cannot wrap the PSA key err=%d\n", err);
		return err;
	}

	mbedtls_x509write_csr csr;
	mbedtls_x509write_csr_init(&csr);
	mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
	mbedtls_x509write_csr_set_key(&csr, &pk);

	char subject[COURSE_DEVICE_ID_MAX + 4];
	snprintf(subject, sizeof(subject), "CN=%s", CONFIG_COURSE_DEVICE_ID);
	err = mbedtls_x509write_csr_set_subject_name(&csr, subject);
	if (err == 0) {
		err = mbedtls_x509write_csr_set_extension(&csr, credential_oid,
							  sizeof(credential_oid), 0,
							  value, 2 + credential_len);
	}
	if (err != 0) {
		printk("identity.csr cannot build the request err=%d\n", err);
		goto done;
	}

	/*
	 * DER, written from the end of the buffer backwards, which is how
	 * mbedTLS writes every DER structure. The returned length is the number
	 * of bytes actually used and they sit at the end of the buffer, so the
	 * request is moved to the front before it is handed back.
	 */
	err = mbedtls_x509write_csr_der(&csr, out, out_size);
	if (err < 0) {
		printk("identity.csr cannot encode the request err=%d\n", err);
		goto done;
	}
	*out_len = (size_t)err;
	memmove(out, out + out_size - *out_len, *out_len);
	err = 0;
	printk("identity.csr built a %zu byte request, signed by the device key\n", *out_len);
	printk("identity.csr the Bootstrap credential is inside the signature, not beside it\n");

done:
	mbedtls_x509write_csr_free(&csr);
	mbedtls_pk_free(&pk);
	memset(value, 0, sizeof(value));
	return err;
}

int course_identity_store_certificate(const unsigned char *der, size_t len)
{
	if (der == NULL || len == 0 || len > sizeof(stored_cert)) {
		printk("identity.store certificate length %zu is out of range\n", len);
		return -EINVAL;
	}
	mbedtls_x509_crt cert;
	mbedtls_x509_crt_init(&cert);
	int err = mbedtls_x509_crt_parse_der(&cert, der, len);
	mbedtls_x509_crt_free(&cert);
	if (err != 0) {
		printk("identity.store refusing a certificate that will not parse err=%d\n", err);
		return err;
	}

	err = settings_save_one(COURSE_CERT_SETTINGS_KEY, der, len);
	if (err != 0) {
		printk("identity.store settings write failed err=%d\n", err);
		return err;
	}
	memcpy(stored_cert, der, len);
	stored_cert_len = len;
	(void)describe_certificate();
	printk("identity.store certificate held, device_id=%s\n", device_id);
	printk("identity.store fingerprint=sha256:%s\n", fingerprint);
	return 0;
}


/*
 * The pending Operational key.
 *
 * Volatile, and that is the decision #140 settled rather than an oversight.
 * #135 has a press on an already-claimed device still generate, so the device
 * holds a pending key and an issued one at the same moment; and it requires the
 * pending key to die with the window, and a reset to kill the window. A
 * volatile key makes both of those properties PSA enforces instead of cleanup
 * code this firmware has to get right, and it hands E-6-05 its counterpoint: a
 * flash dump taken during an open Claim window does not contain this key,
 * because it was never written.
 *
 * PSA_KEY_USAGE_COPY is what psa_copy_key() needs, and it is the only flag
 * added. A copy cannot gain usage flags its source did not have, so the key
 * that lands in the persistent slot is as non-exportable as the Factory key and
 * E-6-04 is untouched.
 */
int course_identity_generate_operational_key(void)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	/* A second physical action supersedes the first. #134: two live pending
	 * keys for one device would be two ways in.
	 */
	course_identity_discard_operational_key();

	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH |
					     PSA_KEY_USAGE_SIGN_MESSAGE |
					     PSA_KEY_USAGE_COPY);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

	status = psa_generate_key(&attributes, &pending_key);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		printk("identity.operational key generation failed status=%d\n", (int)status);
		return (int)status;
	}
	pending_key_held = true;
	printk("identity.operational generated a pending P-256 key, volatile\n");
	printk("identity.operational it is in RAM only. A reset destroys it, and so does the\n");
	printk("identity.operational window closing. Nothing writes it to flash unless a\n");
	printk("identity.operational certificate comes back for it.\n");
	return 0;
}

void course_identity_discard_operational_key(void)
{
	if (!pending_key_held) {
		return;
	}
	(void)psa_destroy_key(pending_key);
	pending_key_held = false;
	printk("identity.operational the pending key is destroyed\n");
}

int course_identity_build_operational_csr(unsigned char *out, size_t out_size,
					  size_t *out_len)
{
	if (out == NULL || out_len == NULL) {
		return -EINVAL;
	}
	if (!pending_key_held) {
		printk("identity.csr no pending Operational key; press BOOT to open a window\n");
		return -ENOENT;
	}
	if (device_id[0] == '\0') {
		printk("identity.csr this device holds no Factory certificate to take a name from\n");
		return -ENOENT;
	}

	mbedtls_pk_context pk;
	mbedtls_x509write_csr csr;
	char subject[COURSE_DEVICE_ID_MAX + 4];
	int err;

	mbedtls_pk_init(&pk);
	err = mbedtls_pk_wrap_psa(&pk, pending_key);
	if (err != 0) {
		printk("identity.csr cannot wrap the pending key err=%d\n", err);
		return err;
	}

	mbedtls_x509write_csr_init(&csr);
	mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
	mbedtls_x509write_csr_set_key(&csr, &pk);

	/*
	 * The subject name comes out of the Factory certificate, not out of
	 * CONFIG_COURSE_DEVICE_ID. It is the third identifier #137's
	 * identifier-consistent check compares, beside the certificate subject
	 * and the request path, and taking it from the build would let an image
	 * ask to be issued a certificate naming a neighbour.
	 *
	 * No Bootstrap credential extension. Tier 6 put one inside the
	 * signature because the station had no other way to know who was
	 * asking. This request travels on a connection the Factory key has
	 * already authenticated, so there is nothing left for it to prove.
	 */
	snprintf(subject, sizeof(subject), "CN=%s", device_id);
	err = mbedtls_x509write_csr_set_subject_name(&csr, subject);
	if (err != 0) {
		printk("identity.csr cannot set the subject err=%d\n", err);
		goto done;
	}

	err = mbedtls_x509write_csr_der(&csr, out, out_size);
	if (err < 0) {
		printk("identity.csr cannot encode the request err=%d\n", err);
		goto done;
	}
	*out_len = (size_t)err;
	memmove(out, out + out_size - *out_len, *out_len);
	err = 0;
	printk("identity.csr built a %zu byte Operational request for %s\n", *out_len, device_id);

done:
	mbedtls_x509write_csr_free(&csr);
	mbedtls_pk_free(&pk);
	return err;
}

/*
 * Does this certificate describe the key we are holding?
 *
 * Both halves are exported in the PSA format, which for P-256 is the 65 byte
 * uncompressed point, and compared. psa_export_public_key() is permitted on a
 * non-exportable key by the PSA specification regardless of the usage flags,
 * because a public key is public.
 */
static int certificate_matches_pending_key(mbedtls_x509_crt *cert)
{
	unsigned char from_key[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
	unsigned char from_cert[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
	size_t key_len = 0;
	size_t cert_len = 0;
	psa_status_t status;
	int err;

	status = psa_export_public_key(pending_key, from_key, sizeof(from_key), &key_len);
	if (status != PSA_SUCCESS) {
		printk("identity.store cannot read the pending public key status=%d\n",
		       (int)status);
		return (int)status;
	}
	err = mbedtls_pk_write_pubkey_psa(&cert->pk, from_cert, sizeof(from_cert), &cert_len);
	if (err != 0) {
		printk("identity.store cannot read the certificate public key err=%d\n", err);
		return err;
	}
	if (key_len != cert_len || memcmp(from_key, from_cert, key_len) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int course_identity_store_operational_certificate(const unsigned char *der, size_t len)
{
	char issued_to[COURSE_DEVICE_ID_MAX];
	mbedtls_x509_crt cert;
	int err;

	if (der == NULL || len == 0 || len > COURSE_CERT_MAX) {
		printk("identity.store Operational certificate length %zu is out of range\n", len);
		return -EINVAL;
	}
	if (!pending_key_held) {
		printk("identity.store a certificate arrived with no pending key to match it\n");
		printk("identity.store against. The window is closed; nothing is stored.\n");
		return -ENOENT;
	}

	mbedtls_x509_crt_init(&cert);
	err = mbedtls_x509_crt_parse_der(&cert, der, len);
	if (err != 0) {
		printk("identity.store refusing an Operational certificate that will not parse "
		       "err=%d\n", err);
		goto done;
	}

	err = certificate_matches_pending_key(&cert);
	if (err != 0) {
		printk("identity.store this certificate is not for the key this device is\n");
		printk("identity.store holding. Refused; the pending key is untouched.\n");
		goto done;
	}

	/*
	 * A CN mismatch is a refusal and not a warning. Accepting it would mean
	 * this device had taken a certificate naming a different device, and
	 * then presented it as its own on every connection.
	 */
	copy_attribute(&cert.subject, oid_cn, issued_to, sizeof(issued_to));
	if (device_id[0] == '\0' || strcmp(issued_to, device_id) != 0) {
		printk("identity.store this certificate names %s and this device is %s\n",
		       issued_to[0] == '\0' ? "nobody" : issued_to, device_id);
		printk("identity.store refused. A device that accepts a certificate naming\n");
		printk("identity.store someone else has stopped being one device.\n");
		err = -EBADMSG;
		goto done;
	}

	/*
	 * Only now does anything become persistent, and the key goes first.
	 *
	 * A certificate written before its key would describe a key that does
	 * not exist, which is the failure course_identity_erase() has been
	 * arguing against since Tier 6.
	 */
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t copied;
	psa_status_t status;

	status = psa_destroy_key(COURSE_OPERATIONAL_KEY_ID);
	if (status != PSA_SUCCESS && status != PSA_ERROR_INVALID_HANDLE) {
		printk("identity.store cannot clear the previous Operational key status=%d\n",
		       (int)status);
		err = (int)status;
		goto done;
	}

	psa_set_key_id(&attributes, COURSE_OPERATIONAL_KEY_ID);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	/*
	 * No usage flags and no algorithm are set here on purpose. psa_copy_key()
	 * takes the source key's policy when the target names none, and a copy
	 * can only narrow it. Restating the flags would be a second place for
	 * PSA_KEY_USAGE_EXPORT to creep in.
	 */
	status = psa_copy_key(pending_key, &attributes, &copied);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		printk("identity.store psa_copy_key refused status=%d\n", (int)status);
		err = (int)status;
		goto done;
	}

	err = settings_save_one(COURSE_OPERATIONAL_CERT_SETTINGS_KEY, der, len);
	if (err != 0) {
		printk("identity.store Operational settings write failed err=%d\n", err);
		(void)psa_destroy_key(COURSE_OPERATIONAL_KEY_ID);
		goto done;
	}

	memcpy(stored_op_cert, der, len);
	stored_op_cert_len = len;
	(void)describe_operational_certificate();
	course_identity_discard_operational_key();

	printk("identity.store operational certificate held, device_id=%s owner=%s\n",
	       device_id, operational_owner[0] == '\0' ? "unreadable" : operational_owner);
	printk("identity.store fingerprint=sha256:%s key=0x%08x\n",
	       operational_fingerprint, (unsigned int)COURSE_OPERATIONAL_KEY_ID);
	printk("identity.store the key was copied into its persistent slot, not re-generated.\n");
	printk("identity.store It is still the key that signed the request, and it is still\n");
	printk("identity.store non-exportable: a copy cannot gain a flag its source lacked.\n");

done:
	mbedtls_x509_crt_free(&cert);
	return err;
}

int course_identity_erase(void)
{
	/*
	 * Four places in Tier 7, because there are two keys in Secure Storage
	 * and two certificates in settings. Erasing some and not the others
	 * leaves a certificate describing a key that no longer exists, which
	 * looks provisioned and cannot sign anything. That is why this is one
	 * call rather than four.
	 *
	 * The pending key goes too. It is volatile, so it would not survive a
	 * reset anyway, but remanufacturing a device that is halfway through a
	 * Claim window should not leave the window open.
	 */
	course_identity_discard_operational_key();

	psa_status_t status = psa_destroy_key(COURSE_FACTORY_KEY_ID);
	if (status != PSA_SUCCESS && status != PSA_ERROR_INVALID_HANDLE) {
		printk("identity.erase could not destroy the key status=%d\n", (int)status);
		return (int)status;
	}
	status = psa_destroy_key(COURSE_OPERATIONAL_KEY_ID);
	if (status != PSA_SUCCESS && status != PSA_ERROR_INVALID_HANDLE) {
		printk("identity.erase could not destroy the Operational key status=%d\n",
		       (int)status);
		return (int)status;
	}
	int err = settings_delete(COURSE_CERT_SETTINGS_KEY);
	if (err != 0 && err != -ENOENT) {
		printk("identity.erase could not delete the certificate err=%d\n", err);
		return err;
	}
	err = settings_delete(COURSE_OPERATIONAL_CERT_SETTINGS_KEY);
	if (err != 0 && err != -ENOENT) {
		printk("identity.erase could not delete the Operational certificate err=%d\n", err);
		return err;
	}
	stored_cert_len = 0;
	stored_op_cert_len = 0;
	device_id[0] = '\0';
	fingerprint[0] = '\0';
	operational_owner[0] = '\0';
	operational_fingerprint[0] = '\0';
	printk("identity.erase both keys destroyed and both certificates deleted\n");
	printk("identity.erase this device is unprovisioned again, and its old record stands\n");
	return 0;
}

#endif /* CONFIG_COURSE_IDENTITY_FACTORY */
