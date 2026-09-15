/*
 * Tier 6 device identity.
 *
 * Settled on issues #105, #112, #113, #114 and #120.
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
 */

#include "identity.h"

#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>
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

/* Where the certificate is kept. Settings, not Secure Storage.
 *
 * A certificate is public by construction: the device hands it to anyone who
 * connects. Putting it inside a store whose purpose is confidentiality would
 * blur the distinction this tier exists to draw, and a Learner who saw the key
 * and the certificate handled identically would learn that "secure storage"
 * means "important storage".
 */
#define COURSE_CERT_SETTINGS_KEY "course/identity/factory-cert"
#define COURSE_CERT_MAX 800

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

static int cert_settings_set(const char *name, size_t len,
			     settings_read_cb read_cb, void *cb_arg)
{
	ARG_UNUSED(name);
	if (len > sizeof(stored_cert)) {
		printk("identity.load certificate is %zu bytes, larger than %zu\n",
		       len, sizeof(stored_cert));
		return -EINVAL;
	}
	ssize_t got = read_cb(cb_arg, stored_cert, len);
	if (got < 0) {
		return (int)got;
	}
	stored_cert_len = (size_t)got;
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

	const mbedtls_x509_name *name = &cert.subject;
	while (name != NULL) {
		if (name->oid.len == 3 && name->oid.p[0] == 0x55 &&
		    name->oid.p[1] == 0x04 && name->oid.p[2] == 0x03) {
			size_t len = name->val.len;
			if (len >= sizeof(device_id)) {
				len = sizeof(device_id) - 1;
			}
			memcpy(device_id, name->val.p, len);
			device_id[len] = '\0';
			break;
		}
		name = name->next;
	}

	uint8_t digest[32];
	size_t digest_len = 0;
	if (psa_hash_compute(PSA_ALG_SHA_256, stored_cert, stored_cert_len,
			     digest, sizeof(digest), &digest_len) == PSA_SUCCESS) {
		for (size_t i = 0; i < digest_len; i++) {
			snprintf(&fingerprint[i * 2], 3, "%02x", digest[i]);
		}
	}

	mbedtls_x509_crt_free(&cert);
	return 0;
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

	if (stored_cert_len == 0) {
		printk("identity.state unprovisioned, no Factory certificate held\n");
	} else {
		printk("identity.state provisioned device_id=%s\n", device_id);
		printk("identity.state certificate fingerprint=sha256:%s\n", fingerprint);
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

const char *course_identity_fingerprint(void)
{
	return fingerprint;
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

int course_identity_erase(void)
{
	/*
	 * Two places, because the key and the certificate are kept differently
	 * and on purpose. Erasing one and not the other leaves a certificate
	 * describing a key that no longer exists, which looks provisioned and
	 * cannot sign anything.
	 */
	psa_status_t status = psa_destroy_key(COURSE_FACTORY_KEY_ID);
	if (status != PSA_SUCCESS && status != PSA_ERROR_INVALID_HANDLE) {
		printk("identity.erase could not destroy the key status=%d\n", (int)status);
		return (int)status;
	}
	int err = settings_delete(COURSE_CERT_SETTINGS_KEY);
	if (err != 0 && err != -ENOENT) {
		printk("identity.erase could not delete the certificate err=%d\n", err);
		return err;
	}
	stored_cert_len = 0;
	device_id[0] = '\0';
	fingerprint[0] = '\0';
	printk("identity.erase key destroyed and certificate deleted\n");
	printk("identity.erase this device is unprovisioned again, and its old record stands\n");
	return 0;
}

#else /* CONFIG_COURSE_IDENTITY_SHARED */

/*
 * The shared identity.
 *
 * Every image built this way carries the same name. There is no key generation
 * and no Bootstrap credential: possession of the compiled-in credential is
 * simultaneously the identity and the authorization to enroll, which is what
 * section 11 means by a reusable default credential remaining active.
 */

int course_identity_init(void)
{
	printk("identity.state shared, every image built this way is this device\n");
	return 0;
}

bool course_identity_is_provisioned(void)
{
	return true;
}

const char *course_identity_device_id(void)
{
	return CONFIG_COURSE_DEVICE_ID;
}

const char *course_identity_fingerprint(void)
{
	return "shared";
}

#endif /* CONFIG_COURSE_IDENTITY_FACTORY */
