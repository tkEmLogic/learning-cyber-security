#include "ota_client.h"

#include <stdio.h>
#include <string.h>
#include <zephyr/data/json.h>
#include <zephyr/dfu/flash_img.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/kernel.h>
#include <zephyr/net/http/client.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>

#include <mbedtls/x509.h>

/* The Course certificate authority, compiled into this image.
 *
 * ./course build firmware writes course_ca_der.inc from the authority
 * generated for your Course environment. Without it the build falls back to
 * anchor/course_ca_der.inc, which is empty, and this image then trusts nothing
 * and says so on the console.
 *
 * The trailing zero keeps the array from being zero length when the anchor is
 * empty, so the length is one less than the array.
 */
static const unsigned char course_ca_der[] = {
#include "course_ca_der.inc"
	0x00
};

#define COURSE_CA_DER_LEN (sizeof(course_ca_der) - 1)

/* One tag identifies the trust anchor in Zephyr's credential store. */
#define COURSE_CA_TAG 1

#define OTA_REQUEST_TIMEOUT_MS 15000
#define OTA_DOWNLOAD_TIMEOUT_MS 120000
#define OTA_RECV_BUF_SIZE 1024
#define OTA_BODY_BUF_SIZE 768
#define OTA_EVENT_PATH "/v1/devices/" CONFIG_COURSE_DEVICE_ID "/events"

/* The manifest and its signature get their own buffers, and they are static
 * for the same reason recv_buf is: this runs on the main thread's stack and a
 * kilobyte of manifest plus a verification is not what that stack is sized
 * for. A kilobyte of .bss spent here is visible in the map file; a stack
 * overflow during a signature check is not.
 *
 * OTA_MANIFEST_BUF_SIZE is generous on purpose. A manifest that does not fit
 * is refused as truncated rather than verified as far as it got.
 */
#define OTA_MANIFEST_BUF_SIZE 1024
#define OTA_SIGNATURE_BUF_SIZE 96

static uint8_t recv_buf[OTA_RECV_BUF_SIZE];
static char manifest_buf[OTA_MANIFEST_BUF_SIZE];
static uint8_t signature_buf[OTA_SIGNATURE_BUF_SIZE];

/* The JSON parser stores each string as a pointer into the response buffer,
 * so parsing needs its own struct of pointers. The values are copied into the
 * caller's fixed-size record before that buffer goes out of scope.
 *
 * Only the fields Tier 0 acts on appear here. json_obj_parse skips the rest of
 * the release record, so adding fields to the service does not break the
 * device.
 */
struct release_json {
	const char *release_id;
	const char *version;
	const char *image_path;
	const char *image_sha256;
	int image_size;
};

static const struct json_obj_descr release_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct release_json, release_id, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct release_json, version, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct release_json, image_path, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct release_json, image_sha256, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct release_json, image_size, JSON_TOK_NUMBER),
};

static void copy_field(char *target, size_t len, const char *value)
{
	if (value == NULL) {
		target[0] = '\0';
		return;
	}
	strncpy(target, value, len - 1);
	target[len - 1] = '\0';
}

struct body_capture {
	char *buf;
	size_t len;
	size_t used;
	/* A response longer than the buffer used to be silently cut short. For
	 * a release record that produced a parse error nobody could read; for a
	 * manifest it would mean verifying a prefix of what was sent, which is
	 * the sort of thing a signature check exists to prevent. So truncation
	 * is recorded and treated as a failure.
	 */
	bool overflow;
};

struct status_capture {
	int code;
};

struct image_writer {
	struct flash_img_context ctx;
	const struct release_manifest *manifest;
	size_t written;
	bool length_checked;
	int err;
};

/* Register the trust anchor once. The credential store keeps a pointer rather
 * than a copy, which is why course_ca_der has static storage.
 */
static int ota_install_trust_anchor(void)
{
	static bool installed;
	int err;

	if (installed) {
		return 0;
	}
	if (COURSE_CA_DER_LEN == 0) {
		printk("ota.tls no trust anchor is compiled into this image\n");
		printk("ota.tls this image trusts nothing and will refuse every service\n");
		printk("ota.tls run ./course setup and build again\n");
		return -ENOENT;
	}
	err = tls_credential_add(COURSE_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				 course_ca_der, COURSE_CA_DER_LEN);
	if (err != 0 && err != -EEXIST) {
		printk("ota.tls trust anchor rejected err=%d\n", err);
		return err;
	}
	installed = true;
	return 0;
}

/* Say which check failed, not just that something did.
 *
 * A device that stops without explaining teaches nothing, and "connection
 * failed" is indistinguishable from a cable problem. This reconnects once with
 * verification set to optional, purely to read the verification flags, and
 * closes the socket immediately. No request is ever sent on it and no data ever
 * crosses it.
 *
 * The connection that carries data, above, always requires verification. This
 * one exists so the refusal can be read out loud.
 */
static void ota_explain_refusal(struct sockaddr_in *addr)
{
	sec_tag_t tags[] = {COURSE_CA_TAG};
	int optional = TLS_PEER_VERIFY_OPTIONAL;
	uint32_t result = 0;
	socklen_t len = sizeof(result);
	int sock;

	sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (sock < 0) {
		return;
	}
	(void)zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, tags, sizeof(tags));
	(void)zsock_setsockopt(sock, SOL_TLS, TLS_HOSTNAME,
			       CONFIG_COURSE_OTA_SERVICE_NAME,
			       sizeof(CONFIG_COURSE_OTA_SERVICE_NAME));
	(void)zsock_setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY, &optional, sizeof(optional));
	if (zsock_connect(sock, (struct sockaddr *)addr, sizeof(*addr)) == 0 &&
	    zsock_getsockopt(sock, SOL_TLS, TLS_CERT_VERIFY_RESULT, &result, &len) == 0) {
		printk("ota.tls verification flags 0x%08x\n", result);
		if (result & MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
			printk("ota.tls  the certificate was not issued by the trust anchor in this image\n");
			printk("ota.tls  compared: the certificate issuer against the Course certificate authority\n");
		}
		if (result & MBEDTLS_X509_BADCERT_CN_MISMATCH) {
			printk("ota.tls  the certificate does not carry the name this device requires\n");
			printk("ota.tls  compared: the certificate names against %s\n",
			       CONFIG_COURSE_OTA_SERVICE_NAME);
		}
		if (result & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE)) {
			printk("ota.tls  the certificate validity window was rejected\n");
		}
		if (result == 0) {
			printk("ota.tls  the certificate verified; the failure was not the certificate\n");
		}
	}
	zsock_close(sock);
}

static int ota_connect(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(CONFIG_COURSE_OTA_TLS_PORT),
	};
	sec_tag_t tags[] = {COURSE_CA_TAG};
	int required = TLS_PEER_VERIFY_REQUIRED;
	int sock;
	int err;

	if (net_addr_pton(AF_INET, CONFIG_COURSE_OTA_HOST, &addr.sin_addr) != 0) {
		printk("ota.target invalid address %s\n", CONFIG_COURSE_OTA_HOST);
		return -EINVAL;
	}

	err = ota_install_trust_anchor();
	if (err != 0) {
		return err;
	}

	sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (sock < 0) {
		printk("ota.socket failed errno=%d\n", errno);
		return -errno;
	}

	/* The three options that make this a check rather than an encryption
	 * tunnel. The anchor to verify against, the name to require, and the
	 * demand that verification succeed.
	 *
	 * Zephyr already requires verification for clients by default, and sets
	 * an empty hostname when the application sets none, so a forgotten
	 * option fails loudly rather than accepting anything. This code states
	 * the requirement anyway, because a control that depends on a default
	 * is a control nobody can see.
	 */
	if (zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, tags, sizeof(tags)) < 0 ||
	    zsock_setsockopt(sock, SOL_TLS, TLS_HOSTNAME, CONFIG_COURSE_OTA_SERVICE_NAME,
			     sizeof(CONFIG_COURSE_OTA_SERVICE_NAME)) < 0 ||
	    zsock_setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY, &required, sizeof(required)) < 0) {
		printk("ota.tls could not configure verification errno=%d\n", errno);
		zsock_close(sock);
		return -errno;
	}

	if (zsock_connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int connect_errno = errno;

		printk("ota.tls refused the connection to %s:%d errno=%d\n",
		       CONFIG_COURSE_OTA_HOST, CONFIG_COURSE_OTA_TLS_PORT, connect_errno);
		printk("ota.tls required name %s issued by the trust anchor in this image\n",
		       CONFIG_COURSE_OTA_SERVICE_NAME);
		zsock_close(sock);
		ota_explain_refusal(&addr);
		printk("ota.tls no release data was read, and the running image is unchanged\n");
		return -connect_errno;
	}
	printk("ota.tls verified %s at %s:%d, connection established\n",
	       CONFIG_COURSE_OTA_SERVICE_NAME, CONFIG_COURSE_OTA_HOST,
	       CONFIG_COURSE_OTA_TLS_PORT);
	return sock;
}

static int capture_body(struct http_response *rsp, enum http_final_call final,
			void *user_data)
{
	struct body_capture *capture = user_data;
	size_t room;

	ARG_UNUSED(final);

	if (rsp->body_frag_len == 0) {
		return 0;
	}
	room = capture->len - capture->used - 1;
	if (rsp->body_frag_len > room) {
		capture->overflow = true;
	} else {
		room = rsp->body_frag_len;
	}
	memcpy(capture->buf + capture->used, rsp->body_frag_start, room);
	capture->used += room;
	capture->buf[capture->used] = '\0';
	return 0;
}

/* http_client_req refuses a request with no response callback, so even a
 * fire-and-forget POST needs one. This records the status line so the caller
 * can tell a rejected report from a delivered one.
 */
static int capture_status(struct http_response *rsp, enum http_final_call final,
			  void *user_data)
{
	struct status_capture *capture = user_data;

	ARG_UNUSED(final);

	if (capture != NULL) {
		capture->code = rsp->http_status_code;
	}
	return 0;
}

static int write_image(struct http_response *rsp, enum http_final_call final,
		       void *user_data)
{
	struct image_writer *writer = user_data;

	if (writer->err != 0) {
		return writer->err;
	}

	/* Check 5, first half, and the last thing that happens before a byte
	 * reaches flash. The transfer announced a length in its headers; if
	 * that does not match the size the signed manifest declared, nothing is
	 * written at all.
	 *
	 * A declared length is a promise, not a fact, so the same check runs
	 * again on the delivered count after the transfer. This half exists so
	 * an obviously wrong image never touches the slot.
	 */
	if (!writer->length_checked) {
		writer->length_checked = true;
		if (rsp->content_length == 0) {
			printk("ota.install the transfer declared no length; the size check "
			       "runs on the delivered bytes instead\n");
		} else if (release_policy_check_size(writer->manifest, rsp->content_length,
						     "length this transfer declared before any "
						     "byte was written", true) != 0) {
			writer->err = -EMSGSIZE;
			return writer->err;
		}
	}

	if (rsp->body_frag_len > 0) {
		writer->err = release_digest_update(rsp->body_frag_start, rsp->body_frag_len);
		if (writer->err != 0) {
			return writer->err;
		}
		writer->err = flash_img_buffered_write(&writer->ctx,
						       rsp->body_frag_start,
						       rsp->body_frag_len, false);
		if (writer->err != 0) {
			printk("ota.write failed offset=%zu err=%d\n",
			       writer->written, writer->err);
			return writer->err;
		}
		writer->written += rsp->body_frag_len;
	}
	if (final == HTTP_DATA_FINAL) {
		writer->err = flash_img_buffered_write(&writer->ctx, NULL, 0, true);
		if (writer->err != 0) {
			printk("ota.flush failed err=%d\n", writer->err);
			return writer->err;
		}
	}
	return 0;
}

static int run_request(struct http_request *req, int32_t timeout_ms, void *user_data)
{
	int sock = ota_connect();
	int err;

	if (sock < 0) {
		return sock;
	}
	/* The Host header names the service, the socket connects to an address.
	 * The name is never resolved: it is what the certificate is checked
	 * against, and what the service is called.
	 */
	req->host = CONFIG_COURSE_OTA_SERVICE_NAME;
	req->protocol = "HTTP/1.1";
	req->recv_buf = recv_buf;
	req->recv_buf_len = sizeof(recv_buf);

	err = http_client_req(sock, req, timeout_ms, user_data);
	zsock_close(sock);

	if (err < 0) {
		printk("ota.request failed url=%s err=%d\n", req->url, err);
		return err;
	}
	return 0;
}

int ota_client_fetch_assignment(struct ota_release *release)
{
	char body[OTA_BODY_BUF_SIZE];
	struct body_capture capture = {.buf = body, .len = sizeof(body)};
	struct release_json parsed = {0};
	struct http_request req = {
		.method = HTTP_GET,
		.url = "/v1/releases/current",
		.response = capture_body,
	};
	int err;

	body[0] = '\0';
	err = run_request(&req, OTA_REQUEST_TIMEOUT_MS, &capture);
	if (err != 0) {
		return err;
	}
	if (capture.used == 0) {
		printk("ota.assignment empty response\n");
		return -ENODATA;
	}
	if (capture.overflow) {
		printk("ota.assignment response longer than %zu bytes, refused as truncated\n",
		       sizeof(body));
		return -EMSGSIZE;
	}

	err = json_obj_parse(body, capture.used, release_descr,
			     ARRAY_SIZE(release_descr), &parsed);
	if (err < 0) {
		printk("ota.assignment unreadable err=%d\n", err);
		return err;
	}

	memset(release, 0, sizeof(*release));
	copy_field(release->release_id, sizeof(release->release_id), parsed.release_id);
	copy_field(release->version, sizeof(release->version), parsed.version);
	copy_field(release->image_path, sizeof(release->image_path), parsed.image_path);
	copy_field(release->image_sha256, sizeof(release->image_sha256), parsed.image_sha256);
	release->image_size = parsed.image_size;

	if (release->release_id[0] == '\0' || release->image_path[0] == '\0') {
		printk("ota.assignment missing release_id or image_path\n");
		return -EINVAL;
	}
	return 0;
}

/* Fetch one stored artifact of a release into a caller supplied buffer.
 *
 * The manifest and its signature are both served as opaque stored bytes, so
 * one function fetches either. Nothing here looks inside what it downloaded:
 * that is release_policy.c's job, and it does it in the order that matters.
 */
static int ota_fetch_release_artifact(const char *release_id, const char *suffix,
				      char *buf, size_t buf_len, size_t *used)
{
	char url[OTA_FIELD_MAX + 40];
	struct body_capture capture = {.buf = buf, .len = buf_len};
	struct http_request req = {
		.method = HTTP_GET,
		.response = capture_body,
	};
	int err;

	if (snprintf(url, sizeof(url), "/v1/releases/%s/%s", release_id, suffix) >=
	    (int)sizeof(url)) {
		return -ENOMEM;
	}
	req.url = url;
	buf[0] = '\0';

	err = run_request(&req, OTA_REQUEST_TIMEOUT_MS, &capture);
	if (err != 0) {
		return err;
	}
	if (capture.used == 0) {
		printk("ota.manifest %s returned nothing\n", url);
		return -ENODATA;
	}
	if (capture.overflow) {
		printk("ota.manifest %s is longer than the %zu bytes this device will "
		       "hold; refused as truncated rather than verified in part\n",
		       url, buf_len - 1);
		return -EMSGSIZE;
	}
	*used = capture.used;
	return 0;
}

int ota_client_fetch_manifest(const char *release_id, struct release_manifest *manifest)
{
	size_t manifest_len = 0;
	size_t signature_len = 0;
	int err;

	err = ota_fetch_release_artifact(release_id, "manifest",
					 manifest_buf, sizeof(manifest_buf), &manifest_len);
	if (err != 0) {
		return err;
	}
	err = ota_fetch_release_artifact(release_id, "manifest.sig",
					 (char *)signature_buf, sizeof(signature_buf),
					 &signature_len);
	if (err != 0) {
		return err;
	}
	printk("ota.manifest fetched %zu manifest bytes and a %zu byte detached signature\n",
	       manifest_len, signature_len);

	/* Check 1, and it runs here rather than after the parse on purpose.
	 * The bytes below are still exactly what came off the socket. One line
	 * further on they will not be, because the JSON parser rewrites the
	 * buffer it reads.
	 */
	err = release_policy_verify((const uint8_t *)manifest_buf, manifest_len,
				    signature_buf, signature_len);
	if (err != 0) {
		return err;
	}
	err = release_policy_parse(manifest_buf, manifest_len, manifest);
	if (err != 0) {
		return err;
	}
	return release_policy_admit(manifest, release_id);
}

int ota_client_report(const char *event, const char *machine_state,
		      const char *release_id, const char *detail)
{
	char payload[320];
	const char *headers[] = {"Content-Type: application/json\r\n", NULL};
	struct status_capture status = {0};
	struct http_request req = {
		.method = HTTP_POST,
		.url = OTA_EVENT_PATH,
		.header_fields = headers,
		.response = capture_status,
	};
	int len;
	int err;

	len = snprintf(payload, sizeof(payload),
		       "{\"device_id\":\"%s\",\"event\":\"%s\",\"machine_state\":\"%s\","
		       "\"running_release_id\":\"%s\",\"detail\":\"%s\","
		       "\"transport\":\"https\",\"synthetic_data\":true}",
		       CONFIG_COURSE_DEVICE_ID, event, machine_state, release_id,
		       detail == NULL ? "" : detail);
	if (len < 0 || len >= (int)sizeof(payload)) {
		return -ENOMEM;
	}
	req.payload = payload;
	req.payload_len = len;

	err = run_request(&req, OTA_REQUEST_TIMEOUT_MS, &status);
	if (err != 0) {
		return err;
	}
	if (status.code < 200 || status.code >= 300) {
		printk("ota.report rejected status=%d\n", status.code);
		return -EIO;
	}
	return 0;
}

bool ota_release_differs(const struct ota_release *release)
{
	return strcmp(release->release_id, CONFIG_COURSE_RELEASE_ID) != 0;
}

int ota_client_install(const struct release_manifest *manifest)
{
	char url[OTA_FIELD_MAX + 16];
	char digest_hex[65];
	struct image_writer writer = {.manifest = manifest};
	struct http_request req = {
		.method = HTTP_GET,
		.response = write_image,
	};
	int err;

	/* The path comes from the manifest, not from the Update assignment.
	 * Section 7 calls it the immutable image path: it is part of what was
	 * signed, so the service cannot point a verified release at a different
	 * file.
	 */
	if (snprintf(url, sizeof(url), "/v1/firmware/%s", manifest->image_path) >=
	    (int)sizeof(url)) {
		return -ENOMEM;
	}
	req.url = url;

	printk("ota.install starting release_id=%s version=%s size=%d\n",
	       manifest->release_id, manifest->version, manifest->image_size);
	printk("ota.install every value above came from the signed manifest\n");

	err = release_digest_begin();
	if (err != 0) {
		return err;
	}

	err = flash_img_init(&writer.ctx);
	if (err != 0) {
		printk("ota.slot unavailable err=%d\n", err);
		return err;
	}

	err = run_request(&req, OTA_DOWNLOAD_TIMEOUT_MS, &writer);
	if (err != 0) {
		return err;
	}
	if (writer.err != 0) {
		return writer.err;
	}
	if (writer.written == 0) {
		printk("ota.install received no image bytes\n");
		return -ENODATA;
	}

	/* Check 5, second half: what actually arrived, against what was
	 * signed. The header check above can be lied to; this one counts.
	 */
	err = release_policy_check_size(manifest, writer.written,
					"number of bytes this transfer actually delivered",
					false);
	if (err != 0) {
		return err;
	}

	/* Check 6. The bytes are in the secondary slot by now, because an
	 * image this size is streamed through a device that cannot hold it.
	 * What this check protects is the upgrade request below: an image whose
	 * digest is wrong is never asked for, so it is never swapped in and
	 * never booted, and MCUboot would refuse it on its own signature
	 * anyway. The two verifiers stay independent; passing one is never
	 * evidence for the other.
	 */
	err = release_digest_finish(digest_hex, sizeof(digest_hex));
	if (err != 0) {
		return err;
	}
	err = release_policy_check_digest(manifest, digest_hex);
	if (err != 0) {
		return err;
	}

	printk("ota.install wrote %zu bytes to the secondary slot\n", writer.written);
	printk("ota.install six checks ran and none refused\n");

	err = boot_request_upgrade(BOOT_UPGRADE_PERMANENT);
	if (err != 0) {
		printk("ota.upgrade request failed err=%d\n", err);
		return err;
	}
	printk("ota.upgrade requested a permanent swap, no test boot, no rollback\n");
	printk("ota.upgrade the bootloader now checks the signature and the security "
	       "counter itself, and its refusal is the one that stops a downgrade\n");
	return 0;
}

const char *ota_client_anchor_description(void)
{
	if (COURSE_CA_DER_LEN == 0) {
		return "none compiled in, this image trusts nothing";
	}
	return CONFIG_COURSE_TRUST_ANCHOR_FINGERPRINT;
}
