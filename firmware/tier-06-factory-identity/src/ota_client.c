#include "ota_client.h"
#include "identity.h"
#include "health_gate.h"
#include "recovery_state.h"

#include <stdio.h>
#include <string.h>
#include <zephyr/data/json.h>
#include <zephyr/dfu/flash_img.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/storage/stream_flash.h>
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
/* The event path is built at runtime from Tier 6 onwards.
 *
 * Every earlier tier pasted CONFIG_COURSE_DEVICE_ID in here with the
 * preprocessor, which was correct while every board reported the same name. The
 * factory build reports an identifier read out of its own Factory certificate,
 * so the path cannot be known until the certificate is.
 *
 * A device with no identity builds no path and sends no event. There is
 * deliberately no fallback to the shared name: "failed enrollment silently
 * falls back to shared identity" is a stated failure criterion in section 11.
 */
#define OTA_EVENT_PATH_MAX (sizeof("/v1/devices//events") + COURSE_DEVICE_ID_MAX)

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

/* How often the progress record is written, in bytes.
 *
 * About 28 writes for a full image rather than the several hundred a per-chunk
 * record would cost, and at most this much re-downloaded after a power cut,
 * which is invisible to a Learner.
 *
 * It is also what makes a resume legal at all. stream_flash writes must be
 * aligned to the write block size, so a resume offset has to be too, and a
 * multiple of 64 KiB is a multiple of both the write block and the 4 KiB
 * sector. An arbitrary byte offset would not have been.
 */
#define OTA_CHECKPOINT_BYTES (64 * 1024)

struct image_writer {
	struct stream_flash_ctx stream;
	const struct release_manifest *manifest;
	/* Bytes already in the slot when this request started. Zero for a
	 * fresh download.
	 */
	size_t resume_offset;
	/* Bytes this request has written. */
	size_t written;
	/* Bytes written since the progress record was last updated. */
	size_t since_checkpoint;
	bool headers_checked;
	int err;
};

static uint8_t stream_buf[512];

/* Writes the progress record for everything currently in the slot.
 *
 * Called after the bytes it describes have reached flash, never before. That
 * order is the whole safety property: a record that lags the flash can only
 * under-claim, and under-claiming costs re-downloaded bytes, while
 * over-claiming would resume into a gap and build an image that only the
 * digest would catch.
 */
static int checkpoint(struct image_writer *writer)
{
	struct download_record record;

	memset(&record, 0, sizeof(record));
	strncpy(record.release_id, writer->manifest->release_id,
		sizeof(record.release_id) - 1);
	strncpy(record.digest, writer->manifest->image_sha256,
		sizeof(record.digest) - 1);
	record.offset = (uint32_t)(writer->resume_offset + writer->written);
	record.size = (uint32_t)writer->manifest->image_size;

	return recovery_download_write(&record);
}

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

	/* The response headers are judged once, before a byte reaches flash.
	 *
	 * Two things are checked here and a third is deliberately left to the
	 * digest.
	 *
	 * A resumed request must come back as 206 Partial Content. A server
	 * that ignores Range and answers 200 with the whole body is the case
	 * most likely to be got wrong, because it looks like success while
	 * overwriting the slot from byte zero as the device believes it is
	 * appending. Refusing 200 outright is what stops that.
	 *
	 * The length the response declares, added to what is already in the
	 * slot, must come to the size the signed manifest declared. That
	 * catches a range that is the wrong length.
	 *
	 * What is not checked here is the Content-Range header's start offset.
	 * Reading a named response header means reaching into
	 * http_request.internal to recover the caller's context from the
	 * parser, which is a subsystem's private business and breaks on
	 * upgrade. So a response that starts at the wrong offset but is the
	 * right length reaches flash and is refused afterwards by the digest,
	 * which is computed over the slot rather than over the stream. Section
	 * 7 requires all three to be refused; two are refused before any write
	 * and one after, and the module says so rather than implying the
	 * device caught everything early.
	 */
	if (!writer->headers_checked) {
		writer->headers_checked = true;

		if (writer->resume_offset > 0 && rsp->http_status_code != 206) {
			printk("ota.resume refused status=%d, expected 206 Partial Content\n",
			       rsp->http_status_code);
			printk("ota.resume a service that ignores Range and returns the whole\n");
			printk("ota.resume body would restart this image from byte zero while\n");
			printk("ota.resume this device believed it was appending\n");
			writer->err = -EPROTO;
			return writer->err;
		}
		if (rsp->content_length > 0) {
			size_t total = writer->resume_offset + rsp->content_length;

			if (release_policy_check_size(writer->manifest, total,
						      "length this transfer declared, added to what "
						      "is already in the slot, before any byte was "
						      "written", true) != 0) {
				writer->err = -EMSGSIZE;
				return writer->err;
			}
		} else {
			printk("ota.install the transfer declared no length; the size check "
			       "runs on the delivered bytes instead\n");
		}
	}

	/* A download runs for longer than the watchdog window, and it runs in
	 * main, which is the thread the watchdog is vouching for. Without this
	 * the device resets itself part way through every transfer. Feeding here
	 * is correct rather than a workaround: bytes arriving and being written
	 * is exactly the thread doing its job.
	 */
	health_gate_feed();

	if (rsp->body_frag_len > 0) {
		writer->err = stream_flash_buffered_write(&writer->stream,
							  rsp->body_frag_start,
							  rsp->body_frag_len, false);
		if (writer->err != 0) {
			printk("ota.write failed offset=%zu err=%d\n",
			       writer->resume_offset + writer->written, writer->err);
			return writer->err;
		}
		writer->written += rsp->body_frag_len;
		writer->since_checkpoint += rsp->body_frag_len;

		if (writer->since_checkpoint >= OTA_CHECKPOINT_BYTES) {
			/* Flush first, so the record describes bytes that are
			 * actually in flash rather than bytes still sitting in
			 * the stream buffer.
			 */
			writer->err = stream_flash_buffered_write(&writer->stream, NULL, 0, true);
			if (writer->err != 0) {
				return writer->err;
			}
			writer->since_checkpoint = 0;
			writer->err = checkpoint(writer);
			if (writer->err != 0) {
				printk("ota.progress could not be recorded err=%d\n",
				       writer->err);
				return writer->err;
			}
			printk("ota.progress %zu of %d bytes are in the slot\n",
			       writer->resume_offset + writer->written,
			       writer->manifest->image_size);
		}
	}
	if (final == HTTP_DATA_FINAL) {
		writer->err = stream_flash_buffered_write(&writer->stream, NULL, 0, true);
		if (writer->err != 0) {
			printk("ota.flush failed err=%d\n", writer->err);
			return writer->err;
		}
		writer->err = checkpoint(writer);
	}
	return writer->err;
}

static int run_request(struct http_request *req, int32_t timeout_ms, void *user_data)
{
	int sock;
	int err;

	/* Every exchange with the service is main making progress, and main is
	 * the thread the watchdog vouches for. Feeding around each one is what
	 * keeps ordinary work from looking like a hang.
	 *
	 * This matters more than it sounds. One poll opens four TLS
	 * connections, and ECDSA handshakes on this part are not fast. Feeding
	 * once per poll was enough while the device had nothing to download and
	 * refused the assignment early, and stopped being enough the moment it
	 * had a manifest to fetch. The board showed it as a healthy image
	 * resetting partway through the poll that would have started an
	 * install.
	 */
	health_gate_feed();

	sock = ota_connect();
	if (sock < 0) {
		return sock;
	}
	health_gate_feed();
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
	health_gate_feed();

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
	const char *device_id = course_identity_device_id();
	char event_path[OTA_EVENT_PATH_MAX];
	char payload[320];

	/* A device with no identity says nothing, rather than saying it is
	 * somebody else. This is the refusal that makes the factory build's
	 * unprovisioned state visible instead of silent.
	 */
	if (device_id == NULL) {
		printk("ota.report suppressed: this device holds no identity to report under\n");
		return -ENOENT;
	}
	if (snprintf(event_path, sizeof(event_path), "/v1/devices/%s/events", device_id) >=
	    (int)sizeof(event_path)) {
		return -ENOMEM;
	}

	const char *headers[] = {"Content-Type: application/json\r\n", NULL};
	struct status_capture status = {0};
	struct http_request req = {
		.method = HTTP_POST,
		.url = event_path,
		.header_fields = headers,
		.response = capture_status,
	};
	int len;
	int err;

	len = snprintf(payload, sizeof(payload),
		       "{\"device_id\":\"%s\",\"event\":\"%s\",\"machine_state\":\"%s\","
		       "\"running_release_id\":\"%s\",\"detail\":\"%s\","
		       "\"transport\":\"http\",\"synthetic_data\":true}",
		       device_id, event, machine_state, release_id,
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

/* Throws away a partial download.
 *
 * The record is cleared first and the slot erased second, which is the mirror
 * of the order the download writes in. Writing lags the flash so the record can
 * only under-claim; discarding leads it so a power cut in the middle leaves no
 * record rather than a record pointing into an erased slot.
 *
 * One rule underneath both: the record may never describe more than the flash
 * holds.
 */
static void discard_partial_download(const struct flash_area *fa, const char *why)
{
	printk("ota.discard %s\n", why);
	(void)recovery_download_clear();
	if (fa != NULL) {
		(void)flash_area_flatten(fa, 0, fa->fa_size);
	}
	printk("ota.discard the progress record was cleared before the slot was erased,\n");
	printk("ota.discard so a power cut here leaves no record rather than one pointing\n");
	printk("ota.discard into an erased slot\n");
}

/* Decides where this download starts.
 *
 * A stored record is a hint about where to resume and never a thing to trust.
 * The manifest it is checked against was fetched again and its signature
 * verified again before this function ran, so what is compared here is
 * freshly verified metadata against remembered metadata, and the verified copy
 * wins every time.
 *
 * Section 7 names the cases that discard a partial download: a changed
 * release, an invalid range response, an excessive retry count, a size
 * mismatch, or a digest mismatch. The first, fourth and fifth are decided
 * here.
 */
static size_t resume_point(const struct release_manifest *manifest,
			   const struct flash_area *fa)
{
	struct download_record record;

	if (recovery_download_read(&record) != 0) {
		return 0;
	}

	if (strncmp(record.release_id, manifest->release_id, sizeof(record.release_id)) != 0) {
		discard_partial_download(fa, "the release changed since this download started");
		return 0;
	}
	if (record.size != (uint32_t)manifest->image_size) {
		discard_partial_download(fa, "the release is the same but its size is not");
		return 0;
	}
	if (strncmp(record.digest, manifest->image_sha256, sizeof(record.digest)) != 0) {
		discard_partial_download(fa, "the release is the same but its digest is not");
		return 0;
	}
	if (record.offset == 0U || record.offset >= (uint32_t)manifest->image_size) {
		discard_partial_download(fa, "the recorded offset is not inside this image");
		return 0;
	}

	printk("ota.resume %u of %d bytes are already in the slot\n",
	       record.offset, manifest->image_size);
	printk("ota.resume the manifest was fetched and verified again before this record\n");
	printk("ota.resume was allowed to matter. The record says where to resume, never what\n");
	printk("ota.resume to believe.\n");
	return record.offset;
}

int ota_client_install(const struct release_manifest *manifest)
{
	char url[OTA_FIELD_MAX + 16];
	char range[64];
	char digest_hex[65];
	const char *headers[2] = {NULL, NULL};
	const struct flash_area *fa = NULL;
	struct flash_pages_info page;
	struct image_writer writer = {.manifest = manifest};
	struct http_request req = {
		.method = HTTP_GET,
		.response = write_image,
	};
	size_t base;
	size_t total;
	int err;

	if (snprintf(url, sizeof(url), "/v1/firmware/%s", manifest->image_path) >=
	    (int)sizeof(url)) {
		return -ENOMEM;
	}
	req.url = url;

	printk("ota.install starting release_id=%s version=%s size=%d\n",
	       manifest->release_id, manifest->version, manifest->image_size);
	printk("ota.install every value above came from the signed manifest\n");

	err = flash_area_open(PARTITION_ID(slot1_partition), &fa);
	if (err != 0) {
		printk("ota.slot unavailable err=%d\n", err);
		return err;
	}

	/* Swap-using-offset places a downloaded image one sector into the
	 * secondary slot rather than at its start, so every offset here is
	 * relative to that, not to the slot.
	 */
	err = flash_get_page_info_by_offs(flash_area_get_device(fa), fa->fa_off, &page);
	if (err != 0) {
		flash_area_close(fa);
		return err;
	}
	base = fa->fa_off + page.size;

	writer.resume_offset = resume_point(manifest, fa);

	if (writer.resume_offset == 0) {
		/* A fresh download erases the whole slot once, rather than
		 * relying on stream_flash to erase ahead of itself. Tier 4 got
		 * this from flash_img_init(), which Tier 5 no longer uses:
		 * that function has no way to start anywhere but the
		 * beginning, which is precisely what a resumable download
		 * needs.
		 */
		printk("ota.install erasing the secondary slot for a fresh download\n");
		err = flash_area_flatten(fa, 0, fa->fa_size);
		if (err != 0) {
			flash_area_close(fa);
			printk("ota.slot erase failed err=%d\n", err);
			return err;
		}
	} else {
		snprintf(range, sizeof(range), "Range: bytes=%zu-\r\n", writer.resume_offset);
		headers[0] = range;
		req.header_fields = headers;
		printk("ota.resume requesting %s", range);
	}

	err = stream_flash_init(&writer.stream, flash_area_get_device(fa), stream_buf,
				sizeof(stream_buf), base + writer.resume_offset,
				fa->fa_size - page.size - writer.resume_offset, NULL);
	if (err != 0) {
		flash_area_close(fa);
		printk("ota.slot stream init failed err=%d\n", err);
		return err;
	}

	/* The writer's own reason wins over the transport's.
	 *
	 * When a response callback returns an error the HTTP client aborts the
	 * connection, and http_client_req() reports that abort rather than the
	 * reason for it: a refused range response comes back as -113, which is
	 * indistinguishable from the network dropping. Taking the transport's
	 * word for it sent a refused response down the resume path instead of
	 * the discard path, so the device kept a partial download it had already
	 * decided not to trust.
	 *
	 * It would also have pointed a Learner at the network for a failure that
	 * had nothing to do with it.
	 */
	err = run_request(&req, OTA_DOWNLOAD_TIMEOUT_MS, &writer);
	if (writer.err != 0) {
		err = writer.err;
	}
	if (err != 0) {
		/* An interrupted transfer keeps its progress record and its
		 * bytes. That is the whole point of the tier: the next poll
		 * resumes from where this one stopped rather than starting
		 * again. Only a refusal discards.
		 */
		if (err == -EPROTO || err == -EMSGSIZE) {
			discard_partial_download(fa, "the response was refused before any write");
		} else {
			printk("ota.install interrupted with %zu bytes in the slot; the record\n",
			       writer.resume_offset + writer.written);
			printk("ota.install survives and the next poll resumes from there\n");
		}
		flash_area_close(fa);
		return err;
	}

	total = writer.resume_offset + writer.written;
	if (total == 0) {
		flash_area_close(fa);
		printk("ota.install received no image bytes\n");
		return -ENODATA;
	}

	err = release_policy_check_size(manifest, total,
					"number of bytes now in the secondary slot",
					false);
	if (err != 0) {
		discard_partial_download(fa, "the delivered size did not match the manifest");
		flash_area_close(fa);
		return err;
	}

	/* The digest is computed by reading the slot back, not by hashing the
	 * stream as Tier 4 did.
	 *
	 * A resumable download cannot hash the stream: after a power cut the
	 * hash state is gone, and persisting SHA-256 midstate would be a great
	 * deal of unpleasantness for no gain. Reading the slot back is also the
	 * better check. Tier 4's comment says the digest protects the upgrade
	 * request, and hashing the slot makes that true of what is actually in
	 * the flash rather than of what the device believes it wrote.
	 *
	 * This is where a range response that started at the wrong offset is
	 * caught, since nothing earlier reads Content-Range.
	 */
	err = release_digest_slot(fa, page.size, total, digest_hex, sizeof(digest_hex));
	if (err != 0) {
		flash_area_close(fa);
		return err;
	}
	err = release_policy_check_digest(manifest, digest_hex);
	if (err != 0) {
		discard_partial_download(fa, "the slot does not hash to the signed digest");
		flash_area_close(fa);
		return err;
	}

	flash_area_close(fa);

	printk("ota.install %zu bytes are in the secondary slot and hash to the signed digest\n",
	       total);

	/* The download is finished, so the progress record has nothing left to
	 * describe. Clearing it here means a power cut between now and the
	 * reboot cannot make the device think a transfer is still in flight.
	 */
	(void)recovery_download_clear();

	err = boot_request_upgrade(BOOT_UPGRADE_TEST);
	if (err != 0) {
		printk("ota.upgrade request failed err=%d\n", err);
		return err;
	}

	printk("ota.upgrade requested a TEST swap, not a permanent one\n");
	printk("ota.upgrade Tier 3 and Tier 4 asked for permanent on purpose. From Tier 5 the\n");
	printk("ota.upgrade application never does: the image has to prove it works first, and\n");
	printk("ota.upgrade if it does not, MCUboot puts the old one back without being asked.\n");
	printk("ota.upgrade The fallback path has existed since Tier 0 and this is T0-W-07 closing.\n");
	return 0;
}

bool ota_client_has_trust_anchor(void)
{
	return COURSE_CA_DER_LEN > 0;
}

/* The update client needs nothing set up beyond what the image was built with,
 * so readiness is the same question as having something to trust. It is a
 * separate predicate all the same, because the two answer different questions
 * and a later tier that gives the client real state to initialise should not
 * have to go looking for where readiness was quietly folded into something
 * else.
 */
bool ota_client_ready(void)
{
	return ota_client_has_trust_anchor();
}

const char *ota_client_anchor_description(void)
{
	if (COURSE_CA_DER_LEN == 0) {
		return "none compiled in, this image trusts nothing";
	}
	return CONFIG_COURSE_TRUST_ANCHOR_FINGERPRINT;
}
