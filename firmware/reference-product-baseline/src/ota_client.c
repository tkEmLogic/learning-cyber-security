#include "ota_client.h"

#include <stdio.h>
#include <string.h>
#include <zephyr/data/json.h>
#include <zephyr/dfu/flash_img.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/kernel.h>
#include <zephyr/net/http/client.h>
#include <zephyr/net/socket.h>

#define OTA_REQUEST_TIMEOUT_MS 15000
#define OTA_DOWNLOAD_TIMEOUT_MS 120000
#define OTA_RECV_BUF_SIZE 1024
#define OTA_BODY_BUF_SIZE 768
#define OTA_EVENT_PATH "/v1/devices/" CONFIG_COURSE_DEVICE_ID "/events"

static uint8_t recv_buf[OTA_RECV_BUF_SIZE];

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
};

struct status_capture {
	int code;
};

struct image_writer {
	struct flash_img_context ctx;
	size_t written;
	int err;
};

static int ota_connect(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(CONFIG_COURSE_OTA_PORT),
	};
	int sock;

	if (net_addr_pton(AF_INET, CONFIG_COURSE_OTA_HOST, &addr.sin_addr) != 0) {
		printk("ota.target invalid address %s\n", CONFIG_COURSE_OTA_HOST);
		return -EINVAL;
	}

	sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		printk("ota.socket failed errno=%d\n", errno);
		return -errno;
	}
	if (zsock_connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printk("ota.connect failed host=%s port=%d errno=%d\n",
		       CONFIG_COURSE_OTA_HOST, CONFIG_COURSE_OTA_PORT, errno);
		zsock_close(sock);
		return -errno;
	}
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
	if (rsp->body_frag_len < room) {
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
	if (rsp->body_frag_len > 0) {
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
	req->host = CONFIG_COURSE_OTA_HOST;
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
		       "\"transport\":\"http\",\"synthetic_data\":true}",
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

int ota_client_install(const struct ota_release *release)
{
	char url[OTA_FIELD_MAX + 16];
	struct image_writer writer = {0};
	struct http_request req = {
		.method = HTTP_GET,
		.response = write_image,
	};
	int err;

	if (snprintf(url, sizeof(url), "/v1/firmware/%s", release->image_path) >=
	    (int)sizeof(url)) {
		return -ENOMEM;
	}
	req.url = url;

	printk("ota.install starting release_id=%s version=%s size=%d\n",
	       release->release_id, release->version, release->image_size);
	printk("ota.install declared_sha256=%s (Tier 0 does not check it)\n",
	       release->image_sha256);

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
	if (release->image_size > 0 && writer.written != (size_t)release->image_size) {
		printk("ota.install size mismatch declared=%d received=%zu\n",
		       release->image_size, writer.written);
		return -EMSGSIZE;
	}

	printk("ota.install wrote %zu bytes to the secondary slot\n", writer.written);

	err = boot_request_upgrade(BOOT_UPGRADE_PERMANENT);
	if (err != 0) {
		printk("ota.upgrade request failed err=%d\n", err);
		return err;
	}
	printk("ota.upgrade requested permanent overwrite, no test boot, no rollback\n");
	return 0;
}
