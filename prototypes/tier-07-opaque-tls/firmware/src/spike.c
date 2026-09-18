/*
 * PROTOTYPE. Throwaway spike code for issue #157. Not production firmware.
 *
 * Drives one connection and prints a verdict a human can read off the console.
 * It runs from main() rather than from a shell command, because the Tier 6
 * provisioning shell closes itself the moment the device is enrolled and this
 * board is enrolled.
 *
 * Issue #158 added three things to it, all on this one image because each of
 * them costs a flash: an http_client_req() over the same socket, a stack high
 * water mark, and an attempt at a second concurrent socket.
 */

#include "opaque_tls.h"
#include "identity.h"

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/http/client.h>
#include <zephyr/debug/thread_analyzer.h>
#include <string.h>

#include <psa/crypto.h>

/* The spike server, which is not the OTA service. It presents the same course
 * service certificate and requires a client certificate issued by the
 * manufacturer device authority.
 */
#define SPIKE_PORT 8444

static void report_key_survives(void)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(course_identity_key_id(), &attributes);

	if (status != PSA_SUCCESS) {
		printk("spike.key 0x%08x IS GONE after the handshake, status=%d\n",
		       (unsigned int)course_identity_key_id(), (int)status);
		printk("spike.key that would mean the wrapper took ownership of it\n");
		psa_reset_key_attributes(&attributes);
		return;
	}
	printk("spike.key 0x%08x still present after the handshake and the free\n",
	       (unsigned int)course_identity_key_id());
	printk("spike.key usage flags 0x%08x, exportable=%s\n",
	       (unsigned int)psa_get_key_usage_flags(&attributes),
	       (psa_get_key_usage_flags(&attributes) & PSA_KEY_USAGE_EXPORT) ? "yes" : "no");
	psa_reset_key_attributes(&attributes);
}

/*
 * Issue #158, question one: can http_client_req() run on this descriptor?
 *
 * Nothing here is clever. It is the same call ota_client.c's run_request()
 * makes, over a socket opened on IPPROTO_COURSE_OPAQUE_TLS instead of
 * IPPROTO_TLS_1_2. If the poll implementation in opaque_tls.c is wrong, this
 * either fails outright at the first zsock_poll() or hangs until the timeout,
 * and both are visible on the console.
 */

struct spike_capture {
	int status;
	size_t body_len;
	bool complete;
	unsigned int calls;
};

static uint8_t http_recv_buf[512];

static int spike_response(struct http_response *rsp, enum http_final_call final,
			  void *user_data)
{
	struct spike_capture *capture = user_data;

	capture->status = rsp->http_status_code;
	capture->body_len += rsp->body_frag_len;
	capture->calls++;
	if (final == HTTP_DATA_FINAL) {
		capture->complete = true;
	}
	return 0;
}

static void spike_http_client(struct sockaddr_in *addr, const char *url)
{
	struct spike_capture capture = {0};
	struct http_request req = {
		.method = HTTP_GET,
		.url = url,
		.host = CONFIG_COURSE_OTA_SERVICE_NAME,
		.protocol = "HTTP/1.1",
		.response = spike_response,
		.recv_buf = http_recv_buf,
		.recv_buf_len = sizeof(http_recv_buf),
	};
	int64_t started;
	int sock;
	int err;

	printk("spike.http asking http_client_req() to run on the opaque socket, GET %s\n", url);
	course_opaque_tls_reset_poll_stats();

	course_opaque_tls_set_hostname(CONFIG_COURSE_OTA_SERVICE_NAME);

	sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_COURSE_OPAQUE_TLS);
	if (sock < 0) {
		printk("spike.http no socket, errno=%d\n", errno);
		return;
	}
	if (zsock_connect(sock, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
		printk("spike.http handshake failed errno=%d\n", errno);
		zsock_close(sock);
		return;
	}

	started = k_uptime_get();
	err = http_client_req(sock, &req, 5000, &capture);
	printk("spike.http http_client_req returned %d after %lld ms\n",
	       err, k_uptime_get() - started);

	if (err < 0) {
		printk("spike.http HTTP OVER THE OPAQUE SOCKET FAILED url=%s err=%d\n", url, err);
	} else {
		printk("spike.http HTTP OVER THE OPAQUE SOCKET WORKED url=%s status=%d body=%zu complete=%s reads=%u\n",
		       url, capture.status, capture.body_len,
		       capture.complete ? "yes" : "no", capture.calls);
	}

	const struct course_opaque_tls_poll_stats *stats = course_opaque_tls_poll_stats();

	printk("spike.poll %s prepare: %u forwarded, %u already-had-plaintext\n",
	       url, stats->prepare_forwarded, stats->prepare_already);
	printk("spike.poll %s update: %u decrypted-now, %u from-mbedtls-buffer, %u partial-record\n",
	       url, stats->update_decrypted, stats->update_buffered,
	       stats->update_partial_record);

	zsock_close(sock);
}

/*
 * Issue #158, question two: how close to the edge does the handshake run?
 *
 * #138 warned the key load and sign overran 2 KiB on the shell thread, and
 * Tier 6 raised CONFIG_SHELL_STACK_SIZE to 8192 because of it. #157 ran the
 * handshake on main and measured nothing, so this reports main directly and
 * then lets the analyzer speak for every thread.
 */
static void report_stack(const char *when)
{
	size_t unused = 0;
	int err = k_thread_stack_space_get(k_current_get(), &unused);

	if (err != 0) {
		printk("spike.stack %s unavailable err=%d\n", when, err);
		return;
	}
	printk("spike.stack %s main has %zu bytes of %d never touched, high water %zu\n",
	       when, unused, CONFIG_MAIN_STACK_SIZE,
	       (size_t)CONFIG_MAIN_STACK_SIZE - unused);
}

/*
 * Issue #158, question three: what happens to a second socket?
 *
 * The spike holds one static context and refuses a second with ENOMEM. This
 * says so on the console rather than leaving it as a claim in a note.
 */
static void report_concurrency(void)
{
	int first;
	int second;

	first = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_COURSE_OPAQUE_TLS);
	if (first < 0) {
		printk("spike.concurrency the first socket failed, errno=%d\n", errno);
		return;
	}
	second = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_COURSE_OPAQUE_TLS);
	if (second < 0) {
		printk("spike.concurrency a second socket is refused with errno=%d, one at a time\n",
		       errno);
	} else {
		printk("spike.concurrency a second socket was accepted, fd=%d\n", second);
		zsock_close(second);
	}
	zsock_close(first);
}

void course_opaque_tls_spike(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(SPIKE_PORT),
	};
	char request[192];
	char response[256];
	int sock;
	ssize_t n;

	printk("spike.begin one mutually authenticated handshake, issue #157\n");

	if (!course_identity_is_provisioned()) {
		printk("spike.abort this device holds no Factory identity to present\n");
		return;
	}
	printk("spike.identity presenting %s\n", course_identity_device_id());

	if (net_addr_pton(AF_INET, CONFIG_COURSE_OTA_HOST, &addr.sin_addr) != 0) {
		printk("spike.abort invalid address %s\n", CONFIG_COURSE_OTA_HOST);
		return;
	}

	course_opaque_tls_set_hostname(CONFIG_COURSE_OTA_SERVICE_NAME);

	sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_COURSE_OPAQUE_TLS);
	if (sock < 0) {
		printk("spike.socket the registered implementation was not reached, errno=%d\n",
		       errno);
		printk("spike.socket that alone disproves the route\n");
		return;
	}
	printk("spike.socket protocol %d dispatched to the course implementation, fd=%d\n",
	       IPPROTO_COURSE_OPAQUE_TLS, sock);

	if (zsock_connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		const struct course_opaque_tls_result *result = course_opaque_tls_last_result();

		printk("spike.result HANDSHAKE FAILED errno=%d mbedtls=-0x%04x verify=0x%08x\n",
		       errno, (unsigned int)-result->mbedtls_error,
		       (unsigned int)result->verify_flags);
		zsock_close(sock);
		report_key_survives();
		return;
	}

	const struct course_opaque_tls_result *result = course_opaque_tls_last_result();

	printk("spike.result HANDSHAKE COMPLETED %s %s\n", result->version, result->ciphersuite);
	printk("spike.result peer verification flags 0x%08x\n", (unsigned int)result->verify_flags);

	/* Data across it, so the answer is not just "the handshake ended". */
	snprintf(request, sizeof(request),
		 "GET /spike HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		 CONFIG_COURSE_OTA_SERVICE_NAME);
	n = zsock_send(sock, request, strlen(request), 0);
	if (n < 0) {
		printk("spike.data send failed errno=%d\n", errno);
	} else {
		n = zsock_recv(sock, response, sizeof(response) - 1, 0);
		if (n < 0) {
			printk("spike.data recv failed errno=%d\n", errno);
		} else {
			response[n] = '\0';
			char *line_end = strchr(response, '\r');

			if (line_end != NULL) {
				*line_end = '\0';
			}
			printk("spike.data the service answered: %s\n", response);
		}
	}

	zsock_close(sock);
	report_key_survives();
	report_stack("after the raw handshake");

	/* The question #158 exists for. */
	spike_http_client(&addr, "/spike");
	report_key_survives();
	report_stack("after http_client_req");

	/*
	 * And the version of it that actually tests the poll implementation.
	 *
	 * A 60 byte reply arrives in one record and is consumed in one read, so
	 * it never leaves anything buffered and never sees a partial record. The
	 * two failures the poll code guards against both need a body larger than
	 * one recv_buf: 64 KiB against a 512 byte buffer makes mbedTLS hold
	 * decrypted bytes the TCP descriptor can no longer signal, which is the
	 * case that hangs, and it is the shape of the image download Tier 7
	 * needs to carry.
	 */
	spike_http_client(&addr, "/spike/large");
	report_key_survives();
	report_stack("after the 64 KiB download");
	thread_analyzer_print(0);

	report_concurrency();
	printk("spike.end\n");
}
