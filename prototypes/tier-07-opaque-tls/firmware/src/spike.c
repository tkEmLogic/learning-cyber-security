/*
 * PROTOTYPE. Throwaway spike code for issue #157. Not production firmware.
 *
 * Drives one connection and prints a verdict a human can read off the console.
 * It runs from main() rather than from a shell command, because the Tier 6
 * provisioning shell closes itself the moment the device is enrolled and this
 * board is enrolled.
 */

#include "opaque_tls.h"
#include "identity.h"

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
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
	printk("spike.end\n");
}
