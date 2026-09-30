/*
 * The support listener. See support_listener.h for what it is and why it is
 * here; this file only keeps its promises.
 */

#include "support_listener.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/printk.h>

#include "identity.h"

#define SUPPORT_REQUEST_MAX 64
#define SUPPORT_REPLY_MAX   192

static void (*support_reset)(void);

/* A request is one word. A trailing newline or carriage return, which nc and
 * most scripts add, is not part of it.
 */
static void trim_request(char *request, size_t length)
{
	request[length] = '\0';
	while (length > 0 && (request[length - 1] == '\n' || request[length - 1] == '\r')) {
		request[--length] = '\0';
	}
}

static void reply(int sock, const struct sockaddr *peer, socklen_t peer_len, const char *text)
{
	(void)zsock_sendto(sock, text, strlen(text), 0, peer, peer_len);
}

static void support_thread(void *a, void *b, void *c)
{
	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_port = htons(CONFIG_COURSE_SUPPORT_LISTENER_PORT),
		.sin_addr = { .s_addr = htonl(INADDR_ANY) },
	};
	char request[SUPPORT_REQUEST_MAX];
	char text[SUPPORT_REPLY_MAX];
	int sock;

	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		printk("support.listener not started: socket failed, errno=%d\n", errno);
		return;
	}
	if (zsock_bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
		printk("support.listener not started: bind to UDP %d failed, errno=%d\n",
		       CONFIG_COURSE_SUPPORT_LISTENER_PORT, errno);
		(void)zsock_close(sock);
		return;
	}

	printk("support.listener listening on UDP %d for inventory and reboot\n",
	       CONFIG_COURSE_SUPPORT_LISTENER_PORT);
	printk("support.listener it asks no one who they are (T9-W-34)\n");

	while (true) {
		struct sockaddr_in peer;
		socklen_t peer_len = sizeof(peer);
		char from[NET_IPV4_ADDR_LEN];
		ssize_t length;

		length = zsock_recvfrom(sock, request, sizeof(request) - 1, 0,
					(struct sockaddr *)&peer, &peer_len);
		if (length < 0) {
			k_sleep(K_SECONDS(1));
			continue;
		}
		trim_request(request, (size_t)length);
		(void)zsock_inet_ntop(AF_INET, &peer.sin_addr, from, sizeof(from));

		if (strcmp(request, "inventory") == 0) {
			const char *id = course_identity_device_id();

			snprintf(text, sizeof(text),
				 "device_id=%s release_id=%s security_counter=%d\n",
				 id == NULL ? "none" : id, CONFIG_COURSE_RELEASE_ID,
				 CONFIG_COURSE_SECURITY_COUNTER);
			reply(sock, (struct sockaddr *)&peer, peer_len, text);
			printk("support.inventory answered %s:%u, unauthenticated\n",
			       from, ntohs(peer.sin_port));
		} else if (strcmp(request, "reboot") == 0) {
			reply(sock, (struct sockaddr *)&peer, peer_len, "rebooting\n");
			printk("support.reboot requested by %s:%u, unauthenticated; resetting now\n",
			       from, ntohs(peer.sin_port));
			/* Long enough for the reply and the line above to leave. */
			k_sleep(K_MSEC(200));
			support_reset();
		} else {
			reply(sock, (struct sockaddr *)&peer, peer_len, "unknown request\n");
			printk("support.unknown request from %s:%u ignored\n",
			       from, ntohs(peer.sin_port));
		}
	}
}

K_THREAD_STACK_DEFINE(support_stack, 2048);
static struct k_thread support_thread_data;

void course_support_listener_start(void (*reset)(void))
{
	support_reset = reset;
	k_thread_create(&support_thread_data, support_stack,
			K_THREAD_STACK_SIZEOF(support_stack), support_thread,
			NULL, NULL, NULL, K_PRIO_PREEMPT(9), 0, K_NO_WAIT);
	k_thread_name_set(&support_thread_data, "support");
}
