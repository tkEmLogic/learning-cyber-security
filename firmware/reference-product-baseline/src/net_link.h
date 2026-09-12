/*
 * Joining the local course Wi-Fi network.
 *
 * Tier 0 joins one WPA2 network with a passphrase compiled into the image and
 * takes its address from DHCP. It does not check what network it joined, and
 * it keeps no state across a reboot.
 */

#ifndef COURSE_NET_LINK_H
#define COURSE_NET_LINK_H

#include <stddef.h>

/* Joins the configured network and waits for a DHCP address.
 *
 * Returns 0 once an IPv4 address is assigned, -ENOTSUP when no Wi-Fi
 * interface exists, -EINVAL when no network is configured, and -ETIMEDOUT
 * when no address arrives within CONFIG_COURSE_WIFI_CONNECT_TIMEOUT_SECONDS.
 */
int net_link_connect(void);

/* Writes the current IPv4 address into buf. Returns 0 on success. */
int net_link_address(char *buf, size_t len);

#endif /* COURSE_NET_LINK_H */
