#include <course/net_link.h>

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi.h>
#include <zephyr/net/wifi_mgmt.h>

#define LINK_EVENTS (NET_EVENT_IPV4_ADDR_ADD)
#define WIFI_EVENTS (NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT)

static K_SEM_DEFINE(address_ready, 0, 1);

static struct net_mgmt_event_callback link_callback;
static struct net_mgmt_event_callback wifi_callback;

static void on_link_event(struct net_mgmt_event_callback *cb, uint64_t event,
			  struct net_if *iface)
{
	ARG_UNUSED(cb);
	ARG_UNUSED(iface);

	if (event == NET_EVENT_IPV4_ADDR_ADD) {
		k_sem_give(&address_ready);
	}
}

static void on_wifi_event(struct net_mgmt_event_callback *cb, uint64_t event,
			  struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	ARG_UNUSED(iface);

	switch (event) {
	case NET_EVENT_WIFI_CONNECT_RESULT:
		if (status->status != 0) {
			printk("wifi.association failed status=%d\n", status->status);
		} else {
			printk("wifi.association succeeded ssid=%s\n", CONFIG_COURSE_WIFI_SSID);
		}
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		printk("wifi.disconnected status=%d\n", status->status);
		break;
	default:
		break;
	}
}

int net_link_connect(void)
{
	struct net_if *iface = net_if_get_first_wifi();
	struct wifi_connect_req_params params = {0};
	int err;

	if (iface == NULL) {
		printk("wifi.unavailable no Wi-Fi interface is present\n");
		return -ENOTSUP;
	}
	if (strlen(CONFIG_COURSE_WIFI_SSID) == 0) {
		printk("wifi.unconfigured run ./course setup --wifi-ssid <name> --wifi-psk <passphrase>\n");
		return -EINVAL;
	}

	net_mgmt_init_event_callback(&link_callback, on_link_event, LINK_EVENTS);
	net_mgmt_add_event_callback(&link_callback);
	net_mgmt_init_event_callback(&wifi_callback, on_wifi_event, WIFI_EVENTS);
	net_mgmt_add_event_callback(&wifi_callback);

	params.ssid = (const uint8_t *)CONFIG_COURSE_WIFI_SSID;
	params.ssid_length = strlen(CONFIG_COURSE_WIFI_SSID);
	params.psk = (const uint8_t *)CONFIG_COURSE_WIFI_PSK;
	params.psk_length = strlen(CONFIG_COURSE_WIFI_PSK);
	params.security = WIFI_SECURITY_TYPE_PSK;
	params.channel = WIFI_CHANNEL_ANY;
	params.band = WIFI_FREQ_BAND_2_4_GHZ;
	params.mfp = WIFI_MFP_OPTIONAL;
	params.timeout = CONFIG_COURSE_WIFI_CONNECT_TIMEOUT_SECONDS;

	printk("wifi.connecting ssid=%s security=wpa2-psk band=2.4GHz\n", CONFIG_COURSE_WIFI_SSID);

	err = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &params, sizeof(params));
	if (err != 0) {
		printk("wifi.request failed err=%d\n", err);
		return err;
	}

	if (k_sem_take(&address_ready,
		       K_SECONDS(CONFIG_COURSE_WIFI_CONNECT_TIMEOUT_SECONDS)) != 0) {
		printk("wifi.address timed out after %d seconds\n",
		       CONFIG_COURSE_WIFI_CONNECT_TIMEOUT_SECONDS);
		return -ETIMEDOUT;
	}

	return 0;
}

int net_link_address(char *buf, size_t len)
{
	struct net_if *iface = net_if_get_first_wifi();
	struct net_if_ipv4 *ipv4;

	if (iface == NULL || iface->config.ip.ipv4 == NULL) {
		return -ENOTSUP;
	}
	ipv4 = iface->config.ip.ipv4;

	ARRAY_FOR_EACH(ipv4->unicast, i) {
		if (!ipv4->unicast[i].ipv4.is_used ||
		    ipv4->unicast[i].ipv4.addr_type != NET_ADDR_DHCP) {
			continue;
		}
		if (net_addr_ntop(AF_INET, &ipv4->unicast[i].ipv4.address.in_addr,
				  buf, len) == NULL) {
			return -EINVAL;
		}
		return 0;
	}
	return -ENOENT;
}
