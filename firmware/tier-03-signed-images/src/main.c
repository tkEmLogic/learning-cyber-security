#include <course/beacon.h>
#include <course/net_link.h>
#include "ota_client.h"

#include <string.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/sys/util.h>

#include <esp_rom_sys.h>

#define ASSERT_PARTITION(node, expected_offset, expected_size) \
	BUILD_ASSERT(DT_REG_ADDR(DT_NODELABEL(node)) == (expected_offset)); \
	BUILD_ASSERT(DT_REG_SIZE(DT_NODELABEL(node)) == (expected_size))

BUILD_ASSERT(DT_REG_SIZE(DT_NODELABEL(flash0)) == 0x400000);
ASSERT_PARTITION(boot_partition, 0x000000, 0x010000);
ASSERT_PARTITION(sys_partition, 0x010000, 0x010000);
ASSERT_PARTITION(slot0_partition, 0x020000, 0x1c0000);
ASSERT_PARTITION(slot1_partition, 0x1e0000, 0x1c0000);
ASSERT_PARTITION(slot0_lpcore_partition, 0x3a0000, 0x008000);
ASSERT_PARTITION(slot1_lpcore_partition, 0x3a8000, 0x008000);
ASSERT_PARTITION(storage_partition, 0x3b0000, 0x030000);
ASSERT_PARTITION(scratch_partition, 0x3e0000, 0x01f000);
ASSERT_PARTITION(coredump_partition, 0x3ff000, 0x001000);

static void announce(enum beacon_state state)
{
	printk("ESP32-C6 Reference product: Tier 2, authenticated service connection\n");
	printk("Image label: %s\n", CONFIG_COURSE_IMAGE_LABEL);
	printk("Running release: %s\n", CONFIG_COURSE_RELEASE_ID);
	printk("Board: %s\n", CONFIG_BOARD_TARGET);
	printk("Tier 2 boot mode: unsigned MCUboot, swap using offset, no test boot, no rollback\n");
	printk("Tier 2 protects the connection. It does not make an image authentic.\n");
	printk("Synthetic shared device identifier: %s\n", CONFIG_COURSE_DEVICE_ID);
	printk("OTA service: https://%s:%d at address %s\n",
	       CONFIG_COURSE_OTA_SERVICE_NAME, CONFIG_COURSE_OTA_TLS_PORT,
	       CONFIG_COURSE_OTA_HOST);
	printk("Trust anchor: %s\n", ota_client_anchor_description());
	printk("Beacon state: %s, toggle period: %u ms\n",
	       beacon_state_name(state), beacon_toggle_period_ms(state));
	printk("Hardware note: this board's onboard LED is wired to 3V3 and cannot be driven\n");
}

/* Restart the whole chip, not only the processor.
 *
 * Zephyr's sys_reboot() ends in esp_restart(), which resets the processor but
 * deliberately leaves the BBPLL running so the ROM can keep logging. MCUboot
 * then tries to configure a PLL that is already on, and hangs inside its clock
 * setup before it reaches any of its own code. An update installed that way
 * never starts, and the board only recovers by a manual reset.
 *
 * The ROM's system reset returns the clocks to their power-on state, so
 * MCUboot starts exactly as it does after a power cycle.
 */
static void course_reset_system(void)
{
	esp_rom_software_reset_system();

	/* The reset is immediate. This loop only satisfies the compiler. */
	while (true) {
		k_sleep(K_FOREVER);
	}
}

/* One poll: report status, read the assignment, and install it when it names
 * a different release. Returns true when the device should reboot into a
 * freshly installed image.
 */
static bool poll_once(enum beacon_state state)
{
	struct ota_release release;
	const char *state_name = beacon_state_name(state);

	/* A rejected status report must not stop the update check: the two
	 * exchanges are independent, and Tier 0 gates neither on the other.
	 */
	(void)ota_client_report("status.observed", state_name, CONFIG_COURSE_RELEASE_ID,
				"plaintext HTTP, shared identifier");

	if (ota_client_fetch_assignment(&release) != 0) {
		return false;
	}

	printk("ota.assignment release_id=%s version=%s image=%s\n",
	       release.release_id, release.version, release.image_path);

	if (!ota_release_differs(&release)) {
		printk("ota.assignment matches the running release, nothing to install\n");
		return false;
	}

	printk("ota.assignment differs from running release %s, installing without any check\n",
	       CONFIG_COURSE_RELEASE_ID);

	if (ota_client_install(&release) != 0) {
		(void)ota_client_report("update.failed", state_name,
					CONFIG_COURSE_RELEASE_ID, release.release_id);
		return false;
	}

	(void)ota_client_report("update.installed", state_name, CONFIG_COURSE_RELEASE_ID,
				release.release_id);
	return true;
}

int main(void)
{
	enum beacon_state state = beacon_configured_state();
	char address[NET_IPV4_ADDR_LEN];

	announce(state);

	if (net_link_connect() != 0) {
		printk("Offline mode: no OTA exchange is possible\n");
		printk("Hardware note: Wi-Fi, HTTP transfer, and OTA install remain unobserved\n");
		while (true) {
			k_sleep(K_SECONDS(CONFIG_COURSE_POLL_INTERVAL_SECONDS));
			printk("status.offline device_id=%s machine_state=%s\n",
			       CONFIG_COURSE_DEVICE_ID, beacon_state_name(state));
		}
	}

	if (net_link_address(address, sizeof(address)) == 0) {
		printk("wifi.address %s assigned by DHCP\n", address);
	}

	while (true) {
		if (poll_once(state)) {
			printk("Rebooting into the newly installed image\n");
			k_sleep(K_MSEC(200));
			course_reset_system();
		}
		k_sleep(K_SECONDS(CONFIG_COURSE_POLL_INTERVAL_SECONDS));
	}
}
