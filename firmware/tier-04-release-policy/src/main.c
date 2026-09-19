#include <course/beacon.h>
#include <course/net_link.h>
#include "ota_client.h"

#include <string.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/sys/util.h>

#include <esp_rom_sys.h>
#include <hal/efuse_hal.h>

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

/* Print the silicon revision the chip reports beside the product hardware
 * revision this build asserts.
 *
 * They are two different kinds of fact and Tier 4 turns on the difference.
 * efuse_hal_chip_revision() reads eFuse and returns the wafer stepping as
 * major * 100 + minor: it describes the die, it is set by the silicon vendor,
 * and nothing about it says which product this board was built into.
 *
 * The product hardware revision is the one a release is targeted at, and
 * nothing on this part reports it. So it is asserted by the build, compiled
 * in, and compared against a signed range. Product identity is asserted and
 * protected, never read: a value an attacker can set is not an identity, and a
 * value this device reads is not a claim anybody signed.
 */
static void announce_hardware(void)
{
	uint32_t revision = efuse_hal_chip_revision();

	printk("Silicon revision read from eFuse: v%u.%u\n",
	       revision / 100, revision % 100);
	printk("Product hardware revision asserted by this build: %d\n",
	       CONFIG_COURSE_HARDWARE_REVISION);
	printk("The first is read from the chip. The second is asserted and signed, because\n");
	printk("nothing on this part reports which product a board was built into.\n");
}

static void announce(enum beacon_state state)
{
	printk("ESP32-C6 Reference product: Tier 4, protected release metadata\n");
	printk("Image label: %s\n", CONFIG_COURSE_IMAGE_LABEL);
	printk("Running release: %s\n", CONFIG_COURSE_RELEASE_ID);
	printk("Security counter of the running image: %d\n", CONFIG_COURSE_SECURITY_COUNTER);
	printk("Release channel this device follows: %s\n", CONFIG_COURSE_RELEASE_CHANNEL);
	printk("Board: %s\n", CONFIG_BOARD_TARGET);
	announce_hardware();
	printk("Tier 4 boot mode: signed MCUboot images, swap using offset, permanent upgrade\n");
	printk("Tier 4 downgrade prevention: by security counter, enforced by the bootloader\n");
	printk("Image verification key this build trusted: %s\n",
	       CONFIG_COURSE_SIGNING_KEY_FINGERPRINT);
	printk("That is the key the build used. This application cannot read what the bootloader holds.\n");
	printk("Release manifest verification key: %s\n", release_policy_key_description());
	printk("One key signs both the image and the manifest, and two independent verifiers\n");
	printk("check them. Passing one is never evidence for the other.\n");
	printk("Tier 4 verifies signed release metadata before it parses it, and refuses six ways.\n");
	printk("Synthetic shared device identifier: %s\n", CONFIG_COURSE_DEVICE_ID);
	printk("OTA service: https://%s:%d at address %s\n",
	       CONFIG_COURSE_OTA_SERVICE_NAME, CONFIG_COURSE_OTA_TLS_PORT,
	       CONFIG_COURSE_OTA_HOST);
	printk("Trust anchor: %s\n", ota_client_anchor_description());
	printk("Beacon state: %s, toggle period: %u ms\n",
	       beacon_state_name(state), beacon_toggle_period_ms(state));
	printk("Hardware note: %s\n", beacon_led_note());
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

/* One poll: report status, read the assignment, fetch and verify the signed
 * manifest for whatever release it names, and install only if every check
 * passes. Returns true when the device should reboot into a freshly installed
 * image.
 *
 * The Update assignment is unchanged from Tier 0, down to the "signed": true
 * it still carries about itself. What changed is that the device stops taking
 * its word for anything except which release to go and ask about.
 */
static bool poll_once(enum beacon_state state)
{
	struct ota_release release;
	struct release_manifest manifest;
	const char *state_name = beacon_state_name(state);

	/* A rejected status report must not stop the update check: the two
	 * exchanges are independent, and Tier 0 gates neither on the other.
	 */
	(void)ota_client_report("status.observed", state_name, CONFIG_COURSE_RELEASE_ID,
				"verified service, signed release metadata");

	if (ota_client_fetch_assignment(&release) != 0) {
		return false;
	}

	printk("ota.assignment release_id=%s version=%s image=%s\n",
	       release.release_id, release.version, release.image_path);
	printk("ota.assignment it also claims size=%d sha256=%s\n",
	       release.image_size, release.image_sha256);
	printk("ota.assignment this device believes neither; they are the service's claims\n");
	printk("ota.assignment about itself. Only release_id is used, to know what to ask about.\n");

	if (!ota_release_differs(&release)) {
		printk("ota.assignment matches the running release, nothing to install\n");
		return false;
	}

	printk("ota.assignment offers %s instead of the running %s; asking for its signed manifest\n",
	       release.release_id, CONFIG_COURSE_RELEASE_ID);

	if (ota_client_fetch_manifest(release.release_id, &manifest) != 0) {
		(void)ota_client_report("update.refused", state_name,
					CONFIG_COURSE_RELEASE_ID, release.release_id);
		return false;
	}

	if (ota_client_install(&manifest) != 0) {
		(void)ota_client_report("update.failed", state_name,
					CONFIG_COURSE_RELEASE_ID, manifest.release_id);
		return false;
	}

	(void)ota_client_report("update.installed", state_name, CONFIG_COURSE_RELEASE_ID,
				manifest.release_id);
	return true;
}

int main(void)
{
	enum beacon_state state = beacon_configured_state();
	char address[NET_IPV4_ADDR_LEN];

	/* Before the banner, so the banner's hardware note can report whether
	 * the LED really started rather than whether it was asked to.
	 */
	beacon_led_start(state);
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
