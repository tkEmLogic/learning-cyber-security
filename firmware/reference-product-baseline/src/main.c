#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#define COURSE_DEVICE_ID "beacon-development-shared"
#define COURSE_ASSIGNMENT_PATH "/v1/releases/current"
#define COURSE_EVENT_PATH "/v1/devices/" COURSE_DEVICE_ID "/events"

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

enum beacon_state {
	BEACON_STEADY,
	BEACON_FAST_BLINK,
	BEACON_SLOW_BLINK,
};

static const char *beacon_state_name(enum beacon_state state)
{
	switch (state) {
	case BEACON_STEADY:
		return "steady";
	case BEACON_FAST_BLINK:
		return "fast";
	case BEACON_SLOW_BLINK:
		return "slow";
	default:
		return "unknown";
	}
}

static uint32_t beacon_toggle_period_ms(enum beacon_state state)
{
	switch (state) {
	case BEACON_FAST_BLINK:
		return 200;
	case BEACON_SLOW_BLINK:
		return 1000;
	case BEACON_STEADY:
	default:
		return 0;
	}
}

int main(void)
{
	enum beacon_state state = BEACON_STEADY;

	printk("ESP32-C6 Reference product: intentionally unsecured Tier 0\n");
	printk("Board: %s\n", CONFIG_BOARD_TARGET);
	printk("Tier 0 boot mode: unsigned MCUboot with swap using scratch\n");
	printk("Synthetic shared device identifier: %s\n", COURSE_DEVICE_ID);
	printk("Prepared HTTP assignment endpoint: %s\n", COURSE_ASSIGNMENT_PATH);
	printk("Prepared HTTP status endpoint: %s\n", COURSE_EVENT_PATH);
	printk("Beacon state: %s, toggle period: %u ms\n",
	       beacon_state_name(state), beacon_toggle_period_ms(state));
	printk("Hardware note: Wi-Fi, HTTP transfer, flash, serial, and LED output require physical validation\n");

	while (true) {
		k_sleep(K_SECONDS(30));
		printk("status.observed device_id=%s machine_state=%s\n",
		       COURSE_DEVICE_ID, beacon_state_name(state));
	}
}
