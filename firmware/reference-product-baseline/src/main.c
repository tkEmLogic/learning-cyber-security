#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

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

int main(void)
{
	printk("ESP32-C6 Reference product build baseline\n");
	printk("Board: %s\n", CONFIG_BOARD_TARGET);
	printk("Tier 0 boot mode: unsigned MCUboot with swap using scratch\n");
	return 0;
}
