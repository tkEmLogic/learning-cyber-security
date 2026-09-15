/*
 * Enable the ESP32-C6 hardware random number generator's clock.
 *
 * Without this the generator is not clocked, LPPERI_RNG_DATA_REG is frozen,
 * and every random value on the board is the RTC timer's low byte XORed with a
 * constant. Found on issue #126 while building Tier 6, which is the first tier
 * to generate a long-lived private key on the device. The key it produced had
 * four random bytes and twenty-eight bytes of counter.
 *
 * Four links, each checked rather than assumed:
 *
 *   1. Espressif's own C6 bring-up clears the whole LPPERI clock enable
 *      register on a power-on reset, keeping only the eFuse clock:
 *
 *          LPPERI.clk_en.val = 0;
 *          LPPERI.clk_en.efuse_ck_en = 1;  // keep efuse clock enabled
 *
 *      in components/esp_hal_clock/esp32c6/include/hal/clk_gate_ll.h. That
 *      clears LPPERI_RNG_CK_EN, bit 24, whose reset default is 1.
 *
 *   2. ESP-IDF turns it back on in ESP_SYSTEM_INIT_FN(init_rng, ...) at the
 *      bottom of components/esp_hw_support/hw_random.c. That is ESP-IDF's
 *      startup framework, and Zephyr does not run it.
 *
 *   3. Zephyr's entropy_esp32_init() calls clock_control_on() on the trng0
 *      node instead, which reaches non_shared_periph_module_enable(112). That
 *      switch has no case for ESP32_RNG_MODULE, so it does nothing.
 *
 *   4. The register read on the board before this file existed was 0x40000000:
 *      exactly and only efuse_ck_en, which is what step 1 leaves behind when
 *      nothing has undone it.
 *
 * The entropy driver itself is not at fault and needs no change. It is
 * Espressif's esp_random() copied verbatim, and its pacing is right: on this
 * board esp_clk_apb_freq() reports 40 MHz, so it waits about 64 microseconds
 * between words, which is more conservative than its own comment describes. A
 * first diagnosis blamed the driver and was wrong; it is named here so that
 * nobody reads the driver and re-derives it.
 *
 * This lives in firmware/common rather than in Tier 6 because the generator is
 * the platform's, and every tier from Tier 2 on opens a TLS connection whose
 * ephemeral key agreement draws on it. A fix that only reached the tier that
 * happened to notice would leave the other four running on a frozen generator.
 *
 * Upstream has already fixed this, in zephyrproject-rtos/zephyr commit 1df3062
 * of 2026-06-05, which added rng_ll_enable() to entropy_esp32_init(). That
 * landed after the v4.4 branch was cut, so v4.4.2 does not carry it, and v4.4.2
 * is what this course pins. The commit is titled "align with updated
 * hal_espressif hal apis" and says nothing about entropy, so the repair looks
 * incidental rather than deliberate.
 *
 * When the course moves to a Zephyr that has it, this file becomes redundant
 * and should be deleted rather than left to rot. Until then it is harmless
 * either way: setting a bit that is already set costs one register write.
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>

#ifdef CONFIG_SOC_SERIES_ESP32C6

#include <soc/lpperi_reg.h>

/*
 * After the entropy driver's own init, which runs at CONFIG_ENTROPY_INIT_PRIORITY
 * and defaults to 50, and before anything that asks for a random number. The
 * driver's init does no harm; it simply does not do this.
 */
static int course_enable_hw_rng_clock(void)
{
	REG_SET_BIT(LPPERI_CLK_EN_REG, LPPERI_RNG_CK_EN);
	return 0;
}

SYS_INIT(course_enable_hw_rng_clock, PRE_KERNEL_1, 60);

#endif /* CONFIG_SOC_SERIES_ESP32C6 */
