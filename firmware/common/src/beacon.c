#include <course/beacon.h>

#include <string.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>

/* The LED half is compiled in only when this build asks for it AND the board
 * actually offers a strip to drive. Both halves of that test matter. The
 * Kconfig symbol is the Learner's switch; the alias is the board's answer. A
 * board target without the alias, or a build with the symbol turned off,
 * compiles this file down to the console-only behaviour it had before the
 * DevKitC-1 arrived.
 */
#if defined(CONFIG_COURSE_BEACON_LED) && DT_HAS_ALIAS(led_strip)
#define BEACON_LED_DRIVEN 1
#endif

#ifdef BEACON_LED_DRIVEN
#include <zephyr/device.h>
#include <zephyr/drivers/led_strip.h>
#endif

enum beacon_state beacon_configured_state(void)
{
	const char *configured = CONFIG_COURSE_BEACON_STATE;

	if (strcmp(configured, "fast") == 0) {
		return BEACON_FAST_BLINK;
	}
	if (strcmp(configured, "slow") == 0) {
		return BEACON_SLOW_BLINK;
	}
	return BEACON_STEADY;
}

const char *beacon_state_name(enum beacon_state state)
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

uint32_t beacon_toggle_period_ms(enum beacon_state state)
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

#ifdef BEACON_LED_DRIVEN

static const struct device *const beacon_led = DEVICE_DT_GET(DT_ALIAS(led_strip));

/* Whether the driver came up. Read by beacon_led_note() for the boot banner,
 * so the banner reports what happened instead of what was configured.
 */
static bool beacon_led_running;

/* The state this LED shows, set once by beacon_led_start() before the blink
 * thread exists, so the thread only ever reads it.
 */
static enum beacon_state beacon_led_state;

/* The product in the course story has one RGB indicator: solid green means
 * normal operation, and red means one of the two fictional error states. The
 * two error states are both red, and they are told apart by how fast the LED
 * blinks. Colour says "healthy or not"; the blink rate says which error.
 *
 * The pixel is built fresh on the stack for every write. led_strip_update_rgb()
 * is documented as being allowed to overwrite the buffer it is given, so a
 * shared constant would be handed to a function permitted to scribble on it.
 */
static void beacon_led_write(bool lit)
{
	uint8_t level = lit ? CONFIG_COURSE_BEACON_LED_BRIGHTNESS : 0;
	struct led_rgb pixel = { 0 };
	int err;

	if (beacon_led_state == BEACON_STEADY) {
		pixel.g = level;
	} else {
		pixel.r = level;
	}

	err = led_strip_update_rgb(beacon_led, &pixel, 1);
	if (err != 0) {
		/* Reported on every failed write rather than latched once,
		 * because a write that starts failing partway through a run is
		 * worth seeing on the console too.
		 */
		printk("beacon.led write failed err=%d\n", err);
	}
}

K_THREAD_STACK_DEFINE(beacon_led_stack, 1024);
static struct k_thread beacon_led_thread_data;

static void beacon_led_blink(void *period_arg, void *unused_b, void *unused_c)
{
	uint32_t period = (uint32_t)(uintptr_t)period_arg;
	bool lit = true;

	ARG_UNUSED(unused_b);
	ARG_UNUSED(unused_c);

	for (;;) {
		k_sleep(K_MSEC(period));
		lit = !lit;
		beacon_led_write(lit);
	}
}

void beacon_led_start(enum beacon_state state)
{
	uint32_t period = beacon_toggle_period_ms(state);

	if (!device_is_ready(beacon_led)) {
		printk("beacon.led driver not ready; the state is on the console only\n");
		return;
	}

	beacon_led_running = true;
	beacon_led_state = state;

	/* The LED starts lit in every state. A blinking state then goes dark
	 * one period later, so the first thing a Learner sees is the same for
	 * all three states and the state is told apart by what follows.
	 */
	beacon_led_write(true);

	if (period == 0) {
		/* Steady. The WS2812 holds the last colour it was sent until
		 * it is sent another one or loses power, so nothing has to
		 * keep refreshing it, and no thread is created.
		 */
		return;
	}

	k_thread_create(&beacon_led_thread_data, beacon_led_stack,
			K_THREAD_STACK_SIZEOF(beacon_led_stack), beacon_led_blink,
			(void *)(uintptr_t)period, NULL, NULL,
			K_PRIO_PREEMPT(10), 0, K_NO_WAIT);
	k_thread_name_set(&beacon_led_thread_data, "beacon_led");
}

const char *beacon_led_note(void)
{
	if (beacon_led_running) {
		return "the onboard RGB LED on GPIO8 shows the same beacon state as the console";
	}
	return "the onboard RGB LED did not start; the beacon state is on the console only";
}

#else /* BEACON_LED_DRIVEN */

void beacon_led_start(enum beacon_state state)
{
	ARG_UNUSED(state);
}

const char *beacon_led_note(void)
{
	return "this build drives no onboard LED; the beacon state is on the console only";
}

#endif /* BEACON_LED_DRIVEN */
