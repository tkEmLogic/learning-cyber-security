#include <course/beacon.h>

#include <string.h>
#include <zephyr/kernel.h>

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
