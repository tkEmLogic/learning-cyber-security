/*
 * The simulated machine state that the Reference product shows.
 *
 * The nanoESP32-C6 1.0 board wires its onboard LED to the 3V3 rail, so the
 * LED cannot be driven on this hardware (see docs/esp32c6-build-baseline.md).
 * The state is therefore reported on the serial console instead.
 */

#ifndef COURSE_BEACON_H
#define COURSE_BEACON_H

#include <stdint.h>

enum beacon_state {
	BEACON_STEADY,
	BEACON_FAST_BLINK,
	BEACON_SLOW_BLINK,
};

/* Returns the state named by CONFIG_COURSE_BEACON_STATE, or BEACON_STEADY
 * when the configured name is not one of steady, fast, or slow.
 */
enum beacon_state beacon_configured_state(void);

const char *beacon_state_name(enum beacon_state state);

/* Milliseconds between LED transitions; 0 means the LED stays on. */
uint32_t beacon_toggle_period_ms(enum beacon_state state);

#endif /* COURSE_BEACON_H */
