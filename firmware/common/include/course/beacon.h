/*
 * The simulated machine state that the Reference product shows.
 *
 * The state is always reported on the serial console, because the console is
 * the course's evidence surface and several tiers quote its lines. On the
 * ESP32-C6-DevKitC-1 the same state is also shown on the board's one
 * addressable RGB LED, a WS2812 on GPIO8 (see
 * docs/esp32c6-build-baseline.md). The LED is an addition to the console
 * output and never a replacement for it.
 *
 * CONFIG_COURSE_BEACON_LED turns the LED half off. A board whose devicetree
 * has no led-strip alias builds and runs with the console output alone.
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

/* Starts showing the state on the onboard LED.
 *
 * A steady state is written once and then left alone. A blinking state gets a
 * small thread of its own, which does nothing but turn the LED on and off at
 * the state's toggle period. That thread is deliberately separate from
 * anything a tier runs: in Tier 5 and Tier 7 the thread named "beacon" feeds
 * the health gate and must keep its own timing, and a health signal that also
 * had to wait on an LED write would no longer be measuring what it claims to
 * measure.
 *
 * Every failure here is reported and survivable. A device that cannot light
 * its LED still runs, still reports its state on the console, and still
 * performs every update and every check the tier is about. Call this before
 * the boot banner, so beacon_led_note() below can describe what really
 * happened rather than what was intended.
 */
void beacon_led_start(enum beacon_state state);

/* One line for the boot banner saying what the LED does in this build.
 *
 * The answer is not known until beacon_led_start() has run, because it depends
 * on whether the driver came up on this particular board, so this reports an
 * observation rather than a build-time claim.
 */
const char *beacon_led_note(void);

#endif /* COURSE_BEACON_H */
