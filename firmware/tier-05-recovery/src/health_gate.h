/*
 * The local health gate Tier 5 runs before it confirms an image.
 *
 * MCUboot starts a freshly swapped image as an unconfirmed test image. It has
 * already checked the signature and the security counter, which is everything
 * a bootloader can know. What it cannot know is whether the image works, and
 * that is what this gate is for.
 *
 * Four named checks, then a 60 second window. Every check is local. Section 6
 * is explicit that loss of network service alone must not fail the gate,
 * because local application health is separated from optional backend
 * reachability, so nothing here asks whether the service can be reached. A
 * device on a dead network passes this gate and confirms, and that is the
 * required behaviour rather than a gap in it.
 *
 * Every check runs and every result is printed, rather than stopping at the
 * first failure. This is the same choice Tier 4 made with its eight refusal
 * reasons: a Learner diagnosing a prepared failure needs to see which checks
 * passed, not only which one failed first. It is also what makes the
 * fail-health release legible, since one named check fails while three
 * visibly pass.
 */

#ifndef COURSE_HEALTH_GATE_H
#define COURSE_HEALTH_GATE_H

#include <stdbool.h>
#include <stddef.h>

enum health_result {
	/* Every check passed and the window elapsed with the device still
	 * healthy. The caller may confirm the image.
	 */
	HEALTH_PASSED = 0,
	/* A named check failed. The name is in the reason string. */
	HEALTH_FAILED,
	/* The window expired without every check being satisfied. Distinct
	 * from HEALTH_FAILED because the specification separates a failed
	 * check from an expired timer, and the two prepared releases that
	 * produce them are what make that separation observable.
	 */
	HEALTH_TIMEOUT,
};

/* Starts the watchdog that resets a trial image which hangs before it can
 * report failure.
 *
 * Nothing in this course has ever enabled the watchdog, and the esp32 driver
 * actively disables the hardware during its own init, so it is off until this
 * runs. An image that hangs on a board with no watchdog running looks exactly
 * like a control working.
 *
 * This catches an ordinary hung thread, which was checked on the board rather
 * than assumed from the driver source. The driver programs stage 0 as an
 * interrupt whose handler calls wdt_hal_handle_intr(), documented as clearing
 * the interrupt and feeding the watchdog, which would mean only a hang that
 * also blocked interrupts ever reached the resetting stage.
 *
 * It does not work out that way. wdt_hal_handle_intr() must be called with
 * write protection disabled, wdt_esp32_feed() unseals and reseals around its
 * own feed, and wdt_esp32_isr() does neither. So the handler's feed does not
 * take effect and stage 1 resets the chip, which is what the board shows as
 * rst:0x7 (TG0_WDT_HPSYS).
 *
 * That is a property of this driver rather than a guarantee, and an upstream
 * fix to the handler would change it silently. Tier 5 says so rather than
 * presenting it as a promise.
 */
int health_gate_start_watchdog(void);

/* Runs the four checks and then the window.
 *
 * reason is filled with the name of the check that failed, or with the name of
 * the check that was still unsatisfied when the window expired. It is left
 * empty on success.
 */
enum health_result health_gate_run(char *reason, size_t reason_len);

/* Reports that the reference product did a unit of work.
 *
 * Called from the beacon's own thread, and observed by the beacon-running
 * check. It does not feed the watchdog: the two questions are different, and
 * collapsing them breaks one of the trial behaviours.
 */
void health_gate_note_beacon(void);

/* Feeds the watchdog.
 *
 * Called only from the thread that drives the device's main work, and never
 * from a timer or an interrupt. That is the whole reason a hung thread is
 * caught at all: a feed on a k_timer keeps running while the thread it is
 * supposed to be vouching for is dead, so the watchdog would guard nothing.
 *
 * It is deliberately not conditional on the beacon advancing. The watchdog's
 * job is a thread that has stopped entirely; a beacon that has stopped while
 * the thread still runs is the health gate's job, and it produces a controlled
 * reboot after the window rather than a reset ten seconds in.
 */
void health_gate_feed(void);

#endif /* COURSE_HEALTH_GATE_H */
