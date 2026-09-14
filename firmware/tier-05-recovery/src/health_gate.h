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
 * What this catches is narrower than it looks. The Zephyr esp32 driver
 * programs stage 0 as an interrupt and its own ISR feeds the watchdog at the
 * end, so the stage that resets the chip is reached only when interrupts are
 * blocked. A hang that still services interrupts is fed forever and never
 * reset, which includes a plain loop in a thread and an ordinary deadlock.
 * That is a real residual availability risk and it is in the Tier 5 weakness
 * ledger rather than hidden behind a watchdog that appears to catch
 * everything.
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
 * This is what beacon-running observes, and it is also what feeds the
 * watchdog. One loop proves liveness and feeds the dog, so there is a single
 * thing whose stopping is the failure rather than two mechanisms to reason
 * about.
 */
void health_gate_note_beacon(void);

#endif /* COURSE_HEALTH_GATE_H */
