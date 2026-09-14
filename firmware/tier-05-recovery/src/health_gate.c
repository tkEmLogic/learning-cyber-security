#include "health_gate.h"
#include "ota_client.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <zephyr/devicetree.h>
#include <zephyr/drivers/watchdog.h>
#include <zephyr/kernel.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

/* The dev kit enables one Timer Group watchdog and gives it this alias. The
 * second is disabled in the SoC devicetree, and the RTC watchdog is not
 * exposed to Zephyr at all on this part.
 */
#define WDT_NODE DT_ALIAS(watchdog0)

static const struct device *const wdt = DEVICE_DT_GET_OR_NULL(WDT_NODE);
static int wdt_channel = -1;

static atomic_t beacon_ticks;

/* How long the watchdog is given before it decides the device is not coming
 * back.
 *
 * Comfortably longer than one pass of the loop that feeds it, and comfortably
 * shorter than the health window, so a hang is caught during the trial rather
 * than after it. The research behind this tier could not pin down exactly how
 * the driver's second stage relates to its first, so the reset lands somewhere
 * between one and two times this value. That is enough to size a window
 * against the 60 second gate and not enough to quote a deadline, so no course
 * text quotes one.
 */
#define WDT_WINDOW_MS 10000

int health_gate_start_watchdog(void)
{
	struct wdt_timeout_cfg cfg = {
		.window.min = 0U,
		.window.max = WDT_WINDOW_MS,
		.callback = NULL,
		.flags = WDT_FLAG_RESET_SOC,
	};
	int err;

	if (wdt == NULL || !device_is_ready(wdt)) {
		printk("health.watchdog no watchdog device, a hung trial image would hang forever\n");
		return -ENODEV;
	}

	wdt_channel = wdt_install_timeout(wdt, &cfg);
	if (wdt_channel < 0) {
		printk("health.watchdog install failed err=%d\n", wdt_channel);
		return wdt_channel;
	}

	/* WDT_OPT_PAUSE_HALTED_BY_DBG keeps a paused debugger from resetting the
	 * board out from under whoever is reading it.
	 */
	err = wdt_setup(wdt, WDT_OPT_PAUSE_HALTED_BY_DBG);
	if (err != 0) {
		printk("health.watchdog setup failed err=%d\n", err);
		return err;
	}

	printk("health.watchdog armed at %d ms on channel %d\n", WDT_WINDOW_MS, wdt_channel);
	printk("health.watchdog Only the thread doing the work feeds it, never a timer. A feed on\n");
	printk("health.watchdog a timer would keep running while the thread it vouches for was\n");
	printk("health.watchdog dead, and the watchdog would be guarding nothing.\n");
	return 0;
}

void health_gate_note_beacon(void)
{
	atomic_inc(&beacon_ticks);
}

void health_gate_feed(void)
{
	if (wdt != NULL && wdt_channel >= 0) {
		(void)wdt_feed(wdt, wdt_channel);
	}
}

/* Check 1: the running image is one the bootloader was able to describe.
 *
 * MCUboot verified this image's signature before it ran, which is the check
 * that matters and is not one the application can repeat: the application is
 * the thing that would have to be trusted to repeat it. What the application
 * can establish is that it can read its own slot's header back and that the
 * header describes an image, which catches a primary slot that is not what
 * anybody thinks it is.
 *
 * The module text says exactly this. A check that overstated itself here would
 * teach a Learner to believe an application's word about its own integrity,
 * which is the habit the whole course is written against.
 */
static bool check_image_integrity(void)
{
	struct mcuboot_img_header header;
	int err;

	err = boot_read_bank_header(PARTITION_ID(slot0_partition), &header,
				    sizeof(header));
	if (err != 0) {
		printk("health.check the primary slot header is unreadable err=%d\n", err);
		return false;
	}
	return header.h.v1.image_size > 0U;
}

/* Check 2: the material this image needs in order to trust anything is
 * present.
 *
 * Both are compiled in, so this cannot fail on a correctly built image. It can
 * and does fail on one built without the Course certificate authority or
 * without the Release manifest verification key, which the build allows on
 * purpose so the repository still builds standalone. An image that trusts
 * nothing is the right failure, and a health gate that let it confirm anyway
 * would be the wrong one.
 */
static bool check_credentials_loaded(void)
{
	return ota_client_has_trust_anchor() && release_policy_has_key();
}

/* Check 3: the reference product is doing its job.
 *
 * This is section 6's "reference-product state handling". For a status beacon
 * the product state is the beacon producing status; there is no second thing
 * it can mean for this product.
 *
 * It is the only check that must keep holding for the whole window, which is
 * what makes the window a gate rather than a delay.
 */
static bool check_beacon_running(void)
{
	static atomic_val_t last;
	atomic_val_t now = atomic_get(&beacon_ticks);
	bool advanced = now != last;

	last = now;
	return advanced;
}

/* Check 4: the update client came up.
 *
 * Deliberately scoped to the client having initialised, never to it having
 * reached the service. Section 6 forbids loss of network service alone from
 * failing this gate, and this is the check that would otherwise violate it: an
 * "is the service reachable" check here would turn every network outage into a
 * revert, which is the endless loop the specification names by name.
 */
static bool check_update_client_ready(void)
{
#ifdef CONFIG_COURSE_TRIAL_FAIL_HEALTH
	/* The fail-health release fails exactly one named check while the other
	 * three visibly pass, so a Learner reads the cause instead of inferring
	 * it from where the output stopped.
	 *
	 * It fails at boot, before the window opens, which is what separates it
	 * from timeout-health: that release passes every check and then lets the
	 * window expire.
	 */
	printk("health.check update-client-ready is failed deliberately by this build\n");
	return false;
#else
	return ota_client_ready();
#endif
}

struct health_check {
	const char *name;
	bool (*run)(void);
	bool holds_for_window;
};

static const struct health_check checks[] = {
	{"image-integrity", check_image_integrity, false},
	{"credentials-loaded", check_credentials_loaded, false},
	{"beacon-running", check_beacon_running, true},
	{"update-client-ready", check_update_client_ready, false},
};

enum health_result health_gate_run(char *reason, size_t reason_len)
{
	bool failed = false;
	const char *first_failure = NULL;
	int64_t deadline;

	if (reason_len > 0U) {
		reason[0] = '\0';
	}

	printk("health.gate running %zu local checks, then a %d second window\n",
	       ARRAY_SIZE(checks), CONFIG_COURSE_HEALTH_GATE_SECONDS);
	printk("health.gate no check asks whether the service is reachable. Section 6 forbids\n");
	printk("health.gate network loss alone from failing this gate.\n");

	/* Every check runs. Stopping at the first failure would hide which of
	 * the others were fine, and the fail-health release is only legible
	 * because three checks visibly pass beside the one that does not.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(checks); i++) {
		bool ok = checks[i].run();

		printk("health.check %-20s %s\n", checks[i].name, ok ? "pass" : "FAIL");
		if (!ok && !failed) {
			failed = true;
			first_failure = checks[i].name;
		}
	}

	if (failed) {
		if (reason_len > 0U) {
			strncpy(reason, first_failure, reason_len - 1);
			reason[reason_len - 1] = '\0';
		}
		printk("health.gate refused by %s before the window started\n", first_failure);
		return HEALTH_FAILED;
	}

	/* The window is timed from here, the end of the boot checks, rather than
	 * from boot. Starting it at boot would let a slow boot eat the window
	 * and make the gate's length depend on something it is not measuring.
	 */
	printk("health.gate every check passed, holding for %d seconds\n",
	       CONFIG_COURSE_HEALTH_GATE_SECONDS);

	deadline = k_uptime_get() + (int64_t)CONFIG_COURSE_HEALTH_GATE_SECONDS * 1000;
	while (k_uptime_get() < deadline) {
		k_sleep(K_SECONDS(5));
		health_gate_feed();

		for (size_t i = 0; i < ARRAY_SIZE(checks); i++) {
			if (!checks[i].holds_for_window) {
				continue;
			}
			if (!checks[i].run()) {
				int64_t left = (deadline - k_uptime_get()) / 1000;

				printk("health.check %-20s FAIL with %lld seconds left\n",
				       checks[i].name, (long long)left);
				if (reason_len > 0U) {
					strncpy(reason, checks[i].name, reason_len - 1);
					reason[reason_len - 1] = '\0';
				}
				/* The window is still running, so this is an
				 * expiry rather than a boot-time refusal. The
				 * timeout-health release reaches this line and
				 * the fail-health one does not.
				 */
				printk("health.gate window expired without a verdict\n");
				return HEALTH_TIMEOUT;
			}
		}
		printk("health.gate holding, %lld seconds left\n",
		       (long long)((deadline - k_uptime_get()) / 1000));
	}

	printk("health.gate passed\n");
	return HEALTH_PASSED;
}
