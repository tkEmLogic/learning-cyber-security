#include <course/beacon.h>
#include <course/net_link.h>
#include "health_gate.h"
#include "identity.h"
#include "ota_client.h"
#include "recovery_state.h"

#include <string.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/kernel.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/sys/util.h>

#include <esp_rom_sys.h>
#include <hal/efuse_hal.h>

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

/* Print the silicon revision the chip reports beside the product hardware
 * revision this build asserts.
 *
 * They are two different kinds of fact and Tier 4 turns on the difference.
 * efuse_hal_chip_revision() reads eFuse and returns the wafer stepping as
 * major * 100 + minor: it describes the die, it is set by the silicon vendor,
 * and nothing about it says which product this board was built into.
 *
 * The product hardware revision is the one a release is targeted at, and
 * nothing on this part reports it. So it is asserted by the build, compiled
 * in, and compared against a signed range. Product identity is asserted and
 * protected, never read: a value an attacker can set is not an identity, and a
 * value this device reads is not a claim anybody signed.
 */
static void announce_hardware(void)
{
	uint32_t revision = efuse_hal_chip_revision();

	printk("Silicon revision read from eFuse: v%u.%u\n",
	       revision / 100, revision % 100);
	printk("Product hardware revision asserted by this build: %d\n",
	       CONFIG_COURSE_HARDWARE_REVISION);
	printk("The first is read from the chip. The second is asserted and signed, because\n");
	printk("nothing on this part reports which product a board was built into.\n");
}

static void announce(enum beacon_state state)
{
	printk("ESP32-C6 Reference product: Tier 5, recoverable installation\n");
	printk("Image label: %s\n", CONFIG_COURSE_IMAGE_LABEL);
	printk("Running release: %s\n", CONFIG_COURSE_RELEASE_ID);
	printk("Security counter of the running image: %d\n", CONFIG_COURSE_SECURITY_COUNTER);
	printk("Release channel this device follows: %s\n", CONFIG_COURSE_RELEASE_CHANNEL);
	printk("Board: %s\n", CONFIG_BOARD_TARGET);
	announce_hardware();
	printk("Tier 5 boot mode: signed MCUboot images, swap using offset, TEST upgrade\n");
	printk("Tier 5 downgrade prevention: by security counter, enforced by the bootloader\n");
	printk("Source revision of this build: %s\n", CONFIG_COURSE_SOURCE_REVISION);
	printk("That identifies the build, not the release. It also travels in a protected\n");
	printk("MCUboot TLV, so the bootloader can say what it is swapping in. Your own build\n");
	printk("carries your hash and will not match a published one.\n");
	printk("Trial behaviour compiled into this image: %s\n",
	       CONFIG_COURSE_TRIAL_BEHAVIOUR_NAME);
	printk("Image verification key this build trusted: %s\n",
	       CONFIG_COURSE_SIGNING_KEY_FINGERPRINT);
	printk("That is the key the build used. This application cannot read what the bootloader holds.\n");
	printk("Release manifest verification key: %s\n", release_policy_key_description());
	printk("One key signs both the image and the manifest, and two independent verifiers\n");
	printk("check them. Passing one is never evidence for the other.\n");
	printk("Tier 5 verifies signed release metadata before it parses it, installs on trial,\n");
	printk("and puts the old image back itself when the new one cannot prove it works.\n");
	printk("Synthetic shared device identifier: %s\n", CONFIG_COURSE_DEVICE_ID);
	printk("OTA service: https://%s:%d at address %s\n",
	       CONFIG_COURSE_OTA_SERVICE_NAME, CONFIG_COURSE_OTA_TLS_PORT,
	       CONFIG_COURSE_OTA_HOST);
	printk("Trust anchor: %s\n", ota_client_anchor_description());
	printk("Beacon state: %s, toggle period: %u ms\n",
	       beacon_state_name(state), beacon_toggle_period_ms(state));
	printk("Hardware note: this board's onboard LED is wired to 3V3 and cannot be driven\n");
}

/* Restart the whole chip, not only the processor.
 *
 * Zephyr's sys_reboot() ends in esp_restart(), which resets the processor but
 * deliberately leaves the BBPLL running so the ROM can keep logging. MCUboot
 * then tries to configure a PLL that is already on, and hangs inside its clock
 * setup before it reaches any of its own code. An update installed that way
 * never starts, and the board only recovers by a manual reset.
 *
 * The ROM's system reset returns the clocks to their power-on state, so
 * MCUboot starts exactly as it does after a power cycle.
 */
static void course_reset_system(void)
{
	esp_rom_software_reset_system();

	/* The reset is immediate. This loop only satisfies the compiler. */
	while (true) {
		k_sleep(K_FOREVER);
	}
}

/* The reference product's own work, in its own thread.
 *
 * This is what the beacon-running health check observes. It is a thread rather
 * than a timer because a timer would keep ticking while the application was
 * dead, and a liveness signal that outlives the thing it describes is not a
 * liveness signal.
 *
 * It does not feed the watchdog. The watchdog is fed by the thread driving the
 * device's work, which is main, and keeping the two separate is what lets a
 * stalled beacon produce a controlled reboot after the health window while a
 * stalled main thread produces a watchdog reset ten seconds in.
 */
static void beacon_thread(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	for (;;) {
		k_sleep(K_SECONDS(1));

#ifdef CONFIG_COURSE_TRIAL_TIMEOUT_HEALTH
		/* The timeout-health release stops after the boot checks have
		 * seen one tick. Every check passes, the window opens, and then
		 * nothing advances again, so the window expires without a
		 * verdict rather than refusing at boot. That is the distinction
		 * section 6 draws between a failed check and an expired timer.
		 *
		 * It stops only while the image is on trial. A trial behaviour
		 * that kept running after the image was confirmed would be a
		 * permanent defect rather than a failed trial: the first build
		 * of this tier did exactly that, and a confirmed
		 * timeout-health image rebooted on the watchdog every ten
		 * seconds forever. An unhealthy release must fail its trial and
		 * nothing else.
		 */
		static int ticks;

		if (!boot_is_img_confirmed() && ++ticks > 1) {
			continue;
		}
#endif
		health_gate_note_beacon();
	}
}

K_THREAD_STACK_DEFINE(beacon_stack, 1024);
static struct k_thread beacon_thread_data;

/* What this image does during its trial boot.
 *
 * Every one of the five images is a real, correctly signed release. None is
 * hostile: nobody without the Release signing key can produce any of them, so
 * an unhealthy release is the manufacturer publishing something broken, which
 * section 11 names beside the attacks. The device cannot tell a broken release
 * from a leaked key, and it recovers from either the same way.
 */
static void run_trial_behaviour(void)
{
#if defined(CONFIG_COURSE_TRIAL_CRASH)
	printk("trial.crash faulting deliberately before the health gate starts\n");
	printk("trial.crash this image never reaches the code that could record a reason,\n");
	printk("trial.crash so the next boot identifies it by reset cause and by the absence\n");
	printk("trial.crash of any written reason\n");
	k_sleep(K_MSEC(100));
	/* __builtin_trap() emits an illegal instruction, which faults.
	 *
	 * The first version of this wrote to address 0x00000001 and expected a
	 * fault that never came: nothing on this part traps that write, so the
	 * image carried on into the health gate and failed it instead. A crash
	 * release that quietly turns into a failed-health release is worse than
	 * no crash release, because the tier would be demonstrating the wrong
	 * one of its two paths and the output would nearly support it.
	 */
	__builtin_trap();
#elif defined(CONFIG_COURSE_TRIAL_HANG)
	printk("trial.hang stopping here, in the thread that feeds the watchdog\n");
	printk("trial.hang an ordinary loop is enough. Interrupts keep being serviced and the\n");
	printk("trial.hang beacon thread keeps running; what stops is the feed, because only\n");
	printk("trial.hang this thread ever performs one.\n");
	printk("trial.hang the next boot shows rst:0x7 (TG0_WDT_HPSYS) and no written reason\n");
	k_sleep(K_MSEC(100));
	for (;;) {
	}
#endif
}

/* One update event, held until there is a network to send it on.
 *
 * The health gate runs before net_link_connect(), which is what makes section
 * 6's constraint structural rather than careful: a gate that has not connected
 * cannot be failed by a connection. The cost is that everything the trial has
 * to say happens offline.
 *
 * Reporting it immediately was worse than useless. It could never succeed, and
 * it printed a TLS failure directly beneath a health failure, which reads like
 * the network having caused the revert. Section 6 forbids that from being
 * true, and the device was printing evidence for it anyway.
 *
 * So the event waits here and goes out once the link is up. A failure is
 * reported by the image that comes back after the revert, which is the only
 * image still running to report anything.
 */
static struct {
	bool present;
	const char *event;
	char release_id[RECOVERY_ID_MAX];
	char detail[RECOVERY_REASON_MAX];
} pending_event;

static void queue_event(const char *event, const char *release_id, const char *detail)
{
	pending_event.present = true;
	pending_event.event = event;
	strncpy(pending_event.release_id, release_id, sizeof(pending_event.release_id) - 1);
	pending_event.release_id[sizeof(pending_event.release_id) - 1] = '\0';
	strncpy(pending_event.detail, detail, sizeof(pending_event.detail) - 1);
	pending_event.detail[sizeof(pending_event.detail) - 1] = '\0';

	printk("event.queued %s release_id=%s detail=%s\n", event, release_id, detail);
	printk("event.queued held until the link is up. Nothing here waits on the network,\n");
	printk("event.queued because the decision it describes was made without one.\n");
}

/* Queue a revert, naming the release that failed without pretending it is the
 * one running.
 *
 * The service stores an event's release identifier as running_release_id, and
 * for a revert the release that failed is precisely the one that is not
 * running. Putting the failed release in that field produced a record saying
 * the device was running an image it had just thrown away, which is worse than
 * saying nothing: a fleet view built on it would show the broken release
 * spreading.
 *
 * So the running release stays the running release and the failed one goes in
 * the detail, which is free text and already carries reasons.
 */
static void queue_revert(const char *failed_release, const char *reason)
{
	char detail[RECOVERY_REASON_MAX];

	snprintf(detail, sizeof(detail), "%s %s", failed_release, reason);
	queue_event("update.reverted", CONFIG_COURSE_RELEASE_ID, detail);
}

static void flush_pending_event(const char *state_name)
{
	if (!pending_event.present) {
		return;
	}
	pending_event.present = false;
	(void)ota_client_report(pending_event.event, state_name,
				pending_event.release_id, pending_event.detail);
}

/* What the device woke up as.
 *
 * MCUboot decides the swap and reports its type; only the application knows
 * why a trial gave up, because that happened in the previous boot of a
 * different image. So the reason is persisted before the controlled reboot and
 * replayed here, and the Learner correlates this with the bootloader's own
 * line from the same boot.
 *
 * Nothing translates either into prose. Tier 3's rule was that a replay must
 * never print a bare verdict, and turning a swap type into a sentence would
 * put the Learner back to trusting a verdict.
 */
static bool report_boot_state(void)
{
	struct failure_record failure;
	bool confirmed = boot_is_img_confirmed();

	printk("boot.state running image is %s\n",
	       confirmed ? "confirmed" : "on trial, not yet confirmed");

	if (recovery_failure_take(&failure) == 0) {
		printk("boot.state the previous boot gave up on release %s at check %s\n",
		       failure.release_id, failure.reason);
		printk("boot.state and MCUboot has put this image back. That is a revert.\n");
		queue_revert(failure.release_id, failure.reason);
	} else if (confirmed) {
		struct trial_record trial;

		printk("boot.state no reason was recorded by a previous boot\n");
		printk("boot.state A crash or a hang leaves nothing here: the device can say why\n");
		printk("boot.state it gave up only if it was still alive enough to write it down.\n");

		/* A revert after a crash or a hang leaves no reason, and the
		 * device is not blind all the same: a trial record naming a
		 * release it is not running is evidence that a trial happened
		 * and did not stick.
		 *
		 * This is the most important event this tier produces, because
		 * it names exactly the release that is hardest to diagnose. A
		 * device that stayed silent here would leave the fleet blindest
		 * about the failures that matter most.
		 */
		if (recovery_trial_peek(&trial) == 0 &&
		    strncmp(trial.release_id, CONFIG_COURSE_RELEASE_ID,
			    sizeof(trial.release_id)) != 0) {
			printk("boot.state release %s was tried %u times and is not what is running\n",
			       trial.release_id, trial.attempts);
			queue_revert(trial.release_id, "reason-unrecorded");
		}
	}

	recovery_state_report();
	return confirmed;
}

/* Prove this image works, then confirm it. */
static void confirm_or_revert(void)
{
	char reason[RECOVERY_REASON_MAX];
	enum health_result result;
	uint32_t attempt = 0;
	int err;

	printk("trial.begin this image is unconfirmed, so it has to earn the slot it is in\n");

	/* The attempt is recorded before the trial rather than after it fails.
	 * A crashing image never reaches code that could record a failure, and
	 * a hung one is reset from interrupt context where an NVS write is not
	 * safe, so counting failures would miss exactly the two failures that
	 * most need counting.
	 */
	err = recovery_trial_begin(CONFIG_COURSE_RELEASE_ID, &attempt);
	if (err == 0) {
		printk("trial.begin attempt %u of %d for release %s\n", attempt,
		       CONFIG_COURSE_TRIAL_FAILURE_LIMIT, CONFIG_COURSE_RELEASE_ID);
	}

	run_trial_behaviour();

	result = health_gate_run(reason, sizeof(reason));
	if (result == HEALTH_PASSED) {
		err = boot_write_img_confirmed();
		if (err != 0) {
			printk("trial.confirm failed err=%d, this image will be reverted\n", err);
			course_reset_system();
		}
		(void)recovery_trial_clear();
		printk("trial.confirm this image is now the one the device falls back to\n");
		queue_event("update.confirmed", CONFIG_COURSE_RELEASE_ID, "health gate passed");
		return;
	}

	/* Written before the reboot, because after it this image is no longer
	 * running and cannot say anything.
	 */
	/* Written before the reboot, because after it this image is no longer
	 * running. The image that comes back reports it: this one has no
	 * network and is about to stop existing.
	 */
	(void)recovery_failure_write(CONFIG_COURSE_RELEASE_ID, reason);

	printk("trial.revert %s at check %s\n",
	       result == HEALTH_TIMEOUT ? "the health window expired" : "a health check failed",
	       reason);
	printk("trial.revert this image is still unconfirmed, so MCUboot will put the last\n");
	printk("trial.revert confirmed image back on the next boot without being asked\n");
	k_sleep(K_MSEC(200));
	course_reset_system();
}

/* One poll: report status, read the assignment, fetch and verify the signed
 * manifest for whatever release it names, and install only if every check
 * passes. Returns true when the device should reboot into a freshly installed
 * image.
 *
 * The Update assignment is unchanged from Tier 0, down to the "signed": true
 * it still carries about itself. What changed is that the device stops taking
 * its word for anything except which release to go and ask about.
 */
static bool poll_once(enum beacon_state state)
{
	struct ota_release release;
	struct release_manifest manifest;
	const char *state_name = beacon_state_name(state);
	uint32_t attempts = 0;

	/* A rejected status report must not stop the update check: the two
	 * exchanges are independent, and Tier 0 gates neither on the other.
	 */
	(void)ota_client_report("status.observed", state_name, CONFIG_COURSE_RELEASE_ID,
				"verified service, signed release metadata");

	if (ota_client_fetch_assignment(&release) != 0) {
		return false;
	}

	printk("ota.assignment release_id=%s version=%s image=%s\n",
	       release.release_id, release.version, release.image_path);
	printk("ota.assignment it also claims size=%d sha256=%s\n",
	       release.image_size, release.image_sha256);
	printk("ota.assignment this device believes neither; they are the service's claims\n");
	printk("ota.assignment about itself. Only release_id is used, to know what to ask about.\n");

	/* Section 7's sixth rejection condition, which Tier 4 documented as
	 * absent because it had no confirmation flow to compare against.
	 *
	 * "An image it has already confirmed" means the image the device is
	 * currently running. Read that way the condition needs no stored state
	 * at all: the device compares the offered release id against its own
	 * and asks MCUboot whether it is confirmed, and both facts are already
	 * in hand. Remembering every release ever confirmed would be the
	 * application-managed accepted-image database section 6 forbids, under
	 * a different name.
	 *
	 * This is a refusal with its own reason, not "no update available".
	 * That would be the service's answer; this is the device's, and
	 * blurring the two hides that a check ran.
	 */
	if (!ota_release_differs(&release)) {
		if (boot_is_img_confirmed()) {
			printk("ota.refused check=already-confirmed release_id=%s\n",
			       release.release_id);
			printk("ota.refused this device confirmed that image and is running it\n");
			(void)ota_client_report("update.refused", state_name,
						CONFIG_COURSE_RELEASE_ID, "already-confirmed");
		} else {
			printk("ota.assignment matches the running release, nothing to install\n");
		}
		return false;
	}

	/* The bound that stops a revert loop.
	 *
	 * A release that downloads cleanly, installs cleanly and then fails its
	 * trial is offered again on the next poll, because nothing about it is
	 * invalid. Without a bound the device installs it, fails, reverts, and
	 * does it all again forever.
	 *
	 * The count prints on every attempt rather than only when it fires, so
	 * the mechanism is visible from the first cycle instead of after three
	 * reboots and three health windows.
	 */
	if (recovery_trial_read(release.release_id, &attempts) == 0 &&
	    attempts >= (uint32_t)CONFIG_COURSE_TRIAL_FAILURE_LIMIT) {
		printk("ota.refused check=trial-limit release_id=%s attempts=%u of %d\n",
		       release.release_id, attempts, CONFIG_COURSE_TRIAL_FAILURE_LIMIT);
		printk("ota.refused this release has already been given every trial it gets.\n");
		printk("ota.refused The beacon carries on; the device is healthy and has simply\n");
		printk("ota.refused stopped accepting one release.\n");
		(void)ota_client_report("update.refused", state_name,
					CONFIG_COURSE_RELEASE_ID, "trial-limit");
		return false;
	}

	printk("ota.assignment offers %s instead of the running %s; asking for its signed manifest\n",
	       release.release_id, CONFIG_COURSE_RELEASE_ID);

	if (ota_client_fetch_manifest(release.release_id, &manifest) != 0) {
		(void)ota_client_report("update.refused", state_name,
					CONFIG_COURSE_RELEASE_ID, release.release_id);
		return false;
	}

	if (ota_client_install(&manifest) != 0) {
		(void)ota_client_report("update.failed", state_name,
					CONFIG_COURSE_RELEASE_ID, manifest.release_id);
		return false;
	}

	(void)ota_client_report("update.installed", state_name, CONFIG_COURSE_RELEASE_ID,
				manifest.release_id);
	return true;
}

/* Wait for the next poll without starving the watchdog.
 *
 * The poll interval is thirty seconds and the watchdog window is ten, so a
 * single sleep across the interval would have the device reset itself between
 * polls. The first build of this tier did exactly that, and the board showed
 * it as a healthy image rebooting on rst:0x7 every half minute.
 *
 * Sleeping in slices keeps the two independent: the watchdog window stays
 * short, so a hung thread is caught quickly, and the poll interval stays long,
 * so the service is not hammered. Tying one to the other would mean choosing
 * between catching a hang late and polling too often.
 */
static void idle_between_polls(void)
{
	const int slice = 2;

	for (int waited = 0; waited < CONFIG_COURSE_POLL_INTERVAL_SECONDS; waited += slice) {
		k_sleep(K_SECONDS(slice));
		health_gate_feed();
	}
}

int main(void)
{
	enum beacon_state state = beacon_configured_state();
	char address[NET_IPV4_ADDR_LEN];

	announce(state);

	/* Everything below depends on the storage partition being available,
	 * because a device that cannot remember where a download got to cannot
	 * resume one, and a device that cannot count trials cannot bound them.
	 * A failure here is reported and survivable: the tier degrades to
	 * Tier 4's behaviour rather than refusing to run.
	 */
	/* Identity comes up before the recovery state, because both write to the
	 * same NVS instance and identity.c is what starts the settings subsystem
	 * that owns it. Tier 5 mounted its own instance here; Tier 6 shares one.
	 */
	(void)course_identity_init();
	(void)recovery_state_init();
	course_identity_gate();

	/* Armed before the trial behaviour runs, so a hung image is already
	 * being watched by the time it hangs.
	 */
	(void)health_gate_start_watchdog();
	k_thread_create(&beacon_thread_data, beacon_stack,
			K_THREAD_STACK_SIZEOF(beacon_stack), beacon_thread,
			NULL, NULL, NULL, K_PRIO_PREEMPT(10), 0, K_NO_WAIT);
	k_thread_name_set(&beacon_thread_data, "beacon");

	if (!report_boot_state()) {
		confirm_or_revert();
	}

	if (net_link_connect() != 0) {
		printk("Offline mode: no OTA exchange is possible\n");
		printk("Hardware note: Wi-Fi, HTTP transfer, and OTA install remain unobserved\n");
		while (true) {
			k_sleep(K_SECONDS(CONFIG_COURSE_POLL_INTERVAL_SECONDS));
			printk("status.offline device_id=%s machine_state=%s\n",
			       CONFIG_COURSE_DEVICE_ID, beacon_state_name(state));
		}
	}

	if (net_link_address(address, sizeof(address)) == 0) {
		printk("wifi.address %s assigned by DHCP\n", address);
	}

	flush_pending_event(beacon_state_name(state));

	while (true) {
		/* main is the thread the watchdog vouches for, so main is the
		 * only thing that feeds it.
		 */
		health_gate_feed();
		if (poll_once(state)) {
			printk("Rebooting into the newly installed image\n");
			k_sleep(K_MSEC(200));
			course_reset_system();
		}
		idle_between_polls();
	}
}

#ifdef CONFIG_COURSE_PROVISIONING_SHELL

void course_provisioning_open(void);
void course_provisioning_close(void);

#if DT_NODE_EXISTS(DT_ALIAS(sw0))
static const struct gpio_dt_spec provisioning_button = GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);
#endif

/* Is someone physically holding the board in provisioning mode?
 *
 * This is the re-entry path for remanufacturing. Without it the interface
 * closes permanently on enrollment and there is no way to send the erase
 * command: reflashing does not help, because Secure Storage lives in the
 * storage partition and survives a slot 0 flash exactly the way MCUboot's
 * trailer does.
 *
 * The cost is a weakness worth naming rather than hiding. Anyone with physical
 * access and this button can put the device back into provisioning mode.
 */
static bool provisioning_button_held(void)
{
#if DT_NODE_EXISTS(DT_ALIAS(sw0)) && defined(CONFIG_COURSE_PROVISIONING_BUTTON_REOPENS)
	if (!gpio_is_ready_dt(&provisioning_button)) {
		return false;
	}
	if (gpio_pin_configure_dt(&provisioning_button, GPIO_INPUT) != 0) {
		return false;
	}
	return gpio_pin_get_dt(&provisioning_button) > 0;
#else
	return false;
#endif
}

void course_identity_gate(void)
{
	bool provisioned = course_identity_is_provisioned();
	bool held = provisioning_button_held();

	if (!provisioned) {
		printk("provision.gate this device holds no identity, opening the interface\n");
		printk("provision.gate type: provision status\n");
		course_provisioning_open();
		return;
	}
	if (held) {
		printk("provision.gate the button is held, reopening the interface on an\n");
		printk("provision.gate already provisioned device. This is remanufacturing.\n");
		course_provisioning_open();
		return;
	}
	printk("provision.gate provisioned, and the provisioning interface is not running\n");
	printk("provision.gate nothing on this console will enroll it. Hold BOOT at reset\n");
	printk("provision.gate to reopen it deliberately.\n");
}

#else

void course_identity_gate(void)
{
	/* The shared build has nothing to provision. Every image built this way
	 * already is the device, which is the problem.
	 */
}

#endif /* CONFIG_COURSE_PROVISIONING_SHELL */
