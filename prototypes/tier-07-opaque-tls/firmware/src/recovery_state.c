#include "recovery_state.h"

#include <errno.h>
#include <string.h>

/* zephyr/fs/nvs.h is deprecated in this Zephyr; the API is unchanged and only
 * the header moved.
 */
#include <zephyr/kvss/nvs.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

/* NVS record identifiers.
 *
 * Small integers rather than strings, because this is NVS rather than the
 * settings subsystem. Settings would give string keys and a tidier API, and it
 * is built on NVS here, so it would be a layer of ergonomics over three
 * records with a handful of fields each. In the one tier whose subject is what
 * survives a power cut, a Learner is better served by seeing the write that
 * matters than by a nicer interface to it.
 */
#define RECOVERY_NVS_DOWNLOAD 1
#define RECOVERY_NVS_TRIAL 2
#define RECOVERY_NVS_FAILURE 3

/* Tier 6 changed where this lives, and nothing about what it does.
 *
 * Tier 5 mounted its own nvs_fs at the first byte of the storage partition and
 * explained at length why it used NVS directly rather than the settings
 * subsystem. That reasoning still holds and the raw writes below are unchanged.
 *
 * What changed is that Tier 6 puts a PSA Secure Storage key in the same
 * partition, and the ITS store writes through settings, whose own NVS instance
 * takes its offset from the partition's first byte and cannot be moved: there
 * is no Kconfig and no devicetree property for it. Both instances therefore
 * landed on the same bytes, and nothing detected it. nvs_mount() checks write
 * block size, sector size against page size, and a count of at least two, and
 * nothing else, so both mounts returned 0. The damage did not even wait for a
 * write, because mounting erases the sector after the write sector.
 *
 * So this file stops mounting a second instance and uses the one settings
 * already owns. The entry identifiers do not overlap: settings uses 0x8000 and
 * above, and the three records below are 1, 2 and 3.
 *
 * This is a bug Tier 6 found in Tier 5, fixed here rather than in the
 * published Tier 5, whose behaviour on its own is correct. It only surfaced
 * now because Tier 5 was the only user of this partition. Measured on issue
 * #109, decided on issue #120.
 */
static struct nvs_fs *course_nvs;
static bool mounted;

int recovery_state_init(void)
{
	void *storage = NULL;
	int err;

	if (mounted) {
		return 0;
	}

	/* settings_subsys_init() is what mounts the instance, and identity.c
	 * calls it before this runs. Calling it again is harmless and makes the
	 * dependency explicit rather than relying on main's ordering.
	 */
	err = settings_subsys_init();
	if (err != 0) {
		printk("recovery.state settings would not start err=%d\n", err);
		return err;
	}
	err = settings_storage_get(&storage);
	if (err != 0 || storage == NULL) {
		printk("recovery.state cannot reach the settings storage err=%d\n", err);
		return err != 0 ? err : -ENODEV;
	}
	course_nvs = (struct nvs_fs *)storage;

	mounted = true;
	printk("recovery.state sharing the settings NVS instance at 0x%lx, %u sectors of %u bytes\n",
	       (unsigned long)course_nvs->offset, course_nvs->sector_count,
	       course_nvs->sector_size);
	printk("recovery.state record ids 1 to 3; settings uses 0x8000 and above\n");
	printk("recovery.state Tier 6 shares this instance with PSA Secure Storage\n");
	return 0;
}

static int read_record(uint16_t id, void *out, size_t len)
{
	ssize_t got;

	if (!mounted) {
		return -ENODEV;
	}
	got = nvs_read(course_nvs, id, out, len);
	if (got == -ENOENT) {
		return -ENOENT;
	}
	if (got < 0) {
		return (int)got;
	}
	if ((size_t)got != len) {
		/* A record of the wrong length is a record written by different
		 * code. Treat it as absent rather than as data: reading a
		 * struct out of bytes that were never that struct is how a
		 * recovery mechanism becomes the thing it was meant to prevent.
		 */
		printk("recovery.state record %u is %d bytes, expected %zu; discarding it\n",
		       id, (int)got, len);
		(void)nvs_delete(course_nvs, id);
		return -ENOENT;
	}
	return 0;
}

static int write_record(uint16_t id, const void *in, size_t len)
{
	ssize_t written;

	if (!mounted) {
		return -ENODEV;
	}
	written = nvs_write(course_nvs, id, in, len);
	if (written < 0) {
		return (int)written;
	}
	return 0;
}

int recovery_download_read(struct download_record *record)
{
	return read_record(RECOVERY_NVS_DOWNLOAD, record, sizeof(*record));
}

int recovery_download_write(const struct download_record *record)
{
	return write_record(RECOVERY_NVS_DOWNLOAD, record, sizeof(*record));
}

int recovery_download_clear(void)
{
	if (!mounted) {
		return -ENODEV;
	}
	return nvs_delete(course_nvs, RECOVERY_NVS_DOWNLOAD);
}

int recovery_trial_read(const char *release_id, uint32_t *attempts)
{
	struct trial_record record;
	int err;

	*attempts = 0U;
	err = read_record(RECOVERY_NVS_TRIAL, &record, sizeof(record));
	if (err == -ENOENT) {
		return 0;
	}
	if (err != 0) {
		return err;
	}
	if (strncmp(record.release_id, release_id, sizeof(record.release_id)) != 0) {
		/* The count belongs to a different release. A release the device
		 * is not being offered any more is not one it needs to remember
		 * having failed.
		 */
		return 0;
	}
	*attempts = record.attempts;
	return 0;
}

int recovery_trial_peek(struct trial_record *record)
{
	return read_record(RECOVERY_NVS_TRIAL, record, sizeof(*record));
}

int recovery_trial_begin(const char *release_id, uint32_t *attempt)
{
	struct trial_record record;
	uint32_t attempts = 0U;
	int err;

	err = recovery_trial_read(release_id, &attempts);
	if (err != 0) {
		return err;
	}

	memset(&record, 0, sizeof(record));
	strncpy(record.release_id, release_id, sizeof(record.release_id) - 1);
	record.attempts = attempts + 1U;

	err = write_record(RECOVERY_NVS_TRIAL, &record, sizeof(record));
	if (err != 0) {
		return err;
	}
	*attempt = record.attempts;
	return 0;
}

int recovery_trial_clear(void)
{
	if (!mounted) {
		return -ENODEV;
	}
	return nvs_delete(course_nvs, RECOVERY_NVS_TRIAL);
}

int recovery_failure_write(const char *release_id, const char *reason)
{
	struct failure_record record;

	memset(&record, 0, sizeof(record));
	strncpy(record.release_id, release_id, sizeof(record.release_id) - 1);
	strncpy(record.reason, reason, sizeof(record.reason) - 1);
	return write_record(RECOVERY_NVS_FAILURE, &record, sizeof(record));
}

int recovery_failure_take(struct failure_record *record)
{
	int err;

	err = read_record(RECOVERY_NVS_FAILURE, record, sizeof(*record));
	if (err != 0) {
		return err;
	}
	(void)nvs_delete(course_nvs, RECOVERY_NVS_FAILURE);
	return 0;
}

void recovery_state_report(void)
{
	struct download_record download;
	struct trial_record trial;

	if (!mounted) {
		printk("recovery.state not mounted, so nothing survives a power cut\n");
		return;
	}

	if (recovery_download_read(&download) == 0) {
		printk("recovery.state download release_id=%s offset=%u size=%u\n",
		       download.release_id, download.offset, download.size);
		printk("recovery.state that many bytes are known to be in the secondary slot.\n");
		printk("recovery.state The record is written after the bytes, so it may lag the\n");
		printk("recovery.state flash and can never describe more than the flash holds.\n");
	} else {
		printk("recovery.state download none in progress\n");
	}

	if (read_record(RECOVERY_NVS_TRIAL, &trial, sizeof(trial)) == 0) {
		printk("recovery.state trial release_id=%s attempts=%u of %d\n",
		       trial.release_id, trial.attempts,
		       CONFIG_COURSE_TRIAL_FAILURE_LIMIT);
	} else {
		printk("recovery.state trial no release is being tried\n");
	}
}
