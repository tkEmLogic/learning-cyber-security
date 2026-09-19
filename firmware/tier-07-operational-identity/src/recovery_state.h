/*
 * The state Tier 5 keeps in flash so a power cut is survivable.
 *
 * This is the first use of the 192 KiB storage partition at 0x3b0000. It has
 * been in the pinned flash map since Tier 0 and no tier has written to it, so
 * everything here is new ground for the course rather than an extension of
 * something earlier.
 *
 * Three records, each answering a question the device cannot answer from the
 * slot contents alone:
 *
 *   download  where a partial transfer got to, and what it was transferring
 *   trial     how many times a release has been put on trial
 *   failure   why the last trial gave up, for the boot that happens after it
 *
 * None of these is trusted input. The download record says where to resume,
 * never what to believe: a resume re-fetches the Release manifest and verifies
 * its signature again before the record is allowed to matter. Keeping that
 * distinction is the point. In the one tier that introduces persistent state,
 * promoting flash contents to a trust anchor would be exactly the wrong habit
 * to teach.
 */

#ifndef COURSE_RECOVERY_STATE_H
#define COURSE_RECOVERY_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RECOVERY_ID_MAX 64
#define RECOVERY_DIGEST_MAX 72
#define RECOVERY_REASON_MAX 64

/* Where a partial download got to.
 *
 * offset is the number of image bytes known to be in the secondary slot. It is
 * written after those bytes reach flash, never before, so it can only ever
 * describe less than the slot holds. A record that over-claims would resume
 * into a gap and produce a corrupt image that only the digest would catch; a
 * record that under-claims costs at most one checkpoint of re-downloaded
 * bytes. Only one of those is safe, so the record always lags the flash.
 *
 * size and digest are copied from the verified manifest at the time the
 * download started. They are kept so a resume can tell that the release
 * changed underneath it without asking the service, which matters because
 * Tier 4 established the service as the party that chooses what a device is
 * offered.
 */
struct download_record {
	char release_id[RECOVERY_ID_MAX];
	char digest[RECOVERY_DIGEST_MAX];
	uint32_t offset;
	uint32_t size;
};

/* How many times one release has been put on trial.
 *
 * The count is incremented when a trial begins, never when one fails. A
 * crashing image never reaches code that could record a failure, and a hung
 * one is reset from interrupt context where an NVS write is not safe, so a
 * count kept on failure would miss the two failures that most need counting.
 * Counting attempts rather than failures is robust against a trial image
 * dying in any manner at all, including manners nobody has thought of.
 *
 * reported says the fleet has already been told about this trial. It is here
 * because the record outlives the revert it describes: nothing clears the
 * count on the path where a revert actually happened, and nothing may, because
 * this same count is the bound that stops a revert loop. Clearing it to silence
 * a duplicate report would hand the device straight back to installing a
 * failing release forever.
 *
 * So the count stays and the report is marked instead. Keeping "already said"
 * apart from "how many times tried" is what lets one record answer two
 * questions that stop being true at different moments.
 */
struct trial_record {
	char release_id[RECOVERY_ID_MAX];
	uint32_t attempts;
	bool reported;
};

/* Why the last trial gave up.
 *
 * Only two of the four trial failures can fill this in. A failed health check
 * and an expired health window both happen in thread context with time to
 * spare. A crash and a hang do not: the device can tell you why it gave up
 * only if it was still alive enough to write it down.
 *
 * That asymmetry is not a defect to engineer around. It is the honest
 * description of what a watchdog reset is, and Tier 5 teaches it rather than
 * hiding it behind a uniform-looking report.
 */
struct failure_record {
	char release_id[RECOVERY_ID_MAX];
	char reason[RECOVERY_REASON_MAX];
};

/* Mounts the storage partition. Every function below returns -ENODEV until
 * this has succeeded.
 */
int recovery_state_init(void);

/* Reads the download record. Returns 0 when one was found, -ENOENT when there
 * is no partial download recorded.
 */
int recovery_download_read(struct download_record *record);

/* Writes the download record. Call after the bytes it describes are in flash.
 */
int recovery_download_write(const struct download_record *record);

/* Forgets any partial download.
 *
 * Call this before erasing the slot, which is the mirror of the write order
 * and for the same reason. Writing lags the flash so the record can only
 * under-claim; discarding leads it so a power cut in the middle leaves no
 * record rather than a record pointing into an erased slot. One rule underneath
 * both: the record may never describe more than the flash holds.
 */
int recovery_download_clear(void);

/* Reads the trial count for a release. Returns 0 with attempts set to zero
 * when the release has never been tried.
 */
int recovery_trial_read(const char *release_id, uint32_t *attempts);

/* Reads the trial record as stored, whichever release it belongs to.
 *
 * Needed because a device that has just reverted after a crash or a hang has
 * no failure reason to read, and the only remaining evidence that a trial
 * happened at all is a trial record naming a release it is not running.
 */
int recovery_trial_peek(struct trial_record *record);

/* Records that a trial of this release is about to begin, and reports the
 * attempt number it is. Starting a different release forgets the previous
 * one's count.
 */
int recovery_trial_begin(const char *release_id, uint32_t *attempt);

/* Forgets the trial count, which happens when a release confirms. */
int recovery_trial_clear(void);

/* Records that the revert this trial record describes has been reported.
 *
 * Marks rather than clears, for the reason given on struct trial_record. The
 * mark is set once the event is queued and not once it is delivered, because
 * delivery is best effort and nothing acknowledges it. A device that reverts
 * while it cannot reach the service therefore never reports that revert at
 * all. That is a real limit, and this tier names it rather than hiding it
 * behind a retry, which is what the duplicate reports were pretending to be.
 */
int recovery_trial_mark_reported(void);

/* Records why a trial gave up, for the boot that follows the revert. */
int recovery_failure_write(const char *release_id, const char *reason);

/* Reads and then forgets the reason the last trial gave up. Returns -ENOENT
 * when nothing wrote one, which is what a crash or a hang leaves behind.
 */
int recovery_failure_take(struct failure_record *record);

/* Prints every record. A state a Learner cannot see is a state they cannot be
 * taught, so this runs at boot and again on every resume.
 */
void recovery_state_report(void);

#endif /* COURSE_RECOVERY_STATE_H */
