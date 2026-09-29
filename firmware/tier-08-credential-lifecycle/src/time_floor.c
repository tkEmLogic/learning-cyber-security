/*
 * The Time floor. See time_floor.h for what it is, what it judges and what it
 * refuses to judge.
 */

#include "time_floor.h"
#include "identity.h"
#include "recovery_state.h"

#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>

#include <mbedtls/x509.h>

/*
 * What NVS record 4 holds: the floor and what last raised it. Fixed-width
 * fields rather than an mbedtls_x509_time, so the record's size does not
 * depend on how a library lays out a struct.
 */
struct floor_record {
	int32_t year;
	int32_t mon;
	int32_t day;
	int32_t hour;
	int32_t min;
	int32_t sec;
	char source[48];
};

/* NVS record 5: the event the refused certificate could not deliver. */
struct expiry_record {
	char detail[96];
};

static mbedtls_x509_time floor_time;
static char floor_source[48];
static char floor_text[24];

static void format_time(const mbedtls_x509_time *t, char *out, size_t out_size)
{
	snprintf(out, out_size, "%04d-%02d-%02dT%02d:%02d:%02dZ", t->year, t->mon, t->day,
		 t->hour, t->min, t->sec);
}

/*
 * RFC 3339 in UTC, exactly the shape Go's time.RFC3339 writes for a UTC time:
 * 2026-09-29T10:00:00Z. Fractional seconds and offsets are refused rather than
 * guessed at, because a floor that misread a signed date would move time by
 * whatever the misreading was, and it can never move back.
 */
static int parse_time(const char *text, mbedtls_x509_time *out)
{
	int year, mon, day, hour, min, sec;
	char zone = '\0';
	char extra = '\0';

	if (text == NULL ||
	    sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2d%c%c", &year, &mon, &day, &hour, &min, &sec,
		   &zone, &extra) != 7 ||
	    zone != 'Z' || strlen(text) != 20) {
		return -EINVAL;
	}
	if (year < 2000 || year > 9999 || mon < 1 || mon > 12 || day < 1 || day > 31 ||
	    hour > 23 || min > 59 || sec > 60 || hour < 0 || min < 0 || sec < 0) {
		return -EINVAL;
	}
	out->year = year;
	out->mon = mon;
	out->day = day;
	out->hour = hour;
	out->min = min;
	out->sec = sec;
	return 0;
}

static void persist(void)
{
	struct floor_record record;
	int err;

	memset(&record, 0, sizeof(record));
	record.year = floor_time.year;
	record.mon = floor_time.mon;
	record.day = floor_time.day;
	record.hour = floor_time.hour;
	record.min = floor_time.min;
	record.sec = floor_time.sec;
	strncpy(record.source, floor_source, sizeof(record.source) - 1);
	err = recovery_record_write(RECOVERY_NVS_TIME_FLOOR, &record, sizeof(record));
	if (err != 0) {
		printk("time.floor could not be persisted err=%d; it holds for this boot only\n", err);
	}
}

static void set_floor(const mbedtls_x509_time *t, const char *source)
{
	floor_time = *t;
	strncpy(floor_source, source, sizeof(floor_source) - 1);
	floor_source[sizeof(floor_source) - 1] = '\0';
	format_time(&floor_time, floor_text, sizeof(floor_text));
}

/*
 * The one comparison the floor makes, and the one consequence.
 *
 * valid_to earlier than the floor is a certain expiry: time has provably
 * passed it. Equal or later proves nothing either way, and the device carries
 * on presenting the certificate for the service to judge, which is the only
 * party with a clock.
 */
static void judge(void)
{
	mbedtls_x509_time valid_to;
	char valid_text[24];

	if (course_identity_candidate_valid_to(&valid_to) == 0 &&
	    mbedtls_x509_time_cmp(&valid_to, &floor_time) < 0) {
		format_time(&valid_to, valid_text, sizeof(valid_text));
		printk("time.floor the renewal candidate expired at %s, before the floor %s.\n",
		       valid_text, floor_text);
		printk("time.floor A candidate that cannot be used is not kept.\n");
		course_identity_discard_candidate();
	}

	if (course_identity_operational_expired() ||
	    course_identity_operational_valid_to(&valid_to) != 0) {
		return;
	}
	if (mbedtls_x509_time_cmp(&valid_to, &floor_time) >= 0) {
		return;
	}

	format_time(&valid_to, valid_text, sizeof(valid_text));
	course_identity_refuse_expired_operational();
	printk("time.floor expired valid_to=%s floor=%s\n", valid_text, floor_text);
	printk("time.floor the Operational certificate expired at %s, and this device has\n",
	       valid_text);
	printk("time.floor signed proof that the time is at least %s,\n", floor_text);
	printk("time.floor from %s. It stops presenting that certificate now. The product\n",
	       floor_source);
	printk("time.floor keeps running; nothing is erased; the lifecycle state is the\n");
	printk("time.floor service's to change, not this device's. The way back is recovery.\n");
	printk("time.floor This proves a certain expiry only. A certificate that expired after\n");
	printk("time.floor the last release this device verified still looks alive from here.\n");

	struct expiry_record record;

	memset(&record, 0, sizeof(record));
	snprintf(record.detail, sizeof(record.detail), "valid_to=%s floor=%s", valid_text,
		 floor_text);
	if (recovery_record_write(RECOVERY_NVS_TIME_FLOOR_EXPIRY, &record, sizeof(record)) != 0) {
		printk("time.floor the expiry event could not be stored\n");
	}
}

int time_floor_init(void)
{
	struct floor_record record;
	mbedtls_x509_time seed;
	mbedtls_x509_time stored;

	if (parse_time(CONFIG_COURSE_TIME_FLOOR_SEED, &seed) != 0) {
		printk("time.floor the build seed %s is not RFC 3339 UTC; this is a build defect\n",
		       CONFIG_COURSE_TIME_FLOOR_SEED);
		return -EINVAL;
	}
	set_floor(&seed, "the build seed");

	if (recovery_record_read(RECOVERY_NVS_TIME_FLOOR, &record, sizeof(record)) == 0) {
		stored.year = record.year;
		stored.mon = record.mon;
		stored.day = record.day;
		stored.hour = record.hour;
		stored.min = record.min;
		stored.sec = record.sec;
		record.source[sizeof(record.source) - 1] = '\0';
		if (mbedtls_x509_time_cmp(&stored, &seed) >= 0) {
			set_floor(&stored, record.source);
		} else {
			persist();
		}
	} else {
		persist();
	}

	printk("time.floor %s, set by %s\n", floor_text, floor_source);
	printk("time.floor a lower bound on the time, never the time. It rises to the created_at\n");
	printk("time.floor of every Release manifest whose signature verifies, and judges only\n");
	printk("time.floor this device's own Operational certificate.\n");
	judge();
	return 0;
}

void time_floor_observe(const char *created_at, const char *release_id)
{
	mbedtls_x509_time seen;
	char source[48];

	if (parse_time(created_at, &seen) != 0) {
		printk("time.floor the verified created_at %s is not RFC 3339 UTC; the floor stays "
		       "at %s\n", created_at == NULL ? "(none)" : created_at, floor_text);
		return;
	}
	if (mbedtls_x509_time_cmp(&seen, &floor_time) <= 0) {
		printk("time.floor stays at %s; release %s was created at %s, which is not later\n",
		       floor_text, release_id, created_at);
		return;
	}
	snprintf(source, sizeof(source), "release %s", release_id);
	set_floor(&seen, source);
	persist();
	printk("time.floor raised to %s by the signed created_at of release %s\n", floor_text,
	       release_id);
	printk("time.floor the signature is the evidence, whether or not the release installs\n");
	judge();
}

const char *time_floor_text(void)
{
	return floor_text;
}

bool time_floor_expiry_pending(char *detail, size_t detail_size)
{
	struct expiry_record record;

	if (recovery_record_read(RECOVERY_NVS_TIME_FLOOR_EXPIRY, &record, sizeof(record)) != 0) {
		return false;
	}
	record.detail[sizeof(record.detail) - 1] = '\0';
	strncpy(detail, record.detail, detail_size - 1);
	detail[detail_size - 1] = '\0';
	return true;
}

void time_floor_expiry_delivered(void)
{
	(void)recovery_record_delete(RECOVERY_NVS_TIME_FLOOR_EXPIRY);
}
