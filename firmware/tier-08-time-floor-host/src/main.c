/*
 * E-8-11, a host build of Tier 8's Time floor (#262).
 *
 * Whoever holds the release signing key can end every Operational credential
 * by dating a manifest in the future (#217). This program shows it with the
 * firmware's own code: time_floor.c, release_policy.c and recovery_state.c are
 * compiled unchanged from firmware/tier-08-credential-lifecycle/src. The
 * manifest path below is the three calls ota_client_fetch_manifest() makes
 * after the download, in its order: verify the signature over the exact bytes,
 * parse them, raise the Time floor, then admit or refuse by policy.
 *
 * It must never run on a board, and it cannot: it is built for native_sim,
 * it opens no socket, and the only key it verifies against is a throwaway one
 * that ./course service bypass e-8-11 generated for this run and never wrote
 * down. A board would keep the floor ahead for good, and refuse every
 * certificate issued before that date, which is what the second boot shows.
 *
 * The runner starts this program twice on one simulated flash file, with
 * -testargs naming the boot. What survives between the two is record 4 in NVS,
 * exactly what survives a reset on the board.
 */

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>

#include <cmdline.h>
#include <nsi_main.h>

#include "identity_host.h"
#include "recovery_state.h"
#include "release_policy.h"
#include "time_floor.h"

/* Generated per run. See the runner in internal/courseapp/tier08_time_floor.go. */
static const uint8_t operational_cert[] = {
#include "operational_cert.inc"
};
static const uint8_t recovered_cert[] = {
#include "recovered_cert.inc"
};
static const char far_manifest[] = {
#include "far_manifest.inc"
	0x00
};
static const uint8_t far_manifest_sig[] = {
#include "far_manifest_sig.inc"
};
/* The same far-future bytes, signed by a key this build does not trust. */
static const uint8_t untrusted_manifest_sig[] = {
#include "untrusted_manifest_sig.inc"
};
static const char ordinary_manifest[] = {
#include "ordinary_manifest.inc"
	0x00
};
static const uint8_t ordinary_manifest_sig[] = {
#include "ordinary_manifest_sig.inc"
};

/* The parser rewrites the buffer it reads, as it does on the board. */
static char manifest_buf[1024];

/* Which boot this is, from -testargs. */
enum boot {
	BOOT_UNKNOWN,
	BOOT_FIRST,
	BOOT_AFTER_RECOVERY,
};

static enum boot which_boot(void)
{
	int argc = 0;
	char **argv = NULL;

	native_get_test_cmd_line_args(&argc, &argv);
	if (argc == 1 && strcmp(argv[0], "first") == 0) {
		return BOOT_FIRST;
	}
	if (argc == 1 && strcmp(argv[0], "after-recovery") == 0) {
		return BOOT_AFTER_RECOVERY;
	}
	return BOOT_UNKNOWN;
}

/* What the TLS layer would be handed for the Operational identity. */
static int report_presentation(void)
{
	const unsigned char *der = NULL;
	size_t len = 0;
	int err = host_identity_present(&der, &len);

	if (err == 0) {
		printk("host.present operational certificate presented, %zu bytes\n", len);
	} else if (err == -EKEYEXPIRED) {
		printk("host.present operational certificate refused err=-EKEYEXPIRED\n");
	} else {
		printk("host.present no operational certificate err=%d\n", err);
	}
	return err;
}

/*
 * ota_client_fetch_manifest() after its two downloads, line for line: the
 * signature over the exact bytes first, then the parse, then the floor, then
 * the policy.
 */
static int receive_manifest(const char *body, const uint8_t *sig, size_t sig_len)
{
	struct release_manifest manifest;
	size_t len = strlen(body);
	int err;

	if (len >= sizeof(manifest_buf)) {
		printk("host.manifest the generated manifest is %zu bytes, too long\n", len);
		return -EMSGSIZE;
	}
	memcpy(manifest_buf, body, len);
	manifest_buf[len] = '\0';

	err = release_policy_verify((const uint8_t *)manifest_buf, len, sig, sig_len);
	if (err != 0) {
		return err;
	}
	err = release_policy_parse(manifest_buf, len, &manifest);
	if (err != 0) {
		return err;
	}
	printk("host.manifest release %s, created_at %s, signature verified\n",
	       manifest.release_id, manifest.created_at);
	time_floor_observe(manifest.created_at, manifest.release_id);
	err = release_policy_admit(&manifest, manifest.release_id);
	printk("host.manifest release policy answered %d; the floor saw this manifest first\n", err);
	return 0;
}

static int first_boot(void)
{
	printk("host.boot first: a synthetic Operational certificate issued today\n");
	if (host_identity_load(operational_cert, sizeof(operational_cert)) != 0) {
		return -EINVAL;
	}
	if (time_floor_init() != 0) {
		return -EINVAL;
	}
	if (report_presentation() != 0) {
		printk("host.result the certificate was refused before any manifest; nothing is shown\n");
		return -EALREADY;
	}

	printk("host.boot the far-future manifest, signed by a key this image does not trust\n");
	if (receive_manifest(far_manifest, untrusted_manifest_sig, sizeof(untrusted_manifest_sig)) == 0) {
		printk("host.result a manifest this image cannot verify was accepted\n");
		return -EPERM;
	}
	if (report_presentation() != 0) {
		printk("host.result an unverified manifest moved the floor\n");
		return -EPERM;
	}

	printk("host.boot the same manifest, signed with the release key\n");
	if (receive_manifest(far_manifest, far_manifest_sig, sizeof(far_manifest_sig)) != 0) {
		printk("host.result the far-future manifest did not verify; the floor never saw it\n");
		return -EACCES;
	}
	return report_presentation() == -EKEYEXPIRED ? 0 : -EPERM;
}

static int after_recovery(void)
{
	printk("host.boot after a reset: a fresh certificate, as a recovery would issue today\n");
	if (host_identity_load(recovered_cert, sizeof(recovered_cert)) != 0) {
		return -EINVAL;
	}
	if (time_floor_init() != 0) {
		return -EINVAL;
	}

	printk("host.boot an ordinary manifest, created now, signed with the same key\n");
	if (receive_manifest(ordinary_manifest, ordinary_manifest_sig,
			     sizeof(ordinary_manifest_sig)) != 0) {
		printk("host.result the ordinary manifest did not verify\n");
		return -EACCES;
	}
	return report_presentation() == -EKEYEXPIRED ? 0 : -EPERM;
}

int main(void)
{
	enum boot boot = which_boot();
	int err;

	if (boot == BOOT_UNKNOWN) {
		printk("host.result run with -testargs first, then -testargs after-recovery\n");
		nsi_exit(2);
	}
	err = recovery_state_init();
	if (err != 0) {
		printk("host.result the simulated storage partition would not mount err=%d\n", err);
		nsi_exit(1);
	}

	err = boot == BOOT_FIRST ? first_boot() : after_recovery();
	printk("host.result %s err=%d\n", err == 0 ? "refused" : "not-refused", err);
	nsi_exit(err == 0 ? 0 : 1);
	return 0;
}
