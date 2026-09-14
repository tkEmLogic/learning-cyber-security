/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Report what the bootloader saw in a candidate image, before it judges it.
 *
 * MCUboot prints one line for every kind of bad image:
 *
 *     E: Image in the secondary slot is not valid!
 *
 * It does not say why. bootutil_img_validate() returns a single fih_ret and
 * every failure inside it leaves through a silent goto, so the cause never
 * reaches the caller. That is deliberate. One return value is harder to skip
 * past with a fault injection glitch than a set of them, and a bootloader is
 * exactly where that trade is worth making.
 *
 * A Learner still has to be able to tell four failures apart. So this hook
 * reports facts and leaves the verdict alone. It prints what is actually in
 * the image, then returns FIH_BOOT_HOOK_REGULAR, and MCUboot runs its normal
 * validation and makes every accept and reject decision. Read the two lines
 * together:
 *
 *     I: course: slot=secondary header=ok tlv=ok signature=none key=n/a
 *     E: Image in the secondary slot is not valid!
 *
 * Nothing in the MCUboot tree is modified. This file is a Zephyr module that
 * reaches the bootloader build through mcuboot_EXTRA_ZEPHYR_MODULES, using the
 * hook interface MCUboot publishes for exactly this purpose. Its Kconfig help
 * says that adding the source file is the downstream project's job.
 */

#include <string.h>

#include <zephyr/kernel.h>

#include "bootutil/bootutil.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/crypto/sha.h"
#include "mcuboot_config/mcuboot_config.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil/image.h"
#include "bootutil/sign_key.h"
#include "bootutil/boot_public_hooks.h"
#include "flash_map_backend/flash_map_backend.h"

/* Log through MCUboot's own module, so these lines arrive on the same console
 * and at the same level as the bootloader's, and a Learner reads one stream.
 */
BOOT_LOG_MODULE_DECLARE(mcuboot);

/* Erased NOR flash reads as all ones. A structure field that holds this was
 * never written, which is how a download that stopped early is told apart from
 * one that arrived complete and wrong.
 */
#define COURSE_ERASED_16 0xffff

/* MCUboot's SHA wrapper does not quite finish the job of hiding its backend.
 *
 * bootutil_sha_init() returns 0 for success on every backend. But
 * bootutil_sha_update() and bootutil_sha_finish() return the backend's own
 * value, and TinyCrypt reports success as 1 and failure as 0, which is the
 * opposite of the convention mbedTLS and PSA use. So the meaning of the return
 * value changes halfway through one API.
 *
 * The pinned course build uses MCUboot's bundled TinyCrypt, which issue #50
 * confirmed. Treating its 1 as an error is what made the key comparison
 * silently report nokey on the board the first time this ran.
 */
#if defined(MCUBOOT_USE_TINYCRYPT)
#define COURSE_SHA_OK(rc) ((rc) == 1)
#else
#define COURSE_SHA_OK(rc) ((rc) == 0)
#endif

/* What the image looked like. Each field is something read off the flash, not
 * something concluded about it.
 */
struct course_image_facts {
	const char *header;
	const char *tlv;
	const char *signature;
	const char *key;
};

/* Find the image header.
 *
 * Swap using offset puts a downloaded image one sector into the secondary
 * slot. MCUboot carries that offset in its swap state, which this hook is not
 * given, so look in both places and believe the magic.
 */
static int course_find_image(const struct flash_area *fap, uint32_t *image_off,
			     struct image_header *hdr)
{
	const uint32_t candidates[] = {
		0,
		CONFIG_COURSE_REFUSAL_REASON_SLOT_OFFSET,
	};

	for (size_t i = 0; i < ARRAY_SIZE(candidates); i++) {
		if (candidates[i] + sizeof(*hdr) > flash_area_get_size(fap)) {
			continue;
		}
		if (flash_area_read(fap, candidates[i], hdr, sizeof(*hdr)) != 0) {
			continue;
		}
		if (hdr->ih_magic == IMAGE_MAGIC) {
			*image_off = candidates[i];
			return 0;
		}
	}

	return -1;
}

/* SHA-256 of the public key this bootloader was built with.
 *
 * A signed image carries the same hash in its key hash TLV, which is how
 * MCUboot picks a key when more than one is compiled in. Comparing them is
 * cheap, and it is the whole difference between an image signed by the
 * Learner's key and one signed by an attacker key that is otherwise just as
 * valid.
 */
static int course_own_key_hash(uint8_t *out)
{
	bootutil_sha_context ctx;
	int rc = 0;

	if (bootutil_key_cnt < 1 || bootutil_keys[0].key == NULL) {
		return -1;
	}

	if (bootutil_sha_init(&ctx) != 0) {
		return -1;
	}
	if (!COURSE_SHA_OK(bootutil_sha_update(&ctx, bootutil_keys[0].key,
					       *bootutil_keys[0].len)) ||
	    !COURSE_SHA_OK(bootutil_sha_finish(&ctx, out))) {
		rc = -1;
	}
	bootutil_sha_drop(&ctx);

	return rc;
}

/* Walk the TLV area and record what is there.
 *
 * This deliberately does not verify anything. It does not hash the image and
 * it does not check a signature, because MCUboot is about to do both and doing
 * them twice would double the cost of every boot and put a second copy of the
 * decision in code the course wrote.
 */
static void course_read_tlvs(const struct flash_area *fap, uint32_t image_off,
			     const struct image_header *hdr,
			     struct course_image_facts *facts)
{
	struct image_tlv_info info;
	uint8_t own_hash[IMAGE_HASH_SIZE];
	uint32_t off = image_off + hdr->ih_hdr_size + hdr->ih_img_size;
	uint32_t area_size = flash_area_get_size(fap);
	uint32_t end;
	bool have_own_hash = course_own_key_hash(own_hash) == 0;

	if (off + sizeof(info) > area_size ||
	    flash_area_read(fap, off, &info, sizeof(info)) != 0) {
		facts->tlv = "none";
		return;
	}

	/* A protected TLV area comes first when one is present. Step over it to
	 * reach the unprotected area, which is where the signature lives.
	 */
	if (info.it_magic == IMAGE_TLV_PROT_INFO_MAGIC) {
		off += info.it_tlv_tot;
		if (off + sizeof(info) > area_size ||
		    flash_area_read(fap, off, &info, sizeof(info)) != 0) {
			facts->tlv = "none";
			return;
		}
	}

	if (info.it_magic != IMAGE_TLV_INFO_MAGIC) {
		/* Erased flash where the TLV area should start means the image
		 * stopped arriving. Without this, a download that was cut short
		 * before its signature looks exactly like an image that was
		 * never signed, and those are two different attacks.
		 */
		facts->tlv = info.it_magic == COURSE_ERASED_16 ? "truncated" : "none";
		return;
	}

	end = off + info.it_tlv_tot;
	if (end > area_size) {
		/* The area says it is longer than the slot it sits in. */
		facts->tlv = "short";
		return;
	}

	facts->tlv = "ok";
	facts->signature = "none";
	facts->key = "n/a";
	off += sizeof(info);

	while (off + sizeof(struct image_tlv) <= end) {
		struct image_tlv tlv;

		if (flash_area_read(fap, off, &tlv, sizeof(tlv)) != 0) {
			return;
		}
		if (tlv.it_type == COURSE_ERASED_16) {
			/* Erased flash inside a TLV area the header says is
			 * longer. The image was cut short partway through.
			 */
			facts->tlv = "truncated";
			return;
		}
		off += sizeof(tlv);

		if (off + tlv.it_len > end) {
			facts->tlv = "short";
			return;
		}

		switch (tlv.it_type) {
		case IMAGE_TLV_ECDSA_SIG:
			facts->signature = "present";
			break;
		case IMAGE_TLV_KEYHASH: {
			uint8_t seen[IMAGE_HASH_SIZE];

			if (!have_own_hash) {
				facts->key = "nokey";
				break;
			}
			if (tlv.it_len != sizeof(seen)) {
				facts->key = "badlen";
				break;
			}
			if (flash_area_read(fap, off, seen, sizeof(seen)) != 0) {
				facts->key = "readfail";
				break;
			}
			facts->key = memcmp(seen, own_hash, sizeof(seen)) == 0
					     ? "match"
					     : "other";
			break;
		}
		default:
			break;
		}

		off += tlv.it_len;
	}
}

static void course_report(int img_index, int slot)
{
	struct course_image_facts facts = {
		.header = "none",
		.tlv = "n/a",
		.signature = "n/a",
		.key = "n/a",
	};
	const struct flash_area *fap = NULL;
	struct image_header hdr;
	uint32_t image_off = 0;
	int fa_id = flash_area_id_from_multi_image_slot(img_index, slot);

	if (fa_id < 0 || flash_area_open(fa_id, &fap) != 0) {
		BOOT_LOG_INF("course: slot=%d unreadable", slot);
		return;
	}

	if (course_find_image(fap, &image_off, &hdr) == 0) {
		facts.header = "ok";
		course_read_tlvs(fap, image_off, &hdr, &facts);
	}

	flash_area_close(fap);

	BOOT_LOG_INF("course: slot=%s header=%s tlv=%s signature=%s key=%s",
		     slot == BOOT_SLOT_PRIMARY ? "primary" : "secondary",
		     facts.header, facts.tlv, facts.signature, facts.key);
}

/* The hook itself.
 *
 * Returning FIH_BOOT_HOOK_REGULAR is the whole contract. At the call site in
 * loader.c, a hook that returns anything else replaces MCUboot's validation
 * with its own answer. This one reports and steps aside, so course written
 * code never decides whether an image is allowed to run.
 */
fih_ret boot_image_check_hook(int img_index, int slot)
{
	course_report(img_index, slot);

	FIH_RET(FIH_BOOT_HOOK_REGULAR);
}

/* The rest of the hook interface.
 *
 * CONFIG_BOOT_IMAGE_ACCESS_HOOKS is one switch for the whole interface, not
 * one switch per hook. Turning it on to gain boot_image_check_hook() makes
 * MCUboot call every other hook in the set too, and the bootloader does not
 * link until all of them exist. That is worth knowing before turning the
 * option on in a real product: the cost of one hook is a stub for each of its
 * neighbours.
 *
 * Each of these returns BOOT_HOOK_REGULAR, which tells MCUboot to carry on
 * exactly as if no hook were there.
 */

int boot_read_image_header_hook(int img_index, int slot,
				struct image_header *img_head)
{
	ARG_UNUSED(img_index);
	ARG_UNUSED(slot);
	ARG_UNUSED(img_head);

	return BOOT_HOOK_REGULAR;
}

int boot_perform_update_hook(int img_index, struct image_header *img_head,
			     const struct flash_area *area)
{
	ARG_UNUSED(img_index);
	ARG_UNUSED(img_head);
	ARG_UNUSED(area);

	return BOOT_HOOK_REGULAR;
}

int boot_copy_region_post_hook(int img_index, const struct flash_area *area,
			       size_t size)
{
	ARG_UNUSED(img_index);
	ARG_UNUSED(area);
	ARG_UNUSED(size);

	return 0;
}

int boot_read_swap_state_primary_slot_hook(int image_index,
					   struct boot_swap_state *state)
{
	ARG_UNUSED(image_index);
	ARG_UNUSED(state);

	return BOOT_HOOK_REGULAR;
}
