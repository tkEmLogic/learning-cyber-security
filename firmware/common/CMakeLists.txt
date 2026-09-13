# SPDX-License-Identifier: Apache-2.0

# Code that is the same in every Hardening tier.
#
# The status beacon and the Wi-Fi link do not change when a security control is
# added, so they live here once instead of being copied into each tier's
# application. Everything a tier actually changes, meaning main.c and the OTA
# client, stays in that tier's own directory, where a Learner can read it whole
# and diff it against the tier before.

zephyr_library_named(course_common)

zephyr_library_sources(
	src/beacon.c
	src/net_link.c
)

zephyr_include_directories(include)
