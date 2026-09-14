# SPDX-License-Identifier: Apache-2.0

# This module is built into MCUboot, not into the application.
#
# It reaches the bootloader image through mcuboot_EXTRA_ZEPHYR_MODULES, which
# the tier's sysbuild.cmake sets. Nothing in the MCUboot tree is modified.

if(CONFIG_COURSE_REFUSAL_REASON)
	zephyr_library()
	zephyr_library_sources(src/course_refusal_reason.c)
	zephyr_library_link_libraries(MCUBOOT_BOOTUTIL)
endif()
