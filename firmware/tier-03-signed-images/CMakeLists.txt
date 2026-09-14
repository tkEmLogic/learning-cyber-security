# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

list(APPEND EXTRA_ZEPHYR_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../common)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(tier_03_signed_images)

test_sysbuild()

# The trust anchor is compiled into the image, the same way the Wi-Fi
# credentials are. ./course build firmware writes course_ca_der.inc from the
# Course certificate authority in .course-secrets/, and passes the directory
# here.
#
# Without it the build falls back to anchor/, which holds an empty anchor. The
# repository then still builds standalone, and the resulting image refuses to
# connect and says why. An image that trusts nothing is the right failure: the
# alternative is an image that trusts anything.
# The directory arrives in the environment rather than as a CMake cache
# variable. Sysbuild keeps an image-scoped -D<image>_VAR in its own cache and
# does not forward an arbitrary one into the image build, so a cache variable
# silently produced an image with no anchor. The environment reaches every
# image's configure step.
if(DEFINED ENV{COURSE_CA_INC_DIR})
	zephyr_include_directories($ENV{COURSE_CA_INC_DIR})
else()
	zephyr_include_directories(anchor)
endif()

target_sources(app PRIVATE
	src/main.c
	src/ota_client.c
)
