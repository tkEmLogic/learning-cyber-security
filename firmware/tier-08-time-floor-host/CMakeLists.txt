# SPDX-License-Identifier: Apache-2.0
#
# A host build of Tier 8's Time floor (#262), for native_sim.
#
# It compiles the Tier 8 firmware's own time_floor.c, release_policy.c and
# recovery_state.c, unchanged and from their own directory, so the host result
# is the firmware's code judging, not a copy of it. Only identity.c is
# replaced, by src/identity_host.c, because identity.c needs the ESP32-C6's
# Secure Storage and a claimed board. ./course service bypass e-8-11 builds and
# runs this; it is never flashed and it opens no socket.

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(tier_08_time_floor_host)

set(TIER08_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../tier-08-credential-lifecycle/src)

# The inputs are generated per run by ./course service bypass e-8-11: a
# throwaway release verification key, two manifests signed with its private
# half, and two synthetic Operational certificates. They arrive in the
# environment for the reason the Tier 8 build gives in its own CMakeLists.txt.
# Without them this build fails, rather than judging nothing.
if(NOT DEFINED ENV{COURSE_TIME_FLOOR_HOST_INPUTS})
	message(FATAL_ERROR "COURSE_TIME_FLOOR_HOST_INPUTS is not set; run ./course service bypass e-8-11, which generates the inputs")
endif()
zephyr_include_directories($ENV{COURSE_TIME_FLOOR_HOST_INPUTS})
zephyr_include_directories(${TIER08_SRC})

target_sources(app PRIVATE
	src/main.c
	src/identity_host.c
	${TIER08_SRC}/recovery_state.c
	${TIER08_SRC}/release_policy.c
	${TIER08_SRC}/time_floor.c
)
