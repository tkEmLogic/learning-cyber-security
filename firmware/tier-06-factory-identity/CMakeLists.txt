# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

list(APPEND EXTRA_ZEPHYR_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../common)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(tier_06_factory_identity)

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

# The release manifest verification key arrives the same way, from
# ./course build firmware, which writes release_pubkey.inc from the public half
# of the Learner's Release signing key. It has its own variable because it is
# its own decision: the certificate authority says which service to talk to,
# and this key says whose release metadata to believe. Nothing about one
# implies the other.
#
# Without it the build falls back to anchor/, which holds no key, and the
# resulting image verifies no manifest and says so at boot and at every
# refusal. That is the same honest failure the empty trust anchor produces.
if(DEFINED ENV{COURSE_RELEASE_KEY_INC_DIR})
	zephyr_include_directories($ENV{COURSE_RELEASE_KEY_INC_DIR})
else()
	zephyr_include_directories(anchor)
endif()

# The fleet identity, compiled into the shared image only.
#
# ./course build firmware --tier 06 --variant shared writes these and sets the
# variable. It is the one build in the course that is handed a private key, and
# the variable is set for that one variant, so the factory build does not have
# the key on its include path at all. See the Tier 6 section of
# docs/fixture-safety-contract.md for the bound on that exception.
#
# Without it the build falls back to anchor/, which is empty, and the shared
# image can prove possession of nothing and says so. That is the same honest
# failure the empty trust anchor produces.
if(DEFINED ENV{COURSE_SHARED_IDENTITY_INC_DIR})
	zephyr_include_directories($ENV{COURSE_SHARED_IDENTITY_INC_DIR})
else()
	zephyr_include_directories(anchor)
endif()

target_sources(app PRIVATE
	src/health_gate.c
	src/identity.c
	src/main.c
	src/ota_client.c
	src/recovery_state.c
	src/release_policy.c
)

target_sources_ifdef(CONFIG_COURSE_PROVISIONING_SHELL app PRIVATE
	src/provisioning_shell.c
)

target_sources_ifdef(CONFIG_COURSE_SHARED_SHELL app PRIVATE
	src/shared_shell.c
)
