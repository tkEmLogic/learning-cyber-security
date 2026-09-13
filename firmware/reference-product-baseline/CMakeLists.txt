# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

# The shared beacon and Wi-Fi code. Every tier pulls in the same module, so a
# fix there reaches every tier instead of needing nine copies.
list(APPEND EXTRA_ZEPHYR_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../common)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(reference_product_baseline)

test_sysbuild()

target_sources(app PRIVATE
	src/main.c
	src/ota_client.c
)
