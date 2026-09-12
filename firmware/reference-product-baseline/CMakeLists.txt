# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(reference_product_baseline)

test_sysbuild()

target_sources(app PRIVATE
	src/main.c
	src/beacon.c
	src/net_link.c
	src/ota_client.c
)
