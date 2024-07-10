# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation
# Copyright 2022-2024 NXP
#
# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

#allow_experimental_apis = true
if dpdk_conf.has('RTE_NET_DPAA2')
        deps += ['net_dpaa2']
endif
deps += ['pdump']
sources = files(
	'main.c',
)

includes += include_directories('../../lib/pdump')
includes += include_directories('../../lib/bpf')
includes += include_directories('../../drivers/net/dpaa2/')
