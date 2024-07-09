# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020-2024 NXP

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

deps += ['dmadev']
if dpdk_conf.has('RTE_NET_DPAA2')
        deps += ['net_dpaa2']
endif
#if dpdk_conf.has('RTE_NET_LSXINIC')
        deps += ['net_lsxinic']
#endif
allow_experimental_apis = true
sources = files(
	'main.c'
)

cflags += ['-DALLOW_INTERNAL_API']

includes += include_directories('../../drivers/common/dpaax/')
includes += include_directories('../../drivers/net/lsxinic/')
includes += include_directories('../../drivers/bus/fslmc/')
includes += include_directories('../../drivers/bus/pci/')
includes += include_directories('../../lib/pci/')
