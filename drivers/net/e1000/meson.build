# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation
# Copyright 2024 NXP

subdir('base')
objs = [base_objs]

if dpdk_conf.get('RTE_USE_NON_CACHE_MEM') == 1
	deps += ['common_dpaax']
endif

sources = files(
        'e1000_logs.c',
        'em_ethdev.c',
        'em_rxtx.c',
        'igb_ethdev.c',
        'igb_flow.c',
        'igb_pf.c',
        'igb_rxtx.c',
)

includes += include_directories('base')
