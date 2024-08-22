# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021-2024 NXP
#

deps += ['bbdev', 'bus_vdev', 'ring']
allow_experimental_apis = true

sources = files('bbdev_la93xx.c', 'bbdev_la93xx_wdog.c')

cmd = run_command('sh', '-c', 'echo $LA9310_COMMON_HEADERS')
LA9310_COMMON_HEADERS = cmd.stdout().strip()
message('LA9310_COMMON_HEADERS=' + LA9310_COMMON_HEADERS)
includes += [include_directories(LA9310_COMMON_HEADERS)]

headers = files('rte_pmd_bbdev_la93xx.h')
