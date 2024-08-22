# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020-2024 NXP

deps += ['bbdev', 'bus_vdev', 'ring']
allow_experimental_apis = true

sources = files('bbdev_la12xx.c', 'bbdev_la12xx_feca_param.c', 'bbdev_la12xx_wdog.c')

cflags += ['-DHOST=1',
           '-DMODEM=0']

cmd = run_command('sh', '-c', 'echo $COMMON_HEADERS_DIR')
COMMON_HEADERS_DIR = cmd.stdout().strip()
message('COMMON_HEADERS_DIR=' + COMMON_HEADERS_DIR)
includes += [include_directories(COMMON_HEADERS_DIR)]

headers = files('rte_pmd_bbdev_la12xx.h')
