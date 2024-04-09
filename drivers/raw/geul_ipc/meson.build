# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2024 NXP

deps += ['rawdev', 'mempool', 'bus_vdev']
allow_experimental_apis = true

sources = files('geul_ipc_api.c', 'geul_ipc_dev.c')

cflags += ['-DHOST=1',
           '-DMODEM=0']

cmd = run_command('sh', '-c', 'echo $COMMON_HEADERS_DIR')
COMMON_HEADERS_DIR = cmd.stdout().strip()
message('COMMON_HEADERS_DIR=' + COMMON_HEADERS_DIR)
includes += [include_directories(COMMON_HEADERS_DIR)]

install_headers('rte_pmd_geul_ipc_rawdev.h')
