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

build = false

if cc.has_header('geul_cpe_ipc.h', include_directories: includes)
            build = true
else
	reason = 'geul_cpi_ipc.h not available'
	subdir_done()
endif

install_headers('rte_pmd_geul_ipc_rawdev.h')
