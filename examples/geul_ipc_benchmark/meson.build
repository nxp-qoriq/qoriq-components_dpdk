# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019-2024 NXP

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

if dpdk_conf.has('RTE_RAW_GEUL_IPC')
	deps += ['rawdev', 'raw_geul_ipc', 'timer']
else
    build = false
endif

allow_experimental_apis = true
sources = files(
	'main.c'
)
cflags += ['-DHOST=1',
           '-DMODEM=0']

cmd = run_command('sh', '-c', 'echo $COMMON_HEADERS_DIR')
COMMON_HEADERS_DIR = cmd.stdout().strip()
message('COMMON_HEADERS_DIR=' + COMMON_HEADERS_DIR)
includes += [include_directories(COMMON_HEADERS_DIR)]

includes += include_directories('../../drivers/raw/geul_ipc/')
