# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023-2024 NXP

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

# Enable experimental API flag as pmd_la12xx APIs
allow_experimental_apis = true
sources = files(
        'main.c',
)
deps += ['bbdev', 'bus_vdev']
if dpdk_conf.has('RTE_BASEBAND_LA12XX')
    deps += ['baseband_la12xx']
endif
cmd = run_command('sh', '-c', 'echo $COMMON_HEADERS_DIR')
COMMON_HEADERS_DIR = cmd.stdout().strip()
message('COMMON_HEADERS_DIR=' + COMMON_HEADERS_DIR)

includes += [include_directories(COMMON_HEADERS_DIR)]
includes += include_directories('../../drivers/baseband/la12xx/')
