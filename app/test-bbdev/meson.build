# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

# Enable experimental API flag as pmd_la12xx APIs
allow_experimental_apis = true
sources = files(
        'main.c',
 #       'test_bbdev.c',
        'test_bbdev_perf.c',
        'test_bbdev_vector.c',
)
deps += ['bbdev', 'bus_vdev']
if dpdk_conf.has('RTE_BASEBAND_FPGA_LTE_FEC')
    deps += ['baseband_fpga_lte_fec']
endif
if dpdk_conf.has('RTE_BASEBAND_FPGA_5GNR_FEC')
    deps += ['baseband_fpga_5gnr_fec']
endif
if dpdk_conf.has('RTE_BASEBAND_ACC')
    deps += ['baseband_acc']
endif
if dpdk_conf.has('RTE_BASEBAND_LA12XX')
    deps += ['baseband_la12xx']
endif
cmd = run_command('sh', '-c', 'echo $COMMON_HEADERS_DIR')
COMMON_HEADERS_DIR = cmd.stdout().strip()
message('COMMON_HEADERS_DIR=' + COMMON_HEADERS_DIR)

includes += [include_directories(COMMON_HEADERS_DIR)]
includes += include_directories('../../drivers/baseband/la12xx/')
