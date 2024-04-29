# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020-2024 NXP

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

deps += 'bbdev'
allow_experimental_apis = true
sources = files(
	'main.c',
	'ipc.c',
	'cmd_line.c',
	'cmd_timer.c',
	'tti.c',
	'tti_lib.c'
)

cmd = run_command('sh', '-c', 'echo $LA9310_COMMON_HEADERS')
LA9310_COMMON_HEADERS = cmd.stdout().strip()

if LA9310_COMMON_HEADERS != ''
message('LA9310_COMMON_HEADERS=' + LA9310_COMMON_HEADERS)
includes += [include_directories(LA9310_COMMON_HEADERS)]
else
    build = false
    reason = 'missing LA9310_COMMON_HEADERS'
    subdir_done()
endif

rtdep = dependency('librt', required: false)
if not rtdep.found()
    rtdep = cc.find_library('rt', required: false)
endif
if not rtdep.found()
    build = false
    reason = 'missing dependency, "librt"'
    subdir_done()
endif

ext_deps += rtdep
