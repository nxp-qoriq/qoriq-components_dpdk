# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018, 2024 NXP

if is_windows
    subdir_done()
endif

drivers = [
        'cnxk_bphy',
        'cnxk_gpio',
        'dpaa2_cmdif',
        'ifpga',
        'ntb',
        'skeleton',
]
cmd = run_command('sh', '-c', 'echo $COMMON_HEADERS_DIR')
COMMON_HEADERS_DIR = cmd.stdout().strip()
if COMMON_HEADERS_DIR != ''
  drivers += 'geul_ipc'
endif

std_deps = ['rawdev']
