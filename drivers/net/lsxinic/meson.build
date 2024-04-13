# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022-2024 NXP

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

deps += ['bus_lsx_pciep', 'dmadev', 'dma_dpaa2', 'net_dpaa2']
sources = files(
	'lsxinic_common_helper.c',
	'lsxinic_ep_ethdev.c',
	'lsxinic_ep_rxtx.c',
	'lsxinic_ep_dma.c',
	'lsxinic_ep_ethtool.c',
	'lsxinic_rc_ethdev.c',
	'lsxinic_rc_rxtx.c',
	'lsxinic_rc_pf.c',
	'lsxinic_ep_vio_blk.c',
	'lsxinic_ep_vio.c',
	'lsxinic_ep_vio_net.c',
	'lsxinic_ep_vio_rxtx.c',
	'lsxinic_rc_vio.c',
	'lsxinic_rc_pci.c'
)

includes += include_directories(
	'../../bus/fslmc',
	'../../bus/fslmc/mc',
	'../../bus/fslmc/portal',
	'../../bus/fslmc/qbman/include',
	'../../mempool/dpaa2',
	'../dpaa2/mc',
	'../virtio'
)

headers = files('rte_pmd_lsxinic.h')
