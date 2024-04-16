/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_lsx_pciep_bus.h>

#include "lsxinic_ep_dma.h"
#include "lsxinic_common_logs.h"

static int s_lsinic_dma_idx;

static rte_spinlock_t s_lsinic_dma_sl = RTE_SPINLOCK_INITIALIZER;

int
lsinic_dma_acquire(int silent,
	uint16_t nb_vchans, uint16_t nb_desc,
	enum lsinic_dma_direction dir,
	int *dma_id_acquired)
{
	struct rte_dma_info dev_info;
	struct rte_dma_conf dev_conf;
	int ret, dma_idx;

	rte_spinlock_lock(&s_lsinic_dma_sl);

acquire_again:
	dma_idx = rte_dma_next_dev(s_lsinic_dma_idx);
	if (dma_idx < 0) {
		LSXINIC_PMD_ERR("No DMA available from DMA%d",
			s_lsinic_dma_idx);
		rte_spinlock_unlock(&s_lsinic_dma_sl);
		return -EINVAL;
	}
	s_lsinic_dma_idx = dma_idx + 1;

	ret = rte_dma_info_get(dma_idx, &dev_info);
	if (ret) {
		rte_spinlock_unlock(&s_lsinic_dma_sl);
		return ret;
	}

	if (dev_info.nb_vchans) {
		LSXINIC_PMD_INFO("DMA%d may be configured in another process",
			dma_idx);
		goto acquire_again;
	}

	if (nb_vchans > dev_info.max_vchans) {
		LSXINIC_PMD_ERR("acquire chan(%d) > dma[%d] max chan(%d)",
			nb_vchans, dma_idx, dev_info.max_vchans);
		rte_spinlock_unlock(&s_lsinic_dma_sl);
		return -ENOTSUP;
	}

	if (nb_desc > dev_info.max_desc) {
		LSXINIC_PMD_ERR("acquire desc(%d) > dma[%d] max desc(%d)",
			nb_desc, dma_idx, dev_info.max_desc);
		rte_spinlock_unlock(&s_lsinic_dma_sl);
		return -ENOTSUP;
	}

	if (silent && !(dev_info.dev_capa & RTE_DMA_CAPA_SILENT)) {
		LSXINIC_PMD_ERR("dma[%d] not support silent mode",
			dma_idx);
		rte_spinlock_unlock(&s_lsinic_dma_sl);
		return -ENOTSUP;
	}

	if (dir == LSINIC_DMA_MEM_TO_PCIE &&
		!(dev_info.dev_capa & RTE_DMA_CAPA_MEM_TO_DEV)) {
		LSXINIC_PMD_ERR("dma[%d] not support mem2dev",
			dma_idx);
		rte_spinlock_unlock(&s_lsinic_dma_sl);
		return -ENOTSUP;
	}

	if (dir == LSINIC_DMA_PCIE_TO_MEM &&
		!(dev_info.dev_capa & RTE_DMA_CAPA_DEV_TO_MEM)) {
		LSXINIC_PMD_ERR("dma[%d] not support dev2mem",
			dma_idx);
		rte_spinlock_unlock(&s_lsinic_dma_sl);
		return -ENOTSUP;
	}

	if (dir == LSINIC_DMA_MEM_TO_MEM &&
		!(dev_info.dev_capa & RTE_DMA_CAPA_MEM_TO_MEM)) {
		LSXINIC_PMD_ERR("dma[%d] not support mem2mem",
			dma_idx);
		rte_spinlock_unlock(&s_lsinic_dma_sl);
		return -ENOTSUP;
	}

	if (dir == LSINIC_DMA_PCIE_TO_PCIE &&
		!(dev_info.dev_capa & RTE_DMA_CAPA_DEV_TO_DEV)) {
		LSXINIC_PMD_ERR("dma[%d] not support dev2dev",
			dma_idx);
		rte_spinlock_unlock(&s_lsinic_dma_sl);
		return -ENOTSUP;
	}

	dev_conf.nb_vchans = nb_vchans;
	dev_conf.enable_silent = silent;
	ret = rte_dma_configure(dma_idx, &dev_conf);
	if (ret) {
		LSXINIC_PMD_ERR("dma[%d] configure failed(%d)",
			dma_idx, ret);
		rte_spinlock_unlock(&s_lsinic_dma_sl);
		return ret;
	}

	if (dma_id_acquired)
		*dma_id_acquired = dma_idx;

	rte_spinlock_unlock(&s_lsinic_dma_sl);

	return 0;
}

int
lsinic_dma_release(int dma_idx)
{
	int ret;

	ret = rte_dma_stop(dma_idx);
	if (ret)
		return ret;
	ret = rte_dma_close(dma_idx);
	if (ret)
		return ret;

	return 0;
}
