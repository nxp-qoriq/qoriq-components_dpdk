/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

#ifndef _LSXINIC_EP_DMA_H_
#define _LSXINIC_EP_DMA_H_

#include <rte_dmadev.h>
#include <rte_pmd_dpaax_qdma.h>

struct lsinic_dma_job {
	rte_iova_t src;
	rte_iova_t dst;
	uint32_t len;
	uint32_t idx;
	uint64_t cnxt;
};

struct lsinic_dma_seg_job {
	rte_iova_t src[RTE_DPAAX_QDMA_JOB_SUBMIT_MAX];
	rte_iova_t dst[RTE_DPAAX_QDMA_JOB_SUBMIT_MAX];
	uint32_t len[RTE_DPAAX_QDMA_JOB_SUBMIT_MAX];
	uint32_t seg_nb;
	uint64_t cnxt;
};

enum lsinic_dma_direction {
	LSINIC_DMA_MEM_TO_PCIE,
	LSINIC_DMA_PCIE_TO_MEM,
	LSINIC_DMA_MEM_TO_MEM,
	LSINIC_DMA_PCIE_TO_PCIE
};

#define LSINIC_QDMA_EQ_MAX_NB RTE_DPAAX_QDMA_JOB_SUBMIT_MAX
#define LSINIC_QDMA_DQ_MAX_NB 64
#define LSINIC_QDMA_EQ_DATA_MAX_NB \
	(RTE_DPAAX_QDMA_JOB_SUBMIT_MAX - 8)

#define LSINIC_DMA_BURST_ASSERT(nb) \
	do { \
		if (unlikely((nb) > LSINIC_QDMA_EQ_MAX_NB)) { \
			rte_panic("%s: lsinic eq(%d) > max(%d)\n", \
				__func__, nb, LSINIC_QDMA_EQ_MAX_NB); \
		} \
	} while (0)

int
lsinic_dma_acquire(int silent,
	uint16_t nb_vchans, uint16_t nb_desc,
	enum lsinic_dma_direction dir,
	int *dma_id_acquired);
int
lsinic_dma_release(int dma_idx);

#endif /* _LSXINIC_EP_DMA_H_ */
