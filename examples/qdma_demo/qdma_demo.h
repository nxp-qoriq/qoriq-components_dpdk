/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2024 NXP
 */
#ifndef __QDMA_DEMO_H__
#define __QDMA_DEMO_H__

#define PAGE_SIZE	(sysconf(_SC_PAGESIZE))
#define PAGE_MASK	(~(PAGE_SIZE - 1))

#define PCI_TO_PCI 1
#define MEM_TO_PCI 2
#define PCI_TO_MEM 3
#define MEM_TO_MEM 4

#define BURST_NB_MAX 256

struct qdma_test_case {
	const char *name;
	const char *help;
	int id;
};

struct qdma_test_mode {
	const char *name;
	int id;
};

struct dma_job {
	/** Source Address from where DMA is (to be) performed */
	uint64_t src;
	uint8_t *vdmasrc;
	uint8_t *vcpusrc;
	/** Destination Address where DMA is (to be) done */
	uint64_t dest;
	uint8_t *vdmadst;
	uint8_t *vcpudst;
	/** Length of the DMA operation in bytes. */
	uint32_t dma_len;
	uint32_t cpu_len;
	uint32_t idx;
	/** Flags corresponding to an DMA operation */
	uint32_t flags;
};

#define TEST_ARG_NAME_SIZE 30
#define ARG_PCI_ADDR (1 << 0)
#define ARG_SIZE (1 << 1)
#define ARG_TEST_ID (1 << 2)
#define ARG_LATENCY (1 << 3)
#define ARG_TEST_MODE (1 << 4)
#define ARG_SCATTER_GATHER (1 << 5)
#define ARG_BURST (1 << 6)
#define ARG_NUM (1 << 7)
#define ARG_VALIDATE (1 << 8)
#define ARG_SEG_IOVA (1 << 9)
#define ARG_PCI_SIZE (1 << 10)
#define ARG_PCI_EP (1 << 11)
#define ARG_PCI_EP_RBP (1 << 12)
#define ARG_SILENT (1 << 13)
#define ARG_DMA_LATENCY (1 << 14)
#define ARG_CPU_SIZE (1 << 15)

#endif
