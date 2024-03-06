/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2024 NXP
 */

#ifndef _DPAA_QDMA_H_
#define _DPAA_QDMA_H_

#include <rte_io.h>

#ifndef BIT
#define BIT(nr)		(1UL << (nr))
#endif

#define RETRIES	5

#ifndef GENMASK
#define BITS_PER_LONG	(__SIZEOF_LONG__ * 8)
#define GENMASK(h, l) \
		(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#endif

#define QDMA_CTRL_REGION_OFFSET 0
#define QDMA_CTRL_REGION_SIZE 0x10000
#define QDMA_STATUS_REGION_OFFSET \
	(QDMA_CTRL_REGION_OFFSET + QDMA_CTRL_REGION_SIZE)
#define QDMA_STATUS_REGION_SIZE 0x10000

#define FSL_QDMA_DMR			0x0
#define FSL_QDMA_DSR			0x4
#define FSL_QDMA_DEDR			0xe04
#define FSL_QDMA_DECFDW0R		0xe10
#define FSL_QDMA_DECFDW1R		0xe14
#define FSL_QDMA_DECFDW2R		0xe18
#define FSL_QDMA_DECFDW3R		0xe1c
#define FSL_QDMA_DECFQIDR		0xe30
#define FSL_QDMA_DECBR			0xe34

#define FSL_QDMA_BCQMR(x)		(0xc0 + 0x100 * (x))
#define FSL_QDMA_BCQSR(x)		(0xc4 + 0x100 * (x))
#define FSL_QDMA_BCQEDPA_SADDR(x)	(0xc8 + 0x100 * (x))
#define FSL_QDMA_BCQDPA_SADDR(x)	(0xcc + 0x100 * (x))
#define FSL_QDMA_BCQEEPA_SADDR(x)	(0xd0 + 0x100 * (x))
#define FSL_QDMA_BCQEPA_SADDR(x)	(0xd4 + 0x100 * (x))
#define FSL_QDMA_BCQIER(x)		(0xe0 + 0x100 * (x))
#define FSL_QDMA_BCQIDR(x)		(0xe4 + 0x100 * (x))

#define FSL_QDMA_SQEDPAR		0x808
#define FSL_QDMA_SQDPAR			0x80c
#define FSL_QDMA_SQEEPAR		0x810
#define FSL_QDMA_SQEPAR			0x814
#define FSL_QDMA_BSQMR			0x800
#define FSL_QDMA_BSQSR			0x804
#define FSL_QDMA_BSQICR			0x828
#define FSL_QDMA_CQIER			0xa10
#define FSL_QDMA_SQCCMR			0xa20

#define FSL_QDMA_SQCCMR_ENTER_WM	0x200000

#define FSL_QDMA_QUEUE_MAX		8

#define FSL_QDMA_BCQMR_EN		0x80000000
#define FSL_QDMA_BCQMR_EI		0x40000000

#define FSL_QDMA_BCQMR_CD_THLD(x)	((x) << 20)
#define FSL_QDMA_BCQMR_CQ_SIZE(x)	((x) << 16)

/* Update the value appropriately whenever QDMA_QUEUE_SIZE
 * changes.
 */

#define FSL_QDMA_BCQSR_QF_XOFF_BE	0x1000100

#define FSL_QDMA_BSQMR_EN		0x80000000
#define FSL_QDMA_BSQMR_CQ_SIZE(x)	((x) << 16)
#define FSL_QDMA_BSQMR_DI		0xc0

#define FSL_QDMA_BSQSR_QE_BE		0x200

#define FSL_QDMA_DMR_DQD		0x40000000
#define FSL_QDMA_DSR_DB			0x80000000

#define FSL_QDMA_CIRCULAR_DESC_SIZE_MIN	64
#define FSL_QDMA_CIRCULAR_DESC_SIZE_MAX	16384
#define FSL_QDMA_QUEUE_NUM_MAX		8

#define FSL_QDMA_CMD_RWTTYPE		0x4
#define FSL_QDMA_CMD_LWC		0x2

#define FSL_QDMA_CMD_RWTTYPE_OFFSET	28
#define FSL_QDMA_CMD_LWC_OFFSET		16
#define FSL_QDMA_CMD_PF			BIT(17)

#define FSL_QDMA_CMD_SSEN		BIT(19)
#define FSL_QDMA_CFG_SSS_OFFSET		12
#define FSL_QDMA_CMD_SSS_STRIDE		128
#define FSL_QDMA_CMD_SSS_DISTANCE	128

#define QDMA_CCDF_STATUS		20
#define QDMA_CCDF_OFFSET		20
#define QDMA_CCDF_MASK			GENMASK(28, 20)
#define QDMA_CCDF_FOTMAT		BIT(29)
#define QDMA_CCDF_SER			BIT(30)

#define QDMA_SG_FIN			BIT(30)
#define QDMA_SG_LEN_MASK		GENMASK(29, 0)

#define COMMAND_QUEUE_OVERFLOW		10

/* qdma engine attribute */
#define QDMA_QUEUE_SIZE			64
#define QDMA_STATUS_SIZE		QDMA_QUEUE_SIZE
#define QDMA_CCSR_BASE			0x8380000
#define QDMA_BLOCK_OFFSET		0x10000
#define QDMA_BLOCKS			4
#define QDMA_QUEUES			8
#define QDMA_QUEUE_CR_WM		32

#define QDMA_BIG_ENDIAN			1
#ifdef QDMA_BIG_ENDIAN
#define QDMA_IN(addr)		be32_to_cpu(rte_read32(addr))
#define QDMA_OUT(addr, val)	rte_write32(be32_to_cpu(val), addr)
#define QDMA_IN_BE(addr)	rte_read32(addr)
#define QDMA_OUT_BE(addr, val)	rte_write32(val, addr)
#else
#define QDMA_IN(addr)		rte_read32(addr)
#define QDMA_OUT(addr, val)	rte_write32(val, addr)
#define QDMA_IN_BE(addr)	be32_to_cpu(rte_write32(addr))
#define QDMA_OUT_BE(addr, val)	rte_write32(be32_to_cpu(val), addr)
#endif

#define FSL_QDMA_BLOCK_BASE_OFFSET(fsl_qdma_engine, x)			\
	(((fsl_qdma_engine)->block_offset) * (x))

/* qDMA Command Descriptor Formats */
struct fsl_qdma_format {
	uint32_t status; /* ser, status */
	uint32_t cfg;	/* format, offset */
	union {
		struct {
			uint32_t addr_lo; /* low 32-bits of 40-bit address */
			uint8_t addr_hi; /* high 8-bits of 40-bit address */
			uint8_t __reserved1[2];
			uint8_t cfg8b_w1; /* dd, queue */
		};
		uint64_t data;
	};
};

/* qDMA Source Descriptor Format */
struct fsl_qdma_sdf {
	uint32_t rev3;
	uint32_t cfg; /* rev4, bit[0-11] - ssd, bit[12-23] sss */
	uint32_t rev5;
	uint32_t cmd;
};

/* qDMA Destination Descriptor Format */
struct fsl_qdma_ddf {
	uint32_t rev1;
	uint32_t cfg; /* rev2, bit[0-11] - dsd, bit[12-23] - dss */
	uint32_t rev3;
	uint32_t cmd;
};

struct fsl_qdma_df {
	struct fsl_qdma_sdf sdf;
	struct fsl_qdma_ddf ddf;
};

struct fsl_qdma_cmpd_ft {
	struct fsl_qdma_format desc_buf;
	struct fsl_qdma_format desc_sbuf;
	struct fsl_qdma_format desc_dbuf;
};

struct fsl_qdma_queue {
	struct fsl_qdma_format *cmd_desc;
	int used;
	struct fsl_qdma_cmpd_ft **ft;
	uint16_t ci;
	uint16_t complete;
	uint16_t n_cq;
	uint8_t block_id;
	uint8_t queue_id;
	void *block_vir;
	uint32_t le_cqmr;
	struct fsl_qdma_format *cq;
	struct rte_dma_stats stats;
	uint8_t pending;
	dma_addr_t bus_addr;
	struct fsl_qdma_df **df;
};

struct fsl_qdma_engine {
	void *reg_base;
	void *ctrl_base;
	void *status_base;
	void *block_base;
	uint32_t n_queues;
	struct fsl_qdma_queue **queue;
	struct fsl_qdma_queue **status;
	uint32_t num_blocks;
	int block_offset;
};

#endif /* _DPAA_QDMA_H_ */
