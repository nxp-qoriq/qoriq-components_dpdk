/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023-2024 NXP
 */
#ifndef __ENETQOS_HW_
#define __ENETQOS_HW_

#ifndef LINUX_MACROS
#ifndef BITS_PER_LONG
#define BITS_PER_LONG	(__SIZEOF_LONG__ * 8)
#endif

#ifndef BITS_PER_LONG_LONG
#define BITS_PER_LONG_LONG  (__SIZEOF_LONG_LONG__ * 8)
#endif

#ifndef BITy
#define BIT(a) (1UL << (a))
#endif /* BIT */

#ifndef BIT_ULL
#define BIT_ULL(a) (1ULL << (a))
#endif /* BIT_ULL */

#ifndef GENMASK
#define GENMASK(h, l)	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#endif /* GENMASK */

#ifndef GENMASK_ULL
#define GENMASK_ULL(h, l) \
	(((~0ULL) << (l)) & (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))
#endif /* GENMASK_ULL */
#endif /* LINUX_MACROS */

/* From chapter 11.7.6.1.1 ENET_QOS memory map */

#define MAX_LINE_SIZE		38
#define ENETQ_CCSR_SIZE		0x10000

/* Register offset to ENETQ_BASE_ADDR */

/* MAC Configuration Register (ENETQ_MAC_CONFIG) */
#define ENETQ_MAC_CONFIG	0x0 /* MAC Configuration Register */

/* MAC Configuration Register (ENETQ_MAC_CONFIG) */
#define ENETQ_MAC_CONFIG_IPC		BIT(27) /* Checksum Offload */
#define ENETQ_MAC_CONFIG_CST		BIT(21) /* CRC stripping */
#define ENETQ_MAC_CONFIG_BE		BIT(18) /* Packet Burst Enable */
#define ENETQ_MAC_CONFIG_JD		BIT(17) /* Jabber Disable */
#define ENETQ_MAC_CONFIG_JE		BIT(16) /* Jumbo Packet Enable */
#define ENETQ_MAC_CONFIG_PS		BIT(15) /* Port Select */
#define ENETQ_MAC_CONFIG_DM		BIT(13) /* Duplex Mode */
#define ENETQ_MAC_CONFIG_DCRS		BIT(9) /* Disable Carrier Sense During Transmission */
#define ENETQ_MAC_CONFIG_TE		BIT(1) /* Transmitter Enable */
#define ENETQ_MAC_CONFIG_RE		BIT(0) /* Receiver Enable */


#define ENETQ_MAC_PKT_FILTER		0x8 /* MAC Packet Filter Register */
#define ENETQ_MAC_PKT_FILTER_PR	BIT(0) /* MAC Packet Filter Promiscuous Mode */

/* Receive Queue Control register (ENETQ_MAC_RXQ_CTRL(x)) */
#define ENETQ_MAC_RXQ_CTRL(id)		(0xa0 + id * 4) /* Receive Queue Control */

#define ENETQ_MAC_RX_QUEUE_CLEAR(q)	~(GENMASK(1, 0) << ((q) * 2)) /* Receive Queue enable */
#define ENETQ_MAC_RX_AV_QUEUE_ENABLE(q)	BIT((q) * 2) /* Queue enablement for AV */
#define ENETQ_MAC_RX_DCB_QUEUE_ENABLE(q)	BIT(((q) * 2) + 1) /* Queue enablement for DCB */


/* MAC HW ADDR register (ENETQ_MAC_ADDR_HIGH) */

#define ENETQ_MAC_ADDR_HIGH(reg_val)	(0x300 + reg_val * 8) /* MAC Address High */
#define ENETQ_MAC_ADDR_LOW(reg_val)	(0x304 + reg_val * 8) /* MAC Address Low */

#define ENETQ_MAC_HI_DCS		GENMASK(18, 16) /* DMA Channel Select */
#define ENETQ_MAC_HI_DCS_SHIFT		16
#define ENETQ_MAC_HI_REG_AE		BIT(31) /* Address Enable */

/*  MTL registers */
#define ENETQ_MTL_OPERATION_MODE	0xc00 /* MTL Operation Mode */
#define ENETQ_MTL_RXQ_DMA_MAP0	0xc30 /* Receive Queue & DMA Channel Mapping For Queue 0 to 3 */
#define ENETQ_MTL_RXQ_DMA_MAP1	0xc34 /* Receive Queue & DMA Channel Mapping For Queue 4 to 7 */

/* This field controls the routing of the packet received in Queue 0 to the DMA channel */
#define ENETQ_MTL_RXQ_DMA_Q0MDMACH_MASK		GENMASK(3, 0)
#define ENETQ_MTL_RXQ_DMA_Q0MDMACH(x)		((x) << 0)
/* This field controls the routing of the packet received in Queue x to the DMA channel */
#define ENETQ_MTL_RXQ_DMA_QXMDMACH_MASK(x)	GENMASK(11 + (8 * ((x) - 1)), 8 * (x))
#define ENETQ_MTL_RXQ_DMA_QXMDMACH(chan, q)	((chan) << (8 * (q)))

#define ENETQ_MTL_TXQ_CH_BASE_ADDR	0xd00 /* Queue 0 Transmit Operation Mode */
#define ENETQ_MTL_CH_OFFSET		0x40
#define ENETQ_MTL_CHX_BASE_ADDR(x)	(ENETQ_MTL_TXQ_CH_BASE_ADDR + \
						(x * ENETQ_MTL_CH_OFFSET))
#define ENETQ_MTL_CH_TX_OP_MODE(x)	ENETQ_MTL_CHX_BASE_ADDR(x) /* Queue x Transmit Operation Mode */
#define ENETQ_MTL_CH_RX_OP_MODE(x)	(ENETQ_MTL_CHX_BASE_ADDR(x) + 0x30) /* Queue x Receive Operation Mode */

/* Queue Transmit Operation Mode (ENETQ_MTL_CH_TX_OP_MODE) */
#define ENETQ_MTL_OP_MODE_TQS_MASK	GENMASK(24, 16) /* Transmit Queue Size */
#define ENETQ_MTL_OP_MODE_TQS_SHIFT	16
#define ENETQ_MTL_OP_MODE_TXQEN_MASK	GENMASK(3, 2)
#define ENETQ_MTL_OP_MODE_TXQEN_AV	BIT(2) /* Transmit Queue Enable AV */
#define ENETQ_MTL_OP_MODE_TXQEN	BIT(3) /* Transmit Queue Enable */
#define ENETQ_MTL_OP_MODE_TSF	BIT(1) /* Transmit Store and Forward */

/* Queue Receive Operation Mode (ENETQ_MTL_CH_RX_OP_MODE) */
#define ENETQ_MTL_OP_MODE_RQS_MASK	GENMASK(29, 20) /* Receive Queue Size */
#define ENETQ_MTL_OP_MODE_RQS_SHIFT	20
#define ENETQ_MTL_OP_MODE_RFD_MASK	GENMASK(19, 14) /* Threshold for Deactivating Flow Control */
#define ENETQ_MTL_OP_MODE_RFD_SHIFT	14
#define ENETQ_MTL_OP_MODE_RFA_MASK	GENMASK(13, 8) /* Threshold for Activating Flow Control */
#define ENETQ_MTL_OP_MODE_RFA_SHIFT	8
#define ENETQ_MTL_OP_MODE_EHFC	BIT(7) /* Enable Hardware Flow Control */
#define ENETQ_MTL_OP_MODE_RSF		BIT(5) /* Receive Queue Store and Forward */

/* MTL algorithms identifiers */
#define ENETQ_MTL_TX_ALGO_WRR		0x0
#define ENETQ_MTL_TX_ALGO_WFQ		0x1
#define ENETQ_MTL_TX_ALGO_DWRR		0x2
#define ENETQ_MTL_TX_ALGO_SP		0x3

#define ENETQ_MTL_OP_SCHALG_MASK	GENMASK(6, 5)
#define ENETQ_MTL_OP_SCHALG_WRR		(0x0 << 5)
#define ENETQ_MTL_OP_SCHALG_WFQ		(0x1 << 5)
#define ENETQ_MTL_OP_SCHALG_DWRR	(0x2 << 5)
#define ENETQ_MTL_OP_SCHALG_SP		(0x3 << 5)

/* MTL Queue Weight Regs */
#define ENETQ_MTL_TXQW_BASE_ADDR	0x00000d18
#define ENETQ_MTL_TXQW_BASE_OFFSET	0x40
#define ENETQ_MTL_TXQXW_BASE_ADDR(x)	(ENETQ_MTL_TXQW_BASE_ADDR + \
						((x) * ENETQ_MTL_TXQW_BASE_OFFSET))
#define ENETQ_MTL_TXQW_ISCQW_MASK	GENMASK(20, 0)

/* INIT operating mode for MAC */
#define ENETQ_MAC_CORE_INIT (ENETQ_MAC_CONFIG_JD | ENETQ_MAC_CONFIG_DM | \
		ENETQ_MAC_CONFIG_BE | ENETQ_MAC_CONFIG_DCRS | \
		ENETQ_MAC_CONFIG_JE | ENETQ_MAC_CONFIG_CST)

/* Rx frame status */
enum rx_frame_status {
	ok_frame = 0x0,
	discard_frame = 0x1,
	csum_none = 0x2,
	llc_snap = 0x4,
	dma_owner = 0x8,
	rx_not_ldesc = 0x10,
};

/* Tx frame status */
enum tx_frame_status {
	tx_comp = 0x0,
	tx_not_ldesc = 0x1,
	tx_error = 0x2,
	tx_dma_owner = 0x4,
	tx_error_bump_tc = 0x8,
};

#define ENETQ_CHAIN_MODE		0x1
#define ENETQ_RING_MODE		0x2

/* DMA registers */

#define ENETQ_DMA_MODE		0x1000 /* DMA Bus Mode */
#define ENETQ_DMA_SYS_BUS_MODE	0x1004 /* DMA System Bus Mode */

/* DMA Bus Mode register (ENETQ_DMA_MODE) */
#define ENETQ_DMA_BUS_MODE_DCHE		BIT(19)
#define ENETQ_DMA_BUS_MODE_SFT_RESET	BIT(0) /* Software Reset */

/* DMA Channel Control Register (ENETQ_DMA_CH_CONTROL) */
#define ENETQ_DMA_BUS_MODE_PBL	BIT(16) /* Programmable Burst Length */
#define ENETQ_DMA_BUS_MODE_PBL_SHIFT	16
#define ENETQ_DMA_BUS_MODE_RPBL_SHIFT	16

/* DMA System Bus Mode Register (ENETQ_DMA_SYS_BUS_MODE) */
#define ENETQ_DMA_SYS_BUS_MB		BIT(14) /* Mixed burst */
#define ENETQ_DMA_SYS_BUS_AAL	BIT(12) /* Address-Aligned Beats */
#define ENETQ_DMA_SYS_BUS_EAME	BIT(11) /* Enable Enhanced Addressing */
#define ENETQ_DMA_SYS_BUS_FB		BIT(0) /* Fixed Burst Length */

struct eqos_dma_ch_regs {
	uint32_t ctrl; /* 0x00 */
	uint32_t tx_ctrl; /* 0x04 */
	uint32_t rx_ctrl; /* 0x08 */
	uint32_t rsvd1; /* 0x0C */
	uint32_t tx_addr_hi; /* 0x010 */
	uint32_t tx_addr; /* 0x14 */
	uint32_t rx_addr_hi; /* 0x18 */
	uint32_t rx_addr; /* 0x1c */
	uint32_t tx_tail_addr; /* 0x20 */
	uint32_t rsvd2; /* 0x34 */
	uint32_t rx_tail_addr; /* 0x28 */
	uint32_t tx_ring_len; /* 0x2c */
	uint32_t rx_ring_len; /* 0x30 */
	uint32_t intr_en; /* 0x34 */
	uint32_t intr_wdog; /* 0x38 */
	uint32_t ctrl_status; /* 0x3C */
	uint32_t rsvd3; /* 0x40 */
	uint32_t tx_desc; /* 0x44 */
	uint32_t rx_desc; /* 0x4C */
	uint32_t rsvd4; /* 0x50 */
	uint32_t tx_desc_addr; /* 0x54 */
	uint32_t rsvd5; /* 0x58 */
	uint32_t rx_desc_addr; /* 0x5C */
	uint32_t dma_status; /* 0x60 */
	uint32_t miss_frame_cnt; /* 0x64 */
	uint32_t rx_frame_accept_cnt; /* 0x68 */
	uint32_t rx_eri_cnt; /* 0x64 */
};

#define ENETQ_DMA_CHX_REGS(addr, x) \
	(struct eqos_dma_ch_regs  *)((size_t)addr + 0x1100 + (x *0x80))

/* DMA Channel Transmit Control Register (ENETQ_DMA_CH_TX_CONTROL) */
#define ENETQ_DMA_CONTROL_EDSE	BIT(28) /* Enhanced Descriptor Enable */
#define ENETQ_DMA_CONTROL_OSP	BIT(4) /* Operate on Second Packet */
#define ENETQ_DMA_CONTROL_ST		BIT(0) /* Start or Stop Transmission */

/* DMA Channel Receive Control (ENETQ_DMA_CH_RX_CONTROL) */
#define ENETQ_DMA_CONTROL_SR		BIT(0) /* Start or Stop Receive */
#define ENETQ_DMA_RBSZ_MASK		GENMASK(14, 1) /* Receive Buffer size */
#define ENETQ_DMA_RBSZ_SHIFT		1

/****************************************/
/* Descriptor Defines */
/****************************************/

/* Transmit Normal Descriptor */
#define ENETQ_TDES2_BUF1_SZ_MASK	GENMASK(13, 0) /* Buffer 1 Length */
#define ENETQ_TDES2_BUF2_SZ_MASK	GENMASK(29, 16) /* Buffer 2 Length */
#define ENETQ_TDES2_BUF2_SZ_MASK_SHIFT	16
#define ENETQ_TDES3_PKT_SZ_MASK	GENMASK(14, 0) /* Frame Length */

#define ENETQ_TDES3_IP_HDR_ERR	BIT(0) /* IP Header Error */
#define ENETQ_TDES3_DEF		BIT(1) /* Deferred Bit  */
#define ENETQ_TDES3_UNDERFLOW_ERR	BIT(2) /* Underflow Error */
#define ENETQ_TDES3_EXCESSIVE_DEFERRAL	BIT(3) /* Excessive Deferral */
#define ENETQ_TDES3_EXCESSIVE_COLLISION	BIT(8) /* Excessive Collision */
#define ENETQ_TDES3_LATE_COLLISION	BIT(9) /* Late Collision  */
#define ENETQ_TDES3_NO_CARRIER	BIT(10) /* No Carrier */
#define ENETQ_TDES3_LOSS_CARRIER	BIT(11) /* Loss of Carrier */
#define ENETQ_TDES3_PL_ERR		BIT(12) /* Payload Checksum Error */
#define ENETQ_TDES3_PKT_FLUSHED	BIT(13) /* Packet Flushed */
#define ENETQ_TDES3_JABBER_TIMEOUT	BIT(14) /* Jabber Timeout */
#define ENETQ_TDES3_ERR_SUMMARY	BIT(15) /* Error Summary */

#define ENETQ_TDES3_LAST_DESC		BIT(28) /* Last Descriptor */
#define ENETQ_TDES3_LAST_DESC_SHIFT	28
#define ENETQ_TDES3_FIRST_DESC	BIT(29) /* First Descriptor */
#define ENETQ_TDES3_OWN		BIT(31) /* Own Bit */
#define ENETQ_TDES3_OWN_SHIFT	31

/* Receive normal descriptor */
#define ENETQ_RDES3_PKT_SZ_MASK	GENMASK(14, 0) /* Packet Length */
#define ENETQ_RDES3_ERR_SUMMARY	BIT(15) /* Error Summary */
#define ENETQ_RDES3_PKT_LEN_TYPE_MASK GENMASK(18, 16) /* Length/Type Field */
#define ENETQ_RDES3_DRIBBLE_ERR	BIT(19) /* Dribble Bit Error */
#define ENETQ_RDES3_RECEIVE_ERR	BIT(20) /* Receive Error */
#define ENETQ_RDES3_OVERFLOW_ERR	BIT(21) /* Overflow Error */
#define ENETQ_RDES3_GIANT_PKT		BIT(23) /* Giant Packet */
#define ENETQ_RDES3_CRC_ERR		BIT(24) /* CRC Error */
#define ENETQ_RDES3_RDES0_VALID	BIT(25) /* Receive Status RDES0 Valid */
#define ENETQ_RDES3_RDES1_VALID	BIT(26) /* Receive Status RDES1 Valid */
#define ENETQ_RDES3_RDES2_VALID	BIT(27) /* Receive Status RDES2 Valid */
#define ENETQ_RDES3_LAST_DESC		BIT(28) /* Last Descriptor */
#define ENETQ_RDES3_FIRST_DESC	BIT(29) /* First Descriptor */
#define ENETQ_RDES3_CTX_DESC		BIT(30) /* Receive Context Descriptor */
#define ENETQ_RDES3_CTX_DESC_SHIFT	30

#define ENETQ_RDES3_BUFFER1_VALID_ADDR	BIT(24) /* Buffer 1 Address Valid */
#define ENETQ_RDES3_BUFFER2_VALID_ADDR	BIT(25) /* Buffer 2 Address Valid */
#define ENETQ_RDES3_OWN		BIT(31) /* Own Bit */

#define ENETQ_RDES1_IPV4			BIT(4) /* IPv4 Header Present */
#define ENETQ_RDES1_IPHE			BIT(3) /* IP Header Error */
#define ENETQ_RDES1_IPCE			BIT(7) /* IP Payload Error */

#endif /*__ENETQOS_HW_*/
