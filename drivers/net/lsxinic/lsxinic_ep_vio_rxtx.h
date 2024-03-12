// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2024 NXP  */

#ifndef _LSXINIC_EP_VIO_RXTX_H_
#define _LSXINIC_EP_VIO_RXTX_H_

#include <rte_ethdev.h>
#include <rte_dmadev.h>
#include <rte_pmd_dpaax_qdma.h>

#include "virtio.h"
#include "virtio_ring.h"

#include "lsxinic_ep_vio_ring.h"

#ifndef __aligned
#define __aligned __rte_aligned
#endif

enum {VIRTIO_RXQ, VIRTIO_TXQ, VIRTIO_QNUM};
enum LSXVIO_QEUE_TYPE {
	LSXVIO_QUEUE_RX,
	LSXVIO_QUEUE_TX
};

enum LSXVIO_QEUE_STATUS {
	LSXVIO_QUEUE_UNAVAILABLE,
	LSXVIO_QUEUE_START,
	LSXVIO_QUEUE_RUNNING,
	LSXVIO_QUEUE_STOP,
};

#define	LSXVIO_MAX_DATA_PER_TXD	4096

#define	LSXVIO_DMA_ALIGN_MASK	0x3F

#ifndef MCACHE_NUM
#define MCACHE_NUM (LSINIC_MAX_BURST_NUM * 4)
#endif
#define MCACHE_MASK (MCACHE_NUM - 1)

/**
 * Structure associated with each descriptor of the TX ring of a TX queue.
 */
struct lsxvio_queue_entry {
	struct rte_mbuf *mbuf; /**< mbuf associated with TX desc, if any. */
	uint32_t idx;
	/**For CB buffer, the len excludes CB header size. */
	uint32_t len;
	uint32_t flag;
	uint32_t bd_idx; /**< Index of next descriptor in ring. */
	uint32_t sg_id; /**< Index of last scattered descriptor. */
	uint32_t align_dma_offset;
	union {
		char *complete;
		uint8_t dma_complete;
	};
};

enum lsxvio_dma_cntx_type {
	LSXVIO_DMA_RX_CNTX_DATA,
	LSXVIO_DMA_CNTX_ADDR,
	LSXVIO_DMA_TX_CNTX_DATA
};

struct lsxvio_dma_cntx {
	enum lsxvio_dma_cntx_type cntx_type;
	union {
		uint32_t cntx_data;
		void *cntx_addr;
	};
};

#define LSXVIO_QUEUE_IDX_INORDER_FLAG (1ull << 0)
#define LSXVIO_QUEUE_PKD_INORDER_FLAG (1ull << 1)
#define LSXVIO_QUEUE_DMA_APPEND_FLAG (1ull << 2)
#define LSXVIO_QUEUE_DMA_BD_NOTIFY_FLAG (1ull << 3)
#define LSXVIO_QUEUE_DMA_ADDR_NOTIFY_FLAG (1ull << 4)
#define LSXVIO_QUEUE_DMA_SG_FLAG (1ull << 5)
#define LSXVIO_QUEUE_DMA_SILENT_FLAG (1ull << 6)

#define LSXVIO_DATA_DMA_START 0
#define LSXVIO_E2R_BD_DMA_START \
	(LSXVIO_DATA_DMA_START + LSINIC_BD_ENTRY_COUNT)
#define LSXVIO_R2E_BD_DMA_START \
	(LSXVIO_E2R_BD_DMA_START + LSINIC_BD_ENTRY_COUNT)
#define LSXVIO_R2E_IDX_BD_DMA_START \
	(LSXVIO_R2E_BD_DMA_START + LSINIC_BD_ENTRY_COUNT)
#define LSXVIO_BD_DMA_MAX_COUNT \
	(LSXVIO_R2E_IDX_BD_DMA_START + LSINIC_BD_ENTRY_COUNT)

/**
 * Structure associated with each RX queue.
 */
struct lsxvio_queue {
	void *desc_addr;
	struct vring_desc *vdesc;
	struct vring_desc *shadow_vdesc;
	struct lsxvio_short_desc *shadow_sdesc;
	uint64_t shadow_phy;
	struct vring_packed_desc *pdesc;

	struct vring_avail *avail;
	struct vring_used *used;

	uint64_t mem_base;
	uint16_t local_used_idx;
	uint32_t size;

	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	uint16_t bd_dma_idx;

	struct vring_avail *shadow_avail;
	struct lsxvio_packed_notify *packed_notify;

	struct vring_used *shadow_used_split;
	struct vring_packed_desc *shadow_pdesc;
	uint64_t shadow_pdesc_phy;
	const struct rte_memzone *shadow_pdesc_mz;

	uint16_t shadow_used_idx;
	/* Record packed ring enqueue latest desc cache aligned index */
	uint16_t shadow_aligned_idx;
	/* Record packed ring first dequeue desc index */
	uint16_t shadow_last_used_idx;
	struct lsxvio_adapter *adapter;
	struct lsxvio_queue_cfg *cfg;
	struct lsxvio_queue *pair;
	enum LSXVIO_QEUE_TYPE type;
	uint16_t status;
	/* flag */
	uint32_t flag;
	uint16_t cached_flags;

	struct rte_mempool  *mb_pool; /**< mbuf pool to populate RX ring. */

	struct lsxvio_queue_entry *sw_ring;
	struct lsxvio_dma_cntx *dma_sw_cntx;

	/* DMA */
	struct lsinic_dma_job *dma_jobs;
	struct lsxvio_dma_cntx *dma_bd_cntx;
	uint16_t *dma_idx;

	uint32_t core_id;
	int32_t dma_id;
	int32_t dma_vq;
	uint64_t ob_base;

	/* MSI-X */
	uint32_t msix_irq;
	uint32_t msix_cmd;
	void *msix_vaddr;

	/* BD index */
	uint16_t head;
	uint16_t start_dma_idx;
	uint16_t append_dma_idx;
	uint16_t next_dma_idx;
	uint16_t next_avail_idx;
	uint16_t next_used_idx;

	/* queue setting */
	uint32_t nb_desc;
	uint32_t nb_avail;

	uint16_t  *notify_addr;
	/* Multi-en/dequeue for qdma */
	uint32_t jobs_pending;

	uint32_t queue_id; /**< RX queue index. */
	uint32_t reg_idx;  /**< RX queue register index. */
	uint32_t port_id;  /**< Device port identifier. */
	uint32_t crc_len;  /**< 0 if CRC stripped, 4 otherwise. */
	uint32_t drop_en;  /**< If not 0, set SRRCTL.Drop_En. */

	/* qDMA configure */
	struct rte_dma_vchan_conf qdma_config;

	uint64_t packets_old;
	/* statistics */
	uint64_t packets;
	uint64_t bytes;
	uint64_t bytes_fcs;
	uint64_t bytes_overhead;
	uint64_t bytes_overhead_old;
	uint64_t errors;
	uint64_t drop_packet_num;
	uint64_t ring_full;
	uint64_t loop_total;
	uint64_t loop_avail;

	/* point to the working queue */
	struct lsxvio_queue *working;
	/* point to the next queue belonged to the same core */
	struct lsxvio_queue *sibling;
	uint32_t nb_q;

	struct rte_eth_dev *dev;

	uint16_t mhead;
	uint16_t mtail;
	uint32_t mcnt;
	struct rte_mbuf *mcache[MCACHE_NUM];

	struct rte_mempool *qdma_pool;

	uint64_t bytes_dq;
	uint64_t bytes_eq;
	uint64_t pkts_dq;
	uint64_t pkts_eq;

	/* Pointer to Next instance used by q list */
	TAILQ_ENTRY(lsxvio_queue) next;
};

#define  lsxvio_rx_queue lsxvio_queue
#define  lsxvio_tx_queue lsxvio_queue

void lsxvio_rx_queue_release_mbufs(struct lsxvio_rx_queue *rxq);
void lsxvio_rx_queue_release(struct lsxvio_rx_queue *rxq);
void lsxvio_reset_rx_queue(struct lsxvio_rx_queue *rxq);
void lsxvio_tx_queue_release(struct lsxvio_tx_queue *txq);
void lsxvio_reset_tx_queue(struct lsxvio_tx_queue *txq);

int lsxvio_dev_rxq_init(struct lsxvio_rx_queue *rxq);
int lsxvio_dev_txq_init(struct lsxvio_tx_queue *txq);
int lsxvio_dev_rx_mq_init(struct lsxvio_rx_queue *rxq);
int lsxvio_dev_tx_mq_init(struct lsxvio_tx_queue *txq);
void lsxvio_dev_rx_tx_bind(struct rte_eth_dev *dev);
void lsxvio_dev_rx_stop(struct rte_eth_dev *dev);
void lsxvio_dev_tx_stop(struct rte_eth_dev *dev);
void lsxvio_dev_rx_enable_start(struct rte_eth_dev *dev);
void lsxvio_dev_tx_enable_start(struct rte_eth_dev *dev);
int lsxvio_dev_tx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_txconf *tx_conf);

int lsxvio_dev_rx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp);

void lsxvio_queue_reset(struct lsxvio_queue *q);
void lsxvio_queue_release(struct lsxvio_queue *q);
#endif
