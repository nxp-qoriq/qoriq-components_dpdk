// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2024 NXP  */

#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_prefetch.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_sctp.h>
#include <rte_string_fns.h>
#include <rte_errno.h>
#include <ethdev_driver.h>
#include <dpaa2_hw_pvt.h>

#include "lsxinic_common.h"
#include "lsxinic_common_pmd.h"
#include "lsxinic_vio_common.h"
#include "lsxinic_ep_vio_net.h"
#include "lsxinic_ep_vio_rxtx.h"
#include "lsxinic_ep_dma.h"
#include <rte_pmd_dpaa2_qdma.h>

#define DEFAULT_BURST_THRESH LSINIC_QDMA_EQ_DATA_MAX_NB

static void lsxvio_all_virt_dev_tx_loop(void);

static void
lsxvio_queue_dma_release(struct lsxvio_queue *q)
{
	if (q->dma_jobs) {
		rte_free(q->dma_jobs);
		q->dma_jobs = NULL;
	}
}

static void
lsxvio_queue_release_mbufs(struct lsxvio_queue *q)
{
	uint32_t i;

	if (q->sw_ring) {
		for (i = 0; i < q->nb_desc; i++) {
			if (q->sw_ring[i].mbuf) {
				rte_pktmbuf_free(q->sw_ring[i].mbuf);
				q->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

static int
lsxvio_queue_dma_create(struct lsxvio_queue *q)
{
	uint32_t lcore_id = rte_lcore_id(), i;
	int pcie_id = q->adapter->lsx_dev->pcie_id;
	int pf_id = q->adapter->lsx_dev->pf;
	int vf_id = q->adapter->lsx_dev->vf;
	int is_vf = q->adapter->lsx_dev->is_vf;
	int ret;
	int16_t dma_id;
	uint16_t *pvq;

	if (q->dma_vq >= 0)
		return 0;

	q->core_id = lcore_id;

	if (q->type == LSXVIO_QUEUE_RX) {
		dma_id = q->adapter->rxq_dma_id;
		pvq = &q->adapter->rxq_dma_vchan_used;
		if (q->adapter->rbp_enable) {
			q->qdma_config.direction = RTE_DMA_DIR_DEV_TO_MEM;
			q->qdma_config.src_port.port_type = RTE_DMA_PORT_PCIE;
			q->qdma_config.src_port.pcie.coreid = pcie_id;
			q->qdma_config.src_port.pcie.pfid = pf_id;
			if (is_vf) {
				q->qdma_config.src_port.pcie.vfen = 1;
				q->qdma_config.src_port.pcie.vfid = vf_id;
			} else {
				q->qdma_config.src_port.pcie.vfen = 0;
			}
			q->qdma_config.dst_port.port_type = RTE_DMA_PORT_NONE;
		} else {
			q->qdma_config.direction = RTE_DMA_DIR_MEM_TO_MEM;
			q->qdma_config.src_port.port_type = RTE_DMA_PORT_NONE;
			q->qdma_config.dst_port.port_type = RTE_DMA_PORT_NONE;
		}
	} else {
		dma_id = q->adapter->txq_dma_id;
		pvq = &q->adapter->txq_dma_vchan_used;
		if (q->adapter->rbp_enable) {
			q->qdma_config.direction = RTE_DMA_DIR_MEM_TO_DEV;
			q->qdma_config.src_port.port_type = RTE_DMA_PORT_NONE;
			q->qdma_config.dst_port.port_type = RTE_DMA_PORT_PCIE;
			q->qdma_config.dst_port.pcie.coreid = pcie_id;
			q->qdma_config.dst_port.pcie.pfid = pf_id;
			if (is_vf) {
				q->qdma_config.dst_port.pcie.vfen = 1;
				q->qdma_config.dst_port.pcie.vfid = vf_id;
			} else {
				q->qdma_config.dst_port.pcie.vfen = 0;
			}
		} else {
			q->qdma_config.direction = RTE_DMA_DIR_MEM_TO_MEM;
			q->qdma_config.src_port.port_type = RTE_DMA_PORT_NONE;
			q->qdma_config.dst_port.port_type = RTE_DMA_PORT_NONE;
		}
	}

	q->qdma_config.nb_desc = LSXVIO_BD_DMA_MAX_COUNT;

	for (i = 0; i < LSXVIO_BD_DMA_MAX_COUNT; i++)
		q->dma_jobs[i].idx = i;

	ret = rte_dma_vchan_setup(dma_id, *pvq,
		&q->qdma_config);
	if (ret)
		return ret;
	q->dma_vq = *pvq;
	(*pvq)++;

	return 0;
}

static int
lsxvio_queue_dma_clean(struct lsxvio_queue *q)
{
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB];
	int ret = 0;

	if (q->flag & LSXVIO_QUEUE_DMA_SILENT_FLAG)
		return 0;

	if (q->pkts_eq == q->pkts_dq)
		return 0;

	ret = rte_dma_completed(q->dma_id, q->dma_vq,
		LSINIC_QDMA_DQ_MAX_NB, idx_completed, NULL);

	q->pkts_dq += ret;

	if (q->pkts_eq != q->pkts_dq) {
		LSXINIC_PMD_WARN("port%d %sq%d %ld pkts in dma",
			q->port_id,
			q->type == LSXVIO_QUEUE_TX ? "tx" : "rx",
			q->queue_id, q->pkts_eq - q->pkts_dq);

		return -EAGAIN;
	}

	return 0;
}

static void
lsxvio_queue_free_swring(struct lsxvio_queue *q)
{
	if (!q)
		return;

	if (q->sw_ring)
		rte_free(q->sw_ring);
}

void
lsxvio_queue_release(struct lsxvio_queue *q)
{
	if (!q)
		return;

	lsxvio_queue_release_mbufs(q);
	lsxvio_queue_free_swring(q);
	lsxvio_queue_dma_release(q);
	rte_free(q);
}

static struct lsxvio_queue *
lsxvio_queue_alloc(struct lsxvio_adapter *adapter,
	uint16_t queue_idx,
	int socket_id, uint32_t nb_desc)
{
	struct lsxvio_queue *q;

	q = rte_zmalloc_socket("ethdev queue", sizeof(struct lsxvio_queue),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!q) {
		LSXINIC_PMD_ERR("Failed to allocate memory for queue\n");
		return NULL;
	}
	memset(q, 0, sizeof(struct lsxvio_queue));

	adapter->vqs[queue_idx] = q;
	q->adapter = adapter;

	q->nb_desc = nb_desc;
	q->queue_id = queue_idx;
	q->dma_vq = -1;
	q->nb_q = 1;
	q->sibling = NULL;

	/* Allocate software ring */
	q->sw_ring = rte_zmalloc_socket("q->sw_ring",
			sizeof(struct lsxvio_queue_entry) * nb_desc,
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->sw_ring) {
		LSXINIC_PMD_ERR("Failed to create sw_ring");
		goto _err;
	}

	q->dma_sw_cntx = rte_zmalloc_socket("q->dma_sw_cntx",
			sizeof(struct lsxvio_dma_cntx) * nb_desc,
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->dma_sw_cntx) {
		LSXINIC_PMD_ERR("Failed to create dma_sw_cntx");
		goto _err;
	}

	q->dma_bd_cntx = rte_zmalloc_socket("q->dma_bd_cntx",
			sizeof(struct lsxvio_dma_cntx) * nb_desc,
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->dma_bd_cntx) {
		LSXINIC_PMD_ERR("Failed to create dma_bd_cntx");
		goto _err;
	}

	/* Allocate DMA jobs ring */
	q->dma_jobs = rte_zmalloc_socket("q->dma_jobs",
		sizeof(struct lsinic_dma_job) * LSXVIO_BD_DMA_MAX_COUNT,
		RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->dma_jobs) {
		LSXINIC_PMD_ERR("Failed to create dma_jobs");
		goto _err;
	}

	adapter->num_queues += 1;

	return q;

_err:
	lsxvio_queue_release(q);
	return NULL;
}

void
lsxvio_queue_reset(struct lsxvio_queue *q)
{
	struct lsxvio_queue_entry *xe = q->sw_ring;
	struct lsxvio_dma_cntx *dma_cntx = q->dma_sw_cntx;
	uint32_t i;

	/* Initialize SW ring entries */
	for (i = 0; i < q->nb_desc; i++) {
		xe[i].mbuf = NULL;
		xe[i].idx = i;
		xe[i].bd_idx = i;
		xe[i].flag = 0;
		if (q->type == LSXVIO_QUEUE_TX &&
			q->flag & LSXVIO_QUEUE_PKD_INORDER_FLAG)
			xe[i].dma_complete = 1;

		dma_cntx[i].cntx_type = LSXVIO_DMA_CNTX_ADDR;
		dma_cntx[i].cntx_addr = &xe[i];
	}

	q->next_dma_idx = 0;
	q->last_avail_idx = 0;
	q->last_used_idx = 0;
	q->errors = 0;
	q->drop_packet_num = 0;
	q->ring_full = 0;
	q->loop_total = 0;
	q->loop_avail = 0;

	q->jobs_pending = 0;
	q->mhead = 0;
	q->mtail = 0;
	q->mcnt = 0;
}

static int lsxvio_add_txq_to_list(struct lsxvio_queue *txq)
{
	struct lsxvio_queue *queue = NULL;
	struct lsxvio_adapter *adapter = txq->adapter;
	uint32_t this_core = rte_lcore_id();

	if (!adapter->txq_list_initialized[this_core]) {
		TAILQ_INIT(&adapter->txq_list[this_core]);
		adapter->txq_list_initialized[this_core] = 1;
		adapter->txq_num_in_list[this_core] = 0;
	}

	/* Check if txq already added to list */
	TAILQ_FOREACH(queue, &adapter->txq_list[this_core], next) {
		if (queue == txq)
			return 0;
	}

	TAILQ_INSERT_TAIL(&adapter->txq_list[this_core], txq, next);
	adapter->txq_num_in_list[this_core]++;

	LSXINIC_PMD_DBG("Add port%d txq%d to list NUM%d",
		txq->port_id, txq->queue_id,
		adapter->txq_num_in_list[this_core]);

	return 0;
}

static int
lsxvio_remove_txq_from_list(struct lsxvio_queue *txq)
{
	struct lsxvio_queue *q, *tq;
	struct lsxvio_adapter *adapter = txq->adapter;
	uint32_t this_core = rte_lcore_id();

	RTE_TAILQ_FOREACH_SAFE(q, &adapter->txq_list[this_core], next, tq) {
		if (q == txq) {
			TAILQ_REMOVE(&adapter->txq_list[this_core],
				q, next);
			adapter->txq_num_in_list[this_core]--;
			LSXINIC_PMD_DBG("Remove port%d txq%d from list NUM%d",
				txq->port_id, txq->queue_id,
				adapter->txq_num_in_list[this_core]);
			break;
		}
	}

	return 0;
}

static void
lsxvio_queue_stop(struct lsxvio_queue *q)
{
	q->status = LSXVIO_QUEUE_STOP;
}

static int
lsxvio_queue_start(struct lsxvio_queue *q)
{
	struct lsxvio_adapter *adapter = q->adapter;
	int ret;

	lsxvio_queue_reset(q);

	rte_spinlock_lock(&adapter->rxq_dma_start_lock);
	if (q->type == LSXVIO_QUEUE_RX &&
		!adapter->rxq_dma_started) {
		ret = rte_dma_start(adapter->rxq_dma_id);
		if (ret) {
			LSXINIC_PMD_ERR("dma[%d] start failed(%d)",
				adapter->rxq_dma_id, ret);
			rte_spinlock_unlock(&adapter->rxq_dma_start_lock);
			return ret;
		}
		adapter->rxq_dma_started = 1;
	}
	rte_spinlock_unlock(&adapter->rxq_dma_start_lock);

	rte_spinlock_lock(&adapter->txq_dma_start_lock);
	if (q->type == LSXVIO_QUEUE_TX &&
		!adapter->txq_dma_started) {
		ret = rte_dma_start(adapter->txq_dma_id);
		if (ret) {
			LSXINIC_PMD_ERR("dma[%d] start failed(%d)",
				adapter->txq_dma_id, ret);
			rte_spinlock_unlock(&adapter->txq_dma_start_lock);
			return ret;
		}
		adapter->txq_dma_started = 1;
	}
	rte_spinlock_unlock(&adapter->txq_dma_start_lock);

	return 0;
}

static void lsxvio_queue_update(struct lsxvio_queue *q)
{
	int ret;

	if (q->status == LSXVIO_QUEUE_UNAVAILABLE)
		return;

	if (q->status == LSXVIO_QUEUE_RUNNING)
		return;

	if (q->status == LSXVIO_QUEUE_START) {
		ret = lsxvio_queue_start(q);
		if (ret)
			return;

		if (q->type == LSXVIO_QUEUE_TX)
			lsxvio_add_txq_to_list(q);

		q->status = LSXVIO_QUEUE_RUNNING;
	}
	if (q->status == LSXVIO_QUEUE_STOP) {
		if (lsxvio_queue_dma_clean(q)) {
			rte_delay_ms(500);
			return;
		}

		if (q->type == LSXVIO_QUEUE_TX)
			lsxvio_remove_txq_from_list(q);
	}
}

static int
lsxvio_queue_init(struct lsxvio_queue *q)
{
	/* Currently the queeu has been inited in lsxvio_queue_alloc. */
	q->status = LSXVIO_QUEUE_UNAVAILABLE;

	return 0;
}

int
lsxvio_dev_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t tx_queue_id,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct lsxvio_adapter *adapter = dev->data->dev_private;
	uint16_t queue_idx = tx_queue_id * VIRTIO_QNUM + VIRTIO_RXQ;
	struct lsxvio_queue *txq;
	struct lsxvio_common_cfg *common =
		BASE_TO_COMMON(adapter->cfg_base);
	char *penv;
	int ret;

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->tx_queues[tx_queue_id])
		lsxvio_queue_release(dev->data->tx_queues[tx_queue_id]);

	/* First allocate the tx queue data structure */
	txq = lsxvio_queue_alloc(adapter, queue_idx, socket_id, nb_desc);
	if (!txq)
		return -ENOMEM;

	txq->dma_id = adapter->txq_dma_id;
	txq->port_id = dev->data->port_id;

	/* using RC's rx ring to send EP's packets */
	txq->dev = dev;
	txq->type = LSXVIO_QUEUE_TX;

	dev->data->tx_queues[tx_queue_id] = txq;

	if (common->lsx_feature & LSX_VIO_EP2RC_PACKED) {
		txq->flag |= LSXVIO_QUEUE_PKD_INORDER_FLAG;
		txq->cached_flags = VRING_PACKED_DESC_F_AVAIL_USED;
	}

	penv = getenv("LSXVIO_TX_QDMA_APPEND");
	if (penv) {
		if (atoi(penv))
			txq->flag |= LSXVIO_QUEUE_DMA_APPEND_FLAG;
	} else {
		txq->flag |= LSXVIO_QUEUE_DMA_APPEND_FLAG;
	}

	if (common->lsx_feature & LSX_VIO_EP2RC_DMA_ADDR_NOTIFY)
		txq->flag |= LSXVIO_QUEUE_DMA_ADDR_NOTIFY_FLAG;
	if (common->lsx_feature & LSX_VIO_EP2RC_DMA_BD_NOTIFY)
		txq->flag |= LSXVIO_QUEUE_DMA_BD_NOTIFY_FLAG;

	ret = lsxvio_queue_dma_create(txq);
	if (ret)
		return ret;

	if (adapter->txq_dma_silent)
		txq->flag |= LSXVIO_QUEUE_DMA_SILENT_FLAG;

	if (common->lsx_feature & LSX_VIO_EP2RC_DMA_SG_ENABLE)
		txq->flag |= LSXVIO_QUEUE_DMA_SG_FLAG;

	txq->dma_idx = rte_malloc(NULL,
		sizeof(uint16_t) * nb_desc,
		RTE_DPAA2_QDMA_SG_IDX_ADDR_ALIGN);
	if (!txq->dma_idx)
		return -ENOMEM;

	return 0;
}

void
lsxvio_dev_tx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid)
{
	lsxvio_queue_release(dev->data->tx_queues[qid]);
}

void
lsxvio_dev_rx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid)
{
	lsxvio_queue_release(dev->data->rx_queues[qid]);
}

int
lsxvio_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t rx_queue_id,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mp)
{
	struct lsxvio_adapter *adapter = dev->data->dev_private;
	uint16_t queue_idx = rx_queue_id * VIRTIO_QNUM + VIRTIO_TXQ;
	struct lsxvio_queue *rxq;
	struct lsxvio_common_cfg *common =
		BASE_TO_COMMON(adapter->cfg_base);
	char *penv;
	int ret;

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->rx_queues[rx_queue_id] != NULL)
		lsxvio_queue_release(dev->data->rx_queues[rx_queue_id]);

	/* First allocate the tx queue data structure */
	rxq = lsxvio_queue_alloc(adapter, queue_idx, socket_id, nb_desc);
	if (!rxq)
		return -ENOMEM;

	rxq->dma_id = adapter->rxq_dma_id;
	rxq->mb_pool = mp;
	rxq->port_id = dev->data->port_id;
	rxq->crc_len = 0;
	rxq->drop_en = rx_conf->rx_drop_en;

	/* using RC's rx ring to send EP's packets */
	rxq->desc_addr = NULL;
	rxq->dev = dev;
	rxq->type = LSXVIO_QUEUE_RX;

	dev->data->rx_queues[rx_queue_id] = rxq;

	if (common->lsx_feature & LSX_VIO_RC2EP_IN_ORDER)
		rxq->flag |= LSXVIO_QUEUE_IDX_INORDER_FLAG;

	penv = getenv("LSXVIO_RX_QDMA_APPEND");
	if (penv) {
		if (atoi(penv))
			rxq->flag |= LSXVIO_QUEUE_DMA_APPEND_FLAG;
	} else {
		rxq->flag |= LSXVIO_QUEUE_DMA_APPEND_FLAG;
	}

	if (common->lsx_feature & LSX_VIO_RC2EP_DMA_BD_NOTIFY)
		rxq->flag |= LSXVIO_QUEUE_DMA_BD_NOTIFY_FLAG;

	ret = lsxvio_queue_dma_create(rxq);
	if (ret)
		return ret;

	if (adapter->rxq_dma_silent)
		rxq->flag |= LSXVIO_QUEUE_DMA_SILENT_FLAG;

	if (common->lsx_feature & LSX_VIO_RC2EP_DMA_SG_ENABLE)
		rxq->flag |= LSXVIO_QUEUE_DMA_SG_FLAG;

	rxq->dma_idx = rte_malloc(NULL,
		sizeof(uint16_t) * nb_desc,
		RTE_DPAA2_QDMA_SG_IDX_ADDR_ALIGN);
	if (!rxq->dma_idx)
		return -ENOMEM;

	return 0;
}

/* Initializes Receive Unit. */
int
lsxvio_dev_rx_init(struct rte_eth_dev *dev)
{
	struct lsxvio_queue *rxq;
	uint16_t i;
	int ret;

	/* Setup RX queues */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		ret = lsxvio_queue_init(rxq);
		if (ret)
			return ret;
	}

	return 0;
}

/* Initializes Transmit Unit. */
void
lsxvio_dev_tx_init(struct rte_eth_dev *dev)
{
	struct lsxvio_queue *txq;
	uint16_t i;

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		lsxvio_queue_init(txq);
	}
}

void lsxvio_dev_rx_tx_bind(struct rte_eth_dev *dev)
{
	struct lsxvio_queue *txq;
	struct lsxvio_queue *rxq;
	uint16_t i, num;

	num = RTE_MIN(dev->data->nb_tx_queues,
		     dev->data->nb_rx_queues);

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < num; i++) {
		txq = dev->data->tx_queues[i];
		rxq = dev->data->rx_queues[i];
		if (!txq || !rxq)
			continue;

		rxq->pair = txq;
		txq->pair = rxq;
	}
}

void lsxvio_dev_rx_stop(struct rte_eth_dev *dev)
{
	struct lsxvio_queue *rxq;
	uint16_t i;

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		lsxvio_queue_stop(rxq);
	}
}

void lsxvio_dev_tx_stop(struct rte_eth_dev *dev)
{
	struct lsxvio_queue *txq;
	uint16_t i;

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		lsxvio_queue_stop(txq);
	}
}

void
lsxvio_dev_clear_queues(struct rte_eth_dev *dev)
{
	uint32_t i, j;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct lsxvio_queue *txq = dev->data->tx_queues[i];
		struct lsxvio_queue *next = txq;

		if (txq->shadow_pdesc_mz) {
			rte_memzone_free(txq->shadow_pdesc_mz);
			txq->shadow_pdesc_mz = NULL;
		}
		if (txq->shadow_used_split) {
			/** The address alloced was shift to align with 64b,
			 * so let's recover to original address to free.
			 * vq->shadow_used_split =
			 * (void *)((char *)vq->shadow_used_split +
			 * offsetof(struct vring_used, ring[0]));
			 */
			rte_free((uint8_t *)txq->shadow_used_split -
				offsetof(struct vring_used, ring[0]));
			txq->shadow_used_split = NULL;
		}

		for (j = 0; j < txq->nb_q; j++) {
			if (next == NULL)
				break;

			lsxvio_queue_release_mbufs(txq);
			lsxvio_queue_reset(next);
			next = next->sibling;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct lsxvio_queue *rxq = dev->data->rx_queues[i];
		struct lsxvio_queue *next = rxq;

		if (rxq->shadow_pdesc_mz) {
			rte_memzone_free(rxq->shadow_pdesc_mz);
			rxq->shadow_pdesc_mz = NULL;
		}
		if (rxq->shadow_used_split) {
			/** The address alloced was shift to align with 64b,
			 * so let's recover to original address to free.
			 * vq->shadow_used_split =
			 * (void *)((char *)vq->shadow_used_split +
			 * offsetof(struct vring_used, ring[0]));
			 */
			rte_free((uint8_t *)rxq->shadow_used_split -
				offsetof(struct vring_used, ring[0]));
			rxq->shadow_used_split = NULL;
		}

		for (j = 0; j < rxq->nb_q; j++) {
			if (!next)
				break;

			lsxvio_queue_release_mbufs(rxq);
			lsxvio_queue_reset(next);
			next = next->sibling;
		}
	}
}

static __rte_always_inline void
update_shadow_used_ring_split(struct lsxvio_queue *vq,
	uint16_t desc_idx, uint32_t len)
{
	uint16_t i = vq->shadow_used_idx++;

	vq->shadow_used_split->ring[i].id  = desc_idx;
	vq->shadow_used_split->ring[i].len = len;
}

static __rte_always_inline void
do_flush_shadow_used_ring_split(struct lsxvio_queue *vq,
	uint16_t to, uint16_t from, uint16_t size)
{
	if (likely(is_align_64(&vq->used->ring[0]) &&
		is_align_64(&vq->shadow_used_split->ring[0]))) {
		rte_memcpy(&vq->used->ring[to],
			&vq->shadow_used_split->ring[from],
			size * sizeof(struct vring_used_elem));
	} else {
		uint16_t i;

		for (i = 0; i < size; i++) {
			vq->used->ring[to + i].id =
				vq->shadow_used_split->ring[from + i].id;
			vq->used->ring[to + i].len =
				vq->shadow_used_split->ring[from + i].len;
		}
	}
	rte_wmb();
}

static __rte_always_inline void
flush_shadow_used_ring_split(struct lsxvio_queue *vq)
{
	uint16_t used_idx = vq->last_used_idx & (vq->nb_desc - 1);
	uint16_t shadow_used_idx = vq->shadow_used_idx;

	if (used_idx + shadow_used_idx <= vq->nb_desc) {
		do_flush_shadow_used_ring_split(vq, used_idx, 0,
			shadow_used_idx);
	} else {
		uint16_t size;

		/* update used ring interval [used_idx, vq->size] */
		size = vq->nb_desc - used_idx;
		do_flush_shadow_used_ring_split(vq, used_idx, 0, size);

		 /* update the left half used ring interval [0, left_size] */
		do_flush_shadow_used_ring_split(vq, 0, size,
			shadow_used_idx - size);
	}

	vq->last_used_idx += shadow_used_idx;
	vq->local_used_idx += shadow_used_idx;
	vq->used->idx = vq->local_used_idx;
	vq->shadow_used_idx = 0;
}

static inline uint16_t
lsxvio_xmit_dma_bd_jobs(struct lsxvio_queue *vq,
	struct lsinic_dma_job *bd_jobs[],
	uint16_t start_idx, uint16_t end_idx)
{
	uint16_t dma_bd_nb = 0;
	struct lsinic_dma_job *vq_bd_jobs =
		&vq->dma_jobs[LSXVIO_E2R_BD_DMA_START];

	bd_jobs[0] = &vq_bd_jobs[start_idx];
	dma_bd_nb++;
	if (end_idx < start_idx && end_idx > 0) {
		bd_jobs[0]->len = (vq->nb_desc - start_idx) *
			sizeof(struct vring_packed_desc);
		bd_jobs[dma_bd_nb] = &vq_bd_jobs[0];
		bd_jobs[dma_bd_nb]->len = end_idx *
			sizeof(struct vring_packed_desc);
		dma_bd_nb++;
	} else if (end_idx > 0) {
		bd_jobs[0]->len = (end_idx - start_idx) *
			sizeof(struct vring_packed_desc);
	} else {
		/* end_idx == 0*/
		bd_jobs[0]->len = (vq->nb_desc - start_idx) *
			sizeof(struct vring_packed_desc);
	}

	return dma_bd_nb;
}

static inline void
lsxvio_qdma_append(struct lsxvio_queue *vq,
	bool append)
{
	int ret = 0, i, dma_idx, dma_bd_nb = 0;
	uint16_t append_len;
	uint64_t flags;
	struct lsinic_dma_job *dma_jobs[LSINIC_QDMA_EQ_MAX_NB];

	if (vq->append_dma_idx >= vq->start_dma_idx) {
		append_len = vq->append_dma_idx - vq->start_dma_idx;
	} else {
		append_len = vq->nb_desc - vq->start_dma_idx +
			vq->append_dma_idx;
	}

	if (!(vq->flag & LSXVIO_QUEUE_DMA_APPEND_FLAG))
		append = false;

	if ((append && append_len < LSINIC_QDMA_EQ_DATA_MAX_NB) ||
		!append_len)
		return;

	LSINIC_DMA_BURST_ASSERT(append_len);

	for (i = 0; i < append_len; i++) {
		dma_idx = (vq->start_dma_idx + i) & (vq->nb_desc - 1);
		dma_jobs[i] = &vq->dma_jobs[dma_idx];
	}

	if (vq->type == LSXVIO_QUEUE_TX &&
		vq->flag & LSXVIO_QUEUE_DMA_SILENT_FLAG) {
		dma_bd_nb = lsxvio_xmit_dma_bd_jobs(vq,
			&dma_jobs[append_len],
			vq->start_dma_idx,
			(vq->start_dma_idx + append_len) & (vq->nb_desc - 1));
	}

	LSINIC_DMA_BURST_ASSERT((append_len + dma_bd_nb));

	if (vq->flag & LSXVIO_QUEUE_DMA_SG_FLAG) {
		struct rte_dma_sge src_sg[append_len + dma_bd_nb];
		struct rte_dma_sge dst_sg[append_len + dma_bd_nb];

		for (i = 0; i < (append_len + dma_bd_nb); i++) {
			vq->dma_idx[i] = dma_jobs[i]->idx;
			src_sg[i].addr = dma_jobs[i]->src;
			src_sg[i].length = dma_jobs[i]->len;
			dst_sg[i].addr = dma_jobs[i]->dst;
			dst_sg[i].length = dma_jobs[i]->len;
		}
		flags = RTE_DPAA2_QDMA_SG_SUBMIT(vq->dma_idx,
					RTE_DMA_OP_FLAG_SUBMIT);
		ret = rte_dma_copy_sg(vq->dma_id,
			vq->dma_vq,
			src_sg, dst_sg, append_len + dma_bd_nb,
			append_len + dma_bd_nb,
			flags);
	} else {
		for (i = 0; i < (append_len + dma_bd_nb); i++) {
			flags = RTE_DPAA2_QDMA_COPY_SUBMIT(dma_jobs[i]->idx, 0);
			ret = rte_dma_copy(vq->dma_id, vq->dma_vq,
				dma_jobs[i]->src, dma_jobs[i]->dst,
				dma_jobs[i]->len, flags);
			if (unlikely(ret))
				break;
		}
		ret = rte_dma_submit(vq->dma_id, vq->dma_vq);
	}
	if (likely(!ret)) {
		vq->jobs_pending -= (append_len + dma_bd_nb);
		vq->pkts_eq += (append_len + dma_bd_nb);
		vq->start_dma_idx += append_len;
		vq->start_dma_idx =
			vq->start_dma_idx & (vq->nb_desc - 1);
		vq->append_dma_idx = vq->start_dma_idx;
	} else {
		vq->errors++;
	}
}

static inline void
lsxvio_qdma_multiple_enqueue(struct lsxvio_queue *queue,
	struct lsinic_dma_job **jobs, uint16_t nb_jobs)
{
	int ret = 0, i;
	struct rte_dma_sge src_sg[nb_jobs];
	struct rte_dma_sge dst_sg[nb_jobs];
	uint64_t flags;

	LSINIC_DMA_BURST_ASSERT(nb_jobs);

	if (queue->flag & LSXVIO_QUEUE_DMA_SG_FLAG) {
		for (i = 0; i < nb_jobs; i++) {
			queue->dma_idx[i] = jobs[i]->idx;
			src_sg[i].addr = jobs[i]->src;
			src_sg[i].length = jobs[i]->len;

			dst_sg[i].addr = jobs[i]->dst;
			dst_sg[i].length = jobs[i]->len;
		}
		flags = RTE_DPAA2_QDMA_SG_SUBMIT(queue->dma_idx,
					RTE_DMA_OP_FLAG_SUBMIT);
		ret = rte_dma_copy_sg(queue->dma_id,
			queue->dma_vq,
			src_sg, dst_sg, nb_jobs, nb_jobs,
			flags);
	} else {
		for (i = 0; i < nb_jobs; i++) {
			flags = RTE_DPAA2_QDMA_COPY_SUBMIT(jobs[i]->idx, 0);
			ret = rte_dma_copy(queue->dma_id,
				queue->dma_vq,
				jobs[i]->src, jobs[i]->dst,
				jobs[i]->len, flags);
			if (unlikely(ret))
				break;
		}
		ret = rte_dma_submit(queue->dma_id, queue->dma_vq);
	}
	if (likely(!ret)) {
		queue->jobs_pending -= nb_jobs;
		queue->pkts_eq += nb_jobs;
	} else {
		LSXINIC_PMD_ERR("QDMA copy failed!(%d)",
			ret);
		queue->errors++;
	}
}

/*********************************************************************
 *
 *  RX functions
 *
 **********************************************************************/
static uint16_t
lsxvio_rx_dma_dequeue(struct lsxvio_queue *rxq)
{
	struct lsinic_dma_job *dma_job;
	struct lsxvio_queue_entry *rxe = NULL;
	struct lsxvio_dma_cntx *dma_cntx;
	int i, idx, ret = 0;
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB];

	if (rxq->pkts_eq == rxq->pkts_dq)
		return 0;

	ret = rte_dma_completed(rxq->dma_id,
		rxq->dma_vq, LSINIC_QDMA_DQ_MAX_NB,
		idx_completed, NULL);

	LSXINIC_PMD_DBG("enter %s nb_in_dma=%ld, dequeue ret=%d",
		__func__, rxq->pkts_eq - rxq->pkts_dq, ret);
	if (unlikely(ret <= 0)) {
		if (ret < 0) {
			LSXINIC_PMD_ERR("nb_in_dma=%ld, dq err=%d",
				rxq->pkts_eq - rxq->pkts_dq, ret);
		}

		return 0;
	}
	rxq->pkts_dq += ret;
	if (rxq->flag & LSXVIO_QUEUE_IDX_INORDER_FLAG) {
		for (i = 0; i < ret; i++) {
			dma_job = &rxq->dma_jobs[idx_completed[i]];
			if (!dma_job->cnxt)
				continue;
			dma_cntx = (void *)dma_job->cnxt;
			if (dma_cntx->cntx_type == LSXVIO_DMA_RX_CNTX_DATA) {
				rxq->shadow_avail->idx = dma_cntx->cntx_data;
				continue;
			} else if (dma_cntx->cntx_type ==
				LSXVIO_DMA_TX_CNTX_DATA) {
				rxq->pair->packed_notify->last_avail_idx =
					dma_cntx->cntx_data;
				continue;
			}
			rxe = dma_cntx->cntx_addr;
			rxe->dma_complete = 1;
		}
		return i;
	}

	for (i = 0; i < ret; i++) {
		dma_job = &rxq->dma_jobs[idx_completed[i]];
		if (!dma_job->cnxt)
			continue;
		dma_cntx = (void *)dma_job->cnxt;
		RTE_ASSERT(dma_cntx->cntx_type == LSXVIO_DMA_CNTX_ADDR);
		rxe = dma_cntx->cntx_addr;
		if (rxe) {
			if (rxe->flag) {
				idx = rxe->idx & (rxq->nb_desc - 1);
				update_shadow_used_ring_split(rxq, idx, 0);
			}

			/* This should record the completed jobs,
			 * so it need to be updated after got
			 * qdma response.
			 */
			rxq->mcache[rxq->mtail] = rxe->mbuf;
			rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
			rxq->mcnt++;
			rte_prefetch0(rte_pktmbuf_mtod(rxe->mbuf, void *));
		}
	}

	return i;
}

static void
lsxvio_recv_one_pkt(struct lsxvio_queue *rxq,
	uint16_t desc_idx, uint16_t head,
	struct rte_mbuf *rxm,
	struct lsinic_dma_job *dma_job)
{
	struct lsxvio_queue_entry *rxe = &rxq->sw_ring[desc_idx];
	struct vring_desc *desc;
	struct lsxvio_short_desc *sdesc;
	uint64_t addr;
	uint32_t pkt_len;
	uint32_t total_bytes = 0, total_packets = 0;
	uint32_t len;
	struct lsxvio_dma_cntx *dma_cntx;

	if (rxq->shadow_sdesc) {
		sdesc = &rxq->shadow_sdesc[desc_idx];
		len = sdesc->len;
		addr = rxq->mem_base + sdesc->addr_offset;
	} else {
		desc = &rxq->shadow_vdesc[desc_idx];
		len = desc->len;
		addr = desc->addr;
	}

	if (!dma_job)
		dma_job = &rxq->dma_jobs[desc_idx];

	LSXINIC_PMD_DBG("desc info: addr=%lx len=%d", addr, len);
	if (len > LSXVIO_MAX_DATA_PER_TXD) {
		LSXINIC_PMD_ERR("port%d rxq%d BD%d error len:0x%08x, cpu:%d",
			rxq->port_id, rxq->queue_id, desc_idx, len,
			rte_lcore_id());
		rxq->errors++;
		return;
	}
	pkt_len = len - rxq->crc_len;

	if (!rxm)
		rxm = rte_mbuf_raw_alloc(rxq->mb_pool);
	if (!rxm) {
		LSXINIC_PMD_DBG("RX mbuf alloc failed port%d-rxq%d",
			rxq->port_id,
			rxq->queue_id);
		rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
		return;
	}

	/* rxm is ret_mbuf passed to upper layer */
	rxe->mbuf = rxm;
	rxe->len = len;
	rxe->flag = head;
	dma_cntx = &rxq->dma_sw_cntx[desc_idx];
	dma_cntx->cntx_addr = rxe;
	dma_job->cnxt = (uint64_t)dma_cntx;

	dma_job->dst =
		rte_cpu_to_le_64(rte_mbuf_data_iova_default(rxm));
	dma_job->src = addr + rxq->ob_base;
	rxe->align_dma_offset = (dma_job->src) & LSXVIO_DMA_ALIGN_MASK;
	dma_job->src -= rxe->align_dma_offset;
	dma_job->len = pkt_len + rxe->align_dma_offset;
	if (rxq->adapter->rxq_dma_silent) {
		rxe->complete = rte_pktmbuf_mtod_offset(rxm, char *, len);
		*rxe->complete = LSINIC_XFER_COMPLETE_INIT_FLAG;
		dma_job->len++;
	}
	rxq->append_dma_idx++;
	rxq->append_dma_idx = rxq->append_dma_idx & (rxq->nb_desc - 1);

	rxm->nb_segs = 1;
	rxm->next = NULL;
	rxm->pkt_len = pkt_len;
	rxm->data_len = pkt_len;
	rxm->port = rxq->port_id;
	rxm->data_off = RTE_PKTMBUF_HEADROOM + rxe->align_dma_offset;

	rxq->jobs_pending++;
	/*rxq->nb_in_dma++;*/
	total_bytes += len + rxe->align_dma_offset;
	total_packets++;
}

static inline uint16_t
lsxvio_append_bd_dma(struct lsxvio_queue *vq,
	struct lsinic_dma_job **jobs)
{
	uint16_t bd_dma_idx, last_bd_dma_idx, free;
	uint32_t size = vq->mem_base ?
		sizeof(struct lsxvio_short_desc) :
		sizeof(struct vring_desc);
	int rxq_rsp = 1;
	struct lsinic_dma_job *r2e_jobs, *r2e_idx_jobs;

	last_bd_dma_idx = vq->bd_dma_idx;
	if (vq->type == LSXVIO_QUEUE_RX) {
		bd_dma_idx = vq->shadow_avail->flags;
	} else {
		bd_dma_idx = vq->packed_notify->dma_idx;
		size = vq->mem_base ?
			sizeof(uint32_t) : sizeof(uint64_t);
		if (vq->pair->flag & LSXVIO_QUEUE_DMA_SILENT_FLAG)
			rxq_rsp = 0;
	}

	if (last_bd_dma_idx == bd_dma_idx)
		return 0;

	free = (bd_dma_idx - last_bd_dma_idx) & (vq->nb_desc - 1);

	vq->bd_dma_idx = bd_dma_idx;
	last_bd_dma_idx = last_bd_dma_idx & (vq->nb_desc - 1);
	bd_dma_idx = bd_dma_idx & (vq->nb_desc - 1);

	r2e_jobs = &vq->dma_jobs[LSXVIO_R2E_BD_DMA_START];
	r2e_idx_jobs = &vq->dma_jobs[LSXVIO_R2E_IDX_BD_DMA_START];
	if (bd_dma_idx > last_bd_dma_idx) {
		jobs[0] = &r2e_jobs[last_bd_dma_idx];
		jobs[0]->len = size * free;
		jobs[0]->cnxt = (uint64_t)&vq->dma_bd_cntx[last_bd_dma_idx];
		vq->dma_bd_cntx[last_bd_dma_idx].cntx_data =
			bd_dma_idx;
		if (vq->type == LSXVIO_QUEUE_TX && !rxq_rsp) {
			jobs[1] = &r2e_jobs[bd_dma_idx];
			return 2;
		}
		return 1;
	}

	jobs[0] = &r2e_jobs[last_bd_dma_idx];
	jobs[0]->len = size * (vq->nb_desc - last_bd_dma_idx);
	jobs[0]->cnxt = (uint64_t)&vq->dma_bd_cntx[last_bd_dma_idx];
	vq->dma_bd_cntx[last_bd_dma_idx].cntx_data = vq->nb_desc - 1;
	if (bd_dma_idx) {
		jobs[1] = &r2e_jobs[0];
		jobs[1]->len = size * bd_dma_idx;
		jobs[1]->cnxt = (uint64_t)&vq->dma_bd_cntx[0];
		vq->dma_bd_cntx[0].cntx_data = bd_dma_idx;
		if (vq->type == LSXVIO_QUEUE_TX && !rxq_rsp) {
			jobs[2] = &r2e_idx_jobs[bd_dma_idx];
			return 3;
		}
		return 2;
	}
	if (vq->type == LSXVIO_QUEUE_TX && !rxq_rsp) {
		jobs[1] = &r2e_idx_jobs[bd_dma_idx];
		return 2;
	}
	return 1;
}

static int
lsxvio_tx_dma_addr_loop(struct lsinic_dma_job **jobs,
	struct lsxvio_adapter *adapter)
{
	struct lsxvio_queue *q, *tq;
	uint16_t dma_nb = 0, ret;
	uint32_t this_core = rte_lcore_id();

	RTE_TAILQ_FOREACH_SAFE(q, &adapter->txq_list[this_core], next, tq) {
		ret = lsxvio_append_bd_dma(q, &jobs[dma_nb]);
		dma_nb += ret;
	}

	return dma_nb;
}

#undef LSXVIO_REMOTE_PKT_DUMP

#ifdef LSXVIO_REMOTE_PKT_DUMP
static void
lsxvio_dump_remote_buf(struct lsxvio_adapter *adapter,
	uint64_t remote_addr, const uint16_t len)
{
	uint8_t *virt;
	uint32_t i;
	uint64_t mask;
	char *print_buf;
	uint32_t print_len = 0, offset = 0;

	if (!rte_lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
		if (adapter->rbp_enable) {
			LSXINIC_PMD_ERR("%s NOT support to dump remote buffer",
				"RBP enabled");
			return;
		}
		mask = rte_lsx_pciep_bus_win_mask(adapter->lsx_dev);
		if (mask && (remote_addr & mask)) {
			LSXINIC_PMD_ERR("Align err: Bus(0x%lx)-mask(0x%lx)",
				remote_addr, mask);
			return;
		}
		if (mask && (LSXVIO_PER_RING_MEM_MAX_SIZE & mask)) {
			LSXINIC_PMD_ERR("Align err: Size(0x%lx)-mask(0x%lx)",
				(unsigned long)LSXVIO_PER_RING_MEM_MAX_SIZE,
				mask);
			return;
		}
		virt = rte_lsx_pciep_set_ob_win(adapter->lsx_dev,
			remote_addr, LSXVIO_PER_RING_MEM_MAX_SIZE, NULL);
	} else {
		virt = DPAA2_IOVA_TO_VADDR_AND_CHECK(remote_addr,
			LSXVIO_PER_RING_MEM_MAX_SIZE);
	}

	print_buf = rte_malloc(NULL, len * 16 + 1024, 0);
	if (print_buf) {
		LSXINIC_PMD_ERR("Failed to alloc print buffer");
		return;
	}

	print_len = sprintf(print_buf,
		"Remote buf(0x%lx) len:%d\r\n", remote_addr, len);
	offset = print_len;
	for (i = 0; i < len; i++) {
		print_len = sprintf(&print_buf[offset], "%02x ", virt[i]);
		offset += print_len;
		if ((i + 1) % 16 == 0) {
			print_len = sprintf(&print_buf[offset], "\r\n");
			offset += print_len;
		}
	}
	print_len = sprintf(&print_buf[offset], "\r\n");
	offset += print_len;

	LSXINIC_PMD_INFO("%s", print_buf);
	rte_free(print_buf);
}
#endif

static void
lsxvio_recv_dma_notify(struct lsxvio_queue *vq)
{
	struct lsinic_dma_job *jobs[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_mbuf *mbufs[DEFAULT_BURST_THRESH];
	int ret;
	uint16_t i = 0, bd_num = 0, dma_tbd_nb;
	uint16_t dma_rbd_nb, start_idx = vq->last_avail_idx;
	struct lsxvio_short_desc *sdesc;
	struct lsxvio_queue_entry *rxe;
	struct lsxvio_dma_cntx *dma_cntx;

	start_idx = start_idx & (vq->nb_desc - 1);
	while (1) {
		if (bd_num >= DEFAULT_BURST_THRESH)
			break;

		sdesc = &vq->shadow_sdesc[start_idx];
		if (!sdesc->len)
			break;

		jobs[bd_num] = &vq->dma_jobs[start_idx];
		jobs[bd_num]->src = sdesc->addr_offset + vq->mem_base;
		jobs[bd_num]->src += vq->ob_base;
		jobs[bd_num]->len = sdesc->len;
#ifdef LSXVIO_REMOTE_PKT_DUMP
		lsxvio_dump_remote_buf(vq->adapter, jobs[bd_num]->src,
			jobs[bd_num]->len);
#endif
		bd_num++;
		start_idx = (start_idx + 1) & (vq->nb_desc - 1);
		sdesc->len = 0;
	}

	if (!bd_num)
		goto append_bd_dma;

	ret = rte_pktmbuf_alloc_bulk(vq->mb_pool, mbufs, bd_num);
	if (unlikely(ret))
		return;
	start_idx = vq->last_avail_idx & (vq->nb_desc - 1);
	for (i = 0; i < bd_num; i++) {
		rxe = &vq->sw_ring[start_idx];
		dma_cntx = &vq->dma_sw_cntx[start_idx];

		rxe->mbuf = mbufs[i];
		rxe->len = jobs[i]->len;
		rxe->mbuf->pkt_len = rxe->len;
		rxe->mbuf->data_len = rxe->len;
		rxe->flag = 0;

		jobs[i]->cnxt = (uint64_t)dma_cntx;
		jobs[i]->dst =
			rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbufs[i]));
		start_idx = (start_idx + 1) & (vq->nb_desc - 1);
	}

append_bd_dma:
	dma_rbd_nb = lsxvio_append_bd_dma(vq, &jobs[bd_num]);
	dma_tbd_nb = lsxvio_tx_dma_addr_loop(&jobs[bd_num + dma_rbd_nb],
		vq->adapter);
	if (!(bd_num + dma_rbd_nb + dma_tbd_nb))
		return;

	lsxvio_qdma_multiple_enqueue(vq, jobs,
		bd_num + dma_rbd_nb + dma_tbd_nb);
	vq->last_avail_idx += bd_num;
}

static void
lsxvio_recv_bd_burst(struct lsxvio_queue *vq)
{
	struct lsinic_dma_job *jobs[DEFAULT_BURST_THRESH];
	uint16_t desc_idxs[DEFAULT_BURST_THRESH];
	uint16_t heads[DEFAULT_BURST_THRESH];
	struct rte_mbuf *mbufs[DEFAULT_BURST_THRESH];
	int ret;
	uint16_t free_entries, i = 0, j, avail_idx, desc_idx, bd_num = 0;
	uint16_t tx_bd_nb;
	struct vring_avail *avail;

	if (vq->shadow_avail)
		free_entries = vq->shadow_avail->idx - vq->last_avail_idx;
	else
		free_entries = vq->avail->idx - vq->last_avail_idx;

	if (!free_entries)
		goto tx_addr_dma_read;

	if (vq->flag & LSXVIO_QUEUE_IDX_INORDER_FLAG)
		avail = vq->shadow_avail;
	else
		avail = vq->avail;

	for (i = 0; i < free_entries; i++) {
		avail_idx = (vq->last_avail_idx + i) & (vq->nb_desc - 1);
		desc_idx = avail->ring[avail_idx];
		heads[bd_num] = 1;
		j = 0;
		do {
			desc_idxs[bd_num] = desc_idx;
			bd_num++;
			j++;
			if (!vq->shadow_vdesc)
				break;
			if (likely(!(vq->shadow_vdesc[desc_idx].flags &
				VRING_DESC_F_NEXT)))
				break;
			desc_idx = vq->vdesc[desc_idx].next;
			if (bd_num < DEFAULT_BURST_THRESH)
				heads[bd_num] = 0;
		} while (1);

		if (bd_num >= DEFAULT_BURST_THRESH) {
			i++;
			break;
		}
	}

	ret = rte_pktmbuf_alloc_bulk(vq->mb_pool, mbufs, bd_num);
	if (unlikely(ret))
		return;

	for (j = 0; j < bd_num; j++) {
		jobs[j] = &vq->dma_jobs[desc_idxs[j]];
		lsxvio_recv_one_pkt(vq, desc_idxs[j], heads[j],
			mbufs[j], jobs[j]);
	}

	lsxvio_qdma_append(vq, false);

tx_addr_dma_read:
	tx_bd_nb = lsxvio_tx_dma_addr_loop(&jobs[bd_num],
		vq->adapter);
	if ((bd_num + tx_bd_nb) == 0)
		return;

	lsxvio_qdma_multiple_enqueue(vq, jobs,
		bd_num + tx_bd_nb);
	vq->last_avail_idx += i;
}

static void
lsxvio_recv_bd(struct lsxvio_queue *vq)
{
	uint16_t free_entries, i, avail_idx, desc_idx, head, bd_num = 0;
	uint16_t tx_bd_nb;
	struct vring_avail *avail;
	struct lsinic_dma_job *jobs[DEFAULT_BURST_THRESH];

	if (vq->shadow_avail)
		free_entries = vq->shadow_avail->idx - vq->last_avail_idx;
	else
		free_entries = vq->avail->idx - vq->last_avail_idx;

	if (free_entries == 0)
		goto tx_addr_dma_read;

	if (vq->flag & LSXVIO_QUEUE_IDX_INORDER_FLAG)
		avail = vq->shadow_avail;
	else
		avail = vq->avail;

	for (i = 0; i < free_entries; i++) {
		avail_idx = (vq->last_avail_idx + i) & (vq->nb_desc - 1);
		desc_idx = avail->ring[avail_idx];
		head = 1;
		LSXINIC_PMD_DBG("avail_idx=%d, desc_idx=%d free_entries=%d",
			avail_idx, desc_idx, free_entries);
		/** Currently no indirect support. */
		do {
			jobs[bd_num] = &vq->dma_jobs[desc_idx];
			lsxvio_recv_one_pkt(vq, desc_idx, head,
				NULL, jobs[bd_num]);
			head = 0;
			bd_num++;
			if (!vq->shadow_vdesc)
				break;
			if (likely(!(vq->shadow_vdesc[desc_idx].flags &
				VRING_DESC_F_NEXT)))
				break;
			desc_idx = vq->vdesc[desc_idx].next;
		} while (1);

		if (bd_num >= DEFAULT_BURST_THRESH) {
			i++;
			break;
		}
	}

tx_addr_dma_read:
	tx_bd_nb = lsxvio_tx_dma_addr_loop(&jobs[bd_num],
		vq->adapter);
	if ((bd_num + tx_bd_nb) == 0)
		return;

	lsxvio_qdma_multiple_enqueue(vq, jobs,
		bd_num + tx_bd_nb);
	vq->last_avail_idx += i;
}

static bool
lsxvio_queue_running(struct lsxvio_queue *q)
{
	return q->status == LSXVIO_QUEUE_RUNNING;
}

static uint16_t
lsxvio_recv_pkts_no_dma_rsp(struct lsxvio_queue *rxq)
{
	uint16_t used_idx, bd_num = 0, start_from, size, idx;
	struct lsxvio_queue_entry *sw_bd, *next_sw_bd;

	used_idx = rxq->last_used_idx & (rxq->nb_desc - 1);
	sw_bd = &rxq->sw_ring[used_idx];
	start_from = used_idx;
	while (likely(sw_bd->complete &&
		*sw_bd->complete == LSINIC_XFER_COMPLETE_DONE_FLAG)) {
		idx = (rxq->last_used_idx + 1) & (rxq->nb_desc - 1);
		next_sw_bd = &rxq->sw_ring[idx];
		if (likely(next_sw_bd->complete))
			rte_prefetch0(next_sw_bd->complete);
		if (unlikely(((rxq->mtail + 2) & MCACHE_MASK) ==
			rxq->mhead))
			break;
		idx = sw_bd->idx & (rxq->nb_desc - 1);
		if (!(rxq->flag & LSXVIO_QUEUE_IDX_INORDER_FLAG))
			update_shadow_used_ring_split(rxq, idx, 0);
		rxq->mcache[rxq->mtail] = sw_bd->mbuf;
		rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
		rxq->mcnt++;
		bd_num++;
		rte_prefetch0(rte_pktmbuf_mtod(sw_bd->mbuf, void *));
		sw_bd->complete = NULL;
		rxq->last_used_idx++;
		used_idx = rxq->last_used_idx & (rxq->nb_desc - 1);
		sw_bd = &rxq->sw_ring[used_idx];
	}

	if (!bd_num)
		return 0;

	if (rxq->flag & LSXVIO_QUEUE_IDX_INORDER_FLAG)
		goto skip_update_used_ring;

	rxq->shadow_used_idx = 0;

	if (start_from + bd_num <= rxq->nb_desc) {
		do_flush_shadow_used_ring_split(rxq, start_from, 0,
			bd_num);
	} else {
		size = rxq->nb_desc - start_from;
		do_flush_shadow_used_ring_split(rxq, start_from, 0, size);

		 /* update the left half used ring interval [0, left_size] */
		do_flush_shadow_used_ring_split(rxq, 0, size,
			bd_num - size);
	}

skip_update_used_ring:
	rxq->local_used_idx += bd_num;
	rxq->used->idx = rxq->local_used_idx;

	return bd_num;
}

static uint16_t
lsxvio_recv_pkts_in_order(struct lsxvio_queue *rxq)
{
	uint16_t used_idx, bd_num = 0;
	struct lsxvio_queue_entry *sw_bd;

	used_idx = rxq->last_used_idx & (rxq->nb_desc - 1);
	sw_bd = &rxq->sw_ring[used_idx];
	while (likely(sw_bd->dma_complete)) {
		if (unlikely(((rxq->mtail + 2) & MCACHE_MASK) ==
			rxq->mhead))
			break;
		rxq->mcache[rxq->mtail] = sw_bd->mbuf;
		rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
		rxq->mcnt++;
		bd_num++;
		rte_prefetch0(rte_pktmbuf_mtod(sw_bd->mbuf, void *));
		sw_bd->dma_complete = 0;
		rxq->last_used_idx++;
		used_idx = rxq->last_used_idx & (rxq->nb_desc - 1);
		sw_bd = &rxq->sw_ring[used_idx];
	}

	if (!bd_num) {
		/* Skip accessing PCIe*/
		return 0;
	}

	rxq->local_used_idx += bd_num;
	rxq->used->idx = rxq->local_used_idx;

	return bd_num;
}

static void
lsxvio_queue_trigger_interrupt(struct lsxvio_queue *q)
{
	if (!q->msix_vaddr)
		return;

	if (!rte_lsx_pciep_hw_sim_get(q->adapter->pcie_idx)) {
		/* MSI/MSIx */
		rte_lsx_pciep_start_msix(q->msix_vaddr, q->msix_cmd);
	}
}

uint16_t
lsxvio_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	uint16_t nb_rx = 0;
	uint16_t count = 0;
	struct rte_mbuf *rxm;
	struct lsxvio_queue *rxq = rx_queue;
#ifdef RTE_LIBRTE_LSINIC_DEBUG_RX
	uint16_t i;
	char *cpu_virt;
#endif
	uint64_t pkt_old = rxq->packets;

	if (!lsxvio_queue_running(rxq)) {
		/* From now the queue can work. */
		lsxvio_queue_update(rxq);
		if (!lsxvio_queue_running(rxq))
			return 0;
	}

	if (rxq->flag & LSXVIO_QUEUE_DMA_BD_NOTIFY_FLAG) {
		lsxvio_recv_dma_notify(rxq);
	} else {
		if (1)
			lsxvio_recv_bd_burst(rxq);
		else
			lsxvio_recv_bd(rxq);
	}
	if (rxq->flag & LSXVIO_QUEUE_DMA_SILENT_FLAG) {
		lsxvio_recv_pkts_no_dma_rsp(rxq);
	} else if (rxq->flag & LSXVIO_QUEUE_IDX_INORDER_FLAG) {
		lsxvio_rx_dma_dequeue(rxq);
		lsxvio_recv_pkts_in_order(rxq);
	} else {
		lsxvio_rx_dma_dequeue(rxq);
	}

	lsxvio_all_virt_dev_tx_loop();

	if (rxq->mcnt < 1)
		return 0;

	count = RTE_MIN(nb_pkts, rxq->mcnt);

	for (nb_rx = 0; nb_rx < count; nb_rx++) {
		rxm = rxq->mcache[rxq->mhead];
#ifdef RTE_LIBRTE_LSINIC_DEBUG_RX
		cpu_virt = rte_pktmbuf_mtod_offset(rxm, char *, 0);
		LSXINIC_PMD_DBG("recv buf, pf=%d, qid=%d, len=%d",
			rxq->adapter->pf_idx, rxq->queue_id, rxm->pkt_len);
		for (i = 0; i < rxm->pkt_len; i += 4) {
			LSXINIC_PMD_DBG("%x ",
				rte_be_to_cpu_32(*(uint32_t *)(cpu_virt + i)));
		}
		LSXINIC_PMD_DBG("\n");
#endif
		rxm->packet_type = RTE_PTYPE_L3_IPV4;
		rx_pkts[nb_rx] = rxm;
		rxq->mhead = (rxq->mhead + 1) & MCACHE_MASK;
		rxq->mcnt--;
		rxq->bytes += rxm->pkt_len;
		rxq->bytes_fcs +=
			rxm->pkt_len + LSINIC_ETH_FCS_SIZE;
		rxq->bytes_overhead +=
			rxm->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;
	}

	if (rxq->shadow_used_idx)
		flush_shadow_used_ring_split(rxq);

	rxq->packets += nb_rx;

	if (rxq->packets > pkt_old)
		lsxvio_queue_trigger_interrupt(rxq);

	return nb_rx;
}

static uint16_t
lsxvio_tx_dma_dequeue(struct lsxvio_queue *txq)
{
	struct lsinic_dma_job *dma_job;
	struct lsxvio_queue_entry *txe = NULL;
	uint16_t idx, free_idx = 0;
	int i, ret = 0;
	struct rte_mbuf *free_mbufs[LSINIC_QDMA_DQ_MAX_NB];
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB];

	if (txq->pkts_eq == txq->pkts_dq)
		return 0;

	ret = rte_dma_completed(txq->dma_id, txq->dma_vq,
		LSINIC_QDMA_DQ_MAX_NB, idx_completed, NULL);
	if (txq->flag & LSXVIO_QUEUE_DMA_BD_NOTIFY_FLAG)
		goto skip_update_rc;
	for (i = 0; i < ret; i++) {
		dma_job = &txq->dma_jobs[idx_completed[i]];
		txe = (void *)dma_job->cnxt;
		if (txq->flag & LSXVIO_QUEUE_PKD_INORDER_FLAG && txe) {
			struct vring_packed_desc *desc = &txq->pdesc[txe->idx];
			uint64_t *src, *dst;

			src = (uint64_t *)(&txq->shadow_pdesc[txe->idx].len);
			dst = (uint64_t *)(&desc->len);
			*dst = *src;
			free_mbufs[free_idx] = txe->mbuf;
			free_idx++;
			txe->mbuf = NULL;
			txq->next_dma_idx++;
		} else if (txe) {
			idx = txe->idx & (txq->nb_desc - 1);
			/* This should record the completed jobs,
			 * so it need to be updated after got
			 * qdma response.
			 */
			update_shadow_used_ring_split(txq, idx, txe->len);
			free_mbufs[free_idx] = txe->mbuf;
			free_idx++;
			txe->mbuf = NULL;
			txq->next_dma_idx++;
		}
	}

skip_update_rc:
	txq->pkts_dq += ret;

	if (free_idx)
		rte_pktmbuf_free_bulk(free_mbufs, free_idx);

	return ret;
}

static int
lsxvio_xmit_one_pkt(struct lsxvio_queue *vq, uint16_t desc_idx,
	struct rte_mbuf *rxm, uint16_t head,
	struct rte_mbuf **free_mbuf)
{
	struct lsinic_dma_job *dma_job = &vq->dma_jobs[vq->append_dma_idx];
	struct lsxvio_queue_entry *txe = &vq->sw_ring[desc_idx];
	struct vring_desc *vdesc = NULL;
	struct lsxvio_packed_notify *pnotify = NULL;
	uint64_t addr = 0;

	if (free_mbuf)
		*free_mbuf = NULL;
	if (vq->flag & LSXVIO_QUEUE_PKD_INORDER_FLAG) {
		pnotify = vq->packed_notify;
		if (vq->mem_base) {
			if (pnotify->addr_offset[desc_idx] == MAX_U32)
				return -ENOSPC;
			vq->shadow_pdesc[desc_idx].addr = vq->mem_base +
				pnotify->addr_offset[desc_idx];
			pnotify->addr_offset[desc_idx] = MAX_U32;
		} else {
			if (!pnotify->addr[desc_idx])
				return -ENOSPC;
			vq->shadow_pdesc[desc_idx].addr =
				pnotify->addr[desc_idx];
			pnotify->addr[desc_idx] = 0;
		}

		addr = vq->shadow_pdesc[desc_idx].addr;
		vq->shadow_pdesc[desc_idx].flags = vq->cached_flags;
		vq->shadow_pdesc[desc_idx].len = rxm->pkt_len +
			vq->adapter->vtnet_hdr_size;
		if (txe->mbuf) {
			if (free_mbuf)
				*free_mbuf = txe->mbuf;
			else
				rte_pktmbuf_free(txe->mbuf);
		}
	} else {
		vdesc = &vq->vdesc[desc_idx];
		addr = vdesc->addr;
	}

	/* rxm is ret_mbuf passed to upper layer */
	txe->mbuf = rxm;
	txe->flag = head;
	txe->len = rxm->pkt_len;

	dma_job->cnxt = (uint64_t)txe;
	dma_job->src = rte_mbuf_data_iova(rxm);
	dma_job->dst = addr + vq->ob_base;
	dma_job->len = rxm->pkt_len;

	vq->jobs_pending++;
	vq->append_dma_idx = (vq->append_dma_idx + 1) & (vq->nb_desc - 1);
	LSXINIC_PMD_DBG("xmit src=%lx, dest=%lx, len=%d, pending=%d",
		dma_job->src, dma_job->dest, dma_job->len, vq->jobs_pending);

	return 0;
}

static void lsxvio_tx_loop(struct lsxvio_adapter *adapter)
{
	struct lsxvio_queue *q, *tq;
	uint32_t this_core = rte_lcore_id();

	RTE_TAILQ_FOREACH_SAFE(q, &adapter->txq_list[this_core], next, tq) {
		if (!lsxvio_queue_running(q)) {
			/* From now the queue can work. */
			lsxvio_queue_update(q);
			if (!lsxvio_queue_running(q))
				return;
		}

		if (!(q->flag & LSXVIO_QUEUE_DMA_SILENT_FLAG)
			&& q->pkts_eq > q->pkts_dq) {
			lsxvio_tx_dma_dequeue(q);
			if (!(q->flag & LSXVIO_QUEUE_PKD_INORDER_FLAG) &&
				q->shadow_used_idx) {
				flush_shadow_used_ring_split(q);
				lsxvio_queue_trigger_interrupt(q);
			}
		}

		if (q->packets == q->packets_old)
			lsxvio_qdma_append(q, false);
		q->packets_old = q->packets;

		q->loop_total++;
	}
}

static void lsxvio_all_virt_dev_tx_loop(void)
{
	struct rte_lsx_pciep_device *dev;
	struct lsxvio_adapter *adapter;
	enum lsinic_dev_type *dev_type;

	dev = rte_lsx_pciep_first_dev();
	while (dev) {
		dev_type = dev->eth_dev->data->dev_private;
		if (*dev_type != LSINIC_VIRTIO_DEV) {
			dev = (struct rte_lsx_pciep_device *)
					TAILQ_NEXT(dev, next);
			continue;
		}
		adapter = dev->eth_dev->data->dev_private;
		lsxvio_tx_loop(adapter);
		dev = (struct rte_lsx_pciep_device *)
			TAILQ_NEXT(dev, next);
	}
}

#define LSXVIO_XMIT_PACKED_AVAIL_THRESHOLD 32
static uint16_t
lsxvio_xmit_pkts_packed_burst(struct lsxvio_queue *vq,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint16_t tx_num = 0, avail_idx;
	int ret;
	uint16_t free_idx = 0;
	struct rte_mbuf *free_pkts[nb_pkts];

	while (1) {
		avail_idx = vq->last_avail_idx;
		ret = lsxvio_xmit_one_pkt(vq, avail_idx,
			tx_pkts[tx_num], 1, &free_pkts[free_idx]);
		if (free_pkts[free_idx])
			free_idx++;
		if (ret)
			break;
		vq->bytes += tx_pkts[tx_num]->pkt_len;
		vq->bytes_fcs +=
			tx_pkts[tx_num]->pkt_len +
				LSINIC_ETH_FCS_SIZE;
		vq->bytes_overhead +=
			tx_pkts[tx_num]->pkt_len +
				LSINIC_ETH_OVERHEAD_SIZE;
		tx_num++;
		nb_pkts--;
		vq->packets++;
		vq->last_avail_idx++;
		if (unlikely(vq->last_avail_idx >= vq->nb_desc)) {
			vq->cached_flags ^= VRING_PACKED_DESC_F_AVAIL_USED;
			vq->last_avail_idx -= vq->nb_desc;
		}
		if (!nb_pkts)
			break;
	}

	if (free_idx)
		rte_pktmbuf_free_bulk(free_pkts, free_idx);
	lsxvio_qdma_append(vq, true);

	return tx_num;
}

static uint16_t
lsxvio_xmit_pkts_burst(struct lsxvio_queue *vq,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint16_t tx_num = 0, free_entries, i, j, avail_idx, desc_idx, head;
	struct lsinic_dma_job *jobs[LSINIC_QDMA_EQ_MAX_NB];

	free_entries = vq->avail->idx - vq->last_avail_idx;
	if (free_entries == 0)
		return 0;

	for (i = 0; (i < free_entries) && nb_pkts; i++) {
		avail_idx = (vq->last_avail_idx + i) & (vq->nb_desc - 1);
		desc_idx = vq->avail->ring[avail_idx];
		head = 1;

		/** Currently no indirect support. */
		j = 0;
		while (1) {
			lsxvio_xmit_one_pkt(vq, desc_idx,
				tx_pkts[tx_num], head, NULL);
			vq->bytes += tx_pkts[tx_num]->pkt_len;
			vq->bytes_fcs +=
				tx_pkts[tx_num]->pkt_len +
				LSINIC_ETH_FCS_SIZE;
			vq->bytes_overhead +=
				tx_pkts[tx_num]->pkt_len +
				LSINIC_ETH_OVERHEAD_SIZE;
			jobs[tx_num] = &vq->dma_jobs[desc_idx];
			j++;
			tx_num++;
			nb_pkts--;
			vq->packets++;
			if ((vq->vdesc[desc_idx].flags &
				VRING_DESC_F_NEXT) == 0)
				break;
			desc_idx = vq->vdesc[desc_idx].next;
			head = 0;
		}
	}

	lsxvio_qdma_multiple_enqueue(vq, jobs, tx_num);
	vq->last_avail_idx += i;

	return tx_num;
}

uint16_t
lsxvio_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct lsxvio_queue *txq;

	txq = tx_queue;

	if (!lsxvio_queue_running(txq)) {
		/* From now the queue can work. */
		lsxvio_queue_update(txq);
		if (!lsxvio_queue_running(txq))
			return 0;
	}

	txq->loop_avail++;

	if (txq->flag & LSXVIO_QUEUE_PKD_INORDER_FLAG) {
		return lsxvio_xmit_pkts_packed_burst(txq, tx_pkts,
			nb_pkts);
	}

	/* TX loop */
	return lsxvio_xmit_pkts_burst(txq, tx_pkts, nb_pkts);
}
