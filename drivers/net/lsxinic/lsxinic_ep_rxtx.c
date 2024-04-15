/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

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
#include <rte_lsx_pciep_bus.h>
#include <portal/dpaa2_hw_pvt.h>

#include "lsxinic_common_pmd.h"
#include "lsxinic_common.h"
#include "lsxinic_common_reg.h"
#include "lsxinic_ep_ethdev.h"
#include "lsxinic_ep_rxtx.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_ep_dma.h"

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
#include <fsl_qbman_portal.h>
#include <portal/dpaa2_hw_dpio.h>
#include <dpaa2_hw_mempool.h>
#include <dpaa2_ethdev.h>
#include "base/dpaa2_hw_dpni_annot.h"
#endif

/* Default RS bit threshold values */
#ifndef DEFAULT_TX_RS_THRESH
#define DEFAULT_TX_RS_THRESH   32
#endif
#ifndef DEFAULT_TX_FREE_THRESH
#define DEFAULT_TX_FREE_THRESH 32
#endif

#define NIC_RX_BUFFER_SIZE 0x200

/* Rings setup and release.
 *
 * TDBA/RDBA should be aligned on 16 byte boundary. But TDLEN/RDLEN should be
 * multiple of 128 bytes. So we align TDBA/RDBA on 128 byte boundary. This will
 * also optimize cache line size effect. H/W supports up to cache line size 128.
 */
#define LSINIC_ALIGN 128

/* Maximum number of Ring Descriptors.
 *
 * Since RDLEN/TDLEN should be multiple of 128 bytes, the number of ring
 * descriptors should meet the following condition:
 *      (num_ring_desc * sizeof(rx/tx descriptor)) % 128 == 0
 */
#define LSINIC_MIN_RING_DESC 64
#define LSINIC_MAX_RING_DESC 1024

/* TX queues list */
TAILQ_HEAD(lsinic_tx_queue_list, lsinic_queue);

/* per thread TX queue list */
static RTE_DEFINE_PER_LCORE(uint8_t,
	lsinic_txq_list_initialized);
static RTE_DEFINE_PER_LCORE(uint8_t,
	lsinic_txq_deqeue_from_rxq);
static RTE_DEFINE_PER_LCORE(uint8_t,
	lsinic_txq_num_in_list);
static RTE_DEFINE_PER_LCORE(struct lsinic_tx_queue_list,
	lsinic_txq_list);
static RTE_DEFINE_PER_LCORE(pthread_t, pthrd_id);

static int s_lsx_tx_busy_log;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
struct lsinic_recycle_dev {
	TAILQ_ENTRY(lsinic_recycle_dev) next;
	struct rte_eth_dev *recycle_dev;
	int used;
};

TAILQ_HEAD(lsinic_recycle_dev_list, lsinic_recycle_dev);

static struct lsinic_recycle_dev_list recycle_dev_list =
	TAILQ_HEAD_INITIALIZER(recycle_dev_list);

static rte_spinlock_t recycle_dev_list_lock =
	RTE_SPINLOCK_INITIALIZER;
#endif

static int
lsinic_queue_start(struct lsinic_queue *q);

static inline int
lsinic_tx_bd_available(struct lsinic_queue *txq,
	uint16_t bd_idx);

static void
lsinic_txq_loop(uint16_t dq_sync);

static bool
lsinic_queue_running(struct lsinic_queue *q)
{
	return q->status == LSINIC_QUEUE_RUNNING;
}

static bool
lsinic_queue_msi_masked(struct lsinic_queue *q)
{
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(q->adapter->hw_addr, LSINIC_RCS_REG_OFFSET);

	return rcs_reg->msix_mask[q->msix_irq];
}

static inline void lsinic_mbuf_reset(struct rte_mbuf *m)
{
	struct rte_mempool *mp = m->pool;
	uint32_t mbuf_size, buf_len;
	uint16_t priv_size;

	priv_size = rte_pktmbuf_priv_size(mp);
	mbuf_size = (uint32_t)(sizeof(struct rte_mbuf) + priv_size);
	buf_len = rte_pktmbuf_data_room_size(mp);

	m->priv_size = priv_size;
	m->buf_addr = (char *)m + mbuf_size;
	m->buf_iova = rte_mempool_virt2iova(m) + mbuf_size;
	m->buf_len = (uint16_t)buf_len;
	rte_pktmbuf_reset_headroom(m);
	m->data_len = 0;
	m->ol_flags = 0;
}

static __rte_always_inline void
lsinic_lbd_dma_start_update(struct lsinic_queue *queue,
	uint16_t used_idx)
{
	queue->local_src_bd_desc[used_idx].bd_status &=
		~((uint32_t)RING_BD_STATUS_MASK);
	queue->local_src_bd_desc[used_idx].bd_status |=
		RING_BD_HW_PROCESSING;
}

static void
lsinic_queue_dma_release(struct lsinic_queue *q)
{
	if (q->dma_jobs) {
		rte_free(q->dma_jobs);
		q->dma_jobs = NULL;
	}

	if (q->dma_seg_jobs) {
		rte_free(q->dma_seg_jobs);
		q->dma_seg_jobs = NULL;
	}
}

static int
lsinic_queue_dma_create(struct lsinic_queue *q)
{
	uint32_t i;
	int pcie_id = q->adapter->pcie_idx;
	int pf_id = q->adapter->pf_idx;
	int is_vf = q->adapter->is_vf;
	int vf_id = q->adapter->vf_idx;
	uint16_t *pvq;
	int ret, dma_id;

	if (q->dma_vq >= 0)
		return 0;

	if (q->type == LSINIC_QUEUE_RX) {
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

	q->qdma_config.nb_desc = LSINIC_BD_DMA_MAX_COUNT;

	for (i = 0; i < LSINIC_BD_DMA_MAX_COUNT; i++)
		q->dma_jobs[i].idx = i;

	ret = rte_dma_vchan_setup(dma_id, *pvq, &q->qdma_config);
	if (ret)
		return ret;
	q->dma_vq = *pvq;
	(*pvq)++;
	q->dma_id = dma_id;

	q->dma_bd_update = 0;
	if (q->type == LSINIC_QUEUE_TX) {
		if (q->adapter->ep_cap & LSINIC_EP_CAP_TXQ_BD_DMA_UPDATE)
			q->dma_bd_update |= DMA_BD_EP2RC_UPDATE;
	} else {
		if (q->adapter->cap & LSINIC_CAP_RC_XFER_BD_DMA_UPDATE)
			q->dma_bd_update |= DMA_BD_RC2EP_UPDATE;
	}

	return 0;
}

static int
lsinic_queue_dma_clean(struct lsinic_queue *q)
{
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB];
	int ret, i;

	if (q->pkts_eq == q->pkts_dq ||
		(q->type == LSINIC_QUEUE_TX &&
		q->adapter->txq_dma_silent) ||
		(q->type == LSINIC_QUEUE_RX &&
		q->adapter->rxq_dma_silent))
		return 0;

	ret = rte_dma_completed(q->dma_id, q->dma_vq,
		LSINIC_QDMA_DQ_MAX_NB, idx_completed, NULL);
	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < q->nb_desc)
			q->pkts_dq++;
	}

	if (q->pkts_eq != q->pkts_dq) {
		LSXINIC_PMD_WARN("port%d %sq%d %ld pkts in dma",
			q->port_id,
			q->type == LSINIC_QUEUE_TX ? "tx" : "rx",
			q->reg_idx, q->pkts_eq - q->pkts_dq);

		return -EAGAIN;
	}

	return 0;
}

/* (Re)set dynamic lsinic queue fields to defaults */
void
lsinic_queue_reset(struct lsinic_queue *q)
{
	struct lsinic_sw_bd *xe = q->sw_ring;
	struct lsinic_dma_job *dma_jobs = q->dma_jobs;
	uint32_t i;

	q->ep_reg->cir = 0;
	if (q->rc_reg)
		LSINIC_WRITE_REG(&q->rc_reg->cir, 0);
	/* Initialize SW ring entries */
	for (i = 0; i < q->nb_desc; i++) {
		xe[i].mbuf = NULL;
		xe[i].my_idx = i;
		if (q->type == LSINIC_QUEUE_TX &&
			q->rc_mem_bd_type == RC_MEM_SEG_LEN)
			xe[i].dma_complete = 1;
		dma_jobs[i].cnxt = (uint64_t)(&xe[i]);
	}

	q->next_dma_idx = 0;
	q->next_avail_idx = 0;
	q->next_used_idx = 0;
	q->errors = 0;
	q->drop_packet_num = 0;
	q->ring_full = 0;
	q->loop_total = 0;
	q->loop_avail = 0;

	q->jobs_pending = 0;
	q->jobs_avail_idx = 0;
	q->mhead = 0;
	q->mtail = 0;
	q->mcnt = 0;
}

static inline void
lsinic_qdma_rx_seg_enqueue(struct lsinic_queue *queue)
{
	int ret = -1;
	uint16_t nb_jobs = 0, jobs_idx, i, jobs_avail_idx, j;
	struct rte_dma_sge src[LSINIC_QDMA_EQ_DATA_MAX_NB];
	struct rte_dma_sge dst[LSINIC_QDMA_EQ_DATA_MAX_NB];
	struct lsinic_dma_seg_job *job;
	uint32_t len_total = 0;
	uint64_t flags;

	/* Qdma multi-enqueue support, max enqueue 32 entries once.
	 * if there are 32 entries or time out, handle them in batch
	 */

	jobs_avail_idx = queue->jobs_avail_idx;
	nb_jobs = queue->jobs_pending;

	if (!nb_jobs)
		return;

	for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
		jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
		job = &queue->dma_seg_jobs[jobs_idx];
		for (j = 0; j < job->seg_nb; j++) {
			queue->dma_idx[j] = jobs_idx;
			src[j].addr = job->src[j];
			src[j].length = job->len[j];
			dst[j].addr = job->dst[j];
			dst[j].length = job->len[j];
			len_total += job->len[j];
		}
		flags = RTE_DPAAX_QDMA_SG_SUBMIT(queue->dma_idx,
			RTE_DMA_OP_FLAG_SUBMIT);
		ret = rte_dma_copy_sg(queue->dma_id,
			queue->dma_vq, src, dst,
			job->seg_nb, job->seg_nb, flags);
		if (likely(ret >= 0)) {
			queue->pkts_eq += job->seg_nb;
		} else {
			queue->errors++;
			return;
		}
	}

	queue->jobs_pending -= nb_jobs;
	queue->jobs_avail_idx += nb_jobs;
	queue->bytes_eq += len_total;
}

static inline void
lsinic_qdma_tx_seg_enqueue(struct lsinic_queue *queue)
{
	int ret;
	uint16_t jobs_idx, i, jobs_avail_idx;
	struct rte_dma_sge src[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_dma_sge dst[LSINIC_QDMA_EQ_MAX_NB];
	struct lsinic_dma_job *bd_job = NULL;
	struct lsinic_dma_job *e2r_bd_jobs;
	struct lsinic_dma_seg_job *seg_job;
	uint16_t sg_nb = 0;
	uint32_t txq_dma_bd_start = queue->wdma_bd_start;
	uint32_t total_len = 0;
	uint64_t flags;

	jobs_avail_idx = queue->jobs_avail_idx;

	if (!queue->jobs_pending)
		return;

	e2r_bd_jobs = &queue->dma_jobs[LSINIC_E2R_BD_DMA_START];

	if (queue->dma_bd_update & DMA_BD_EP2RC_UPDATE) {
		bd_job = &e2r_bd_jobs[txq_dma_bd_start];
		bd_job->len = queue->wdma_bd_len;
	}

	jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);

	seg_job = &queue->dma_seg_jobs[jobs_idx];

	for (i = 0; i < seg_job->seg_nb; i++) {
		queue->dma_idx[i] = jobs_idx;
		src[i].addr = seg_job->src[i];
		src[i].length = seg_job->len[i];
		dst[i].addr = seg_job->dst[i];
		dst[i].length = seg_job->len[i];
		total_len += seg_job->len[i];
	}
	sg_nb = seg_job->seg_nb;

	if (bd_job) {
		queue->dma_idx[seg_job->seg_nb] = bd_job->idx;
		src[seg_job->seg_nb].addr = bd_job->src;
		src[seg_job->seg_nb].length = bd_job->len;
		dst[seg_job->seg_nb].addr = bd_job->dst;
		dst[seg_job->seg_nb].length = bd_job->len;
		sg_nb++;
	}

	flags = RTE_DPAAX_QDMA_SG_SUBMIT(queue->dma_idx,
			RTE_DMA_OP_FLAG_SUBMIT);
	ret = rte_dma_copy_sg(queue->dma_id, queue->dma_vq,
			src, dst, sg_nb, sg_nb, flags);
	if (likely(ret >= 0)) {
		queue->jobs_pending--;
		queue->jobs_avail_idx++;
		queue->bytes_eq += total_len;
		queue->pkts_eq += seg_job->seg_nb;
	} else {
		LSXINIC_PMD_ERR("LSINIC QDMA enqueue failed!");
		queue->errors++;
	}

	queue->wdma_bd_start = LSINIC_BD_DMA_START_FLAG;
}

static void
lsinic_rxq_print_bd_desc(struct lsinic_queue *queue,
	uint16_t idx, int is_ep)
{
	char print_buf[2048];
	uint16_t str_len;

	sprintf(print_buf, "RXQ%d:\r\n", queue->queue_id);
	str_len = strlen(print_buf);
	if (is_ep && queue->ep_bd_desc) {
		sprintf(&print_buf[str_len],
			"%s[%d]:%s:0x%lx,%s:0x%08x,%s:0x%08x\r\n",
			"EP lsinic_bd_desc", idx,
			"pkt_addr", queue->ep_bd_desc[idx].pkt_addr,
			"len_cmd", queue->ep_bd_desc[idx].len_cmd,
			"bd_status", queue->ep_bd_desc[idx].bd_status);
		str_len = strlen(print_buf);
	}
	if (is_ep && queue->rx_src_addrl) {
		sprintf(&print_buf[str_len],
			"%s[%d]:%s:0x%08x,%s:0x%08x\r\n",
			"EP lsinic_ep_rx_src_addrl", idx,
			"pkt_addr_low",
			queue->rx_src_addrl[idx].pkt_addr_low,
			"len_cmd",
			queue->rx_src_addrl[idx].len_cmd);
		str_len = strlen(print_buf);
	}
	if (is_ep && queue->rx_src_addrx) {
		sprintf(&print_buf[str_len],
			"%s[%d]:%s:0x%04x,%s:0x%04x\r\n",
			"EP lsinic_ep_rx_src_addrx", idx,
			"pkt_idx",
			queue->rx_src_addrx[idx].pkt_idx,
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
			"len_cmd",
			queue->rx_src_addrx[idx].len_cmd);
#else
			"len",
			queue->rx_src_addrx[idx].len);
#endif
		str_len = strlen(print_buf);
	}

	if (!is_ep && queue->rc_bd_desc) {
		sprintf(&print_buf[str_len],
			"%s[%d]:%s:0x%lx,%s:0x%08x,%s:0x%08x\r\n",
			"RC lsinic_bd_desc", idx,
			"pkt_addr", queue->rc_bd_desc[idx].pkt_addr,
			"len_cmd", queue->rc_bd_desc[idx].len_cmd,
			"bd_status", queue->rc_bd_desc[idx].bd_status);
		str_len = strlen(print_buf);
	}
	if (!is_ep && queue->rc_rx_src_addrl) {
		sprintf(&print_buf[str_len],
			"%s[%d]:%s:0x%08x,%s:0x%08x\r\n",
			"RC lsinic_ep_rx_src_addrl", idx,
			"pkt_addr_low",
			queue->rc_rx_src_addrl[idx].pkt_addr_low,
			"len_cmd",
			queue->rc_rx_src_addrl[idx].len_cmd);
		str_len = strlen(print_buf);
	}
	if (!is_ep && queue->rc_rx_src_addrx) {
		sprintf(&print_buf[str_len],
			"%s[%d]:%s:0x%04x,%s:0x%04x\r\n",
			"RC lsinic_ep_rx_src_addrx", idx,
			"pkt_idx",
			queue->rc_rx_src_addrx[idx].pkt_idx,
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
			"len_cmd",
			queue->rc_rx_src_addrx[idx].len_cmd);
#else
			"len",
			queue->rc_rx_src_addrx[idx].len);
#endif
	}
	if (is_ep)
		LSXINIC_PMD_INFO("local %s", print_buf);
	else
		LSXINIC_PMD_INFO("remote %s", print_buf);
}

static void
lsinic_txq_print_bd_desc(struct lsinic_queue *queue,
	uint16_t idx, int is_ep)
{
	char print_buf[2048];
	uint16_t str_len;

	sprintf(print_buf, "TXQ%d:\r\n", queue->queue_id);
	str_len = strlen(print_buf);
	if (is_ep && queue->ep_bd_desc) {
		sprintf(&print_buf[str_len],
			"%s[%d]:%s:0x%lx,%s:0x%08x,%s:0x%08x\r\n",
			"EP lsinic_bd_desc", idx,
			"pkt_addr", queue->ep_bd_desc[idx].pkt_addr,
			"len_cmd", queue->ep_bd_desc[idx].len_cmd,
			"bd_status", queue->ep_bd_desc[idx].bd_status);
		str_len = strlen(print_buf);
	}
	if (is_ep && queue->tx_dst_addr) {
		sprintf(&print_buf[str_len],
			"%s[%d]:%s:0x%lx\r\n",
			"EP lsinic_ep_tx_dst_addr", idx,
			"pkt_addr",
			queue->tx_dst_addr[idx].pkt_addr);
		str_len = strlen(print_buf);
	}

	if (!is_ep && queue->rc_bd_desc) {
		sprintf(&print_buf[str_len],
			"%s[%d]:%s:0x%lx,%s:0x%08x,%s:0x%08x\r\n",
			"RC lsinic_bd_desc", idx,
			"pkt_addr", queue->rc_bd_desc[idx].pkt_addr,
			"len_cmd", queue->rc_bd_desc[idx].len_cmd,
			"bd_status", queue->rc_bd_desc[idx].bd_status);
		str_len = strlen(print_buf);
	}
	if (!is_ep && queue->rc_tx_dst_addr) {
		sprintf(&print_buf[str_len],
			"%s[%d]:%s:0x%lx\r\n",
			"RC lsinic_ep_tx_dst_addr", idx,
			"pkt_addr",
			queue->rc_tx_dst_addr[idx].pkt_addr);
		str_len = strlen(print_buf);
	}

	if (is_ep)
		LSXINIC_PMD_INFO("local %s", print_buf);
	else
		LSXINIC_PMD_INFO("remote %s", print_buf);
}

static inline void
lsinic_rxq_print_remote_bd(struct lsinic_queue *q,
	uint32_t ep_cap, uint32_t start, uint32_t end)
{
	if (likely(!(ep_cap & LSINIC_EP_CAP_RXQ_BD_DMA_UPDATE_DBG)))
		return;

	while (start != end) {
		lsinic_rxq_print_bd_desc(q, start, 0);
		start = (start + 1) & (q->nb_desc - 1);
	}
}

static inline void
lsinic_txq_print_remote_bd(struct lsinic_queue *q,
	uint32_t ep_cap, uint32_t start, uint32_t end)
{
	if (likely(!(ep_cap & LSINIC_EP_CAP_TXQ_ADDR_DMA_READ_DBG)))
		return;

	while (start != end) {
		lsinic_txq_print_bd_desc(q, start, 0);
		start = (start + 1) & (q->nb_desc - 1);
	}
}

static inline void
lsinic_rxq_print_local_bd(struct lsinic_queue *q,
	uint32_t ep_cap, uint32_t start, uint32_t end,
	uint32_t delay_ms)
{
	if (likely(!(ep_cap & LSINIC_EP_CAP_RXQ_BD_DMA_UPDATE_DBG)))
		return;

	if (delay_ms && start != end)
		rte_delay_ms(delay_ms);
	while (start != end) {
		lsinic_rxq_print_bd_desc(q, start, 1);
		start = (start + 1) & (q->nb_desc - 1);
	}
}

static inline void
lsinic_txq_print_local_bd(struct lsinic_queue *q,
	uint32_t ep_cap, uint32_t start, uint32_t end,
	uint32_t delay_ms)
{
	if (likely(!(ep_cap & LSINIC_EP_CAP_TXQ_ADDR_DMA_READ_DBG)))
		return;

	if (delay_ms && start != end)
		rte_delay_ms(delay_ms);
	while (start != end) {
		lsinic_txq_print_bd_desc(q, start, 1);
		start = (start + 1) & (q->nb_desc - 1);
	}
}

static inline void
lsinic_rxq_dma_eq(void *q, int append, int dma_bd)
{
	struct lsinic_queue *queue = q;
	struct lsinic_queue *txq = queue->pair;
	int ret, loop;
	uint16_t nb_jobs = 0, jobs_idx, i, jobs_avail_idx, j, k, dq;
	struct rte_dma_sge src[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_dma_sge dst[LSINIC_QDMA_EQ_MAX_NB];
	uint16_t max_jobs_nb, bd_jobs_nb = 0, bd_size, txq_bd_jobs_nb = 0;
	uint32_t ep_cap = queue->adapter->ep_cap;
	struct lsinic_dma_job *job, *bd_jobs[2], *bd_job_base;
	struct lsinic_dma_job *txq_bd_jobs[2];
	uint32_t len_total = 0, last_pir = 0, pir = 0;
	uint32_t txq_last_pir = 0, txq_pir = 0;
	uint64_t flags;

	/* Qdma multi-enqueue support, max enqueue 32 entries once.
	 * if there are 32 entries or time out, handle them in batch
	 */

	jobs_avail_idx = queue->jobs_avail_idx;
	max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB;
	if (queue->dma_bd_update & DMA_BD_RC2EP_UPDATE)
		max_jobs_nb -= 2;
	if (txq && (txq->dma_bd_update & DMA_BD_RC2EP_UPDATE))
		max_jobs_nb -= 2;

	if (!append) {
		nb_jobs = queue->jobs_pending;
		if (nb_jobs > max_jobs_nb)
			nb_jobs = max_jobs_nb;
	} else {
		if (queue->jobs_pending >= max_jobs_nb)
			nb_jobs = max_jobs_nb;
	}

	if ((queue->dma_bd_update & DMA_BD_RC2EP_UPDATE) &&
		(dma_bd || nb_jobs)) {
		last_pir = queue->rdma_bd_start;
		pir = queue->ep_reg->pir;
		bd_job_base = &queue->dma_jobs[LSINIC_R2E_BD_DMA_START];
		bd_jobs[0] = &bd_job_base[last_pir];
		bd_jobs[1] = &bd_job_base[0];
		bd_size = queue->rdma_bd_len;
		if (pir > last_pir) {
			bd_jobs_nb = 1;
			bd_jobs[0]->len = (pir - last_pir) * bd_size;
		} else if (pir < last_pir) {
			bd_jobs[0]->len = (queue->nb_desc - last_pir) * bd_size;
			bd_jobs[1]->len = pir * bd_size;
			if (pir > 0)
				bd_jobs_nb = 2;
			else
				bd_jobs_nb = 1;
		}
		lsinic_rxq_print_remote_bd(queue, ep_cap, last_pir, pir);
	}

	nb_jobs += bd_jobs_nb;

	if (txq && (txq->dma_bd_update & DMA_BD_RC2EP_UPDATE) &&
		(dma_bd || nb_jobs)) {
		txq_last_pir = txq->rdma_bd_start;
		txq_pir = txq->ep_reg->pir;
		bd_job_base = &txq->dma_jobs[LSINIC_R2E_BD_DMA_START];
		txq_bd_jobs[0] = &bd_job_base[txq_last_pir];
		txq_bd_jobs[1] = &bd_job_base[0];
		bd_size = txq->rdma_bd_len;
		if (txq_pir > txq_last_pir) {
			txq_bd_jobs_nb = 1;
			txq_bd_jobs[0]->len =
				(txq_pir - txq_last_pir) * bd_size;
		} else if (txq_pir < txq_last_pir) {
			txq_bd_jobs[0]->len =
				(txq->nb_desc - txq_last_pir) * bd_size;
			txq_bd_jobs[1]->len = txq_pir * bd_size;
			if (txq_pir > 0)
				txq_bd_jobs_nb = 2;
			else
				txq_bd_jobs_nb = 1;
		}
		lsinic_txq_print_remote_bd(txq, ep_cap, txq_last_pir, txq_pir);
	}

	nb_jobs += txq_bd_jobs_nb;

	if (!nb_jobs)
		return;

	for (i = 0; i < nb_jobs - bd_jobs_nb - txq_bd_jobs_nb;
		i++, jobs_avail_idx++) {
		jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
		job = &queue->dma_jobs[jobs_idx];
		queue->dma_idx[i] = job->idx;
		src[i].addr = queue->dma_jobs[jobs_idx].src;
		src[i].length = job->len;
		dst[i].addr = queue->dma_jobs[jobs_idx].dst;
		dst[i].length = job->len;
		len_total += job->len;
	}

	for (j = 0; j < bd_jobs_nb; j++) {
		queue->dma_idx[i + j] = bd_jobs[j]->idx;
		src[i + j].addr = bd_jobs[j]->src;
		src[i + j].length = bd_jobs[j]->len;
		dst[i + j].addr = bd_jobs[j]->dst;
		dst[i + j].length = bd_jobs[j]->len;
	}

	for (k = 0; k < txq_bd_jobs_nb; k++) {
		queue->dma_idx[i + j + k] = txq_bd_jobs[k]->idx;
		src[i + j + k].addr = txq_bd_jobs[k]->src;
		src[i + j + k].length = txq_bd_jobs[k]->len;
		dst[i + j + k].addr = txq_bd_jobs[k]->dst;
		dst[i + j + k].length = txq_bd_jobs[k]->len;
	}

eq_again:
	if (ep_cap & LSINIC_EP_CAP_RXQ_SG_DMA) {
		flags = RTE_DPAAX_QDMA_SG_SUBMIT(queue->dma_idx,
			RTE_DMA_OP_FLAG_SUBMIT);
		ret = rte_dma_copy_sg(queue->dma_id,
			queue->dma_vq, src, dst,
			nb_jobs, nb_jobs, flags);
	} else {
		for (i = 0; i < nb_jobs; i++) {
			flags = RTE_DPAAX_QDMA_COPY_SUBMIT(queue->dma_idx[i],
				0);
			ret = rte_dma_copy(queue->dma_id,
				queue->dma_vq, src[i].addr,
				dst[i].addr, src[i].length, flags);
			if (unlikely(ret < 0))
				break;
		}
		ret = rte_dma_submit(queue->dma_id, queue->dma_vq);
	}
	if (likely(ret >= 0)) {
		nb_jobs -= (bd_jobs_nb + txq_bd_jobs_nb);
		queue->jobs_pending -= nb_jobs;
		queue->jobs_avail_idx += nb_jobs;
		queue->bytes_eq += len_total;
		queue->pkts_eq += nb_jobs;
		queue->bd_eq += (bd_jobs_nb + txq_bd_jobs_nb);
	} else {
		if (!queue->adapter->rxq_dma_silent) {
			loop = 0;
			dq = 0;
			while (!dq) {
				dq = queue->dma_dq(queue);
				loop++;
				if (loop > 1000)
					break;
			}
			if (dq)
				goto eq_again;
		}
		nb_jobs -= (bd_jobs_nb + txq_bd_jobs_nb);
		LSXINIC_PMD_ERR("RXQ rxbd(%d)/txbd(%d)/data(%d)",
			bd_jobs_nb, txq_bd_jobs_nb,
			nb_jobs);
		LSXINIC_PMD_ERR("RXQ BD: eq(%ld)/dq(%ld)",
			queue->bd_eq, queue->bd_dq);
		LSXINIC_PMD_ERR("RXQ PKT: eq(%ld)/dq(%ld)",
			queue->pkts_eq, queue->pkts_dq);
		queue->errors += nb_jobs;
	}
	lsinic_rxq_print_local_bd(queue, ep_cap, last_pir, pir, 100);
	lsinic_txq_print_local_bd(txq, ep_cap, txq_last_pir, txq_pir, 100);

	queue->rdma_bd_start = pir;
	if (txq)
		txq->rdma_bd_start = txq_pir;
}

static inline void
lsinic_txq_dma_eq(void *q, int append)
{
	struct lsinic_queue *queue = q;
	int ret, loop;
	uint16_t nb_jobs = 0, jobs_idx, i, jobs_avail_idx;
	struct rte_dma_sge src[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_dma_sge dst[LSINIC_QDMA_EQ_MAX_NB];
	struct lsinic_dma_job *jobs[LSINIC_QDMA_EQ_MAX_NB];
	struct lsinic_dma_job *e2r_bd_jobs;
	uint16_t txq_bd_jobs_num = 0, dq;
	uint16_t bd_jobs_len, max_jobs_nb;
	uint32_t txq_dma_bd_start = queue->wdma_bd_start;
	uint16_t txq_bd_step = queue->wdma_bd_len;
	struct lsinic_bd_desc *ep_bd_desc = NULL;
	uint32_t ep_cap = queue->adapter->ep_cap;
	uint64_t flags;

	if (queue->dma_bd_update & DMA_BD_EP2RC_UPDATE) {
		/* At most 2 TX DMA bd jobs.*/
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB - 2;
	} else {
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB;
	}

	if (queue->rc_mem_bd_type == RC_MEM_LONG_BD)
		ep_bd_desc = queue->local_src_bd_desc;

	jobs_avail_idx = queue->jobs_avail_idx;

	if (!append) {
		nb_jobs = queue->jobs_pending;
		if (nb_jobs > max_jobs_nb)
			nb_jobs = max_jobs_nb;
	} else if (queue->jobs_pending >= max_jobs_nb) {
		nb_jobs = max_jobs_nb;
	}

	if (!nb_jobs && append)
		return;

	e2r_bd_jobs = &queue->dma_jobs[LSINIC_E2R_BD_DMA_START];

	if ((queue->dma_bd_update & DMA_BD_EP2RC_UPDATE) &&
		nb_jobs) {
		bd_jobs_len = txq_bd_step * nb_jobs;
		jobs[nb_jobs] = &e2r_bd_jobs[txq_dma_bd_start];
		if ((txq_dma_bd_start + nb_jobs) <= queue->nb_desc) {
			txq_bd_jobs_num = 1;
			jobs[nb_jobs]->len = bd_jobs_len;
		} else {
			jobs[nb_jobs]->len = txq_bd_step *
				(queue->nb_desc - txq_dma_bd_start);
			jobs[nb_jobs + 1] = &e2r_bd_jobs[0];
			jobs[nb_jobs + 1]->len =
				bd_jobs_len - jobs[nb_jobs]->len;
			txq_bd_jobs_num = 2;
		}

		if (ep_bd_desc) {
			for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
				jobs_idx = jobs_avail_idx &
					(queue->nb_desc - 1);
				jobs[i] = &queue->dma_jobs[jobs_idx];
				ep_bd_desc[jobs_idx].bd_status &=
					~((uint32_t)RING_BD_STATUS_MASK);
				ep_bd_desc[jobs_idx].bd_status |=
					RING_BD_HW_COMPLETE;
			}
		} else {
			for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
				jobs_idx = jobs_avail_idx &
					(queue->nb_desc - 1);
				jobs[i] = &queue->dma_jobs[jobs_idx];
			}
		}
	} else if (nb_jobs) {
		for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
			jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
			jobs[i] = &queue->dma_jobs[jobs_idx];
		}
	}

	nb_jobs += txq_bd_jobs_num;

	if (!nb_jobs)
		return;

	for (i = 0; i < nb_jobs; i++) {
		queue->dma_idx[i] = jobs[i]->idx;
		src[i].addr = jobs[i]->src;
		src[i].length = jobs[i]->len;
		dst[i].addr = jobs[i]->dst;
		dst[i].length = jobs[i]->len;
	}

eq_again:
	if (ep_cap & LSINIC_EP_CAP_TXQ_SG_DMA) {
		flags = RTE_DPAAX_QDMA_SG_SUBMIT(queue->dma_idx,
			RTE_DMA_OP_FLAG_SUBMIT);
		ret = rte_dma_copy_sg(queue->dma_id, queue->dma_vq,
			src, dst,
			nb_jobs, nb_jobs, flags);
	} else {
		for (i = 0; i < nb_jobs; i++) {
			flags = RTE_DPAAX_QDMA_COPY_SUBMIT(queue->dma_idx[i],
				0);
			ret = rte_dma_copy(queue->dma_id, queue->dma_vq,
				src[i].addr, dst[i].addr, src[i].length, flags);
			if (unlikely(ret < 0))
				break;
		}
		ret = rte_dma_submit(queue->dma_id, queue->dma_vq);
	}

	if (likely(ret >= 0)) {
		queue->jobs_pending -= (nb_jobs - txq_bd_jobs_num);
		queue->jobs_avail_idx += (nb_jobs - txq_bd_jobs_num);
		for (i = 0; i < (nb_jobs - txq_bd_jobs_num); i++)
			queue->bytes_eq += jobs[i]->len;
		queue->pkts_eq += (nb_jobs - txq_bd_jobs_num);
		queue->bd_eq += txq_bd_jobs_num;
	} else {
		if (!queue->adapter->txq_dma_silent) {
			loop = 0;
			dq = 0;
			while (!dq) {
				dq = queue->dma_dq(queue);
				loop++;
				if (loop > 10000)
					break;
			}
			if (dq)
				goto eq_again;
		}
		LSXINIC_PMD_ERR("TXQ txbd(%d)/data(%d)",
			txq_bd_jobs_num,
			(nb_jobs - txq_bd_jobs_num));
		LSXINIC_PMD_ERR("TXQ BD: eq(%ld)/dq(%ld)",
			queue->bd_eq, queue->bd_dq);
		LSXINIC_PMD_ERR("TXQ PKT: eq(%ld)/dq(%ld)",
			queue->pkts_eq, queue->pkts_dq);
		queue->errors += (nb_jobs - txq_bd_jobs_num);
	}

	queue->wdma_bd_start = LSINIC_BD_DMA_START_FLAG;
}

static int lsinic_add_txq_to_list(struct lsinic_queue *txq)
{
	struct lsinic_queue *queue = NULL;

	if (!RTE_PER_LCORE(lsinic_txq_list_initialized)) {
		TAILQ_INIT(&RTE_PER_LCORE(lsinic_txq_list));
		RTE_PER_LCORE(lsinic_txq_list_initialized) = 1;
		RTE_PER_LCORE(lsinic_txq_num_in_list) = 0;
	}

	/* Check if txq already added to list */
	TAILQ_FOREACH(queue, &RTE_PER_LCORE(lsinic_txq_list), next) {
		if (queue == txq)
			return 0;
	}

	TAILQ_INSERT_TAIL(&RTE_PER_LCORE(lsinic_txq_list), txq, next);
	/* Rewrite core ID and thread ID because polling context
	 * may differs from the context to start this txq.
	 */
	txq->core_id = rte_lcore_id();
	txq->pid = pthread_self();
	RTE_PER_LCORE(lsinic_txq_num_in_list)++;

	LSXINIC_PMD_DBG("Add port%d txq%d to list NUM%d",
		txq->port_id, txq->queue_id,
		RTE_PER_LCORE(lsinic_txq_num_in_list));

	return 0;
}

static int
lsinic_remove_txq_from_list(struct lsinic_queue *txq)
{
	struct lsinic_queue *q, *tq;

	RTE_TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lsinic_txq_list), next, tq) {
		if (q == txq) {
			TAILQ_REMOVE(&RTE_PER_LCORE(lsinic_txq_list),
				q, next);
			RTE_PER_LCORE(lsinic_txq_num_in_list)--;
			LSXINIC_PMD_DBG("Remove port%d txq%d from list NUM%d",
				txq->port_id, txq->queue_id,
				RTE_PER_LCORE(lsinic_txq_num_in_list));
			break;
		}
	}

	return 0;
}

static void
lsinic_queue_status_update(struct lsinic_queue *q)
{
	int ret;

	if (likely(q->status == LSINIC_QUEUE_RUNNING))
		return;

	if (q->status == LSINIC_QUEUE_UNAVAILABLE)
		return;

	if (q->status == LSINIC_QUEUE_START) {
		ret = lsinic_queue_start(q);
		if (ret < 0) {
			q->status = LSINIC_QUEUE_UNAVAILABLE;
			q->ep_reg->sr = q->status;
			LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);
			return;
		}

		if (q->type == LSINIC_QUEUE_TX && !q->pair)
			lsinic_add_txq_to_list(q);
		else
			RTE_PER_LCORE(lsinic_txq_deqeue_from_rxq) = 1;

		q->status = LSINIC_QUEUE_RUNNING;
		q->ep_reg->sr = q->status;
		if (q->rc_reg)
			LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);

		return;
	}

	if (q->status == LSINIC_QUEUE_STOP) {
		if (lsinic_queue_dma_clean(q)) {
			/* Wait to the next loop to clean dma queue */
			rte_delay_ms(500);
			return;
		}

		if (q->type == LSINIC_QUEUE_TX)
			lsinic_remove_txq_from_list(q);
		else
			RTE_PER_LCORE(lsinic_txq_deqeue_from_rxq) = 0;

		q->status = LSINIC_QUEUE_UNAVAILABLE;
		q->ep_reg->sr = q->status;
		if (q->rc_reg)
			LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);

		return;
	}
}

static __rte_always_inline uint16_t
lsinic_queue_next_avail_idx(struct lsinic_queue *q,
	uint16_t fwd)
{
	return (q->next_avail_idx + fwd) & (q->nb_desc - 1);
}

static __rte_always_inline uint16_t
lsinic_queue_next_used_idx(struct lsinic_queue *q,
	uint16_t fwd)
{
	return (q->next_used_idx + fwd) & (q->nb_desc - 1);
}

static uint16_t
lsinic_xmit_seg_pkt(struct lsinic_queue *txq,
	struct rte_mbuf *tx_pkt)
{
	struct lsinic_ep_tx_seg_dst_addr *dst_addr;
	struct lsinic_sw_bd *txe;
	uint16_t bd_idx, seg_size = tx_pkt->tso_segsz, idx = 0;
	uint32_t remain_size = tx_pkt->pkt_len;
	struct lsinic_dma_seg_job *dma_job;
	uint64_t dst, src_base = rte_mbuf_data_iova(tx_pkt), dst_base;
	struct lsinic_rc_rx_seg *local_seg;

	if (unlikely(!lsinic_queue_running(txq))) {
		lsinic_queue_status_update(txq);
		if (!lsinic_queue_running(txq))
			return 0;
	}

	bd_idx = txq->next_avail_idx & (txq->nb_desc - 1);
	dst_addr = &txq->tx_seg_dst_addr[bd_idx];
	local_seg = &txq->local_src_seg[bd_idx];
	txe = &txq->sw_ring[bd_idx];

	if (unlikely(!dst_addr->ready)) {
		txq->ring_full++;
		txq->drop_packet_num++;
		LSXINIC_PMD_DBG("%s:TXQ%d:buf[%d] unavailable",
			txq->adapter->lsinic_dev->name,
			txq->queue_id, bd_idx);

		return 0;
	}
	if (unlikely(!txe->dma_complete)) {
		txq->ring_full++;
		txq->drop_packet_num++;
		LSXINIC_PMD_DBG("%s:TXQ%d:buf[%d] last dma not complete",
			txq->adapter->lsinic_dev->name,
			txq->queue_id, bd_idx);
		return 0;
	}

	dma_job = &txq->dma_seg_jobs[bd_idx];

	txe->dma_complete = 0;
	if (txe->mbuf)
		rte_pktmbuf_free(txe->mbuf);

	txe->mbuf = tx_pkt;

	if (seg_size > tx_pkt->pkt_len || !seg_size)
		seg_size = tx_pkt->pkt_len;

	dst_base = txq->ob_base + dst_addr->addr_base;
	while (remain_size) {
		dma_job->src[idx] = src_base + idx * seg_size;
		if (dst_addr->entry[idx].positive)
			dst = dst_base + dst_addr->entry[idx].offset;
		else
			dst = dst_base - dst_addr->entry[idx].offset;
		dma_job->dst[idx] = dst;
		if (remain_size > seg_size) {
			dma_job->len[idx] = seg_size;
			local_seg->len[idx] = seg_size;
			remain_size -= seg_size;
		} else {
			dma_job->len[idx] = remain_size;
			local_seg->len[idx] = remain_size;
			remain_size = 0;
		}
		idx++;
	}
	dma_job->seg_nb = idx;
	dma_job->cnxt = (uint64_t)txe;

	local_seg->nb = idx;

	txq->packets++;

	txq->bytes += tx_pkt->pkt_len;
	txq->bytes_fcs += tx_pkt->pkt_len +
			LSINIC_ETH_FCS_SIZE * dma_job->seg_nb;
	txq->bytes_overhead += tx_pkt->pkt_len +
		LSINIC_ETH_OVERHEAD_SIZE * dma_job->seg_nb;

	dst_addr->ready = 0;

	txq->jobs_pending++;

	if (txq->wdma_bd_start == LSINIC_BD_DMA_START_FLAG)
		txq->wdma_bd_start = bd_idx;
	lsinic_qdma_tx_seg_enqueue(txq);
	txq->next_avail_idx++;

	return 1;
}

static uint16_t
lsinic_xmit_one_pkt(struct lsinic_queue *txq,
	struct rte_mbuf *tx_pkt, struct rte_mbuf **free_pkt)
{
	const struct lsinic_bd_desc *ep_txd = NULL;
	struct lsinic_ep_tx_dst_addr *dst_addr = NULL;
	struct lsinic_sw_bd *txe;
	uint16_t bd_idx;
	struct lsinic_dma_job *dma_job;
	struct lsinic_bd_desc *ep_local_txd;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct lsinic_rc_rx_len_cmd *local_cmd;
#else
	struct lsinic_rc_rx_len_idx *local_idx;
#endif

	if (unlikely(!lsinic_queue_running(txq))) {
		lsinic_queue_status_update(txq);
		if (!lsinic_queue_running(txq))
			return 0;
	}

	bd_idx = txq->next_avail_idx & (txq->nb_desc - 1);
	if (txq->ep_mem_bd_type == EP_MEM_DST_ADDR_BD)
		dst_addr = &txq->tx_dst_addr[bd_idx];
	else
		ep_txd = &txq->ep_bd_desc[bd_idx];

	/* Make sure there are enough TX descriptors available to
	 * transmit the entire packet.
	 * nb_used better be less than or equal to txq->tx_rs_thresh
	 */

	if (dst_addr) {
		if (!(((uint64_t)dst_addr) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((const uint8_t *)dst_addr +
				RTE_CACHE_LINE_SIZE);
		}
		if (unlikely(!dst_addr->pkt_addr)) {
			txq->ring_full++;
			txq->drop_packet_num++;
			if (!s_lsx_tx_busy_log)
				return 0;
			LSXINIC_PMD_WARN("TXQ%d remote addr[%d] unavailable",
				txq->queue_id, bd_idx);
			if (!txq->rc_tx_dst_addr)
				return 0;

			LSXINIC_PMD_WARN("Address(0x%lx) in RC, pir(%d-%d)",
				txq->rc_tx_dst_addr[bd_idx].pkt_addr,
				txq->rdma_bd_start, txq->ep_reg->pir);
			return 0;
		}
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		local_cmd = &txq->local_src_len_cmd[bd_idx];
#else
		local_idx = &txq->local_src_len_idx[bd_idx];
#endif

		dma_job = &txq->dma_jobs[bd_idx];
		txe = &txq->sw_ring[bd_idx];

		if (txe->mbuf) {
			if (free_pkt)
				*free_pkt = txe->mbuf;
			else
				rte_pktmbuf_free(txe->mbuf);
		}
		txe->mbuf = tx_pkt;

		dma_job->src = rte_mbuf_data_iova(tx_pkt);
		dma_job->dst = txq->ob_base + dst_addr->pkt_addr;
		dma_job->len = tx_pkt->pkt_len;
		txq->packets++;

		txq->bytes += tx_pkt->pkt_len;
		txq->bytes_fcs += tx_pkt->pkt_len +
			LSINIC_ETH_FCS_SIZE;
		txq->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		local_cmd->total_len = tx_pkt->pkt_len;
		local_cmd->cnt_idx = 0;
#else
		local_idx->total_len = tx_pkt->pkt_len;
		local_idx->idx = 0;
#endif

		dst_addr->pkt_addr = 0;
		dma_job->cnxt = (uint64_t)txe;

		txq->jobs_pending++;

		if (txq->wdma_bd_start == LSINIC_BD_DMA_START_FLAG)
			txq->wdma_bd_start = bd_idx;
		txq->txq_dma_eq(txq, true);
		txq->next_avail_idx++;

		return 1;
	}

	if (unlikely(!lsinic_tx_bd_available(txq, bd_idx))) {
		txq->ring_full++;
		txq->drop_packet_num++;
		if (!txq->rc_bd_desc || !s_lsx_tx_busy_log)
			return 0;
		LSXINIC_PMD_WARN("Status[%d]: remote(0x%08x)/local(0x%08x)",
			bd_idx, txq->rc_bd_desc[bd_idx].bd_status,
			txq->ep_bd_desc[bd_idx].bd_status);
		LSXINIC_PMD_WARN("DMA BD update: pir(%d-%d)",
			txq->rdma_bd_start, txq->ep_reg->pir);
		return 0;
	}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	local_cmd = &txq->local_src_len_cmd[bd_idx];
#else
	local_idx = &txq->local_src_len_idx[bd_idx];
#endif
	ep_local_txd = &txq->local_src_bd_desc[bd_idx];
	if (ep_txd != ep_local_txd)
		memcpy(ep_local_txd, ep_txd, sizeof(struct lsinic_bd_desc));

	dma_job = &txq->dma_jobs[bd_idx];

	txe = &txq->sw_ring[bd_idx];

	if (txe->mbuf) {
		if (free_pkt)
			*free_pkt = txe->mbuf;
		else
			rte_pktmbuf_free(txe->mbuf);
	}
	txe->mbuf = tx_pkt;

	dma_job->src = rte_mbuf_data_iova(tx_pkt);
	dma_job->dst = txq->ob_base + ep_txd->pkt_addr;
	dma_job->len = tx_pkt->pkt_len;
	ep_local_txd->len_cmd = LSINIC_BD_CMD_EOP | tx_pkt->pkt_len;
	txq->packets++;

	txq->bytes += tx_pkt->pkt_len;
	txq->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	txq->bytes_overhead += tx_pkt->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;

	if (txq->rc_mem_bd_type == RC_MEM_LEN_CMD) {
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		local_cmd->total_len = tx_pkt->pkt_len;
		local_cmd->cnt_idx = lsinic_bd_ctx_idx(ep_txd->bd_status);
#else
		local_idx->total_len = tx_pkt->pkt_len;
		local_idx->idx = lsinic_bd_ctx_idx(ep_txd->bd_status);
#endif
	}

	lsinic_lbd_dma_start_update(txq, bd_idx);
	dma_job->cnxt = (uint64_t)txe;

	txq->jobs_pending++;

	if (txq->wdma_bd_start == LSINIC_BD_DMA_START_FLAG)
		txq->wdma_bd_start = bd_idx;
	txq->txq_dma_eq(txq, true);
	txq->next_avail_idx++;

	return 1;
}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
#define ETH_CORE_DPIO DPAA2_PER_LCORE_ETHRX_DPIO

static int
lsinic_add_recycle_dev_list(struct rte_eth_dev *eth_dev)
{
	struct lsinic_recycle_dev *dev = NULL;
	struct lsinic_recycle_dev *tdev = NULL;

	rte_spinlock_lock(&recycle_dev_list_lock);
	RTE_TAILQ_FOREACH_SAFE(dev, &recycle_dev_list, next, tdev) {
		if (dev->recycle_dev == eth_dev) {
			LSXINIC_PMD_WARN("Recycle dev %s has been occupied",
				eth_dev->data->name);
			rte_spinlock_unlock(&recycle_dev_list_lock);
			return -EEXIST;
		}
	}

	dev = rte_malloc(NULL, sizeof(struct lsinic_recycle_dev),
			RTE_CACHE_LINE_SIZE);
	if (!dev) {
		LSXINIC_PMD_ERR("recycle dev alloc failed");
		rte_spinlock_unlock(&recycle_dev_list_lock);
		return -ENOMEM;
	}
	dev->recycle_dev = eth_dev;
	TAILQ_INSERT_TAIL(&recycle_dev_list, dev, next);
	rte_spinlock_unlock(&recycle_dev_list_lock);

	return 0;
}

static int
lsinic_remove_recycle_dev_list(struct rte_eth_dev *eth_dev)
{
	struct lsinic_recycle_dev *dev = NULL;
	struct lsinic_recycle_dev *tdev = NULL;

	rte_spinlock_lock(&recycle_dev_list_lock);
	RTE_TAILQ_FOREACH_SAFE(dev, &recycle_dev_list, next, tdev) {
		if (dev->recycle_dev == eth_dev) {
			TAILQ_REMOVE(&recycle_dev_list, dev, next);
			rte_free(dev);
			rte_spinlock_unlock(&recycle_dev_list_lock);
			return 0;
		}
	}

	rte_spinlock_unlock(&recycle_dev_list_lock);
	return -ENXIO;
}

static inline uint16_t
lsinic_txq_merge_num(struct lsinic_queue *txq,
	struct lsinic_mg_header *mg_header)
{
	uint16_t mg_num = 0;
	uint16_t len;

	while (mg_num < LSINIC_MERGE_MAX_NUM) {
		len = lsinic_mg_entry_len(mg_header->len_cmd[mg_num]);

		if (!len)
			break;
		txq->bytes += len;
		txq->bytes_fcs += len +
			LSINIC_ETH_FCS_SIZE;
		txq->bytes_overhead += len +
			LSINIC_ETH_OVERHEAD_SIZE;
		mg_num++;
	}

	return mg_num;
}

static uint16_t
lsinic_xmit_merged_one_pkt(struct lsinic_queue *txq,
	struct rte_mbuf *tx_pkt,
	struct rte_mbuf **free_pkt)
{
	const struct lsinic_bd_desc *ep_txd = NULL;
	struct lsinic_ep_tx_dst_addr *dst_addr = NULL;
	struct lsinic_sw_bd *txe;
	uint16_t bd_idx, mg_num = 0;
	struct lsinic_dma_job *dma_job;
	struct lsinic_mg_header *mg_header = NULL;
	struct lsinic_bd_desc *ep_local_txd;
	struct lsinic_rc_rx_len_cmd *local_cmd;

	mg_header = rte_pktmbuf_mtod_offset(tx_pkt,
		struct lsinic_mg_header *,
		-sizeof(struct lsinic_mg_header));
	rte_memcpy(mg_header,
		&txq->mg_dsc[txq->mg_dsc_head].mg_header,
		sizeof(struct lsinic_mg_header));

	bd_idx = txq->next_avail_idx & (txq->nb_desc - 1);
	if (txq->ep_mem_bd_type == EP_MEM_DST_ADDR_BD)
		dst_addr = &txq->tx_dst_addr[bd_idx];
	else
		ep_txd = &txq->ep_bd_desc[bd_idx];

	/* Make sure there are enough TX descriptors available to
	 * transmit the entire packet.
	 * nb_used better be less than or equal to txq->tx_rs_thresh
	 */

	if (dst_addr) {
		if (!(((uint64_t)dst_addr) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((const uint8_t *)dst_addr +
				RTE_CACHE_LINE_SIZE);
		}
		if (unlikely(!dst_addr->pkt_addr)) {
			txq->ring_full++;
			txq->drop_packet_num++;
			if (!s_lsx_tx_busy_log)
				return 0;
			LSXINIC_PMD_WARN("TXQ%d remote addr[%d] unavailable",
				txq->queue_id, bd_idx);
			if (!txq->rc_tx_dst_addr)
				return 0;

			LSXINIC_PMD_WARN("Address(0x%lx) in RC, pir(%d-%d)",
				txq->rc_tx_dst_addr[bd_idx].pkt_addr,
				txq->rdma_bd_start, txq->ep_reg->pir);
			return 0;
		}
		local_cmd = &txq->local_src_len_cmd[bd_idx];

		dma_job = &txq->dma_jobs[bd_idx];
		txe = &txq->sw_ring[bd_idx];

		mg_num = lsinic_txq_merge_num(txq, mg_header);

		if (txe->mbuf) {
			if (free_pkt)
				*free_pkt = txe->mbuf;
			else
				rte_pktmbuf_free(txe->mbuf);
		}
		txe->mbuf = tx_pkt;

		dma_job->src = rte_mbuf_data_iova(tx_pkt) -
			sizeof(struct lsinic_mg_header);
		dma_job->dst = txq->ob_base + dst_addr->pkt_addr;
		dma_job->dst -= sizeof(struct lsinic_mg_header);
		dma_job->len = tx_pkt->pkt_len +
			sizeof(struct lsinic_mg_header);

		txq->packets += mg_num;

		local_cmd->total_len = tx_pkt->pkt_len;
		EP2RC_TX_IDX_CNT_SET(local_cmd->cnt_idx,
			0, mg_num);

		dst_addr->pkt_addr = 0;
		dma_job->cnxt = (uint64_t)txe;

		txq->jobs_pending++;

		if (txq->wdma_bd_start == LSINIC_BD_DMA_START_FLAG)
			txq->wdma_bd_start = bd_idx;
		txq->txq_dma_eq(txq, true);
		txq->next_avail_idx++;

		return 1;
	}

	if (unlikely(!lsinic_tx_bd_available(txq, bd_idx))) {
		txq->ring_full++;
		txq->drop_packet_num++;
		if (!txq->rc_bd_desc || !s_lsx_tx_busy_log)
			return 0;
		LSXINIC_PMD_WARN("Status[%d]: remote(0x%08x)/local(0x%08x)",
			bd_idx, txq->rc_bd_desc[bd_idx].bd_status,
			txq->ep_bd_desc[bd_idx].bd_status);
		LSXINIC_PMD_WARN("DMA BD update: pir(%d-%d)",
			txq->rdma_bd_start, txq->ep_reg->pir);
		return 0;
	}

	local_cmd = &txq->local_src_len_cmd[bd_idx];
	ep_local_txd = &txq->local_src_bd_desc[bd_idx];
	if (ep_txd != ep_local_txd)
		memcpy(ep_local_txd, ep_txd, sizeof(struct lsinic_bd_desc));

	dma_job = &txq->dma_jobs[bd_idx];

	txe = &txq->sw_ring[bd_idx];

	mg_num = lsinic_txq_merge_num(txq, mg_header);

	if (txe->mbuf) {
		if (free_pkt)
			*free_pkt = txe->mbuf;
		else
			rte_pktmbuf_free(txe->mbuf);
	}
	txe->mbuf = tx_pkt;

	dma_job->src = rte_mbuf_data_iova(tx_pkt) -
		sizeof(struct lsinic_mg_header);
	dma_job->dst = txq->ob_base + ep_txd->pkt_addr;
	dma_job->dst -= sizeof(struct lsinic_mg_header);
	dma_job->len = tx_pkt->pkt_len +
		sizeof(struct lsinic_mg_header);
	ep_local_txd->len_cmd = LSINIC_BD_CMD_EOP | LSINIC_BD_CMD_MG |
		tx_pkt->pkt_len;
	ep_local_txd->len_cmd |= (((uint32_t)mg_num) <<
		LSINIC_BD_MG_NUM_SHIFT);

	txq->packets += mg_num;

	if (txq->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		local_cmd->total_len = tx_pkt->pkt_len;
		EP2RC_TX_IDX_CNT_SET(local_cmd->cnt_idx,
			lsinic_bd_ctx_idx(ep_txd->bd_status),
			mg_num);
	}

	lsinic_lbd_dma_start_update(txq, bd_idx);
	dma_job->cnxt = (uint64_t)txe;

	txq->jobs_pending++;

	if (txq->wdma_bd_start == LSINIC_BD_DMA_START_FLAG)
		txq->wdma_bd_start = bd_idx;
	txq->txq_dma_eq(txq, true);
	txq->next_avail_idx++;

	return 1;
}

static void
lsinic_tx_merge_one_to_txq(struct lsinic_queue *txq,
	struct rte_mbuf *buf, struct rte_mbuf **free_pkt)
{
	struct lsinic_dpni_mg_dsc *mg_dsc =
		&txq->mg_dsc[txq->mg_dsc_head];
	uint16_t ret;

	if (mg_dsc->attach_mbuf) {
		lsinic_mbuf_reset(mg_dsc->attach_mbuf);
		rte_mempool_put_bulk(mg_dsc->attach_mbuf->pool,
			(void * const *)&mg_dsc->attach_mbuf, 1);
	}

	ret = lsinic_xmit_merged_one_pkt(txq, buf, free_pkt);
	if (unlikely(ret != 1))
		rte_pktmbuf_free(buf);

	txq->mg_dsc_head = (txq->mg_dsc_head + 1) & (txq->nb_desc - 1);

	txq->recycle_pending--;
}

static void
lsinic_tx_burst_merge_cb(struct rte_mbuf **bufs,
	uint16_t num, struct dpaa2_queue *recycle_rxq)
{
	struct lsinic_queue *txq =
		(struct lsinic_queue *)recycle_rxq->lpbk_cntx;
	int i, free_idx = 0;
	struct rte_mbuf *free_pkts[num];
	const int bulk_free = 1;

	if (!num) {
		txq->txq_dma_eq(txq, false);

		return;
	}

	if (!bulk_free) {
		for (i = 0; i < num; i++)
			lsinic_tx_merge_one_to_txq(txq, bufs[i], NULL);
	} else {
		for (i = 0; i < num; i++) {
			free_pkts[free_idx] = NULL;
			lsinic_tx_merge_one_to_txq(txq, bufs[i],
				&free_pkts[free_idx]);
			if (free_pkts[free_idx])
				free_idx++;
		}
		if (free_idx > 0) {
			rte_mempool_put_bulk(free_pkts[0]->pool,
				(void * const *)free_pkts, free_idx);
		}
	}
}

static void
lsinic_rx_burst_split_cb(struct rte_mbuf **bufs,
	uint16_t num, struct dpaa2_queue *split_rxq)
{
	struct lsinic_queue *rx_queue =
		(struct lsinic_queue *)split_rxq->lpbk_cntx;
	int i;

	if (!num)
		return;

	for (i = 0; i < num; i++) {
		rx_queue->recycle_pending--;
		rx_queue->mcache[rx_queue->mtail] = bufs[i];
		rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;

		rx_queue->mcnt++;
	}
}

static void
lsinic_tx_merge_cb(struct rte_mbuf *buf,
	struct dpaa2_queue *recycle_rxq)
{
	struct lsinic_queue *txq =
		(struct lsinic_queue *)recycle_rxq->lpbk_cntx;

	if (!buf) {
		txq->txq_dma_eq(txq, false);

		return;
	}

	lsinic_tx_merge_one_to_txq(txq, buf, NULL);
}

static void
lsinic_rx_split_cb(struct rte_mbuf *mbuf,
	struct dpaa2_queue *split_rxq)
{
	struct lsinic_queue *rx_queue =
		(struct lsinic_queue *)split_rxq->lpbk_cntx;

	if (!mbuf)
		return;

	rx_queue->recycle_pending--;
	rx_queue->mcache[rx_queue->mtail] = mbuf;
	rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;

	rx_queue->mcnt++;
}

static inline uint32_t
lsinic_dpaa2_rx_parse_slow(struct rte_mbuf *mbuf,
	struct dpaa2_annot_hdr *annotation)
{
	uint32_t pkt_type = RTE_PTYPE_UNKNOWN;
	uint16_t *vlan_tci;

	if (BIT_ISSET_AT_POS(annotation->word3, L2_VLAN_1_PRESENT)) {
		vlan_tci = rte_pktmbuf_mtod_offset(mbuf, uint16_t *,
			(VLAN_TCI_OFFSET_1(annotation->word5) >> 16));
		mbuf->vlan_tci = rte_be_to_cpu_16(*vlan_tci);
		mbuf->ol_flags |= RTE_MBUF_F_RX_VLAN;
		pkt_type |= RTE_PTYPE_L2_ETHER_VLAN;
	} else if (BIT_ISSET_AT_POS(annotation->word3, L2_VLAN_N_PRESENT)) {
		vlan_tci = rte_pktmbuf_mtod_offset(mbuf, uint16_t *,
			(VLAN_TCI_OFFSET_1(annotation->word5) >> 16));
		mbuf->vlan_tci = rte_be_to_cpu_16(*vlan_tci);
		mbuf->ol_flags |= RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_QINQ;
		pkt_type |= RTE_PTYPE_L2_ETHER_QINQ;
	}

	if (BIT_ISSET_AT_POS(annotation->word3, L2_ARP_PRESENT)) {
		pkt_type |= RTE_PTYPE_L2_ETHER_ARP;
		goto parse_done;
	} else if (BIT_ISSET_AT_POS(annotation->word3, L2_ETH_MAC_PRESENT)) {
		pkt_type |= RTE_PTYPE_L2_ETHER;
	} else {
		goto parse_done;
	}

	if (BIT_ISSET_AT_POS(annotation->word3, L2_MPLS_1_PRESENT |
				L2_MPLS_N_PRESENT))
		pkt_type |= RTE_PTYPE_L2_ETHER_MPLS;

	if (BIT_ISSET_AT_POS(annotation->word4, L3_IPV4_1_PRESENT |
			     L3_IPV4_N_PRESENT)) {
		pkt_type |= RTE_PTYPE_L3_IPV4;
		if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT |
			L3_IP_N_OPT_PRESENT))
			pkt_type |= RTE_PTYPE_L3_IPV4_EXT;

	} else if (BIT_ISSET_AT_POS(annotation->word4, L3_IPV6_1_PRESENT |
		  L3_IPV6_N_PRESENT)) {
		pkt_type |= RTE_PTYPE_L3_IPV6;
		if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT |
		    L3_IP_N_OPT_PRESENT))
			pkt_type |= RTE_PTYPE_L3_IPV6_EXT;
	} else {
		goto parse_done;
	}

	if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L3CE))
		mbuf->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;
	else if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L4CE))
		mbuf->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_BAD;

	if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_FIRST_FRAGMENT |
	    L3_IP_1_MORE_FRAGMENT |
	    L3_IP_N_FIRST_FRAGMENT |
	    L3_IP_N_MORE_FRAGMENT)) {
		pkt_type |= RTE_PTYPE_L4_FRAG;
		goto parse_done;
	} else {
		pkt_type |= RTE_PTYPE_L4_NONFRAG;
	}

	if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_UDP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_UDP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_TCP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_TCP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_SCTP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_SCTP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_ICMP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_ICMP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_UNKNOWN_PROTOCOL))
		pkt_type |= RTE_PTYPE_UNKNOWN;

parse_done:
	return pkt_type;
}

static inline void
lsinic_lxdpaa2_rx_parse(struct rte_mbuf *m,
	const struct qbman_fd *fd, void *hw_annot_addr)
{
	uint16_t frc = DPAA2_GET_FD_FRC_PARSE_SUM(fd);
	struct dpaa2_annot_hdr *annotation =
			(struct dpaa2_annot_hdr *)hw_annot_addr;

	m->packet_type = RTE_PTYPE_UNKNOWN;
	switch (frc) {
	case DPAA2_PKT_TYPE_ETHER:
		m->packet_type = RTE_PTYPE_L2_ETHER;
		break;
	case DPAA2_PKT_TYPE_IPV4:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4;
		break;
	case DPAA2_PKT_TYPE_IPV6:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6;
		break;
	case DPAA2_PKT_TYPE_IPV4_EXT:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4_EXT;
		break;
	case DPAA2_PKT_TYPE_IPV6_EXT:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6_EXT;
		break;
	case DPAA2_PKT_TYPE_IPV4_TCP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP;
		break;
	case DPAA2_PKT_TYPE_IPV6_TCP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		break;
	case DPAA2_PKT_TYPE_IPV4_UDP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP;
		break;
	case DPAA2_PKT_TYPE_IPV6_UDP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
		break;
	case DPAA2_PKT_TYPE_IPV4_SCTP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_SCTP;
		break;
	case DPAA2_PKT_TYPE_IPV6_SCTP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_SCTP;
		break;
	case DPAA2_PKT_TYPE_IPV4_ICMP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_ICMP;
		break;
	case DPAA2_PKT_TYPE_IPV6_ICMP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_ICMP;
		break;
	default:
		m->packet_type = lsinic_dpaa2_rx_parse_slow(m, annotation);
	}
	m->hash.rss = fd->simple.flc_hi;
	m->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;
}

static inline uint32_t
lsinic_lsdpaa2_rx_parse(struct rte_mbuf *mbuf,
	void *hw_annot_addr)
{
	struct dpaa2_annot_hdr *annotation =
			(struct dpaa2_annot_hdr *)hw_annot_addr;

	if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L3CE))
		mbuf->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;
	else if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L4CE))
		mbuf->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_BAD;

	/* Check detailed parsing requirement */
	if (annotation->word3 & 0x7FFFFC3FFFF)
		return lsinic_dpaa2_rx_parse_slow(mbuf, annotation);

	/* Return some common types from parse processing */
	switch (annotation->word4) {
	case DPAA2_L3_IPv4:
		return RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4;
	case DPAA2_L3_IPv6:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6;
	case DPAA2_L3_IPv4_TCP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 |
				RTE_PTYPE_L4_TCP;
	case DPAA2_L3_IPv4_UDP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 |
				RTE_PTYPE_L4_UDP;
	case DPAA2_L3_IPv6_TCP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6 |
				RTE_PTYPE_L4_TCP;
	case DPAA2_L3_IPv6_UDP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6 |
				RTE_PTYPE_L4_UDP;
	default:
		break;
	}

	return lsinic_dpaa2_rx_parse_slow(mbuf, annotation);
}

static inline struct rte_mbuf *
lsinic_dpaa2_fd_to_mbuf(const struct qbman_fd *fd,
	int port_id, enum LSINIC_QEUE_TYPE lsinic_qtype)
{
	void *v_addr = DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	uint32_t offset;
	uint16_t bpid;
	struct rte_mbuf *mbuf;

	bpid = DPAA2_GET_FD_BPID(fd);
	offset = rte_dpaa2_bpid_info[bpid].meta_data_size;
	mbuf = DPAA2_INLINE_MBUF_FROM_BUF(v_addr, offset);
	/* need to repopulated some of the fields,
	 * as they may have changed in last transmission
	 */
	mbuf->nb_segs = 1;
	mbuf->ol_flags = 0;
	mbuf->data_off = DPAA2_GET_FD_OFFSET(fd);
	mbuf->data_len = DPAA2_GET_FD_LEN(fd);
	mbuf->pkt_len = mbuf->data_len;
	mbuf->port = port_id;
	mbuf->next = NULL;

	if (lsinic_qtype == LSINIC_QUEUE_RX) {
		void *hw_annot_addr =
			(void *)((size_t)v_addr + DPAA2_FD_PTA_SIZE);

		if (dpaa2_svr_family == SVR_LX2160A) {
			lsinic_lxdpaa2_rx_parse(mbuf, fd, hw_annot_addr);
		} else {
			mbuf->packet_type =
				lsinic_lsdpaa2_rx_parse(mbuf, hw_annot_addr);
		}
	}

	return mbuf;
}

static uint16_t
lsinic_dpaa2_rx_lpbk(void *queue,
	struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function receive frames for a given device and VQ*/
	struct dpaa2_queue *dpaa2_q = queue;
	struct qbman_result *dq_storage, *dq_storage1 = NULL;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_rx = 0, pull_size;
	uint8_t pending, status;
	struct qbman_swp *swp;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct queue_storage_info_t *q_storage = dpaa2_q->q_storage[0];
	struct rte_eth_dev_data *eth_data = dpaa2_q->eth_data;
	struct lsinic_queue *lsinic_q;
	struct qbman_result *res;

	if (unlikely(!ETH_CORE_DPIO)) {
		ret = dpaa2_affine_qbman_ethrx_swp();
		if (ret) {
			LSXINIC_PMD_ERR("Failure in affining portal");
			return 0;
		}
	}

	if (unlikely(!rte_dpaa2_bpid_info &&
		     rte_eal_process_type() == RTE_PROC_SECONDARY))
		rte_dpaa2_bpid_info = dpaa2_q->bp_array;

	swp = DPAA2_PER_LCORE_ETHRX_PORTAL;
	pull_size = (nb_pkts > dpaa2_dqrr_size) ? dpaa2_dqrr_size : nb_pkts;
	if (unlikely(!q_storage->active_dqs)) {
		q_storage->toggle = 0;
		dq_storage = q_storage->dq_storage[q_storage->toggle];
		q_storage->last_num_pkts = pull_size;
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_numframes(&pulldesc,
					      q_storage->last_num_pkts);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			DPAA2_VADDR_TO_IOVA(dq_storage), 1);
		if (check_swp_active_dqs(ETH_CORE_DPIO->index)) {
check_again1:
			res = get_swp_active_dqs(ETH_CORE_DPIO->index);
			if (!qbman_check_command_complete(res))
				goto check_again1;
			clear_swp_active_dqs(ETH_CORE_DPIO->index);
		}
		while (1) {
			if (qbman_swp_pull(swp, &pulldesc))
				continue;
			break;
		}
		q_storage->active_dqs = dq_storage;
		q_storage->active_dpio_id = ETH_CORE_DPIO->index;
		set_swp_active_dqs(ETH_CORE_DPIO->index,
				   dq_storage);
	}

	dq_storage = q_storage->active_dqs;
	rte_prefetch0((void *)(size_t)(dq_storage));
	rte_prefetch0((void *)(size_t)(dq_storage + 1));

	/* Prepare next pull descriptor. This will give space for the
	 * prefething done on DQRR entries
	 */
	q_storage->toggle ^= 1;
	dq_storage1 = q_storage->dq_storage[q_storage->toggle];
	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, pull_size);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage1,
		DPAA2_VADDR_TO_IOVA(dq_storage1), 1);

	while (!qbman_check_command_complete(dq_storage))
		;
	if (dq_storage == get_swp_active_dqs(q_storage->active_dpio_id))
		clear_swp_active_dqs(q_storage->active_dpio_id);

	pending = 1;

	lsinic_q = (struct lsinic_queue *)dpaa2_q->lpbk_cntx;

	do {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN
		 */
		while (!qbman_check_new_result(dq_storage))
			;
		rte_prefetch0((void *)((size_t)(dq_storage + 2)));
		/* Check whether Last Pull command is Expired and
		 * setting Condition for Loop termination
		 */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			pending = 0;
			/* Check for valid frame. */
			status = qbman_result_DQ_flags(dq_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0))
				continue;
		}
		fd = qbman_result_DQ_fd(dq_storage);

		if (likely(lsinic_q)) {
			bufs[num_rx] = lsinic_dpaa2_fd_to_mbuf(fd,
				eth_data->port_id,
				lsinic_q->type);
		} else {
			bufs[num_rx] = lsinic_dpaa2_fd_to_mbuf(fd,
				eth_data->port_id,
				LSINIC_QUEUE_TX);
		}

		dq_storage++;
		num_rx++;
	} while (pending);

	if (check_swp_active_dqs(ETH_CORE_DPIO->index)) {
check_again2:
		res = get_swp_active_dqs(ETH_CORE_DPIO->index);
		if (!qbman_check_command_complete(res))
			goto check_again2;
		clear_swp_active_dqs(ETH_CORE_DPIO->index);
	}
	/* issue a volatile dequeue command for next pull */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc))
			continue;
		break;
	}
	q_storage->active_dqs = dq_storage1;
	q_storage->active_dpio_id = ETH_CORE_DPIO->index;
	set_swp_active_dqs(ETH_CORE_DPIO->index, dq_storage1);

	dpaa2_q->rx_pkts += num_rx;

	if (!num_rx) {
		if (lsinic_q && !lsinic_q->recycle_rxq) {
			if (lsinic_q->type == LSINIC_QUEUE_TX)
				lsinic_tx_merge_cb(NULL, dpaa2_q);
			else
				lsinic_rx_split_cb(NULL, dpaa2_q);
		}
	}

	if (lsinic_q && lsinic_q->recycle_rxq)
		return num_rx;

	if (lsinic_q && !lsinic_q->recycle_rxq) {
		if (lsinic_q->type == LSINIC_QUEUE_TX)
			lsinic_tx_burst_merge_cb(bufs, num_rx, dpaa2_q);
		else
			lsinic_rx_burst_split_cb(bufs, num_rx, dpaa2_q);
	}

	return 0;
}

#define LSINIC_DPAA2_SG_MAX_OFFSET \
	(4096 - \
	(sizeof(struct qbman_sge) * LSINIC_MERGE_MAX_NUM))

static uint16_t
lsinic_dpaa2_merge_sg(struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts,
	struct qbman_fd *fd_gather,
	struct lsinic_dpni_mg_dsc *mg_dsc,
	uint16_t data_room)
{
	uint16_t seg_len, align_off, sg_num = 0;
	uint16_t i, total_len = 0;
	struct lsinic_mg_header *mg_header;
	struct rte_mempool *mp = tx_pkts[0]->pool;

	uint16_t bpid, sg_offset, merge_max;
	struct qbman_sge *sgt, *sge = NULL;
	struct rte_mbuf *direct_mbuf = NULL;
	struct rte_mbuf *attach_mbuf = NULL;
	struct rte_mbuf *tmp_mbuf;
	uint64_t fd_iova;
	char *fd_va;
	struct rte_mbuf *free_bufs[LSINIC_MERGE_MAX_NUM];
	uint16_t free_nb = 0;

	for (i = 0; i < nb_pkts; i++) {
		if (!(tx_pkts[i]->ol_flags & LSINIC_SHARED_MBUF)) {
			direct_mbuf = tx_pkts[i];
			break;
		}
		if ((tx_pkts[i]->ol_flags & RTE_MBUF_F_INDIRECT)) {
			attach_mbuf = tx_pkts[i];
			break;
		}
	}

	if (direct_mbuf) {
		tmp_mbuf = direct_mbuf;
		fd_iova = DPAA2_MBUF_VADDR_TO_IOVA(tmp_mbuf);
		fd_va = tmp_mbuf->buf_addr;
	} else if (attach_mbuf) {
		tmp_mbuf = attach_mbuf;
		fd_va = (char *)tmp_mbuf +
				(uint32_t)(sizeof(struct rte_mbuf) +
				rte_pktmbuf_priv_size(mp));
		fd_iova = (rte_iova_t)fd_va +
			tmp_mbuf->buf_iova - (rte_iova_t)tmp_mbuf->buf_addr;
	} else {
		tmp_mbuf = rte_pktmbuf_alloc(mp);
		fd_iova = DPAA2_MBUF_VADDR_TO_IOVA(tmp_mbuf);
		fd_va = tmp_mbuf->buf_addr;
	}

	mg_header = &mg_dsc->mg_header;
	sg_offset = RTE_PKTMBUF_HEADROOM + data_room -
		(sizeof(struct qbman_sge) * LSINIC_MERGE_MAX_NUM);
	if (sg_offset > LSINIC_DPAA2_SG_MAX_OFFSET)
		sg_offset = LSINIC_DPAA2_SG_MAX_OFFSET;
	merge_max = sg_offset - RTE_PKTMBUF_HEADROOM;

	bpid = mempool_to_bpid(mp);
	DPAA2_SET_FD_ADDR(fd_gather, fd_iova);
	DPAA2_SET_ONLY_FD_BPID(fd_gather, bpid);
	if (attach_mbuf)
		DPAA2_SET_FD_IVP(fd_gather);

	DPAA2_SET_FD_OFFSET(fd_gather, sg_offset);
	DPAA2_FD_SET_FORMAT(fd_gather, qbman_fd_sg);
	DPAA2_RESET_FD_FRC(fd_gather);
	DPAA2_RESET_FD_CTRL(fd_gather);
	/*Set Scatter gather table and Scatter gather entries*/
	sgt = (struct qbman_sge *)(fd_va + sg_offset);

	for (i = 0; i < nb_pkts; i++) {
		seg_len = ALIGN(tx_pkts[i]->pkt_len, LSINIC_MG_ALIGN_SIZE);
		if ((tmp_mbuf->data_off + total_len + seg_len) >= sg_offset)
			break;
		if (total_len + seg_len >= merge_max)
			break;
		align_off = seg_len - tx_pkts[i]->pkt_len;
		mg_header->len_cmd[i] =
			lsinic_mg_entry_set(tx_pkts[i]->pkt_len,
				align_off);

		sge = &sgt[i];
		/*Resetting the buffer pool id and offset field*/
		sge->fin_bpid_offset = 0;
		DPAA2_SET_FLE_ADDR(sge, DPAA2_MBUF_VADDR_TO_IOVA(tx_pkts[i]));
		DPAA2_SET_FLE_OFFSET(sge, tx_pkts[i]->data_off);
		if (!(tx_pkts[i]->ol_flags & LSINIC_SHARED_MBUF)) {
			if (likely(tx_pkts[i] != tmp_mbuf))
				DPAA2_SET_FLE_BPID(sge,
					mempool_to_bpid(tx_pkts[i]->pool));
			else
				DPAA2_SET_FLE_IVP(sge);
		} else {
			DPAA2_SET_FLE_BPID(sge,
				mempool_to_bpid(tx_pkts[i]->pool));
			if (unlikely(RTE_MBUF_DIRECT(tx_pkts[i]))) {
				if (tx_pkts[i]->refcnt > 1) {
					DPAA2_SET_FLE_IVP(sge);
					tx_pkts[i]->refcnt--;
				}
				tx_pkts[i]->ol_flags = 0;
			} else {
				struct rte_mbuf *mi;

				mi = rte_mbuf_from_indirect(tx_pkts[i]);
				if (mi->refcnt > 1) {
					DPAA2_SET_FLE_IVP(sge);
					mi->refcnt--;
				}
				if (likely(tx_pkts[i] != attach_mbuf)) {
					free_bufs[free_nb] = tx_pkts[i];
					free_nb++;
				}
			}
		}

		sge->length = seg_len;
		total_len += seg_len;
		sg_num++;
	}

	if (unlikely(!sg_num))
		return 0;

	if (sg_num < LSINIC_MERGE_MAX_NUM)
		mg_header->len_cmd[sg_num] = 0;

	mg_dsc->attach_mbuf = attach_mbuf;

	DPAA2_SET_FD_LEN(fd_gather, total_len);
	DPAA2_SG_SET_FINAL(sge, true);

	if (free_nb > 0) {
		for (i = 0; i < free_nb; i++)
			lsinic_mbuf_reset(free_bufs[i]);
		rte_mempool_put_bulk(mp, (void * const *)free_bufs, free_nb);
	}

	return sg_num;
}

static void
lsinic_dpaa2_enqueue(struct dpaa2_queue *txq,
	struct qbman_fd *fd_arr, int fd_nb)
{
	int ret;
	uint16_t loop = 0;
	struct qbman_eq_desc eqdesc;
	struct qbman_swp *swp;

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			LSXINIC_PMD_ERR("Failure in affining portal");
			return;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	while (qbman_result_SCN_state(txq->cscn))
		;

	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_fq(&eqdesc, txq->fqid);

	while (loop < fd_nb) {
		ret = qbman_swp_enqueue_multiple(swp, &eqdesc,
				&fd_arr[loop], 0,
				fd_nb - loop);
		if (likely(ret >= 0))
			loop += ret;
	}
}

static uint16_t
lsinic_xmit_directly(struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts, struct lsinic_queue *txq,
	struct rte_mbuf **mg_pkts);

static uint16_t
lsinic_dpaa2_merge_tx_lpbk(void *queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_fd fd_gather[LSINIC_MERGE_MAX_NUM];
	uint16_t fd_num = 0, tx_num = 0, ret, direct_nb;
	struct rte_mbuf *mg_pkts[LSINIC_MERGE_MAX_NUM];
	struct lsinic_dpni_mg_dsc *mg_dsc;
	struct lsinic_queue *lsinic_q =
			(struct lsinic_queue *)dpaa2_q->lpbk_cntx;

	direct_nb = lsinic_xmit_directly(tx_pkts, nb_pkts, lsinic_q, mg_pkts);
	nb_pkts -= direct_nb;

	while (nb_pkts) {
		if (((lsinic_q->mg_dsc_tail + 1) & (lsinic_q->nb_desc - 1)) ==
			lsinic_q->mg_dsc_head)
			break;
		mg_dsc = &lsinic_q->mg_dsc[lsinic_q->mg_dsc_tail];
		ret = lsinic_dpaa2_merge_sg(&mg_pkts[tx_num],
				nb_pkts, &fd_gather[fd_num], mg_dsc,
				lsinic_q->adapter->data_room_size);
		if (ret > 0) {
			lsinic_q->mg_dsc_tail =
				(lsinic_q->mg_dsc_tail + 1) &
				(lsinic_q->nb_desc - 1);
			fd_num++;
		}
		tx_num += ret;
		nb_pkts -= ret;
	}
	if (fd_num > 0) {
		lsinic_dpaa2_enqueue(dpaa2_q, fd_gather, fd_num);
		lsinic_q->recycle_pending += fd_num;
	}
	return tx_num + direct_nb;
}

static uint16_t lsinic_dpaa2_split_mbuf_to_fd(
	struct rte_mbuf *mbuf, struct qbman_fd *fd_arr,
	uint16_t num, uint32_t *total_size)
{
	uint16_t idx = 0, offset = 0;
	char *data_base = rte_pktmbuf_mtod(mbuf, char *);
	struct lsinic_mg_header *mg_header = 0;
	uint32_t bpid = mempool_to_bpid(mbuf->pool);
	uint32_t size = 0;

	if (num <= 1) {
		DPAA2_SET_FD_ADDR(&fd_arr[0], mbuf->buf_iova);
		DPAA2_SET_FD_LEN(&fd_arr[0], mbuf->pkt_len);
		DPAA2_SET_ONLY_FD_BPID(&fd_arr[0], bpid);
		DPAA2_SET_FD_OFFSET(&fd_arr[0], mbuf->data_off);
		DPAA2_SET_FD_FRC(&fd_arr[0], 0);
		DPAA2_RESET_FD_CTRL(&fd_arr[0]);
		DPAA2_RESET_FD_FLC(&fd_arr[0]);
		if (total_size)
			*total_size = mbuf->pkt_len;
		return 1;
	}

	mg_header = (struct lsinic_mg_header *)data_base;
	mg_header--;

	for (idx = 0; idx < num; idx++) {
		DPAA2_SET_FD_ADDR(&fd_arr[idx], mbuf->buf_iova);
		DPAA2_SET_FD_LEN(&fd_arr[idx],
			lsinic_mg_entry_len(mg_header->len_cmd[idx]));
		size += lsinic_mg_entry_len(mg_header->len_cmd[idx]);
		/* Just for clear bpid_offset*/
		DPAA2_SET_ONLY_FD_BPID(&fd_arr[idx], 0);
		DPAA2_SET_FD_IVP(&fd_arr[idx]);
		DPAA2_SET_FD_OFFSET(&fd_arr[idx],
			mbuf->data_off + offset);
		DPAA2_SET_FD_FRC(&fd_arr[idx], 0);
		DPAA2_RESET_FD_CTRL(&fd_arr[idx]);
		DPAA2_RESET_FD_FLC(&fd_arr[idx]);

		if ((idx + 1) == num) {
			DPAA2_SET_ONLY_FD_BPID(&fd_arr[idx], bpid);
			break;
		}
		offset += lsinic_mg_entry_len(mg_header->len_cmd[idx]);
		offset += lsinic_mg_entry_align_offset(mg_header->len_cmd[idx]);
	}

	if (total_size)
		*total_size = size;

	return (idx + 1);
}

static uint16_t
lsinic_dpaa2_split_tx_lpbk(void *queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct dpaa2_queue *txq = (struct dpaa2_queue *)queue;
	struct lsinic_queue *lsinic_q =
		(struct lsinic_queue *)txq->lpbk_cntx;
	struct qbman_fd *fd_arr = lsinic_q->recycle_fd;
	uint32_t i, fd_idx = 0, count, len = 0, total_size = 0;

	for (i = 0; i < nb_pkts; i++) {
		count = lsinic_dpaa2_split_mbuf_to_fd(tx_pkts[i],
				&fd_arr[fd_idx],
				lsinic_q->split_cnt[i], &len);
		total_size += len;
		fd_idx += count;
	}

	lsinic_q->bytes += total_size;
	lsinic_q->bytes_fcs +=
		len + LSINIC_ETH_FCS_SIZE * fd_idx;
	lsinic_q->bytes_overhead +=
		len + LSINIC_ETH_OVERHEAD_SIZE * fd_idx;

	lsinic_q->packets += fd_idx;

	if (fd_idx > 0) {
		lsinic_dpaa2_enqueue(txq, fd_arr, fd_idx);
		lsinic_q->recycle_pending += fd_idx;
	}

	return nb_pkts;
}

static int s_use_split_tx_cb;

static int
lsinic_hw_offload_queue_setup(struct lsinic_queue *q)
{
	struct lsinic_adapter *adapter = q->adapter;
	struct dpaa2_queue *dpaa2_txq = NULL;
	struct dpaa2_queue *dpaa2_rxq = NULL;
	struct rte_dpaa2_device *dpaa2_dev = NULL;
	int ret = -1;
	eth_rx_burst_t rx_lpbk = NULL;
	eth_tx_burst_t tx_lpbk = NULL;

	if (q->type == LSINIC_QUEUE_TX &&
		adapter->merge_dev) {
		dpaa2_dev = adapter->merge_dev;
		rx_lpbk = lsinic_dpaa2_rx_lpbk;
		tx_lpbk = lsinic_dpaa2_merge_tx_lpbk;
	} else if (q->type == LSINIC_QUEUE_RX &&
		adapter->split_dev) {
		dpaa2_dev = adapter->split_dev;
		if (!(adapter->ep_cap &
			LSINIC_EP_CAP_HW_DIRECT_EGRESS)) {
			rx_lpbk = lsinic_dpaa2_rx_lpbk;
			tx_lpbk = lsinic_dpaa2_split_tx_lpbk;
		}
		if (getenv("LSINIC_HW_SPLIT_TX_CB"))
			s_use_split_tx_cb = atoi("LSINIC_HW_SPLIT_TX_CB");
	}

	if (dpaa2_dev) {
		ret = rte_pmd_dpaa2_dev_recycle_qp_setup(dpaa2_dev,
				q->queue_id, (uint64_t)q,
				tx_lpbk, rx_lpbk,
				&dpaa2_txq, &dpaa2_rxq);
		if (!ret) {
			q->recycle_txq = dpaa2_txq;
			if (q->type == LSINIC_QUEUE_TX &&
				adapter->ep_cap &
				LSINIC_EP_CAP_RCV_MERGE_RECYCLE_RX)
				q->recycle_rxq = dpaa2_rxq;
			else if (q->type == LSINIC_QUEUE_RX &&
				adapter->ep_cap &
				LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX)
				q->recycle_rxq = dpaa2_rxq;
			else
				q->recycle_rxq = NULL;
		}
	}

	return ret;
}

static int
lsinic_txq_merge_dev_config(struct lsinic_adapter *adapter)
{
	struct rte_eth_dev *recycle_dev;
	int ret;

	recycle_dev = adapter->merge_dev->eth_dev;
	ret = lsinic_add_recycle_dev_list(recycle_dev);
	if (ret) {
		LSXINIC_PMD_WARN("Failed to add %s to list",
			recycle_dev->data->name);
		adapter->merge_dev = NULL;
		adapter->ep_cap &= ~LSINIC_EP_CAP_HW_MERGE_PKTS;
		adapter->merge_dev_cfg_done = 1;

		return ret;
	}
	recycle_dev->data->dev_conf.lpbk_mode = 1;
	ret = recycle_dev->dev_ops->dev_configure(recycle_dev);
	if (ret) {
		LSXINIC_PMD_WARN("Failed to configure %s",
			recycle_dev->data->name);
		recycle_dev->data->dev_conf.lpbk_mode = 0;
		lsinic_remove_recycle_dev_list(recycle_dev);
		adapter->merge_dev = NULL;
		adapter->ep_cap &= ~LSINIC_EP_CAP_HW_MERGE_PKTS;
		adapter->merge_dev_cfg_done = 1;

		return ret;
	}
	LSXINIC_PMD_INFO("%s uses %s to merge packets < %dB",
		adapter->lsinic_dev->eth_dev->data->name,
		recycle_dev->data->name,
		adapter->merge_threshold);
	adapter->merge_dev_cfg_done = 1;

	return 0;
}

static int
lsinic_txq_hw_offload_cfg(struct lsinic_queue *txq)
{
	struct lsinic_adapter *adapter = txq->adapter;
	int ret = 0;
	rte_spinlock_t *lock = &adapter->merge_dev_cfg_lock;

	if (adapter->ep_cap & LSINIC_EP_CAP_HW_MERGE_PKTS) {
		rte_spinlock_lock(lock);
		if (!adapter->merge_dev_cfg_done) {
			ret = lsinic_txq_merge_dev_config(adapter);
			adapter->merge_dev_cfg_done = 1;
			if (ret) {
				rte_spinlock_unlock(lock);

				return ret;
			}
		}
		rte_spinlock_unlock(lock);
		ret = lsinic_hw_offload_queue_setup(txq);
	}

	return ret;
}

static void
lsinic_txq_merge_dev_deconfig(struct lsinic_adapter *adapter)
{
	struct rte_eth_dev *recycle_dev;
	int ret;

	recycle_dev = adapter->merge_dev->eth_dev;
	lsinic_remove_recycle_dev_list(recycle_dev);
	recycle_dev->data->dev_conf.lpbk_mode = 0;
	ret = recycle_dev->dev_ops->dev_configure(recycle_dev);
	if (ret) {
		LSXINIC_PMD_WARN("Recycle dev %s cfg failed",
			recycle_dev->data->name);
	}
	adapter->merge_dev = NULL;
}

static void
lsinic_txq_hw_offload_decfg(struct lsinic_queue *txq)
{
	struct lsinic_adapter *adapter = txq->adapter;
	rte_spinlock_t *lock = &adapter->merge_dev_cfg_lock;

	if (adapter->ep_cap & LSINIC_EP_CAP_HW_MERGE_PKTS) {
		rte_spinlock_lock(lock);
		if (adapter->merge_dev)
			lsinic_txq_merge_dev_deconfig(adapter);
		txq->recycle_txq = NULL;
		txq->recycle_rxq = NULL;
		rte_spinlock_unlock(lock);
	}
}

static int
lsinic_rxq_split_dev_config(struct lsinic_adapter *adapter)
{
	struct rte_eth_dev *recycle_dev;
	int ret;

	recycle_dev = adapter->split_dev->eth_dev;
	ret = lsinic_add_recycle_dev_list(recycle_dev);
	if (ret) {
		LSXINIC_PMD_WARN("Failed to add %s to list",
			recycle_dev->data->name);
		adapter->split_dev = NULL;
		adapter->ep_cap &=
			~LSINIC_EP_CAP_HW_SPLIT_PKTS;

		return ret;
	}
	recycle_dev->data->dev_conf.lpbk_mode = 1;
	ret = recycle_dev->dev_ops->dev_configure(recycle_dev);
	if (ret) {
		LSXINIC_PMD_WARN("Failed to configure %s",
			recycle_dev->data->name);
			recycle_dev->data->dev_conf.lpbk_mode = 0;
		lsinic_remove_recycle_dev_list(recycle_dev);

		adapter->split_dev = NULL;
		adapter->ep_cap &=
			~LSINIC_EP_CAP_HW_SPLIT_PKTS;

		return ret;
	}
	lsinic_split_dev_flow_create(adapter);
	return 0;
}

static int
lsinic_rxq_hw_offload_cfg(struct lsinic_queue *rxq)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	int ret;
	rte_spinlock_t *lock = &adapter->split_dev_cfg_lock;

	if (adapter->ep_cap & LSINIC_EP_CAP_MBUF_CLONE_SPLIT_PKTS) {
		rxq->split_type = LSINIC_MBUF_CLONE_SPLIT;
	} else if (adapter->ep_cap & LSINIC_EP_CAP_HW_SPLIT_PKTS) {
		rxq->split_type = LSINIC_HW_SPLIT;
		if (adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS) {
			ret = lsinic_hw_offload_queue_setup(rxq);
			if (ret)
				return ret;
		} else {
			rte_spinlock_lock(lock);
			if (!adapter->split_dev_cfg_done) {
				ret = lsinic_rxq_split_dev_config(adapter);
				adapter->split_dev_cfg_done = 1;
				if (ret) {
					rte_spinlock_unlock(lock);

					return ret;
				}
			}
			rte_spinlock_unlock(lock);
			lsinic_hw_offload_queue_setup(rxq);
		}
		rxq->recycle_fd = rte_malloc(NULL,
			sizeof(struct qbman_fd) *
			rxq->nb_desc *
			LSINIC_MERGE_MAX_NUM, 64);
	} else {
		rxq->split_type = LSINIC_CPU_SPLIT;
	}

	return 0;
}

static void
lsinic_rxq_split_dev_deconfig(struct lsinic_adapter *adapter)
{
	struct rte_eth_dev *recycle_dev;
	int ret;

	recycle_dev = adapter->split_dev->eth_dev;
	lsinic_remove_recycle_dev_list(recycle_dev);
	recycle_dev->data->dev_conf.lpbk_mode = 0;
	ret = recycle_dev->dev_ops->dev_configure(recycle_dev);
	if (ret) {
		LSXINIC_PMD_WARN("Recycle dev %s cfg failed",
			recycle_dev->data->name);
	}
	adapter->split_dev = NULL;
}

static void
lsinic_rxq_hw_offload_decfg(struct lsinic_queue *rxq)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	rte_spinlock_t *lock = &adapter->split_dev_cfg_lock;

	if (!(adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS) &&
		adapter->ep_cap & LSINIC_EP_CAP_HW_SPLIT_PKTS) {
		rte_spinlock_lock(lock);
		if (adapter->split_dev)
			lsinic_rxq_split_dev_deconfig(adapter);
		rxq->recycle_txq = NULL;
		rxq->recycle_rxq = NULL;
		rte_spinlock_unlock(lock);
	}
}

static int
lsinic_queue_hw_offload_cfg(struct lsinic_queue *q)
{
	if (q->type == LSINIC_QUEUE_TX)
		return lsinic_txq_hw_offload_cfg(q);
	else
		return lsinic_rxq_hw_offload_cfg(q);
}

static void
lsinic_queue_hw_offload_decfg(struct lsinic_queue *q)
{
	if (q->type == LSINIC_QUEUE_TX)
		lsinic_txq_hw_offload_decfg(q);
	else
		lsinic_rxq_hw_offload_decfg(q);
}

static int
lsinic_cloned_mbuf_to_fd(struct rte_mbuf *mbuf,
	struct qbman_fd *fd, uint16_t bpid,
	struct rte_mbuf **free_buf)
{
	/* Assert the mbuf to be sent has NOT been migrated between cores.*/
	if (unlikely(!(mbuf->ol_flags & LSINIC_SHARED_MBUF)))
		return -1;

	RTE_ASSERT(*((uint8_t *)mbuf->dynfield1) == rte_lcore_id());
	DPAA2_SET_FD_ADDR(fd, DPAA2_MBUF_VADDR_TO_IOVA(mbuf));
	DPAA2_SET_FD_LEN(fd, mbuf->data_len);
	DPAA2_SET_ONLY_FD_BPID(fd, bpid);
	DPAA2_SET_FD_OFFSET(fd, mbuf->data_off);
	DPAA2_SET_FD_FRC(fd, 0);
	DPAA2_RESET_FD_CTRL(fd);
	DPAA2_RESET_FD_FLC(fd);

	if (unlikely(RTE_MBUF_DIRECT(mbuf))) {
		if (mbuf->refcnt > 1) {
			DPAA2_SET_FD_IVP(fd);
			mbuf->refcnt--;
		}
		mbuf->ol_flags = 0;
	} else {
		struct rte_mbuf *mi;

		mi = rte_mbuf_from_indirect(mbuf);
		RTE_ASSERT(*((uint8_t *)mi->dynfield1) == rte_lcore_id());
		if (mi->refcnt > 1) {
			DPAA2_SET_FD_IVP(fd);
			mi->refcnt--;
		}
		lsinic_mbuf_reset(mbuf);
		*free_buf = mbuf;

		return 1;
	}

	return 0;
}

static uint16_t
lsinic_try_to_merge(struct lsinic_queue *txq,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts, uint16_t bd_idx)
{
	struct lsinic_bd_desc *ep_txd = NULL;
	struct lsinic_ep_tx_dst_addr *dst_addr = NULL;
	struct lsinic_dma_job *dma_job;
	struct lsinic_sw_bd *txe;
	struct rte_mbuf *tx_pkt, *free_pkt = NULL;

	uint16_t mg_num;
	uint16_t mg_len = 0;
	uint16_t i;

	char *buf, *data = NULL;
	uint64_t buf_dma_addr = 0;
	struct lsinic_mg_header *mg_header;
	uint16_t align_len, align_off;
	struct lsinic_rc_rx_len_cmd *local_cmd;

	if (tx_pkts[0]->nb_segs > 1)
		return 0;

	/* how many packets can be merged */
	for (mg_num = 0; mg_num < nb_pkts; mg_num++) {
		tx_pkt = tx_pkts[mg_num];
		mg_len += ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
		/* todo calculate sg mbuf */
		if (mg_len > txq->adapter->data_room_size)
			break;
		if (mg_num == LSINIC_MERGE_MAX_NUM)
			break;
		if (tx_pkt->pkt_len > txq->adapter->merge_threshold)
			break;
	}

	/* Not need to merge */
	if (mg_num <= 1)
		return 0;

	mg_len += sizeof(struct lsinic_mg_header);

	if (txq->ep_mem_bd_type == EP_MEM_DST_ADDR_BD)
		dst_addr = &txq->tx_dst_addr[bd_idx];
	else
		ep_txd = &txq->local_src_bd_desc[bd_idx];
	dma_job = &txq->dma_jobs[bd_idx];

	txe = &txq->sw_ring[bd_idx];

	/* The first packet */
	if (!(tx_pkts[0]->ol_flags & LSINIC_SHARED_MBUF)) {
		tx_pkt = tx_pkts[0];
	} else {
		tx_pkt = rte_pktmbuf_alloc(tx_pkts[0]->pool);
		tx_pkt->nb_segs = 1;
		tx_pkt->next = NULL;
		tx_pkt->data_off = RTE_PKTMBUF_HEADROOM;
		rte_memcpy((char *)tx_pkt->buf_addr + tx_pkt->data_off,
			(char *)tx_pkts[0]->buf_addr + tx_pkts[0]->data_off,
			tx_pkts[0]->pkt_len);
		tx_pkt->pkt_len = tx_pkts[0]->pkt_len;
		tx_pkt->data_len = tx_pkts[0]->data_len;

		if ((RTE_MBUF_DIRECT(tx_pkts[0]))) {
			tx_pkts[0]->ol_flags = 0;
			if (tx_pkts[0]->refcnt > 1)
				tx_pkts[0]->refcnt--;
			else
				rte_pktmbuf_free(tx_pkts[0]);
		} else {
			struct rte_mbuf *mi;

			mi = rte_mbuf_from_indirect(tx_pkts[0]);
			if (mi->refcnt > 1)
				mi->refcnt--;
			else
				rte_pktmbuf_free(mi);

			lsinic_mbuf_reset(tx_pkts[0]);
			rte_pktmbuf_free(tx_pkts[0]);
		}
	}
	if (txe->mbuf)
		free_pkt = txe->mbuf;

	txe->mbuf = tx_pkt;
	buf_dma_addr = rte_mbuf_data_iova(tx_pkt);

	data = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
	mg_header = (struct lsinic_mg_header *)data;
	mg_header--;
	align_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
	align_off = align_len - tx_pkt->pkt_len;
	mg_header->len_cmd[0] =
		lsinic_mg_entry_set(tx_pkt->pkt_len, align_off);

	mg_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
	buf = data + mg_len;

	txq->bytes += tx_pkt->pkt_len;
	txq->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	txq->bytes_overhead += tx_pkt->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;

	for (i = 1; i < mg_num; i++) {
		if ((i + 2) < mg_num) {
			char *p = rte_pktmbuf_mtod(tx_pkts[i + 1], char *);

			/* Prefetch mbuf for the next */
			rte_lsinic_prefetch(p);
			p = rte_pktmbuf_mtod(tx_pkts[i + 2], char *);
			/* Prefetch data for the next next data*/
			rte_lsinic_prefetch(p);
		}

		tx_pkt = tx_pkts[i];

		align_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
		align_off = align_len - tx_pkt->pkt_len;
		mg_header->len_cmd[i] =
			lsinic_mg_entry_set(tx_pkt->pkt_len, align_off);
		rte_memcpy(buf, rte_pktmbuf_mtod(tx_pkt, char *),
			tx_pkt->pkt_len);
		mg_len += align_len;
		buf = data + mg_len;
		txq->bytes += tx_pkt->pkt_len;
		txq->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		txq->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
	}

	if (i < LSINIC_MERGE_MAX_NUM)
		mg_header->len_cmd[i] = 0;

	for (i = 1; i < mg_num; i++) {
		if (tx_pkts[i]->ol_flags & LSINIC_SHARED_MBUF) {
			if ((RTE_MBUF_DIRECT(tx_pkts[i]))) {
				tx_pkts[i]->ol_flags = 0;
				if (tx_pkts[i]->refcnt > 1)
					tx_pkts[i]->refcnt--;
			} else {
				struct rte_mbuf *mi;

				mi = rte_mbuf_from_indirect(tx_pkts[i]);
				if (mi->refcnt > 1)
					mi->refcnt--;
				else
					rte_pktmbuf_free(mi);
				lsinic_mbuf_reset(tx_pkts[i]);
			}
		}
	}

	if (free_pkt) {
		tx_pkts[0] = free_pkt;
		rte_mempool_put_bulk(tx_pkts[0]->pool,
			(void *)&tx_pkts[0], mg_num);
	} else {
		rte_mempool_put_bulk(tx_pkts[0]->pool,
			(void *)&tx_pkts[1], mg_num - 1);
	}
	txq->packets += mg_num;
	if (ep_txd) {
		ep_txd->len_cmd = LSINIC_BD_CMD_EOP | LSINIC_BD_CMD_MG;
		ep_txd->len_cmd |= mg_len;
		ep_txd->len_cmd |=
			(((uint32_t)mg_num) << LSINIC_BD_MG_NUM_SHIFT);
	}

	if (txq->local_src_len_cmd) {
		local_cmd = &txq->local_src_len_cmd[bd_idx];
		local_cmd->total_len = mg_len;
		if (ep_txd) {
			EP2RC_TX_IDX_CNT_SET(local_cmd->cnt_idx,
				lsinic_bd_ctx_idx(ep_txd->bd_status),
				mg_num);
		} else {
			EP2RC_TX_IDX_CNT_SET(local_cmd->cnt_idx,
				0, mg_num);
		}
	}
	dma_job->src = buf_dma_addr - sizeof(struct lsinic_mg_header);
	if (ep_txd) {
		dma_job->dst = txq->ob_base + ep_txd->pkt_addr;
	} else {
		dma_job->dst = txq->ob_base + dst_addr->pkt_addr;
		dst_addr->pkt_addr = 0;
	}
	dma_job->dst -= sizeof(struct lsinic_mg_header);
	dma_job->len = mg_len + sizeof(struct lsinic_mg_header);
	dma_job->cnxt = (uint64_t)txe;

	if (txq->wdma_bd_start == LSINIC_BD_DMA_START_FLAG)
		txq->wdma_bd_start = bd_idx;

	return mg_num;
}

static uint16_t
lsinic_cpu_merge_xmit(struct lsinic_queue *txq,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	int ret;
	uint16_t bd_idx;

	bd_idx = lsinic_queue_next_avail_idx(txq, 0);

	/* Make sure there are enough TX descriptors available to
	 * transmit the entire packet.
	 * nb_used better be less than or equal to txq->tx_rs_thresh
	 */
	if (unlikely(txq->ep_mem_bd_type == EP_MEM_LONG_BD &&
		!lsinic_tx_bd_available(txq, bd_idx))) {
		txq->ring_full++;
		txq->drop_packet_num += nb_pkts;
		ret = 0;
		if (!txq->rc_bd_desc || !s_lsx_tx_busy_log)
			goto xmit_quit;

		LSXINIC_PMD_WARN("Status[%d]: remote(0x%08x)/local(0x%08x)",
			bd_idx, txq->rc_bd_desc[bd_idx].bd_status,
			txq->ep_bd_desc[bd_idx].bd_status);
		LSXINIC_PMD_WARN("DMA BD update: pir(%d-%d)",
			txq->rdma_bd_start, txq->ep_reg->pir);
		goto xmit_quit;
	}

	if (unlikely(txq->ep_mem_bd_type == EP_MEM_DST_ADDR_BD &&
		!txq->tx_dst_addr[bd_idx].pkt_addr)) {
		txq->ring_full++;
		txq->drop_packet_num += nb_pkts;
		ret = 0;
		if (!s_lsx_tx_busy_log)
			goto xmit_quit;

		LSXINIC_PMD_WARN("TXQ%d remote addr[%d] unavailable",
			txq->queue_id, bd_idx);
		if (!txq->rc_tx_dst_addr)
			goto xmit_quit;

		LSXINIC_PMD_WARN("Address(0x%lx) in RC, pir(%d-%d)",
			txq->rc_tx_dst_addr[bd_idx].pkt_addr,
			txq->rdma_bd_start, txq->ep_reg->pir);
		goto xmit_quit;
	}

	LSXINIC_PMD_DBG("port%d txq%d next_avail_idx=%d bd_idx=%d",
		txq->port_id, txq->queue_id,
		txq->next_avail_idx, bd_idx);

	ret = lsinic_try_to_merge(txq, tx_pkts, nb_pkts, bd_idx);
	if (ret) {
		if (txq->ep_mem_bd_type == EP_MEM_LONG_BD)
			lsinic_lbd_dma_start_update(txq, bd_idx);
		txq->jobs_pending++;
		txq->txq_dma_eq(txq, true);
		txq->next_avail_idx++;
	}

xmit_quit:
	return ret;
}
#endif

static __rte_always_inline struct lsinic_sw_bd *
lsinic_recv_rxe_no_dq(struct lsinic_queue *rxq,
	uint16_t bd_idx)
{
	struct lsinic_sw_bd *rxe = &rxq->sw_ring[bd_idx];
	struct lsinic_sw_bd *next_rxe =
		&rxq->sw_ring[(bd_idx + 1) & (rxq->nb_desc - 1)];

	if (likely(next_rxe->complete))
		rte_lsinic_prefetch(next_rxe->complete);

	if ((*rxe->complete) != LSINIC_XFER_COMPLETE_DONE_FLAG)
		return NULL;
	rxe->complete = NULL;

	return rxe;
}

static __rte_always_inline struct lsinic_sw_bd *
lsinic_recv_rxe(struct lsinic_queue *rxq,
	uint16_t bd_idx)
{
	struct lsinic_sw_bd *rxe = &rxq->sw_ring[bd_idx];

	if (!rxe->dma_complete)
		return NULL;
	rxe->dma_complete = 0;

	return rxe;
}

static __rte_always_inline void
lsinic_recv_dummy_update(struct lsinic_queue *rxq __rte_unused,
	uint16_t bd_idx __rte_unused)
{
}

static __rte_always_inline void
lsinic_recv_rxbd_update(struct lsinic_queue *rxq,
	uint16_t bd_idx)
{
	lsinic_bd_update_used_to_rc(rxq, bd_idx);
}

static int
lsinic_txq_start(struct lsinic_queue *q, uint64_t bd_bus_addr)
{
	uint32_t i;
	uint64_t dma_src_base, dma_dst_base;
	uint64_t dma_rsrc_base = 0, dma_rdst_base = 0, offset = 0;
	int ret;
	struct lsinic_dma_job *dma_jobs;
	struct lsinic_adapter *adapter = q->adapter;
	struct lsinic_bdr_reg *rc_bdr_reg;
	void *remote_dma_bd = NULL;

	if (q->ep_reg->isr && adapter->txq_dma_silent) {
		LSXINIC_PMD_ERR("TXQ%d unable to trigger ISR in %s",
			q->queue_id, "dma silent mode");

		return -ENOTSUP;
	}

	if (q->ep_reg->isr) {
		/* Don't support to write RC BD by DMA if ISR is enabled.*/
		q->dma_bd_update &= (~DMA_BD_EP2RC_UPDATE);
	}

	dma_dst_base = q->ob_base + bd_bus_addr;

	rc_bdr_reg = LSINIC_REG_OFFSET(adapter->rc_ring_virt_base,
		LSINIC_RING_REG_OFFSET);

	if (q->ep_reg->rdma) {
		q->dma_bd_update |= DMA_BD_RC2EP_UPDATE;
		dma_rsrc_base = q->ep_reg->rdmah;
		dma_rsrc_base = dma_rsrc_base << 32;
		dma_rsrc_base |= q->ep_reg->rdmal;
		offset = dma_rsrc_base - bd_bus_addr;
		remote_dma_bd = (uint8_t *)q->rc_bd_mapped_addr + offset;
		dma_rsrc_base += q->ob_base;
	}

	if (q->ep_mem_bd_type == EP_MEM_LONG_BD) {
		q->ep_bd_desc = q->ep_bd_shared_addr;
		if (q->dma_bd_update & DMA_BD_RC2EP_UPDATE) {
			q->rc_bd_desc = remote_dma_bd;
			dma_rdst_base =
				DPAA2_VADDR_TO_IOVA_AND_CHECK(q->ep_bd_desc,
					sizeof(struct lsinic_bd_desc) *
					q->nb_desc);
			if (dma_rdst_base == RTE_BAD_IOVA) {
				LSXINIC_PMD_ERR("No IOMMU map for %p, size=%lx",
					q->ep_bd_desc,
					sizeof(struct lsinic_bd_desc) *
					q->nb_desc);

				return -ENOBUFS;
			}
			q->rdma_bd_len = sizeof(struct lsinic_bd_desc);
		}
		LSXINIC_PMD_INFO("TXQ%d notify by RC with long bd",
			q->queue_id);
	} else if (q->ep_mem_bd_type == EP_MEM_DST_ADDR_BD) {
		q->tx_dst_addr = q->ep_bd_shared_addr;
		if (q->dma_bd_update & DMA_BD_RC2EP_UPDATE) {
			q->rc_tx_dst_addr = remote_dma_bd;
			dma_rdst_base =
				DPAA2_VADDR_TO_IOVA_AND_CHECK(q->tx_dst_addr,
				sizeof(struct lsinic_ep_tx_dst_addr) *
				q->nb_desc);
			if (dma_rdst_base == RTE_BAD_IOVA) {
				LSXINIC_PMD_ERR("No IOMMU map for %p, size=%lx",
					q->tx_dst_addr,
					sizeof(struct lsinic_ep_tx_dst_addr) *
					q->nb_desc);

				return -ENOBUFS;
			}
			q->rdma_bd_len = sizeof(struct lsinic_ep_tx_dst_addr);
		}
		LSXINIC_PMD_INFO("TXQ%d notify by RC with full address",
			q->queue_id);
	} else if (q->ep_mem_bd_type == EP_MEM_DST_ADDR_SEG) {
		q->tx_seg_dst_addr = q->ep_bd_shared_addr;
		LSXINIC_PMD_INFO("TXQ%d notify by RC with seg address",
			q->queue_id);
	} else {
		LSXINIC_PMD_ERR("Invalid TXQ%d ep mem bd type(%d)",
			q->queue_id, q->ep_mem_bd_type);

		return -EINVAL;
	}

	if (q->ep_bd_desc) {
		q->local_src_bd_desc = q->ep_bd_shared_addr;
	} else {
		q->local_src_bd_desc = rte_malloc(NULL,
			LSINIC_BD_RING_SIZE,
			RTE_CACHE_LINE_SIZE);
	}

	if (q->rc_mem_bd_type == RC_MEM_LONG_BD) {
		if (q->rc_bd_desc &&
			q->rc_bd_desc != q->rc_bd_mapped_addr) {
			LSXINIC_PMD_ERR("%s: %p != %p",
				__func__, q->rc_bd_desc, q->rc_bd_mapped_addr);

			return -EINVAL;
		}

		q->rc_bd_desc = q->rc_bd_mapped_addr;

		dma_src_base =
			DPAA2_VADDR_TO_IOVA_AND_CHECK(q->local_src_bd_desc,
			sizeof(struct lsinic_bd_desc) * q->nb_desc);
		if (dma_src_base == RTE_BAD_IOVA) {
			LSXINIC_PMD_ERR("No IOMMU map for %p, size=%lx",
				q->local_src_bd_desc,
				sizeof(struct lsinic_bd_desc) * q->nb_desc);

			return -ENOBUFS;
		}
		q->wdma_bd_len = sizeof(struct lsinic_bd_desc);
		LSXINIC_PMD_INFO("TXQ%d notify to RC with long bd",
			q->queue_id);
	} else if (q->rc_mem_bd_type == RC_MEM_LEN_CMD) {
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		q->tx_len_cmd = q->rc_bd_mapped_addr;
		q->local_src_len_cmd = rte_malloc(NULL,
			LSINIC_LEN_CMD_RING_SIZE,
			RTE_CACHE_LINE_SIZE);
		dma_src_base =
			DPAA2_VADDR_TO_IOVA_AND_CHECK(q->local_src_len_cmd,
			LSINIC_LEN_CMD_RING_SIZE);
		if (dma_src_base == RTE_BAD_IOVA) {
			LSXINIC_PMD_ERR("No IOMMU map for %p, size=%lx",
				q->local_src_len_cmd, LSINIC_LEN_CMD_RING_SIZE);

			return -ENOBUFS;
		}
		q->wdma_bd_len = sizeof(struct lsinic_rc_rx_len_cmd);
#else
		q->tx_len_idx = q->rc_bd_mapped_addr;
		q->local_src_len_idx = rte_malloc(NULL,
			LSINIC_LEN_IDX_RING_SIZE,
			RTE_CACHE_LINE_SIZE);
		dma_src_base =
			DPAA2_VADDR_TO_IOVA_AND_CHECK(q->local_src_len_idx,
				LSINIC_LEN_IDX_RING_SIZE);
		if (dma_src_base == RTE_BAD_IOVA) {
			LSXINIC_PMD_ERR("No IOMMU map for %p, size=%lx",
				q->local_src_len_idx, LSINIC_LEN_IDX_RING_SIZE);

			return -ENOBUFS;
		}
		q->wdma_bd_len = sizeof(struct lsinic_rc_rx_len_idx);
#endif
		LSXINIC_PMD_INFO("TXQ%d notify to RC with len/cmd",
			q->queue_id);
	} else if (q->rc_mem_bd_type == RC_MEM_SEG_LEN) {
		q->tx_seg = q->rc_bd_mapped_addr;
		q->local_src_seg = rte_malloc(NULL,
			LSINIC_SEG_LEN_RING_SIZE,
			RTE_CACHE_LINE_SIZE);
		dma_src_base = DPAA2_VADDR_TO_IOVA_AND_CHECK(q->local_src_seg,
			LSINIC_SEG_LEN_RING_SIZE);
		if (dma_src_base == RTE_BAD_IOVA) {
			LSXINIC_PMD_ERR("No IOMMU map for %p, size=%lx",
				q->local_src_seg, LSINIC_SEG_LEN_RING_SIZE);

			return -ENOBUFS;
		}
		q->wdma_bd_len = sizeof(struct lsinic_rc_rx_seg);
		LSXINIC_PMD_INFO("TXQ%d notify to RC with seg desc",
			q->queue_id);
	} else {
		LSXINIC_PMD_ERR("Invalid TXQ%d rc mem bd type(%d)",
			q->queue_id, q->rc_mem_bd_type);

		return -EINVAL;
	}

	dma_jobs = &q->dma_jobs[LSINIC_E2R_BD_DMA_START];
	for (i = 0; i < q->nb_desc; i++) {
		dma_jobs[i].src = dma_src_base + i * q->wdma_bd_len;
		dma_jobs[i].dst = dma_dst_base + i * q->wdma_bd_len;
	}
	if (dma_rsrc_base && dma_rdst_base) {
		dma_jobs = &q->dma_jobs[LSINIC_R2E_BD_DMA_START];
		for (i = 0; i < q->nb_desc; i++) {
			dma_jobs[i].src = dma_rsrc_base + i * q->rdma_bd_len;
			dma_jobs[i].dst = dma_rdst_base + i * q->rdma_bd_len;
		}
	}
	/* Note: ep-rx == rc-tx */
	if (adapter->rc_ring_virt_base)
		q->rc_reg = &rc_bdr_reg->rx_ring[q->queue_id];
	else
		q->rc_reg = q->ep_reg;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		ret = lsinic_queue_hw_offload_cfg(q);
		if (ret)
			return ret;
#endif
	lsinic_queue_reset(q);

	rte_spinlock_lock(&adapter->txq_dma_start_lock);
	if (!adapter->txq_dma_started) {
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

	q->core_id = rte_lcore_id();
	q->pid = pthread_self();

	if (q->dma_bd_update & DMA_BD_RC2EP_UPDATE)
		q->rdma_bd_start = 0;

	return 0;
}

static int
lsinic_rxq_start(struct lsinic_queue *q, uint64_t bd_bus_addr)
{
	uint32_t i;
	uint64_t dma_src_base, dma_dst_base, offset;
	struct lsinic_bd_desc *bd_desc;
	int ret;
	struct lsinic_dma_job *dma_jobs;
	struct lsinic_adapter *adapter = q->adapter;
	struct lsinic_bdr_reg *rc_bdr_reg;
	void *remote_dma_bd = NULL;

	if (q->ep_reg->isr && adapter->rxq_dma_silent) {
		LSXINIC_PMD_ERR("RXQ%d unable to trigger ISR in %s",
			q->queue_id, "dma silent mode");

		return -ENOTSUP;
	}

	if (!q->ep_reg->rdma)
		q->dma_bd_update &= (~DMA_BD_RC2EP_UPDATE);

	q->local_src_bd_desc = rte_malloc(NULL,
		LSINIC_BD_RING_SIZE,
		RTE_CACHE_LINE_SIZE);
	if (!q->local_src_bd_desc) {
		LSXINIC_PMD_ERR("RXQ%d local src bd desc alloc failed",
			q->queue_id);

		return -ENOMEM;
	}

	dma_src_base = q->ep_reg->rdmah;
	dma_src_base = dma_src_base << 32;
	dma_src_base |= q->ep_reg->rdmal;

	if ((q->dma_bd_update & DMA_BD_RC2EP_UPDATE) &&
		!dma_src_base) {
		LSXINIC_PMD_ERR("RXQ%d dma bd source is not set by RC",
			q->queue_id);

		return -EINVAL;
	}

	offset = dma_src_base - bd_bus_addr;
	remote_dma_bd = (uint8_t *)q->rc_bd_mapped_addr + offset;

	rc_bdr_reg = LSINIC_REG_OFFSET(adapter->rc_ring_virt_base,
			LSINIC_RING_REG_OFFSET);

	dma_src_base += q->ob_base;
	dma_dst_base = DPAA2_VADDR_TO_IOVA_AND_CHECK(q->ep_bd_shared_addr,
		LSINIC_BD_RING_SIZE);
	if (dma_dst_base == RTE_BAD_IOVA) {
		LSXINIC_PMD_ERR("No IOMMU map for %p, size=%lx",
			q->ep_bd_shared_addr, LSINIC_BD_RING_SIZE);

		return -ENOBUFS;
	}

	if (q->ep_mem_bd_type == EP_MEM_LONG_BD) {
		q->ep_bd_desc = q->ep_bd_shared_addr;
		bd_desc = q->ep_bd_shared_addr;
		for (i = 0; i < q->nb_desc; i++)
			bd_desc[i].bd_status = RING_BD_READY;
		if (q->dma_bd_update & DMA_BD_RC2EP_UPDATE)
			q->rc_bd_desc = remote_dma_bd;
		LSXINIC_PMD_INFO("RXQ%d notify by RC with long bd",
			q->queue_id);
		q->rdma_bd_len = sizeof(struct lsinic_bd_desc);
	} else if (q->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD) {
		q->rx_src_addrl = q->ep_bd_shared_addr;
		if (q->dma_bd_update & DMA_BD_RC2EP_UPDATE)
			q->rc_rx_src_addrl = remote_dma_bd;
		LSXINIC_PMD_INFO("RXQ%d notify by RC with low addr",
			q->queue_id);
		q->rdma_bd_len = sizeof(struct lsinic_ep_rx_src_addrl);
	} else if (q->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
		q->rx_src_addrx = q->ep_bd_shared_addr;
		if (q->dma_bd_update & DMA_BD_RC2EP_UPDATE)
			q->rc_rx_src_addrx = remote_dma_bd;
		LSXINIC_PMD_INFO("RXQ%d notify by RC with index addr",
			q->queue_id);
		q->rdma_bd_len = sizeof(struct lsinic_ep_rx_src_addrx);
	} else if (q->ep_mem_bd_type == EP_MEM_SRC_SEG_BD) {
		q->rx_src_seg = q->ep_bd_shared_addr;
		if (q->dma_bd_update & DMA_BD_RC2EP_UPDATE)
			q->rc_rx_src_seg = remote_dma_bd;
		LSXINIC_PMD_INFO("RXQ%d notify by RC with SG bd",
			q->queue_id);
		q->rdma_bd_len = sizeof(struct lsinic_seg_desc);
	} else {
		LSXINIC_PMD_ERR("Invalid RXQ ep mem bd type(%d)",
			q->ep_mem_bd_type);

		return -EINVAL;
	}

	if (q->rc_mem_bd_type == RC_MEM_LONG_BD) {
		if (q->rc_bd_desc &&
			q->rc_bd_desc != q->rc_bd_mapped_addr) {
			LSXINIC_PMD_ERR("%s: %p != %p",
				__func__, q->rc_bd_desc, q->rc_bd_mapped_addr);

			return -EINVAL;
		}
		q->rc_bd_desc = q->rc_bd_mapped_addr;
		LSXINIC_PMD_INFO("RXQ%d confirm to RC with long bd",
			q->queue_id);
	} else if (q->rc_mem_bd_type == RC_MEM_BD_CNF) {
		q->rc_rx_complete = q->rc_bd_mapped_addr;
		LSXINIC_PMD_INFO("RXQ%d confirm to RC with bd complete",
			q->queue_id);
	} else if (q->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		q->local_src_free_idx = rte_malloc(NULL,
			sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
		LSXINIC_PMD_INFO("RXQ%d confirm to RC with idx",
			q->queue_id);
	} else {
		LSXINIC_PMD_ERR("Invalid RXQ rc mem bd type(%d)",
			q->rc_mem_bd_type);

		return -EINVAL;
	}

	dma_jobs = &q->dma_jobs[LSINIC_R2E_BD_DMA_START];
	for (i = 0; i < q->nb_desc; i++) {
		dma_jobs[i].src = dma_src_base + i * q->rdma_bd_len;
		dma_jobs[i].dst = dma_dst_base + i * q->rdma_bd_len;
	}

	if (adapter->rxq_dma_silent)
		q->recv_rxe = lsinic_recv_rxe_no_dq;
	else
		q->recv_rxe = lsinic_recv_rxe;

	if (q->rc_mem_bd_type == RC_MEM_IDX_CNF)
		q->recv_update = lsinic_recv_dummy_update;
	else if (q->rc_mem_bd_type == RC_MEM_BD_CNF)
		q->recv_update = lsinic_recv_dummy_update;
	else
		q->recv_update = lsinic_recv_rxbd_update;

	if (adapter->rc_ring_virt_base)
		q->rc_reg = &rc_bdr_reg->tx_ring[q->queue_id];
	else
		q->rc_reg = q->ep_reg;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	ret = lsinic_queue_hw_offload_cfg(q);
	if (ret)
		return ret;
#endif

	lsinic_queue_reset(q);

	if (q->ep_mem_bd_type == EP_MEM_LONG_BD &&
		q->rc_mem_bd_type == RC_MEM_LONG_BD) {
		rte_memcpy(q->rc_bd_desc, q->ep_bd_desc,
			sizeof(struct lsinic_bd_desc) * q->nb_desc);
	} else if (q->rc_mem_bd_type == RC_MEM_BD_CNF) {
		for (i = 0; i < q->nb_desc; i++)
			q->rc_rx_complete[i].bd_complete = RING_BD_READY;
	}

	rte_spinlock_lock(&adapter->rxq_dma_start_lock);
	if (!adapter->rxq_dma_started) {
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

	q->core_id = rte_lcore_id();
	q->pid = pthread_self();

	if (q->dma_bd_update & DMA_BD_RC2EP_UPDATE)
		q->rdma_bd_start = 0;

	return 0;
}

static int
lsinic_queue_start(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;
	uint32_t msix_vector, cap;
	uint64_t bd_bus_addr, ob_offset, ob_size;
	struct lsinic_adapter *adapter = q->adapter;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	struct lsinic_eth_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	uint32_t ep_mem_bd_type, rc_mem_bd_type;

	LSXINIC_PMD_INFO("port%d %sq%d start, nb_desc:%d",
		q->port_id,
		q->type == LSINIC_QUEUE_TX ? "tx" : "rx",
		q->reg_idx, q->nb_desc);

	if (lsinic_dev->mmsi_flag != LSINIC_DONT_INT) {
		msix_vector =
			(LSINIC_READ_REG(&ring_reg->icr) >>
			LSINIC_INT_VECTOR_SHIFT);
		q->msix_irq = msix_vector;
		if (!rte_lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
			q->msix_cmd = lsinic_dev->msix_data[msix_vector];
			q->msix_vaddr = lsinic_dev->msix_addr[msix_vector];
			if (q->msix_vaddr == 0) {
				LSXINIC_PMD_ERR("q->msix_vaddr == NULL");
				return -EINVAL;
			}
		}
	}

	bd_bus_addr = LSINIC_READ_REG((&q->ep_reg->r_desch));
	bd_bus_addr = bd_bus_addr << 32;
	bd_bus_addr |= LSINIC_READ_REG((&q->ep_reg->r_descl));
	if (bd_bus_addr) {
		if (bd_bus_addr < adapter->rc_ring_bus_base) {
			LSXINIC_PMD_ERR("%s%d %s(0x%lx) < %s(0x%lx)",
				q->type == LSINIC_QUEUE_RX ?
				"RXQ" : "TXQ", q->queue_id,
				"BD PCIe address", bd_bus_addr,
				"BD PCIe base",
				adapter->rc_ring_bus_base);
			return -EINVAL;
		}
		ob_offset = bd_bus_addr - adapter->rc_ring_bus_base;
		ob_size = adapter->rc_ring_size;
		if (ob_offset >= ob_size) {
			LSXINIC_PMD_ERR("%s%d %s(0x%lx) > %s(0x%lx)",
				q->type == LSINIC_QUEUE_RX ?
				"RXQ" : "TXQ", q->queue_id,
				"BD PCIe offset", ob_offset,
				"OB PCIe size", ob_size);
			return -EINVAL;
		}
		q->rc_bd_mapped_addr = adapter->rc_ring_virt_base + ob_offset;
	} else {
		LSXINIC_PMD_ERR("%s%d No bd addr set from RC",
			q->type == LSINIC_QUEUE_RX ?
			"RXQ" : "TXQ", q->queue_id);
		return -EINVAL;
	}

	ep_mem_bd_type = LSINIC_READ_REG(&q->ep_reg->r_ep_mem_bd_type);
	rc_mem_bd_type = LSINIC_READ_REG(&q->ep_reg->r_rc_mem_bd_type);

	if (ep_mem_bd_type == EP_MEM_LONG_BD &&
		rc_mem_bd_type == RC_MEM_LONG_BD) {
		/** Slow path*/
		rte_spinlock_lock(&adapter->cap_lock);
		cap = q->adapter->cap;
		if (q->type == LSINIC_QUEUE_RX)
			LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_SET(cap,
				RC_XMIT_BD_CNF);
		else
			LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_SET(cap,
				EP_XMIT_LBD_TYPE);
		q->adapter->cap = cap;
		LSINIC_WRITE_REG(&reg->cap, adapter->cap);
		rte_spinlock_unlock(&adapter->cap_lock);
	}
	q->ep_mem_bd_type = ep_mem_bd_type;
	q->rc_mem_bd_type = rc_mem_bd_type;

	if (q->type == LSINIC_QUEUE_RX)
		return lsinic_rxq_start(q, bd_bus_addr);
	else
		return lsinic_txq_start(q, bd_bus_addr);
}

static void
lsinic_queue_stop(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;

	q->status = LSINIC_QUEUE_STOP;
	ring_reg->sr = q->status;
	if (q->rc_reg) {
		LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);
		q->rc_reg = NULL;
	}
	q->msix_vaddr = NULL;
}

static int
lsinic_queue_init(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;

	ring_reg->barl = q->nb_desc;
	LSINIC_WRITE_REG(&q->rc_reg->barl, q->nb_desc);

	q->status = LSINIC_QUEUE_UNAVAILABLE;
	ring_reg->sr = q->status;
	if (q->rc_reg)
		LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);

	return 0;
}

static void
lsinic_queue_enable_start(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;
	uint32_t delay_ms = 0;
	int wait_max_sec = LSINIC_RING_WAIT_DEFAULT_SEC;
	enum LSINIC_QEUE_STATUS status = LSINIC_QUEUE_START;

	if (getenv("LSINIC_RING_WAIT_SEC")) {
		wait_max_sec = atoi("LSINIC_RING_WAIT_SEC");
		if (wait_max_sec < 0)
			wait_max_sec = LSINIC_RING_WAIT_DEFAULT_SEC;
	}
	q->status = LSINIC_QUEUE_START;
	rte_smp_wmb();
	do {
		rte_delay_us_sleep(1000);
		rte_smp_rmb();
		delay_ms++;
		status = q->status;
		if (status == LSINIC_QUEUE_START &&
			!(delay_ms % 1000)) {
			LSXINIC_PMD_WARN("%s%d not running after %d seconds",
				q->type == LSINIC_QUEUE_RX ?
				"RXQ" : "TXQ", q->queue_id, delay_ms / 1000);
			wait_max_sec--;
		}
	} while (status == LSINIC_QUEUE_START && wait_max_sec > 0);

	if (status != LSINIC_QUEUE_RUNNING)	{
		LSXINIC_PMD_WARN("%s%d un-expected status(%d)",
			q->type == LSINIC_QUEUE_RX ?
			"RXQ" : "TXQ", q->queue_id, status);
	}
	ring_reg->sr = q->status;
	if (q->rc_reg)
		LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);
}

static void
lsinic_queue_release_mbufs(struct lsinic_queue *q)
{
	unsigned int i;

	if (q->sw_ring) {
		for (i = 0; i < q->nb_desc; i++) {
			if (q->sw_ring[i].mbuf) {
				rte_pktmbuf_free(q->sw_ring[i].mbuf);
				q->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

static void
lsinic_queue_free_swring(struct lsinic_queue *q)
{
	if (!q)
		return;

	if (q->sw_ring)
		rte_free(q->sw_ring);
	if (q->dma_jobs)
		rte_free(q->dma_jobs);
}

void
lsinic_queue_release(struct lsinic_queue *q)
{
	if (!q)
		return;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	lsinic_queue_hw_offload_decfg(q);
#endif

	lsinic_queue_release_mbufs(q);
	lsinic_queue_free_swring(q);
	lsinic_queue_dma_release(q);

	if (q->type == LSINIC_QUEUE_RX &&
		q->local_src_free_idx)
		rte_free(q->local_src_free_idx);
	else if (q->type == LSINIC_QUEUE_TX) {
		if (q->rc_mem_bd_type == RC_MEM_SEG_LEN) {
			if (q->local_src_seg)
				rte_free(q->local_src_seg);
		} else {
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
			if (q->local_src_len_cmd)
				rte_free(q->local_src_len_cmd);
#else
			if (q->local_src_len_idx)
				rte_free(q->local_src_len_idx);
#endif
		}
	}

	if (q->local_src_bd_desc &&
		q->local_src_bd_desc != q->ep_bd_desc)
		rte_free(q->local_src_bd_desc);

	rte_free(q);
}

struct lsinic_queue *
lsinic_queue_alloc(struct lsinic_adapter *adapter,
	uint16_t queue_idx,
	int socket_id, uint32_t nb_desc,
	enum LSINIC_QEUE_TYPE type)
{
	struct lsinic_queue *q;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	RTE_SET_USED(lsinic_cloned_mbuf_to_fd);
#endif

	/* Validate number of transmit descriptors.
	 * It must not exceed hardware maximum, and must be multiple
	 * of LSINIC_ALIGN.
	 */
	if (((nb_desc * sizeof(struct lsinic_bd_desc)) % LSINIC_ALIGN) != 0 ||
	    nb_desc > LSINIC_MAX_RING_DESC ||
	    nb_desc < LSINIC_MIN_RING_DESC) {
		LSXINIC_PMD_ERR("lsinic queue cannot support %d descs",
			     nb_desc);
		return NULL;
	}

	/* First allocate the tx queue data structure */
	if (type == LSINIC_QUEUE_RX)
		q = &adapter->rxqs[queue_idx];
	else
		q = &adapter->txqs[queue_idx];

	q->adapter = adapter;
	q->type = type;

	q->nb_desc = nb_desc;
	q->queue_id = queue_idx;
	q->reg_idx = queue_idx;
	q->nb_q = 1;
	q->dma_vq = -1;

	/* Allocate software ring */
	q->sw_ring = rte_zmalloc_socket("q->sw_ring",
		sizeof(struct lsinic_sw_bd) * nb_desc,
		RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->sw_ring) {
		LSXINIC_PMD_ERR("Failed to create sw_ring");
		goto _err;
	}

	/* Allocate DMA jobs ring */
	q->dma_jobs = rte_zmalloc_socket("q->dma_jobs",
		sizeof(struct lsinic_dma_job) * LSINIC_BD_DMA_MAX_COUNT,
		RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->dma_jobs) {
		LSXINIC_PMD_ERR("Failed to create dma_jobs");
		goto _err;
	}

	q->dma_seg_jobs = rte_zmalloc_socket("q->dma_seg_jobs",
		sizeof(struct lsinic_dma_seg_job) * LSINIC_BD_DMA_MAX_COUNT,
		RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->dma_seg_jobs) {
		LSXINIC_PMD_ERR("Failed to create dma_seg_jobs");
		goto _err;
	}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	q->mg_dsc = rte_zmalloc_socket(NULL,
		sizeof(struct lsinic_dpni_mg_dsc) * nb_desc,
		RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->mg_dsc) {
		LSXINIC_PMD_ERR("Failed to alloc merge descriptors");
		goto _err;
	}
	q->mg_dsc_head = 0;
	q->mg_dsc_tail = 0;
#endif

	return q;

_err:
	lsinic_queue_release(q);
	return NULL;
}

static void
lsinic_queue_trigger_interrupt(struct lsinic_queue *q)
{
	struct lsinic_adapter *adapter;
	struct rte_lsx_pciep_device *lsinic_dev;

	if (likely(!q->ep_reg->isr))
		return;

	adapter = q->adapter;
	lsinic_dev = adapter->lsinic_dev;

	if (likely(lsinic_dev->mmsi_flag == LSX_PCIEP_DONT_INT))
		return;

	if (lsinic_queue_msi_masked(q))
		return;

	if (!rte_lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
		/* MSI/MSIx */
		rte_lsx_pciep_start_msix(q->msix_vaddr, q->msix_cmd);
	}
}

/*********************************************************************
 *
 *  TX functions
 *
 **********************************************************************/
static void
lsinic_tx_notify_burst_to_rc(struct lsinic_queue *txq)
{
	uint16_t pending, burst1 = 0, burst2 = 0;
	uint16_t bd_idx, bd_idx_first, i;
	struct lsinic_bd_desc *local_bd;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct lsinic_rc_rx_len_cmd *tx_len_cmd = txq->tx_len_cmd;
#else
	struct lsinic_rc_rx_len_idx *tx_len_idx = txq->tx_len_idx;
#endif

	pending = txq->next_dma_idx - txq->next_used_idx;
	bd_idx_first = lsinic_queue_next_used_idx(txq, 0);
	for (i = 0; i < pending; i++) {
		bd_idx = lsinic_queue_next_used_idx(txq, i);
		local_bd = &txq->local_src_bd_desc[bd_idx];
		if ((local_bd->bd_status & RING_BD_STATUS_MASK)
			!= RING_BD_HW_COMPLETE) {
			/* Due to OOO DMA*/
			break;
		}
		lsinic_ep_notify_to_rc(txq, bd_idx, 0);
	}
	if ((bd_idx_first + i) > txq->nb_desc) {
		burst1 = txq->nb_desc - bd_idx_first;
		burst2 = i - burst1;
	} else {
		burst1 = i;
		burst2 = 0;
	}
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	lsinic_pcie_memcp_align(&tx_len_cmd[bd_idx_first],
		&txq->local_src_len_cmd[bd_idx_first],
		burst1 * sizeof(struct lsinic_rc_rx_len_cmd));
	if (burst2) {
		lsinic_pcie_memcp_align(&tx_len_cmd[0],
			&txq->local_src_len_cmd[0],
			burst2 * sizeof(struct lsinic_rc_rx_len_cmd));
	}
#else
	lsinic_pcie_memcp_align(&tx_len_idx[bd_idx_first],
		&txq->local_src_len_idx[bd_idx_first],
		burst1 * sizeof(struct lsinic_rc_rx_len_idx));
	if (burst2) {
		lsinic_pcie_memcp_align(&tx_len_idx[0],
			&txq->local_src_len_idx[0],
			burst2 * sizeof(struct lsinic_rc_rx_len_idx));
	}
#endif
	txq->next_used_idx += i;
	if (likely(i > 0))
		lsinic_queue_trigger_interrupt(txq);
}

static void
lsinic_tx_seg_notify_to_rc(struct lsinic_queue *txq)
{
	uint16_t pending, burst1 = 0, burst2 = 0;
	uint16_t bd_idx_first;
	struct lsinic_rc_rx_seg *tx_seg = txq->tx_seg;

	pending = txq->next_dma_idx - txq->next_used_idx;
	bd_idx_first = lsinic_queue_next_used_idx(txq, 0);
	if ((bd_idx_first + pending) > txq->nb_desc) {
		burst1 = txq->nb_desc - bd_idx_first;
		burst2 = pending - burst1;
	} else {
		burst1 = pending;
		burst2 = 0;
	}

	lsinic_pcie_memcp_align(&tx_seg[bd_idx_first],
		&txq->local_src_seg[bd_idx_first],
		burst1 * sizeof(struct lsinic_rc_rx_seg));
	if (burst2) {
		lsinic_pcie_memcp_align(&tx_seg[0],
			&txq->local_src_seg[0],
			burst2 * sizeof(struct lsinic_rc_rx_seg));
	}

	txq->next_used_idx += pending;
	if (likely(pending > 0))
		lsinic_queue_trigger_interrupt(txq);
}

static void
lsinic_tx_update_to_rc(struct lsinic_queue *txq)
{
	uint16_t pending, bd_idx, i;
	struct lsinic_bd_desc *local_bd;

	if (txq->rc_mem_bd_type == RC_MEM_SEG_LEN) {
		lsinic_tx_seg_notify_to_rc(txq);

		return;
	} else if (txq->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		lsinic_tx_notify_burst_to_rc(txq);

		return;
	}

	pending = txq->next_dma_idx - txq->next_used_idx;
	for (i = 0; i < pending; i++) {
		bd_idx = lsinic_queue_next_used_idx(txq, i);
		local_bd = &txq->local_src_bd_desc[bd_idx];
		if ((local_bd->bd_status & RING_BD_STATUS_MASK)
			!= RING_BD_HW_COMPLETE) {
			/* Due to OOO DMA*/
			break;
		}
		if (txq->rc_mem_bd_type == RC_MEM_LEN_CMD)
			lsinic_ep_notify_to_rc(txq, bd_idx, 1);
		else
			lsinic_bd_update_used_to_rc(txq, bd_idx);
	}

	txq->next_used_idx += i;

	if (likely(i > 0))
		lsinic_queue_trigger_interrupt(txq);
}

static uint16_t
lsinic_txq_dma_dq(void *q)
{
	struct lsinic_queue *txq = q;
	struct lsinic_dma_job *dma_job;
	struct lsinic_dma_seg_job *seg_job;
	struct lsinic_sw_bd *txe = NULL;
	const struct lsinic_bd_desc *bd;
	uint16_t pkts_dq = 0;
	int i, ret = 0;
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB], idx;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (txq->pkts_eq == txq->pkts_dq && txq->recycle_txq)
		return 0;
#endif

	ret = rte_dma_completed(txq->adapter->txq_dma_id,
		txq->dma_vq, LSINIC_QDMA_DQ_MAX_NB,
		idx_completed, NULL);
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (!txq->recycle_txq && !ret)
#else
	if (!ret)
#endif
		txq->txq_dma_eq(txq, false);

	if (txq->ep_mem_bd_type == EP_MEM_DST_ADDR_SEG)
		goto dq_seg;

	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < LSINIC_BD_ENTRY_COUNT) {
			idx = idx_completed[i];
		} else {
			idx = idx_completed[i] - LSINIC_BD_ENTRY_COUNT;
			txq->bd_dq++;
			continue;
		}
		dma_job = &txq->dma_jobs[idx];
		txq->bytes_dq += dma_job->len;
		pkts_dq++;
		if (likely(txq->dma_bd_update & DMA_BD_EP2RC_UPDATE))
			continue;
		txe = &txq->sw_ring[idx];
		if (txq->ep_bd_desc) {
			bd = &txq->ep_bd_desc[txe->my_idx];
			lsinic_bd_dma_complete_update(txq, txe->my_idx, bd);
		}
		if (likely(!(txe->mbuf->ol_flags & LSINIC_SHARED_MBUF))) {
			rte_pktmbuf_free(txe->mbuf);
		} else {
			if ((RTE_MBUF_DIRECT(txe->mbuf))) {
				txe->mbuf->ol_flags = 0;
				if (txe->mbuf->refcnt > 1)
					txe->mbuf->refcnt--;
				else
					rte_pktmbuf_free(txe->mbuf);
			} else {
				struct rte_mbuf *mi =
					rte_mbuf_from_indirect(txe->mbuf);

				if (mi->refcnt > 1)
					mi->refcnt--;
				else
					rte_pktmbuf_free(mi);
				lsinic_mbuf_reset(txe->mbuf);
				rte_pktmbuf_free(txe->mbuf);
			}
		}
		txe->mbuf = NULL;
		txq->next_dma_idx++;
	}
	txq->pkts_dq += pkts_dq;

	return i;

dq_seg:
	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < LSINIC_BD_ENTRY_COUNT) {
			idx = idx_completed[i];
		} else {
			idx = idx_completed[i] - LSINIC_BD_ENTRY_COUNT;
			continue;
		}
		txe = &txq->sw_ring[idx];
		pkts_dq++;
		seg_job = &txq->dma_seg_jobs[idx];
		if (unlikely(!seg_job->seg_nb ||
			seg_job->seg_nb >= RTE_DPAAX_QDMA_JOB_SUBMIT_MAX)) {
			LSXINIC_PMD_ERR("DMA SEG jobs[%d].seg_nb(%d)",
				idx, seg_job->seg_nb);
			rte_panic("Fatal quit\n");
		}
		seg_job->seg_nb--;
		if (!seg_job->seg_nb) {
			txq->bytes_dq += txe->mbuf->pkt_len;
			rte_pktmbuf_free(txe->mbuf);
			txe->mbuf = NULL;
			txe->dma_complete = 1;
		}

		if (likely(txq->dma_bd_update & DMA_BD_EP2RC_UPDATE))
			continue;
		txq->next_dma_idx++;
	}
	txq->pkts_dq += pkts_dq;

	return i;
}

static inline int
lsinic_tx_bd_available(struct lsinic_queue *txq,
	uint16_t bd_idx)
{
	const struct lsinic_bd_desc *ep_txd = &txq->ep_bd_desc[bd_idx];
	int full_count = 0;

	if (!(((uint64_t)ep_txd) & RTE_CACHE_LINE_MASK))
		rte_lsinic_prefetch((const uint8_t *)ep_txd +
			RTE_CACHE_LINE_SIZE);

	while (unlikely((ep_txd->bd_status & RING_BD_STATUS_MASK) !=
					RING_BD_READY)) {
		if (!txq->adapter->txq_dma_silent) {
			if (txq->pkts_eq > txq->pkts_dq) {
				txq->dma_dq(txq);
				if (!(txq->dma_bd_update & DMA_BD_EP2RC_UPDATE))
					lsinic_tx_update_to_rc(txq);
			}
		}
		full_count++;
		if (full_count > LSINIC_RING_FULL_THRESH_COUNT)
			return 0;
	}

	return 1;
}

static uint16_t
lsinic_xmit_pkts_burst(struct lsinic_queue *txq,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts, int mg_enable)
{
	uint16_t tx_num = 0;
	int ret, free_idx = 0;
	const int bulk_free = 1;
	struct rte_mbuf *free_pkts[nb_pkts];
	struct rte_mbuf *free_pkt = NULL;
	struct rte_mbuf **ppkt = NULL;

	if (bulk_free)
		ppkt = &free_pkt;

	if (txq->ep_mem_bd_type == EP_MEM_DST_ADDR_SEG) {
		while (nb_pkts) {
			ret = lsinic_xmit_seg_pkt(txq, tx_pkts[tx_num]);
			if (unlikely(ret != 1)) {
				txq->errors += nb_pkts;
				break;
			}

			tx_num++;
			nb_pkts--;
		}
		goto free_last_pkts;
	}

#ifndef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	UNUSED(mg_enable);
	while (nb_pkts) {
		ret = lsinic_xmit_one_pkt(txq, tx_pkts[tx_num], ppkt);
		if (ppkt && *ppkt) {
			free_pkts[free_idx] = *ppkt;
			free_idx++;
			*ppkt = NULL;
		}
		if (unlikely(ret != 1)) {
			txq->errors += nb_pkts;
			break;
		}

		tx_num++;
		nb_pkts--;
	}
#else
	while (nb_pkts) {
		ret = 0;
		if (mg_enable)
			ret = lsinic_cpu_merge_xmit(txq, &tx_pkts[tx_num],
					nb_pkts);
		if (ret) {
			tx_num += ret;
			nb_pkts -= ret;
		} else {
			ret = lsinic_xmit_one_pkt(txq, tx_pkts[tx_num],
				ppkt);
			if (ppkt && *ppkt) {
				free_pkts[free_idx] = *ppkt;
				free_idx++;
				*ppkt = NULL;
			}
			if (unlikely(ret != 1)) {
				txq->errors += nb_pkts;
				break;
			}

			tx_num++;
			nb_pkts--;
		}
	}
#endif

free_last_pkts:
	if (free_idx > 0)
		rte_pktmbuf_free_bulk(free_pkts, free_idx);

	if (unlikely(!txq->pair)) {
		if (!(txq->dma_bd_update & DMA_BD_EP2RC_UPDATE))
			lsinic_txq_loop(tx_num);
		else
			lsinic_txq_loop(0);
	}

	return tx_num;
}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
static uint16_t
lsinic_xmit_directly(struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts, struct lsinic_queue *txq,
	struct rte_mbuf **mg_pkts)
{
	uint16_t i, direct_nb = 0, mg_nb = 0, ret;
	struct rte_mbuf *direct_pkts[LSINIC_MERGE_MAX_NUM];

	for (i = 0; i < nb_pkts; i++) {
		if (tx_pkts[i]->pkt_len > txq->adapter->merge_threshold) {
			direct_pkts[direct_nb] = tx_pkts[i];
			direct_nb++;
		} else {
			mg_pkts[mg_nb] = tx_pkts[i];
			mg_nb++;
		}
	}

	if (mg_nb == 1) {
		direct_pkts[direct_nb] = mg_pkts[0];
		direct_nb++;
		mg_nb = 0;
	}

	if (direct_nb > 0) {
		ret = lsinic_xmit_pkts_burst(txq, direct_pkts,
				direct_nb, 0);
		if (unlikely(ret < direct_nb))
			rte_pktmbuf_free_bulk(&direct_pkts[ret],
				direct_nb - ret);
	}

	return direct_nb;
}
#endif

uint16_t
lsinic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct lsinic_queue *txq;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct rte_eth_dev *recycle_dev;
#endif

	txq = tx_queue;
	if (unlikely(txq->core_id == RTE_MAX_LCORE && txq->pair)) {
		/* This txq has not been added to list from it's pair.*/
		return 0;
	}

	if (unlikely(!txq->ep_enabled))
		return 0;

	if (unlikely(!lsinic_queue_running(txq))) {
		rte_spinlock_lock(&txq->multi_core_lock);
		lsinic_queue_status_update(txq);
		if (!lsinic_queue_running(txq)) {
			rte_spinlock_unlock(&txq->multi_core_lock);
			return 0;
		}
		rte_spinlock_unlock(&txq->multi_core_lock);
	}

	if (unlikely(!RTE_PER_LCORE(pthrd_id)))
		RTE_PER_LCORE(pthrd_id) = pthread_self();

	if (unlikely(txq->core_id != rte_lcore_id() ||
		!pthread_equal(txq->pid, RTE_PER_LCORE(pthrd_id)))) {
		if (!txq->multi_core_ring) {
			char ring_name[RTE_MEMZONE_NAMESIZE];

			sprintf(ring_name,
				"txq_mpsc_%d_%d_%d_%d_%d",
				txq->adapter->pcie_idx,
				txq->adapter->pf_idx,
				txq->adapter->is_vf,
				txq->adapter->vf_idx,
				txq->queue_id);
			rte_spinlock_lock(&txq->multi_core_lock);
			if (txq->multi_core_ring) {
				rte_spinlock_unlock(&txq->multi_core_lock);
				goto eq_start;
			}
			txq->multi_core_ring = rte_ring_create(ring_name,
				txq->nb_desc, rte_socket_id(),
				RING_F_SC_DEQ);
			rte_spinlock_unlock(&txq->multi_core_lock);
			if (txq->multi_core_ring) {
				LSXINIC_PMD_INFO("%s created on core %d.",
					ring_name, rte_lcore_id());
			} else {
				LSXINIC_PMD_ERR("%s created on core %d failed.",
					ring_name, rte_lcore_id());
				return 0;
			}
		}

eq_start:
		return rte_ring_mp_enqueue_burst(txq->multi_core_ring,
				(void * const *)tx_pkts, nb_pkts, NULL);
	}
#ifdef LSXINIC_LATENCY_PROFILING
	{
		int i, j;
		uint64_t tick = rte_get_timer_cycles();
		uint8_t *tick_8 = (uint8_t *)&tick;
		uint8_t *tick_save;

		for (i = 0; i < nb_pkts; i++) {
			tick_save = rte_pktmbuf_mtod_offset(tx_pkts[i],
				uint8_t *, tx_pkts[i]->pkt_len);
			for (j = 0; j < (int)sizeof(uint64_t); j++)
				tick_save[j] = tick_8[j];
			tx_pkts[i]->pkt_len += sizeof(uint64_t);
			tx_pkts[i]->data_len += sizeof(uint64_t);
		}
	}
#endif

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (txq->recycle_txq) {
		recycle_dev = txq->adapter->merge_dev->eth_dev;
		return recycle_dev->tx_pkt_burst(txq->recycle_txq,
				tx_pkts, nb_pkts);
	}
#endif

	txq->loop_avail++;

	/* TX loop */
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	return lsinic_xmit_pkts_burst(txq, tx_pkts, nb_pkts,
			txq->adapter->cap & LSINIC_CAP_XFER_PKT_MERGE);
#else
	return lsinic_xmit_pkts_burst(txq, tx_pkts, nb_pkts, 0);
#endif
}

/*********************************************************************
 *
 *  RX functions
 *
 **********************************************************************/
static uint16_t
lsinic_rxq_dma_dq(void *q)
{
	struct lsinic_queue *rxq = q;
	struct lsinic_sw_bd *rxe;
	struct lsinic_bd_desc *rxdp;
	struct lsinic_dma_job *dma_job;
	int i, ret = 0;
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB], idx;

	if (rxq->pkts_eq == rxq->pkts_dq &&
		rxq->bd_eq == rxq->bd_dq)
		return 0;

	ret = rte_dma_completed(rxq->adapter->rxq_dma_id,
		rxq->dma_vq, LSINIC_QDMA_DQ_MAX_NB,
		idx_completed, NULL);
	if (!ret)
		return 0;

	if (rxq->ep_mem_bd_type == EP_MEM_SRC_SEG_BD)
		goto dq_seg;

	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < LSINIC_BD_ENTRY_COUNT) {
			idx = idx_completed[i];
		} else {
			idx = idx_completed[i] - LSINIC_BD_ENTRY_COUNT;
			rxq->bd_dq++;
			continue;
		}
		rxe = &rxq->sw_ring[idx];
		dma_job = &rxq->dma_jobs[idx];
		rxq->bytes_dq += dma_job->len;
		rxq->pkts_dq++;
		rxe->dma_complete = 1;
		if (rxq->ep_bd_desc) {
			rxdp = &rxq->ep_bd_desc[rxe->my_idx];
			lsinic_bd_dma_complete_update(rxq, rxe->my_idx, rxdp);
		}
	}

	return ret;

dq_seg:

	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < LSINIC_BD_ENTRY_COUNT) {
			idx = idx_completed[i];
		} else {
			idx = idx_completed[i] - LSINIC_BD_ENTRY_COUNT;
			rxq->bd_dq++;
			continue;
		}
		rxe = &rxq->sw_ring[idx];
		rxq->dma_seg_jobs[idx].seg_nb--;
		if (!rxq->dma_seg_jobs[idx].seg_nb) {
			rxq->bytes_dq += rxe->mbuf->pkt_len;
			rxe->dma_complete = 1;
		}
		rxq->pkts_dq++;
	}

	return ret;
}

static __rte_always_inline void
lsinic_recv_mbuf_dma_set(void *job,
	struct rte_mbuf *mbuf, uint32_t pkt_len, uint32_t port_id,
	int complete_check)
{
	struct lsinic_sw_bd *rxe;
	struct lsinic_dma_job *dma_job = job;

	dma_job->dst = rte_mbuf_data_iova_default(mbuf);
	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->pkt_len = pkt_len;
	mbuf->data_len = pkt_len;
	mbuf->port = port_id;
	rxe = (struct lsinic_sw_bd *)dma_job->cnxt;
	mbuf->data_off = RTE_PKTMBUF_HEADROOM + rxe->align_dma_offset;
	rxe->mbuf = mbuf;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (rxe->mg)
		dma_job->dst -= sizeof(struct lsinic_mg_header);
#endif
	if (complete_check) {
		rxe->complete = rte_pktmbuf_mtod_offset(mbuf,
			char *, pkt_len);
		(*rxe->complete) = LSINIC_XFER_COMPLETE_INIT_FLAG;
		dma_job->len++;
	} else {
		rxe->dma_complete = 0;
	}
}

static __rte_always_inline void
lsinic_local_bd_status_update(struct lsinic_queue *q,
	uint16_t bd_idx, uint32_t bd_status)
{
	struct lsinic_bd_desc *rxdp = &q->local_src_bd_desc[bd_idx];

	rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
	rxdp->bd_status |= bd_status;
}

static uint16_t
lsinic_recv_seg_bd(struct lsinic_queue *rxq)
{
	struct lsinic_seg_desc *rxdp;
	struct lsinic_dma_seg_job *dma_seg_job;
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint64_t addr_base = rxq->ob_base;

	uint32_t offset = 0, align_len;
	uint16_t bd_idx, idx, next_bd_idx;
	uint8_t *prefetch_addr;

	rxq->loop_total++;
	if (unlikely(lsinic_queue_next_avail_idx(rxq, 1) ==
		lsinic_queue_next_used_idx(rxq, 0)))
		return 0;

	bd_idx = lsinic_queue_next_avail_idx(rxq, 0);

	next_bd_idx = (bd_idx + 1) & (rxq->nb_desc - 1);
	prefetch_addr = (void *)&rxq->rx_src_seg[next_bd_idx];

	rxdp = &rxq->rx_src_seg[bd_idx];
	if (!rxdp->nb)
		return 0;

	for (idx = 0; idx < LSINIC_SEG_DESC_CACHE_LINE_NB; idx++)
		rte_prefetch0(prefetch_addr + idx * RTE_CACHE_LINE_SIZE);

	rxm = rte_pktmbuf_alloc(rxq->mb_pool);
	if (unlikely(!rxm))
		return 0;

	rxm->data_off = RTE_PKTMBUF_HEADROOM;

	rxe = &rxq->sw_ring[bd_idx];
	rxe->mbuf = rxm;
	dma_seg_job = &rxq->dma_seg_jobs[bd_idx];

	addr_base += rxdp->base_addr;
	for (idx = 0; idx < rxdp->nb; idx++) {
		if (rxdp->entry[idx].positive) {
			dma_seg_job->src[idx] = addr_base +
				rxdp->entry[idx].offset;
		} else {
			dma_seg_job->src[idx] = addr_base -
				rxdp->entry[idx].offset;
		}
		dma_seg_job->len[idx] = rxdp->entry[idx].len;
		dma_seg_job->dst[idx] = rte_pktmbuf_iova_offset(rxm, offset);
		offset += dma_seg_job->len[idx];
	}
	dma_seg_job->seg_nb = rxdp->nb;
	dma_seg_job->cnxt = (uint64_t)rxe;

	rxm->pkt_len = offset;
	rxm->data_len = offset;

	align_len = offset;
	while (align_len % rxdp->nb)
		align_len++;
	rxm->tso_segsz = align_len / rxdp->nb;

	if (rxq->adapter->rxq_dma_silent) {
		rxe->complete = rte_pktmbuf_mtod_offset(rxm,
			char *, offset);
		(*rxe->complete) = LSINIC_XFER_COMPLETE_INIT_FLAG;
		dma_seg_job->len[rxdp->nb - 1]++;
	} else {
		rxe->dma_complete = 0;
	}

	rxq->next_avail_idx++;

	rxq->loop_avail++;

	rxq->jobs_pending++;
	lsinic_qdma_rx_seg_enqueue(rxq);

	return rxdp->nb;
}

static uint16_t
lsinic_recv_idx_bulk_alloc_buf(struct lsinic_queue *rxq)
{
	struct lsinic_ep_rx_src_addrx *rxdp;
	struct lsinic_dma_job *dma_job[DEFAULT_TX_RS_THRESH];
	struct rte_mbuf *rxm[DEFAULT_TX_RS_THRESH];
	struct lsinic_sw_bd *rxe;

	uint32_t pkt_len[DEFAULT_TX_RS_THRESH];
	uint16_t bd_idx;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	uint16_t len_cmd;
#endif
	uint16_t bd_num = 0, idx, size;
	const uint64_t addr_base =
		rxq->ob_base + rxq->adapter->rc_dma_base;
	const uint32_t rc_dma_elt_size =
		rxq->adapter->rc_dma_elt_size;
	uint8_t e_complete = rxq->adapter->rxq_dma_silent ? 1 : 0;

	do {
		if (unlikely(lsinic_queue_next_avail_idx(rxq, 1) ==
			lsinic_queue_next_used_idx(rxq, 0)))
			break;
		bd_idx = lsinic_queue_next_avail_idx(rxq, 0);
		rxdp = &rxq->rx_src_addrx[bd_idx];

		if (!(((uint64_t)rxdp) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((uint8_t *)rxdp +
				RTE_CACHE_LINE_SIZE);
		}

		if (!rxdp->idx_cmd_len) {
			rxq->rxq_dma_eq(rxq, false, true);
			break;
		}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		len_cmd = rxdp->len_cmd;
		size = len_cmd & LSINIC_EP_RX_SRC_ADDRX_LEN_MASK;
#else
		size = rxdp->len;
#endif
		if (unlikely(size > rxq->adapter->data_room_size)) {
			LSXINIC_PMD_ERR("port%d rxq%d BD%d size:0x%08x",
				rxq->port_id, rxq->queue_id, bd_idx, size);
			rxq->errors++;
			rte_panic("line %d\tassert \"%s\" failed\n",
				__LINE__, "size err");
			/* to do skip this bd */
			/* TODO
			 * dma_job for this entry should also be skipped
			 */

			break;
		}
		rxe = &rxq->sw_ring[bd_idx];
		dma_job[bd_num] = &rxq->dma_jobs[bd_idx];
		dma_job[bd_num]->cnxt = (uint64_t)rxe;

		dma_job[bd_num]->src = addr_base +
			rxdp->pkt_idx * rc_dma_elt_size;

		pkt_len[bd_num] = size;
		dma_job[bd_num]->len = pkt_len[bd_num];
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		if (len_cmd & LSINIC_EP_RX_SRC_ADDRX_MERGE) {
			dma_job[bd_num]->len += sizeof(struct lsinic_mg_header);
			dma_job[bd_num]->src -= sizeof(struct lsinic_mg_header);
			rxe->mg = 1;
		} else {
			rxe->mg = 0;
		}
#endif

		bd_num++;
		rxq->next_avail_idx++;

		if (bd_num >= DEFAULT_TX_RS_THRESH)
			break;
	} while (1);

	rxq->loop_total++;

	if (unlikely(!bd_num))
		return 0;

	if (likely(!rte_pktmbuf_alloc_bulk(rxq->mb_pool,
		rxm, bd_num))) {
		for (idx = 0; idx < bd_num; idx++) {
			rxq->rx_dma_mbuf_set(dma_job[idx],
				rxm[idx], pkt_len[idx],
				rxq->port_id, e_complete);
		}
		for (idx = 0; idx < bd_num; idx++) {
			rxq->jobs_pending++;
			rxq->rxq_dma_eq(rxq, true, false);
		}
		rxq->rxq_dma_eq(rxq, false, true);
	} else {
		rxq->next_avail_idx -= bd_num;
	}

	if (bd_num > 0)
		rxq->loop_avail++;

	return bd_num;
}

static uint16_t
lsinic_recv_addrl_bulk_alloc_buf(struct lsinic_queue *rxq)
{
	struct lsinic_ep_rx_src_addrl *rxdp;
	struct lsinic_dma_job *dma_job[DEFAULT_TX_RS_THRESH];
	struct rte_mbuf *rxm[DEFAULT_TX_RS_THRESH];
	struct lsinic_sw_bd *rxe;

	uint32_t pkt_len[DEFAULT_TX_RS_THRESH];
	uint16_t bd_idx;
	uint32_t size;
	uint32_t len_cmd;
	uint16_t bd_num = 0, idx;
	uint64_t addr_base;
	uint8_t e_complete = rxq->adapter->rxq_dma_silent ? 1 : 0;

	addr_base = rxq->ob_base + rxq->adapter->rc_dma_base;

	do {
		if (unlikely(lsinic_queue_next_avail_idx(rxq, 1) ==
			lsinic_queue_next_used_idx(rxq, 0)))
			break;
		bd_idx = lsinic_queue_next_avail_idx(rxq, 0);
		rxdp = &rxq->rx_src_addrl[bd_idx];

		if (!(((uint64_t)rxdp) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((uint8_t *)rxdp +
				RTE_CACHE_LINE_SIZE);
		}

		if (!rxdp->addr_cmd_len) {
			rxq->rxq_dma_eq(rxq, false, true);
			break;
		}

		len_cmd = rxdp->len_cmd;
		size = len_cmd & LSINIC_BD_LEN_MASK;
		if (unlikely(size > rxq->adapter->data_room_size)) {
			LSXINIC_PMD_ERR("port%d rxq%d BD%d len_cmd:0x%08x",
				rxq->port_id, rxq->queue_id, bd_idx, len_cmd);
			rxq->errors++;
			rte_panic("line %d\tassert \"%s\" failed\n",
				__LINE__, "size err");
			/* to do skip this bd */
			/* TODO
			 * dma_job for this entry should also be skipped
			 */

			break;
		}
		rxe = &rxq->sw_ring[bd_idx];
		dma_job[bd_num] = &rxq->dma_jobs[bd_idx];
		dma_job[bd_num]->cnxt = (uint64_t)rxe;

		dma_job[bd_num]->src = addr_base + rxdp->pkt_addr_low;

		pkt_len[bd_num] = size;
		dma_job[bd_num]->len = pkt_len[bd_num];
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		if (len_cmd & LSINIC_BD_CMD_MG) {
			dma_job[bd_num]->len += sizeof(struct lsinic_mg_header);
			dma_job[bd_num]->src -= sizeof(struct lsinic_mg_header);
			rxe->mg = 1;
		} else {
			rxe->mg = 0;
		}
#endif

		bd_num++;
		rxq->next_avail_idx++;

		if (bd_num >= DEFAULT_TX_RS_THRESH)
			break;
	} while (1);

	rxq->loop_total++;

	if (unlikely(!bd_num))
		return 0;

	if (likely(!rte_pktmbuf_alloc_bulk(rxq->mb_pool,
		rxm, bd_num))) {
		for (idx = 0; idx < bd_num; idx++) {
			rxq->rx_dma_mbuf_set(dma_job[idx],
				rxm[idx], pkt_len[idx],
				rxq->port_id, e_complete);
		}
		for (idx = 0; idx < bd_num; idx++) {
			rxq->jobs_pending++;
			rxq->rxq_dma_eq(rxq, true, false);
		}
		rxq->rxq_dma_eq(rxq, false, true);
	} else {
		rxq->next_avail_idx -= bd_num;
	}

	if (bd_num > 0)
		rxq->loop_avail++;

	return bd_num;
}

static uint16_t
lsinic_recv_bd_bulk_alloc_buf(struct lsinic_queue *rxq)
{
	struct lsinic_bd_desc *rxdp;
	struct lsinic_dma_job *dma_job[DEFAULT_TX_RS_THRESH];
	struct lsinic_sw_bd *rxe = NULL;
	struct rte_mbuf *rxm[DEFAULT_TX_RS_THRESH];

	uint32_t pkt_len[DEFAULT_TX_RS_THRESH];
	uint16_t bd_idx, first_bd_idx;
	uint32_t size;
	uint32_t len_cmd;
	uint16_t bd_num = 0, idx;

	first_bd_idx = lsinic_queue_next_avail_idx(rxq, 0);

	do {
		if (unlikely(lsinic_queue_next_avail_idx(rxq, 1) ==
			lsinic_queue_next_used_idx(rxq, 0)))
			break;
		bd_idx = lsinic_queue_next_avail_idx(rxq, 0);
		rxdp = &rxq->ep_bd_desc[bd_idx];

		if (!(((uint64_t)rxdp) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((const uint8_t *)rxdp +
				RTE_CACHE_LINE_SIZE);
		}

		if ((rxdp->bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_AVAILABLE) {
			rxq->rxq_dma_eq(rxq, false, true);
			break;
		}
		rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
		rxdp->bd_status |= RING_BD_HW_PROCESSING;

		len_cmd = rxdp->len_cmd;
		size = len_cmd & LSINIC_BD_LEN_MASK;
		if (unlikely(size > rxq->adapter->data_room_size)) {
			LSXINIC_PMD_ERR("port%d rxq%d BD%d len_cmd:0x%08x",
				rxq->port_id, rxq->queue_id, bd_idx, len_cmd);
			rxq->errors++;
			rte_panic("line %d\tassert \"%s\" failed\n",
				__LINE__, "size err");
			/* to do skip this bd */
			/* TODO
			 * dma_job for this entry should also be skipped
			 */

			break;
		}

		dma_job[bd_num] = &rxq->dma_jobs[bd_idx];

		rxe = &rxq->sw_ring[bd_idx];

		dma_job[bd_num]->cnxt = (uint64_t)rxe;

		LSXINIC_PMD_DBG("port%d rxq%d bd_idx=%d pkt_len=%d",
			rxq->port_id, rxq->queue_id,
			bd_idx, size);

		dma_job[bd_num]->src = rxdp->pkt_addr + rxq->ob_base;
		/* qdma read memory must be aligned 64 */
		rxe->align_dma_offset =
			LSINIC_ALIGN_DMA_CALC_OFFSET(dma_job[bd_num]->src);
		dma_job[bd_num]->src -= rxe->align_dma_offset;
#ifdef LSINIC_CHECK_DMA_ALIGNED
		if (!rte_is_aligned((void *)dma_job[bd_num]->src,
			64)) {
			LSXINIC_PMD_DBG("BD%d src:0x%lx %s",
				bd_num,
				dma_job->src,
				"not aligned with 64");
		}
#endif

		pkt_len[bd_num] = size - rxq->crc_len;
		dma_job[bd_num]->len = pkt_len[bd_num] +
			rxe->align_dma_offset;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		if (len_cmd & LSINIC_BD_CMD_MG) {
			dma_job[bd_num]->len += sizeof(struct lsinic_mg_header);
			dma_job[bd_num]->src -= sizeof(struct lsinic_mg_header);
			rxe->mg = 1;
		} else {
			rxe->mg = 0;
		}
#endif

		bd_num++;
		rxq->next_avail_idx++;

		if (bd_num >= DEFAULT_TX_RS_THRESH)
			break;
	} while (1);

	rxq->loop_total++;

	if (unlikely(!bd_num))
		return 0;

	if (likely(!rte_pktmbuf_alloc_bulk(rxq->mb_pool,
		rxm, bd_num))) {
		if (rxq->adapter->rxq_dma_silent) {
			for (idx = 0; idx < bd_num; idx++) {
				lsinic_local_bd_status_update(rxq,
					(first_bd_idx + idx) &
					(rxq->nb_desc - 1),
					RING_BD_ADDR_CHECK |
					RING_BD_HW_COMPLETE);
				rxq->rx_dma_mbuf_set(dma_job[idx],
					rxm[idx], pkt_len[idx],
					rxq->port_id, 1);
			}
		} else {
			for (idx = 0; idx < bd_num; idx++) {
				rxq->rx_dma_mbuf_set(dma_job[idx],
					rxm[idx], pkt_len[idx],
					rxq->port_id, 0);
			}
		}
		for (idx = 0; idx < bd_num; idx++) {
			rxq->jobs_pending++;
			rxq->rxq_dma_eq(rxq, true, false);
		}
		rxq->rxq_dma_eq(rxq, false, true);
	} else {
		rxq->next_avail_idx -= bd_num;
	}

	if (bd_num > 0)
		rxq->loop_avail++;

	return bd_num;
}

static uint16_t
lsinic_recv_bd(struct lsinic_queue *rxq)
{
	struct lsinic_bd_desc *rxdp;
	struct lsinic_dma_job *dma_job;
	struct lsinic_sw_bd *rxe = NULL;
	struct rte_mbuf *rxm;

	uint32_t pkt_len;
	uint16_t bd_idx;
	uint32_t size;
	uint32_t len_cmd;
	uint16_t bd_num = 0;

	do {
		if (unlikely(lsinic_queue_next_avail_idx(rxq, 1) ==
			lsinic_queue_next_used_idx(rxq, 0)))
			break;
		bd_idx = lsinic_queue_next_avail_idx(rxq, 0);
		rxdp = &rxq->ep_bd_desc[bd_idx];

		if (!(((uint64_t)rxdp) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((const uint8_t *)rxdp +
				RTE_CACHE_LINE_SIZE);
		}

		if ((rxdp->bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_AVAILABLE) {
			rxq->rxq_dma_eq(rxq, false, true);
			break;
		}
		rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
		rxdp->bd_status |= RING_BD_HW_PROCESSING;

		len_cmd = rxdp->len_cmd;
		size = len_cmd & LSINIC_BD_LEN_MASK;
		if (unlikely(size > rxq->adapter->data_room_size)) {
			LSXINIC_PMD_ERR("port%d rxq%d BD%d len_cmd:0x%08x",
				rxq->port_id, rxq->queue_id, bd_idx, len_cmd);
			rxq->errors++;
			rte_panic("line %d\tassert \"%s\" failed\n",
				__LINE__, "size err");

			break;
		}

		dma_job = &rxq->dma_jobs[bd_idx];

		rxe = &rxq->sw_ring[bd_idx];

		if (rxq->adapter->rxq_dma_silent) {
			lsinic_local_bd_status_update(rxq, bd_idx,
				RING_BD_ADDR_CHECK | RING_BD_HW_COMPLETE);
		} else {
			lsinic_local_bd_status_update(rxq, bd_idx,
				RING_BD_HW_PROCESSING);
		}

		dma_job->cnxt = (uint64_t)rxe;

		LSXINIC_PMD_DBG("port%d rxq%d bd_idx=%d pkt_len=%d",
			rxq->port_id, rxq->queue_id,
			bd_idx, size);

		rxm = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (unlikely(!rxm)) {
			struct rte_eth_dev_data *dev_data;

			LSXINIC_PMD_DBG("Port%d RXQ%d mbuf alloc failed",
				rxq->port_id, rxq->queue_id);
			dev_data = rte_eth_devices[rxq->port_id].data;
			dev_data->rx_mbuf_alloc_failed++;
			break;
		}

		/* rxm is ret_mbuf passed to upper layer */
		rxe->mbuf = rxm;

		dma_job->dst = rte_mbuf_data_iova_default(rxm);
		dma_job->src = rxdp->pkt_addr + rxq->ob_base;
		/* qdma read memory must be aligned 64 */
		rxe->align_dma_offset =
			LSINIC_ALIGN_DMA_CALC_OFFSET(dma_job->src);
		dma_job->src -= rxe->align_dma_offset;
#ifdef LSINIC_CHECK_DMA_ALIGNED
		if (!rte_is_aligned((void *)dma_job->src, 64)) {
			LSXINIC_PMD_DBG("RXQ%d dma src(0x%lx) not aligned",
				rxq->queue_id, dma_job->src);
		}
#endif
		pkt_len = size - rxq->crc_len;
		dma_job->len = pkt_len + rxe->align_dma_offset;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		if (len_cmd & LSINIC_BD_CMD_MG) {
			dma_job->len += sizeof(struct lsinic_mg_header);
			dma_job->dst -= sizeof(struct lsinic_mg_header);
			dma_job->src -= sizeof(struct lsinic_mg_header);
		}
#endif

		rxm->nb_segs = 1;
		rxm->next = NULL;
		rxm->pkt_len = pkt_len;
		rxm->data_len = pkt_len;
		rxm->port = rxq->port_id;
		rxm->data_off = RTE_PKTMBUF_HEADROOM +
			rxe->align_dma_offset;

		if (rxq->adapter->rxq_dma_silent) {
			rxe->complete =
				rte_pktmbuf_mtod_offset(rxm,
					char *, dma_job->len);
			(*rxe->complete) =
				LSINIC_XFER_COMPLETE_INIT_FLAG;
			dma_job->len++;
		} else {
			rxe->dma_complete = 0;
		}

		rxq->next_avail_idx++;
		rxq->jobs_pending++;
		rxq->rxq_dma_eq(rxq, true, false);
		bd_num++;

		if (bd_num >= DEFAULT_TX_RS_THRESH)
			break;
	} while (1);

	if (unlikely(!bd_num))
		return 0;

	rxq->rxq_dma_eq(rxq, false, true);

	rxq->loop_avail++;

	return bd_num;
}

static void
lsinic_txq_loop(uint16_t dq_sync)
{
	struct lsinic_queue *q, *tq;
	struct lsinic_adapter *adapter;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct rte_eth_dev *offload_dev;
#endif
	struct rte_mbuf *tx_pkts[DEFAULT_TX_RS_THRESH];
	uint16_t ret, i, xmit_ret, dq, dq_total = 0;

	if (unlikely(!RTE_PER_LCORE(pthrd_id)))
		RTE_PER_LCORE(pthrd_id) = pthread_self();

	/* Check if txq already added to list */
	RTE_TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lsinic_txq_list), next, tq) {
		adapter = q->adapter;
		if (unlikely(!lsinic_queue_running(q))) {
			lsinic_queue_status_update(q);
			if (!lsinic_queue_running(q))
				continue;
		}

		if (unlikely(q->core_id != rte_lcore_id())) {
			TAILQ_REMOVE(&RTE_PER_LCORE(lsinic_txq_list),
				q, next);
			continue;
		}

		if (q->multi_core_ring) {
			ret = rte_ring_sc_dequeue_burst(q->multi_core_ring,
				(void **)tx_pkts, DEFAULT_TX_RS_THRESH, NULL);
			if (ret) {
				xmit_ret = lsinic_xmit_pkts(q, tx_pkts, ret);
				for (i = xmit_ret; i < ret; i++)
					rte_pktmbuf_free(tx_pkts[i]);
			}
		}

		if (!adapter->txq_dma_silent) {
			if (unlikely(dq_sync)) {
				while (dq_total != dq_sync) {
					q->txq_dma_eq(q, false);
					dq = q->dma_dq(q);
					if (dq > 0)
						dq_total += dq;
				}
			} else {
				dq_total = q->dma_dq(q);
			}
			if (!(q->dma_bd_update & DMA_BD_EP2RC_UPDATE)) {
				if (dq_total > 0)
					lsinic_tx_update_to_rc(q);
			}
		}
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		else if (!q->recycle_txq) {
			if (likely(q->packets_old == q->packets))
				q->txq_dma_eq(q, false);
			q->packets_old = q->packets;
		}
#else
		else if (q->ep_mem_bd_type != EP_MEM_DST_ADDR_SEG) {
			if (likely(q->packets_old == q->packets))
				q->txq_dma_eq(q, false);
			q->packets_old = q->packets;
		}
#endif

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		if (q->recycle_rxq) {
			offload_dev = adapter->merge_dev->eth_dev;
			ret = offload_dev->rx_pkt_burst(q->recycle_rxq,
					tx_pkts,
					DEFAULT_TX_RS_THRESH);
			if (likely(ret > 0)) {
				for (i = 0; i < ret; i++) {
					lsinic_tx_merge_cb(tx_pkts[i],
						q->recycle_rxq);
				}
			} else {
				lsinic_tx_merge_cb(NULL, q->recycle_rxq);
			}
		}
#endif

		q->loop_total++;
	}
}

static int
lsinic_rxq_loop(struct lsinic_queue *rxq)
{
	const int bulk_alloc = 1;
	uint16_t rc_recvd = 0;

	if (unlikely(!lsinic_queue_running(rxq))) {
		lsinic_queue_status_update(rxq);
		if (rxq->pair)
			lsinic_add_txq_to_list(rxq->pair);
		if (!lsinic_queue_running(rxq))
			return -EAGAIN;
	}

	if (unlikely(!rxq->ep_enabled))
		return 0;

	if (rxq->ep_mem_bd_type == EP_MEM_SRC_SEG_BD) {
		rc_recvd = lsinic_recv_seg_bd(rxq);
	} else if (bulk_alloc) {
		if (rxq->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD)
			rc_recvd = lsinic_recv_idx_bulk_alloc_buf(rxq);
		else if (rxq->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD)
			rc_recvd = lsinic_recv_addrl_bulk_alloc_buf(rxq);
		else
			rc_recvd = lsinic_recv_bd_bulk_alloc_buf(rxq);
	} else {
		if (rxq->ep_mem_bd_type != EP_MEM_LONG_BD) {
			LSXINIC_PMD_ERR("RX by SHORT BD TBD");
			return -EINVAL;
		}
		rc_recvd = lsinic_recv_bd(rxq);
	}

	if ((rxq->dma_bd_update & DMA_BD_RC2EP_UPDATE) && !rc_recvd)
		rxq->rxq_dma_eq(rxq, false, true);

	if (!rxq->adapter->rxq_dma_silent)
		rxq->dma_dq(rxq);

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (rxq->recycle_rxq) {
		uint16_t ret, i;
		struct rte_mbuf *mbuf_split[DEFAULT_TX_RS_THRESH];
		struct rte_eth_dev *offload_dev =
			rxq->adapter->split_dev->eth_dev;

		if (likely(offload_dev->data->dev_started)) {
			ret = offload_dev->rx_pkt_burst(rxq->recycle_rxq,
					mbuf_split,
					DEFAULT_TX_RS_THRESH);
			if (likely(ret > 0)) {
				for (i = 0; i < ret; i++) {
					lsinic_rx_split_cb(mbuf_split[i],
						rxq->recycle_rxq);
				}
			}
		}
	}
#endif

	return rc_recvd;
}

static const uint8_t
s_hw_complete_16b[16] __rte_cache_aligned = {
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,

	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE
};

static inline void
lsinic_recv_cnf_burst_update(struct lsinic_queue *rxq,
	uint16_t nb_rx, uint16_t first_idx)
{
	uint8_t *start;

	if (unlikely(!nb_rx))
		return;

	if (rxq->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		rxq->local_src_free_idx->idx_complete =
			(first_idx + nb_rx) & (rxq->nb_desc - 1);
		rxq->rc_reg->cir = rxq->local_src_free_idx->idx_complete;
	} else if (rxq->rc_mem_bd_type == RC_MEM_BD_CNF) {
		start = &rxq->rc_rx_complete[first_idx].bd_complete;
		if ((first_idx + nb_rx) < rxq->nb_desc) {
			lsinic_pcie_memset_align(start,
				s_hw_complete_16b, nb_rx);
		} else {
			lsinic_pcie_memset_align(start,
				s_hw_complete_16b,
				rxq->nb_desc - first_idx);
			if ((first_idx + nb_rx) != rxq->nb_desc) {
				start = &rxq->rc_rx_complete[0].bd_complete;
				lsinic_pcie_memset_align(start,
					s_hw_complete_16b,
					first_idx + nb_rx - rxq->nb_desc);
			}
		}
	} else {
		/* Implemented by recv_update callback*/
	}
}

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
static int
lsinic_fetch_merge_rx_buffer(struct lsinic_queue *rx_queue,
	void *rx_desc, struct rte_mbuf *mbuf)
{
	char *data = NULL;
	char *data_base = NULL;
	uint16_t pkt_len, align_off, idx, offset, total_size;
	struct lsinic_mg_header *mg_header;
	struct lsinic_bd_desc *lbd;
	struct lsinic_ep_rx_src_addrl *sbd;
	struct lsinic_ep_rx_src_addrx *xbd;

	if (rx_queue->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
		xbd = rx_desc;
		total_size = xbd->len_cmd &
			LSINIC_EP_RX_SRC_ADDRX_LEN_MASK;
	} else if (rx_queue->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD) {
		sbd = rx_desc;
		total_size = sbd->len_cmd;
		total_size &= LSINIC_BD_LEN_MASK;
	} else {
		lbd = rx_desc;
		total_size = lbd->len_cmd;
		total_size &= LSINIC_BD_LEN_MASK;
	}

	rte_lsinic_prefetch(mbuf);
	if (total_size  > rx_queue->adapter->data_room_size) {
		LSXINIC_PMD_ERR("packet(%d) is too bigger!",
			total_size);
		return 0;
	}

	data_base = rte_pktmbuf_mtod(mbuf, char *);

	mg_header = (struct lsinic_mg_header *)
		(data_base - sizeof(struct lsinic_mg_header));
	pkt_len = lsinic_mg_entry_len(mg_header->len_cmd[0]);
	if ((pkt_len + sizeof(struct lsinic_mg_header)) > total_size)
		return 0;

	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->pkt_len = pkt_len;
	mbuf->data_len = pkt_len;
	mbuf->port = rx_queue->port_id;
	mbuf->packet_type = RTE_PTYPE_L3_IPV4;
	rx_queue->mcache[rx_queue->mtail] = mbuf;
	rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
	rx_queue->mcnt++;

	align_off = lsinic_mg_entry_align_offset(mg_header->len_cmd[0]);
	offset = pkt_len + align_off;

	LSXINIC_PMD_DBG("EP MGD0: len=%d next_off=%d",
		pkt_len, offset);

	idx = 1;
	while (idx < LSINIC_MERGE_MAX_NUM) {
		pkt_len =
			lsinic_mg_entry_len(mg_header->len_cmd[idx]);
		if (!pkt_len)
			break;
		align_off =
			lsinic_mg_entry_align_offset(mg_header->len_cmd[idx]);

		if ((offset + pkt_len + align_off) > total_size)
			break;

		mbuf = rte_mbuf_raw_alloc(rx_queue->mb_pool);
		if (!mbuf) {
			LSXINIC_PMD_ERR("MG RX mbuf alloc failed p:%u q:%u",
				rx_queue->port_id, rx_queue->queue_id);
			break;
		}

		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		data = rte_pktmbuf_mtod(mbuf, char *);
		rte_memcpy(data, (void *)(data_base + offset), pkt_len);
		mbuf->nb_segs = 1;
		mbuf->next = NULL;
		mbuf->pkt_len = pkt_len;
		mbuf->data_len = pkt_len;
		mbuf->port = rx_queue->port_id;
		mbuf->packet_type = RTE_PTYPE_L3_IPV4;

		rx_queue->mcache[rx_queue->mtail] = mbuf;
		rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
		rx_queue->mcnt++;

		offset += pkt_len + align_off;
		LSXINIC_PMD_DBG("EP MGD%d: len=%d next_off=%d\n",
			idx, pkt_len, offset);
		idx++;
	}

	return idx;
}

static uint16_t
lsinic_split_clone_mbufs(struct lsinic_queue *rx_queue,
	struct rte_mbuf *mbuf)
{
	uint16_t idx, offset;
	char *data_base = rte_pktmbuf_mtod(mbuf, char *);
	struct lsinic_mg_header *mg_header =
		(struct lsinic_mg_header *)
		(data_base - sizeof(struct lsinic_mg_header));
	struct rte_mbuf *new_mbuf[LSINIC_MERGE_MAX_NUM];
	int ret;
	uint8_t *pcore;
	uint16_t num = 0;

	rx_queue->mcache[rx_queue->mtail] = mbuf;
	rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
	rx_queue->mcnt++;

	mbuf->data_len = lsinic_mg_entry_len(mg_header->len_cmd[0]);
	mbuf->pkt_len = mbuf->data_len;
	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->port = rx_queue->port_id;
	mbuf->packet_type = RTE_PTYPE_L3_IPV4;
	offset = mbuf->pkt_len + mbuf->data_off +
			lsinic_mg_entry_align_offset(mg_header->len_cmd[0]);
	while (num < LSINIC_MERGE_MAX_NUM && mg_header->len_cmd[num])
		num++;

	if (num > 1) {
		ret = rte_pktmbuf_alloc_bulk(rx_queue->mb_pool,
			new_mbuf, num - 1);
		if (ret)
			return 1;
		mbuf->refcnt = (uint16_t)(mbuf->refcnt + num - 1);
	} else {
		return num;
	}

	mbuf->ol_flags |= LSINIC_SHARED_MBUF;
	pcore = (uint8_t *)mbuf->dynfield1;
	*pcore = rte_lcore_id();

	for (idx = 0; idx < (num - 1); idx++) {
		new_mbuf[idx]->ol_flags |=
			RTE_MBUF_F_INDIRECT | LSINIC_SHARED_MBUF;
		new_mbuf[idx]->buf_iova = mbuf->buf_iova;
		new_mbuf[idx]->buf_addr = mbuf->buf_addr;
		new_mbuf[idx]->buf_len = mbuf->buf_len;

		new_mbuf[idx]->data_off = offset;
		new_mbuf[idx]->pkt_len =
			lsinic_mg_entry_len(mg_header->len_cmd[idx]);
		new_mbuf[idx]->data_len =
			new_mbuf[idx]->pkt_len;
		new_mbuf[idx]->nb_segs = 1;
		new_mbuf[idx]->next = NULL;
		new_mbuf[idx]->port = rx_queue->port_id;
		new_mbuf[idx]->packet_type = RTE_PTYPE_L3_IPV4;
		pcore = (uint8_t *)new_mbuf[idx]->dynfield1;
		*pcore = rte_lcore_id();
		RTE_ASSERT(ALIGN(new_mbuf[idx]->pkt_len,
			LSINIC_MG_ALIGN_SIZE) ==
			(new_mbuf[idx]->pkt_len +
			lsinic_mg_entry_align_offset(mg_header->len_cmd[idx])));

		rx_queue->mcache[rx_queue->mtail] = new_mbuf[idx];
		rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
		rx_queue->mcnt++;

		offset += new_mbuf[idx]->pkt_len +
			lsinic_mg_entry_align_offset(mg_header->len_cmd[idx]);
	}

	return num;
}

static uint16_t
lsinic_dpaa2_recv_pkts_sbd(struct lsinic_queue *rxq,
	uint16_t rx_count)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, nb_rx = 0, first_idx;
	struct lsinic_ep_rx_src_addrx *rx_addrx = NULL;
	struct lsinic_ep_rx_src_addrl *rx_addrl = NULL;
	struct rte_eth_dev *recycle_dev = adapter->split_dev->eth_dev;
	eth_tx_burst_t tx_pkt_burst = NULL;
	struct rte_mbuf *mbuf_array[rx_count];
	struct lsinic_mg_header *mg_header;
	uint32_t count = 0, len, fd_idx = 0, mbuf_idx = 0;

	if (s_use_split_tx_cb) {
		if (adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS)
			tx_pkt_burst = lsinic_dpaa2_split_tx_lpbk;
		else
			tx_pkt_burst = recycle_dev->tx_pkt_burst;
	}

	first_idx = lsinic_queue_next_used_idx(rxq, 0);
	while (nb_rx < rx_count) {
		bd_idx = lsinic_queue_next_used_idx(rxq, 0);
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (!rxe)
			break;
		if (rxq->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
			rx_addrx = &rxq->rx_src_addrx[bd_idx];

			if (rx_addrx->len_cmd & LSINIC_EP_RX_SRC_ADDRX_MERGE) {
				mg_header = (struct lsinic_mg_header *)
					rte_pktmbuf_mtod(rxe->mbuf, char *);
				mg_header--;
				count = 0;
				while (count < LSINIC_MERGE_MAX_NUM &&
					mg_header->len_cmd[count])
					count++;
			} else {
				count = 1;
			}
		} else {
			rx_addrl = &rxq->rx_src_addrl[bd_idx];

			if (rx_addrl->len_cmd & LSINIC_BD_CMD_MG) {
				count = (rx_addrl->len_cmd &
					LSINIC_BD_MG_NUM_MASK) >>
					LSINIC_BD_MG_NUM_SHIFT;
			} else {
				count = 1;
			}
		}

		if (tx_pkt_burst) {
			rxq->split_cnt[mbuf_idx] = count;
			mbuf_array[mbuf_idx] = rxe->mbuf;
			fd_idx += count;
			mbuf_idx++;
			if (fd_idx >= MAX_TX_RING_SLOTS) {
				tx_pkt_burst(rxq->recycle_txq,
					mbuf_array, mbuf_idx);
				fd_idx = 0;
				mbuf_idx = 0;
			}
		} else {
			count = lsinic_dpaa2_split_mbuf_to_fd(rxe->mbuf,
					&rxq->recycle_fd[fd_idx], count, &len);
			rxq->bytes += len;
			rxq->bytes_fcs += len +
				LSINIC_ETH_FCS_SIZE * count;
			rxq->bytes_overhead += len +
				LSINIC_ETH_OVERHEAD_SIZE * count;
			rxq->packets += count;
			fd_idx += count;
			if (fd_idx >= MAX_TX_RING_SLOTS) {
				lsinic_dpaa2_enqueue(rxq->recycle_txq,
					&rxq->recycle_fd[0], fd_idx);
				fd_idx = 0;
			}
		}

		if (rx_addrx)
			rx_addrx->idx_cmd_len = 0;
		else
			rx_addrl->addr_cmd_len = 0;
		nb_rx++;
		rxq->next_used_idx++;
	}

	lsinic_recv_cnf_burst_update(rxq, nb_rx, first_idx);

	if (tx_pkt_burst && mbuf_idx) {
		tx_pkt_burst(rxq->recycle_txq, mbuf_array, mbuf_idx);
	} else if (fd_idx > 0) {
		lsinic_dpaa2_enqueue(rxq->recycle_txq,
				&rxq->recycle_fd[0], fd_idx);
	}

	return nb_rx;
}

static uint16_t
lsinic_dpaa2_recv_pkts(struct lsinic_queue *rxq,
	uint16_t rx_count)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, nb_rx = 0, fd_idx = 0, mbuf_idx = 0;
	uint32_t count = 0, len, first_idx;
	const struct lsinic_bd_desc *rxdp = NULL;
	struct rte_eth_dev *recycle_dev = adapter->split_dev->eth_dev;
	eth_tx_burst_t tx_pkt_burst = NULL;
	struct rte_mbuf *mbuf_array[rx_count];

	if (s_use_split_tx_cb) {
		if (adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS)
			tx_pkt_burst = lsinic_dpaa2_split_tx_lpbk;
		else
			tx_pkt_burst = recycle_dev->tx_pkt_burst;
	}

	first_idx = lsinic_queue_next_used_idx(rxq, 0);
	while (nb_rx < rx_count) {
		bd_idx = lsinic_queue_next_used_idx(rxq, 0);
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (unlikely(!rxe))
			break;
		rxdp = &rxq->ep_bd_desc[bd_idx];

		if (rxdp->len_cmd & LSINIC_BD_CMD_MG) {
			count = (rxdp->len_cmd & LSINIC_BD_MG_NUM_MASK) >>
					LSINIC_BD_MG_NUM_SHIFT;
		} else {
			count = 1;
		}

		if (tx_pkt_burst) {
			rxq->split_cnt[mbuf_idx] = count;
			mbuf_array[mbuf_idx] = rxe->mbuf;
			fd_idx += count;
			mbuf_idx++;
			if (fd_idx >= MAX_TX_RING_SLOTS) {
				tx_pkt_burst(rxq->recycle_txq,
					mbuf_array, mbuf_idx);
				fd_idx = 0;
				mbuf_idx = 0;
			}
		} else {
			count = lsinic_dpaa2_split_mbuf_to_fd(rxe->mbuf,
					&rxq->recycle_fd[fd_idx], count, &len);
			rxq->bytes += len;
			rxq->bytes_fcs += len +
				LSINIC_ETH_FCS_SIZE * count;
			rxq->bytes_overhead += len +
				LSINIC_ETH_OVERHEAD_SIZE * count;
			rxq->packets += count;
			fd_idx += count;
			if (fd_idx >= MAX_TX_RING_SLOTS) {
				lsinic_dpaa2_enqueue(rxq->recycle_txq,
					&rxq->recycle_fd[0], fd_idx);
				fd_idx = 0;
			}
		}
		nb_rx++;
		rxq->recv_update(rxq, bd_idx);
		rxq->next_used_idx++;
	}

	lsinic_recv_cnf_burst_update(rxq, nb_rx, first_idx);

	if (tx_pkt_burst && mbuf_idx) {
		tx_pkt_burst(rxq->recycle_txq, mbuf_array, mbuf_idx);
	} else if (fd_idx > 0) {
		lsinic_dpaa2_enqueue(rxq->recycle_txq,
				&rxq->recycle_fd[0], fd_idx);
	}

	return nb_rx;
}
#endif

static uint16_t
lsinic_recv_pkts_to_cache_seg(struct lsinic_queue *rxq)
{
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, first_idx;
	uint16_t nb_rx = 0;
	uint16_t rx_count;
	struct lsinic_seg_desc *rxdp = NULL;

	rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	if (!rx_count)
		return 0;

	first_idx = lsinic_queue_next_used_idx(rxq, 0);
	while (nb_rx < rx_count) {
		bd_idx = lsinic_queue_next_used_idx(rxq, 0);
		rxdp = &rxq->rx_src_seg[bd_idx];
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (!rxe)
			break;
		nb_rx++;

		rxm = rxe->mbuf;
		RTE_ASSERT(rxm);

		rxm->nb_segs = rxdp->nb;
		rxm->packet_type = RTE_PTYPE_L3_IPV4;
		rxq->mcache[rxq->mtail] = rxm;
		rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
		rxq->mcnt++;
		rxdp->nb = 0;

		rxq->next_used_idx++;

		if (rxq->mcnt > LSINIC_MAX_BURST_NUM)
			break;
	}

	lsinic_recv_cnf_burst_update(rxq, nb_rx, first_idx);

	return nb_rx;
}

static uint16_t
lsinic_recv_pkts_to_cache_idx(struct lsinic_queue *rxq)
{
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, first_idx;
	uint16_t nb_rx = 0;
	uint16_t rx_count;
	struct lsinic_ep_rx_src_addrx *rxdp = NULL;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	int count = 0;
#endif

	rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	if (!rx_count)
		return 0;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (rxq->recycle_txq)
		return lsinic_dpaa2_recv_pkts_sbd(rxq, rx_count);
#endif

	first_idx = lsinic_queue_next_used_idx(rxq, 0);
	while (nb_rx < rx_count) {
		bd_idx = lsinic_queue_next_used_idx(rxq, 0);
		rxdp = &rxq->rx_src_addrx[bd_idx];
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (!rxe)
			break;
		nb_rx++;

		rxm = rxe->mbuf;
		RTE_ASSERT(rxm);

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		if (rxdp->len_cmd & LSINIC_EP_RX_SRC_ADDRX_MERGE) {
			if (rxq->split_type == LSINIC_MBUF_CLONE_SPLIT) {
				count = lsinic_split_clone_mbufs(rxq, rxm);
			} else {
				count = lsinic_fetch_merge_rx_buffer(rxq,
					rxdp, rxm);
			}
		} else
#endif
		{
			rxm->packet_type = RTE_PTYPE_L3_IPV4;
			rxq->mcache[rxq->mtail] = rxm;
			rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
			rxq->mcnt++;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
			count = 1;
#endif
		}
		rxdp->idx_cmd_len = 0;

		rxq->next_used_idx++;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		if (!count)
			break;
#endif
		if (rxq->mcnt > LSINIC_MAX_BURST_NUM)
			break;
	}

	lsinic_recv_cnf_burst_update(rxq, nb_rx, first_idx);

	return nb_rx;
}

static uint16_t
lsinic_recv_pkts_to_cache_addrl(struct lsinic_queue *rxq)
{
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, first_idx;
	uint16_t nb_rx = 0;
	uint16_t rx_count;
	struct lsinic_ep_rx_src_addrl *rxdp = NULL;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	int count = 0;
#endif

	rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	if (!rx_count)
		return 0;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (rxq->recycle_txq)
		return lsinic_dpaa2_recv_pkts_sbd(rxq, rx_count);
#endif

	first_idx = lsinic_queue_next_used_idx(rxq, 0);
	while (nb_rx < rx_count) {
		bd_idx = lsinic_queue_next_used_idx(rxq, 0);
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (!rxe)
			break;
		rxdp = &rxq->rx_src_addrl[bd_idx];
		nb_rx++;

		rxm = rxe->mbuf;
		RTE_ASSERT(rxm);

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		if (rxdp->len_cmd & LSINIC_BD_CMD_MG) {
			if (rxq->split_type == LSINIC_MBUF_CLONE_SPLIT) {
				count = lsinic_split_clone_mbufs(rxq, rxm);
			} else {
				count = lsinic_fetch_merge_rx_buffer(rxq,
					rxdp, rxm);
			}
		} else
#endif
		{
			rxm->packet_type = RTE_PTYPE_L3_IPV4;
			rxq->mcache[rxq->mtail] = rxm;
			rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
			rxq->mcnt++;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
			count = 1;
#endif
		}
		rxdp->addr_cmd_len = 0;

		rxq->next_used_idx++;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		if (!count)
			break;
#endif
		if (rxq->mcnt > LSINIC_MAX_BURST_NUM)
			break;
	}

	lsinic_recv_cnf_burst_update(rxq, nb_rx, first_idx);

	return nb_rx;
}

static uint16_t
lsinic_recv_pkts_to_cache(struct lsinic_queue *rxq)
{
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, first_idx;
	uint16_t nb_rx = 0;
	uint16_t rx_count;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct lsinic_bd_desc *rxdp = NULL;
	int count = 0;
#endif

	rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	if (!rx_count)
		return 0;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	if (rxq->recycle_txq)
		return lsinic_dpaa2_recv_pkts(rxq, rx_count);
#endif

	first_idx = lsinic_queue_next_used_idx(rxq, 0);
	while (nb_rx < rx_count) {
		bd_idx = lsinic_queue_next_used_idx(rxq, 0);
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (!rxe)
			break;
		nb_rx++;

		rxm = rxe->mbuf;
		RTE_ASSERT(rxm);

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		rxdp = &rxq->local_src_bd_desc[bd_idx];
		if (rxdp->len_cmd & LSINIC_BD_CMD_MG) {
			count = (rxdp->len_cmd & LSINIC_BD_MG_NUM_MASK) >>
					LSINIC_BD_MG_NUM_SHIFT;
			if (rxq->split_type == LSINIC_MBUF_CLONE_SPLIT) {
				count = lsinic_split_clone_mbufs(rxq, rxm);
			} else {
				count = lsinic_fetch_merge_rx_buffer(rxq,
					rxdp, rxm);
			}
		} else
#endif
		{
			rxm->packet_type = RTE_PTYPE_L3_IPV4;
			rxq->mcache[rxq->mtail] = rxm;
			rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
			rxq->mcnt++;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
			count = 1;
#endif
		}

		rxq->recv_update(rxq, bd_idx);
		rxq->next_used_idx++;

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
		if (!count)
			break;
#endif
		if (rxq->mcnt > LSINIC_MAX_BURST_NUM)
			break;
	}

	lsinic_recv_cnf_burst_update(rxq, nb_rx, first_idx);

	return nb_rx;
}

uint16_t
lsinic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	int ret;
	struct rte_mbuf *rxm;
	uint16_t nb_rx;
	uint16_t count;
	struct lsinic_queue *rxq = rx_queue;
#ifdef LSXINIC_LATENCY_PROFILING
	uint64_t current_tick = 0;
	uint64_t tick_load;
	uint8_t *tick_load_8 = (uint8_t *)&tick_load;
	uint8_t *tick_save;
	uint8_t i;
	double cyc_per_us = rxq->adapter->cycs_per_us;
	double curr_latency;
#endif
	uint64_t pkt_old = rxq->packets;

	if (unlikely(!rxq->ep_enabled))
		return 0;

	lsinic_txq_loop(0);
	ret = lsinic_rxq_loop(rxq);
	if (unlikely(ret < 0)) {
		/**This RXQ not started yet.*/
		return 0;
	}
	if (rxq->ep_mem_bd_type == EP_MEM_SRC_SEG_BD)
		lsinic_recv_pkts_to_cache_seg(rxq);
	else if (rxq->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD)
		lsinic_recv_pkts_to_cache_idx(rxq);
	else if (rxq->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD)
		lsinic_recv_pkts_to_cache_addrl(rxq);
	else
		lsinic_recv_pkts_to_cache(rxq);

	if (rxq->mcnt == 0)
		return 0;

	count = RTE_MIN(nb_pkts, rxq->mcnt);
#ifdef LSXINIC_LATENCY_PROFILING
	if (count > 0)
		current_tick = rte_get_timer_cycles();
#endif
	for (nb_rx = 0; nb_rx < count; nb_rx++) {
		rxm = rxq->mcache[rxq->mhead];
#ifdef LSXINIC_LATENCY_PROFILING
		tick_save = rte_pktmbuf_mtod_offset(rxm,
			uint8_t *, rxm->pkt_len - sizeof(uint64_t));
		for (i = 0; i < (uint8_t)sizeof(uint64_t); i++)
			tick_load_8[i] = tick_save[i];
		rxq->cyc_diff_total += (current_tick - tick_load);
		curr_latency = (current_tick - tick_load) / cyc_per_us;
		if (rxq->latency_min > curr_latency)
			rxq->latency_min = curr_latency;
		rxq->avg_latency =
			rxq->cyc_diff_total /
			(rxq->packets + nb_rx + 1) / cyc_per_us;
		if (curr_latency >= 2 * rxq->avg_latency &&
			curr_latency < 4 * rxq->avg_latency) {
			rxq->avg_x2_total++;
		} else if (curr_latency >= 4 * rxq->avg_latency &&
			curr_latency < 10 * rxq->avg_latency) {
			rxq->avg_x2_total++;
			rxq->avg_x4_total++;
		} else if (curr_latency >= 10 * rxq->avg_latency &&
			curr_latency < 20 * rxq->avg_latency) {
			rxq->avg_x2_total++;
			rxq->avg_x4_total++;
			rxq->avg_x10_total++;
		} else if (curr_latency >= 20 * rxq->avg_latency &&
			curr_latency < 40 * rxq->avg_latency) {
			rxq->avg_x2_total++;
			rxq->avg_x4_total++;
			rxq->avg_x10_total++;
			rxq->avg_x20_total++;
		} else if (curr_latency >= 40 * rxq->avg_latency &&
			curr_latency < 100 * rxq->avg_latency) {
			rxq->avg_x2_total++;
			rxq->avg_x4_total++;
			rxq->avg_x10_total++;
			rxq->avg_x20_total++;
			rxq->avg_x40_total++;
		} else if (curr_latency >= 100 * rxq->avg_latency) {
			rxq->avg_x2_total++;
			rxq->avg_x4_total++;
			rxq->avg_x10_total++;
			rxq->avg_x20_total++;
			rxq->avg_x40_total++;
			rxq->avg_x100_total++;
		}
		rxm->pkt_len -= sizeof(uint64_t);
		rxm->data_len -= sizeof(uint64_t);
#endif
		rx_pkts[nb_rx] = rxm;
		rxq->mhead = (rxq->mhead + 1) & MCACHE_MASK;
		rxq->mcnt--;
		rxq->bytes += rxm->pkt_len;
		rxq->bytes_fcs += rxm->pkt_len +
			LSINIC_ETH_FCS_SIZE * rxm->nb_segs;
		rxq->bytes_overhead += rxm->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE * rxm->nb_segs;

#ifdef RTE_LIBRTE_LSINIC_DEBUG_RX
		lsinic_mbuf_print_all(rxm);
#endif
	}

	rxq->packets += nb_rx;
	if (rxq->packets > pkt_old)
		lsinic_queue_trigger_interrupt(rxq);

	return nb_rx;
}

/*********************************************************************
 *
 *  Queue management functions
 *
 **********************************************************************/
void
lsinic_dev_tx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid)
{
	lsinic_queue_release(dev->data->tx_queues[qid]);
}

int
lsinic_dev_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct lsinic_adapter *adapter = dev->process_private;
	struct lsinic_bdr_reg *bdr_reg =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct lsinic_queue *txq;
	int ret;
	uint64_t base_offset = LSINIC_EP2RC_RING_OFFSET(adapter->max_qpairs);
	uint8_t *txq_base = adapter->bd_desc_base + base_offset;
	uint64_t q_offset = queue_idx * LSINIC_RING_SIZE;

	if ((queue_idx + 1) > adapter->max_qpairs) {
		LSXINIC_PMD_ERR("config txq number(%d) > max qpair(%d)",
			queue_idx + 1, adapter->max_qpairs);
		return -EINVAL;
	}
	/* Note: ep-tx == rc-rx */

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->tx_queues[queue_idx])
		lsinic_queue_release(dev->data->tx_queues[queue_idx]);

	/* First allocate the tx queue data structure */
	txq = lsinic_queue_alloc(adapter, queue_idx, socket_id,
			nb_desc, LSINIC_QUEUE_TX);
	if (!txq)
		return -ENOMEM;

	txq->txq_dma_eq = lsinic_txq_dma_eq;
	txq->dma_dq = lsinic_txq_dma_dq;
	txq->dma_id = adapter->txq_dma_id;
	txq->dma_vq = -1;
	txq->port_id = dev->data->port_id;

	/* using RC's rx ring to send EP's packets */
	txq->ep_reg = &bdr_reg->rx_ring[queue_idx];
	txq->rc_bd_desc = NULL;
	txq->rc_reg = txq->ep_reg;
	txq->dev = dev;
	txq->ep_bd_shared_addr = txq_base + q_offset;

	txq->core_id = RTE_MAX_LCORE;
	txq->pid = 0;
	rte_spinlock_init(&txq->multi_core_lock);

	lsinic_byte_memset(txq->ep_bd_shared_addr,
		0, LSINIC_RING_SIZE);

	dev->tx_pkt_burst = lsinic_xmit_pkts;

	lsinic_queue_reset(txq);

	dev->data->tx_queues[queue_idx] = txq;

	if (adapter->tx_ring_bd_count != txq->nb_desc) {
		adapter->tx_ring_bd_count = txq->nb_desc;
		LSINIC_WRITE_REG(&eth_reg->rx_entry_num, txq->nb_desc);
	}
	if (adapter->num_tx_queues <= queue_idx) {
		adapter->num_tx_queues = queue_idx + 1;
		LSINIC_WRITE_REG(&eth_reg->rx_ring_num, adapter->num_tx_queues);
	}

	ret = lsinic_queue_dma_create(txq);
	if (ret) {
		LSXINIC_PMD_ERR("%s txq%d dma create failed",
			dev->data->name,
			txq->queue_id);

		return ret;
	}

	txq->wdma_bd_start = LSINIC_BD_DMA_START_FLAG;
	txq->rdma_bd_start = LSINIC_BD_DMA_START_FLAG;
	txq->dma_idx = rte_malloc(NULL,
		sizeof(uint16_t) * nb_desc,
		RTE_DPAAX_QDMA_SG_IDX_ADDR_ALIGN);
	if (!txq->dma_idx)
		return -ENOMEM;

	return 0;
}

void
lsinic_dev_rx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid)
{
	lsinic_queue_release(dev->data->rx_queues[qid]);
}

static const struct rte_memzone *
lsinic_dev_mempool_continue_mz(struct rte_mempool *mp)
{
	struct rte_mempool_memhdr *hdr;
	struct rte_memzone *mz = NULL;
	struct rte_memzone *last_mz = NULL;

	STAILQ_FOREACH(hdr, &mp->mem_list, next) {
		mz = hdr->opaque;
		if (last_mz && mz != last_mz)
			return NULL;
		last_mz = mz;
	}

	return mz;
}

int
lsinic_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mp)
{
	struct lsinic_adapter *adapter = dev->process_private;
	struct lsinic_bdr_reg *bdr_reg =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct lsinic_queue *rxq;
	int ret;
	struct lsinic_eth_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct rte_lsx_pciep_device *lsinic_dev;
	uint64_t base_offset = LSINIC_RC2EP_RING_OFFSET(adapter->max_qpairs);
	uint8_t *rxq_base = adapter->bd_desc_base + base_offset;
	uint64_t q_offset = queue_idx * LSINIC_RING_SIZE;

	if ((queue_idx + 1) > adapter->max_qpairs) {
		LSXINIC_PMD_ERR("config rxq number(%d) > max qpair(%d)",
			queue_idx + 1, adapter->max_qpairs);
		return -EINVAL;
	}
	lsinic_dev = adapter->lsinic_dev;

	/* Note: ep-rx == rc-tx */

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->rx_queues[queue_idx])
		lsinic_queue_release(dev->data->rx_queues[queue_idx]);

	/* First allocate the tx queue data structure */
	rxq = lsinic_queue_alloc(adapter, queue_idx, socket_id,
			nb_desc, LSINIC_QUEUE_RX);
	if (!rxq)
		return -ENOMEM;

	adapter->data_room_size =
		rte_pktmbuf_data_room_size(mp) - RTE_PKTMBUF_HEADROOM;
	LSINIC_WRITE_REG(&reg->max_data_room, adapter->data_room_size);

	rxq->rx_dma_mbuf_set = lsinic_recv_mbuf_dma_set;
	rxq->rxq_dma_eq = lsinic_rxq_dma_eq;
	rxq->dma_dq = lsinic_rxq_dma_dq;
	rxq->dma_id = adapter->rxq_dma_id;
	rxq->dma_vq = -1;
	rxq->mb_pool = mp;
	rxq->port_id = dev->data->port_id;
	rxq->crc_len = 0;
	rxq->drop_en = rx_conf->rx_drop_en;
	rxq->core_id = RTE_MAX_LCORE;
	rxq->pid = 0;
	rte_spinlock_init(&rxq->multi_core_lock);

	/* using RC's tx ring to receive EP's packets */
	rxq->ep_reg = &bdr_reg->tx_ring[queue_idx];
	rxq->rc_bd_desc = NULL;
	rxq->rc_reg = rxq->ep_reg;
	rxq->dev = dev;
	rxq->ep_bd_shared_addr = rxq_base + q_offset;

	lsinic_byte_memset(rxq->ep_bd_shared_addr, 0,
		LSINIC_RING_SIZE);

	lsinic_queue_reset(rxq);

	dev->data->rx_queues[queue_idx] = rxq;

	if (adapter->rx_ring_bd_count != rxq->nb_desc) {
		adapter->rx_ring_bd_count = rxq->nb_desc;
		LSINIC_WRITE_REG(&eth_reg->tx_entry_num, rxq->nb_desc);
	}
	if (adapter->num_rx_queues <= queue_idx) {
		adapter->num_rx_queues = queue_idx + 1;
		LSINIC_WRITE_REG(&eth_reg->tx_ring_num, adapter->num_rx_queues);
	}

	if (adapter->cap & LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM &&
		!lsinic_dev->virt_addr[LSX_PCIEP_XFER_MEM_BAR_IDX]) {
		const struct rte_memzone *mz;
		int ret, bar;
		uint64_t mask;

		mz = lsinic_dev_mempool_continue_mz(mp);
		if (!mz)
			return -ENOMEM;

		mask = rte_lsx_pciep_bus_win_mask(lsinic_dev);
		if (mask && (mask & mz->len)) {
			LSXINIC_PMD_ERR("!Align Len(0x%lx)-mask(0x%lx)",
				mz->len, mask);
			return -EINVAL;
		}

		bar = LSX_PCIEP_XFER_MEM_BAR_IDX;
		lsinic_dev->virt_addr[bar] = mz->addr;
		lsinic_dev->iov_addr[bar] = mz->iova;
		lsinic_dev->phy_addr[bar] = rte_mem_virt2phy(mz->addr);

		ret = rte_lsx_pciep_set_ib_win(lsinic_dev, bar, mz->len);
		if (ret)
			return ret;
		if (rte_lsx_pciep_hw_sim_get(adapter->pcie_idx) &&
			!lsinic_dev->is_vf) {
			ret = rte_lsx_pciep_sim_dev_map_inbound(lsinic_dev);
			if (ret)
				return ret;
		}
	}

	ret = lsinic_queue_dma_create(rxq);
	if (ret) {
		LSXINIC_PMD_ERR("%s rxq%d dma create failed",
			dev->data->name,
			rxq->queue_id);

		return ret;
	}

	rxq->wdma_bd_start = LSINIC_BD_DMA_START_FLAG;
	rxq->rdma_bd_start = LSINIC_BD_DMA_START_FLAG;

	rxq->dma_idx = rte_malloc(NULL,
		sizeof(uint16_t) * nb_desc,
		RTE_DPAAX_QDMA_SG_IDX_ADDR_ALIGN);
	if (!rxq->dma_idx)
		return -ENOMEM;

#ifdef LSXINIC_LATENCY_PROFILING
	rxq->latency_min = 1000 * 1000;
#endif

	return 0;
}

void
lsinic_dev_clear_queues(struct rte_eth_dev *dev)
{
	unsigned int i, j;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct lsinic_queue *txq = dev->data->tx_queues[i];
		struct lsinic_queue *next = txq;

		if (!txq)
			continue;
		for (j = 0; j < txq->nb_q; j++) {
			if (!next)
				break;

			if (next->status != LSINIC_QUEUE_RUNNING) {
				lsinic_queue_release_mbufs(next);
				lsinic_queue_reset(next);
				if (next->multi_core_ring) {
					rte_ring_free(next->multi_core_ring);
					next->multi_core_ring = NULL;
				}
			}
			next = next->sibling;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct lsinic_queue *rxq = dev->data->rx_queues[i];
		struct lsinic_queue *next = rxq;

		if (!rxq)
			continue;
		for (j = 0; j < rxq->nb_q; j++) {
			if (!next)
				break;

			if (next->status != LSINIC_QUEUE_RUNNING) {
				lsinic_queue_release_mbufs(next);
				lsinic_queue_reset(next);
				if (next->multi_core_ring) {
					rte_ring_free(next->multi_core_ring);
					next->multi_core_ring = NULL;
				}
			}
			next = next->sibling;
		}
	}
}

/*********************************************************************
 *
 *  Device RX/TX init functions
 *
 **********************************************************************/
int lsinic_dev_rxq_init(struct lsinic_queue *rxq)
{
	lsinic_queue_init(rxq);

	/* Reset crc_len in case it was changed after queue setup by a
	 * call to configure.
	 */
	rxq->crc_len = 0;
	if (rxq->adapter->cap & LSINIC_CAP_RC_XFER_BD_DMA_UPDATE)
		rxq->ep_reg->rdma = 1;
	else
		rxq->ep_reg->rdma = 0;

	return 0;
}

/* Initializes Receive Unit.
 */
int
lsinic_dev_rx_init(struct rte_eth_dev *dev)
{
	struct lsinic_queue *rxq;
	uint16_t i;
	int ret;

	/* Setup RX queues */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		if (rxq->status != LSINIC_QUEUE_RUNNING) {
			ret = lsinic_dev_rxq_init(rxq);
			if (ret)
				return ret;
		}
		rxq->ep_enabled = 1;
	}

	return 0;
}

int lsinic_dev_txq_init(struct lsinic_tx_queue *txq)
{
	lsinic_queue_init(txq);

	return 0;
}

/* Initializes Transmit Unit.
 */
void
lsinic_dev_tx_init(struct rte_eth_dev *dev)
{
	struct lsinic_queue *txq;
	uint16_t i;

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		if (txq->status != LSINIC_QUEUE_RUNNING)
			lsinic_dev_txq_init(txq);
		txq->ep_enabled = 1;
	}
}

void lsinic_dev_rx_tx_bind(struct rte_eth_dev *dev)
{
	struct lsinic_queue *txq;
	struct lsinic_queue *rxq;
	uint16_t i, num;
	uint32_t rdma;
	struct lsinic_adapter *adapter = dev->process_private;

	num = RTE_MIN(dev->data->nb_tx_queues,
			dev->data->nb_rx_queues);

	/* Link RX and Tx Descriptor Rings */
	for (i = 0; i < num; i++) {
		txq = dev->data->tx_queues[i];
		rxq = dev->data->rx_queues[i];
		if (!txq || !rxq)
			continue;

		rxq->pair = txq;
		txq->pair = rxq;
	}
	rdma = adapter->cap;
	rdma = rdma & LSINIC_CAP_RC_RECV_ADDR_DMA_UPDATE;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		if (txq->pair && rdma)
			txq->ep_reg->rdma = 1;
		else
			txq->ep_reg->rdma = 0;
	}
}

uint16_t
lsinic_dev_rx_stop(struct rte_eth_dev *dev, int force)
{
	struct lsinic_queue *rxq;
	uint16_t i, stop_count = 0;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		if (!rxq) {
			stop_count++;
			continue;
		}
		rxq->ep_enabled = 0;
		if (force || rxq->status != LSINIC_QUEUE_RUNNING) {
			lsinic_queue_stop(rxq);
			stop_count++;
		}
	}

	return stop_count;
}

uint16_t
lsinic_dev_tx_stop(struct rte_eth_dev *dev, int force)
{
	struct lsinic_queue *txq;
	uint16_t i, stop_count = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		if (!txq) {
			stop_count++;
			continue;
		}
		txq->ep_enabled = 0;
		if (force || txq->status != LSINIC_QUEUE_RUNNING) {
			lsinic_queue_stop(txq);
			stop_count++;
		}
	}

	return stop_count;
}

void lsinic_dev_rx_enable_start(struct rte_eth_dev *dev)
{
	struct lsinic_queue *rxq;
	uint16_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		lsinic_queue_enable_start(rxq);
	}
}

void lsinic_dev_tx_enable_start(struct rte_eth_dev *dev)
{
	struct lsinic_queue *txq;
	uint16_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		lsinic_queue_enable_start(txq);
	}
}
