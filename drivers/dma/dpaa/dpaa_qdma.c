/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2024 NXP
 */

#include <bus_dpaa_driver.h>
#include <rte_dmadev_pmd.h>

#include "dpaa_qdma.h"
#include "dpaa_qdma_logs.h"

static inline void
qdma_desc_addr_set64(struct fsl_qdma_format *ccdf, u64 addr)
{
	ccdf->addr_hi = upper_32_bits(addr);
	ccdf->addr_lo = rte_cpu_to_le_32(lower_32_bits(addr));
}

static inline void
qdma_ccdf_set_format(struct fsl_qdma_format *ccdf, int offset)
{
	ccdf->cfg = rte_cpu_to_le_32(QDMA_CCDF_FOTMAT | offset);
}

static inline int
qdma_ccdf_get_status(const struct fsl_qdma_format *ccdf)
{
	return (rte_le_to_cpu_32(ccdf->status) & QDMA_CCDF_MASK)
		>> QDMA_CCDF_STATUS;
}

static inline void
qdma_ccdf_set_ser(struct fsl_qdma_format *ccdf, int status)
{
	ccdf->status = rte_cpu_to_le_32(QDMA_CCDF_SER | status);
}

static inline void
qdma_csgf_set_len(struct fsl_qdma_format *csgf, int len)
{
	csgf->cfg = rte_cpu_to_le_32(len & QDMA_SG_LEN_MASK);
}

static inline void
qdma_csgf_set_f(struct fsl_qdma_format *csgf, int len)
{
	csgf->cfg = rte_cpu_to_le_32(QDMA_SG_FIN | (len & QDMA_SG_LEN_MASK));
}

static inline int ilog2(int x)
{
	int log = 0;

	x >>= 1;

	while (x) {
		log++;
		x >>= 1;
	}
	return log;
}

static inline int ilog2_qsize(uint32_t q_size)
{
	return (ilog2(q_size) - ilog2(64));
}

static inline int ilog2_qthld(uint32_t q_thld)
{
	return (ilog2(q_thld) - ilog2(16));
}

static inline int
fsl_qdma_queue_bd_in_hw(struct fsl_qdma_queue *fsl_queue)
{
	struct rte_dma_stats *stats = &fsl_queue->stats;

	return (stats->submitted - stats->completed);
}

static uint32_t
qdma_readl(void *addr)
{
	return QDMA_IN(addr);
}

static void
qdma_writel(uint32_t val, void *addr)
{
	QDMA_OUT(addr, val);
}

static uint32_t
qdma_readl_be(void *addr)
{
	return QDMA_IN_BE(addr);
}

static void
qdma_writel_be(uint32_t val, void *addr)
{
	QDMA_OUT_BE(addr, val);
}

static void *
dma_pool_alloc(int size, int aligned, dma_addr_t *phy_addr)
{
	void *virt_addr;

	virt_addr = rte_malloc("dma pool alloc", size, aligned);
	if (!virt_addr)
		return NULL;

	*phy_addr = rte_mem_virt2iova(virt_addr);

	return virt_addr;
}

/*
 * Pre-request command descriptor and compound S/G for enqueue.
 */
static int
fsl_qdma_pre_comp_sd_desc(struct fsl_qdma_queue *queue)
{
	struct fsl_qdma_sdf *sdf;
	struct fsl_qdma_ddf *ddf;
	struct fsl_qdma_format *ccdf;
	uint16_t i, j;
	struct fsl_qdma_format *head;
	struct fsl_qdma_cmpd_ft *ft;
	struct fsl_qdma_df *df;

	head = queue->cmd_desc;

	for (i = 0; i < queue->n_cq; i++) {
		dma_addr_t phy_ft = 0, phy_df = 0;

		queue->ft[i] =
			dma_pool_alloc(sizeof(struct fsl_qdma_cmpd_ft),
				RTE_CACHE_LINE_SIZE, &phy_ft);
		if (!queue->ft[i])
			goto fail;

		queue->df[i] =
			dma_pool_alloc(sizeof(struct fsl_qdma_df),
				RTE_CACHE_LINE_SIZE, &phy_df);
		if (!queue->df[i]) {
			rte_free(queue->ft[i]);
			goto fail;
		}

		memset(queue->ft[i], 0, sizeof(struct fsl_qdma_cmpd_ft));
		memset(queue->df[i], 0, sizeof(struct fsl_qdma_df));

		ft = queue->ft[i];
		df = queue->df[i];
		sdf = &df->sdf;
		ddf = &df->ddf;
		/* Compound Command Descriptor(Frame List Table) */
		qdma_desc_addr_set64(&ft->desc_buf, phy_df);

		/* It must be 32 as Compound S/G Descriptor */
		qdma_csgf_set_len(&ft->desc_buf,
			sizeof(struct fsl_qdma_df));
		/* Descriptor Buffer */
		sdf->cmd = rte_cpu_to_le_32(FSL_QDMA_CMD_RWTTYPE <<
			       FSL_QDMA_CMD_RWTTYPE_OFFSET);
#ifdef RTE_DMA_DPAA_ERRATA_ERR050265
		sdf->cmd |= rte_cpu_to_le_32(FSL_QDMA_CMD_PF);
#endif
		ddf->cmd = rte_cpu_to_le_32(FSL_QDMA_CMD_RWTTYPE <<
			       FSL_QDMA_CMD_RWTTYPE_OFFSET);
		ddf->cmd |= rte_cpu_to_le_32(FSL_QDMA_CMD_LWC <<
				FSL_QDMA_CMD_LWC_OFFSET);

		ccdf = queue->cmd_desc;
		qdma_desc_addr_set64(ccdf, phy_ft);
		qdma_ccdf_set_format(ccdf, 0);
		qdma_ccdf_set_ser(ccdf, 0);
		queue->cmd_desc++;
	}
	queue->cmd_desc = head;
	queue->ci = 0;

	return 0;

fail:
	for (j = 0; j < i; j++) {
		rte_free(queue->ft[j]);
		rte_free(queue->df[j]);
	}

	return -ENOMEM;
}

static struct fsl_qdma_queue *
fsl_qdma_alloc_queue_resources(struct fsl_qdma_engine *fsl_qdma,
	int queue_id, int block_id)
{
	struct fsl_qdma_queue *queue_temp;
	uint32_t queue_size;

	queue_temp = rte_zmalloc("qdma: queue head",
		sizeof(struct fsl_qdma_queue), 0);
	if (!queue_temp) {
		DPAA_QDMA_ERR("no memory to allocate queues\n");
		return NULL;
	}
	queue_size = sizeof(struct fsl_qdma_format) * QDMA_QUEUE_SIZE;

	queue_temp->cq = dma_pool_alloc(queue_size,
		queue_size, &queue_temp->bus_addr);
	if (!queue_temp->cq) {
		rte_free(queue_temp);
		return NULL;
	}

	memset(queue_temp->cq, 0x0, queue_size);

	queue_temp->block_vir = fsl_qdma->block_base +
		FSL_QDMA_BLOCK_BASE_OFFSET(fsl_qdma, block_id);
	queue_temp->n_cq = QDMA_QUEUE_SIZE;
	queue_temp->queue_id = queue_id;
	queue_temp->pending = 0;
	queue_temp->cmd_desc = queue_temp->cq;
	queue_temp->ft = rte_malloc("Compound Frame Table",
			sizeof(void *) * QDMA_QUEUE_SIZE, 0);
	if (!queue_temp->ft) {
		rte_free(queue_temp->cq);
		rte_free(queue_temp);
		return NULL;
	}
	queue_temp->df = rte_malloc("Descriptor Buffer",
			sizeof(void *) * QDMA_QUEUE_SIZE, 0);
	if (!queue_temp->df) {
		rte_free(queue_temp->ft);
		rte_free(queue_temp->cq);
		rte_free(queue_temp);
		return NULL;
	}
	memset(&queue_temp->stats, 0, sizeof(struct rte_dma_stats));

	return queue_temp;
}

static void
fsl_qdma_free_queue_resources(struct fsl_qdma_queue *queue)
{
	rte_free(queue->df);
	rte_free(queue->ft);
	rte_free(queue->cq);
	rte_free(queue);
}

static struct fsl_qdma_queue *
fsl_qdma_prep_status_queue(struct fsl_qdma_engine *fsl_qdma,
	uint32_t block_id)
{
	struct fsl_qdma_queue *status_head;
	uint32_t status_size;

	status_size = QDMA_STATUS_SIZE * sizeof(struct fsl_qdma_format);

	status_head = rte_zmalloc("qdma: status head",
		sizeof(*status_head), 0);
	if (!status_head)
		return NULL;

	/*
	 * Buffer for queue command
	 */
	status_head->cq = dma_pool_alloc(status_size,
		status_size, &status_head->bus_addr);

	if (!status_head->cq) {
		rte_free(status_head);
		return NULL;
	}

	memset(status_head->cq, 0x0, status_size);
	status_head->n_cq = status_size;
	status_head->cmd_desc = status_head->cq;
	status_head->block_id = block_id;
	status_head->block_vir = fsl_qdma->block_base +
		FSL_QDMA_BLOCK_BASE_OFFSET(fsl_qdma, block_id);

	return status_head;
}

static void
fsl_qdma_free_status_queue(struct fsl_qdma_queue *status)
{
	rte_free(status->cq);
	rte_free(status);
}

static int
fsl_qdma_halt(struct fsl_qdma_engine *fsl_qdma)
{
	uint8_t *ctrl = fsl_qdma->ctrl_base;
	uint8_t *block;
	int i, count = RETRIES;
	unsigned int j;
	uint32_t reg;

	/* Disable the command queue and wait for idle state. */
	reg = qdma_readl(ctrl + FSL_QDMA_DMR);
	reg |= FSL_QDMA_DMR_DQD;
	qdma_writel(reg, ctrl + FSL_QDMA_DMR);
	for (j = 0; j < fsl_qdma->num_blocks; j++) {
		block = fsl_qdma->block_base +
			FSL_QDMA_BLOCK_BASE_OFFSET(fsl_qdma, j);
		for (i = 0; i < FSL_QDMA_QUEUE_NUM_MAX; i++)
			qdma_writel(0, block + FSL_QDMA_BCQMR(i));
	}
	while (true) {
		reg = qdma_readl(ctrl + FSL_QDMA_DSR);
		if (!(reg & FSL_QDMA_DSR_DB))
			break;
		if (count-- < 0)
			return -EBUSY;
		rte_delay_us(100);
	}

	for (j = 0; j < fsl_qdma->num_blocks; j++) {
		block = fsl_qdma->block_base +
			FSL_QDMA_BLOCK_BASE_OFFSET(fsl_qdma, j);

		/* Disable status queue. */
		qdma_writel(0, block + FSL_QDMA_BSQMR);

		/*
		 * clear the command queue interrupt detect register for
		 * all queues.
		 */
		qdma_writel(0xffffffff, block + FSL_QDMA_BCQIDR(0));
	}

	return 0;
}

static int
fsl_qdma_queue_transfer_complete(struct fsl_qdma_queue *fsl_queue,
	const uint16_t nb_cpls,
	enum rte_dma_status_code *status)
{
	uint32_t reg;
	int count = 0;
	uint8_t *block = fsl_queue->block_vir;

	while (count < nb_cpls) {
		reg = qdma_readl_be(block + FSL_QDMA_BSQSR);
		if (reg & FSL_QDMA_BSQSR_QE_BE)
			return count;

		qdma_writel_be(FSL_QDMA_BSQMR_DI, block + FSL_QDMA_BSQMR);
		if (status != NULL)
			status[count] = RTE_DMA_STATUS_SUCCESSFUL;
		fsl_queue->complete++;
		if (unlikely(fsl_queue->complete >= fsl_queue->n_cq))
			fsl_queue->complete = 0;

		count++;
	}
	return count;
}

static int
fsl_qdma_reg_init(struct fsl_qdma_engine *fsl_qdma)
{
	struct fsl_qdma_queue *temp;
	void *ctrl = fsl_qdma->ctrl_base;
	uint8_t *block;
	uint32_t i, j, k = 0;
	uint32_t reg;
	int ret, val;

	/* Try to halt the qDMA engine first. */
	ret = fsl_qdma_halt(fsl_qdma);
	if (ret) {
		DPAA_QDMA_ERR("DMA halt failed!");
		return ret;
	}

	for (j = 0; j < fsl_qdma->num_blocks; j++) {
		block = fsl_qdma->block_base +
			FSL_QDMA_BLOCK_BASE_OFFSET(fsl_qdma, j);
		for (i = 0; i < QDMA_QUEUES; i++) {
			temp = fsl_qdma->queue[k];
			/*
			 * Initialize Command Queue registers to
			 * point to the first
			 * command descriptor in memory.
			 * Dequeue Pointer Address Registers
			 * Enqueue Pointer Address Registers
			 */

			qdma_writel(lower_32_bits(temp->bus_addr),
				    block + FSL_QDMA_BCQDPA_SADDR(i));
			qdma_writel(upper_32_bits(temp->bus_addr),
				    block + FSL_QDMA_BCQEDPA_SADDR(i));
			qdma_writel(lower_32_bits(temp->bus_addr),
				    block + FSL_QDMA_BCQEPA_SADDR(i));
			qdma_writel(upper_32_bits(temp->bus_addr),
				    block + FSL_QDMA_BCQEEPA_SADDR(i));

			/* Initialize the queue mode. */
			reg = FSL_QDMA_BCQMR_EN;
			reg |= FSL_QDMA_BCQMR_CD_THLD(ilog2_qthld(temp->n_cq));
			reg |= FSL_QDMA_BCQMR_CQ_SIZE(ilog2_qsize(temp->n_cq));
			temp->le_cqmr = reg;
			qdma_writel(reg, block + FSL_QDMA_BCQMR(i));
			k++;
		}

		/*
		 * Workaround for erratum: ERR010812.
		 * We must enable XOFF to avoid the enqueue rejection occurs.
		 * Setting SQCCMR ENTER_WM to 0x20.
		 */

		qdma_writel(FSL_QDMA_SQCCMR_ENTER_WM,
			    block + FSL_QDMA_SQCCMR);

		/*
		 * Initialize status queue registers to point to the first
		 * command descriptor in memory.
		 * Dequeue Pointer Address Registers
		 * Enqueue Pointer Address Registers
		 */

		temp = fsl_qdma->status[j];
		qdma_writel(upper_32_bits(temp->bus_addr),
			block + FSL_QDMA_SQEEPAR);
		qdma_writel(lower_32_bits(temp->bus_addr),
			block + FSL_QDMA_SQEPAR);
		qdma_writel(upper_32_bits(temp->bus_addr),
			block + FSL_QDMA_SQEDPAR);
		qdma_writel(lower_32_bits(temp->bus_addr),
			block + FSL_QDMA_SQDPAR);
		/* Desiable status queue interrupt. */

		qdma_writel(0x0, block + FSL_QDMA_BCQIER(0));
		qdma_writel(0x0, block + FSL_QDMA_BSQICR);
		qdma_writel(0x0, block + FSL_QDMA_CQIER);

		/* Initialize the status queue mode. */
		reg = FSL_QDMA_BSQMR_EN;
		val = ilog2_qsize(temp->n_cq);
		reg |= FSL_QDMA_BSQMR_CQ_SIZE(val);
		qdma_writel(reg, block + FSL_QDMA_BSQMR);
	}

	reg = qdma_readl(ctrl + FSL_QDMA_DMR);
	reg &= ~FSL_QDMA_DMR_DQD;
	qdma_writel(reg, ctrl + FSL_QDMA_DMR);

	return 0;
}

static int
fsl_qdma_enqueue_desc(struct fsl_qdma_queue *fsl_queue,
	uint64_t flags, dma_addr_t dst,
	dma_addr_t src, size_t len)
{
	uint8_t *block = fsl_queue->block_vir;
	struct fsl_qdma_format *csgf_src, *csgf_dest;
	struct fsl_qdma_cmpd_ft *ft;
#ifdef RTE_DMA_DPAA_ERRATA_ERR050757
	struct fsl_qdma_sdf *sdf;
	uint32_t cfg = 0;
#endif

#ifdef CONFIG_RTE_DMA_DPAA_ERR_CHK
	uint32_t reg;

	/* retrieve and store the register value in big endian
	 * to avoid bits swap
	 */
	reg = qdma_readl_be(block +
			 FSL_QDMA_BCQSR(fsl_queue->queue_id));
	if (reg & (FSL_QDMA_BCQSR_QF_XOFF_BE)) {
		DPAA_QDMA_ERR("QDMA Engine is busy\n");
		return -EBUSY;
	}
#else
	/* check whether critical watermark level reached,
	 * below check is valid for only single queue per block
	 */
	if (fsl_qdma_queue_bd_in_hw(fsl_queue) >= QDMA_QUEUE_CR_WM) {
		DPAA_QDMA_DEBUG("Queue is full, try dequeue first\n");
		return -ENOSPC;
	}
#endif

	if (unlikely(fsl_queue->pending == fsl_queue->n_cq)) {
		DPAA_QDMA_DEBUG("Queue is full, try dma submit first\n");
		return -ENOSPC;
	}

	ft = fsl_queue->ft[fsl_queue->ci];
	csgf_src = &ft->desc_sbuf;
	csgf_dest = &ft->desc_dbuf;
#ifdef RTE_DMA_DPAA_ERRATA_ERR050757
	sdf = fsl_queue->df[fsl_queue->ci];
	sdf->cmd = rte_cpu_to_le_32(FSL_QDMA_CMD_RWTTYPE <<
			FSL_QDMA_CMD_RWTTYPE_OFFSET);
#ifdef RTE_DMA_DPAA_ERRATA_ERR050265
	sdf->cmd |= rte_cpu_to_le_32(FSL_QDMA_CMD_PF);
#endif
	if (len > FSL_QDMA_CMD_SSS_DISTANCE) {
		sdf->cmd |= rte_cpu_to_le_32(FSL_QDMA_CMD_SSEN);
		cfg |= rte_cpu_to_le_32(FSL_QDMA_CMD_SSS_STRIDE <<
					FSL_QDMA_CFG_SSS_OFFSET |
					FSL_QDMA_CMD_SSS_DISTANCE);
		sdf->cfg = cfg;
	} else
		sdf->cfg = 0;
#endif
	qdma_desc_addr_set64(csgf_src, src);
	qdma_csgf_set_len(csgf_src, len);
	qdma_desc_addr_set64(csgf_dest, dst);
	qdma_csgf_set_len(csgf_dest, len);
	/* This entry is the last entry. */
	qdma_csgf_set_f(csgf_dest, len);
	fsl_queue->ci++;

	if (fsl_queue->ci == fsl_queue->n_cq)
		fsl_queue->ci = 0;

	if (flags & RTE_DMA_OP_FLAG_SUBMIT) {
		qdma_writel(fsl_queue->le_cqmr | FSL_QDMA_BCQMR_EI,
			block + FSL_QDMA_BCQMR(fsl_queue->queue_id));
		fsl_queue->stats.submitted++;
	} else {
		fsl_queue->pending++;
	}

	if (fsl_queue->ci)
		return fsl_queue->ci - 1;
	else
		return fsl_queue->n_cq;
}

static int
dpaa_info_get(const struct rte_dma_dev *dev, struct rte_dma_info *dev_info,
	__rte_unused uint32_t info_sz)
{
	struct fsl_qdma_engine *fsl_qdma = dev->data->dev_private;

	dev_info->dev_capa = RTE_DMA_CAPA_MEM_TO_MEM |
		RTE_DMA_CAPA_SILENT | RTE_DMA_CAPA_OPS_COPY;
	dev_info->max_vchans = fsl_qdma->n_queues;
	dev_info->max_desc = QDMA_QUEUE_SIZE;
	dev_info->min_desc = QDMA_QUEUE_SIZE;

	return 0;
}

static int
dpaa_get_channel(struct fsl_qdma_engine *fsl_qdma,
	uint16_t vchan)
{
	int ret;
	struct fsl_qdma_queue *fsl_queue = fsl_qdma->queue[vchan];

	if (fsl_queue->used)
		return 0;

	ret = fsl_qdma_pre_comp_sd_desc(fsl_queue);
	if (ret)
		return ret;

	fsl_queue->used = 1;

	return 0;
}

static int
dpaa_qdma_configure(__rte_unused struct rte_dma_dev *dmadev,
	__rte_unused const struct rte_dma_conf *dev_conf,
	__rte_unused uint32_t conf_sz)
{
	return 0;
}

static int
dpaa_qdma_start(__rte_unused struct rte_dma_dev *dev)
{
	return 0;
}

static int
dpaa_qdma_close(__rte_unused struct rte_dma_dev *dev)
{
	return 0;
}

static int
dpaa_qdma_queue_setup(struct rte_dma_dev *dmadev,
	uint16_t vchan,
	__rte_unused const struct rte_dma_vchan_conf *conf,
	__rte_unused uint32_t conf_sz)
{
	struct fsl_qdma_engine *fsl_qdma = dmadev->data->dev_private;

	return dpaa_get_channel(fsl_qdma, vchan);
}

static int
dpaa_qdma_submit(void *dev_private, uint16_t vchan)
{
	struct fsl_qdma_engine *fsl_qdma = dev_private;
	struct fsl_qdma_queue *fsl_queue = fsl_qdma->queue[vchan];
	void *block = fsl_queue->block_vir;

	while (fsl_queue->pending) {
		qdma_writel(fsl_queue->le_cqmr | FSL_QDMA_BCQMR_EI,
			block + FSL_QDMA_BCQMR(fsl_queue->queue_id));
		fsl_queue->pending--;
		fsl_queue->stats.submitted++;
	}

	return 0;
}

static int
dpaa_qdma_enqueue(void *dev_private, uint16_t vchan,
	rte_iova_t src, rte_iova_t dst,
	uint32_t length, uint64_t flags)
{
	struct fsl_qdma_engine *fsl_qdma = dev_private;
	struct fsl_qdma_queue *fsl_queue = fsl_qdma->queue[vchan];
	int ret;

	ret = fsl_qdma_enqueue_desc(fsl_queue, flags, dst, src, length);

	return ret;
}

static uint16_t
dpaa_qdma_dequeue_status(void *dev_private, uint16_t vchan,
	const uint16_t nb_cpls, uint16_t *last_idx,
	enum rte_dma_status_code *st)
{
	struct fsl_qdma_engine *fsl_qdma = dev_private;
	int ret;
	struct fsl_qdma_queue *fsl_queue = fsl_qdma->queue[vchan];
	void *status = fsl_qdma->status_base;
	int intr;

	ret = fsl_qdma_queue_transfer_complete(fsl_queue,
			nb_cpls, st);
	if (!ret) {
		intr = qdma_readl_be(status + FSL_QDMA_DEDR);
		if (intr) {
#ifdef CONFIG_RTE_DMA_DPAA_ERR_CHK
			DPAA_QDMA_ERR("DMA transaction error! %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECFDW0R);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECFDW0R %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECFDW1R);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECFDW1R %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECFDW2R);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECFDW2R %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECFDW3R);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECFDW3R %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECFQIDR);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECFQIDR %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECBR);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECBR %x\n", intr);
#endif
			qdma_writel_be(0xbf,
				    status + FSL_QDMA_DEDR);
			fsl_queue->stats.errors++;
		}
	}

	fsl_queue->stats.completed += ret;
	if (last_idx) {
		if (unlikely(!fsl_queue->complete))
			*last_idx = fsl_queue->n_cq - 1;
		else
			*last_idx = fsl_queue->complete - 1;
	}

	return ret;
}


static uint16_t
dpaa_qdma_dequeue(void *dev_private,
	uint16_t vchan, const uint16_t nb_cpls,
	uint16_t *last_idx, bool *has_error)
{
	struct fsl_qdma_engine *fsl_qdma = dev_private;
	int ret;
	struct fsl_qdma_queue *fsl_queue = fsl_qdma->queue[vchan];
#ifdef CONFIG_RTE_DMA_DPAA_ERR_CHK
	void *status = fsl_qdma->status_base;
	int intr;
#endif

	*has_error = false;
	ret = fsl_qdma_queue_transfer_complete(fsl_queue,
			nb_cpls, NULL);
#ifdef CONFIG_RTE_DMA_DPAA_ERR_CHK
	if (!ret) {
		intr = qdma_readl_be(status + FSL_QDMA_DEDR);
		if (intr) {
			DPAA_QDMA_ERR("DMA transaction error! %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECFDW0R);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECFDW0R %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECFDW1R);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECFDW1R %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECFDW2R);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECFDW2R %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECFDW3R);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECFDW3R %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECFQIDR);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECFQIDR %x\n", intr);
			intr = qdma_readl(status + FSL_QDMA_DECBR);
			DPAA_QDMA_INFO("reg FSL_QDMA_DECBR %x\n", intr);
			qdma_writel_be(0xbf,
				    status + FSL_QDMA_DEDR);
			intr = qdma_readl(status + FSL_QDMA_DEDR);
			*has_error = true;
			fsl_queue->stats.errors++;
		}
	}
#endif
	fsl_queue->stats.completed += ret;
	if (last_idx) {
		if (unlikely(!fsl_queue->complete))
			*last_idx = fsl_queue->n_cq - 1;
		else
			*last_idx = fsl_queue->complete - 1;
	}

	return ret;
}

static int
dpaa_qdma_stats_get(const struct rte_dma_dev *dmadev,
	uint16_t vchan, struct rte_dma_stats *rte_stats, uint32_t size)
{
	struct fsl_qdma_engine *fsl_qdma = dmadev->data->dev_private;
	struct fsl_qdma_queue *fsl_queue = fsl_qdma->queue[vchan];
	struct rte_dma_stats *stats = &fsl_queue->stats;

	if (size < sizeof(rte_stats))
		return -EINVAL;
	if (!rte_stats)
		return -EINVAL;

	*rte_stats = *stats;

	return 0;
}

static int
dpaa_qdma_stats_reset(struct rte_dma_dev *dmadev, uint16_t vchan)
{
	struct fsl_qdma_engine *fsl_qdma = dmadev->data->dev_private;
	struct fsl_qdma_queue *fsl_queue = fsl_qdma->queue[vchan];

	memset(&fsl_queue->stats, 0, sizeof(struct rte_dma_stats));

	return 0;
}

static uint16_t
dpaa_qdma_burst_capacity(const void *dev_private, uint16_t vchan)
{
	const struct fsl_qdma_engine *fsl_qdma = dev_private;
	struct fsl_qdma_queue *fsl_queue = fsl_qdma->queue[vchan];

	return fsl_queue->n_cq - fsl_queue->pending;
}

static struct rte_dma_dev_ops dpaa_qdma_ops = {
	.dev_info_get		  = dpaa_info_get,
	.dev_configure            = dpaa_qdma_configure,
	.dev_start                = dpaa_qdma_start,
	.dev_close                = dpaa_qdma_close,
	.vchan_setup		  = dpaa_qdma_queue_setup,
	.stats_get		  = dpaa_qdma_stats_get,
	.stats_reset		  = dpaa_qdma_stats_reset,
};

static int
dpaa_qdma_init(struct rte_dma_dev *dmadev)
{
	struct fsl_qdma_engine *fsl_qdma = dmadev->data->dev_private;
	uint64_t phys_addr;
	int ccsr_qdma_fd;
	int regs_size;
	int ret;
	uint32_t i, j, k;

	fsl_qdma->n_queues = QDMA_QUEUES * QDMA_BLOCKS;
	fsl_qdma->num_blocks = QDMA_BLOCKS;
	fsl_qdma->block_offset = QDMA_BLOCK_OFFSET;

	ccsr_qdma_fd = open("/dev/mem", O_RDWR);
	if (unlikely(ccsr_qdma_fd < 0)) {
		DPAA_QDMA_ERR("Can not open /dev/mem for qdma CCSR map");
		return ccsr_qdma_fd;
	}

	regs_size = fsl_qdma->block_offset * fsl_qdma->num_blocks;
	regs_size += (QDMA_CTRL_REGION_SIZE + QDMA_STATUS_REGION_SIZE);
	phys_addr = QDMA_CCSR_BASE;
	fsl_qdma->reg_base = mmap(NULL, regs_size,
		PROT_READ | PROT_WRITE, MAP_SHARED,
		ccsr_qdma_fd, phys_addr);

	close(ccsr_qdma_fd);
	if (fsl_qdma->reg_base == MAP_FAILED) {
		DPAA_QDMA_ERR("Map qdma reg: Phys(0x%lx), size(%d)",
			phys_addr, regs_size);
		return -ENOMEM;
	}

	fsl_qdma->ctrl_base =
		fsl_qdma->reg_base + QDMA_CTRL_REGION_OFFSET;
	fsl_qdma->status_base =
		fsl_qdma->reg_base + QDMA_STATUS_REGION_OFFSET;
	fsl_qdma->block_base =
		fsl_qdma->status_base + QDMA_STATUS_REGION_SIZE;

	fsl_qdma->status = rte_malloc("status queue",
		sizeof(struct fsl_qdma_queue) * QDMA_BLOCKS, 0);
	if (!fsl_qdma->status) {
		ret = -ENOMEM;
		goto err;
	}

	fsl_qdma->queue = rte_malloc("cmd queue",
		sizeof(struct fsl_qdma_queue) * fsl_qdma->n_queues, 0);
	if (!fsl_qdma->queue) {
		rte_free(fsl_qdma->status);
		ret = -ENOMEM;
		goto err;
	}

	k = 0;
	for (i = 0; i < fsl_qdma->num_blocks; i++) {
		fsl_qdma->status[i] =
			fsl_qdma_prep_status_queue(fsl_qdma, i);
		if (!fsl_qdma->status[i]) {
			ret = -ENOMEM;
			goto mem_free;
		}
		j = 0;
		for (j = 0; j < QDMA_QUEUES; j++) {
			fsl_qdma->queue[k] =
				fsl_qdma_alloc_queue_resources(fsl_qdma, j, i);
			if (!fsl_qdma->queue[k]) {
				ret = -ENOMEM;
				goto mem_free;
			}
			k++;
		}
	}

	ret = fsl_qdma_reg_init(fsl_qdma);
	if (ret) {
		DPAA_QDMA_ERR("Can't Initialize the qDMA engine.\n");
		rte_free(fsl_qdma->status);
		goto mem_free;
	}

	return 0;

mem_free:
	for (j = 0; j < k; j++)
		fsl_qdma_free_queue_resources(fsl_qdma->queue[j]);

	for (j = 0; j < i; j++)
		fsl_qdma_free_status_queue(fsl_qdma->status[j]);

	if (fsl_qdma->status)
		rte_free(fsl_qdma->status);
err:
	if (fsl_qdma->queue)
		rte_free(fsl_qdma->queue);
	munmap(fsl_qdma->ctrl_base, regs_size);

	return ret;
}

static int
dpaa_qdma_probe(__rte_unused struct rte_dpaa_driver *dpaa_drv,
		struct rte_dpaa_device *dpaa_dev)
{
	struct rte_dma_dev *dmadev;
	int ret;

	dmadev = rte_dma_pmd_allocate(dpaa_dev->device.name,
				      rte_socket_id(),
				      sizeof(struct fsl_qdma_engine));
	if (!dmadev) {
		DPAA_QDMA_ERR("Unable to allocate dmadevice");
		return -EINVAL;
	}

	dpaa_dev->dmadev = dmadev;
	dmadev->dev_ops = &dpaa_qdma_ops;
	dmadev->device = &dpaa_dev->device;
	dmadev->fp_obj->dev_private = dmadev->data->dev_private;
	dmadev->fp_obj->copy = dpaa_qdma_enqueue;
	dmadev->fp_obj->submit = dpaa_qdma_submit;
	dmadev->fp_obj->completed = dpaa_qdma_dequeue;
	dmadev->fp_obj->completed_status = dpaa_qdma_dequeue_status;
	dmadev->fp_obj->burst_capacity = dpaa_qdma_burst_capacity;

	/* Invoke PMD device initialization function */
	ret = dpaa_qdma_init(dmadev);
	if (ret) {
		(void)rte_dma_pmd_release(dpaa_dev->device.name);
		return ret;
	}

	dmadev->state = RTE_DMA_DEV_READY;
	return 0;
}

static int
dpaa_qdma_remove(struct rte_dpaa_device *dpaa_dev)
{
	struct rte_dma_dev *dmadev = dpaa_dev->dmadev;
	struct fsl_qdma_engine *fsl_qdma = dmadev->data->dev_private;
	uint32_t i;

	for (i = 0; i < fsl_qdma->num_blocks; i++)
		fsl_qdma_free_status_queue(fsl_qdma->status[i]);

	for (i = 0; i < fsl_qdma->num_blocks * QDMA_QUEUES; i++)
		fsl_qdma_free_queue_resources(fsl_qdma->queue[i]);

	rte_free(fsl_qdma->queue);
	rte_free(fsl_qdma->status);

	(void)rte_dma_pmd_release(dpaa_dev->device.name);

	return 0;
}

static struct rte_dpaa_driver rte_dpaa_qdma_pmd;

static struct rte_dpaa_driver rte_dpaa_qdma_pmd = {
	.drv_type = FSL_DPAA_QDMA,
	.probe = dpaa_qdma_probe,
	.remove = dpaa_qdma_remove,
};

RTE_PMD_REGISTER_DPAA(dpaa_qdma, rte_dpaa_qdma_pmd);
RTE_LOG_REGISTER_DEFAULT(dpaa_qdma_logtype, INFO);
