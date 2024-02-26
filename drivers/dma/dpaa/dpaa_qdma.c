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

static inline u64
qdma_ccdf_get_queue(const struct fsl_qdma_format *ccdf)
{
	return ccdf->cfg8b_w1 & 0xff;
}

static inline int
qdma_ccdf_get_offset(const struct fsl_qdma_format *ccdf)
{
	return (rte_le_to_cpu_32(ccdf->cfg) & QDMA_CCDF_MASK)
		>> QDMA_CCDF_OFFSET;
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

static inline int
ilog2(int x)
{
	int log = 0;

	x >>= 1;

	while (x) {
		log++;
		x >>= 1;
	}
	return log;
}

static u32
qdma_readl(void *addr)
{
	return QDMA_IN(addr);
}

static void
qdma_writel(u32 val, void *addr)
{
	QDMA_OUT(addr, val);
}

static u32
qdma_readl_be(void *addr)
{
	return QDMA_IN_BE(addr);
}

static void
qdma_writel_be(u32 val, void *addr)
{
	QDMA_OUT_BE(addr, val);
}

static void
*dma_pool_alloc(int size, int aligned, dma_addr_t *phy_addr)
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
fsl_qdma_pre_request_enqueue_comp_sd_desc(
					struct fsl_qdma_queue *queue,
					int size, int aligned)
{
	struct fsl_qdma_sdf *sdf;
	struct fsl_qdma_ddf *ddf;
	struct fsl_qdma_format *csgf_desc;
	struct fsl_qdma_format *ccdf;
	int i, j;
	struct fsl_qdma_format *head;

	head = queue->virt_head;

	for (i = 0; i < (int)(queue->n_cq); i++) {
		dma_addr_t bus_addr = 0, desc_bus_addr = 0;

		queue->virt_addr[i] =
		dma_pool_alloc(size, aligned, &bus_addr);
		if (!queue->virt_addr[i])
			goto fail;

		queue->desc_virt_addr[i] =
		dma_pool_alloc(size, aligned, &desc_bus_addr);
		if (!queue->desc_virt_addr[i]) {
			rte_free(queue->virt_addr[i]);
			goto fail;
		}

		memset(queue->virt_addr[i], 0, FSL_QDMA_COMMAND_BUFFER_SIZE);
		memset(queue->desc_virt_addr[i], 0,
		       FSL_QDMA_DESCRIPTOR_BUFFER_SIZE);

		csgf_desc = (struct fsl_qdma_format *)queue->virt_addr[i] +
			    QDMA_DESC_OFF;
		sdf = (struct fsl_qdma_sdf *)queue->desc_virt_addr[i];
		ddf = (struct fsl_qdma_ddf *)sdf + QDMA_DESC_OFF;
		/* Compound Command Descriptor(Frame List Table) */
		qdma_desc_addr_set64(csgf_desc, desc_bus_addr);

		/* It must be 32 as Compound S/G Descriptor */
		qdma_csgf_set_len(csgf_desc, 32);
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

		ccdf = (struct fsl_qdma_format *)queue->virt_head;
		qdma_desc_addr_set64(ccdf, bus_addr + 16);
		qdma_ccdf_set_format(ccdf, qdma_ccdf_get_offset(queue->virt_addr[i]));
		qdma_ccdf_set_ser(ccdf, qdma_ccdf_get_status(queue->virt_addr[i]));
		queue->virt_head++;
	}
	queue->virt_head = head;
	queue->ci = 0;

	return 0;

fail:
	for (j = 0; j < i; j++) {
		rte_free(queue->virt_addr[j]);
		rte_free(queue->desc_virt_addr[j]);
	}

	return -ENOMEM;
}

static struct fsl_qdma_queue
*fsl_qdma_alloc_queue_resources(struct fsl_qdma_engine *fsl_qdma, int k, int b)
{
	struct fsl_qdma_queue *queue_temp;

	queue_temp = rte_zmalloc("qdma: queue head", sizeof(*queue_temp), 0);
	if (!queue_temp) {
		printf("no memory to allocate queues\n");
		return NULL;
	}

	queue_temp->cq =
	dma_pool_alloc(sizeof(struct fsl_qdma_format) *
		       QDMA_QUEUE_SIZE,
		       sizeof(struct fsl_qdma_format) *
		       QDMA_QUEUE_SIZE, &queue_temp->bus_addr);

	if (!queue_temp->cq) {
		rte_free(queue_temp);
		return NULL;
	}

	memset(queue_temp->cq, 0x0, QDMA_QUEUE_SIZE *
	       sizeof(struct fsl_qdma_format));

	queue_temp->queue_base = fsl_qdma->block_base +
		FSL_QDMA_BLOCK_BASE_OFFSET(fsl_qdma, b);
	queue_temp->n_cq = QDMA_QUEUE_SIZE;
	queue_temp->id = k;
	queue_temp->pending = 0;
	queue_temp->virt_head = queue_temp->cq;
	queue_temp->virt_addr = rte_malloc("queu virt addr",
			sizeof(void *) * QDMA_QUEUE_SIZE, 0);
	if (!queue_temp->virt_addr) {
		rte_free(queue_temp->cq);
		rte_free(queue_temp);
		return NULL;
	}
	queue_temp->desc_virt_addr = rte_malloc("queu desc virt addr",
			sizeof(void *) * QDMA_QUEUE_SIZE, 0);
	if (!queue_temp->desc_virt_addr) {
		rte_free(queue_temp->virt_addr);
		rte_free(queue_temp->cq);
		rte_free(queue_temp);
		return NULL;
	}
	queue_temp->stats = (struct rte_dma_stats){0};

	return queue_temp;
}

static void
fsl_qdma_free_queue_resources(struct fsl_qdma_queue *queue)
{
	rte_free(queue->desc_virt_addr);
	rte_free(queue->virt_addr);
	rte_free(queue->cq);
	rte_free(queue);
}

static struct
fsl_qdma_queue *fsl_qdma_prep_status_queue(struct fsl_qdma_engine *fsl_qdma,
					   u32 id)
{
	struct fsl_qdma_queue *status_head;
	unsigned int status_size;

	status_size = QDMA_STATUS_SIZE;

	status_head = rte_zmalloc("qdma: status head", sizeof(*status_head), 0);
	if (!status_head)
		return NULL;

	/*
	 * Buffer for queue command
	 */
	status_head->cq = dma_pool_alloc(sizeof(struct fsl_qdma_format) *
					 status_size,
					 sizeof(struct fsl_qdma_format) *
					 status_size,
					 &status_head->bus_addr);

	if (!status_head->cq) {
		rte_free(status_head);
		return NULL;
	}

	memset(status_head->cq, 0x0, status_size *
	       sizeof(struct fsl_qdma_format));
	status_head->n_cq = status_size;
	status_head->virt_head = status_head->cq;
	status_head->queue_base = fsl_qdma->block_base +
		FSL_QDMA_BLOCK_BASE_OFFSET(fsl_qdma,id);

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
	void *ctrl = fsl_qdma->ctrl_base;
	void *block;
	int i, count = RETRIES;
	unsigned int j;
	u32 reg;

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
fsl_qdma_queue_transfer_complete(void *block, const uint16_t nb_cpls,
				 enum rte_dma_status_code *status)
{
	u32 reg;
	int count = 0;

	while (count < nb_cpls) {
		reg = qdma_readl_be(block + FSL_QDMA_BSQSR);
		if (reg & FSL_QDMA_BSQSR_QE_BE)
			return count;

		qdma_writel_be(FSL_QDMA_BSQMR_DI, block + FSL_QDMA_BSQMR);
		if (status != NULL)
			status[count] = RTE_DMA_STATUS_SUCCESSFUL;

		count++;

	}
	return count;
}

static int
fsl_qdma_reg_init(struct fsl_qdma_engine *fsl_qdma)
{
	struct fsl_qdma_queue *temp;
	void *ctrl = fsl_qdma->ctrl_base;
	void *block;
	u32 i, j;
	u32 reg;
	int ret, val;

	/* Try to halt the qDMA engine first. */
	ret = fsl_qdma_halt(fsl_qdma);
	if (ret) {
		DPAA_QDMA_ERR("DMA halt failed!");
		return ret;
	}

	int k = 0;
	for (j = 0; j < fsl_qdma->num_blocks; j++) {
		block = fsl_qdma->block_base +
			FSL_QDMA_BLOCK_BASE_OFFSET(fsl_qdma, j);
		k = 0;
		for (i = (j * QDMA_QUEUES); i < ((j * QDMA_QUEUES) + QDMA_QUEUES); i++) {
			temp = fsl_qdma->queue[i];
			/*
			 * Initialize Command Queue registers to
			 * point to the first
			 * command descriptor in memory.
			 * Dequeue Pointer Address Registers
			 * Enqueue Pointer Address Registers
			 */

			qdma_writel(lower_32_bits(temp->bus_addr),
				    block + FSL_QDMA_BCQDPA_SADDR(k));
			qdma_writel(upper_32_bits(temp->bus_addr),
				    block + FSL_QDMA_BCQEDPA_SADDR(k));
			qdma_writel(lower_32_bits(temp->bus_addr),
				    block + FSL_QDMA_BCQEPA_SADDR(k));
			qdma_writel(upper_32_bits(temp->bus_addr),
				    block + FSL_QDMA_BCQEEPA_SADDR(k));

			/* Initialize the queue mode. */
			reg = FSL_QDMA_BCQMR_EN;
			reg |= FSL_QDMA_BCQMR_CD_THLD(ilog2(temp->n_cq) - 4);
			reg |= FSL_QDMA_BCQMR_CQ_SIZE(ilog2(temp->n_cq) - 6);
			qdma_writel(reg, block + FSL_QDMA_BCQMR(k));
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

		qdma_writel(
			    upper_32_bits(fsl_qdma->status[j]->bus_addr),
			    block + FSL_QDMA_SQEEPAR);
		qdma_writel(
			    lower_32_bits(fsl_qdma->status[j]->bus_addr),
			    block + FSL_QDMA_SQEPAR);
		qdma_writel(
			    upper_32_bits(fsl_qdma->status[j]->bus_addr),
			    block + FSL_QDMA_SQEDPAR);
		qdma_writel(
			    lower_32_bits(fsl_qdma->status[j]->bus_addr),
			    block + FSL_QDMA_SQDPAR);
		/* Desiable status queue interrupt. */

		qdma_writel(0x0, block + FSL_QDMA_BCQIER(0));
		qdma_writel(0x0, block + FSL_QDMA_BSQICR);
		qdma_writel(0x0, block + FSL_QDMA_CQIER);

		/* Initialize the status queue mode. */
		reg = FSL_QDMA_BSQMR_EN;
		val = ilog2(fsl_qdma->status[j]->n_cq) - 6;
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
	void *block = fsl_queue->queue_base;
	struct fsl_qdma_format *csgf_src, *csgf_dest;
#ifdef RTE_DMA_DPAA_ERRATA_ERR050757
	struct fsl_qdma_sdf *sdf;
	u32 cfg = 0;
#endif

#ifdef CONFIG_RTE_DMA_DPAA_ERR_CHK
	u32 reg;

	/* retrieve and store the register value in big endian
	 * to avoid bits swap
	 */
	reg = qdma_readl_be(block +
			 FSL_QDMA_BCQSR(fsl_queue->id));
	if (reg & (FSL_QDMA_BCQSR_QF_XOFF_BE)) {
		DPAA_QDMA_ERR("QDMA Engine is busy\n");
		return -1;
	}
#else
	/* check whether critical watermark level reached,
	 * below check is valid for only single queue per block
	 */
	if ((fsl_queue->stats.submitted - fsl_queue->stats.completed)
			>= QDMA_QUEUE_CR_WM) {
		DPAA_QDMA_DEBUG("Queue is full, try dequeue first\n");
		return -1;
	}
#endif
	if (unlikely(fsl_queue->pending == fsl_queue->n_cq)) {
		DPAA_QDMA_DEBUG("Queue is full, try dma submit first\n");
		return -1;
	}

	csgf_src = (struct fsl_qdma_format *)fsl_queue->virt_addr[fsl_queue->ci] +
		   QDMA_SGF_SRC_OFF;
	csgf_dest = (struct fsl_qdma_format *)fsl_queue->virt_addr[fsl_queue->ci] +
		    QDMA_SGF_DST_OFF;
#ifdef RTE_DMA_DPAA_ERRATA_ERR050757
	sdf = (struct fsl_qdma_sdf *)fsl_queue->desc_virt_addr[fsl_queue->ci];
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
		qdma_writel_be(FSL_QDMA_BCQMR_EI,
			       block + FSL_QDMA_BCQMR(fsl_queue->id));
		fsl_queue->stats.submitted++;
	} else {
		fsl_queue->pending++;
	}
	return 0;
}

static int
dpaa_info_get(const struct rte_dma_dev *dev, struct rte_dma_info *dev_info,
	      uint32_t info_sz)
{
#define DPAADMA_MAX_DESC        64
#define DPAADMA_MIN_DESC        64

	RTE_SET_USED(dev);
	RTE_SET_USED(info_sz);

	dev_info->dev_capa = RTE_DMA_CAPA_MEM_TO_MEM |
			     RTE_DMA_CAPA_MEM_TO_DEV |
			     RTE_DMA_CAPA_DEV_TO_DEV |
			     RTE_DMA_CAPA_DEV_TO_MEM |
			     RTE_DMA_CAPA_SILENT |
			     RTE_DMA_CAPA_OPS_COPY;
	dev_info->max_vchans = 4;
	dev_info->max_desc = DPAADMA_MAX_DESC;
	dev_info->min_desc = DPAADMA_MIN_DESC;

	return 0;
}

static int
dpaa_get_channel(struct fsl_qdma_engine *fsl_qdma,  uint16_t vchan)
{
	u32 i;
	int ret;
	struct fsl_qdma_queue *fsl_queue;

	if (fsl_qdma->free_block_id == QDMA_BLOCKS) {
		DPAA_QDMA_ERR("Maximum 4 queues can be configured\n");
		return -1;
	}

	i = fsl_qdma->free_block_id * QDMA_QUEUES;

	fsl_queue = fsl_qdma->queue[i];
	ret = fsl_qdma_pre_request_enqueue_comp_sd_desc(fsl_queue,
			FSL_QDMA_COMMAND_BUFFER_SIZE, 64);
	if (ret)
		return ret;

	fsl_qdma->vchan_map[vchan] = i;
	fsl_qdma->free_block_id++;
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
	struct fsl_qdma_engine *fsl_qdma = (struct fsl_qdma_engine *)dev_private;
	struct fsl_qdma_queue *fsl_queue =
		fsl_qdma->queue[fsl_qdma->vchan_map[vchan]];
	void *block = fsl_queue->queue_base;

	while (fsl_queue->pending) {
		qdma_writel_be(FSL_QDMA_BCQMR_EI, block + FSL_QDMA_BCQMR(fsl_queue->id));
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
	struct fsl_qdma_engine *fsl_qdma = (struct fsl_qdma_engine *)dev_private;
	struct fsl_qdma_queue *fsl_queue =
		fsl_qdma->queue[fsl_qdma->vchan_map[vchan]];
	int ret, idx;

	idx = (uint16_t)(fsl_queue->stats.submitted + fsl_queue->pending);

	ret = fsl_qdma_enqueue_desc(fsl_queue, flags, (dma_addr_t)dst, (dma_addr_t)src, length);
	if (ret < 0)
		return ret;

	return idx;
}

static uint16_t
dpaa_qdma_dequeue_status(void *dev_private, uint16_t vchan,
			 const uint16_t nb_cpls, uint16_t *last_idx,
			 enum rte_dma_status_code *st)
{
	struct fsl_qdma_engine *fsl_qdma = (struct fsl_qdma_engine *)dev_private;
	int ret;
	struct fsl_qdma_queue *fsl_queue =
		fsl_qdma->queue[fsl_qdma->vchan_map[vchan]];
	void *status = fsl_qdma->status_base;
	int intr;

	ret = fsl_qdma_queue_transfer_complete(fsl_queue->queue_base,
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
	if (last_idx != NULL)
		*last_idx = (uint16_t)(fsl_queue->stats.completed - 1);

	return ret;
}


static uint16_t
dpaa_qdma_dequeue(void *dev_private,
		  uint16_t vchan, const uint16_t nb_cpls,
		  uint16_t *last_idx, bool *has_error)
{
	struct fsl_qdma_engine *fsl_qdma = (struct fsl_qdma_engine *)dev_private;
	int ret;
	struct fsl_qdma_queue *fsl_queue =
		fsl_qdma->queue[fsl_qdma->vchan_map[vchan]];
#ifdef CONFIG_RTE_DMA_DPAA_ERR_CHK
	void *status = fsl_qdma->status_base;
	int intr;
#endif

	*has_error = false;
	ret = fsl_qdma_queue_transfer_complete(fsl_queue->queue_base,
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
	if (last_idx != NULL)
		*last_idx = (uint16_t)(fsl_queue->stats.completed - 1);
	return ret;
}

static int
dpaa_qdma_stats_get(const struct rte_dma_dev *dmadev, uint16_t vchan,
		    struct rte_dma_stats *rte_stats, uint32_t size)
{
	struct fsl_qdma_engine *fsl_qdma = dmadev->data->dev_private;
	struct fsl_qdma_queue *fsl_queue =
		fsl_qdma->queue[fsl_qdma->vchan_map[vchan]];
	struct rte_dma_stats *stats = &fsl_queue->stats;

	if (size < sizeof(rte_stats))
		return -EINVAL;
	if (rte_stats == NULL)
		return -EINVAL;

	*rte_stats = *stats;

	return 0;
}

static int
dpaa_qdma_stats_reset(struct rte_dma_dev *dmadev, uint16_t vchan)
{
	struct fsl_qdma_engine *fsl_qdma = dmadev->data->dev_private;
	struct fsl_qdma_queue *fsl_queue =
		fsl_qdma->queue[fsl_qdma->vchan_map[vchan]];

	fsl_queue->stats = (struct rte_dma_stats){0};

	return 0;
}

static uint16_t
dpaa_qdma_burst_capacity(const void *dev_private, uint16_t vchan)
{
	const struct fsl_qdma_engine *fsl_qdma  = dev_private;
	struct fsl_qdma_queue *fsl_queue =
		fsl_qdma->queue[fsl_qdma->vchan_map[vchan]];

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
	u32 i, k = 0;
	int j;

	fsl_qdma->n_queues = QDMA_QUEUES * QDMA_BLOCKS;
	fsl_qdma->num_blocks = QDMA_BLOCKS;
	fsl_qdma->block_offset = QDMA_BLOCK_OFFSET;

	ccsr_qdma_fd = open("/dev/mem", O_RDWR);
	if (unlikely(ccsr_qdma_fd < 0)) {
		DPAA_QDMA_ERR("Can not open /dev/mem for qdma CCSR map");
		return -1;
	}

	regs_size = fsl_qdma->block_offset * (fsl_qdma->num_blocks + 2);
	phys_addr = QDMA_CCSR_BASE;
	fsl_qdma->ctrl_base = mmap(NULL, regs_size, PROT_READ |
					 PROT_WRITE, MAP_SHARED,
					 ccsr_qdma_fd, phys_addr);

	close(ccsr_qdma_fd);
	if (fsl_qdma->ctrl_base == MAP_FAILED) {
		DPAA_QDMA_ERR("Can not map CCSR base qdma: Phys: %08" PRIx64
		       "size %d\n", phys_addr, regs_size);
		return -1;
	}

	fsl_qdma->status_base = fsl_qdma->ctrl_base + QDMA_BLOCK_OFFSET;
	fsl_qdma->block_base = fsl_qdma->status_base + QDMA_BLOCK_OFFSET;

	fsl_qdma->status = rte_malloc("status queue", sizeof(struct fsl_qdma_queue) * 4, 0);
	if (!fsl_qdma->status)
		goto err;

	fsl_qdma->queue = rte_malloc("cmd queue", sizeof(struct fsl_qdma_queue) * 32, 0);
	if (!fsl_qdma->queue) {
		rte_free(fsl_qdma->status);
		goto err;
	}

	for (i = 0; i < fsl_qdma->num_blocks; i++) {
		fsl_qdma->status[i] = fsl_qdma_prep_status_queue(fsl_qdma, i);
		if (!fsl_qdma->status[i])
			goto mem_free;
		j = 0;
		for (k = (i * QDMA_QUEUES); k < ((i * QDMA_QUEUES) + QDMA_QUEUES); k++) {
			fsl_qdma->queue[k] = fsl_qdma_alloc_queue_resources(fsl_qdma, j, i);
			if (!fsl_qdma->queue[k])
				goto mem_free;
			j++;
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
	for (i = 0; i < fsl_qdma->num_blocks; i++) {
		for (k = (i * QDMA_QUEUES); k < ((i * QDMA_QUEUES) + QDMA_QUEUES); k++)
			fsl_qdma_free_queue_resources(fsl_qdma->queue[k]);
		fsl_qdma_free_status_queue(fsl_qdma->status[i]);
	}
	rte_free(fsl_qdma->status);
err:
	rte_free(fsl_qdma->queue);
	munmap(fsl_qdma->ctrl_base, regs_size);

	return -1;
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
	uint32_t i, k;

	for (i = 0; i < fsl_qdma->num_blocks; i++) {
		for (k = (i * QDMA_QUEUES); k < ((i * QDMA_QUEUES) + QDMA_QUEUES); k++)
			fsl_qdma_free_queue_resources(fsl_qdma->queue[k]);
		fsl_qdma_free_status_queue(fsl_qdma->status[i]);
	}

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
