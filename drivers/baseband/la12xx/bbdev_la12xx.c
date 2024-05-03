/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021,2023 NXP
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <dirent.h>
#include <math.h>

#include <rte_common.h>
#include <bus_vdev_driver.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_kvargs.h>
#include <rte_hexdump.h>
#include <rte_io.h>

#include <rte_bbdev.h>
#include <rte_bbuf.h>
#include <rte_bbdev_pmd.h>
#include <rte_pmd_bbdev_la12xx.h>

#include <gul_pci_def.h>
#include <geul_bbdev_ipc.h>
#include <geul_ipc_um.h>
#include <gul_host_if.h>
#include <geul_ipc.h>

#include "bbdev_la12xx.h"
#include "bbdev_la12xx_pmd_logs.h"
#include "bbdev_la12xx_feca_param.h"
#include "bbdev_la12xx_wdog.h"

#define DRIVER_NAME baseband_la12xx

/*  Initialisation params structure that can be used by LA12xx BBDEV driver */
struct bbdev_la12xx_params {
	int8_t modem_id; /*< LA12xx modem instance id */
};

#ifdef RTE_LA12XX_SOCKET
struct la12xx_meta {
	int socket_id;
	rte_iova_t iova;
};
#endif

int bbdev_socket_id;

#define BBDEV_LA12XX_VDEV_MODEM_ID_ARG	"modem"
#define LA12XX_MAX_MODEM	4
#define LA12XX_MAX_CORES	6
#define LA12XX_MAX_VSPA		8

#define BBDEV_LA12XX_LDPC_ENC_CORE	0
#define BBDEV_LA12XX_LDPC_DEC_CORE	1
#define BBDEV_LA12XX_POLAR_ENC_CORE	2
#define BBDEV_LA12XX_POLAR_DEC_CORE	3
#define BBDEV_LA12XX_RAW_CORE		0

#define VSPA_MAILBOX_DUMMY_WRITE	0x1234

/* Maximum allowed requested bytes */
#define SD_MAX_REQ_BYTES		0xFF80
#define SD_LLRS_PER_RE_MASK		0x0000FFFF

/* BE Swapped Shared Decode (SD) Job type */
#define FECA_JOB_SD_BE		0x1000000 /* BE for 1 */
/* BE Swapped Shared Encode (SE) Job type */
#define FECA_JOB_SE_BE		0x3000000 /* BE for 3 */
/* BE Swapped Shared Encode Job Type used in DCM mode */
#define FECA_JOB_SE_DCM_BE	0x7000000 /* BE for 7 */
/* BE Swapped Shared Decode Job Type used in DCM mode */
#define FECA_JOB_SD_DCM_BE	0x8000000 /* BE for 8 */

static const char * const bbdev_la12xx_valid_params[] = {
	BBDEV_LA12XX_VDEV_MODEM_ID_ARG,
};

static inline char *
get_data_ptr(struct rte_bbdev_op_data *op_data)
{
	if (op_data->is_direct_mem)
	       return op_data->mem;

	return rte_bbuf_mtod((struct rte_bbuf *)op_data->bdata, char *);
}

/* la12xx BBDev logging ID */
int bbdev_la12xx_logtype;

static const struct rte_bbdev_op_cap bbdev_capabilities[] = {
	{
		.type   = RTE_BBDEV_OP_LDPC_ENC,
		.cap.ldpc_enc = {
			.capability_flags =
					RTE_BBDEV_LDPC_RATE_MATCH |
					RTE_BBDEV_LDPC_CRC_24A_ATTACH |
					RTE_BBDEV_LDPC_CRC_24B_ATTACH |
					RTE_BBDEV_LDPC_ENC_SCRAMBLING_OFFLOAD,
			.num_buffers_src =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			.num_buffers_dst =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
		}
	},
	{
		.type   = RTE_BBDEV_OP_LDPC_DEC,
		.cap.ldpc_dec = {
			.capability_flags =
					RTE_BBDEV_LDPC_CRC_TYPE_24A_CHECK |
					RTE_BBDEV_LDPC_CRC_TYPE_24B_CHECK |
					RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP |
					RTE_BBDEV_LDPC_DEC_LLR_CONV_OFFLOAD |
					RTE_BBDEV_LDPC_DEC_SCRAMBLING_OFFLOAD |
					RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE |
					RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE |
					RTE_BBDEV_LDPC_COMPACT_HARQ |
					RTE_BBDEV_LDPC_PARTIAL_COMPACT_HARQ,
			.num_buffers_src =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			.num_buffers_hard_out =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
			.llr_size = 8,
			.llr_decimals = 1,
		}
	},
	{
		.type   = RTE_BBDEV_OP_POLAR_DEC,
	},
	{
		.type   = RTE_BBDEV_OP_POLAR_ENC,
	},
	{
		.type   = RTE_BBDEV_OP_RAW,
	},
	{
		.type   = RTE_BBDEV_OP_LA12XX_VSPA,
	},
	RTE_BBDEV_END_OF_CAPABILITIES_LIST()
};

static struct rte_bbdev_queue_conf default_queue_conf;

/* Get device info */
static void
la12xx_info_get(struct rte_bbdev *dev,
		struct rte_bbdev_driver_info *dev_info)
{
	struct bbdev_la12xx_private *priv = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	dev_info->driver_name = RTE_STR(DRIVER_NAME);
	dev_info->max_num_queues = priv->max_queues;
	dev_info->queue_size_lim = default_queue_conf.queue_size;
	dev_info->hardware_accelerated = true;
	dev_info->max_dl_queue_priority = 0;
	dev_info->max_ul_queue_priority = 0;
	dev_info->data_endianness = RTE_BIG_ENDIAN;
	dev_info->default_queue_conf = default_queue_conf;
	dev_info->capabilities = bbdev_capabilities;
	dev_info->cpu_flag_reqs = NULL;
	dev_info->min_alignment = 64;

	dev_info->num_queues[RTE_BBDEV_OP_NONE] = 0;
	dev_info->num_queues[RTE_BBDEV_OP_TURBO_DEC] = 0;
	dev_info->num_queues[RTE_BBDEV_OP_TURBO_ENC] = 0;
	dev_info->num_queues[RTE_BBDEV_OP_LDPC_DEC] = LA12XX_MAX_QUEUES / 2;
	dev_info->num_queues[RTE_BBDEV_OP_LDPC_ENC] = LA12XX_MAX_QUEUES / 2;
	dev_info->queue_priority[RTE_BBDEV_OP_LDPC_DEC] = 1;
	dev_info->queue_priority[RTE_BBDEV_OP_LDPC_ENC] = 1;
	rte_bbdev_log_debug("got device info from %u", dev->data->dev_id);
}

/* Release queue */
static int
la12xx_queue_release(struct rte_bbdev *dev, uint16_t q_id)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(q_id);

	PMD_INIT_FUNC_TRACE();

	return 0;
}

#ifdef RTE_LA12XX_SOCKET
static int
check_memseg(__rte_unused const struct rte_memseg_list *msl,
	     const struct rte_memseg *ms, void *arg)
{
	struct la12xx_meta *meta = arg;

	if (ms->iova == meta->iova) {
		if (ms->socket_id != meta->socket_id)
			rte_bbdev_dp_log(WARNING, "Mapping non BBDEV socket id"
			       " %d memory to PCIe address space (BBDEV socket"
			       " id = %d)\n",
			       ms->socket_id, meta->socket_id);
	}

	return 0;
}
#endif

static inline int
map_second_hugepage_addr(ipc_userspace_t *ipc_priv, void *addr)
{
	ipc_pci_map_query_t pci_map_query;
	struct rte_memseg *mseg;
	uint64_t addr_diff;
	uint32_t size;
	int ret;

	addr_diff = ((uint64_t) (addr) -
		((uint64_t)ipc_priv->hugepg_start[0].host_vaddr));

	if (addr_diff < ipc_priv->hugepg_start[0].size) {
		rte_bbdev_log(INFO,
			"addr: %p already mapped at index 0", addr);
		return 0;
	}

	addr_diff = ((uint64_t) (addr) -
		((uint64_t)ipc_priv->hugepg_start[1].host_vaddr));

	if (addr_diff < ipc_priv->hugepg_start[1].size) {
		rte_bbdev_log(INFO,
			"addr: %p already mapped at index 1", addr);
		return 0;
	}

	rte_bbdev_log(INFO,
		"Creating hugepage mapping for second hugepage");

	ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_QUERY_PCI_MAP,
		    &pci_map_query);
	if (ret) {
		rte_bbdev_log(ERR,
			"IOCTL_GUL_IPC_QUERY_PCI_MAP ioctl failed");
		return -1;
	}

	if (!pci_map_query.mem_avail) {
		rte_bbdev_log(ERR,
			"No memory available for mapping");
		return -1;
	}

	mseg = rte_mem_virt2memseg(addr, NULL);

	size = RTE_MIN(pci_map_query.mem_avail, mseg->len);

#ifdef RTE_LA12XX_SOCKET
	struct la12xx_meta meta;

	meta.iova = mseg->iova;
	meta.socket_id = RTE_LA12XX_SOCKET_ID;
	rte_memseg_walk(check_memseg, &meta);
#endif
	/* Map last portion of the hugepage memory as in DPDK memory
	 * allocation from hugepage starts from the end.
	 */
	ipc_priv->sys_map.hugepg_start.host_phys =
			rte_mem_virt2phy(mseg->addr) + mseg->len - size;
	ipc_priv->sys_map.hugepg_start.size = size;

	ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_GET_PCI_MAP,
		    &ipc_priv->sys_map.hugepg_start);
	if (ret) {
		rte_bbdev_log(INFO,
			"IOCTL_GUL_IPC_GET_PCI_MAP ioctl failed");
		return -1;
	}

	ipc_priv->hugepg_start[1].host_phys =
			ipc_priv->sys_map.hugepg_start.host_phys;
	ipc_priv->hugepg_start[1].host_vaddr =
			(void *)((uint64_t)(mseg->addr) + mseg->len - size);
	ipc_priv->hugepg_start[1].modem_phys =
			ipc_priv->sys_map.hugepg_start.modem_phys;
	ipc_priv->hugepg_start[1].size =
			ipc_priv->sys_map.hugepg_start.size;

	rte_bbdev_log(INFO, "2nd hugepage Map %lx %p %zx\n",
				  mseg->iova,
				  mseg->addr, mseg->len);
	return size;
}


static inline uint32_t
get_l1_pcie_addr(ipc_userspace_t *ipc_priv, void *addr)
{
	uint64_t addr_diff;
	int mapped_size;

	addr_diff = ((uint64_t) (addr) -
		((uint64_t)ipc_priv->hugepg_start[0].host_vaddr));

	if (addr_diff < ipc_priv->hugepg_start[0].size)
		return (uint32_t)(ipc_priv->hugepg_start[0].modem_phys +
				  addr_diff);

	/* Create mapping for second hugepage if not created */
	if (!ipc_priv->hugepg_start[1].host_vaddr) {
		mapped_size = map_second_hugepage_addr(ipc_priv, addr);
		if (mapped_size < 0) {
			rte_bbdev_log(ERR,
				"Mapping of hugepage address failed");
			return 0;
		}
	}

	addr_diff = ((uint64_t) (addr) -
		((uint64_t)ipc_priv->hugepg_start[1].host_vaddr));

	if (addr_diff < ipc_priv->hugepg_start[1].size) {
		return (uint32_t)(ipc_priv->hugepg_start[1].modem_phys +
				  addr_diff);
	} else {
		rte_bbdev_log(ERR, "Address not mapped over PCI %lx",
				     (uint64_t) (addr));
		return 0;
	}
}

int
rte_pmd_get_la12xx_mapaddr(uint16_t dev_id, void *addr)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;

	return get_l1_pcie_addr(ipc_priv, addr);
}

#define MODEM_P2V(A) \
	((uint64_t) ((unsigned long) (A) \
		+ (unsigned long)(ipc_priv->peb_start.host_vaddr)))

#pragma GCC push_options
#pragma GCC optimize ("O1")

static int
la12xx_e200_queue_setup(struct rte_bbdev *dev,
		struct bbdev_la12xx_q_priv *q_priv,
		const struct rte_bbdev_queue_conf *queue_conf)
{
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	uint32_t msg_size = sizeof(struct bbdev_ipc_raw_op_t);
	struct gul_hif *mhif;
	ipc_metadata_t *ipc_md;
	ipc_ch_t *ch;
	int instance_id = 0;
	void *vaddr;
	uint32_t i;
	void *cd_crc_stat;
	feca_job_t *feca_jobs;

	PMD_INIT_FUNC_TRACE();

	rte_bbdev_log_debug("setting up queue %d", q_priv->q_id);

	if (q_priv->q_id < priv->num_valid_queues) {
		q_priv->host_pi = 0;
		q_priv->host_ci = 0;
		q_priv->host_params->pi = 0;
		q_priv->host_params->ci = 0;

		rte_bbdev_log(WARNING,
			"Queue [%d] already configured, not configuring again",
			q_priv->q_id);

		goto config_modem_queue;
	}

	for (i = 0; i < q_priv->queue_size; i++) {
		vaddr = rte_zmalloc_socket(NULL, msg_size, RTE_CACHE_LINE_SIZE,
					   dev->data->socket_id);
		if (!vaddr) {
			rte_bbdev_log(ERR,
				"Memory allocation failed for vaddr");
			return -ENOMEM;
		}
		q_priv->msg_ch_vaddr[i] = vaddr;
	}

	q_priv->host_params = rte_zmalloc_socket(NULL, sizeof(host_ipc_params_t),
			RTE_CACHE_LINE_SIZE, dev->data->socket_id);
	if (!q_priv->host_params) {
		rte_bbdev_log(ERR, "Memory allocation failed for host_params");
		return -ENOMEM;
	}

	if (q_priv->op_type != RTE_BBDEV_OP_RAW) {
		feca_jobs = rte_zmalloc_socket(NULL, sizeof(feca_job_t) * IPC_MAX_DEPTH,
				RTE_CACHE_LINE_SIZE, dev->data->socket_id);
		if (!feca_jobs) {
			rte_bbdev_log(ERR, "Memory allocation failed for feca jobs");
			return -ENOMEM;
		}

		for (i = 0; i < IPC_MAX_DEPTH; i++)
			q_priv->feca_jobs[i] = &feca_jobs[i];
	}

	/* Set queue properties for LA12xx device */
	switch (q_priv->op_type) {
	case RTE_BBDEV_OP_LDPC_ENC:
		if (priv->num_ldpc_enc_queues >=
				ipc_priv->instance->max_ldpc_enc_feca_queues) {
			rte_bbdev_log(ERR,
				"num_ldpc_enc_queues reached max value");
			return -1;
		}
		q_priv->la12xx_core_id = BBDEV_LA12XX_LDPC_ENC_CORE;
		q_priv->feca_blk_id = priv->num_ldpc_enc_queues++;
		break;
	case RTE_BBDEV_OP_LDPC_DEC:
		if (priv->num_ldpc_dec_queues >=
				ipc_priv->instance->max_ldpc_dec_feca_queues) {
			rte_bbdev_log(ERR,
				"num_ldpc_dec_queues reached max value");
			return -1;
		}
		q_priv->la12xx_core_id = BBDEV_LA12XX_LDPC_DEC_CORE;
		q_priv->feca_blk_id = priv->num_ldpc_dec_queues++;
		q_priv->per_op_hw_id = queue_conf->per_op_hw_id;
		break;
	case RTE_BBDEV_OP_POLAR_ENC:
		if (priv->num_polar_enc_queues >=
				ipc_priv->instance->max_polar_enc_feca_queues) {
			rte_bbdev_log(ERR,
				"num_polar_enc_queues reached max value");
			return -1;
		}
		q_priv->la12xx_core_id = BBDEV_LA12XX_POLAR_ENC_CORE;
		q_priv->feca_blk_id = 0;
		priv->num_polar_enc_queues++;
		break;
	case RTE_BBDEV_OP_POLAR_DEC:
		if (priv->num_polar_dec_queues >=
				ipc_priv->instance->max_polar_dec_feca_queues) {
			rte_bbdev_log(ERR,
				"num_polar_dec_queues reached max value");
			return -1;
		}
		q_priv->la12xx_core_id = BBDEV_LA12XX_POLAR_DEC_CORE;
		q_priv->feca_blk_id = 0;
		cd_crc_stat = rte_malloc_socket(NULL, sizeof(uint32_t),
				RTE_CACHE_LINE_SIZE, dev->data->socket_id);
		if (!cd_crc_stat) {
			rte_bbdev_log(ERR, "Unable to callote cd crc mem");
			return -1;
		}
		q_priv->cd_crc_stat_addr = get_l1_pcie_addr(ipc_priv, cd_crc_stat);
		priv->num_polar_dec_queues++;
		break;
	case RTE_BBDEV_OP_RAW:
		if (queue_conf->raw_queue_conf.modem_core_id >=
				LA12XX_MAX_CORES) {
			rte_bbdev_log(ERR, "Invalid modem core id: %d",
				queue_conf->raw_queue_conf.modem_core_id);
			return -1;
		}

		if (priv->num_raw_queues >=
				ipc_priv->instance->max_raw_queues) {
			rte_bbdev_log(ERR,
				"num_raw_queues reached max value");
			return -1;
		}

		q_priv->la12xx_core_id =
			queue_conf->raw_queue_conf.modem_core_id;
		q_priv->is_host_to_modem =
			queue_conf->raw_queue_conf.direction;
		q_priv->conf_enable =
			queue_conf->raw_queue_conf.conf_enable;

		priv->num_raw_queues++;
		break;
	default:
		rte_bbdev_log(ERR, "Unsupported op type: %d\n",
			q_priv->op_type);
		return -1;
	}

	if (!q_priv->is_host_to_modem) {
		for (i = 0; i < queue_conf->queue_size; i++) {
			q_priv->bbdev_op[i] = rte_zmalloc_socket(NULL,
					sizeof(struct rte_bbdev_raw_op), 0,
					dev->data->socket_id);
			if (!q_priv->bbdev_op[i]) {
				rte_bbdev_log(ERR,
					"Memory allocation failed for bbdev_op[%d]", i);
				return -ENOMEM;
			}
		}
	}

	q_priv->feca_blk_id_be32 = rte_cpu_to_be_32(q_priv->feca_blk_id);

	priv->per_queue_hram_size = FECA_HRAM_SIZE / priv->num_ldpc_dec_queues;

config_modem_queue:
	mhif = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;
	/* offset is from start of PEB */
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->peb_start.host_vaddr +
		mhif->ipc_regs.ipc_mdata_offset);
	ch = &ipc_md->instance_list[instance_id].ch_list[q_priv->q_id];

	/* Start init of channel */
	ch->md.ring_size = rte_cpu_to_be_32(q_priv->queue_size);
	ch->depth = rte_cpu_to_be_32(q_priv->queue_size);
	ch->md.pi = 0;
	ch->md.ci = 0;
	ch->md.msg_size = msg_size;
	for (i = 0; i < q_priv->queue_size; i++) {
		/* Only offset now */
		ch->bd_h[i].modem_ptr =
			rte_cpu_to_be_32(get_l1_pcie_addr(ipc_priv, q_priv->msg_ch_vaddr[i]));
		ch->bd_h[i].host_virt_l =
			lower_32_bits(q_priv->msg_ch_vaddr[i]);
		ch->bd_h[i].host_virt_h =
			upper_32_bits(q_priv->msg_ch_vaddr[i]);
		/* Not sure use of this len may be for CRC*/
		ch->bd_h[i].len = 0;
	}

	ch->host_ipc_params =
		rte_cpu_to_be_32(get_l1_pcie_addr(ipc_priv, q_priv->host_params));
	ch->la12xx_core_id =
		rte_cpu_to_be_32(q_priv->la12xx_core_id);
	ch->feca_blk_id = rte_cpu_to_be_32(q_priv->feca_blk_id);

	if (q_priv->op_type == RTE_BBDEV_OP_RAW) {
		ch->is_host_to_modem =
			rte_cpu_to_be_32(q_priv->is_host_to_modem);
		ch->conf_enable =
			rte_cpu_to_be_32(q_priv->conf_enable);
	}

	rte_bbdev_log_debug("e200 Queue (%d) configured", q_priv->q_id);

	return 0;
}

static int
la12xx_vspa_queue_setup(struct rte_bbdev *dev,
		struct bbdev_la12xx_q_priv *q_priv)
{
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	void *lsb_addr, *msb_addr;
	uint32_t l1_pcie_addr;

	PMD_INIT_FUNC_TRACE();

	if (q_priv->q_id < priv->num_valid_queues) {
		rte_bbdev_log(WARNING,
			"Queue [%d] already configured, not configuring again",
			q_priv->q_id);
	} else {
		/* Allocate memory for BD ring */
		q_priv->vspa_ring = rte_zmalloc_socket(NULL, sizeof(struct vspa_desc) *
				q_priv->queue_size, RTE_CACHE_LINE_SIZE,
				dev->data->socket_id);
		if (!q_priv->vspa_ring) {
			rte_bbdev_log(ERR, "Memory allocation failed for vspa_ring");
			return -ENOMEM;
		}
		priv->queues_priv[q_priv->q_id] = q_priv;
	}

	/* send address and queue size to VSPA */
	l1_pcie_addr = get_l1_pcie_addr(ipc_priv, q_priv->vspa_ring);

	q_priv->vspa_ring->host_flag = 0;
	q_priv->vspa_ring->vspa_flag = 0;
	q_priv->vspa_desc_wr_index = 0;
	q_priv->vspa_desc_rd_index = 0;

	/* Mail box 0 */
	lsb_addr = (void *)((uint64_t)ipc_priv->modem_ccsrbar.host_vaddr +
		VSPA_ADDRESS(q_priv->la12xx_core_id) + VSPA_LSB_OFFSET);
	msb_addr = (void *)((uint64_t)ipc_priv->modem_ccsrbar.host_vaddr +
		VSPA_ADDRESS(q_priv->la12xx_core_id) + VSPA_MSB_OFFSET);

	rte_write32(q_priv->queue_size, msb_addr);
	rte_mb();
	rte_write32(l1_pcie_addr, lsb_addr);

	return 0;
}

/* Setup a queue */
static int
la12xx_queue_setup(struct rte_bbdev *dev, uint16_t q_id,
		const struct rte_bbdev_queue_conf *queue_conf)
{
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct rte_bbdev_queue_data *q_data;
	struct bbdev_la12xx_q_priv *q_priv;
	int new_queue = 0, ret;
	struct gul_hif *mhif;
	ipc_metadata_t *ipc_md;
	int instance_id = 0;
	ipc_ch_t *ch;

	PMD_INIT_FUNC_TRACE();

	/* Move to setup_queues callback */
	q_data = &dev->data->queues[q_id];
	q_priv = q_data->queue_private;

	/* If queue already configured, skip allocation */
	if (!q_priv) {
		q_priv = rte_zmalloc_socket(NULL,
			sizeof(struct bbdev_la12xx_q_priv), 0,
			dev->data->socket_id);
		if (!q_priv) {
			rte_bbdev_log(ERR, "Memory allocation failed for qpriv");
			return -ENOMEM;
		}

		q_data->queue_private = q_priv;
		q_priv->q_id = q_id;
		q_priv->bbdev_priv = dev->data->dev_private;
		q_priv->queue_size = queue_conf->queue_size;
		q_priv->op_type = queue_conf->op_type;

		new_queue = 1;
	}

	mhif = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;
	/* offset is from start of PEB */
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->peb_start.host_vaddr +
		mhif->ipc_regs.ipc_mdata_offset);
	ch = &ipc_md->instance_list[instance_id].ch_list[q_priv->q_id];
	ch->op_type = rte_cpu_to_be_32(q_priv->op_type);

	if (q_priv->op_type == RTE_BBDEV_OP_LA12XX_VSPA) {
		if (queue_conf->raw_queue_conf.modem_core_id < LA12XX_MAX_VSPA)
			q_priv->la12xx_core_id =
				queue_conf->raw_queue_conf.modem_core_id;
		else
			q_priv->la12xx_core_id = 0;
		rte_bbdev_log(INFO, "VSPA core is %d for queue id = %d\n",
				q_priv->la12xx_core_id, q_id);
		ch->la12xx_core_id =
			rte_cpu_to_be_32(q_priv->la12xx_core_id);
		ret = la12xx_vspa_queue_setup(dev, q_priv);
		if (ret) {
			rte_bbdev_log(ERR,
				"la12xx_vspa_queue_setup failed for qid: %d",
				q_id);
			return ret;
		}
	} else {
		ret = la12xx_e200_queue_setup(dev, q_priv, queue_conf);
		if (ret) {
			rte_bbdev_log(ERR,
				"la12xx_e200_queue_setup failed for qid: %d",
				q_id);
			return ret;
		}
	}

	/* Increment valid queue for newly allocated queue */
	if (new_queue)
		priv->num_valid_queues++;

	return 0;
}

uint16_t
rte_pmd_la12xx_queue_core_config(uint16_t dev_id, uint16_t queue_ids[],
		uint16_t core_ids[], uint16_t num_queues)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct bbdev_la12xx_q_priv *q_priv;
	struct gul_hif *mhif;
	ipc_metadata_t *ipc_md;
	ipc_ch_t *ch;
	int queue_id, core_id;
	int i, instance_id = 0;
	uint32_t op_type;

	mhif = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->peb_start.host_vaddr +
		mhif->ipc_regs.ipc_mdata_offset);

	for (i = 0; i < num_queues; i++) {
		q_priv = dev->data->queues[i].queue_private;
		queue_id = queue_ids[i];
		core_id = core_ids[i];

		if (queue_id >= dev->data->num_queues) {
			rte_bbdev_log(ERR,
				"Invalid queue ID %d", queue_id);
			return -1;
		}

		ch = &ipc_md->instance_list[instance_id].ch_list[queue_id];
		op_type = rte_be_to_cpu_32(ch->op_type);

		if (op_type == RTE_BBDEV_OP_LA12XX_VSPA)
			continue;

		if (core_id >= GUL_EP_CORE_MAX) {
			rte_bbdev_log(ERR,
				"Invalid core ID %d for queue %d",
				core_id, queue_id);
			return -1;
		}

		if (op_type == RTE_BBDEV_OP_POLAR_ENC) {
			if (priv->la12xx_polar_enc_core == -1)
				priv->la12xx_polar_enc_core = core_id;
			else if (priv->la12xx_polar_enc_core != core_id) {
				rte_bbdev_log(ERR,
					"All polar encode queue not configuerd on same LA12xx e200 core");
			}
		}

		if (op_type == RTE_BBDEV_OP_POLAR_DEC) {
			if (priv->la12xx_polar_dec_core == -1)
				priv->la12xx_polar_dec_core = core_id;
			else if (priv->la12xx_polar_dec_core != core_id) {
				rte_bbdev_log(ERR,
					"All polar decode queues not configuerd on same LA12xx e200 core");
			}
		}

		ch->la12xx_core_id = rte_cpu_to_be_32(core_id);
		q_priv->la12xx_core_id = core_id;
	}

	return 0;
}

uint16_t
rte_pmd_la12xx_queue_input_circ_size(uint16_t dev_id, uint16_t queue_id,
				    uint32_t input_circ_size)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct bbdev_la12xx_q_priv *q_priv;
	struct gul_hif *mhif;
	ipc_metadata_t *ipc_md;
	ipc_ch_t *ch;
	int instance_id = 0;
	uint32_t op_type;

	if (queue_id >= dev->data->num_queues) {
		rte_bbdev_log(ERR,
			"Invalid queue ID %d", queue_id);
		return -1;
	}

	mhif = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->peb_start.host_vaddr +
		mhif->ipc_regs.ipc_mdata_offset);

	q_priv = dev->data->queues[queue_id].queue_private;
	op_type = q_priv->op_type;

	if (op_type != RTE_BBDEV_OP_LDPC_ENC &&
			op_type != RTE_BBDEV_OP_LDPC_DEC) {
		rte_bbdev_log(ERR,
			"input circ buffer size configuration only supported for LDPC");
		return -1;
	}

	ch = &ipc_md->instance_list[instance_id].ch_list[queue_id];
	ch->feca_input_circ_size = rte_cpu_to_be_32(input_circ_size);
	q_priv->feca_input_circ_size = input_circ_size;

	return 0;
}

static int
la12xx_start(struct rte_bbdev *dev)
{
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	int ready = 0, i, n_vspa_q = 0;
	struct gul_hif *hif_start;
	struct bbdev_la12xx_q_priv *q_priv;
	ipc_metadata_t *ipc_md;
	ipc_ch_t *ch;

	PMD_INIT_FUNC_TRACE();

	hif_start = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->peb_start.host_vaddr +
			hif_start->ipc_regs.ipc_mdata_offset);

	/* Set Host Read bit */
	SET_HIF_HOST_RDY(hif_start, HIF_HOST_READY_IPC_APP);

	/* No need to wait if only VSPA queues */
	for (i = 0; i < dev->data->num_queues; i++) {
		if (dev->data->queues[i].conf.op_type != RTE_BBDEV_OP_LA12XX_VSPA) {
			n_vspa_q = 1;
			break;
		}
	}

	if (n_vspa_q == 0)
		return 0;

	/* Now wait for modem ready bit */
	while (!ready)
		ready = CHK_HIF_MOD_RDY(hif_start, HIF_MOD_READY_IPC_APP);

	/* Update the input circular buffer size */
	for (uint32_t i = 0; i < dev->data->num_queues; i++) {
		ch = &ipc_md->instance_list[0].ch_list[i];
		q_priv = dev->data->queues[i].queue_private;

		q_priv->feca_input_circ_size =
			rte_be_to_cpu_32(ch->feca_input_circ_size);
	}
	return 0;
}

static const struct rte_bbdev_ops pmd_ops = {
	.info_get = la12xx_info_get,
	.queue_setup = la12xx_queue_setup,
	.queue_release = la12xx_queue_release,
	.start = la12xx_start
};

static int
fill_feca_desc_enc(struct bbdev_la12xx_q_priv *q_priv,
		   struct rte_bbdev_enc_op *bbdev_enc_op,
		   struct rte_bbdev_op_data *in_op_data,
		   feca_job_t *feca_job)
{
	struct rte_bbdev_op_ldpc_enc *ldpc_enc = &bbdev_enc_op->ldpc_enc;
	struct ipc_priv_t *ipc_priv = q_priv->bbdev_priv->ipc_priv;
	uint32_t A = bbdev_enc_op->ldpc_enc.input.length * 8;
	uint32_t e[RTE_BBDEV_LDPC_MAX_CODE_BLOCKS];
	uint32_t codeblock_mask[8], i;
	uint32_t set_index, base_graph2, lifting_index, mod_order;
	uint32_t tb_24_bit_crc, num_code_blocks;
	uint32_t num_input_bytes, e_floor_thresh;
	uint32_t num_output_bits_floor, num_output_bits_ceiling;
	uint32_t SE_SC_X1_INIT, SE_SC_X2_INIT, SE_CIRC_BUF;
	uint32_t int_start_ofst_floor[8], int_start_ofst_ceiling[8];
	se_command_t se_cmd, *se_command;
	se_dcm_command_t *se_dcm_command;
	int16_t TBS_VALID;
	char *data_ptr;
	uint32_t l1_pcie_addr;

	for (i = 0; i < ldpc_enc->tb_params.cab; i++)
		e[i] = ldpc_enc->tb_params.ea;
	for (; i < ldpc_enc->tb_params.c; i++)
		e[i] = ldpc_enc->tb_params.eb;

	memset(codeblock_mask, 0xFF, (8 * sizeof(uint32_t)));

	memset(int_start_ofst_floor, 0, (8 * sizeof(uint32_t)));
	memset(int_start_ofst_ceiling, 0, (8 * sizeof(uint32_t)));

	la12xx_sch_encode_param_convert(ldpc_enc->basegraph, ldpc_enc->q_m,
			e, ldpc_enc->rv_index, A, ldpc_enc->q, ldpc_enc->n_id,
			ldpc_enc->n_rnti, !ldpc_enc->en_scramble,
			ldpc_enc->n_cb, codeblock_mask, &TBS_VALID,
			&set_index, &base_graph2, &lifting_index, &mod_order,
			&tb_24_bit_crc,	&num_code_blocks, &num_input_bytes,
			&e_floor_thresh, &num_output_bits_floor,
			&num_output_bits_ceiling, &SE_SC_X1_INIT,
			&SE_SC_X2_INIT,	int_start_ofst_floor,
			int_start_ofst_ceiling, &SE_CIRC_BUF);

	if (TBS_VALID == 0) {
		rte_bbdev_log(ERR, "Invalid input for SE");
		return -1;
	}

	feca_job->job_type = FECA_JOB_SE_BE;
	feca_job->t_blk_id = q_priv->feca_blk_id_be32;

	se_command = &feca_job->command_chain_t.se_command_ch_obj;

	se_cmd.se_cfg1.raw_se_cfg1 = 0;
	se_cmd.se_cfg1.num_code_blocks = num_code_blocks;
	se_cmd.se_cfg1.tb_24_bit_crc = tb_24_bit_crc;
	se_cmd.se_cfg1.complete_trig_en = 1;
	se_cmd.se_cfg1.mod_order = mod_order;
	se_cmd.se_cfg1.control_data_mux = ldpc_enc->se_ce_mux;
	se_cmd.se_cfg1.lifting_size = lifting_index;
	se_cmd.se_cfg1.base_graph2 = base_graph2;
	se_cmd.se_cfg1.set_index = set_index;
	se_command->se_cfg1.raw_se_cfg1 = se_cmd.se_cfg1.raw_se_cfg1;

	se_cmd.se_sizes1.raw_se_sizes1 = 0;
	se_cmd.se_sizes1.num_input_bytes = num_input_bytes;
	se_cmd.se_sizes1.e_floor_thresh = e_floor_thresh;
	se_command->se_sizes1.raw_se_sizes1 = se_cmd.se_sizes1.raw_se_sizes1;

	se_command->se_circ_buf = SE_CIRC_BUF;
	se_command->se_floor_num_output_bits = num_output_bits_floor;
	se_command->se_ceiling_num_output_bits = num_output_bits_ceiling;
	se_command->se_sc_x1_init = SE_SC_X1_INIT;
	se_command->se_sc_x2_init = SE_SC_X2_INIT;

	data_ptr = get_data_ptr(in_op_data);
	l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);

	se_command->se_axi_in_addr_low = l1_pcie_addr;
	se_command->se_axi_in_num_bytes = in_op_data->length;

	memset(se_command->se_cb_mask, 0xFF, (8 * sizeof(uint32_t)));

	se_command->se_di_start_ofst_floor[0] =
		(int_start_ofst_floor[1] << 16) | int_start_ofst_floor[0];
	se_command->se_di_start_ofst_floor[1] =
		(int_start_ofst_floor[3] << 16) | int_start_ofst_floor[2];
	se_command->se_di_start_ofst_floor[2] =
		(int_start_ofst_floor[5] << 16) | int_start_ofst_floor[4];
	se_command->se_di_start_ofst_floor[3] =
		(int_start_ofst_floor[7] << 16) | int_start_ofst_floor[6];
	se_command->se_di_start_ofst_ceiling[0] =
		(int_start_ofst_ceiling[1] << 16) | int_start_ofst_ceiling[0];
	se_command->se_di_start_ofst_ceiling[1] =
		(int_start_ofst_ceiling[3] << 16) | int_start_ofst_ceiling[2];
	se_command->se_di_start_ofst_ceiling[2] =
		(int_start_ofst_ceiling[5] << 16) | int_start_ofst_ceiling[4];
	se_command->se_di_start_ofst_ceiling[3] =
		(int_start_ofst_ceiling[7] << 16) | int_start_ofst_ceiling[6];

	if (ldpc_enc->se_ce_mux) {
		feca_job->job_type = FECA_JOB_SE_DCM_BE;
		se_dcm_command = &feca_job->command_chain_t.se_dcm_command_ch_obj;
		se_dcm_command->se_bits_per_re = ldpc_enc->se_bits_per_re;

		for (i = 0; i < RTE_BBDEV_5G_MAX_SYMBOLS; i++) {
			se_dcm_command->mux[i].se_n_re_ack_re =
				ldpc_enc->mux[i].se_n_re_ack_re;
			se_dcm_command->mux[i].se_n_csi1_re_n_csi2_re =
				ldpc_enc->mux[i].se_n_csi1_re_n_csi2_re;
			se_dcm_command->mux[i].se_n_ulsch_re_d_ack =
				ldpc_enc->mux[i].se_n_ulsch_re_d_ack;
			se_dcm_command->mux[i].se_d_csi1_d_csi2 =
				ldpc_enc->mux[i].se_d_csi1_d_csi2;
			se_dcm_command->mux[i].se_d_ack2_ack2_re =
				ldpc_enc->mux[i].se_d_ack2_ack2_re;
		}
	}

#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
	rte_bbuf_dump(stdout, bbdev_enc_op->ldpc_enc.input.data,
		bbdev_enc_op->ldpc_enc.input.data->pkt_len);
	if (ldpc_enc->se_ce_mux)
		rte_hexdump(stdout, "SE DCM COMMAND", se_dcm_command,
			    sizeof(se_dcm_command_t));
	else
		rte_hexdump(stdout, "SE COMMAND", se_command,
			    sizeof(se_command_t));
#endif

	return 0;
}

static int
fill_feca_desc_dec(struct bbdev_la12xx_q_priv *q_priv,
		   struct bbdev_ipc_dequeue_op *bbdev_ipc_op,
		   struct rte_bbdev_dec_op *bbdev_dec_op,
		   struct rte_bbdev_op_data *out_op_data,
		   feca_job_t *feca_job)
{
	struct rte_bbdev_op_ldpc_dec *ldpc_dec = &bbdev_dec_op->ldpc_dec;
	struct ipc_priv_t *ipc_priv = q_priv->bbdev_priv->ipc_priv;
	uint32_t A = bbdev_dec_op->ldpc_dec.hard_output.length * 8;
	uint32_t e[RTE_BBDEV_LDPC_MAX_CODE_BLOCKS], remove_tb_crc;
	uint32_t codeblock_mask[RTE_BBDEV_LDPC_MAX_CODE_BLOCKS/32] = {0};
	uint32_t harq_en = 0, compact_harq = 0, size_harq_buffer, C, i;
	uint32_t set_index, base_graph2, lifting_index, mod_order;
	uint32_t tb_24_bit_crc, one_code_block;
	uint32_t num_output_bytes, e_floor_thresh, bits_per_cb;
	uint32_t num_filler_bits, e_div_qm_floor, e_div_qm_ceiling;
	uint32_t SD_SC_X1_INIT, SD_SC_X2_INIT, SD_CIRC_BUF;
	uint32_t di_start_ofst_floor[8], di_start_ofst_ceiling[8];
	uint32_t axi_data_num_bytes, bbdev_ipc_op_flags = 0;
	uint32_t byte, bit, valid_bytes, llrs_per_re;
	sd_command_t sd_cmd, *sd_command;
	sd_dcm_command_t *sd_dcm_command;
	char *data_ptr;
	uint32_t l1_pcie_addr, max_req_bytes;
	int16_t TBS_VALID;

	for (i = 0; i < ldpc_dec->tb_params.cab; i++)
		e[i] = ldpc_dec->tb_params.ea;
	for (; i < ldpc_dec->tb_params.c; i++)
		e[i] = ldpc_dec->tb_params.eb;

	remove_tb_crc =
		!!(ldpc_dec->op_flags & RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP);

	if (ldpc_dec->op_flags & RTE_BBDEV_LDPC_COMPACT_HARQ) {
		bbdev_ipc_op_flags = BBDEV_LDPC_COMPACT_HARQ;
		compact_harq = 1;
	} else if (ldpc_dec->op_flags &
			RTE_BBDEV_LDPC_PARTIAL_COMPACT_HARQ) {
		bbdev_ipc_op_flags |= BBDEV_LDPC_PARTIAL_COMPACT_HARQ;
	}
	bbdev_ipc_op->op_flags = rte_cpu_to_be_32(bbdev_ipc_op_flags);

	if ((bbdev_dec_op->ldpc_dec.op_flags &
	    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
	    ldpc_dec->harq_combined_input.bdata)
		harq_en = 1;

	if (ldpc_dec->op_flags & RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE &&
	    ldpc_dec->op_flags & RTE_BBDEV_LDPC_COMPACT_HARQ) {
		valid_bytes = (ldpc_dec->tb_params.c + 31) / 32;
		for (i = 0; i < valid_bytes; i++)
			codeblock_mask[i] = ldpc_dec->codeblock_mask[i];
	} else {
		/* Set all the codeblock mask */
		for (i = 0; i < ldpc_dec->tb_params.c; i++) {
			/* Set the bit in codeblock */
			byte = i / 32;
			bit = i % 32;
			codeblock_mask[byte] |= (1 << bit);
		}
	}

	la12xx_sch_decode_param_convert(ldpc_dec->basegraph, ldpc_dec->q_m,
			e, ldpc_dec->rv_index, A, ldpc_dec->q, ldpc_dec->n_id,
			ldpc_dec->n_rnti, !ldpc_dec->en_scramble,
			ldpc_dec->n_cb, remove_tb_crc, harq_en,
			&size_harq_buffer, &C, codeblock_mask,
			&TBS_VALID, &set_index, &base_graph2, &lifting_index,
			&mod_order, &tb_24_bit_crc, &one_code_block,
			&e_floor_thresh, &num_output_bytes, &bits_per_cb,
			&num_filler_bits, &SD_SC_X1_INIT, &SD_SC_X2_INIT,
			&e_div_qm_floor, &e_div_qm_ceiling, di_start_ofst_floor,
			di_start_ofst_ceiling, &SD_CIRC_BUF,
			&axi_data_num_bytes);

	if (TBS_VALID == 0) {
		rte_bbdev_log(ERR, "Invalid input for SD");
		return -1;
	}

	feca_job->job_type = FECA_JOB_SD_BE;

	if (q_priv->per_op_hw_id)
		feca_job->t_blk_id = rte_cpu_to_be_32(((struct rte_bbdev_dec_op *)bbdev_dec_op)->hw_id);
	else
		feca_job->t_blk_id = q_priv->feca_blk_id_be32;

	sd_command = &feca_job->command_chain_t.sd_command_ch_obj;

	sd_cmd.sd_cfg1.max_num_iterations = ldpc_dec->iter_max;
	sd_cmd.sd_cfg1.min_num_iterations = 1;
	sd_cmd.sd_cfg1.remove_tb_crc = remove_tb_crc;
	sd_cmd.sd_cfg1.tb_24_bit_crc = tb_24_bit_crc;
	sd_cmd.sd_cfg1.data_control_mux = ldpc_dec->sd_cd_demux;
	sd_cmd.sd_cfg1.one_code_block = one_code_block;
	sd_cmd.sd_cfg1.lifting_index = lifting_index;
	sd_cmd.sd_cfg1.base_graph2 = base_graph2;
	sd_cmd.sd_cfg1.set_index = set_index;
	sd_command->sd_cfg1.raw_sd_cfg1 = sd_cmd.sd_cfg1.raw_sd_cfg1;

	sd_cmd.sd_cfg2.complete_trig_en = 1;
	sd_cmd.sd_cfg2.harq_en = harq_en;
	sd_cmd.sd_cfg2.compact_harq = compact_harq;
	sd_cmd.sd_cfg2.mod_order = mod_order;
	sd_command->sd_cfg2.raw_sd_cfg2 = sd_cmd.sd_cfg2.raw_sd_cfg2;

	sd_cmd.sd_sizes1.num_output_bytes = num_output_bytes;
	sd_cmd.sd_sizes1.e_floor_thresh = e_floor_thresh;
	sd_command->sd_sizes1.raw_sd_sizes1 = sd_cmd.sd_sizes1.raw_sd_sizes1;

	sd_cmd.sd_sizes2.num_filler_bits = num_filler_bits;
	sd_cmd.sd_sizes2.bits_per_cb = bits_per_cb;
	sd_command->sd_sizes2.raw_sd_sizes2 = sd_cmd.sd_sizes2.raw_sd_sizes2;

	sd_command->sd_circ_buf = SD_CIRC_BUF;
	sd_command->sd_floor_num_input_bytes = e_div_qm_floor;
	sd_command->sd_ceiling_num_input_bytes = e_div_qm_ceiling;
	sd_command->sd_hram_base =
		q_priv->feca_blk_id * q_priv->bbdev_priv->per_queue_hram_size;
	sd_command->sd_sc_x1_init = SD_SC_X1_INIT;
	sd_command->sd_sc_x2_init = SD_SC_X2_INIT;

	/* out_addr has already been swapped in the calling function */
	data_ptr = get_data_ptr(out_op_data);
	l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);
	sd_command->sd_axi_data_addr_low = l1_pcie_addr;
	sd_command->sd_axi_data_num_bytes = out_op_data->length;

	for (i = 0; i < 8; i++)
		sd_command->sd_cb_mask[i] = codeblock_mask[i];

	sd_command->sd_di_start_ofst_floor[0] =
		(di_start_ofst_floor[1] << 16) | di_start_ofst_floor[0];
	sd_command->sd_di_start_ofst_floor[1] =
		(di_start_ofst_floor[3] << 16) | di_start_ofst_floor[2];
	sd_command->sd_di_start_ofst_floor[2] =
		(di_start_ofst_floor[5] << 16) | di_start_ofst_floor[4];
	sd_command->sd_di_start_ofst_floor[3] =
		(di_start_ofst_floor[7] << 16) | di_start_ofst_floor[6];
	sd_command->sd_di_start_ofst_ceiling[0] =
		(di_start_ofst_ceiling[1] << 16) | di_start_ofst_ceiling[0];
	sd_command->sd_di_start_ofst_ceiling[1] =
		(di_start_ofst_ceiling[3] << 16) | di_start_ofst_ceiling[2];
	sd_command->sd_di_start_ofst_ceiling[2] =
		(di_start_ofst_ceiling[5] << 16) | di_start_ofst_ceiling[4];
	sd_command->sd_di_start_ofst_ceiling[3] =
		(di_start_ofst_ceiling[7] << 16) | di_start_ofst_ceiling[6];

	if (ldpc_dec->sd_cd_demux) {
		feca_job->job_type = FECA_JOB_SD_DCM_BE;
		sd_dcm_command = &feca_job->command_chain_t.sd_dcm_command_ch_obj;
		/* Calculating the max_req_bytes as per the FECA RM */
		llrs_per_re = SD_LLRS_PER_RE_MASK & ldpc_dec->sd_llrs_per_re;
		if (q_priv->feca_input_circ_size &&
				q_priv->feca_input_circ_size < (1 << 16)) {
			max_req_bytes = q_priv->feca_input_circ_size - 128;
			max_req_bytes = max_req_bytes - (max_req_bytes %
					llrs_per_re);
		} else
			max_req_bytes = SD_MAX_REQ_BYTES - (SD_MAX_REQ_BYTES %
						llrs_per_re);

		sd_dcm_command->sd_llrs_per_re = (max_req_bytes << 16) |
						 llrs_per_re;

		for (i = 0; i < RTE_BBDEV_5G_MAX_SYMBOLS; i++) {
			sd_dcm_command->demux[i].sd_n_re_ack_re =
				ldpc_dec->demux[i].sd_n_re_ack_re;
			sd_dcm_command->demux[i].sd_n_csi1_re_n_csi2_re =
				ldpc_dec->demux[i].sd_n_csi1_re_n_csi2_re;
			sd_dcm_command->demux[i].sd_n_dlsch_re_d_ack =
				ldpc_dec->demux[i].sd_n_dlsch_re_d_ack;
			sd_dcm_command->demux[i].sd_d_csi1_d_csi2 =
				ldpc_dec->demux[i].sd_d_csi1_d_csi2;
			sd_dcm_command->demux[i].sd_d_ack2_ack2_re =
				ldpc_dec->demux[i].sd_d_ack2_ack2_re;
		}
	}

#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
	rte_bbuf_dump(stdout, bbdev_dec_op->ldpc_dec.input.data,
		bbdev_dec_op->ldpc_dec.input.data->data_len);
	if (ldpc_dec->sd_cd_demux)
		rte_hexdump(stdout, "SD DCM COMMAND", sd_dcm_command,
			    sizeof(sd_dcm_command_t));
	else
		rte_hexdump(stdout, "SD COMMAND", sd_command,
			    sizeof(sd_command_t));
#endif

	return 0;
}

static void
fill_feca_desc_polar_op(struct bbdev_ipc_dequeue_op *bbdev_ipc_op,
			struct rte_pmd_la12xx_polar_params *polar_params,
			struct bbdev_la12xx_q_priv *q_priv,
			struct rte_bbdev_op_data *in_op_data,
			struct rte_bbdev_op_data *out_op_data,
			feca_job_t *feca_job)
{
	struct ipc_priv_t *ipc_priv = q_priv->bbdev_priv->ipc_priv;
	char *data_ptr;
	uint32_t l1_pcie_addr, i;
	uint32_t bbdev_ipc_op_flags;
	uint32_t polar_cmd_size;

	feca_job->job_type =
		rte_cpu_to_be_32(polar_params->feca_obj.job_type);
	if (polar_params->feca_obj.job_type ==  FECA_JOB_CE ||
	    polar_params->feca_obj.job_type == FECA_JOB_CE_DCM) {
		ce_command_t *l_ce_cmd =
			&polar_params->feca_obj.command_chain_t.ce_command_ch_obj;
		ce_command_t *ce_cmd = &feca_job->command_chain_t.ce_command_ch_obj;

		polar_params->output.length = (l_ce_cmd->ce_cfg2.E + 7)/8 +
				l_ce_cmd->ce_cfg3.out_pad_bytes;
		/* Set complete trigger */
		l_ce_cmd->ce_cfg1.complete_trig_en = 1;
		ce_cmd->ce_cfg1.raw_ce_cfg1 = l_ce_cmd->ce_cfg1.raw_ce_cfg1;
		ce_cmd->ce_cfg2.raw_ce_cfg2 = l_ce_cmd->ce_cfg2.raw_ce_cfg2;
		ce_cmd->ce_cfg3.raw_ce_cfg3 = l_ce_cmd->ce_cfg3.raw_ce_cfg3;
		ce_cmd->ce_pe_indices.raw_ce_pe_indices =
			l_ce_cmd->ce_pe_indices.raw_ce_pe_indices;

		data_ptr = get_data_ptr(in_op_data);
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);
		ce_cmd->ce_axi_addr_low = l1_pcie_addr;

		for (i = 0; i < 32; i++)
			ce_cmd->ce_fz_lut[i] = l_ce_cmd->ce_fz_lut[i];

		polar_cmd_size  = (sizeof(*ce_cmd) - sizeof(ce_cmd->ce_fz_lut)) >> 2;
		polar_cmd_size += (1 << ce_cmd->ce_cfg1.pe_n) / 32;
		polar_cmd_size *= 4;
		bbdev_ipc_op->polar_cmd_size = polar_cmd_size;

#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
		rte_bbuf_dump(stdout, polar_params->input.data,
			polar_params->input.data->pkt_len);
		rte_hexdump(stdout, "CE COMMAND", ce_cmd, sizeof(ce_command_t));
#endif
	} else {
		cd_command_t *l_cd_cmd =
			&polar_params->feca_obj.command_chain_t.cd_command_ch_obj;
		cd_command_t *cd_cmd =
			&feca_job->command_chain_t.cd_command_ch_obj;

		if (polar_params->dequeue_polar_deq_llrs &&
				((polar_params->feca_obj.job_type == FECA_JOB_CD_DCM_ACK) ||
				 (polar_params->feca_obj.job_type == FECA_JOB_CD_DCM_CS1) ||
				 (polar_params->feca_obj.job_type == FECA_JOB_CD_DCM_CS2))) {

			cd_cmd->cd_cfg2.raw_cd_cfg2 = l_cd_cmd->cd_cfg2.raw_cd_cfg2;
			polar_params->output.length = l_cd_cmd->cd_cfg2.E;
			bbdev_ipc_op_flags = BBDEV_POLAR_DEQUEUE_LLRS;
			bbdev_ipc_op->op_flags = rte_cpu_to_be_32(bbdev_ipc_op_flags);

			polar_cmd_size  = (sizeof(*cd_cmd) - sizeof(cd_cmd->cd_fz_lut)) >> 2;
			polar_cmd_size += (1 << cd_cmd->cd_cfg1.pd_n) / 32;
			polar_cmd_size *= 4;
			bbdev_ipc_op->polar_cmd_size = polar_cmd_size;

			return;
		}

		if (l_cd_cmd->cd_cfg1.pd_n)
			polar_params->output.length = (l_cd_cmd->cd_cfg1.K + 7)/8;
		else
			/* For Short Block (UCI < 11), FECA does not perform
			 * Read Muller decoding, and output is from the
			 * de-ratematcher.
			 */
			polar_params->output.length = l_cd_cmd->cd_cfg1.K;

		l_cd_cmd->cd_cfg1.complete_trig_en = 1;
		/* Set complete trigger */
		cd_cmd->cd_cfg1.raw_cd_cfg1 = l_cd_cmd->cd_cfg1.raw_cd_cfg1;
		cd_cmd->cd_cfg2.raw_cd_cfg2 = l_cd_cmd->cd_cfg2.raw_cd_cfg2;
		cd_cmd->cd_pe_indices.raw_cd_pe_indices =
			l_cd_cmd->cd_pe_indices.raw_cd_pe_indices;

		data_ptr = get_data_ptr(out_op_data);
		cd_cmd->cd_axi_data_addr_low =
			get_l1_pcie_addr(ipc_priv, data_ptr);
		cd_cmd->cd_axi_stat_addr_low = q_priv->cd_crc_stat_addr;

		for (i = 0; i < 32; i++)
			cd_cmd->cd_fz_lut[i] = l_cd_cmd->cd_fz_lut[i];

		polar_cmd_size  = (sizeof(*cd_cmd) - sizeof(cd_cmd->cd_fz_lut)) >> 2;
		polar_cmd_size += (1 << cd_cmd->cd_cfg1.pd_n) / 32;
		polar_cmd_size *= 4;
		bbdev_ipc_op->polar_cmd_size = polar_cmd_size;

#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
		if (polar_params->input.data)
			rte_bbuf_dump(stdout, polar_params->input.data,
				polar_params->input.data->data_len);
		rte_hexdump(stdout, "CD COMMAND", cd_cmd, sizeof(cd_command_t));
#endif
	}
}
#pragma GCC pop_options

/* To handle glibc memcpy unaligned access issue, we need
 * our own wrapper layer to handle corner cases. We use memcpy
 * for size aligned bytes and do left opver byets copy manually.
 */
static inline void ipc_memcpy(void *dst, void *src, uint32_t len)
{
	uint32_t extra_b;

	extra_b = (len & 0x7);
	/* Adjust the length to multiple of 8 byte
	 * and copy extra bytes to avoid BUS error
	 */
	if (extra_b)
		len += (0x8 - extra_b);

	memcpy(dst, src, len);
}

static inline int
is_bd_ring_full(uint32_t ci, uint32_t pi, uint32_t ring_size)
{
	if (((pi + 1) % ring_size) == ci)
		return 1; /* Ring is Full */

	return 0;
}

static inline int
prepare_ldpc_enc_op(struct rte_bbdev_enc_op *bbdev_enc_op,
		    struct bbdev_la12xx_q_priv *q_priv,
		    struct rte_bbdev_op_data *in_op_data,
		    struct rte_bbdev_op_data *out_op_data,
		    feca_job_t *feca_job)
{
	struct rte_bbdev_op_ldpc_enc *ldpc_enc = &bbdev_enc_op->ldpc_enc;
	uint32_t total_out_bits;
	int ret;

	total_out_bits = (ldpc_enc->tb_params.cab *
		ldpc_enc->tb_params.ea) + (ldpc_enc->tb_params.c -
		ldpc_enc->tb_params.cab) * ldpc_enc->tb_params.eb;

	if (ldpc_enc->se_ce_mux)
		ldpc_enc->output.length = ldpc_enc->se_ce_mux_output_size;
	else
		ldpc_enc->output.length = (total_out_bits + 7)/8;

	ret = fill_feca_desc_enc(q_priv, bbdev_enc_op,
				 in_op_data, feca_job);
	if (ret) {
		rte_bbdev_log(ERR,
			"fill_feca_desc_enc failed, ret: %d", ret);
		return ret;
	}

	if (!out_op_data->is_direct_mem)
		rte_bbuf_append((struct rte_bbuf *)out_op_data->bdata,
				ldpc_enc->output.length);

	return 0;
}

static inline int
prepare_ldpc_dec_op(struct rte_bbdev_dec_op *bbdev_dec_op,
		    struct bbdev_ipc_dequeue_op *bbdev_ipc_op,
		    struct bbdev_la12xx_q_priv *q_priv,
		    struct rte_bbdev_op_data *out_op_data,
		    feca_job_t *feca_job)
{
	struct bbdev_la12xx_private *bbdev_priv = q_priv->bbdev_priv;
	struct rte_bbdev_op_ldpc_dec *ldpc_dec = &bbdev_dec_op->ldpc_dec;
	struct rte_bbdev_op_data *harq_in_op_data, *harq_out_op_data;
	struct rte_bbdev_op_data *hard_out_op_data = &ldpc_dec->hard_output;
	uint32_t out_op_data_orig_len = ldpc_dec->hard_output.length;
	uint32_t partial_op_data_orig_len = ldpc_dec->partial_output.length;
	uint32_t *codeblock_mask, i, total_out_bits, sd_circ_buf, l1_pcie_addr;
	uint32_t byte, bit, num_code_blocks = 0, harq_len_per_cb;
	struct ipc_priv_t *ipc_priv = bbdev_priv->ipc_priv;
	char *data_ptr;
	uint16_t sys_cols, valid_bytes, bits_to_set;
	uint32_t mask = 0;
	int ret;

	sys_cols = (ldpc_dec->basegraph == 1) ? 22 : 10;
	if (ldpc_dec->tb_params.c == 0) {
		ldpc_dec->hard_output.length = 0;
		goto fill_feca_desc;
	} else if (ldpc_dec->tb_params.c == 1) {
		total_out_bits = ((sys_cols * ldpc_dec->z_c) -
				ldpc_dec->n_filler);
		/* 5G-NR protocol uses 16 bit CRC when output packet
		 * size <= 3824 (bits). Otherwise 24 bit CRC is used.
		 * Adjust the output bits accordingly
		 */
		if (total_out_bits - 16 <= 3824)
			total_out_bits -= 16;
		else
			total_out_bits -= 24;
		ldpc_dec->hard_output.length = (total_out_bits / 8);
	} else {
		total_out_bits = (((sys_cols * ldpc_dec->z_c) -
				ldpc_dec->n_filler - 24) *
				ldpc_dec->tb_params.c);
		ldpc_dec->hard_output.length = (total_out_bits / 8) - 3;
	}

	codeblock_mask = ldpc_dec->codeblock_mask;

	/* Set all the codeblocks after ldpc_dec->tb_params.c to 0 */
	valid_bytes = (ldpc_dec->tb_params.c + 31) / 32;
	bits_to_set = (ldpc_dec->tb_params.c % 32) ?
		(ldpc_dec->tb_params.c % 32) : 0;

	for (i = 0; i < bits_to_set; i++)
		mask |= (1 << i);
	codeblock_mask[valid_bytes - 1] &= mask;
	for (i = valid_bytes; i < RTE_BBDEV_LDPC_MAX_CODE_BLOCKS/32; i++)
		codeblock_mask[i] = 0;

	if (ldpc_dec->op_flags & RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE &&
	    ldpc_dec->op_flags & RTE_BBDEV_LDPC_COMPACT_HARQ) {
		/* Get the total number of enabled code blocks */
		for (i = 0; i < ldpc_dec->tb_params.c; i++) {
			byte = i / 32;
			bit = i % 32;
			if (codeblock_mask[byte] & (1 << bit))
				num_code_blocks++;
		}
	} else {
		if (ldpc_dec->op_flags & RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE &&
		    ldpc_dec->op_flags & RTE_BBDEV_LDPC_PARTIAL_COMPACT_HARQ) {
			for (i = 0; i < RTE_BBDEV_LDPC_MAX_CODE_BLOCKS/32;
			     i++)
				/* Do not swap as we read byte by byte on LA12xx */
				bbdev_ipc_op->harq_mask[i] = codeblock_mask[i];
		}

		/* Set all the codeblock mask */
		for (i = 0; i < ldpc_dec->tb_params.c; i++) {
			/* Set the bit in codeblock */
			byte = i / 32;
			bit = i % 32;
			/* In case of normal HARQ (not compact or partial compact),
			 * set all the harq bits
			 */
			if (!(ldpc_dec->op_flags &
			    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
			    ldpc_dec->op_flags &
			    RTE_BBDEV_LDPC_PARTIAL_COMPACT_HARQ)
				bbdev_ipc_op->harq_mask[byte] |= (1 << bit);
		}
		num_code_blocks = ldpc_dec->tb_params.c;
	}

	bbdev_ipc_op->num_code_blocks = rte_cpu_to_be_32(num_code_blocks);

fill_feca_desc:
	ret = fill_feca_desc_dec(q_priv, bbdev_ipc_op,
				 bbdev_dec_op, out_op_data,
				 feca_job);
	if (ret) {
		rte_bbdev_log(ERR, "fill_feca_desc_dec failed, ret: %d", ret);
		return ret;
	}

	/* Set up HARQ related information */
	harq_in_op_data = &bbdev_dec_op->ldpc_dec.harq_combined_input;
	if ((bbdev_dec_op->ldpc_dec.op_flags &
	    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
	    harq_in_op_data->bdata) {
		data_ptr = get_data_ptr(harq_in_op_data);
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);
		bbdev_ipc_op->harq_in_addr = l1_pcie_addr;
		bbdev_ipc_op->harq_in_len = harq_in_op_data->length;
	}

	if (bbdev_dec_op->ldpc_dec.op_flags &
	    RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE) {
		harq_out_op_data = &bbdev_dec_op->ldpc_dec.harq_combined_output;
		data_ptr = get_data_ptr(harq_out_op_data);
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);
		bbdev_ipc_op->harq_out_addr = rte_cpu_to_be_32(l1_pcie_addr);
	}

	if (bbdev_dec_op->ldpc_dec.op_flags &
	    RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE ||
	    (bbdev_dec_op->ldpc_dec.op_flags &
	    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE &&
	    bbdev_dec_op->ldpc_dec.op_flags &
	    RTE_BBDEV_LDPC_PARTIAL_COMPACT_HARQ)) {
		sd_circ_buf = feca_job->command_chain_t.sd_command_ch_obj.sd_circ_buf;
		harq_len_per_cb =
			(128 * (uint32_t)ceil((double)sd_circ_buf/128));

		if (harq_len_per_cb * ldpc_dec->tb_params.c >
		    bbdev_priv->per_queue_hram_size) {
			rte_bbdev_log(ERR,
				"harq len required (%d) is more than allocated (%d)",
				harq_len_per_cb * ldpc_dec->tb_params.c,
				bbdev_priv->per_queue_hram_size);
			return -1;
		}

		bbdev_ipc_op->harq_len_per_cb =
			rte_cpu_to_be_32(harq_len_per_cb);
	}

	/* In case of retransmission, bbuf already have been filled in
	 * the previous transmission. So skip appending data in bbuf.
	 */
	if (((out_op_data_orig_len == 0) || (ldpc_dec->rv_index == 0)) &&
			!hard_out_op_data->is_direct_mem)
		rte_bbuf_append((struct rte_bbuf *)hard_out_op_data->bdata,
				hard_out_op_data->length);

	if ((&ldpc_dec->partial_output == out_op_data) &&
	    (partial_op_data_orig_len == 0)) {
		rte_bbuf_append((struct rte_bbuf *)out_op_data->bdata,
				hard_out_op_data->length);
		out_op_data->length = hard_out_op_data->length;
	}

	if (ldpc_dec->max_num_harq_contexts)
		bbdev_ipc_op->max_num_harq_contexts =
			rte_cpu_to_be_32(ldpc_dec->max_num_harq_contexts);

	return 0;
}

static inline int
prepare_polar_op(struct rte_pmd_la12xx_polar_params *polar_params,
		 struct bbdev_ipc_dequeue_op *bbdev_ipc_op,
		 struct bbdev_la12xx_q_priv *q_priv,
		 struct rte_bbdev_op_data *in_op_data,
		 struct rte_bbdev_op_data *out_op_data,
		 feca_job_t *feca_job)
{
	fill_feca_desc_polar_op(bbdev_ipc_op, polar_params, q_priv,
				in_op_data, out_op_data, feca_job);

	if (!out_op_data->is_direct_mem && out_op_data->bdata)
		rte_bbuf_append((struct rte_bbuf *)out_op_data->bdata,
				polar_params->output.length);

	return 0;
}

static inline int
prepare_raw_op(struct rte_pmd_la12xx_raw_params *raw_params,
	       struct bbdev_ipc_dequeue_op *bbdev_ipc_op,
	       struct bbdev_la12xx_q_priv *q_priv,
	       struct rte_bbdev_op_data *out_op_data)
{
	struct ipc_priv_t *ipc_priv = q_priv->bbdev_priv->ipc_priv;
	uint32_t l1_pcie_addr;

	if (raw_params->metadata) {
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv,
					raw_params->metadata);
		bbdev_ipc_op->shared_metadata = rte_cpu_to_be_32(l1_pcie_addr);
	}

	if (!out_op_data)
		bbdev_ipc_op->out_addr = 0;

	return 0;
}

static int
enqueue_single_op(struct bbdev_la12xx_q_priv *q_priv, void *bbdev_op)
{
	struct bbdev_la12xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct bbdev_ipc_dequeue_op *bbdev_ipc_op;
	struct rte_bbdev_op_ldpc_enc *ldpc_enc;
	struct rte_bbdev_op_ldpc_dec *ldpc_dec;
	struct rte_pmd_la12xx_polar_params *polar_params;
	struct rte_pmd_la12xx_raw_params *raw_params;
	uint32_t q_id = q_priv->q_id;
	uint32_t ci, pi;
	ipc_ch_t *ch = &(ipc_instance->ch_list[q_id]);
	ipc_br_md_t *md = &(ch->md);
	uint64_t virt;
	struct rte_bbdev_op_data *in_op_data, *out_op_data;
	feca_job_t *feca_job;
	char *data_ptr;
	uint32_t l1_pcie_addr;
	int ret;

	ci = q_priv->host_ci;
	pi = q_priv->host_pi;

	rte_bbdev_dp_log(DEBUG,
		"before bd_ring_full: pi: %u, ci: %u, ring size: %u",
		pi, ci, q_priv->queue_size);

	if (is_bd_ring_full(ci, pi, q_priv->queue_size)) {
		rte_bbdev_dp_log(DEBUG,
				"bd ring full for queue id: %d", q_id);
		return IPC_CH_FULL;
	}

	virt = MODEM_P2V(q_priv->host_params->bd_m_modem_ptr[pi]);
	bbdev_ipc_op = (struct bbdev_ipc_dequeue_op *)virt;
	feca_job = q_priv->feca_jobs[pi];
	q_priv->bbdev_op[pi] = bbdev_op;

	switch (q_priv->op_type) {
	case RTE_BBDEV_OP_LDPC_ENC:
		ldpc_enc = &(((struct rte_bbdev_enc_op *)bbdev_op)->ldpc_enc);
		in_op_data = &ldpc_enc->input;
		out_op_data = &ldpc_enc->output;

		ret = prepare_ldpc_enc_op(bbdev_op, q_priv, in_op_data,
					  out_op_data, feca_job);
		if (ret) {
			rte_bbdev_log(ERR, "process_ldpc_enc_op fail, ret: %d",
				ret);
			return ret;
		}
		break;

	case RTE_BBDEV_OP_LDPC_DEC:
		ldpc_dec = &(((struct rte_bbdev_dec_op *)bbdev_op)->ldpc_dec);
		in_op_data = &ldpc_dec->input;

		if ((ldpc_dec->op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
		    (ldpc_dec->op_flags &
		    RTE_BBDEV_LDPC_PARTIAL_COMPACT_HARQ))
			out_op_data = &ldpc_dec->partial_output;
		else
			out_op_data = &ldpc_dec->hard_output;

		ret = prepare_ldpc_dec_op(bbdev_op, bbdev_ipc_op,
					  q_priv, out_op_data, feca_job);
		if (ret) {
			rte_bbdev_log(ERR,
				"process_ldpc_dec_op failed, ret: %d", ret);
			return ret;
		}
		break;

	case RTE_BBDEV_OP_POLAR_ENC:
	case RTE_BBDEV_OP_POLAR_DEC:
		polar_params = &(((struct rte_pmd_la12xx_op *)
				bbdev_op)->polar_params);
		in_op_data = &polar_params->input;
		out_op_data = &polar_params->output;

		ret = prepare_polar_op(polar_params, bbdev_ipc_op, q_priv,
				       in_op_data, out_op_data, feca_job);
		if (ret) {
			rte_bbdev_log(ERR,
				"process_polar_op failed, ret: %d", ret);
			return ret;
		}
		break;

	case RTE_BBDEV_OP_RAW:
		raw_params = &(((struct rte_pmd_la12xx_op *)
			bbdev_op)->raw_params);
		in_op_data = &raw_params->input;
		out_op_data = &raw_params->output;

		ret = prepare_raw_op(raw_params, bbdev_ipc_op,
				     q_priv, out_op_data);
		if (ret) {
			rte_bbdev_log(ERR,
				"process_raw_op failed, ret: %d", ret);
			return ret;
		}
		break;

	default:
		rte_bbdev_log(ERR, "unsupported bbdev_ipc op type");
		return -1;
	}

	if (in_op_data->bdata) {
		data_ptr = get_data_ptr(in_op_data);
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);
		bbdev_ipc_op->in_addr = l1_pcie_addr;
		bbdev_ipc_op->in_len = in_op_data->length;
	}

	if (out_op_data->bdata) {
		data_ptr = get_data_ptr(out_op_data);
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);
		bbdev_ipc_op->out_addr = rte_cpu_to_be_32(l1_pcie_addr);
		bbdev_ipc_op->out_len = rte_cpu_to_be_32(out_op_data->length);
	}

	if (q_priv->op_type != RTE_BBDEV_OP_RAW) {
		bbdev_ipc_op->feca_job_addr =
			rte_cpu_to_be_32(get_l1_pcie_addr(ipc_priv, feca_job));
		bbdev_ipc_op->feca_job_type = feca_job->job_type;
		bbdev_ipc_op->feca_blk_id = feca_job->t_blk_id;
		if (q_priv->op_type == RTE_BBDEV_OP_LDPC_DEC) {
			if (q_priv->per_op_hw_id)
				bbdev_ipc_op->feca_blk_id = rte_cpu_to_be_32(((struct rte_bbdev_dec_op *)bbdev_op)->hw_id);
		}
	}

	/* Move Producer Index forward */
	pi++;
	/* Reset PI, if wrapping */
	if (unlikely(pi == q_priv->queue_size))
		pi = 0;
	q_priv->host_pi = pi;

	/* Wait for Data Copy to complete before updating modem pi */
	rte_mb();
	/* now update pi */
	md->pi = rte_cpu_to_be_32(pi);

	rte_bbdev_dp_log(DEBUG, "enter: pi: %u, ci: %u,"
			" ring size: %u",
			pi, ci, q_priv->queue_size);

	return 0;
}

/* Enqueue decode burst */
static uint16_t
enqueue_dec_ops(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_dec_op **ops, uint16_t nb_ops)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	int nb_enqueued, ret;

	for (nb_enqueued = 0; nb_enqueued < nb_ops; nb_enqueued++) {
		ret = enqueue_single_op(q_priv, ops[nb_enqueued]);
		if (ret)
			break;
	}

	q_data->queue_stats.enqueue_err_count += nb_ops - nb_enqueued;
	q_data->queue_stats.enqueued_count += nb_enqueued;

	return nb_enqueued;
}

/* Enqueue encode burst */
static uint16_t
enqueue_enc_ops(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_enc_op **ops, uint16_t nb_ops)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	int nb_enqueued, ret;

	for (nb_enqueued = 0; nb_enqueued < nb_ops; nb_enqueued++) {
		ret = enqueue_single_op(q_priv, ops[nb_enqueued]);
		if (ret)
			break;
	}

	q_data->queue_stats.enqueue_err_count += nb_ops - nb_enqueued;
	q_data->queue_stats.enqueued_count += nb_enqueued;

	return nb_enqueued;
}

static int
enqueue_vspa_op(struct bbdev_la12xx_q_priv *q_priv, void *bbdev_op)
{
	struct rte_pmd_la12xx_vspa_params *vspa_params;
	struct rte_bbdev_op_data *in_op_data, *out_op_data;
	struct bbdev_la12xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct vspa_desc *desc, *prev_desc;
	char *data_ptr;
	uint32_t l1_pcie_addr;
	void *lsb_addr;
	int prev_desc_index, i;

	desc = &q_priv->vspa_ring[q_priv->vspa_desc_wr_index];

	/* In case no descriptor is available, return NULL */
	if (desc->host_flag == 1)
		return -1;

	vspa_params = &(((struct rte_pmd_la12xx_op *)
		bbdev_op)->vspa_params);

	/* Set input data */
	in_op_data = &vspa_params->input;
	if (in_op_data->bdata) {
		data_ptr = get_data_ptr(in_op_data);
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);
		desc->in_addr = l1_pcie_addr;
		desc->in_len = in_op_data->length;
	}

	/* Set output data */
	out_op_data = &vspa_params->output;
	if (out_op_data->bdata) {
		data_ptr = get_data_ptr(out_op_data);
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);
		desc->out_addr = l1_pcie_addr;
	}

	/* Set meta data */
	if (vspa_params->metadata) {
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv,
					vspa_params->metadata);
		desc->meta_addr = l1_pcie_addr;
	}

	/* copy extra data in reserved */
	for (i=0 ; i < 8; i++)
		desc->rsvd[i] = vspa_params->extra_data[i];

	desc->vspa_flag = 0;
	desc->host_cnxt_hi = (uint32_t)((uint64_t)bbdev_op >> 32);
	desc->host_cnxt_lo = (uint32_t)((uint64_t)bbdev_op);

	rte_mb();
	/* Set Host flag to indicate that Host has written the buffer */
	desc->host_flag = 1;
	/* Again set memory barrier, so that 'prev_desc->host_flag' which
	 * is checked below is not executed before setting 'desc->host_flag'.
	 * This will remove any chance of race condition between VSPA and LX2.
	 */
	rte_mb();

	/* Check if previous desc has been processed by VSPA.
	 * If it has been processed, then raise MAILBOX.
	 */
	prev_desc_index = q_priv->vspa_desc_wr_index - 1;
	if (prev_desc_index < 0)
		prev_desc_index = q_priv->queue_size - 1;
	prev_desc = &q_priv->vspa_ring[prev_desc_index];
	if (!prev_desc->host_flag) {
		lsb_addr = (void *)
			((uint64_t)ipc_priv->modem_ccsrbar.host_vaddr +
			VSPA_ADDRESS(q_priv->la12xx_core_id) + VSPA_LSB_OFFSET);
		rte_write32(VSPA_MAILBOX_DUMMY_WRITE, lsb_addr);
	}

	q_priv->vspa_desc_wr_index++;
	if (q_priv->vspa_desc_wr_index == q_priv->queue_size)
		q_priv->vspa_desc_wr_index = 0;

	return 0;
}

static inline int
is_bd_ring_empty(uint32_t ci, uint32_t pi)
{
	if (ci == pi)
		return 1; /* No more Buffer */
	return 0;
}

/* Enqueue raw operation */
static int
enqueue_raw_op(struct rte_bbdev_queue_data *q_data,
	       struct rte_bbdev_raw_op *bbdev_op)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_la12xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct bbdev_ipc_raw_op_t *raw_op;
	uint32_t q_id = q_priv->q_id;
	uint32_t ci, pi, queue_size;
	ipc_ch_t *ch = &(ipc_instance->ch_list[q_id]);
	ipc_br_md_t *md = &(ch->md);
	uint64_t virt;
	struct rte_bbdev_op_data *in_op_data, *out_op_data;
	char *data_ptr;
	uint32_t l1_pcie_addr;
	int conf_enable = q_data->conf.raw_queue_conf.conf_enable;

	/**
	 * In case of confirmation mode, local consumer index is incremented
	 * after receiving the output data(dequeue). Hence, before enqueuing the
	 * raw operation, we need to compare this local consumer index and
	 * producer index to check if bd ring is full.
	 * But, in case of non confirmation mode, since we will not receive the
	 * output data(dequeue function will not be called), local consumer
	 * index will not be updated. Hence, to check if bd ring is full, we
	 * will rely on the shared consumer index, which will be incrememnted by
	 * other side after consuming the packet.
	 */
	if (conf_enable)
		ci = q_priv->host_ci;
	else
		ci = rte_be_to_cpu_32(q_priv->host_params->ci);
	pi = q_priv->host_pi;
	queue_size = q_priv->queue_size;

	rte_bbdev_dp_log(DEBUG,
		"before bd_ring_full: pi: %u, ci: %u, ring size: %u",
		pi, ci, queue_size);

	if (is_bd_ring_full(ci, pi, queue_size)) {
		rte_bbdev_dp_log(DEBUG,
			"bd ring full for queue id: %d", q_id);
		return -EBUSY;
	}

	virt = MODEM_P2V(q_priv->host_params->bd_m_modem_ptr[pi]);
	raw_op = (struct bbdev_ipc_raw_op_t *)virt;
	q_priv->bbdev_op[pi] = bbdev_op;

	in_op_data = &bbdev_op->input;
	out_op_data = &bbdev_op->output;

	if (!out_op_data)
		raw_op->out_addr = 0;

	if (in_op_data->bdata) {
		data_ptr = get_data_ptr(in_op_data);
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);
		raw_op->in_addr = rte_cpu_to_be_32(l1_pcie_addr);
		raw_op->in_len = rte_cpu_to_be_32(in_op_data->length);
	}

	if (out_op_data->bdata) {
		data_ptr = get_data_ptr(out_op_data);
		l1_pcie_addr = get_l1_pcie_addr(ipc_priv, data_ptr);
		raw_op->out_addr = rte_cpu_to_be_32(l1_pcie_addr);
		raw_op->out_len = rte_cpu_to_be_32(out_op_data->length);
	}

	/* Move Producer Index forward */
	pi++;
	/* Reset PI, if wrapping */
	if (unlikely(pi == queue_size))
		pi = 0;
	q_priv->host_pi = pi;

	/* Wait for Data Copy to complete before updating modem pi */
	rte_mb();
	/* now update pi */
	md->pi = rte_cpu_to_be_32(pi);

	rte_bbdev_dp_log(DEBUG,
			"exit: pi: %u, ci: %u, ring size: %u",
			pi, ci, queue_size);

	return IPC_SUCCESS;
}

/* Dequeue raw operation */
static struct rte_bbdev_raw_op *
dequeue_raw_op(struct rte_bbdev_queue_data *q_data)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_la12xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct bbdev_ipc_raw_op_t *dequeue_op;
	struct rte_bbdev_raw_op *op;
	uint32_t ci, pi, temp_ci;
	int is_host_to_modem = q_data->conf.raw_queue_conf.direction;

	if (is_host_to_modem) {
		temp_ci = rte_be_to_cpu_32(q_priv->host_params->ci);
		ci = q_priv->host_ci;
		if (temp_ci == ci)
			return NULL;

		rte_bbdev_log(DEBUG,
			"ci: %u, ring size: %u", ci, q_priv->queue_size);

		op = q_priv->bbdev_op[ci];

		dequeue_op = q_priv->msg_ch_vaddr[ci];

		op->status = rte_be_to_cpu_32(dequeue_op->status);
		op->output.length = rte_be_to_cpu_32(dequeue_op->out_len);

		/* Move Consumer Index forward */
		ci++;
		/* Reset the CI, if wrapping */
		if (unlikely(ci == q_priv->queue_size))
			ci = 0;
		q_priv->host_ci = ci;

		rte_bbdev_dp_log(DEBUG,
			"exit: ci: %u, ring size: %u", ci, q_priv->queue_size);

	} else {
		ci = q_priv->host_ci;
		pi = rte_be_to_cpu_32(q_priv->host_params->pi);

		if (is_bd_ring_empty(ci, pi))
			return NULL;

		rte_bbdev_dp_log(DEBUG,
			"ci: %u, ring size: %u", ci, q_priv->queue_size);

		dequeue_op =
			(struct bbdev_ipc_raw_op_t *)q_priv->msg_ch_vaddr[ci];

		op = q_priv->bbdev_op[ci];

		op->input.length = rte_be_to_cpu_32(dequeue_op->in_len);
		op->output.length = rte_be_to_cpu_32(dequeue_op->out_len);
		op->input.mem =	(void *)MODEM_P2V(rte_be_to_cpu_32(
					dequeue_op->in_addr));
		op->output.mem = (void *)MODEM_P2V(rte_be_to_cpu_32(
					dequeue_op->out_addr));

		rte_bbdev_dp_log(DEBUG,
			"exit: ci: %u, ring size: %u", ci, q_priv->queue_size);
	}

	return op;
}

/* Consume raw operation */
static uint16_t
consume_raw_op(struct rte_bbdev_queue_data *q_data,
	       struct rte_bbdev_raw_op *bbdev_op)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_la12xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct bbdev_ipc_raw_op_t *raw_op;
	ipc_ch_t *ch = &(ipc_instance->ch_list[q_priv->q_id]);
	ipc_br_md_t *md = &(ch->md);
	uint32_t ci;
	uint64_t virt;

	ci = q_priv->host_ci;

	rte_bbdev_dp_log(DEBUG,
		"enter: ci: %u, ring size: %u", ci, q_priv->queue_size);

	virt = MODEM_P2V(q_priv->host_params->bd_m_modem_ptr[ci]);
	raw_op = (struct bbdev_ipc_raw_op_t *)virt;
	raw_op->status = rte_cpu_to_be_32(bbdev_op->status);
	raw_op->out_len = rte_cpu_to_be_32(bbdev_op->output.length);

	/* Move Consumer Index forward */
	ci++;
	/* Reset the CI, if wrapping */
	if (unlikely(ci == q_priv->queue_size))
		ci = 0;
	q_priv->host_ci = ci;

	/* Wait for Data Copy & ci_flag update to complete before updating ci */
	rte_mb();
	/* now update ci */
	md->ci = rte_cpu_to_be_32(ci);

	rte_bbdev_dp_log(DEBUG,
		"exit: ci: %u, ring size: %u", ci, q_priv->queue_size);

	return IPC_SUCCESS;
}

/* Dequeue encode burst */
static void *
dequeue_single_op(struct bbdev_la12xx_q_priv *q_priv, void *dst)
{
	void *op;
	uint32_t ci, temp_ci;

	temp_ci = rte_be_to_cpu_32(q_priv->host_params->ci);
	ci = q_priv->host_ci;
	if (temp_ci == ci)
		return NULL;

	rte_bbdev_dp_log(DEBUG,
		"ci: %u, ring size: %u", ci, q_priv->queue_size);

	op = q_priv->bbdev_op[ci];

	rte_memcpy(dst, q_priv->msg_ch_vaddr[ci],
		sizeof(struct bbdev_ipc_enqueue_op));

	/* Move Consumer Index forward */
	ci++;
	/* Reset the CI, if wrapping */
	if (unlikely(ci == q_priv->queue_size))
		ci = 0;
	q_priv->host_ci = ci;

	rte_bbdev_dp_log(DEBUG,
		"exit: ci: %u, ring size: %u",
		ci, q_priv->queue_size);

	return op;
}

/* Dequeue decode burst */
static uint16_t
dequeue_dec_ops(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_dec_op **ops, uint16_t nb_ops)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_la12xx_private *priv = q_priv->bbdev_priv;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct bbdev_ipc_enqueue_op bbdev_ipc_op;
	struct rte_bbdev_dec_op *l_op;
	struct rte_bbdev_op_data *harq_out_op_data;
	int nb_dequeued, tb_crc, cb_cnt;
	uint32_t harq_out_len;

	for (nb_dequeued = 0; nb_dequeued < nb_ops; nb_dequeued++) {
		ops[nb_dequeued] = dequeue_single_op(q_priv, &bbdev_ipc_op);
		if (!ops[nb_dequeued])
			break;

		l_op = ops[nb_dequeued];
		l_op->status = bbdev_ipc_op.status;

		/* In case of no SD data, which can be the case with
		 * demux scenario, where ACK/CSI are demuxed, simply
		 * continue.
		 */
		if (!ops[nb_dequeued]->ldpc_dec.hard_output.length)
			continue;

		harq_out_op_data = &l_op->ldpc_dec.harq_combined_output;
		if ((l_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE) &&
		    harq_out_op_data->bdata) {
			harq_out_len =
				rte_be_to_cpu_32(bbdev_ipc_op.out_len);
			if (harq_out_len) {
				l_op->ldpc_dec.harq_combined_output.length =
					harq_out_len;
				if (!harq_out_op_data->is_direct_mem)
					rte_bbuf_append((struct rte_bbuf *)harq_out_op_data->bdata,
							harq_out_len);
				l_op->status = 1 << RTE_BBDEV_CRC_ERROR;
			}
		}

		tb_crc = 0;
		if (l_op->ldpc_dec.code_block_mode ||
		    (l_op->ldpc_dec.tb_params.c == 1)) {
			cb_cnt = 1;
			tb_crc = 0;
		} else {
			cb_cnt = l_op->ldpc_dec.tb_params.c;
			tb_crc = l_op->ldpc_dec.tb_params.c;
		}

		/* Copy code block crc status bits + TB status bit */
		ipc_memcpy(l_op->crc_stat,
			   (void *)MODEM_P2V(bbdev_ipc_op.crc_stat_addr),
			   (cb_cnt >> 3) + 1);
		if (!(l_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE) &&
		    !(l_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
		    !(l_op->crc_stat[tb_crc >> 3] & (1 << (tb_crc & 0x7))))
			l_op->status = 1 << RTE_BBDEV_CRC_ERROR;
#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
		rte_bbuf_dump(stdout,
			ops[nb_dequeued]->ldpc_dec.hard_output.data,
			ops[nb_dequeued]->ldpc_dec.hard_output.data->data_len);
#endif
	}
	q_data->queue_stats.dequeued_count += nb_dequeued;

	return nb_dequeued;
}

/* Dequeue encode burst */
static uint16_t
dequeue_enc_ops(struct rte_bbdev_queue_data *q_data,
		struct rte_bbdev_enc_op **ops, uint16_t nb_ops)
{
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_ipc_enqueue_op bbdev_ipc_op;
	int nb_enqueued;

	for (nb_enqueued = 0; nb_enqueued < nb_ops; nb_enqueued++) {
		ops[nb_enqueued] = dequeue_single_op(q_priv, &bbdev_ipc_op);
		if (!ops[nb_enqueued])
			break;
		ops[nb_enqueued]->status = bbdev_ipc_op.status;
#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
		rte_bbuf_dump(stdout, ops[nb_enqueued]->ldpc_enc.output.data,
			ops[nb_enqueued]->ldpc_enc.output.data->data_len);
#endif
	}
	q_data->queue_stats.enqueued_count += nb_enqueued;

	return nb_enqueued;
}

static void *
dequeue_vspa_op(struct bbdev_la12xx_q_priv *q_priv)
{
	struct rte_pmd_la12xx_op *bbdev_la12xx_op;
	struct rte_pmd_la12xx_vspa_params *vspa_params;
	struct rte_bbdev_op_data *out_op_data;
	struct vspa_desc *desc;

	desc = &q_priv->vspa_ring[q_priv->vspa_desc_rd_index];
	if (desc->vspa_flag == 0)
		return NULL;

	bbdev_la12xx_op = (struct rte_pmd_la12xx_op *)
		join_32_bits(desc->host_cnxt_hi, desc->host_cnxt_lo);
	vspa_params = &bbdev_la12xx_op->vspa_params;

	out_op_data = &vspa_params->output;
	if (out_op_data->bdata) {
		out_op_data->length = desc->out_len;
		if (!out_op_data->is_direct_mem && out_op_data->bdata)
			rte_bbuf_append((struct rte_bbuf *)out_op_data->bdata,
					vspa_params->output.length);
	}

	q_priv->vspa_desc_rd_index++;
	if (q_priv->vspa_desc_rd_index == q_priv->queue_size)
		q_priv->vspa_desc_rd_index = 0;

	/* Reset Host and VSPA flag */
	desc->host_flag = 0;
	desc->vspa_flag = 0;

	return (void *)bbdev_la12xx_op;
}

static void
process_deq_raw_op(struct rte_pmd_la12xx_op *op,
		   struct bbdev_ipc_enqueue_op *bbdev_ipc_op)
{
	struct rte_bbdev_op_data *out_op_data;

	out_op_data = &op->raw_params.output;

	if (out_op_data->bdata) {
		op->raw_params.output.length =
			rte_be_to_cpu_32(bbdev_ipc_op->out_len);

		if (!out_op_data->is_direct_mem)
			rte_bbuf_append((struct rte_bbuf *)out_op_data->bdata,
				op->raw_params.output.length);
	}
}

uint16_t
rte_pmd_la12xx_enqueue_ops(uint16_t dev_id, uint16_t queue_id,
		struct rte_pmd_la12xx_op **ops, uint16_t num_ops)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct rte_bbdev_queue_data *q_data = &dev->data->queues[queue_id];
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	int nb_enqueued, ret;

	for (nb_enqueued = 0; nb_enqueued < num_ops; nb_enqueued++) {
		if (q_priv->op_type == RTE_BBDEV_OP_LA12XX_VSPA)
			ret = enqueue_vspa_op(q_priv, ops[nb_enqueued]);
		else
			ret = enqueue_single_op(q_priv, ops[nb_enqueued]);
		if (ret)
			break;
	}

	q_data->queue_stats.enqueue_err_count += num_ops - nb_enqueued;
	q_data->queue_stats.enqueued_count += nb_enqueued;

	return nb_enqueued;
}

uint16_t
rte_pmd_la12xx_dequeue_ops(uint16_t dev_id, uint16_t queue_id,
		struct rte_pmd_la12xx_op **ops, uint16_t num_ops)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct rte_bbdev_queue_data *q_data = &dev->data->queues[queue_id];
	struct bbdev_la12xx_q_priv *q_priv = q_data->queue_private;
	struct bbdev_ipc_enqueue_op bbdev_ipc_op, *p_bbdev_ipc_op;
	int nb_dequeued;

	p_bbdev_ipc_op = &bbdev_ipc_op;

	if (q_priv->op_type == RTE_BBDEV_OP_LA12XX_VSPA) {
		for (nb_dequeued = 0; nb_dequeued < num_ops; nb_dequeued++) {
			ops[nb_dequeued] =
				dequeue_vspa_op(q_priv);
			if (!ops[nb_dequeued])
				break;
		}
	} else {
		for (nb_dequeued = 0; nb_dequeued < num_ops; nb_dequeued++) {
			ops[nb_dequeued] =
				dequeue_single_op(q_priv, p_bbdev_ipc_op);
			if (!ops[nb_dequeued])
				break;
			if (q_priv->op_type != RTE_BBDEV_OP_RAW)
				ops[nb_dequeued]->status = bbdev_ipc_op.status;
			else
				process_deq_raw_op(ops[nb_dequeued], &bbdev_ipc_op);
#ifdef RTE_LIBRTE_LA12XX_DEBUG_DRIVER
			rte_bbuf_dump(stdout,
				ops[nb_dequeued]->polar_params.output.data,
				ops[nb_dequeued]->polar_params.output.data->pkt_len);
#endif
		}
	}
	q_data->queue_stats.dequeued_count += nb_dequeued;

	return nb_dequeued;
}


void
rte_pmd_la12xx_op_init(struct rte_mempool *mempool,
		__rte_unused void *arg, void *element,
		__rte_unused unsigned int n)
{
	struct rte_pmd_la12xx_op *op = element;

	memset(op, 0, mempool->elt_size);
	op->polar_params.mempool = mempool;
}

static int
register_watchdog(struct bbdev_la12xx_private *priv)
{
	int ret;

	PMD_INIT_FUNC_TRACE();

	if (!priv->wdog) {
		priv->wdog = rte_malloc_socket(NULL,
			sizeof(struct wdog), RTE_CACHE_LINE_SIZE,
			bbdev_socket_id);

		/* Register Modem & Watchdog */
		ret = libwdog_register(priv->wdog, priv->modem_id);
		if (ret < 0) {
			rte_bbdev_log(ERR, "libwdog_register failed");
			return ret;
		}
	}

	return 0;
}

static int
deregister_watchdog(struct bbdev_la12xx_private *priv)
{
	int ret;

	PMD_INIT_FUNC_TRACE();

	if (priv->wdog) {
		ret = libwdog_deregister(priv->wdog);
		if (ret) {
			rte_bbdev_log(ERR, "libwdog_deregister failed");
			return ret;
		}
		rte_free(priv->wdog);
		priv->wdog = NULL;
	}

	return 0;
}

int
rte_pmd_la12xx_is_active(uint16_t dev_id)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	int ret;

	PMD_INIT_FUNC_TRACE();

	ret = register_watchdog(priv);
	if (ret != 0) {
		rte_bbdev_log(ERR, "watchdog registration failed");
		return ret;
	}

	/* check if modem not in ready state */
	ret = libwdog_get_modem_status(priv->wdog);
	if (ret < 0) {
		rte_bbdev_log(ERR, "libwdog_get_modem_status failed");
		return ret;
	}

	if (priv->wdog->wdog_modem_status == WDOG_MODEM_NOT_READY)
		return 0;

	return 1;
}

int
rte_pmd_la12xx_get_event_fd(uint16_t dev_id)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	int ret;

	ret = register_watchdog(priv);
	if (ret != 0) {
		rte_bbdev_log(ERR, "watchdog registration failed");
		return ret;
	}

	return priv->wdog->wdog_eventfd;
}

void
rte_pmd_la12xx_clear_event_fd(uint16_t dev_id)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	struct wdog *wdog = priv->wdog;
	uint64_t eftd_ctr;

	libwdog_readwait(wdog->wdog_eventfd, &eftd_ctr, sizeof(uint64_t));
}

int
rte_pmd_la12xx_ldpc_enc_adj_bbuf(struct rte_bbuf *bbuf, uint64_t num_bytes)
{
	uint64_t start_addr, final_start_addr;
	uint64_t adjust_offset;

	start_addr = rte_bbuf_mtod(bbuf, uint64_t);

	final_start_addr = (uint64_t)rte_pmd_la12xx_ldpc_enc_adj_addr((void *)
		(start_addr + 4096), num_bytes);
	adjust_offset = final_start_addr - start_addr;

	/* Check if bbuf have enough tailroom to adjust the offset */
	if (rte_bbuf_tailroom(bbuf) < adjust_offset) {
		rte_bbdev_log(ERR, "tailroom less than adjust length - tailroom: %d, adjust_offset: %ld\n",
				rte_bbuf_tailroom(bbuf), adjust_offset);
		return -ENOMEM;
	}

	bbuf->data_off = bbuf->data_off + adjust_offset;
	return 0;
}

void *
rte_pmd_la12xx_ldpc_enc_adj_addr(void *addr, uint64_t num_bytes)
{
	uint64_t end_addr, start_addr;

	/* This W.A. and address adjustments have been provided by Hardware
	 * team on basis of validation in their environment. This is to adjust
	 * the starting address due to errata present in FECA in Shared Encode.
	 * (DPDM Ticket: TKT0549436)
	 */
	start_addr = (uint64_t)addr;
	end_addr = start_addr + num_bytes;

	if ((num_bytes >= 4096) &&  (((start_addr & 0x1ff) >= 1) &&
	    ((start_addr & 0x1ff) <= 32))) {
		end_addr = (end_addr & 0xfffffffff01f) + 64;
		start_addr = end_addr - num_bytes;
		if (((start_addr & 0x1ff) >= 1) && ((start_addr & 0x1ff) <= 32))
			start_addr += 32;
	} else if ((num_bytes & 0xfff) <= (4096 - (start_addr & 0xfff))) {
		if (((num_bytes & 0xfff) > 32) && ((num_bytes & 0x1ff) >= 1) &&
		    ((num_bytes & 0x1ff) <= 32)) {
			end_addr = (end_addr & 0xfffffffff01f) + 64;
			start_addr = end_addr - num_bytes;
			if (((start_addr & 0x1ff) >= 1) &&
			    ((start_addr & 0x1ff) <= 32))
				start_addr += 32;
		}
	} else {
		if (((end_addr & 0x1ff) >= 1) && ((end_addr & 0x1ff) <= 32)) {
			end_addr = ((end_addr & 0xfffffffff01f) + 64);
			start_addr = end_addr - num_bytes;
			if (((start_addr & 0x1ff) >= 1) &&
			    ((start_addr & 0x1ff) <= 32))
				start_addr += 32;
		}
	}

	return (void *)start_addr;
}

void
rte_pmd_la12xx_ldpc_dec_single_input_dma(uint16_t dev_id)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	ipc_instance_t *ipc_instance = ipc_priv->instance;

	ipc_instance->feca_sd_single_qdma = rte_cpu_to_be_32(1);
}

int
rte_pmd_la12xx_map_hugepage_addr(uint16_t dev_id, void *addr)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;

	return map_second_hugepage_addr(ipc_priv, addr);
}

static inline int
bbdev_soft_reset(uint16_t dev_id)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct rte_bbdev_queue_conf queue_conf = {0};
	struct bbdev_la12xx_q_priv *q_priv;
	int num_queues, ret, i;

	PMD_INIT_FUNC_TRACE();

	/* Re-configure the queues */
	num_queues = dev->data->num_queues;
	for (i = 0; i < num_queues; i++) {
		q_priv = dev->data->queues[i].queue_private;

		/* Do not reconfigure VSPA queues here */
		if (q_priv->op_type == RTE_BBDEV_OP_LA12XX_VSPA)
			continue;

		queue_conf.op_type = q_priv->op_type;
		queue_conf.queue_size = q_priv->queue_size;

		ret = la12xx_queue_setup(dev, i, &queue_conf);
		if (ret) {
			rte_bbdev_log(ERR,
				"setup failed for queue id: %d", i);
			return ret;
		}
	}

	return 0;
}

int
rte_pmd_la12xx_feca_reset(uint16_t dev_id)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	int ret;

	PMD_INIT_FUNC_TRACE();

	ipc_priv->instance->feca_soft_reset = rte_cpu_to_be_32(1);

	/* Now wait for modem to reset he FECA */
	while (ipc_priv->instance->feca_soft_reset)
		;

	ret = bbdev_soft_reset(dev_id);
	if (ret) {
		rte_bbdev_log(ERR, "bbdev soft reset failed");
		return ret;
	}

	return 0;
}

static struct hugepage_info *
get_hugepage_info(void)
{
	struct hugepage_info *hp_info;
	struct rte_memseg *mseg;

	PMD_INIT_FUNC_TRACE();

	hp_info = rte_malloc_socket(NULL, sizeof(struct hugepage_info), 0,
				    bbdev_socket_id);
	if (!hp_info) {
		rte_bbdev_log(ERR, "Unable to allocate on local heap");
		return NULL;
	}

	mseg = rte_mem_virt2memseg(hp_info, NULL);
	hp_info->vaddr = mseg->addr;
	hp_info->paddr = rte_mem_virt2phy(mseg->addr);
	hp_info->len = mseg->len;

	return hp_info;
}

static int open_ipc_dev(int modem_id)
{
	char dev_initials[16], dev_path[PATH_MAX];
	struct dirent *entry;
	int dev_ipc = 0;
	DIR *dir;

	dir = opendir("/dev/");
	if (!dir) {
		rte_bbdev_log(ERR, "Unable to open /dev/");
		return -1;
	}

	sprintf(dev_initials, "gulipcgul%d", modem_id);

	while ((entry = readdir(dir)) != NULL) {
		if (!strncmp(dev_initials, entry->d_name,
		    sizeof(dev_initials) - 1))
			break;
	}
	closedir(dir);

	if (!entry) {
		rte_bbdev_log(ERR, "Error: No gulipcgul%d device", modem_id);
		return -1;
	}

	sprintf(dev_path, "/dev/%s", entry->d_name);
	dev_ipc = open(dev_path, O_RDWR);
	if (dev_ipc  < 0) {
		rte_bbdev_log(ERR, "Error: Cannot open %s", dev_path);
		return -errno;
	}

	return dev_ipc;
}

static int
setup_la12xx_dev(struct rte_bbdev *dev)
{
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	struct hugepage_info *hp = NULL;
	ipc_channel_us_t *ipc_priv_ch = NULL;
	int dev_ipc = 0, dev_mem = 0;
	ipc_instance_t *instance;
	ipc_metadata_t *ipc_md;
	struct gul_hif *mhif;
	uint32_t phy_align = 0, i;
	int ret = -1;

	PMD_INIT_FUNC_TRACE();

	if (!ipc_priv) {
		/* TODO - get a better way */
		/* Get the hugepage info against it */
		hp = get_hugepage_info();
		if (!hp) {
			rte_bbdev_log(ERR, "Unable to get hugepage info");
			ret = -ENOMEM;
			goto err;
		}

		rte_bbdev_log_debug("0x%" PRIx64 " %p 0x%" PRIx64,
				hp->paddr, hp->vaddr, hp->len);

		ipc_priv = rte_zmalloc_socket(0, sizeof(ipc_userspace_t), 0,
				       dev->data->socket_id);
		if (ipc_priv == NULL) {
			rte_bbdev_log(ERR,
				"Unable to allocate memory for ipc priv");
			ret = -ENOMEM;
			goto err;
		}

		dev_mem = open("/dev/mem", O_RDWR);
		if (dev_mem < 0) {
			rte_bbdev_log(ERR, "Error: Cannot open /dev/mem");
			ret = -errno;
			goto err;
		}

		ipc_priv->instance_id = 0;
		ipc_priv->dev_mem = dev_mem;

		rte_bbdev_log_debug("hugepg input 0x%" PRIx64 "%p 0x%" PRIx64,
			hp->paddr, hp->vaddr, hp->len);

		ipc_priv->sys_map.hugepg_start.host_phys = hp->paddr;
		ipc_priv->sys_map.hugepg_start.size = hp->len;

		ipc_priv->hugepg_start[0].host_phys = hp->paddr;
		ipc_priv->hugepg_start[0].host_vaddr = hp->vaddr;
		ipc_priv->hugepg_start[0].size = hp->len;

		rte_free(hp);
	}

	dev_ipc = open_ipc_dev(priv->modem_id);
	if (dev_ipc < 0) {
		rte_bbdev_log(ERR, "Error: open_ipc_dev failed");
		ret = dev_ipc;
		goto err;
	}
	ipc_priv->dev_ipc = dev_ipc;

	/* Send IOCTL to get system map */
	ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_GET_SYS_MAP,
		    &ipc_priv->sys_map);
	if (ret) {
		rte_bbdev_log(ERR,
			"IOCTL_GUL_IPC_GET_SYS_MAP ioctl failed");
		goto err;
	}

	/*
	 *  Backward compatibility. Huge page mapping done with CCSR mapping,
	 *  skip below code.
	 */
	if (!ipc_priv->sys_map.hugepg_start.modem_phys) {
		/* Send IOCTL to put hugepg_start map */
		ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_GET_PCI_MAP,
			    &ipc_priv->sys_map.hugepg_start);
		if (ret) {
			rte_bbdev_log(ERR,
				"IOCTL_GUL_IPC_GET_PCI_MAP ioctl failed");
			goto err;
		}
	}
	/* Update Modem physical address */
	ipc_priv->hugepg_start[0].modem_phys =
		ipc_priv->sys_map.hugepg_start.modem_phys;

	phy_align = (ipc_priv->sys_map.mhif_start.host_phys % 0x1000);
	ipc_priv->mhif_start.host_vaddr =
		mmap(0, ipc_priv->sys_map.mhif_start.size + phy_align,
		     (PROT_READ | PROT_WRITE), MAP_SHARED, ipc_priv->dev_mem,
		     (ipc_priv->sys_map.mhif_start.host_phys - phy_align));
	if (ipc_priv->mhif_start.host_vaddr == MAP_FAILED) {
		rte_bbdev_log(ERR, "MAP failed:");
		ret = -errno;
		goto err;
	}

	ipc_priv->mhif_start.host_vaddr = (void *) ((uintptr_t)
		(ipc_priv->mhif_start.host_vaddr) + phy_align);

	phy_align = (ipc_priv->sys_map.peb_start.host_phys % 0x1000);
	ipc_priv->peb_start.host_vaddr =
		mmap(0, ipc_priv->sys_map.peb_start.size + phy_align,
		     (PROT_READ | PROT_WRITE), MAP_SHARED, ipc_priv->dev_mem,
		     (ipc_priv->sys_map.peb_start.host_phys - phy_align));
	if (ipc_priv->peb_start.host_vaddr == MAP_FAILED) {
		rte_bbdev_log(ERR, "MAP failed:");
		ret = -errno;
		goto err;
	}

	ipc_priv->peb_start.host_vaddr = (void *)((uintptr_t)
		(ipc_priv->peb_start.host_vaddr) + phy_align);

	phy_align = (ipc_priv->sys_map.modem_ccsrbar.host_phys % 0x1000);
	ipc_priv->modem_ccsrbar.host_vaddr =
		mmap(0, ipc_priv->sys_map.modem_ccsrbar.size + phy_align,
		     (PROT_READ | PROT_WRITE), MAP_SHARED, ipc_priv->dev_mem,
		     (ipc_priv->sys_map.modem_ccsrbar.host_phys - phy_align));
	if (ipc_priv->modem_ccsrbar.host_vaddr == MAP_FAILED) {
		rte_bbdev_log(ERR, "MAP failed:");
		ret = -errno;
		goto err;
	}

	ipc_priv->modem_ccsrbar.host_vaddr = (void *)((uintptr_t)
		(ipc_priv->modem_ccsrbar.host_vaddr) + phy_align);

	ipc_priv->hugepg_start[0].modem_phys =
		ipc_priv->sys_map.hugepg_start.modem_phys;

	ipc_priv->mhif_start.host_phys =
		ipc_priv->sys_map.mhif_start.host_phys;
	ipc_priv->mhif_start.size = ipc_priv->sys_map.mhif_start.size;
	ipc_priv->peb_start.host_phys = ipc_priv->sys_map.peb_start.host_phys;
	ipc_priv->peb_start.size = ipc_priv->sys_map.peb_start.size;

	rte_bbdev_log(INFO, "peb 0x%" PRIx64 "%p 0x%" PRIx32,
			ipc_priv->peb_start.host_phys,
			ipc_priv->peb_start.host_vaddr,
			ipc_priv->peb_start.size);
	rte_bbdev_log(INFO, "hugepg 0x%" PRIx64 "%p 0x%" PRIx32,
			ipc_priv->hugepg_start[0].host_phys,
			ipc_priv->hugepg_start[0].host_vaddr,
			ipc_priv->hugepg_start[0].size);
	rte_bbdev_log(INFO, "mhif 0x%" PRIx64 "%p 0x%" PRIx32,
			ipc_priv->mhif_start.host_phys,
			ipc_priv->mhif_start.host_vaddr,
			ipc_priv->mhif_start.size);
	mhif = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;

	/* offset is from start of PEB */
	ipc_md = (ipc_metadata_t *)((uintptr_t)ipc_priv->peb_start.host_vaddr +
			mhif->ipc_regs.ipc_mdata_offset);

	if (sizeof(ipc_metadata_t) != mhif->ipc_regs.ipc_mdata_size) {
		rte_bbdev_log(ERR,
			"ipc_metadata_t =0x%" PRIx64
			", mhif->ipc_regs.ipc_mdata_size=0x%" PRIx32,
			(uint64_t)(sizeof(ipc_metadata_t)),
			mhif->ipc_regs.ipc_mdata_size);
		rte_bbdev_log(ERR, "--> mhif->ipc_regs.ipc_mdata_offset= 0x%"
			PRIx32, mhif->ipc_regs.ipc_mdata_offset);
		rte_bbdev_log(ERR, "gul_hif size=0x%" PRIx64,
			(uint64_t)(sizeof(struct gul_hif)));
		return IPC_MD_SZ_MISS_MATCH;
	}

	ipc_priv->instance = (ipc_instance_t *)
		(&ipc_md->instance_list[ipc_priv->instance_id]);

	instance = ipc_priv->instance;
	priv->max_queues = instance->max_ldpc_dec_feca_queues +
		instance->max_ldpc_enc_feca_queues +
		instance->max_polar_enc_feca_queues +
		instance->max_polar_dec_feca_queues +
		instance->max_raw_queues;
	default_queue_conf.queue_size = instance->max_channel_depth;
	if (!ipc_priv->channels[0]) {
		for (i = 0; i < priv->max_queues; i++) {
			ipc_priv_ch = rte_zmalloc_socket(0,
				sizeof(ipc_channel_us_t), 0,
				dev->data->socket_id);
			if (ipc_priv_ch == NULL) {
				rte_bbdev_log(ERR,
					"Unable to allocate memory for channels");
				ret = -ENOMEM;
			}
			ipc_priv->channels[i] = ipc_priv_ch;
		}
	}

	rte_bbdev_log_debug("finish host init");

	priv->ipc_priv = ipc_priv;

	return 0;

err:
	rte_free(hp);
	rte_free(ipc_priv_ch);
	if (dev_mem >= 0)
		close(dev_mem);
	if (dev_ipc >= 0)
		close(dev_ipc);
	if (ipc_priv && ipc_priv->mhif_start.host_vaddr &&
	    (ipc_priv->mhif_start.host_vaddr != MAP_FAILED)) {
		phy_align = (ipc_priv->sys_map.mhif_start.host_phys % 0x1000);
		munmap(ipc_priv->mhif_start.host_vaddr,
			ipc_priv->sys_map.mhif_start.size + phy_align);
	}
	if (ipc_priv && ipc_priv->peb_start.host_vaddr &&
	    (ipc_priv->peb_start.host_vaddr != MAP_FAILED)) {
		phy_align = (ipc_priv->sys_map.peb_start.host_phys % 0x1000);
		munmap(ipc_priv->peb_start.host_vaddr,
			ipc_priv->sys_map.peb_start.size + phy_align);
	}

	rte_free(ipc_priv);
	return ret;
}

int
rte_pmd_bbdev_reset(uint16_t dev_id)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	ipc_userspace_t *ipc_priv = priv->ipc_priv;
	mem_strt_addr_t hugepg_start;
	int i, ret;

	rte_pmd_la12xx_feca_reset(dev_id);
	for (i = 0; i < MAX_PCI_USER_ALLOC_COUNT; i++) {
		if (ipc_priv->hugepg_start[i].host_vaddr) {
			hugepg_start.host_phys =
				ipc_priv->hugepg_start[i].host_phys;
			hugepg_start.modem_phys =
				ipc_priv->hugepg_start[i].modem_phys;
			hugepg_start.size = ipc_priv->hugepg_start[i].size;
			/* Send IOCTL to put hugepg_start map */
			ret = ioctl(ipc_priv->dev_ipc,
				    IOCTL_GUL_IPC_PUT_PCI_MAP, &hugepg_start);
			if (ret) {
				rte_bbdev_log(ERR,
					"IOCTL_GUL_IPC_GET_PUT_MAP ioctl failed");
				return -1;
			}
			ipc_priv->hugepg_start[i].host_vaddr = 0;
			ipc_priv->hugepg_start[i].modem_phys = 0;
			ipc_priv->hugepg_start[i].host_phys = 0;
			ipc_priv->hugepg_start[i].size = 0;
		}
	}

	return 0;
}

int
rte_pmd_la12xx_reset(uint16_t dev_id)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct bbdev_la12xx_private *priv = dev->data->dev_private;
	int ret = 0;

	rte_bbdev_log(INFO, "BBDEV LA12xx: Resetting device...\n");

	ret = register_watchdog(priv);
	if (ret != 0) {
		rte_bbdev_log(ERR, "watchdog registration failed");
		return ret;
	}

	ret = libwdog_reinit_modem(priv->wdog, 300);
	if (ret < 0) {
		rte_bbdev_log(ERR, "libwdog_reinit_modem failed");
		return ret;
	}

	ret = deregister_watchdog(priv);
	if (ret < 0) {
		rte_bbdev_log(ERR, "watchdog de-registration failed");
		return ret;
	}

	return 0;
}

int
rte_pmd_la12xx_reset_restore_cfg(uint16_t dev_id)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	int ret;

	PMD_INIT_FUNC_TRACE();

	/* Reset the device */
	rte_pmd_la12xx_reset(dev_id);

	/* Setup the device */
	ret = setup_la12xx_dev(dev);
	if (ret < 0) {
		rte_bbdev_log(ERR, "setup_la12xx_dev failed");
		return ret;
	}

	ret = bbdev_soft_reset(dev_id);
	if (ret) {
		rte_bbdev_log(ERR, "bbdev soft reset failed");
		return ret;
	}

	/* Start the device */
	ret = la12xx_start(dev);
	if (ret) {
		rte_bbdev_log(ERR, "device start failed");
		return ret;
	}

	return 0;
}

static inline int
parse_u16_arg(const char *key, const char *value, void *extra_args)
{
	uint16_t *u16 = extra_args;

	unsigned int long result;
	if ((value == NULL) || (extra_args == NULL))
		return -EINVAL;
	errno = 0;
	result = strtoul(value, NULL, 0);
	if ((result >= (1 << 16)) || (errno != 0)) {
		rte_bbdev_log(ERR, "Invalid value %" PRIu64 " for %s",
			      result, key);
		return -ERANGE;
	}
	*u16 = (uint16_t)result;
	return 0;
}

/* Parse integer from integer argument */
static int
parse_integer_arg(const char *key __rte_unused,
		const char *value, void *extra_args)
{
	int i;
	char *end;

	errno = 0;

	i = strtol(value, &end, 10);
	if (*end != 0 || errno != 0 || i < 0 || i > LA12XX_MAX_MODEM) {
		rte_bbdev_log(ERR, "Supported Port IDS are 0 to %d",
			LA12XX_MAX_MODEM - 1);
		return -EINVAL;
	}

	*((uint32_t *)extra_args) = i;

	return 0;
}

/* Parse parameters used to create device */
static int
parse_bbdev_la12xx_params(struct bbdev_la12xx_params *params,
		const char *input_args)
{
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;

	if (params == NULL)
		return -EINVAL;
	if (input_args) {
		kvlist = rte_kvargs_parse(input_args,
				bbdev_la12xx_valid_params);
		if (kvlist == NULL)
			return -EFAULT;

		ret = rte_kvargs_process(kvlist,
					bbdev_la12xx_valid_params[0],
					&parse_integer_arg,
					&params->modem_id);
		if (ret < 0)
			goto exit;

		if (params->modem_id >= LA12XX_MAX_MODEM) {
			rte_bbdev_log(ERR, "Invalid modem id, must be < %u",
					LA12XX_MAX_MODEM);
			goto exit;
		}
	}

exit:
	if (kvlist)
		rte_kvargs_free(kvlist);
	return ret;
}

/* Create device */
static int
la12xx_bbdev_create(struct rte_vdev_device *vdev,
		struct bbdev_la12xx_params *init_params)
{
	struct rte_bbdev *bbdev;
	const char *name = rte_vdev_device_name(vdev);
	struct bbdev_la12xx_private *priv;
	int ret;
	char *env = NULL;

	PMD_INIT_FUNC_TRACE();

	bbdev = rte_bbdev_allocate(name);
	if (bbdev == NULL)
		return -ENODEV;

#ifdef RTE_LA12XX_SOCKET
	bbdev_socket_id = RTE_LA12XX_SOCKET_ID;
#endif

	bbdev->data->dev_private = rte_zmalloc_socket(name,
			sizeof(struct bbdev_la12xx_private),
			RTE_CACHE_LINE_SIZE, bbdev_socket_id);
	if (bbdev->data->dev_private == NULL) {
		rte_bbdev_release(bbdev);
		return -ENOMEM;
	}

	priv = bbdev->data->dev_private;
	priv->modem_id = init_params->modem_id;
	/* if modem id is not configured */
	if (priv->modem_id == -1)
		priv->modem_id = bbdev->data->dev_id;

	rte_bbdev_log(INFO, "Initializing bbdev for:%s  modem-id=%d",
		name, init_params->modem_id);

	/* export environment variable LA12XX_MODEM_RESET=1 to
	 * auto reset the modem on BBDEV device probe.
	 */
	env = getenv("LA12XX_MODEM_RESET");
	if (env && atoi(env)) {
		ret = rte_pmd_la12xx_reset(bbdev->data->dev_id);
		if (ret) {
			rte_bbdev_log(ERR, "Modem reset failed\n");
			rte_free(bbdev->data->dev_private);
			return ret;
		}
	}
	/* Reset Global variables */
	priv->num_ldpc_enc_queues = 0;
	priv->num_ldpc_dec_queues = 0;
	priv->num_polar_enc_queues = 0;
	priv->num_polar_dec_queues = 0;
	priv->per_queue_hram_size = 0;
	priv->la12xx_polar_enc_core = -1;
	priv->la12xx_polar_dec_core = -1;
	priv->num_valid_queues = 0;

	bbdev->data->socket_id = bbdev_socket_id;
	rte_bbdev_log(INFO, "Setting Up %s: DevId=%d, ModemId=%d",
				name, bbdev->data->dev_id, priv->modem_id);
	ret = setup_la12xx_dev(bbdev);
	if (ret) {
		rte_bbdev_log(ERR, "IPC Setup failed for %s", name);
		rte_free(bbdev->data->dev_private);
		return ret;
	}
	bbdev->dev_ops = &pmd_ops;
	bbdev->device = &vdev->device;
	bbdev->intr_handle = NULL;

	bbdev->enqueue_raw_op = enqueue_raw_op;
	bbdev->dequeue_raw_op = dequeue_raw_op;
	bbdev->consume_raw_op = consume_raw_op;

	/* register rx/tx burst functions for data path */
	bbdev->dequeue_enc_ops = dequeue_enc_ops;
	bbdev->dequeue_dec_ops = dequeue_dec_ops;
	bbdev->enqueue_enc_ops = enqueue_enc_ops;
	bbdev->enqueue_dec_ops = enqueue_dec_ops;

	bbdev->dequeue_ldpc_enc_ops = dequeue_enc_ops;
	bbdev->dequeue_ldpc_dec_ops = dequeue_dec_ops;
	bbdev->enqueue_ldpc_enc_ops = enqueue_enc_ops;
	bbdev->enqueue_ldpc_dec_ops = enqueue_dec_ops;

	return 0;
}

/* Initialise device */
static int
la12xx_bbdev_probe(struct rte_vdev_device *vdev)
{
	struct bbdev_la12xx_params init_params = {
		-1,
	};
	const char *name;
	const char *input_args;

	PMD_INIT_FUNC_TRACE();

	if (vdev == NULL)
		return -EINVAL;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	input_args = rte_vdev_device_args(vdev);
	parse_bbdev_la12xx_params(&init_params, input_args);

	return la12xx_bbdev_create(vdev, &init_params);
}

/* Uninitialise device */
static int
la12xx_bbdev_remove(struct rte_vdev_device *vdev)
{
	struct rte_bbdev *bbdev;
	const char *name;

	PMD_INIT_FUNC_TRACE();

	if (vdev == NULL)
		return -EINVAL;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	bbdev = rte_bbdev_get_named_dev(name);
	if (bbdev == NULL)
		return -EINVAL;

	rte_free(bbdev->data->dev_private);

	return rte_bbdev_release(bbdev);
}

static struct rte_vdev_driver bbdev_la12xx_pmd_drv = {
	.probe = la12xx_bbdev_probe,
	.remove = la12xx_bbdev_remove
};

RTE_PMD_REGISTER_ALIAS(DRIVER_NAME, bbdev_la12xx);
RTE_PMD_REGISTER_VDEV(DRIVER_NAME, bbdev_la12xx_pmd_drv);
RTE_PMD_REGISTER_PARAM_STRING(DRIVER_NAME,
	BBDEV_LA12XX_VDEV_MODEM_ID_ARG "=<int> ");
RTE_INIT(la12xx_bbdev_init_log)
{
	bbdev_la12xx_logtype = rte_log_register("pmd.bb.la12xx");
	if (bbdev_la12xx_logtype >= 0)
		rte_log_set_level(bbdev_la12xx_logtype, RTE_LOG_NOTICE);
}
