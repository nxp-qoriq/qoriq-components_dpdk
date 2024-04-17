/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 *
 * ipc lib.c
 *
 */

/* Not sure how the PCI BAR does translation
 * assuming that translation is not done, so host_phys and modem_phys
 * exits else only host_phys is required
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_io.h>
#include <rte_mempool.h>
#include <bus_vdev_driver.h>
#include <gul_pci_def.h>
#include <gul_host_if.h>
#include <geul_cpe_ipc.h>
#include <geul_cpe_ipc_api.h>
#include <rte_pmd_geul_ipc_rawdev.h>
#include <geul_ipc_dev.h>
//#define PR(...) printf(__VA_ARGS__)
#define PR(...)
#undef pr_debug
#define pr_debug(...)

mem_range_t chvpaddr_arr[IPC_MAX_INSTANCE_COUNT][IPC_MAX_CHANNEL_COUNT];
/* Start of IPC IRQs.*/
uint32_t ipc_last_assigned_irq = IPC_CHANNEL_IRQ1;

/* This ID represents the instance ID of IPC on a single Geul. Since only one
 * IPC instance is allowed per geul, it will always be 0.
 */
#define GEUL_IPC_INSTANCE_ID 0

#define MSI_TYPE_A	0
#define MSI_TYPE_B	1
#define MSI_TYPE_C	2

#define DUAL_HUGEPAGE_SUPPORT_ENABLED 0

#define TBD 0
#define DATAPATH_CHECKS 0
#define UNUSED(x) (void)x;
#define MHIF_VADDR(A) \
	(void *)((unsigned long)(A) \
			- (ipc_priv->mhif_start.host_phys) \
			+  ipc_priv->mhif_start.vaddr)

#define IPC_CH_VADDR(A) \
	(void *)((unsigned long)(A) \
			- ipc_priv->ipc_start.host_phys \
			+ ipc_priv->ipc_start.host_vaddr)

#define MODEM_P2V(A) \
	((uint64_t) ((unsigned long) (A) \
			+ (unsigned long )(ipc_priv->peb_start.host_vaddr)))

#ifdef MOTHERWELL_IPC
#define HUGEPG_START(A, x) \
	A->hugepg_start[x]
#else
#define HUGEPG_START(A, x) \
	A->hugepg_start
#endif

#define HOST_RANGE_V(A, x) \
	(((uint64_t)(x) < (uint64_t)HUGEPG_START(A, 0).host_vaddr || \
	  (uint64_t)(x) > ((uint64_t)HUGEPG_START(A, 0).host_vaddr \
	  + HUGEPG_START(A, 0).size)) == 1 ? 0 : 1)

#define JOIN_VA32_64(H,L) ( (uint64_t)( ((H)<<32) | (L)) )
static inline uint64_t join_va2_64(uint32_t h, uint32_t l)
{
	uint64_t high = 0x0;
	high = h;
	return JOIN_VA32_64(high, l);
}

static inline uint32_t get_hugepg_offset(ipc_userspace_t *ipc_priv, void *addr)
{
	ipc_pci_map_query_t pci_map_query;
	mem_range_t hugepgstart;
	struct rte_memseg *mseg;
	uint32_t mapped_size;
	uint64_t addr_diff;
	uint32_t size;
	int ret;

	addr_diff = ((uint64_t) (addr) -
		((uint64_t)HUGEPG_START(ipc_priv, 0).host_vaddr));

#if DUAL_HUGEPAGE_SUPPORT_ENABLED
	if (addr_diff < HUGEPG_START(ipc_priv, 0).size)
#endif
		return (uint32_t)addr_diff;

	/* Create mapping for second hugepage if not created */
	if (!HUGEPG_START(ipc_priv, 1).host_vaddr) {
		ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_QUERY_PCI_MAP,
			    &pci_map_query);
		if (ret) {
			printf("IOCTL_GUL_IPC_QUERY_PCI_MAP ioctl failed\n");
			return 0;
		}

		if (!pci_map_query.mem_avail) {
			printf("No memory available for mapping\n");
			return 0;
		}

		mseg = rte_mem_virt2memseg(addr, NULL);
		if (!mseg) {
			printf("rte_mem_virt2memseg failed\n");
			return 0;
		}

		size = RTE_MIN(pci_map_query.mem_avail, mseg->len);

		/* Map last portion of the hugepage memory as in DPDK memory
		 * allocation from hugepage starts from the end.
		 */
		hugepgstart.host_phys =
			rte_mem_virt2phy(mseg->addr) + mseg->len - size;
		hugepgstart.host_vaddr = (void *)((uint64_t)(mseg->addr) +
					 mseg->len - size);
		hugepgstart.size = size;

		mapped_size = map_second_hugepage_addr(ipc_priv, hugepgstart);
		if (mapped_size == 0) {
			printf("Mapping of hugepage address failed\n");
			return 0;
		}
	}

	addr_diff = ((uint64_t) (addr) -
		((uint64_t)HUGEPG_START(ipc_priv, 1).host_vaddr));

	if (addr_diff < HUGEPG_START(ipc_priv, 1).size)
		return (uint32_t)addr_diff + HUGEPG_START(ipc_priv, 0).size;

	printf("Address not mapped over PCI\n");
	return 0;
}

#if !DUAL_HUGEPAGE_SUPPORT_ENABLED
#define HOST_V2P(A, B) \
	((uint64_t)HUGEPG_START(A, 0).host_phys \
	 + (uint64_t)get_hugepg_offset(A, B))
#endif

#if TBD
static void *get_channel_vaddr(uint32_t channel_id, ipc_userspace_t *ipc_priv);
static void *__get_channel_vaddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv);
static unsigned long get_channel_paddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv);
static unsigned long __get_channel_paddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv);
#endif

static inline void ipc_memcpy(void *dst, void *src, uint32_t len);

#if 0 /* NOT needed */
static int get_ipc_inst(ipc_userspace_t *ipc_priv, uint32_t inst_id);
static int get_channels_info(ipc_userspace_t *ipc, uint32_t instance_id);
#endif
void signal_handler(int signo, siginfo_t *siginfo, void *data);

/*AK signal and PID to be sent kernel */

static struct gul_ipc_stats *get_gul_ipc_stats(ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	struct gul_hif *mhif = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;

	return &(mhif->stats.h_ipc_stats);
}

static inline void ipc_fill_errorcode(int *err, int code)
{
	if (err)
		*err = code;
}

/* Raise MSI channel interrupt*/

static void ipc_channel_raise_msi(ipc_t instance, int msi_val, int msi_type)
{
	ipc_userspace_t *ipc_priv = instance;
	struct host_msi_unit *ccsr_hmsi = NULL;
	int mpic_reg_offset = MPIC_REG_MSIIR;

	if (msi_val >= HOST_MSI_MAX_IRQ_COUNT) {
		printf("Error: Invalid msi value:%d\n", msi_val);
		return;
	}

	switch (msi_type)
	{
		case MSI_TYPE_A:
			mpic_reg_offset = MPIC_REG_MSIIR;
			break;
		case MSI_TYPE_B:
			mpic_reg_offset = MPIC_REG_MSIIRB;
			break;
		case MSI_TYPE_C:
			mpic_reg_offset = MPIC_REG_MSIIRC;
			break;
	}

	ccsr_hmsi = (struct host_msi_unit *)(
			(uint8_t *)ipc_priv->modem_ccsrbar.host_vaddr +
			(MPIC_BASE_ADDRESS + mpic_reg_offset));

	rte_mb();

	rte_write32(rte_cpu_to_be_32((msi_val << MPIC_MSIIR_SRS_BIT) |
				     (msi_val << MPIC_MSIIR_IBS_BIT)),
		    (void *)ccsr_hmsi);
}

static inline
int ipc_is_bd_ring_empty(uint32_t ci, uint32_t ci_flag,
			 uint32_t pi, uint32_t pi_flag)
{
	if (ci == pi) {
		if (ci_flag == pi_flag)
			return 1; /* No more Buffer */
	}
	return 0;
}

static inline
int ipc_is_bd_ring_full(uint32_t ci, uint32_t ci_flag,
			uint32_t pi, uint32_t pi_flag)
{
	if (pi == ci) {
		if (pi_flag != ci_flag)
			return 1; /* Ring is Full */
	}
	return 0;
}

static inline
int ipc_is_bl_full(uint32_t ci, uint32_t ci_flag,
		   uint32_t pi, uint32_t pi_flag)
{
	if (pi == ci) {
		if (pi_flag == ci_flag)
			return 1; /* List is Full */
	}
	return 0;
}

static inline
int ipc_is_bl_empty(uint32_t ci, uint32_t ci_flag,
		    uint32_t pi, uint32_t pi_flag)
{
	if (pi == ci) {
		if (pi_flag != ci_flag)
			return 1; /* No more empty buffer */
	}
	return 0;
}

static inline int open_devmem(void)
{
        int dev_mem = open("/dev/mem", O_RDWR);
        if (dev_mem < 0) {
                printf("Error: Cannot open /dev/mem \n");
                return -1;
        }
        return dev_mem;
}

static inline int open_devipc(int gul_dev_id)
{
	int devipc;
	char name[32];

	sprintf(name, "%s%d", "/dev/gulipcgul", gul_dev_id);
	devipc = open(name, O_RDWR);
        if (devipc  < 0) {
		printf("Error: Cannot open %s \n", name);
		/* Check if ipc device with id 0 exists */
		sprintf(name, "%s%d", "/dev/gulipcgul", 0);
		printf("Checking if %s available...\n", name);
		devipc = open(name, O_RDWR);
		if (devipc < 0) {
			printf("Error: Cannot open %s\n", name);
			return -1;
		}
        }
        return devipc;
}

static inline void ipc_mark_channel_as_configured(uint32_t channel_id, ipc_instance_t *instance)
{
	/* Read mask */
	ipc_bitmask_t mask = instance->cfgmask[channel_id / bitcount(ipc_bitmask_t)];

	/* Set channel specific bit */
	mask |= 1 << (channel_id % bitcount(mask));

	/* Write mask */
	instance->cfgmask[channel_id / bitcount(ipc_bitmask_t)] = mask;
}

int ipc_is_channel_configured(uint32_t channel_id, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);

	/* Validate channel id */
	if (!ipc_instance) {
		h_stats->err_instance_invalid++;
		return IPC_INPUT_INVALID;
	} else if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->err_input_invalid++;
		return IPC_CH_INVALID;
	}
	/* Read mask */
	ipc_bitmask_t mask = ipc_instance->cfgmask[channel_id / bitcount(ipc_bitmask_t)];

	/* !! to return either 0 or 1 */
	return !!(mask & (1 << (channel_id % bitcount(mask))));
}

/* list array size must be IPC_BITMASK_ARRAY_SIZE */
int ipc_get_list_of_configured_channel(ipc_bitmask_t list[], ipc_t instance)
{
	uint32_t i;
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);

	/* Validate instance*/
	if (!ipc_instance || !(ipc_instance->initialized)) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	/* Fill masks from metadata to the argument list */
	for (i = 0; i < IPC_BITMASK_ARRAY_SIZE; i++)
		list[i] = ipc_instance->cfgmask[i];

	return 0;
}

/*
 * Host should init free buffer list
 * So not implemented on modem as of now
 * Internal so done in configure channel
 */
int ipc_init_ptr_buf_list(uint32_t channel_id,
		uint32_t depth, uint32_t size, ipc_t instance)
{
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	UNUSED(channel_id);
	UNUSED(instance);
	UNUSED(depth);
	UNUSED(size);

	h_stats->ipc_ch_stats[channel_id].err_not_implemented++;
	return IPC_NOT_IMPLEMENTED;
}

ipc_sh_buf_t* ipc_get_buf(uint32_t channel_id, ipc_t instance, int *err)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	ipc_ch_t *ch;
	uint32_t ci, ci_flag, pi, pi_flag;
	ipc_sh_buf_t *sh;
	ipc_channel_us_t *ch_us;

	ch_us = ipc_priv->channels[channel_id];
#if DATAPATH_CHECKS
	if (!ipc_instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		ipc_fill_errorcode(err, IPC_INSTANCE_INVALID);
		return NULL;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		ipc_fill_errorcode(err, IPC_CH_INVALID);
		return NULL;
	}
#endif

	ch = &(ipc_instance->ch_list[channel_id]);
#if DATAPATH_CHECKS
	if (!ipc_is_channel_configured(channel_id, ipc_priv)) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		ipc_fill_errorcode(err, IPC_CH_INVALID);
		return NULL;
	}
#endif

	ipc_sh_buf_t *bd = ch->br_bl_desc.bd;
	ipc_br_md_t *md = &(ch->br_bl_desc.md);

	pi = md->pi;
	ci = ch_us->ci_g;
	ci_flag = IPC_GET_CI_FLAG(ci);
	ci = IPC_GET_CI_INDEX(ci);
	pi_flag = IPC_GET_PI_FLAG(pi);
	pi = IPC_GET_PI_INDEX(pi);
	if (unlikely(ipc_is_bl_empty(ci, ci_flag, pi, pi_flag))) {
		h_stats->ipc_ch_stats[channel_id].err_buf_list_empty++;
		ipc_fill_errorcode(err, IPC_BL_EMPTY);
		return NULL;
	}

	sh = &bd[ci];
	pr_debug("%s enter: pi: %u, ci: %u, ring size: %u\r\n", __func__,
			pi, ci, md->ring_size);
	pr_debug("%d %s sh->host_virt_h=%x sh->host_virt_l=%x sh->mod_phys=%x\n\n",
			__LINE__, __func__, sh->host_virt_h, sh->host_virt_l, sh->mod_phys);

	pr_debug("%d %s ch->br_bl_desc.bd[pi].mod_phys=%x ch->br_bl_desc.bd[pi].host_virt_l=%x host_virt_h=%x\n\n", __LINE__, __func__,
			ch->br_bl_desc.bd[pi].mod_phys,
			ch->br_bl_desc.bd[pi].host_virt_l,
			ch->br_bl_desc.bd[pi].host_virt_h);

	ci++;

	/* Flip the PI flag, if wrapcing */
	if (unlikely(ch_us->bl_ring_size_g == 0))
		ch_us->bl_ring_size_g = md->ring_size;
	if (unlikely(ch_us->bl_ring_size_g == ci)) {
		ci = 0;
		ci_flag = ci_flag ? 0 : 1;
	}

	if (ci_flag)
		IPC_SET_CI_FLAG(ci);
	else
		IPC_RESET_CI_FLAG(ci);

	md->ci = ci;
	ch_us->ci_g = ci;
	pr_debug("%s exit: pi: %u, ci: %u, md->ci: %u, ring size: %u\r\n",
			__func__, pi, ci, md->ci, md->ring_size);

	ipc_fill_errorcode(err, IPC_SUCCESS);
	return sh;
}

/*
 * As per current use case/design where PTR channel is used to transfer RX TB
 * from modem to host through shared buffer, This API will be called from host
 * side only to put back the received buffer to free buffer list.
 *
 * HOST only.
 */
int ipc_put_buf(uint32_t channel_id, ipc_sh_buf_t *buf_to_free, ipc_t instance)
{
	pr_debug("here %s %d\n \n \n", __func__, __LINE__);
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t ci, ci_flag, pi, pi_flag;
	ipc_channel_us_t *ch_us;

	ch_us = ipc_priv->channels[channel_id];
#if DATAPATH_CHECKS
	uint64_t range = 0;

	if (!ipc_instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
	range = join_va2_64(buf_to_free->host_virt_h, buf_to_free->host_virt_l);
#if DUAL_HUGEPAGE_SUPPORT_ENABLED
	if (get_hugepg_offset(ipc_priv, range) == 0) {
#else
	if (!HOST_RANGE_V(ipc_priv, range)) {
#endif
		h_stats->ipc_ch_stats[channel_id].err_input_invalid++;
		return IPC_INPUT_INVALID;
	}

	ch = &(ipc_instance->ch_list[channel_id]);
	if (!ipc_is_channel_configured(channel_id, ipc_priv) ||
			ch->ch_type != IPC_CH_PTR || !ch->bl_initialized) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#else
	ch = &(ipc_instance->ch_list[channel_id]);
#endif

	md = &(ch->br_bl_desc.md);
	ci = md->ci;
	pi = ch_us->pi_g;
	pi_flag = IPC_GET_PI_FLAG(pi);
	pi = IPC_GET_PI_INDEX(pi);
	ci_flag = IPC_GET_CI_FLAG(ci);
	ci = IPC_GET_CI_INDEX(ci);
	if (unlikely(ipc_is_bl_full(ci, ci_flag, pi, pi_flag))) {
		h_stats->ipc_ch_stats[channel_id].err_buf_list_full++;
		return IPC_BL_FULL;
	}

	pr_debug("%s enter: pi: %u, ci: %u, ring size: %u\r\n", __func__,
			pi, ci, md->ring_size);
	/* Copy back to ipc_sh_buf_t */
	memcpy(&ch->br_bl_desc.bd[pi], (void *)buf_to_free,
	       sizeof(ipc_sh_buf_t));
	/* Update In flight buffer status */
	ipc_priv->channels[channel_id]->
		bufs_inflight[buf_to_free->cookie] = IPC_FALSE;
	pi++;
	/* Flip the PI flag, if wrapping */
	if (unlikely(ch_us->bl_ring_size_g == pi)) {
		pi = 0;
		pi_flag = pi_flag ? 0 : 1;
	}

	if (pi_flag)
		IPC_SET_PI_FLAG(pi);
	else
		IPC_RESET_PI_FLAG(pi);
	md->pi = pi;
	ch_us->pi_g = pi;

	pr_debug("%d %s sh->host_virt_h=%x sh->host_virt_l=%x sh->mod_phys=%x\n\n",__LINE__, __func__,
			buf_to_free->host_virt_h, buf_to_free->host_virt_l, buf_to_free->mod_phys);

	pr_debug("%d %s ch->br_bl_desc.bd[pi].mod_phys=%x ch->br_bl_desc.bd[pi].host_virt_l=%x host_virt_h=%x\n\n",__LINE__, __func__,
			ch->br_bl_desc.bd[pi].mod_phys,
			ch->br_bl_desc.bd[pi].host_virt_l,
			ch->br_bl_desc.bd[pi].host_virt_h);

	pr_debug("%s exit: pi: %u, ci: %u, md->pi: %u, ring size: %u\r\n",
			__func__, pi, ci, md->pi, md->ring_size);

	return IPC_SUCCESS;
}

int ipc_send_ptr(uint32_t channel_id,
		ipc_sh_buf_t *buf,
		ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	ipc_ch_t *ch;
	ipc_br_md_t *md, *md_bl;
	uint32_t ci, ci_flag, pi, pi_flag;
	ipc_bd_t *bdr, *bd;
	ipc_channel_us_t *ch_us;
	ipc_sh_buf_t *m_desc_virt;
	uint32_t buf_data_size;

	ch_us = ipc_priv->channels[channel_id];
#if DATAPATH_CHECKS
	if (!buf) {
		h_stats->ipc_ch_stats[channel_id].err_input_invalid++;
		return IPC_INPUT_INVALID;
	}

	if (!ipc_instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	ch = &(ipc_instance->ch_list[channel_id]);
#if DATAPATH_CHECKS
	if (!ipc_is_channel_configured(channel_id, ipc_priv)) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	md = &(ch->br_msg_desc.md);

	ci = md->ci;
	pi = ch_us->pi_g;

	pi_flag = IPC_GET_PI_FLAG(pi);
	pi = IPC_GET_PI_INDEX(pi);
	ci_flag = IPC_GET_CI_FLAG(ci);
	ci = IPC_GET_CI_INDEX(ci);

	pr_debug("%s before bd_ring_full: md %p pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u\r\n",
			__func__, md, pi, ci, pi_flag, ci_flag, md->ring_size);

	if (unlikely(ipc_is_bd_ring_full(ci, ci_flag, pi, pi_flag))) {
		ch_us->err_channel_full++;
		h_stats->ipc_ch_stats[channel_id].err_channel_full =
										ch_us->err_channel_full;
		return IPC_CH_FULL;
	}

	if (unlikely(ch_us->msg_desc_virt == NULL)) {
		md_bl = &(ch->br_bl_desc.md);
		ch_us->msg_desc_virt = calloc(md_bl->ring_size, sizeof(ipc_sh_buf_t *));
	}

	if (unlikely(ch_us->msg_desc_virt[pi] == NULL)) {
		bdr = ch->br_msg_desc.bd;
		bd = &bdr[pi];
		ch_us->msg_desc_virt[pi] =
			(ipc_sh_buf_t *)MODEM_P2V(bd->modem_ptr);
	}
	m_desc_virt = ch_us->msg_desc_virt[pi];
	buf_data_size = buf->data_size;

	m_desc_virt->mod_phys = buf->mod_phys;
	m_desc_virt->buf_size = buf->buf_size;
	m_desc_virt->data_size = buf_data_size;

	/* Move Producer Index forward */
	pi++;
	/* Flip the PI flag, if wrapping */
	if (unlikely(ch_us->msg_ring_size_g == 0))
		ch_us->msg_ring_size_g = md->ring_size;
	if (unlikely(ch_us->msg_ring_size_g == pi)) {
		pi = 0;
		pi_flag = pi_flag ? 0 : 1;
	}

	if (pi_flag)
		IPC_SET_PI_FLAG(pi);
	else
		IPC_RESET_PI_FLAG(pi);
	/* Wait for Data Copy and pi_flag update to complete
	 * before updating pi
	 */
	rte_mb();
	/* now update pi */
	md->pi = pi;
	ch_us->pi_g = pi;

	ch_us->num_of_msg_sent++;
	ch_us->total_msg_length += buf_data_size;
	h_stats->ipc_ch_stats[channel_id].num_of_msg_sent = ch_us->num_of_msg_sent;
	h_stats->ipc_ch_stats[channel_id].total_msg_length = ch_us->total_msg_length;

	pr_debug("%s exit: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u\r\n",
			__func__, pi, ci, pi_flag, ci_flag, md->ring_size);

	/* Only Event mode and polling mode is supported.
	 * NAPI mode is un-supported.
	 */
	if (ch->msi_valid == 1)
		ipc_channel_raise_msi(ipc_priv, ch->msi_value, MSI_TYPE_A);

	return IPC_SUCCESS;
}

/*
 * Not to be implemented as of now.
 */
int ipc_get_prod_buf_ptr(uint32_t channel_id, void **buf_ptr, ipc_t instance)
{
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	UNUSED(channel_id);
	UNUSED(buf_ptr);
	UNUSED(instance);

	h_stats->ipc_ch_stats[channel_id].err_not_implemented++;
	return IPC_NOT_IMPLEMENTED;
}

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

int ipc_get_msg_ptr(uint32_t channel_id,
		ipc_t instance,
		void **dst_buffer)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	ipc_bd_t *bdr, *bd;
	uint32_t ci, ci_flag, pi, pi_flag;
	ipc_channel_us_t *ch_us;

	ch_us = ipc_priv->channels[channel_id];
#if DATAPATH_CHECKS
	if (!ipc_instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	ch = &(ipc_instance->ch_list[channel_id]);
#if DATAPATH_CHECKS
	if (!ipc_is_channel_configured(channel_id, ipc_priv)) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	md = &(ch->br_msg_desc.md);
	ci = md->ci;
	pi = ch_us->pi_g;

	pi_flag = IPC_GET_PI_FLAG(pi);
	pi = IPC_GET_PI_INDEX(pi);
	ci_flag = IPC_GET_CI_FLAG(ci);
	ci = IPC_GET_CI_INDEX(ci);
	pr_debug("%s pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, r_size: %u\n",
			__func__, pi, ci, pi_flag, ci_flag, md->ring_size);

	if (unlikely(ipc_is_bd_ring_full(ci, ci_flag, pi, pi_flag))) {
		h_stats->ipc_ch_stats[channel_id].err_channel_full++;
		return IPC_CH_FULL;
	}

	bdr = ch->br_msg_desc.bd;
	bd = &bdr[pi];

	*dst_buffer = (void *)MODEM_P2V(bd->modem_ptr);

	return IPC_SUCCESS;
}

int ipc_send_msg_ptr(uint32_t channel_id,
		uint32_t len,
		ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t pi, pi_flag;
	ipc_bd_t *bdr, *bd;
	ipc_channel_us_t *ch_us;

	ch_us = ipc_priv->channels[channel_id];
#if DATAPATH_CHECKS
	if (!ipc_instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	ch = &(ipc_instance->ch_list[channel_id]);
	md = &(ch->br_msg_desc.md);
#if DATAPATH_CHECKS
	if (!ipc_is_channel_configured(channel_id, ipc_priv)) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	if (!len || (len > md->msg_size)) {
		h_stats->ipc_ch_stats[channel_id].err_input_invalid++;
		return IPC_INPUT_INVALID;
	}
	pi = ch_us->pi_g;
	pi_flag = IPC_GET_PI_FLAG(pi);
	pi = IPC_GET_PI_INDEX(pi);

	bdr = ch->br_msg_desc.bd;
	bd = &bdr[pi];
	bd->len = len;

	/* Move Producer Index forward */
	pi++;
	/* Flip the PI flag, if wrapping */
	if (unlikely(md->ring_size == pi)) {
		pi = 0;
		pi_flag = pi_flag ? 0 : 1;
	}

	if (pi_flag)
		IPC_SET_PI_FLAG(pi);
	else
		IPC_RESET_PI_FLAG(pi);

	md->pi = pi;
	ch_us->pi_g = pi;

	ch_us->num_of_msg_sent++;
	ch_us->total_msg_length += len;
	h_stats->ipc_ch_stats[channel_id].num_of_msg_sent = ch_us->num_of_msg_sent;
	h_stats->ipc_ch_stats[channel_id].total_msg_length = ch_us->total_msg_length;
	pr_debug("%s enter: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u\r\n",
			__func__, pi, IPC_GET_CI_INDEX(md->ci), pi_flag,
			IPC_GET_CI_FLAG(md->ci), md->ring_size);

	/* Only Event mode and polling mode is supported.
	 * NAPI mode is not supported.
	 */
	if (ch->msi_valid == 1)
		ipc_channel_raise_msi(ipc_priv, ch->msi_value, MSI_TYPE_A);

	return IPC_SUCCESS;
}

int ipc_send_msg(uint32_t channel_id,
		void *src,
		uint32_t len,
		ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t ci, ci_flag, pi, pi_flag;
	ipc_bd_t *bdr, *bd;
	uint64_t virt;
	ipc_channel_us_t *ch_us;

	ch_us = ipc_priv->channels[channel_id];
#if DATAPATH_CHECKS
	if (!src || !len) {
		h_stats->ipc_ch_stats[channel_id].err_input_invalid++;
		return IPC_INPUT_INVALID;
	}

	if (!ipc_instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	ch = &(ipc_instance->ch_list[channel_id]);
#if DATAPATH_CHECKS
	if (!ipc_is_channel_configured(channel_id, ipc_priv)) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	md = &(ch->br_msg_desc.md);
	ci = md->ci;
	pi = ch_us->pi_g;

	pi_flag = IPC_GET_PI_FLAG(pi);
	pi = IPC_GET_PI_INDEX(pi);
	ci_flag = IPC_GET_CI_FLAG(ci);
	ci = IPC_GET_CI_INDEX(ci);

	if (len > md->msg_size) {
		h_stats->ipc_ch_stats[channel_id].err_input_invalid++;
		return IPC_INPUT_INVALID;
	}

	pr_debug("%s before bd_ring_full: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u\r\n",
			__func__, pi, ci, pi_flag, ci_flag, md->ring_size);

	if (unlikely(ipc_is_bd_ring_full(ci, ci_flag, pi, pi_flag))) {
		ch_us->err_channel_full++;
		h_stats->ipc_ch_stats[channel_id].err_channel_full =
										ch_us->err_channel_full;
		return IPC_CH_FULL;
	}

	bdr = ch->br_msg_desc.bd;
	bd = &bdr[pi];

	virt = MODEM_P2V(bd->modem_ptr);
	ipc_memcpy((void *)(virt), src, len);
	bd->len = len;
	/* Move Producer Index forward */
	pi++;
	/* Flip the PI flag, if wrapping */
	if (unlikely(md->ring_size == pi)) {
		pi = 0;
		pi_flag = pi_flag ? 0 : 1;
	}

	if (pi_flag)
		IPC_SET_PI_FLAG(pi);
	else
		IPC_RESET_PI_FLAG(pi);

	/* Wait for Data Copy and pi_flag update to complete
	 * before updating pi
	 */
	rte_mb();
	md->pi = pi;
	ch_us->pi_g = pi;

	ch_us->num_of_msg_sent++;
	ch_us->total_msg_length += len;
	h_stats->ipc_ch_stats[channel_id].num_of_msg_sent = ch_us->num_of_msg_sent;
	h_stats->ipc_ch_stats[channel_id].total_msg_length = ch_us->total_msg_length;
	pr_debug("%s enter: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u\r\n",
			__func__, md->pi, md->ci, pi_flag, ci_flag, md->ring_size);

	/* Only Event mode and polling mode is supported.
	 * NAPI mode is not supported.
	 */
	if (ch->msi_valid == 1)
		ipc_channel_raise_msi(ipc_priv, ch->msi_value, MSI_TYPE_A);

	return IPC_SUCCESS;
}


/*
 * PTR channel is used to transfer RX TB from modem to host.
 * So this API will only be used by host to receive RX TB.
 */
int ipc_recv_ptr(uint32_t channel_id, void *dst, ipc_t instance)
{
	PR("here %s %d\n \n \n", __func__, __LINE__);
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t ci, ci_flag, pi, pi_flag;
	ipc_bd_t *bdr, *bd;
	uint64_t vaddr;
	ipc_channel_us_t *ch_us;

	ch_us = ipc_priv->channels[channel_id];
#if DATAPATH_CHECKS
	uint32_t msg_len;

	if (!ipc_instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	ch = &(ipc_instance->ch_list[channel_id]);
#if DATAPATH_CHECKS
	if (!ipc_is_channel_configured(channel_id, ipc_priv)) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	md = &(ch->br_msg_desc.md);
	pi = md->pi;
	ci = ch_us->ci_g;

	ci_flag = IPC_GET_CI_FLAG(ci);
	ci = IPC_GET_CI_INDEX(ci);
	pi_flag = IPC_GET_PI_FLAG(pi);
	pi = IPC_GET_PI_INDEX(pi);
	if (ipc_is_bd_ring_empty(ci, ci_flag, pi, pi_flag)) {
		ch_us->err_channel_empty++;
		h_stats->ipc_ch_stats[channel_id].err_channel_empty =
									ch_us->err_channel_empty;
		return IPC_CH_EMPTY;
	}

	pr_debug("%s: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u\r\n",
		__func__, pi, ci, pi_flag, ci_flag, md->ring_size);

	bdr = ch->br_msg_desc.bd;
	bd = &bdr[ci];
	/* Move Consumer Index forward */
	ci++;
	/* Flip the CI flag, if wrapping */
	if (unlikely(ch_us->msg_ring_size_g == ci)) {
		ci = 0;
		ci_flag = ci_flag ? 0 : 1;
	}

	if (ci_flag)
		IPC_SET_CI_FLAG(ci);
	else
		IPC_RESET_CI_FLAG(ci);

	vaddr = join_va2_64(bd->host_virt_h, bd->host_virt_l);

#if DATAPATH_CHECKS
	msg_len = bd->len;
	if (msg_len > md->msg_size || msg_len == 0) {
		printf("%d %s ERROR size=%x\n\n",__LINE__, __func__, msg_len);
		return IPC_CH_INVALID;
	}
#endif
	memcpy(dst, (void *)vaddr, sizeof(ipc_sh_buf_t));
	/* Update In flight buffer status for IPC recovery purpose*/
	ipc_priv->channels[channel_id]->bufs_inflight[((ipc_sh_buf_t *)dst)->cookie] = IPC_TRUE;

	PR("%d %s size=%x\n\n", __LINE__, __func__, bd->len);
	PR("%d %s dst->host_virt_h=%x dst->host_virt_l=%x dst->mod_phys=%x\n\n",
	   __LINE__, __func__, ((ipc_sh_buf_t *)dst)->host_virt_h,
	   ((ipc_sh_buf_t *)dst)->host_virt_l, ((ipc_sh_buf_t *)dst)->mod_phys);

	/* update the ci now */
	md->ci = ci;
	ch_us->ci_g = ci;
	/* Update Stats */
	ch_us->num_of_msg_recved++;
	ch_us->total_msg_length += ((ipc_sh_buf_t *)dst)->data_size;
	h_stats->ipc_ch_stats[channel_id].num_of_msg_recved = ch_us->num_of_msg_recved;
	h_stats->ipc_ch_stats[channel_id].total_msg_length = ch_us->total_msg_length;
	pr_debug("%s exit: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u\r\n",
		__func__, md->pi, md->ci, pi_flag, ci_flag, md->ring_size);

	pr_debug("%s %d %s\n\n", __func__, __LINE__, (char *)vaddr);
	return IPC_SUCCESS;
}

int ipc_recv_msg(uint32_t channel_id, void *dst,
		uint32_t *len, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t msg_len;
	uint32_t ci, ci_flag, pi, pi_flag;
	uint64_t vaddr;
	ipc_bd_t *bdr, *bd;
	ipc_channel_us_t *ch_us;

	ch_us = ipc_priv->channels[channel_id];
#if DATAPATH_CHECKS
	if (!dst || !len) {
		h_stats->ipc_ch_stats[channel_id].err_input_invalid++;
		return IPC_INPUT_INVALID;
	}

	if (!ipc_instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	ch = &(ipc_instance->ch_list[channel_id]);
#if DATAPATH_CHECKS
	if (!ipc_is_channel_configured(channel_id, ipc_priv)) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	md = &(ch->br_msg_desc.md);
	pi = md->pi;
	ci = ch_us->ci_g;

	ci_flag = IPC_GET_CI_FLAG(ci);
	ci = IPC_GET_CI_INDEX(ci);
	pi_flag = IPC_GET_PI_FLAG(pi);
	pi = IPC_GET_PI_INDEX(pi);
	if (ipc_is_bd_ring_empty(ci, ci_flag, pi, pi_flag)) {
		ch_us->err_channel_empty++;
		h_stats->ipc_ch_stats[channel_id].err_channel_empty =
									ch_us->err_channel_empty;
		return IPC_CH_EMPTY;
	}
	pr_debug("%s: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u\r\n",
		__func__, pi, ci, pi_flag, ci_flag, md->ring_size);

	bdr = ch->br_msg_desc.bd;
	bd = &bdr[ci];
	/* Move Consumer Index forward */
	ci++;
	/* Flip the CI flag, if wrapping */
	if (unlikely(md->ring_size == ci)) {
		ci = 0;
		ci_flag = ci_flag ? 0 : 1;
	}

	if (ci_flag)
		IPC_SET_CI_FLAG(ci);
	else
		IPC_RESET_CI_FLAG(ci);

	md->ci = ci;
	ch_us->ci_g = ci;
	msg_len = bd->len;
#if DATAPATH_CHECKS
	if (msg_len > md->msg_size) {
		h_stats->ipc_ch_stats[channel_id].err_input_invalid++;
		return IPC_INPUT_INVALID;
	}
#endif

	PR("%d %s\n\n",__LINE__, __func__);
	vaddr = join_va2_64(bd->host_virt_h, bd->host_virt_l);
	ipc_memcpy(dst, (void *)(vaddr), msg_len);
	PR("%d %s\n\n",__LINE__, __func__);
	*len = msg_len;

	ch_us->num_of_msg_recved++;
	ch_us->total_msg_length += msg_len;
	h_stats->ipc_ch_stats[channel_id].num_of_msg_recved = ch_us->num_of_msg_recved;
	h_stats->ipc_ch_stats[channel_id].total_msg_length = ch_us->total_msg_length;
	pr_debug("%s exit: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u\r\n",
		__func__, pi, ci, pi_flag, ci_flag, md->ring_size);

	return 0;
}

int ipc_recv_msg_ptr(uint32_t channel_id, void **dst_buffer,
		uint32_t *len, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	ipc_bd_t *bdr, *bd;
	uint64_t vaddr;
	uint32_t ci, ci_flag, pi, pi_flag;
	ipc_channel_us_t *ch_us;

	ch_us = ipc_priv->channels[channel_id];
#if DATAPATH_CHECKS
	if (!dst_buffer || !len) {
		h_stats->ipc_ch_stats[channel_id].err_input_invalid++;
		return IPC_INPUT_INVALID;
	}

	if (!ipc_instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	ch = &(ipc_instance->ch_list[channel_id]);
#if DATAPATH_CHECKS
	if (!ipc_is_channel_configured(channel_id, ipc_priv)) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	md = &(ch->br_msg_desc.md);
	pi = md->pi;
	ci = ch_us->ci_g;

	ci_flag = IPC_GET_CI_FLAG(ci);
	ci = IPC_GET_CI_INDEX(ci);
	pi_flag = IPC_GET_PI_FLAG(pi);
	pi = IPC_GET_PI_INDEX(pi);
	if (ipc_is_bd_ring_empty(ci, ci_flag, pi, pi_flag)) {
		ch_us->err_channel_empty++;
		h_stats->ipc_ch_stats[channel_id].err_channel_empty =
									ch_us->err_channel_empty;
		return IPC_CH_EMPTY;
	}

	pr_debug("%s: pi: %u, ci: %u, pi_flag: %u, ci_flag: %u, ring size: %u\r\n",
		__func__, pi, ci, pi_flag, ci_flag, md->ring_size);

	bdr = ch->br_msg_desc.bd;
	bd = &bdr[ci];
	/* host_phys and virt was done in configure*/
	PR("%d %s\n\n",__LINE__, __func__);
	vaddr = join_va2_64(bd->host_virt_h, bd->host_virt_l);
	*dst_buffer = (void *)vaddr;
	*len = bd->len;

	ch_us->num_of_msg_recved++;
	ch_us->total_msg_length += bd->len;
	h_stats->ipc_ch_stats[channel_id].num_of_msg_recved = ch_us->num_of_msg_recved;
	h_stats->ipc_ch_stats[channel_id].total_msg_length = ch_us->total_msg_length;
	/* ipc_set_consumed_status needed to called by user*/
	/* as occupied and ci is not decremented */

	return IPC_SUCCESS;
}

int ipc_set_produced_status(uint32_t channel_id, ipc_t instance)
{
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	UNUSED(channel_id);
	UNUSED(instance);

	h_stats->ipc_ch_stats[channel_id].err_not_implemented++;
	return IPC_NOT_IMPLEMENTED;
}

int ipc_set_consumed_status(uint32_t channel_id, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t ci, ci_flag;
	ipc_channel_us_t *ch_us;

	ch_us = ipc_priv->channels[channel_id];
#if DATAPATH_CHECKS
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);

	if (!ipc_instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	ch = &(ipc_instance->ch_list[channel_id]);
#if DATAPATH_CHECKS
	if (!ipc_is_channel_configured(channel_id, ipc_priv)) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}
#endif

	md = &(ch->br_msg_desc.md);
	ci = ch_us->ci_g;

	ci_flag = IPC_GET_CI_FLAG(ci);
	ci = IPC_GET_CI_INDEX(ci);
	pr_debug("%s: ci: %u, ci_flag: %u, ring size: %u\r\n",
		__func__, ci, ci_flag, md->ring_size);
	ci++;
	/* Flip the CI flag, if wrapping */
	if (unlikely(md->ring_size == ci)) {
		ci = 0;
		ci_flag = ci_flag ? 0 : 1;
	}
	if (ci_flag)
		IPC_SET_CI_FLAG(ci);
	else
		IPC_RESET_CI_FLAG(ci);

	md->ci = ci;
	ch_us->ci_g = ci;
	pr_debug("%s: ci: %u, ci_flag: %u, ring size: %u\r\n",
		__func__, ci, ci_flag, md->ring_size);

	return IPC_SUCCESS;
}

/* TODO: Implement below API for Geul */
int ipc_chk_recv_status(uint64_t *bmask, ipc_t instance)
{
	UNUSED(bmask);
	UNUSED(instance);

	return IPC_NOT_IMPLEMENTED;
}

int ipc_shutdown(ipc_t ipc)
{
	int i;
	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)ipc;

	/* close dev/geulipc */
	close(ipc_priv->dev_ipc);
	close(ipc_priv->dev_mem);

	/* free memory */
	for (i = 0; i < IPC_MAX_CHANNEL_COUNT; i++)
		free(ipc_priv->channels[i]);

	/* free ipc */
	free(ipc_priv);
	return IPC_SUCCESS;
}

#if DUAL_HUGEPAGE_SUPPORT_ENABLED
int
map_second_hugepage_addr(ipc_t instance, mem_range_t hugepgstart)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_pci_map_query_t pci_map_query;
	size_t size;
	int ret;

	PR("Creating hugepage mapping for second hugepage\n");
	PR("hugepg input %lx %p %x\n", hugepgstart.host_phys,
		hugepgstart.host_vaddr, hugepgstart.size);

	ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_QUERY_PCI_MAP,
		    &pci_map_query);
	if (ret) {
		PR("IOCTL_GUL_IPC_QUERY_PCI_MAP ioctl failed\n");
		return 0;
	}

	if (!pci_map_query.mem_avail) {
		PR("No memory available for mapping\n");
		return 0;
	}

	size = RTE_MIN(pci_map_query.mem_avail, hugepgstart.size);

	/* Map last portion of the hugepage memory as in DPDK memory
	 * allocation from hugepage starts from the end.
	 */
	ipc_priv->sys_map.hugepg_start.host_phys = hugepgstart.host_phys;
	ipc_priv->sys_map.hugepg_start.size = size;

	ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_GET_PCI_MAP,
		    &ipc_priv->sys_map.hugepg_start);
	if (ret) {
		PR("IOCTL_GUL_IPC_GET_PCI_MAP ioctl failed\n");
		return 0;
	}

	HUGEPG_START(ipc_priv, 1).host_phys = hugepgstart.host_phys;
	HUGEPG_START(ipc_priv, 1).host_vaddr = hugepgstart.host_vaddr;
	HUGEPG_START(ipc_priv, 1).modem_phys =
			ipc_priv->sys_map.hugepg_start.modem_phys;
	HUGEPG_START(ipc_priv, 1).size = size;

	return size;
}
#endif

ipc_t ipc_host_init(uint32_t instance_id,
		struct rte_mempool *rtemempool[MAX_MEM_POOL_COUNT],
		mem_range_t hugepgstart, int *err)
{
	ipc_userspace_t *ipc_priv;
	ipc_instance_t *instance_bk;
	ipc_channel_us_t *ipc_priv_ch;
	int ret, dev_ipc, dev_mem, i;
	ipc_metadata_t *ipc_md;
	struct gul_hif *mhif;
	uint32_t phy_align = 0;
	struct gul_ipc_stats *h_stats;

	ipc_priv = malloc(sizeof(ipc_userspace_t));
	if (ipc_priv == NULL) {
		ipc_fill_errorcode(err, IPC_MEM_INVALID);
		return NULL;
	}
	memset(ipc_priv, 0, sizeof(ipc_userspace_t));

	instance_bk = malloc(sizeof(ipc_instance_t));
	if (instance_bk == NULL) {
		ipc_fill_errorcode(err, IPC_MEM_INVALID);
		free(ipc_priv);
		return NULL;
	}
	memset(instance_bk, 0, sizeof(ipc_instance_t));
	ipc_priv->instance_bk = instance_bk;

	for (i = 0; i < IPC_MAX_CHANNEL_COUNT; i++) {
		ipc_priv_ch = malloc(sizeof(ipc_channel_us_t));
		if (ipc_priv_ch == NULL) {
			ipc_fill_errorcode(err, IPC_MALLOC_FAIL);
			return NULL;
		}
		memset(ipc_priv_ch, 0, sizeof(ipc_channel_us_t));
		ipc_priv_ch->eventfd = -1;
		ipc_priv->channels[i] = ipc_priv_ch;
	}
	dev_mem = open_devmem();
	if (dev_mem < 0) {
		ipc_fill_errorcode(err, IPC_OPEN_FAIL);
		goto free_mem;
	}

	dev_ipc = open_devipc(instance_id);
	if (dev_ipc < 0) {
		close(dev_mem);
		ipc_fill_errorcode(err, IPC_OPEN_FAIL);
		goto free_mem;
	}

	ipc_priv->instance_id = instance_id;
	ipc_priv->dev_ipc = dev_ipc;
	ipc_priv->dev_mem = dev_mem;

	PR("hugepg input %lx %p %x\n", hugepgstart.host_phys , hugepgstart.host_vaddr, hugepgstart.size);

	ipc_priv->sys_map.hugepg_start.host_phys = hugepgstart.host_phys;
	ipc_priv->sys_map.hugepg_start.size = hugepgstart.size;
	/* Send IOCTL to get system map */
	/* Send IOCTL to put hugepg_start map */
	ret = ioctl(dev_ipc, IOCTL_GUL_IPC_GET_SYS_MAP, &ipc_priv->sys_map);
	 if (ret) {
		ipc_fill_errorcode(err, IPC_IOCTL_FAIL);
		goto fail_handle;
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
			ipc_fill_errorcode(err, IPC_IOCTL_FAIL);
			goto fail_handle;
		}
	}

	phy_align = (ipc_priv->sys_map.mhif_start.host_phys % 0x1000);
	ipc_priv->mhif_start.host_vaddr =
		mmap(0, ipc_priv->sys_map.mhif_start.size + phy_align, (PROT_READ | \
			PROT_WRITE), MAP_SHARED, dev_mem, \
			(ipc_priv->sys_map.mhif_start.host_phys - phy_align));
	if (ipc_priv->mhif_start.host_vaddr == MAP_FAILED) {
		 perror("MAP failed:");
		ipc_fill_errorcode(err, IPC_MMAP_FAIL);
		goto fail_handle;
	} else
		ipc_priv->mhif_start.host_vaddr = (void *)
			((uint64_t)(ipc_priv->mhif_start.host_vaddr) + phy_align);

	phy_align = (ipc_priv->sys_map.peb_start.host_phys % 0x1000);
	ipc_priv->peb_start.host_vaddr =
		mmap(0, ipc_priv->sys_map.peb_start.size + phy_align, (PROT_READ | \
			PROT_WRITE), MAP_SHARED, dev_mem, \
			(ipc_priv->sys_map.peb_start.host_phys - phy_align));
	if (ipc_priv->peb_start.host_vaddr == MAP_FAILED) {
		perror("MAP failed:");
		ipc_fill_errorcode(err, IPC_MMAP_FAIL);
		goto fail_handle;
	} else
		ipc_priv->peb_start.host_vaddr = (void *)
			((uint64_t)(ipc_priv->peb_start.host_vaddr) + phy_align);

	phy_align = (ipc_priv->sys_map.modem_ccsrbar.host_phys % 0x1000);
	ipc_priv->modem_ccsrbar.host_vaddr =
		mmap(0, ipc_priv->sys_map.modem_ccsrbar.size + phy_align, (PROT_READ | \
			PROT_WRITE), MAP_SHARED, dev_mem, \
			(ipc_priv->sys_map.modem_ccsrbar.host_phys - phy_align));
	if (ipc_priv->modem_ccsrbar.host_vaddr == MAP_FAILED) {
		perror("MAP failed:");
		ipc_fill_errorcode(err, IPC_MMAP_FAIL);
		goto fail_handle;
	} else
		ipc_priv->modem_ccsrbar.host_vaddr = (void *)
			((uint64_t)(ipc_priv->modem_ccsrbar.host_vaddr) + phy_align);

	HUGEPG_START(ipc_priv, 0).host_phys = hugepgstart.host_phys;
	HUGEPG_START(ipc_priv, 0).host_vaddr = hugepgstart.host_vaddr;
	HUGEPG_START(ipc_priv, 0).size = ipc_priv->sys_map.hugepg_start.size;
	HUGEPG_START(ipc_priv, 0).modem_phys = ipc_priv->sys_map.hugepg_start.modem_phys;

	ipc_priv->mhif_start.host_phys = ipc_priv->sys_map.mhif_start.host_phys;
	ipc_priv->mhif_start.size = ipc_priv->sys_map.mhif_start.size;
	ipc_priv->peb_start.host_phys = ipc_priv->sys_map.peb_start.host_phys;
	ipc_priv->peb_start.size = ipc_priv->sys_map.peb_start.size;
	ipc_priv->modem_ccsrbar.host_phys = ipc_priv->sys_map.modem_ccsrbar.host_phys;
	ipc_priv->modem_ccsrbar.size = ipc_priv->sys_map.modem_ccsrbar.size;

	/*These handle to be used create dpdk pool of 2K 16k and 128k */
	ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_2K] = rtemempool[0];
	ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_4K] = rtemempool[1];
	ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_128K] = rtemempool[2];
	ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_SH_BUF] = rtemempool[3];
	ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_R2] = rtemempool[4];

	PR("peb %lx %p %x\n", ipc_priv->peb_start.host_phys , ipc_priv->peb_start.host_vaddr, ipc_priv->peb_start.size);
	PR("ccsr %lx %p %x\n", ipc_priv->modem_ccsrbar.host_phys , ipc_priv->modem_ccsrbar.host_vaddr, ipc_priv->modem_ccsrbar.size);
	PR("hugepg 1 %lx %p %x\n", HUGEPG_START(ipc_priv, 0).host_phys, HUGEPG_START(ipc_priv, 0).host_vaddr,
		HUGEPG_START(ipc_priv, 0).size);
#if DUAL_HUGEPAGE_SUPPORT_ENABLED
	PR("hugepg 2 %lx %p %x\n", HUGEPG_START(ipc_priv, 1).host_phys, HUGEPG_START(ipc_priv, 1).host_vaddr,
		HUGEPG_START(ipc_priv, 1).size);
#endif
	PR("mhif %lx %p %x\n", ipc_priv->mhif_start.host_phys , ipc_priv->mhif_start.host_vaddr, ipc_priv->mhif_start.size);
	mhif = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;
	h_stats = get_gul_ipc_stats(instance_bk);

	/* offset is from start of PEB */
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->peb_start.host_vaddr + mhif->ipc_regs.ipc_mdata_offset);

	if (sizeof(ipc_metadata_t) !=
			mhif->ipc_regs.ipc_mdata_size) {
		ipc_fill_errorcode(err, IPC_MD_SZ_MISS_MATCH);
		h_stats->err_md_sz_mismatch++;
		PR("\n ipc_metadata_t =%lx, mhif->ipc_regs.ipc_mdata_size=%x\n", sizeof(ipc_metadata_t), mhif->ipc_regs.ipc_mdata_size);
		PR("--> mhif->ipc_regs.ipc_mdata_offset= %x\n", mhif->ipc_regs.ipc_mdata_offset);
		PR("gul_hif size=%lx, \n", sizeof(struct gul_hif));
		//return NULL;
	}

	ipc_priv->instance = (ipc_instance_t *)(&ipc_md->instance_list[GEUL_IPC_INSTANCE_ID]);
#if 0
	ret = get_channels_info(ipc_priv, instance_id);
	if (ret) {
		if(!err)
			*err = ERROR_IOCTL;
		return NULL;
	}
#endif

	PR("finish host init\n");
	ipc_fill_errorcode(err, IPC_SUCCESS);
	return ipc_priv;

fail_handle:
	close(dev_mem);
	close(dev_ipc);
free_mem:
	free(ipc_priv->instance_bk);
	free(ipc_priv);
	return NULL;
}

static uint32_t ipc_get_free_irq (void)
{
	if (ipc_last_assigned_irq == HOST_MSI_MAX_IRQ_COUNT)
		return HOST_MSI_MAX_IRQ_COUNT;
	else
		return ipc_last_assigned_irq++;
}

int ipc_configure_channel(uint32_t channel_id, uint32_t depth,
			  ipc_ch_type_t channel_type, uint32_t msg_size,
			  uint8_t en_event, ipc_t instance)
{

	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);
	ipc_ch_t *ch;
	void *vaddr;
	uint32_t i = 0;
	int ret, event_fd;
	ipc_channel_us_t *ch_us;

	ch_us = ipc_priv->channels[channel_id];

	PR("%x %p\n", ipc_instance->initialized, ipc_priv->instance);
	pr_debug("%s: channel: %u, depth: %u, type: %d, msg size: %u\r\n",
			__func__, channel_id, depth, channel_type, msg_size);
	if (!ipc_priv->instance || !ipc_instance->initialized) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->err_input_invalid++;
		return IPC_CH_INVALID;
	}

	if (depth > IPC_MAX_DEPTH) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}

	ch = &(ipc_instance->ch_list[channel_id]);

#if 1
	if (ipc_is_channel_configured(channel_id, ipc_priv)) {
		printf("WARNING: [%s]: Channel already configured\n NOT configuring again\n",__func__);
		return IPC_SUCCESS;
	}
#endif
	pr_debug("%s: channel: %u, depth: %u, type: %d, msg size: %u\r\n",
			__func__, channel_id, depth, channel_type, msg_size);

	/* Start init of channel */
	ch->ch_type = channel_type;
	ch->ch_id = channel_id; /* May not be required since modem does this */
#if 0
	if (ch->bl_initialized == 1) {
		printf("WARNING: [%s]: Channel already configured\n NOT configuring again\n",__func__);
		return IPC_SUCCESS;
	}
#endif

	ch_us->msg_ring_size_g = depth;
	ch_us->bl_ring_size_g = depth;

	if (channel_type == IPC_CH_MSG) {
		ch->br_msg_desc.md.ring_size = depth;
		ch->br_msg_desc.md.pi = 0;
		ch->br_msg_desc.md.ci = 0;
		ch->br_msg_desc.md.msg_size = msg_size;
	//	ch->br_msg_desc.bd[i].len = 0; /* not sure use of this len */
		for (i = 0; i < depth; i++) {
			if (msg_size == SIZE_2K) {
				ret = rte_mempool_get(ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_2K], &vaddr);
				if (ret < 0) {
					h_stats->ipc_ch_stats[channel_id].err_host_buf_alloc_fail++;
					return IPC_HOST_BUF_ALLOC_FAIL;
				}
			} else if (msg_size == SIZE_4K) {
				ret = rte_mempool_get(ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_4K], &vaddr);
				if (ret < 0) {
					h_stats->ipc_ch_stats[channel_id].err_host_buf_alloc_fail++;
					return IPC_HOST_BUF_ALLOC_FAIL;
				}
			}
			/* Only offset now */
			ch->br_msg_desc.bd[i].modem_ptr = get_hugepg_offset(ipc_priv, vaddr);
		//	ch->br_msg_desc.bd[i].modem_ptr = 0xdeadbeef;
		//	ch->br_msg_desc.bd[i].host_phy_l = 0xdeafbee1;
		//	ch->br_msg_desc.bd[i].host_phy_h = 0xdeafbee2;
			ch->br_msg_desc.bd[i].host_virt_l = SPLIT_VA32_L(vaddr);
			ch->br_msg_desc.bd[i].host_virt_h = SPLIT_VA32_H(vaddr);
			/* Not sure use of this len may be for CRC*/
			ch->br_msg_desc.bd[i].len = 0;
		}
		ch->bl_initialized = 1;
	}

	if (channel_type == IPC_CH_PTR) {
		/* do_dpdk_alloc using rtemempool;
		and fill in ipc_sh_buf_t[];
		translate using hugepgstart and hugepgtart.modem
		*/
		/* Fill msg */
		ch->br_msg_desc.md.ring_size = depth;
		ch->br_msg_desc.md.pi = 0;
		ch->br_msg_desc.md.ci = 0;
		ch->br_msg_desc.md.msg_size = sizeof(ipc_sh_buf_t);
		ch->br_msg_desc.bd[i].len = sizeof(ipc_sh_buf_t);

		/* Fill bl */
		ch->br_bl_desc.md.ring_size = depth;
		ch->br_bl_desc.md.pi = 0;
		ch->br_bl_desc.md.ci = 0;
		ch->br_bl_desc.md.msg_size = msg_size; /* 128K */
		for (i = 0; i < depth; i++) {
			/* Fill bl ring */
			ret = rte_mempool_get(ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_128K], &vaddr);
			if (ret < 0) {
				h_stats->ipc_ch_stats[channel_id].err_host_buf_alloc_fail++;
				return IPC_HOST_BUF_ALLOC_FAIL;
			}

			ch->br_bl_desc.bd[i].mod_phys = get_hugepg_offset(ipc_priv, vaddr);
			ch->br_bl_desc.bd[i].host_virt_l = SPLIT_VA32_L(vaddr);
			ch->br_bl_desc.bd[i].host_virt_h = SPLIT_VA32_H(vaddr);
			//ch->br_bl_desc.bd[i].host_phys = HOST_V2P(ipc_priv, vaddr); /* Should be unused */
			/* ch->br_bl_desc.bd[i].buf_size should be unused */
			/* ch->br_bl_desc.bd[i].data_size to be filled by producer */
			ch->br_bl_desc.bd[i].cookie = i; /* Store index */

			/* Fill msg ring */
			ret = rte_mempool_get(ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_SH_BUF], &vaddr);
			if (ret < 0) {
				h_stats->ipc_ch_stats[channel_id].err_host_buf_alloc_fail++;
				return IPC_HOST_BUF_ALLOC_FAIL;
			}

			ch->br_msg_desc.bd[i].modem_ptr = get_hugepg_offset(ipc_priv, vaddr);
			ch->br_msg_desc.bd[i].host_virt_l = SPLIT_VA32_L(vaddr);
			ch->br_msg_desc.bd[i].host_virt_h = SPLIT_VA32_H(vaddr);
			/* ch->br_msg_desc.bd[i].host_phy = HOST_V2P(ipc_priv, vaddr); DO not access now bus error. Should be used to fetch ipc_sh_buf_t*/
		}
		ch->bl_initialized = 1;
	}

	if (en_event) {
		ipc_eventfd_t efd_args;

		/* Open an Event FD to get events from kernel.*/
		event_fd = eventfd(0, EFD_NONBLOCK);
		if (event_fd < 0) {
			perror("Eventfd allocation Failed: ");
			h_stats->ipc_ch_stats[channel_id].err_efd_reg_fail++;
			return IPC_EVENTFD_FAIL;
		}
		PR("Eventfd %d for Channel ID %d\n", event_fd, channel_id);
		ipc_priv->channels[channel_id]->eventfd = event_fd;

		/* Send IOCTL to register this event_fd with kernel*/
		efd_args.efd = event_fd;
		efd_args.ipc_channel_num = channel_id;
		ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_CHANNEL_REGISTER, &efd_args);
		if (ret) {
			printf("IPC_CHANNEL_REGISTER failed for Channel ID %d\n", channel_id);
			h_stats->ipc_ch_stats[channel_id].err_efd_reg_fail++;
			return IPC_EVENTFD_FAIL;
		}
		/* Store the received MSI Value */
		ch->msi_value = efd_args.msi_value;
		ch->msi_valid = en_event;

		PR("got MSI %d for Channel ID %deventfd %d \n",
			efd_args.msi_value, channel_id, event_fd);

	} else {
		ipc_priv->channels[channel_id]->eventfd = -1;
		ch->msi_valid = 0;
	}
	ipc_mark_channel_as_configured(channel_id, ipc_priv->instance);
	/* Take Backup */
	memcpy(ipc_priv->instance_bk, ipc_priv->instance, sizeof(ipc_instance_t));
	PR("finish configure\n");
	return IPC_SUCCESS;

}

int32_t ipc_get_eventfd(uint32_t channel_id, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)instance;
	return ipc_priv->channels[channel_id]->eventfd;
}

void ipc_channel_set_msi_valid(uint32_t channel_id, uint32_t msi_valid_val,
				   ipc_t instance)
{
	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	ipc_ch_t *ch;

	ch = &(ipc_instance->ch_list[channel_id]);
	ch->msi_valid = msi_valid_val;
	/* Following logic is required one time per channel
	 * during initialization of L2-->L1 channels.
	 */
	if (ch->msi_value == 0) {
		ch->msi_value = ipc_get_free_irq();
		/* Back up */
		ipc_priv->instance_bk->ch_list[channel_id].msi_valid =
							msi_valid_val;
		ipc_priv->instance_bk->ch_list[channel_id].msi_value =
							ch->msi_value;
	}
}

void ipc_prep_to_recover(ipc_t ipc_handle)
{
	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)ipc_handle;
	ipc_channel_us_t *ipc_priv_ch;
	int i, ret;

	for (i = 0; i < IPC_MAX_CHANNEL_COUNT; i++) {
		/* Only handle configured channels */
		if (!ipc_is_channel_configured(i, ipc_handle))
			continue;

		ipc_priv_ch = ipc_priv->channels[i];
		if (ipc_priv_ch->eventfd != -1) {
			ipc_eventfd_t efd_args;

			pr_debug("%s: De-Registering Event fd %d  for ch %d \n",
						__func__, ipc_priv_ch->eventfd, i);
			/* Send IOCTL to de-register this event_fd with kernel*/
			efd_args.efd = ipc_priv_ch->eventfd;
			efd_args.ipc_channel_num = i;
			ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_CHANNEL_DEREGISTER, &efd_args);
			if (ret) {
				pr_debug("IPC_CHANNEL_DEREGISTER failed for Channel ID %d\n", i);
			}
		}

		ipc_priv_ch->ci_g = 0;
		ipc_priv_ch->pi_g = 0;
		ipc_priv_ch->num_of_msg_recved = 0;
		ipc_priv_ch->num_of_msg_sent = 0;
		ipc_priv_ch->total_msg_length = 0;
		ipc_priv_ch->err_channel_empty = 0;
		ipc_priv_ch->err_channel_full = 0;
	}
	close(ipc_priv->dev_mem);
	close(ipc_priv->dev_ipc);
	pr_debug("%s: ----- IPC is prepared for L1 recovery ----\n", __func__);
}

static inline void handle_inflight_bufs(ipc_bd_ring_bl_t *bl, uint8_t *bufs_inflight)
{
	ipc_br_md_t *md = &bl->md;
	int i, sort_idx;

	sort_idx = 0;
	for (i = 0; i < IPC_MAX_DEPTH; i++) {
		if (bufs_inflight[i] == IPC_FALSE)
			continue;

		/* if sort_idx is at same location do nothing */
		if (i == sort_idx) {
			sort_idx++;
			continue;
		}
		/* Else replace current in use buffer with free one.
		 * Swapping is not required as duplicate buffer will
		 * be replaced by actual inflight buffer later on.
		 */
		bl->bd[i] = bl->bd[sort_idx];
		sort_idx++;
	}

	/* Now we have empty spaces in start for all inflight buffers,
	 * update the pi and ci accordingly
	 */

	if (sort_idx) {
		uint32_t ci, ci_flag = 0;

		/* sort_idx can go max upto IPC_MAX_DEPTH */
		ci = sort_idx % IPC_MAX_DEPTH;
		if (ci == 0)
			ci_flag = 1; /* Ring is Full */

		if (ci_flag)
			IPC_SET_CI_FLAG(ci);
		else
			IPC_RESET_CI_FLAG(ci);
		/* Update now */
		md->ci = ci;
	}
	printf("In-flight Buffers are %d pi %d ci %d ci_flag %d\n",
		sort_idx, IPC_GET_PI_INDEX(md->pi), IPC_GET_CI_INDEX(md->ci),
		IPC_GET_CI_FLAG(md->ci));
}

int32_t ipc_restore_cfg(ipc_t ipc_handle)
{
	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)ipc_handle;
	struct gul_ipc_stats *h_stats;
	ipc_channel_us_t *ipc_priv_ch;
	ipc_instance_t *instance, *instance_bk;
	int ret, dev_ipc, dev_mem, i;
	ipc_metadata_t *ipc_md;
	struct gul_hif *mhif;

	dev_mem = open_devmem();
	if (dev_mem < 0) {
		pr_debug("%s: open_devmem fail \n", __func__);
		return IPC_OPEN_FAIL;
	} else
		ipc_priv->dev_mem = dev_mem;

	dev_ipc = open_devipc(ipc_priv->instance_id);
	if (dev_ipc < 0) {
		pr_debug("%s: open_devipc fail \n", __func__);
		return IPC_OPEN_FAIL;
	} else
		ipc_priv->dev_ipc = dev_ipc;

	ipc_priv->sys_map.hugepg_start.modem_phys = 0;

	/* Send IOCTL to get system map */
	ret = ioctl(dev_ipc, IOCTL_GUL_IPC_GET_SYS_MAP, &ipc_priv->sys_map);
	 if (ret)
		return IPC_IOCTL_FAIL;

	/*
	 *  Backward compatibility. Huge page mapping done with CCSR mapping,
	 *  skip below code.
	 */
	if (!ipc_priv->sys_map.hugepg_start.modem_phys) {
		/* Send IOCTL to put hugepg_start map */
		ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_GET_PCI_MAP,
			    &ipc_priv->sys_map.hugepg_start);
		if (ret)
			return IPC_IOCTL_FAIL;
	}

	HUGEPG_START(ipc_priv, 0).modem_phys =
			ipc_priv->sys_map.hugepg_start.modem_phys;

	ipc_priv->mhif_start.host_phys = ipc_priv->sys_map.mhif_start.host_phys;
	ipc_priv->mhif_start.size = ipc_priv->sys_map.mhif_start.size;
	ipc_priv->peb_start.host_phys = ipc_priv->sys_map.peb_start.host_phys;
	ipc_priv->peb_start.size = ipc_priv->sys_map.peb_start.size;

	PR("peb %lx %p %x\n", ipc_priv->peb_start.host_phys, ipc_priv->peb_start.host_vaddr, ipc_priv->peb_start.size);
	PR("hugepg0 %lx %p %x\n", HUGEPG_START(ipc_priv, 0).host_phys, HUGEPG_START(ipc_priv, 0).host_vaddr, HUGEPG_START(ipc_priv, 0).size);
#if DUAL_HUGEPAGE_SUPPORT_ENABLED
	PR("hugepg1 %lx %p %x\n", HUGEPG_START(ipc_priv, 1).host_phys, HUGEPG_START(ipc_priv, 1).host_vaddr, HUGEPG_START(ipc_priv, 1).size);
#endif
	PR("mhif %lx %p %x\n", ipc_priv->mhif_start.host_phys, ipc_priv->mhif_start.host_vaddr, ipc_priv->mhif_start.size);
	mhif = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;
	h_stats = get_gul_ipc_stats(ipc_priv->instance_bk);

	/* offset is from start of PEB */
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->peb_start.host_vaddr + mhif->ipc_regs.ipc_mdata_offset);

	if (sizeof(ipc_metadata_t) !=
			mhif->ipc_regs.ipc_mdata_size) {
		h_stats->err_md_sz_mismatch++;
		PR("\n ipc_metadata_t =%lx, mhif->ipc_regs.ipc_mdata_size=%x\n", sizeof(ipc_metadata_t), mhif->ipc_regs.ipc_mdata_size);
		PR("--> mhif->ipc_regs.ipc_mdata_offset= %x\n", mhif->ipc_regs.ipc_mdata_offset);
		PR("gul_hif size=%lx, \n", sizeof(struct gul_hif));
		return IPC_MD_SZ_MISS_MATCH;
	}

	instance_bk = ipc_priv->instance_bk;
	ipc_priv->instance = (ipc_instance_t *)(&ipc_md->instance_list[GEUL_IPC_INSTANCE_ID]);
	instance = ipc_priv->instance;

	pr_debug("---- Host init part done --------\n");

	instance->instance_id = instance_bk->instance_id;
	instance->bbdev_ipc_mode = instance_bk->bbdev_ipc_mode;

	/* Restore the channel configuration */
	for (i = 0; i < IPC_MAX_CHANNEL_COUNT; i++) {
		/* This will enable MSI for L1 channels */
		instance->ch_list[i].msi_valid =
				instance_bk->ch_list[i].msi_valid;
		/* Only restore configured channels */
		ipc_bitmask_t mask = instance_bk->cfgmask[i / bitcount(ipc_bitmask_t)];
		if (0 == !!(mask & (1 << (i % bitcount(mask)))))
			continue;

		memcpy(&instance->ch_list[i], &instance_bk->ch_list[i], sizeof(ipc_ch_t));
		ipc_priv_ch = ipc_priv->channels[i];
		if (ipc_priv_ch->eventfd != -1) {
			ipc_eventfd_t efd_args;

			/* Send IOCTL to register this event_fd with kernel*/
			efd_args.efd = ipc_priv_ch->eventfd;
			efd_args.ipc_channel_num = i;
			ret = ioctl(ipc_priv->dev_ipc, IOCTL_GUL_IPC_CHANNEL_REGISTER, &efd_args);
			if (ret) {
				pr_debug("IPC_CHANNEL_REGISTER failed for Channel ID %d\n", i);
				h_stats->ipc_ch_stats[i].err_efd_reg_fail++;
				return IPC_EVENTFD_FAIL;
			}
			pr_debug("Got MSI %d valid %d for Channel ID %d eventfd %d\n", efd_args.msi_value, instance->ch_list[i].msi_valid, i, ipc_priv_ch->eventfd);
			instance->ch_list[i].msi_value = efd_args.msi_value;
		}

		if (instance_bk->ch_list[i].ch_type == IPC_CH_PTR) {
			ipc_bd_ring_bl_t *bl;
			uint8_t *bufs_inflight;

			bl = &(instance->ch_list[i].br_bl_desc);
			bufs_inflight = ipc_priv->channels[i]->bufs_inflight;

			printf("--- InFlight bufs info for CH[%d] ---\n", i);
			handle_inflight_bufs(bl, bufs_inflight);
		}
		ipc_mark_channel_as_configured(i, ipc_priv->instance);
	}
	instance->initialized = instance_bk->initialized;

	/* Application should Mark HOST APP Ready Bit again */
	return IPC_SUCCESS;

}

#if TBD
/**************** Internal API ************************/
#if 0 /*AK not needed */
/*
 * @get_channels_info
 *
 * Read number of channels and max msg size from sh_ctrl_area
 *
 * Type: Internal function
 */

int get_ipc_inst(ipc_userspace_t *ipc_priv, uint32_t inst_id)
{
	int ret = IPC_SUCCESS;
	ENTER();

	os_het_control_t *sh_ctrl =  ipc_priv->sh_ctrl_area.vaddr;
	os_het_ipc_t *ipc = IPC_CH_VADDR(sh_ctrl->ipc)
				+ sizeof(os_het_ipc_t)*inst_id;
	if (!ipc) {
		ret = -1;
		goto end;
	}
	if (ipc->num_ipc_channels > MAX_IPC_CHANNELS) {
		ret = -1;
		goto end;
	}

	/* ipc_channels is 64 bits but, area of hugetlb/DDR will always
	* less than 4GB(B4),for 913x it is only 2GB, so the value is
	* always in 32 bits, that is why bitwise and with 0xFFFFFFFF
	*/
	if ((ipc->ipc_channels & 0xFFFFFFFF) == 0) {
		ret = -ERR_INCORRECT_RAT_MODE;
		goto end;
	}

	ipc_priv->max_channels = ipc->num_ipc_channels;
	ipc_priv->max_depth = ipc->ipc_max_bd_size;
	ipc_priv->ipc_inst = ipc;
end:
	EXIT(ret);
	return ret;
}

int get_channels_info(ipc_userspace_t *ipc_priv, uint32_t inst_id)
{
	return get_ipc_inst(ipc_priv, inst_id);
}
#endif

/*
 * @get_channel_paddr
 *
 * Returns the phyical address of the channel data structure in the
 * share control area.
 *
 * Type: Internal function
 */
static unsigned long __get_channel_paddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv)
{
	unsigned long		phys_addr;
	ipc_instance_t *ipc = (ipc_instance_t *)ipc_priv->instance;
	ipc_ch_t *ch = &(ipc->ch_list[channel_id]);
	ipc_t *instance = (ipc_t *)ipc_priv;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);

	if (!ipc || !(ipc->initialized)) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}
	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}

#if TBD /* AK not complete */
	phys_addr = (unsigned long)ipc->ipc_channels +
		sizeof(os_het_ipc_channel_t)*channel_id;
	EXIT(phys_addr);
	return phys_addr;
#endif
}
/*
 * @get_channel_vaddr
 *
 * Returns the virtual address of the channel data structure in the
 * share control area.
 *
 * Type: Internal function
 */
static void *__get_channel_vaddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv)
{
#if 0
	void *vaddr;
#endif
	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)instance;
	ipc_instance_t *ipc = ipc_priv->instance;
	ipc_ch_t *ch = &(ipc->ch_list[channel_id]);
	ipc_t *instance = (ipc_t *)ipc_priv;
	struct gul_ipc_stats *h_stats = get_gul_ipc_stats(instance);

	if (!ipc || !(ipc->initialized)) {
		h_stats->err_instance_invalid++;
		return IPC_INSTANCE_INVALID;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		h_stats->ipc_ch_stats[channel_id].err_channel_invalid++;
		return IPC_CH_INVALID;
	}

	ch = &(ipc->ch_list[channel_id]);

	return ch;
}
/*
 * @get_channel_paddr
 *
 * Returns the phyical address of the channel data structure in the
 * share control area.
 *
 * Type: Internal function
 */
static unsigned long get_channel_paddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv)
{
	return chvpaddr_arr[ipc_priv->instance_id][channel_id].host_phys;
}

/*
 * @get_channel_vaddr
 *
 * Returns the virtual address of the channel data structure in the
 * share control area.
 *
 * Type: Internal function
 */
static void *get_channel_vaddr(uint32_t channel_id, ipc_userspace_t *ipc_priv)
{
	return chvpaddr_arr[ipc_priv->instance_id][channel_id].vaddr;
}
#endif
