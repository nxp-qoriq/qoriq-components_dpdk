/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright 2022-2024 NXP
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_cpuflags.h>

#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_dev.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_io.h>
#include <ethdev_pci.h>

#include "virtio_ethdev.h"
#include "virtio_pci.h"
#include "virtqueue.h"
#include "virtio_rxtx.h"
#include "virtio_rxtx_simple.h"
#include "lsxinic_vio_common.h"
#include "lsxinic_rc_hw.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE (sysconf(_SC_PAGESIZE))
#endif

#define LSXVIO_PMD_LOG(level, fmt, args...) \
	RTE_LOG(level, PMD, "lsxvio:" fmt "\n", ##args)

#undef LSXVIO_PMD_DBG_ENABLE

#ifdef LSXVIO_PMD_DBG_ENABLE
#define LSXVIO_PMD_DBG(fmt, args...) \
	LSXVIO_PMD_LOG(DEBUG, fmt, ## args)
#else
#define LSXVIO_PMD_DBG(fmt, args...) \
	do { } while (0)
#endif
#define LSXVIO_PMD_INFO(fmt, args...) \
	LSXVIO_PMD_LOG(INFO, fmt, ## args)
#define LSXVIO_PMD_ERR(fmt, args...) \
	LSXVIO_PMD_LOG(ERR, fmt, ## args)
#define LSXVIO_PMD_WARN(fmt, args...) \
	LSXVIO_PMD_LOG(WARNING, fmt, ## args)

struct lsxvio_local_cfg {
	uint64_t lsx_feature;
	uint64_t queue_mem_base[LSXVIO_MAX_QUEUES];
	const struct rte_memzone *shadow_desc_mz[LSXVIO_MAX_QUEUES];
	void *shadow_desc[LSXVIO_MAX_QUEUES];
	uint64_t shadow_desc_phy[LSXVIO_MAX_QUEUES];
	uint32_t queue_mem_interval[LSXVIO_MAX_QUEUES];
};

struct lsxvio_pci_cfg {
	struct lsxvio_common_cfg common_cfg;
	struct lsxvio_queue_cfg queue_cfg[LSXVIO_MAX_QUEUES];
} __attribute__((__packed__));

struct lsxvio_rc_pci_hw {
	struct virtio_pci_dev pci_dev;
	struct lsxvio_pci_cfg *lsx_cfg; /* PCIe space*/
	uint8_t *ring_base;
	struct lsxvio_local_cfg local_lsx_cfg;
	uint16_t last_avail_idx[LSXVIO_MAX_QUEUES];
};

#define lsxvio_rc_pci_dev(hwp) \
	container_of(hwp, struct lsxvio_rc_pci_hw, pci_dev)

struct virtio_hw_internal s_lsx_vio_hw[RTE_MAX_ETHPORTS];

#define LSX_VIO_OPS(hw)	(s_lsx_vio_hw[(hw)->port_id].virtio_ops)

static int
lsxvio_rc_eth_uninit(struct rte_eth_dev *eth_dev);
static int
lsxvio_rc_eth_configure(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_start(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_stop(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_prom_enable(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_prom_disable(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_mcast_enable(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_mcast_disable(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info);
static int
lsxvio_rc_eth_link_update(struct rte_eth_dev *dev,
	int wait_to_complete);

static void
lsxvio_rc_set_hwaddr(struct virtio_hw *hw);
static void
lsxvio_rc_get_hwaddr(struct virtio_hw *hw);

static int
lsxvio_rc_eth_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats);
static int
lsxvio_rc_eth_xstats_get(struct rte_eth_dev *dev,
	struct rte_eth_xstat *xstats, uint32_t n);
static int
lsxvio_rc_eth_xstats_get_names(struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names,
	uint32_t limit);
static int
lsxvio_rc_eth_stats_reset(struct rte_eth_dev *dev);
static void
lsxvio_rc_free_mbufs(struct rte_eth_dev *dev);

int lsxvio_rc_logtype_init;
int lsxvio_rc_logtype_driver;

static int s_lsxvio_rc_sim;

static const struct rte_pci_id lsxvio_pci_id_map[] = {
	{ RTE_PCI_DEVICE(VIRTIO_PCI_VENDORID, VIRTIO_PCI_LEGACY_DEVICEID_NET) },
	{ RTE_PCI_DEVICE(VIRTIO_PCI_VENDORID, VIRTIO_PCI_MODERN_DEVICEID_NET) },
	{ .vendor_id = 0, /* sentinel */ },
};

struct lsxvio_rc_eth_xstats_name_off {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	uint32_t offset;
};

/* [rt]x_qX_ is prepended to the name string here */
static const
struct lsxvio_rc_eth_xstats_name_off s_lsxvio_rc_rxq_stat_str[] = {
	{
		"good_packets",
		offsetof(struct virtnet_rx, stats.packets)
	},
	{
		"good_bytes",
		offsetof(struct virtnet_rx, stats.bytes)
	},
	{
		"errors",
		offsetof(struct virtnet_rx, stats.errors)
	},
	{
		"multicast_packets",
		offsetof(struct virtnet_rx, stats.multicast)
	},
	{
		"broadcast_packets",
		offsetof(struct virtnet_rx, stats.broadcast)
	},
	{
		"undersize_packets",
		offsetof(struct virtnet_rx, stats.size_bins[0])
	},
	{
		"size_64_packets",
		offsetof(struct virtnet_rx, stats.size_bins[1])
	},
	{
		"size_65_127_packets",
		offsetof(struct virtnet_rx, stats.size_bins[2])
	},
	{
		"size_128_255_packets",
		offsetof(struct virtnet_rx, stats.size_bins[3])
	},
	{
		"size_256_511_packets",
		offsetof(struct virtnet_rx, stats.size_bins[4])
	},
	{
		"size_512_1023_packets",
		offsetof(struct virtnet_rx, stats.size_bins[5])
	},
	{
		"size_1024_1518_packets",
		offsetof(struct virtnet_rx, stats.size_bins[6])
	},
	{
		"size_1519_max_packets",
		offsetof(struct virtnet_rx, stats.size_bins[7])
	},
};

/* [rt]x_qX_ is prepended to the name string here */
static const
struct lsxvio_rc_eth_xstats_name_off s_lsxvio_rc_txq_stat_str[] = {
	{
		"good_packets",
		offsetof(struct virtnet_tx, stats.packets)
	},
	{
		"good_bytes",
		offsetof(struct virtnet_tx, stats.bytes)
	},
	{
		"multicast_packets",
		offsetof(struct virtnet_tx, stats.multicast)
	},
	{
		"broadcast_packets",
		offsetof(struct virtnet_tx, stats.broadcast)
	},
	{
		"undersize_packets",
		offsetof(struct virtnet_tx, stats.size_bins[0])
	},
	{
		"size_64_packets",
		offsetof(struct virtnet_tx, stats.size_bins[1])
	},
	{
		"size_65_127_packets",
		offsetof(struct virtnet_tx, stats.size_bins[2])
	},
	{
		"size_128_255_packets",
		offsetof(struct virtnet_tx, stats.size_bins[3])
	},
	{
		"size_256_511_packets",
		offsetof(struct virtnet_tx, stats.size_bins[4])
	},
	{
		"size_512_1023_packets",
		offsetof(struct virtnet_tx, stats.size_bins[5])
	},
	{
		"size_1024_1518_packets",
		offsetof(struct virtnet_tx, stats.size_bins[6])
	},
	{
		"size_1519_max_packets",
		offsetof(struct virtnet_tx, stats.size_bins[7])
	},
};

static int s_lsxvio_rc_2nd_proc_standalone;

static struct rte_eth_dev_data *s_lsxvio_rc_eth_data;
static rte_spinlock_t s_lsxvio_rc_lock = RTE_SPINLOCK_INITIALIZER;

#define LSXVIO_NB_RXQ_XSTATS (sizeof(s_lsxvio_rc_rxq_stat_str) / \
			    sizeof(s_lsxvio_rc_rxq_stat_str[0]))
#define LSXVIO_NB_TXQ_XSTATS (sizeof(s_lsxvio_rc_txq_stat_str) / \
			    sizeof(s_lsxvio_rc_txq_stat_str[0]))

#ifdef RTE_LSXVIO_RC_DEBUG_DUMP
#define LSXVIO_RC_VIRTQUEUE_DUMP(vq) do { \
	uint16_t used_idx, nused; \
	used_idx = __atomic_load_n(&(vq)->vq_split.ring.used->idx, \
				   __ATOMIC_RELAXED); \
	\
	nused = (uint16_t)(used_idx - (vq)->vq_used_cons_idx); \
	if (virtio_with_packed_queue((vq)->hw)) { \
		LSXVIO_PMD_DBG("PACKEDQ: size=%d free=%d used=%d avail=%d;" \
			(vq)->vq_nentries, (vq)->vq_free_cnt, \
			(vq)->vq_used_cons_idx, (vq)->vq_avail_idx); \
		LSXVIO_PMD_DBG("PACKEDQ: cached_flags=0x%x", \
			(vq)->vq_packed.cached_flags); \
		LSXVIO_PMD_DBG("PACKEDQ: used_wrap_counter=%d", \
			(vq)->vq_packed.used_wrap_counter); \
		break; \
	} \
	LSXVIO_PMD_DBG("VQ: size=%d; free=%d; used=%d; desc_head_idx=%d;" \
		(vq)->vq_nentries, (vq)->vq_free_cnt, nused, \
		(vq)->vq_desc_head_idx); \
	LSXVIO_PMD_DBG("VQ: avail.idx=%d; used_cons_idx=%d; used.idx=%d;" \
		(vq)->vq_split.ring.avail->idx, (vq)->vq_used_cons_idx, \
		__atomic_load_n(&(vq)->vq_split.ring.used->idx, \
			__ATOMIC_RELAXED)); \
	LSXVIO_PMD_DBG("VQ: avail.flags=0x%x; used.flags=0x%x", \
		(vq)->vq_split.ring.avail->flags, \
		(vq)->vq_split.ring.used->flags); \
} while (0)
#else
#define LSXVIO_RC_VIRTQUEUE_DUMP(vq) do { } while (0)
#endif

static uint64_t
lsxvio_rc_virtio_negotiate_features(struct virtio_hw *hw,
	uint64_t host_features)
{
	uint64_t features;

	features = host_features & hw->guest_features;
	LSX_VIO_OPS(hw)->set_features(hw, features);

	return features;
}

static void
lsxvio_rc_virtio_read_dev_config(struct virtio_hw *hw,
	size_t offset, void *dst, int length)
{
	LSX_VIO_OPS(hw)->read_dev_cfg(hw, offset, dst, length);
}

static void
lsxvio_rc_virtio_write_dev_config(struct virtio_hw *hw,
	size_t offset, const void *src, int length)
{
	LSX_VIO_OPS(hw)->write_dev_cfg(hw, offset, src, length);
}

static void
lsxvio_rc_virtio_reset(struct virtio_hw *hw)
{
	uint32_t retry = 0;

	LSX_VIO_OPS(hw)->set_status(hw, VIRTIO_CONFIG_STATUS_RESET);
	/* Flush status write and wait device ready max 3 seconds. */
	while (LSX_VIO_OPS(hw)->get_status(hw) != VIRTIO_CONFIG_STATUS_RESET) {
		if (retry++ > 3000) {
			LSXVIO_PMD_WARN("port %u device reset timeout",
				hw->port_id);
			break;
		}
		usleep(1000L);
	}
}

static void
lsxvio_rc_virtio_set_status(struct virtio_hw *hw, uint8_t status)
{
	if (status != VIRTIO_CONFIG_STATUS_RESET)
		status |= LSX_VIO_OPS(hw)->get_status(hw);

	LSX_VIO_OPS(hw)->set_status(hw, status);
}

static void
lsxvio_rc_virtio_reinit_complete(struct virtio_hw *hw)
{
	lsxvio_rc_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER_OK);
}

static uint8_t
lsxvio_rc_virtio_get_status(struct virtio_hw *hw)
{
	return LSX_VIO_OPS(hw)->get_status(hw);
}

static struct rte_mbuf *
lsxvio_rc_virtqueue_detach_unused(struct virtqueue *vq)
{
	struct rte_mbuf *cookie;
	struct virtio_hw *hw;
	uint16_t start, end;
	int type, idx;

	if (!vq)
		return NULL;

	hw = vq->hw;
	type = virtio_get_queue_type(hw, vq->vq_queue_index);
	start = vq->vq_avail_idx & (vq->vq_nentries - 1);
	end = (vq->vq_avail_idx + vq->vq_free_cnt) & (vq->vq_nentries - 1);

	for (idx = 0; idx < vq->vq_nentries; idx++) {
		if (hw->use_vec_rx && !virtio_with_packed_queue(hw) &&
		    type == VTNET_RQ) {
			if (start <= end && idx >= start && idx < end)
				continue;
			if (start > end && (idx >= start || idx < end))
				continue;
			cookie = vq->sw_ring[idx];
			if (cookie) {
				vq->sw_ring[idx] = NULL;
				return cookie;
			}
		} else {
			cookie = vq->vq_descx[idx].cookie;
			if (cookie) {
				vq->vq_descx[idx].cookie = NULL;
				return cookie;
			}
		}
	}

	return NULL;
}

static inline void
lsxvio_rc_virtqueue_notify(struct virtqueue *vq)
{
	LSX_VIO_OPS(vq->hw)->notify_queue(vq->hw, vq);
}

static void
lsxvio_rc_virtqueue_rxvq_flush_packed(struct virtqueue *vq)
{
	struct vq_desc_extra *dxp;
	uint16_t i;

	struct vring_packed_desc *descs = vq->vq_packed.ring.desc;
	int cnt = 0;

	i = vq->vq_used_cons_idx;
	while (desc_is_used(&descs[i], vq) && cnt++ < vq->vq_nentries) {
		dxp = &vq->vq_descx[descs[i].id];
		if (dxp->cookie) {
			rte_pktmbuf_free(dxp->cookie);
			dxp->cookie = NULL;
		}
		vq->vq_free_cnt++;
		vq->vq_used_cons_idx++;
		if (vq->vq_used_cons_idx >= vq->vq_nentries) {
			vq->vq_used_cons_idx -= vq->vq_nentries;
			vq->vq_packed.used_wrap_counter ^= 1;
		}
		i = vq->vq_used_cons_idx;
	}
}

static void
lsxvio_rc_vq_ring_free_inorder(struct virtqueue *vq,
	uint16_t desc_idx, uint16_t num)
{
	vq->vq_free_cnt += num;
	vq->vq_desc_tail_idx = desc_idx & (vq->vq_nentries - 1);
}

static void
lsxvio_rc_vq_ring_free_chain(struct virtqueue *vq, uint16_t desc_idx)
{
	struct vring_desc *dp, *dp_tail;
	struct vq_desc_extra *dxp;
	uint16_t desc_idx_last = desc_idx;

	dp  = &vq->vq_split.ring.desc[desc_idx];
	dxp = &vq->vq_descx[desc_idx];
	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt + dxp->ndescs);
	if ((dp->flags & VRING_DESC_F_INDIRECT) == 0) {
		while (dp->flags & VRING_DESC_F_NEXT) {
			desc_idx_last = dp->next;
			dp = &vq->vq_split.ring.desc[dp->next];
		}
	}
	dxp->ndescs = 0;

	/**
	 * We must append the existing free chain, if any, to the end of
	 * newly freed chain. If the virtqueue was completely used, then
	 * head would be VQ_RING_DESC_CHAIN_END (ASSERTed above).
	 */
	if (vq->vq_desc_tail_idx == VQ_RING_DESC_CHAIN_END) {
		vq->vq_desc_head_idx = desc_idx;
	} else {
		dp_tail = &vq->vq_split.ring.desc[vq->vq_desc_tail_idx];
		dp_tail->next = desc_idx;
	}

	vq->vq_desc_tail_idx = desc_idx_last;
	dp->next = VQ_RING_DESC_CHAIN_END;
}

static void
lsxvio_rc_virtqueue_rxvq_flush_split(struct virtqueue *vq)
{
	struct virtnet_rx *rxq = &vq->rxq;
	struct virtio_hw *hw = vq->hw;
	struct vring_used_elem *uep;
	struct vq_desc_extra *dxp;
	uint16_t used_idx, desc_idx;
	uint16_t nb_used, i;

	nb_used = virtqueue_nused(vq);

	for (i = 0; i < nb_used; i++) {
		used_idx = vq->vq_used_cons_idx & (vq->vq_nentries - 1);
		uep = &vq->vq_split.ring.used->ring[used_idx];
		if (hw->use_vec_rx) {
			desc_idx = used_idx;
			rte_pktmbuf_free(vq->sw_ring[desc_idx]);
			vq->vq_free_cnt++;
		} else if (hw->use_inorder_rx) {
			desc_idx = (uint16_t)uep->id;
			dxp = &vq->vq_descx[desc_idx];
			if (dxp->cookie) {
				rte_pktmbuf_free(dxp->cookie);
				dxp->cookie = NULL;
			}
			lsxvio_rc_vq_ring_free_inorder(vq, desc_idx, 1);
		} else {
			desc_idx = (uint16_t)uep->id;
			dxp = &vq->vq_descx[desc_idx];
			if (dxp->cookie) {
				rte_pktmbuf_free(dxp->cookie);
				dxp->cookie = NULL;
			}
			lsxvio_rc_vq_ring_free_chain(vq, desc_idx);
		}
		vq->vq_used_cons_idx++;
	}

	if (hw->use_vec_rx) {
		while (vq->vq_free_cnt >= RTE_VIRTIO_VPMD_RX_REARM_THRESH) {
			virtio_rxq_rearm_vec(rxq);
			if (virtqueue_kick_prepare(vq))
				lsxvio_rc_virtqueue_notify(vq);
		}
	}
}

static void
lsxvio_rc_virtqueue_rxvq_flush(struct virtqueue *vq)
{
	struct virtio_hw *hw = vq->hw;

	if (virtio_with_packed_queue(hw))
		lsxvio_rc_virtqueue_rxvq_flush_packed(vq);
	else
		lsxvio_rc_virtqueue_rxvq_flush_split(vq);
}

static inline void
lsxvio_write64_twopart(uint64_t val,
	uint32_t *lo, uint32_t *hi)
{
	rte_write32(val & ((1ULL << 32) - 1), lo);
	rte_write32(val >> 32, hi);
}

static inline uint64_t
lsxvio_priv_feature(struct lsxvio_rc_pci_hw *lsx_hw, int remote)
{
	struct lsxvio_pci_cfg *lsx_cfg = lsx_hw->lsx_cfg;
	struct lsxvio_common_cfg *c_cfg = &lsx_cfg->common_cfg;
	uint64_t lsx_feature;

	if (unlikely(remote)) {
		lsx_feature = rte_read64(&c_cfg->lsx_feature);
		if (lsx_hw->local_lsx_cfg.lsx_feature != lsx_feature)
			lsx_hw->local_lsx_cfg.lsx_feature = lsx_feature;
	} else {
		lsx_feature = lsx_hw->local_lsx_cfg.lsx_feature;
	}

	return lsx_feature;
}

static void
lsxvio_rc_eth_queue_release(struct rte_eth_dev *dev __rte_unused,
	uint16_t qid __rte_unused)
{
	/* do nothing */
}

static uint16_t
lsxvio_rc_get_nr_vq(struct virtio_hw *hw)
{
	uint16_t nr_vq = hw->max_queue_pairs * 2;

	if (virtio_with_feature(hw, VIRTIO_NET_F_CTRL_VQ))
		nr_vq += 1;

	return nr_vq;
}

static inline void
lsxvio_rc_init_split_desc(struct vring *vr, uint8_t *p)
{
	vr->desc = (void *)p;
}

static inline void
lsxvio_rc_init_split_avail_used(struct vring *vr,
	uint8_t *p, unsigned long align, unsigned int num)
{
	vr->num = num;
	vr->avail = (void *)p;
	vr->used = (void *)
		RTE_ALIGN_CEIL((uintptr_t)(&vr->avail->ring[num]),
			align);
	vr->used = (void *)((uint8_t *)vr->used +
		offsetof(struct vring_used, ring[0]));
}

static inline void
lsxvio_rc_init_split(struct vring *vr, uint8_t *pdesc,
	uint8_t *p, unsigned long align, unsigned int num)
{
	if (pdesc) {
		lsxvio_rc_init_split_desc(vr, pdesc);
		lsxvio_rc_init_split_avail_used(vr, p, align, num);
	} else {
		lsxvio_rc_init_split_desc(vr, p);
		lsxvio_rc_init_split_avail_used(vr,
			(p + num * sizeof(struct vring_desc)), align, num);
	}
}

#define LSXVIO_TX_PACKED_BD_NOTIFICATION_UPDATE 1

static void
lsxvio_rc_init_vring(struct virtqueue *vq, int queue_type)
{
	int size = vq->vq_nentries;
	uint8_t *ring_mem = vq->vq_ring_virt_mem;
	struct virtio_pci_dev *dev = virtio_pci_get_dev(vq->hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(dev);
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw, true);
#ifndef LSXVIO_TX_PACKED_BD_NOTIFICATION_UPDATE
	uint8_t *remote_ring_base = lsx_hw->ring_base;
#endif
	struct vring *vr = &vq->vq_split.ring;

	memset(ring_mem, 0, vq->vq_ring_size);

	vq->vq_used_cons_idx = 0;
	vq->vq_desc_head_idx = 0;
	vq->vq_avail_idx = 0;
	vq->vq_desc_tail_idx = (uint16_t)(vq->vq_nentries - 1);
	vq->vq_free_cnt = vq->vq_nentries;
	memset(vq->vq_descx, 0,
		sizeof(struct vq_desc_extra) * vq->vq_nentries);
	if (virtio_with_packed_queue(vq->hw)) {
		vring_init_packed(&vq->vq_packed.ring, ring_mem,
			VIRTIO_VRING_ALIGN, size);
		vring_desc_init_packed(vq, size);
	} else if (queue_type == VTNET_RQ &&
		(lsx_feature & LSX_VIO_EP2RC_PACKED)) {
		vring_init_packed(&vq->vq_packed.ring, ring_mem,
			VIRTIO_VRING_ALIGN, size);
		vring_desc_init_packed(vq, size);
	} else if (queue_type == VTNET_TQ) {
#ifdef LSXVIO_TX_PACKED_BD_NOTIFICATION_UPDATE
		lsxvio_rc_init_split(vr, NULL,
			ring_mem, VIRTIO_VRING_ALIGN, size);
#else
		remote_ring_base += vq->vq_queue_index *
			LSXVIO_PER_RING_MEM_MAX_SIZE;
		lsxvio_rc_init_split(vr, remote_ring_base,
			ring_mem, VIRTIO_VRING_ALIGN, size);
#endif
		vring_desc_init_split(vr->desc, size);
	} else {
		lsxvio_rc_init_split(vr, NULL, ring_mem,
			VIRTIO_VRING_ALIGN, size);
		vring_desc_init_split(vr->desc, size);
	}

	virtqueue_disable_intr(vq);
}

static int
lsxvio_rc_init_queue(struct rte_eth_dev *dev,
	uint16_t vtpci_queue_idx)
{
	char vq_name[VIRTQUEUE_MAX_NAME_SZ];
	char vq_hdr_name[VIRTQUEUE_MAX_NAME_SZ];
	const struct rte_memzone *mz = NULL, *hdr_mz = NULL;
	uint32_t vq_size, size;
	struct lsxvio_rc_pci_hw *lsx_hw = dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->pci_dev.hw;
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw, true);
	struct virtnet_rx *rxvq = NULL;
	struct virtnet_tx *txvq = NULL;
	struct virtnet_ctl *cvq = NULL;
	struct virtqueue *vq;
	size_t sz_hdr_mz = 0;
	void *sw_ring = NULL;
	int queue_type = virtio_get_queue_type(hw, vtpci_queue_idx);
	int ret;
	int numa_node = dev->device->numa_node;
	long page_size;

	LSXVIO_PMD_INFO("%s: set up queue: %u on NUMA node %d",
			dev->data->name, vtpci_queue_idx, numa_node);

	vq_size = LSX_VIO_OPS(hw)->get_queue_num(hw, vtpci_queue_idx);
	LSXVIO_PMD_DBG("vq_size: %u", vq_size);
	if (vq_size == 0) {
		LSXVIO_PMD_ERR("%s: vq%d does not exist",
			dev->data->name, vtpci_queue_idx);
		return -EINVAL;
	}

	if (!virtio_with_packed_queue(hw) && !rte_is_power_of_2(vq_size)) {
		LSXVIO_PMD_ERR("%s: split vq%d size is not power of 2",
			dev->data->name, vtpci_queue_idx);
		return -EINVAL;
	}

	snprintf(vq_name, sizeof(vq_name), "port%d_vq%d",
		 dev->data->port_id, vtpci_queue_idx);

	size = RTE_ALIGN_CEIL(sizeof(*vq) +
		vq_size * sizeof(struct vq_desc_extra),
		RTE_CACHE_LINE_SIZE);
	if (queue_type == VTNET_TQ) {
		sz_hdr_mz = vq_size * sizeof(struct virtio_tx_region);
	} else if (queue_type == VTNET_CQ) {
		/* Allocate a page for control vq command, data and status */
		sz_hdr_mz = PAGE_SIZE;
	}

	vq = rte_zmalloc_socket(vq_name, size, RTE_CACHE_LINE_SIZE,
		numa_node);
	if (!vq) {
		LSXVIO_PMD_ERR("can not allocate vq %s",
			vq_name);
		return -ENOMEM;
	}
	hw->vqs[vtpci_queue_idx] = vq;

	vq->hw = hw;
	vq->vq_queue_index = vtpci_queue_idx;
	vq->vq_nentries = vq_size;
	if (virtio_with_packed_queue(hw)) {
		vq->vq_packed.used_wrap_counter = 1;
		vq->vq_packed.cached_flags = VRING_PACKED_DESC_F_AVAIL;
		vq->vq_packed.event_flags_shadow = 0;
		if (queue_type == VTNET_RQ)
			vq->vq_packed.cached_flags |= VRING_DESC_F_WRITE;
	} else if (queue_type == VTNET_RQ &&
		(lsx_feature & LSX_VIO_EP2RC_PACKED)) {
		vq->vq_packed.used_wrap_counter = 1;
		vq->vq_packed.cached_flags = VRING_PACKED_DESC_F_AVAIL;
		vq->vq_packed.event_flags_shadow = 0;
		vq->vq_packed.cached_flags |= VRING_DESC_F_WRITE;
	}

	vq->vq_ring_size = LSXVIO_PER_RING_MEM_MAX_SIZE;

	mz = rte_memzone_reserve_aligned(vq_name, vq->vq_ring_size,
			numa_node, RTE_MEMZONE_IOVA_CONTIG,
			vq->vq_ring_size);
	if (!mz) {
		if (rte_errno == EEXIST)
			mz = rte_memzone_lookup(vq_name);
		if (!mz) {
			ret = -ENOMEM;
			goto fail_q_alloc;
		}
	}

	memset(mz->addr, 0, mz->len);

	vq->vq_ring_mem = mz->iova;
	vq->vq_ring_virt_mem = mz->addr;
	LSXVIO_PMD_DBG("vq->vq_ring_mem: 0x%lx",
		     (uint64_t)mz->iova);
	LSXVIO_PMD_DBG("vq->vq_ring_virt_mem: 0x%lx",
		     (uint64_t)mz->addr);

	lsxvio_rc_init_vring(vq, queue_type);

	if (sz_hdr_mz) {
		snprintf(vq_hdr_name, sizeof(vq_hdr_name), "port%d_vq%d_hdr",
			 dev->data->port_id, vtpci_queue_idx);
		hdr_mz = rte_memzone_reserve_aligned(vq_hdr_name, sz_hdr_mz,
				numa_node, RTE_MEMZONE_IOVA_CONTIG,
				RTE_CACHE_LINE_SIZE);
		if (!hdr_mz) {
			if (rte_errno == EEXIST)
				hdr_mz = rte_memzone_lookup(vq_hdr_name);
			if (!hdr_mz) {
				ret = -ENOMEM;
				goto fail_q_alloc;
			}
		}
	}

	if (queue_type == VTNET_RQ) {
		size_t sz_sw = (RTE_PMD_VIRTIO_RX_MAX_BURST + vq_size) *
			       sizeof(vq->sw_ring[0]);

		sw_ring = rte_zmalloc_socket("sw_ring", sz_sw,
				RTE_CACHE_LINE_SIZE, numa_node);
		if (!sw_ring) {
			LSXVIO_PMD_ERR("%s: can not allocate RX soft ring",
				dev->data->name);
			ret = -ENOMEM;
			goto fail_q_alloc;
		}

		vq->sw_ring = sw_ring;
		rxvq = &vq->rxq;
		rxvq->port_id = dev->data->port_id;
		rxvq->mz = mz;
	} else if (queue_type == VTNET_TQ) {
		txvq = &vq->txq;
		txvq->port_id = dev->data->port_id;
		txvq->mz = mz;
		txvq->virtio_net_hdr_mz = hdr_mz;
		txvq->virtio_net_hdr_mem = hdr_mz->iova;
	} else if (queue_type == VTNET_CQ) {
		cvq = &vq->cq;
		cvq->mz = mz;
		cvq->virtio_net_hdr_mz = hdr_mz;
		cvq->virtio_net_hdr_mem = hdr_mz->iova;
		page_size = PAGE_SIZE;
		if (page_size != -1)
			memset(cvq->virtio_net_hdr_mz->addr, 0, page_size);
		hw->cvq = cvq;
	}

	vq->vq_ring_mem = (uintptr_t)mz->addr;
	if (queue_type == VTNET_TQ)
		txvq->virtio_net_hdr_mem = (uintptr_t)hdr_mz->addr;
	else if (queue_type == VTNET_CQ)
		cvq->virtio_net_hdr_mem = (uintptr_t)hdr_mz->addr;

	if (queue_type == VTNET_TQ) {
		struct virtio_tx_region *txr;
		uint32_t i;

		txr = hdr_mz->addr;
		memset(txr, 0, vq_size * sizeof(*txr));
		for (i = 0; i < vq_size; i++) {
			struct vring_desc *start_dp = txr[i].tx_indir;

			/* first indirect descriptor is always the tx header */
			if (!virtio_with_packed_queue(hw) &&
				!(queue_type == VTNET_RQ &&
				(lsx_feature & LSX_VIO_EP2RC_PACKED))) {
				vring_desc_init_split(start_dp,
						      RTE_DIM(txr[i].tx_indir));
				start_dp->addr = txvq->virtio_net_hdr_mem
					+ i * sizeof(*txr)
					+ offsetof(struct virtio_tx_region,
						   tx_hdr);
				start_dp->len = hw->vtnet_hdr_size;
				start_dp->flags = VRING_DESC_F_NEXT;
			}
		}
	}

	if (LSX_VIO_OPS(hw)->setup_queue(hw, vq) < 0) {
		LSXVIO_PMD_ERR("%s: setup queue%d failed",
			dev->data->name, vtpci_queue_idx);
		return -EINVAL;
	}

	return 0;

fail_q_alloc:
	rte_free(sw_ring);
	rte_memzone_free(hdr_mz);
	rte_memzone_free(mz);
	rte_free(vq);

	return ret;
}

static void
lsxvio_rc_free_queues(struct virtio_hw *hw)
{
	uint16_t nr_vq = lsxvio_rc_get_nr_vq(hw);
	struct virtqueue *vq;
	int queue_type;
	uint16_t i;
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	struct lsxvio_local_cfg *local_cfg = &lsx_hw->local_lsx_cfg;

	if (!hw->vqs)
		return;

	for (i = 0; i < nr_vq; i++) {
		vq = hw->vqs[i];
		if (!vq)
			continue;

		queue_type = virtio_get_queue_type(hw, i);
		if (queue_type == VTNET_RQ) {
			rte_free(vq->sw_ring);
			rte_memzone_free(vq->rxq.mz);
		} else if (queue_type == VTNET_TQ) {
			rte_memzone_free(vq->txq.mz);
			rte_memzone_free(vq->txq.virtio_net_hdr_mz);
		} else {
			rte_memzone_free(vq->cq.mz);
			rte_memzone_free(vq->cq.virtio_net_hdr_mz);
		}
		if (local_cfg->shadow_desc_mz[i]) {
			rte_memzone_free(local_cfg->shadow_desc_mz[i]);
			local_cfg->shadow_desc_mz[i] = NULL;

			local_cfg->shadow_desc[i] = NULL;
			local_cfg->shadow_desc_phy[i] = 0;
		}

		rte_free(vq);
		hw->vqs[i] = NULL;
	}

	rte_free(hw->vqs);
	hw->vqs = NULL;
}

static int
lsxvio_rc_alloc_queues(struct rte_eth_dev *dev)
{
	struct virtio_hw *hw = dev->data->dev_private;
	uint16_t nr_vq = lsxvio_rc_get_nr_vq(hw);
	uint16_t i;
	int ret;

	hw->vqs = rte_zmalloc(NULL, sizeof(struct virtqueue *) * nr_vq, 0);
	if (!hw->vqs) {
		LSXVIO_PMD_ERR("%s: failed to allocate %d vqs",
			dev->data->name, nr_vq);
		return -ENOMEM;
	}

	for (i = 0; i < nr_vq; i++) {
		ret = lsxvio_rc_init_queue(dev, i);
		if (ret < 0) {
			LSXVIO_PMD_ERR("%s: failed init vq(%d)",
				dev->data->name, i);
			lsxvio_rc_free_queues(hw);
			return ret;
		}
	}

	return 0;
}

static int
lsxvio_rc_eth_close(struct rte_eth_dev *dev)
{
	struct virtio_hw *hw = dev->data->dev_private;

	LSXVIO_PMD_DBG("%s close", dev->data->name);

	if (!hw->opened)
		return 0;

	hw->opened = false;

	lsxvio_rc_virtio_reset(hw);
	lsxvio_rc_free_mbufs(dev);
	lsxvio_rc_free_queues(hw);

	if (dev->device && !s_lsxvio_rc_sim)
		rte_pci_unmap_device(RTE_ETH_DEV_TO_PCI(dev));

	return 0;
}

static int
lsxvio_rc_eth_prom_enable(__rte_unused struct rte_eth_dev *dev)
{
	/* TBD always support.*/

	return 0;
}

static int
lsxvio_rc_eth_prom_disable(__rte_unused struct rte_eth_dev *dev)
{
	/* TBD always support.*/

	return 0;
}

static int
lsxvio_rc_eth_mcast_enable(__rte_unused struct rte_eth_dev *dev)
{
	/* TBD always support.*/

	return 0;
}

static int
lsxvio_rc_eth_mcast_disable(__rte_unused struct rte_eth_dev *dev)
{
	/* TBD always support.*/

	return 0;
}

#define VLAN_TAG_LEN           4    /* 802.3ac tag (not DMA'd) */
static int
lsxvio_rc_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct virtio_hw *hw = dev->data->dev_private;
	uint32_t ether_hdr_len = RTE_ETHER_HDR_LEN + VLAN_TAG_LEN +
				 hw->vtnet_hdr_size;
	uint32_t frame_size = mtu + ether_hdr_len;
	uint32_t max_frame_size = hw->max_mtu + ether_hdr_len;

	max_frame_size = RTE_MIN(max_frame_size, VIRTIO_MAX_RX_PKTLEN);

	if (mtu < RTE_ETHER_MIN_MTU || frame_size > max_frame_size) {
		LSXVIO_PMD_ERR("%s: MTU should be between %d and %d",
			dev->data->name, RTE_ETHER_MIN_MTU,
			max_frame_size - ether_hdr_len);
		return -EINVAL;
	}
	return 0;
}

static int
lsxvio_rc_eth_rxq_intr_enable(struct rte_eth_dev *dev,
	uint16_t queue_id)
{
	struct lsxvio_rc_pci_hw *lsx_hw = dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->pci_dev.hw;
	struct virtnet_rx *rxvq = dev->data->rx_queues[queue_id];
	struct virtqueue *vq = virtnet_rxq_to_vq(rxvq);
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw, true);

	if (lsx_feature & LSX_VIO_EP2RC_PACKED)
		virtqueue_enable_intr_packed(vq);
	virtqueue_enable_intr(vq);
	virtio_mb(hw->weak_barriers);
	return 0;
}

static int
lsxvio_rc_eth_rxq_intr_disable(struct rte_eth_dev *dev,
	uint16_t queue_id)
{
	struct virtnet_rx *rxvq = dev->data->rx_queues[queue_id];
	struct virtqueue *vq = virtnet_rxq_to_vq(rxvq);

	virtqueue_disable_intr(vq);
	return 0;
}

static void
lsxvio_rc_rxq_pool_optimize(struct lsxvio_rc_pci_hw *lsx_hw,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mp, uint16_t q_idx)
{
	struct virtqueue *vq = lsx_hw->pci_dev.hw.vqs[q_idx];
	uint64_t resv0 = rx_conf->reserved_64s[0];
	uint64_t resv1 = rx_conf->reserved_64s[1];
	uint32_t elt_interval;
	int interval_support = 1;
	struct lsxvio_queue_cfg *qcfg =
		&lsx_hw->lsx_cfg->queue_cfg[q_idx];
	struct lsxvio_queue_cfg *txqcfg = qcfg + VTNET_SQ_TQ_QUEUE_IDX;
	uint64_t *local_base;
	uint32_t *local_interval;
	void **shadow_desc;
	uint64_t *shadow_desc_phy;
	const struct rte_memzone **shadow_desc_mz;
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw, true);
	size_t max_size = sizeof(uint64_t) * 4;
	char mz_name[RTE_MEMZONE_NAMESIZE];

#ifndef LSXVIO_TX_PACKED_BD_NOTIFICATION_UPDATE
	qcfg->queue_mem_base = 0;
	qcfg->queue_mem_interval = 0;

	txqcfg->queue_mem_interval = 0;
	txqcfg->queue_mem_interval = 0;

	return;
#endif

	if (resv0 && resv1 && resv1 > resv0 &&
		(resv1 - resv0) <= MAX_U32) {
		qcfg->queue_mem_base = resv0;
		elt_interval = mp->elt_size + mp->header_size +
			mp->trailer_size;
		if (elt_interval * (mp->size - 1) != (resv1 - resv0)) {
			qcfg->queue_mem_interval = 0;
		} else {
			if (mp->size < MAX_U16 && interval_support) {
				qcfg->queue_mem_base += RTE_PKTMBUF_HEADROOM;
				qcfg->queue_mem_interval = elt_interval;
			} else {
				qcfg->queue_mem_interval = 0;
			}
		}
	} else {
		qcfg->queue_mem_base = 0;
		qcfg->queue_mem_interval = 0;
	}
	txqcfg->queue_mem_base = qcfg->queue_mem_base;
	txqcfg->queue_mem_interval = qcfg->queue_mem_interval;

	if (!(lsx_feature & LSX_VIO_EP2RC_PACKED)) {
		qcfg->queue_mem_base = 0;
		qcfg->queue_mem_interval = 0;
	}

	local_base = lsx_hw->local_lsx_cfg.queue_mem_base;
	local_interval = lsx_hw->local_lsx_cfg.queue_mem_interval;
	shadow_desc = lsx_hw->local_lsx_cfg.shadow_desc;
	shadow_desc_phy = lsx_hw->local_lsx_cfg.shadow_desc_phy;
	shadow_desc_mz = lsx_hw->local_lsx_cfg.shadow_desc_mz;

	local_base[q_idx] =	qcfg->queue_mem_base;
	local_interval[q_idx] =	qcfg->queue_mem_interval;
	sprintf(mz_name, "shadow_desc_%d_%p", q_idx, lsx_hw);
	shadow_desc_mz[q_idx] =
		rte_memzone_reserve_aligned(mz_name,
			max_size * vq->vq_nentries, rte_socket_id(),
			0, RTE_CACHE_LINE_SIZE);
	shadow_desc[q_idx] = shadow_desc_mz[q_idx]->addr;
	shadow_desc_phy[q_idx] = shadow_desc_mz[q_idx]->iova;
	qcfg->queue_rc_shadow_base = shadow_desc_phy[q_idx];

	q_idx += VTNET_SQ_TQ_QUEUE_IDX;
	vq = lsx_hw->pci_dev.hw.vqs[q_idx];
	local_base[q_idx] =	txqcfg->queue_mem_base;
	local_interval[q_idx] =	txqcfg->queue_mem_interval;
	sprintf(mz_name, "shadow_desc_%d_%p", q_idx, lsx_hw);
	shadow_desc_mz[q_idx] =
		rte_memzone_reserve_aligned(mz_name,
			max_size * vq->vq_nentries, rte_socket_id(),
			0, RTE_CACHE_LINE_SIZE);
	shadow_desc[q_idx] = shadow_desc_mz[q_idx]->addr;
	shadow_desc_phy[q_idx] = shadow_desc_mz[q_idx]->iova;
	txqcfg->queue_rc_shadow_base = shadow_desc_phy[q_idx];
}

static inline uint16_t
lsxvio_rc_mp_size(struct rte_mempool *mp)
{
	return rte_pktmbuf_data_room_size(mp) - RTE_PKTMBUF_HEADROOM;
}

static int
_lsxvio_rc_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx, uint16_t nb_desc,
	unsigned int socket_id __rte_unused,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mp)
{
	uint16_t vq_idx = 2 * queue_idx + VTNET_SQ_RQ_QUEUE_IDX;
	struct virtio_hw *hw = dev->data->dev_private;
	struct virtqueue *vq = hw->vqs[vq_idx];
	struct virtnet_rx *rxvq;
	uint16_t rx_free_thresh;
	uint16_t buf_size;

	if (rx_conf->rx_deferred_start) {
		LSXVIO_PMD_ERR("Rx deferred start is not supported");
		return -EINVAL;
	}

	buf_size = lsxvio_rc_mp_size(mp);
	if (!hw->rx_ol_scatter && hw->max_rx_pkt_len > buf_size) {
		LSXVIO_PMD_ERR("RxQ%u max_rx_pkt_len(%d) > buf_size(%d)",
			queue_idx, (int)hw->max_rx_pkt_len, buf_size);
		return -EINVAL;
	}

	rx_free_thresh = rx_conf->rx_free_thresh;
	if (rx_free_thresh == 0) {
		rx_free_thresh =
			RTE_MIN(vq->vq_nentries / 4, DEFAULT_RX_FREE_THRESH);
	}

	if (rx_free_thresh & 0x3) {
		LSXVIO_PMD_ERR("%s: rx_free_thresh(%d) NOT multiples of four",
			dev->data->name, rx_free_thresh);
		return -EINVAL;
	}

	if (rx_free_thresh >= vq->vq_nentries) {
		LSXVIO_PMD_ERR("%s rx: free thresh(%d) >= vq(%d).entries(%d)",
			dev->data->name, rx_free_thresh, queue_idx,
			vq->vq_nentries);
		return -EINVAL;
	}
	vq->vq_free_thresh = rx_free_thresh;

	/**
	 * For split ring vectorized path descriptors number must be
	 * equal to the ring size.
	 */
	if (nb_desc > vq->vq_nentries ||
	    (!virtio_with_packed_queue(hw) && hw->use_vec_rx)) {
		nb_desc = vq->vq_nentries;
	}
	vq->vq_free_cnt = RTE_MIN(vq->vq_free_cnt, nb_desc);

	rxvq = &vq->rxq;
	rxvq->queue_id = queue_idx;
	rxvq->mpool = mp;
	dev->data->rx_queues[queue_idx] = rxvq;

	return 0;
}

static int
lsxvio_rc_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mp)
{
	uint16_t vtpci_queue_idx = 2 * queue_idx + VTNET_SQ_RQ_QUEUE_IDX;
	struct lsxvio_rc_pci_hw *lsx_hw = dev->data->dev_private;

	lsxvio_rc_rxq_pool_optimize(lsx_hw, rx_conf, mp, vtpci_queue_idx);
	return _lsxvio_rc_dev_rx_queue_setup(dev, queue_idx, nb_desc,
		socket_id, rx_conf, mp);
}

static int
lsxvio_rc_dev_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx, uint16_t nb_desc,
	unsigned int socket_id __rte_unused,
	const struct rte_eth_txconf *tx_conf)
{
	uint8_t vq_idx = 2 * queue_idx + VTNET_SQ_TQ_QUEUE_IDX;
	struct virtio_hw *hw = dev->data->dev_private;
	struct virtqueue *vq = hw->vqs[vq_idx];
	struct virtnet_tx *txvq;
	uint16_t tx_free_thresh;

	if (tx_conf->tx_deferred_start) {
		LSXVIO_PMD_ERR("Tx deferred start is not supported");
		return -EINVAL;
	}

	if (nb_desc == 0 || nb_desc > vq->vq_nentries)
		nb_desc = vq->vq_nentries;
	vq->vq_free_cnt = RTE_MIN(vq->vq_free_cnt, nb_desc);

	txvq = &vq->txq;
	txvq->queue_id = queue_idx;

	tx_free_thresh = tx_conf->tx_free_thresh;
	if (tx_free_thresh == 0) {
		tx_free_thresh =
			RTE_MIN(vq->vq_nentries / 4, DEFAULT_TX_FREE_THRESH);
	}

	if (tx_free_thresh >= (vq->vq_nentries - 3)) {
		LSXVIO_PMD_ERR("tx free thresh(%d) >= vq(%d).entries(%d)-3",
			tx_free_thresh, queue_idx,
			vq->vq_nentries);
		return -EINVAL;
	}

	vq->vq_free_thresh = tx_free_thresh;

	dev->data->tx_queues[queue_idx] = txvq;
	return 0;
}

static const struct eth_dev_ops lsxvio_rc_eth_dev_ops = {
	.dev_configure           = lsxvio_rc_eth_configure,
	.dev_start               = lsxvio_rc_eth_start,
	.dev_stop                = lsxvio_rc_eth_stop,
	.dev_close               = lsxvio_rc_eth_close,
	.promiscuous_enable      = lsxvio_rc_eth_prom_enable,
	.promiscuous_disable     = lsxvio_rc_eth_prom_disable,
	.allmulticast_enable     = lsxvio_rc_eth_mcast_enable,
	.allmulticast_disable    = lsxvio_rc_eth_mcast_disable,
	.mtu_set                 = lsxvio_rc_mtu_set,
	.dev_infos_get           = lsxvio_rc_eth_info_get,
	.stats_get               = lsxvio_rc_eth_stats_get,
	.xstats_get              = lsxvio_rc_eth_xstats_get,
	.xstats_get_names        = lsxvio_rc_eth_xstats_get_names,
	.stats_reset             = lsxvio_rc_eth_stats_reset,
	.xstats_reset            = lsxvio_rc_eth_stats_reset,
	.link_update             = lsxvio_rc_eth_link_update,
	.rx_queue_setup          = lsxvio_rc_dev_rx_queue_setup,
	.rx_queue_intr_enable    = lsxvio_rc_eth_rxq_intr_enable,
	.rx_queue_intr_disable   = lsxvio_rc_eth_rxq_intr_disable,
	.rx_queue_release        = lsxvio_rc_eth_queue_release,
	.tx_queue_setup          = lsxvio_rc_dev_tx_queue_setup,
	.tx_queue_release        = lsxvio_rc_eth_queue_release,
};

static void
lsxvio_rc_update_stats(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats)
{
	uint32_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		const struct virtnet_tx *txvq = dev->data->tx_queues[i];

		if (!txvq)
			continue;

		stats->opackets += txvq->stats.packets;
		stats->obytes += txvq->stats.bytes;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_opackets[i] = txvq->stats.packets;
			stats->q_obytes[i] = txvq->stats.bytes;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		const struct virtnet_rx *rxvq = dev->data->rx_queues[i];

		if (!rxvq)
			continue;

		stats->ipackets += rxvq->stats.packets;
		stats->ibytes += rxvq->stats.bytes;
		stats->ierrors += rxvq->stats.errors;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_ipackets[i] = rxvq->stats.packets;
			stats->q_ibytes[i] = rxvq->stats.bytes;
		}
	}

	stats->rx_nombuf = dev->data->rx_mbuf_alloc_failed;
}

static int
lsxvio_rc_eth_xstats_get_names(struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names,
	__rte_unused uint32_t limit)
{
	uint32_t i;
	uint32_t count = 0;
	uint32_t t;

	uint32_t nstats = dev->data->nb_tx_queues * LSXVIO_NB_TXQ_XSTATS +
		dev->data->nb_rx_queues * LSXVIO_NB_RXQ_XSTATS;

	if (!xstats_names) {
		/* Note: limit checked in rte_eth_xstats_names() */

		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			struct virtnet_rx *rxvq = dev->data->rx_queues[i];

			if (!rxvq)
				continue;
			for (t = 0; t < LSXVIO_NB_RXQ_XSTATS; t++) {
				snprintf(xstats_names[count].name,
					sizeof(xstats_names[count].name),
					"rx_q%u_%s", i,
					s_lsxvio_rc_rxq_stat_str[t].name);
				count++;
			}
		}

		for (i = 0; i < dev->data->nb_tx_queues; i++) {
			struct virtnet_tx *txvq = dev->data->tx_queues[i];

			if (!txvq)
				continue;
			for (t = 0; t < LSXVIO_NB_TXQ_XSTATS; t++) {
				snprintf(xstats_names[count].name,
					sizeof(xstats_names[count].name),
					"tx_q%u_%s", i,
					s_lsxvio_rc_txq_stat_str[t].name);
				count++;
			}
		}
		return count;
	}
	return nstats;
}

static int
lsxvio_rc_eth_xstats_get(struct rte_eth_dev *dev,
	struct rte_eth_xstat *xstats, uint32_t n)
{
	uint32_t i, t;
	uint32_t count = 0;

	uint32_t nstats = dev->data->nb_tx_queues * LSXVIO_NB_TXQ_XSTATS +
		dev->data->nb_rx_queues * LSXVIO_NB_RXQ_XSTATS;

	if (n < nstats)
		return nstats;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct virtnet_rx *rxvq = dev->data->rx_queues[i];

		if (!rxvq)
			continue;

		for (t = 0; t < LSXVIO_NB_RXQ_XSTATS; t++) {
			xstats[count].value = *(uint64_t *)(((char *)rxvq) +
				s_lsxvio_rc_rxq_stat_str[t].offset);
			xstats[count].id = count;
			count++;
		}
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct virtnet_tx *txvq = dev->data->tx_queues[i];

		if (!txvq)
			continue;

		for (t = 0; t < LSXVIO_NB_TXQ_XSTATS; t++) {
			xstats[count].value = *(uint64_t *)(((char *)txvq) +
				s_lsxvio_rc_txq_stat_str[t].offset);
			xstats[count].id = count;
			count++;
		}
	}

	return count;
}

static int
lsxvio_rc_eth_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats)
{
	lsxvio_rc_update_stats(dev, stats);

	return 0;
}

static int
lsxvio_rc_eth_stats_reset(struct rte_eth_dev *dev)
{
	uint32_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct virtnet_tx *txvq = dev->data->tx_queues[i];

		if (!txvq)
			continue;

		txvq->stats.packets = 0;
		txvq->stats.bytes = 0;
		txvq->stats.multicast = 0;
		txvq->stats.broadcast = 0;
		memset(txvq->stats.size_bins, 0,
		       sizeof(txvq->stats.size_bins[0]) * 8);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct virtnet_rx *rxvq = dev->data->rx_queues[i];

		if (!rxvq)
			continue;

		rxvq->stats.packets = 0;
		rxvq->stats.bytes = 0;
		rxvq->stats.errors = 0;
		rxvq->stats.multicast = 0;
		rxvq->stats.broadcast = 0;
		memset(rxvq->stats.size_bins, 0,
		       sizeof(rxvq->stats.size_bins[0]) * 8);
	}

	return 0;
}

static void
lsxvio_rc_set_hwaddr(struct virtio_hw *hw)
{
	lsxvio_rc_virtio_write_dev_config(hw,
			offsetof(struct virtio_net_config, mac),
			&hw->mac_addr, RTE_ETHER_ADDR_LEN);
}

static void
lsxvio_rc_get_hwaddr(struct virtio_hw *hw)
{
	if (virtio_with_feature(hw, VIRTIO_NET_F_MAC)) {
		lsxvio_rc_virtio_read_dev_config(hw,
			offsetof(struct virtio_net_config, mac),
			&hw->mac_addr, RTE_ETHER_ADDR_LEN);
	} else {
		rte_eth_random_addr(&hw->mac_addr[0]);
		lsxvio_rc_set_hwaddr(hw);
	}
}

static int
lsxvio_rc_negotiate_features(struct virtio_hw *hw,
	uint64_t req_features)
{
	uint64_t host_features;

	/* Prepare guest_features: feature that driver wants to support */
	LSXVIO_PMD_DBG("guest features before negotiate: 0x%lx",
		req_features);

	/* Read device(host) feature bits */
	host_features = LSX_VIO_OPS(hw)->get_features(hw);
	LSXVIO_PMD_DBG("host features before negotiate: 0x%lx",
		host_features);

	/* If supported, ensure MTU value is valid before acknowledging it. */
	if (host_features & req_features & (1ULL << VIRTIO_NET_F_MTU)) {
		struct virtio_net_config config;

		lsxvio_rc_virtio_read_dev_config(hw,
			offsetof(struct virtio_net_config, mtu),
			&config.mtu, sizeof(config.mtu));

		if (config.mtu < RTE_ETHER_MIN_MTU)
			req_features &= ~(1ULL << VIRTIO_NET_F_MTU);
	}

	hw->guest_features = req_features;
	hw->guest_features = lsxvio_rc_virtio_negotiate_features(hw,
		host_features);
	LSXVIO_PMD_DBG("features after negotiate: 0x%lx",
		hw->guest_features);

	if (!virtio_with_feature(hw, VIRTIO_F_VERSION_1)) {
		if (!s_lsxvio_rc_sim) {
			LSXVIO_PMD_ERR("VIRTIO_F_VERSION_1 not enabled!");
			return -EINVAL;
		}
	}
	lsxvio_rc_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_FEATURES_OK);
	if (!(lsxvio_rc_virtio_get_status(hw) &
		VIRTIO_CONFIG_STATUS_FEATURES_OK)) {
		LSXVIO_PMD_ERR("failed to set FEATURES_OK status!");

		return -EINVAL;
	}

	hw->req_guest_features = req_features;

	return 0;
}

static inline void
lsxvio_rc_xmit_help(struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	uint16_t i, len;
	char *src_complete;
	struct rte_mbuf *pkt;

	for (i = 0; i < nb_pkts; i++) {
		pkt = tx_pkts[i];
		len = pkt->pkt_len;
		src_complete = rte_pktmbuf_mtod_offset(pkt, char *, len);
		*src_complete = LSINIC_XFER_COMPLETE_DONE_FLAG;
	}
}

static __rte_always_inline int
lsxcio_rc_virtio_xmit_try_cleanup_inorder(struct virtqueue *vq,
	uint16_t need)
{
	uint16_t nb_used, nb_clean, nb_descs;

	nb_descs = vq->vq_free_cnt + need;
	nb_used = virtqueue_nused(vq);
	nb_clean = RTE_MIN(need, (int)nb_used);

	virtio_xmit_cleanup_inorder(vq, nb_clean);

	return nb_descs - vq->vq_free_cnt;
}

static inline int
lsxvio_rc_tx_cleanup_inorder(struct virtqueue *vq,
	uint16_t need)
{
	return lsxcio_rc_virtio_xmit_try_cleanup_inorder(vq, need);
}

static void
lsxvio_rc_virtio_update_packet_stats(struct virtnet_stats *stats,
	struct rte_mbuf *mbuf)
{
	uint32_t s = mbuf->pkt_len;
	struct rte_ether_addr *ea;

	stats->bytes += s;

	if (s == 64) {
		stats->size_bins[1]++;
	} else if (s > 64 && s < 1024) {
		uint32_t bin;

		/* count zeros, and offset into correct bin */
		bin = (sizeof(s) * 8) - __builtin_clz(s) - 5;
		stats->size_bins[bin]++;
	} else {
		if (s < 64)
			stats->size_bins[0]++;
		else if (s < 1519)
			stats->size_bins[6]++;
		else
			stats->size_bins[7]++;
	}

	ea = rte_pktmbuf_mtod(mbuf, struct rte_ether_addr *);
	if (rte_is_multicast_ether_addr(ea)) {
		if (rte_is_broadcast_ether_addr(ea))
			stats->broadcast++;
		else
			stats->multicast++;
	}
}

static inline void
lsxcio_rc_virtqueue_enqueue_xmit_inorder(struct virtnet_tx *txvq,
	struct rte_mbuf **cookies, uint16_t num)
{
	struct vq_desc_extra *dxp;
	struct virtqueue *vq = virtnet_txq_to_vq(txvq);
	struct vring_desc *start_dp;
	struct virtio_net_hdr *hdr;
	uint16_t idx;
	int16_t head_size = vq->hw->vtnet_hdr_size;
	uint16_t i = 0;

	idx = vq->vq_desc_head_idx;
	start_dp = vq->vq_split.ring.desc;

	while (i < num) {
		idx = idx & (vq->vq_nentries - 1);
		dxp = &vq->vq_descx[vq->vq_avail_idx & (vq->vq_nentries - 1)];
		dxp->cookie = (void *)cookies[i];
		dxp->ndescs = 1;
		lsxvio_rc_virtio_update_packet_stats(&txvq->stats, cookies[i]);

		hdr = rte_pktmbuf_mtod_offset(cookies[i],
				struct virtio_net_hdr *, -head_size);

		/* if offload disabled, hdr is not zeroed yet, do it now */
		if (!vq->hw->has_tx_offload)
			virtqueue_clear_net_hdr(hdr);
		else
			virtqueue_xmit_offload(hdr, cookies[i]);

		start_dp[idx].addr =
			VIRTIO_MBUF_DATA_DMA_ADDR(cookies[i], vq) -
			head_size;
		start_dp[idx].len = cookies[i]->data_len + head_size;
		start_dp[idx].flags = 0;

		vq_update_avail_ring(vq, idx);

		idx++;
		i++;
	};

	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - num);
	vq->vq_desc_head_idx = idx & (vq->vq_nentries - 1);
}

static inline void
lsxvio_rc_virtqueue_enqueue_xmit(struct virtnet_tx *txvq,
	struct rte_mbuf *cookie,
	uint16_t needed, int use_indirect, int can_push,
	int in_order)
{
	struct virtio_tx_region *txr = txvq->virtio_net_hdr_mz->addr;
	struct vq_desc_extra *dxp;
	struct virtqueue *vq = virtnet_txq_to_vq(txvq);
	struct vring_desc *start_dp;
	uint16_t seg_num = cookie->nb_segs;
	uint16_t head_idx, idx;
	int16_t head_size = vq->hw->vtnet_hdr_size;
	bool prepend_header = false;
	struct virtio_net_hdr *hdr;

	head_idx = vq->vq_desc_head_idx;
	idx = head_idx;
	if (in_order)
		dxp = &vq->vq_descx[vq->vq_avail_idx & (vq->vq_nentries - 1)];
	else
		dxp = &vq->vq_descx[idx];
	dxp->cookie = (void *)cookie;
	dxp->ndescs = needed;

	start_dp = vq->vq_split.ring.desc;

	if (can_push) {
		/* prepend cannot fail, checked by caller */
		hdr = rte_pktmbuf_mtod_offset(cookie, struct virtio_net_hdr *,
					      -head_size);
		prepend_header = true;

		/* if offload disabled, it is not zeroed below, do it now */
		if (!vq->hw->has_tx_offload)
			virtqueue_clear_net_hdr(hdr);
	} else if (use_indirect) {
		/* setup tx ring slot to point to indirect
		 * descriptor list stored in reserved region.
		 *
		 * the first slot in indirect ring is already preset
		 * to point to the header in reserved region
		 */
		start_dp[idx].addr  = txvq->virtio_net_hdr_mem +
			RTE_PTR_DIFF(&txr[idx].tx_indir, txr);
		start_dp[idx].len   = (seg_num + 1) * sizeof(struct vring_desc);
		start_dp[idx].flags = VRING_DESC_F_INDIRECT;
		hdr = (struct virtio_net_hdr *)&txr[idx].tx_hdr;

		/* loop below will fill in rest of the indirect elements */
		start_dp = txr[idx].tx_indir;
		idx = 1;
	} else {
		/* setup first tx ring slot to point to header
		 * stored in reserved region.
		 */
		start_dp[idx].addr  = txvq->virtio_net_hdr_mem +
			RTE_PTR_DIFF(&txr[idx].tx_hdr, txr);
		start_dp[idx].len   = vq->hw->vtnet_hdr_size;
		start_dp[idx].flags = VRING_DESC_F_NEXT;
		hdr = (struct virtio_net_hdr *)&txr[idx].tx_hdr;

		idx = start_dp[idx].next;
	}

	if (vq->hw->has_tx_offload)
		virtqueue_xmit_offload(hdr, cookie);

	do {
		start_dp[idx].addr = VIRTIO_MBUF_DATA_DMA_ADDR(cookie, vq);
		start_dp[idx].len = cookie->data_len;
		if (prepend_header) {
			start_dp[idx].addr -= head_size;
			start_dp[idx].len += head_size;
			prepend_header = false;
		}
		start_dp[idx].flags = cookie->next ? VRING_DESC_F_NEXT : 0;
		idx = start_dp[idx].next;
	} while ((cookie = cookie->next) != NULL);

	if (use_indirect)
		idx = vq->vq_split.ring.desc[head_idx].next;

	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - needed);

	vq->vq_desc_head_idx = idx;
	vq_update_avail_ring(vq, head_idx);

	if (!in_order) {
		if (vq->vq_desc_head_idx == VQ_RING_DESC_CHAIN_END)
			vq->vq_desc_tail_idx = idx;
	}
}

static uint16_t
lsxvio_rc_xmit_pkts_inorder(void *tx_queue,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct virtnet_tx *txvq = tx_queue;
	struct virtqueue *vq = virtnet_txq_to_vq(txvq);
	struct virtio_hw *hw = vq->hw;
	uint16_t hdr_size = hw->vtnet_hdr_size;
	uint16_t nb_used, nb_tx = 0, nb_inorder_pkts = 0;
	struct rte_mbuf *inorder_pkts[nb_pkts];
	int need;

	if (unlikely(hw->started == 0 && tx_pkts != hw->inject_pkts))
		return nb_tx;

	if (unlikely(nb_pkts < 1))
		return nb_pkts;

	LSXVIO_RC_VIRTQUEUE_DUMP(vq);
	LSXVIO_PMD_DBG("%d packets to xmit", nb_pkts);
	nb_used = virtqueue_nused(vq);

	if (likely(nb_used > vq->vq_nentries - vq->vq_free_thresh))
		virtio_xmit_cleanup_inorder(vq, nb_used);

	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		struct rte_mbuf *txm = tx_pkts[nb_tx];
		int slots;

		/* optimize ring usage */
		if ((virtio_with_feature(hw, VIRTIO_F_ANY_LAYOUT) ||
		     virtio_with_feature(hw, VIRTIO_F_VERSION_1)) &&
		     rte_mbuf_refcnt_read(txm) == 1 &&
		     RTE_MBUF_DIRECT(txm) &&
		     txm->nb_segs == 1 &&
		     rte_pktmbuf_headroom(txm) >= hdr_size &&
		     rte_is_aligned(rte_pktmbuf_mtod(txm, char *),
				__alignof__(struct virtio_net_hdr_mrg_rxbuf))) {
			inorder_pkts[nb_inorder_pkts] = txm;
			nb_inorder_pkts++;

			continue;
		}

		if (nb_inorder_pkts) {
			need = nb_inorder_pkts - vq->vq_free_cnt;
			if (unlikely(need > 0)) {
				need = lsxvio_rc_tx_cleanup_inorder(vq,
						need);
				if (unlikely(need > 0)) {
					LSXVIO_PMD_ERR("No free tx bd");
					break;
				}
			}
			lsxcio_rc_virtqueue_enqueue_xmit_inorder(txvq,
				inorder_pkts, nb_inorder_pkts);
			nb_inorder_pkts = 0;
		}

		slots = txm->nb_segs + 1;
		need = slots - vq->vq_free_cnt;
		if (unlikely(need > 0)) {
			need = lsxvio_rc_tx_cleanup_inorder(vq, slots);
			if (unlikely(need > 0)) {
				LSXVIO_PMD_ERR("No free tx bd");
				break;
			}
		}
		/* Enqueue Packet buffers */
		lsxvio_rc_virtqueue_enqueue_xmit(txvq, txm, slots, 0, 0, 1);

		lsxvio_rc_virtio_update_packet_stats(&txvq->stats, txm);
	}

	/* Transmit all inorder packets */
	if (nb_inorder_pkts) {
		need = nb_inorder_pkts - vq->vq_free_cnt;
		if (unlikely(need > 0)) {
			need = lsxvio_rc_tx_cleanup_inorder(vq,
					need);
			if (unlikely(need > 0)) {
				LSXVIO_PMD_ERR("No free tx bd");
				nb_inorder_pkts = vq->vq_free_cnt;
				nb_tx -= need;
			}
		}

		lsxcio_rc_virtqueue_enqueue_xmit_inorder(txvq,
			inorder_pkts, nb_inorder_pkts);
	}

	txvq->stats.packets += nb_tx;

	if (likely(nb_tx)) {
		vq_update_avail_idx(vq);

		if (unlikely(virtqueue_kick_prepare(vq))) {
			lsxvio_rc_virtqueue_notify(vq);
			LSXVIO_PMD_DBG("Notified backend after xmit");
		}
	}

	LSXVIO_RC_VIRTQUEUE_DUMP(vq);

	return nb_tx;
}

static uint16_t
lsxvio_rc_xmit_pkts_inorder_help(void *tx_queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	lsxvio_rc_xmit_help(tx_pkts, nb_pkts);

	return lsxvio_rc_xmit_pkts_inorder(tx_queue, tx_pkts, nb_pkts);
}

static inline void
lsxvio_rc_virtio_xmit_cleanup(struct virtqueue *vq, uint16_t num)
{
	uint16_t i, used_idx, desc_idx;

	for (i = 0; i < num; i++) {
		struct vring_used_elem *uep;
		struct vq_desc_extra *dxp;

		used_idx = (uint16_t)(vq->vq_used_cons_idx &
				(vq->vq_nentries - 1));
		uep = &vq->vq_split.ring.used->ring[used_idx];

		desc_idx = (uint16_t)uep->id;
		dxp = &vq->vq_descx[desc_idx];
		vq->vq_used_cons_idx++;
		lsxvio_rc_vq_ring_free_chain(vq, desc_idx);

		if (dxp->cookie) {
			rte_pktmbuf_free(dxp->cookie);
			dxp->cookie = NULL;
		}
	}
}

static uint16_t
lsxvio_rc_virtio_xmit_pkts(void *tx_queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct virtnet_tx *txvq = tx_queue;
	struct virtqueue *vq = virtnet_txq_to_vq(txvq);
	struct virtio_hw *hw = vq->hw;
	uint16_t hdr_size = hw->vtnet_hdr_size;
	uint16_t nb_used, nb_tx = 0;

	if (unlikely(hw->started == 0 && tx_pkts != hw->inject_pkts))
		return nb_tx;

	if (unlikely(nb_pkts < 1))
		return nb_pkts;

	LSXVIO_PMD_DBG("%d packets to xmit", nb_pkts);

	nb_used = virtqueue_nused(vq);

	if (likely(nb_used > vq->vq_nentries - vq->vq_free_thresh))
		lsxvio_rc_virtio_xmit_cleanup(vq, nb_used);

	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		struct rte_mbuf *txm = tx_pkts[nb_tx];
		int can_push = 0, use_indirect = 0, slots, need;

		/* optimize ring usage */
		if ((virtio_with_feature(hw, VIRTIO_F_ANY_LAYOUT) ||
		      virtio_with_feature(hw, VIRTIO_F_VERSION_1)) &&
		    rte_mbuf_refcnt_read(txm) == 1 &&
		    RTE_MBUF_DIRECT(txm) &&
		    txm->nb_segs == 1 &&
		    rte_pktmbuf_headroom(txm) >= hdr_size &&
		    rte_is_aligned(rte_pktmbuf_mtod(txm, char *),
				__alignof__(struct virtio_net_hdr_mrg_rxbuf)))
			can_push = 1;
		else if (virtio_with_feature(hw, VIRTIO_RING_F_INDIRECT_DESC) &&
			 txm->nb_segs < VIRTIO_MAX_TX_INDIRECT)
			use_indirect = 1;

		/* How many main ring entries are needed to this Tx?
		 * any_layout => number of segments
		 * indirect   => 1
		 * default    => number of segments + 1
		 */
		slots = use_indirect ? 1 : (txm->nb_segs + !can_push);
		need = slots - vq->vq_free_cnt;

		/* Positive value indicates it need free vring descriptors */
		if (unlikely(need > 0)) {
			nb_used = virtqueue_nused(vq);

			need = RTE_MIN(need, (int)nb_used);

			lsxvio_rc_virtio_xmit_cleanup(vq, need);
			need = slots - vq->vq_free_cnt;
			if (unlikely(need > 0)) {
				LSXVIO_PMD_ERR("No free tx bd");
				break;
			}
		}

		/* Enqueue Packet buffers */
		lsxvio_rc_virtqueue_enqueue_xmit(txvq, txm, slots,
			use_indirect, can_push, 0);

		lsxvio_rc_virtio_update_packet_stats(&txvq->stats, txm);
	}

	txvq->stats.packets += nb_tx;

	if (likely(nb_tx)) {
		vq_update_avail_idx(vq);

		if (unlikely(virtqueue_kick_prepare(vq))) {
			lsxvio_rc_virtqueue_notify(vq);
			LSXVIO_PMD_DBG("Notified backend after xmit");
		}
	}

	return nb_tx;
}

static uint16_t
lsxvio_rc_xmit_pkts_help(void *tx_queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	lsxvio_rc_xmit_help(tx_pkts, nb_pkts);

	return lsxvio_rc_virtio_xmit_pkts(tx_queue, tx_pkts, nb_pkts);
}

static void
lsxvio_rc_virtio_tso_fix_cksum(struct rte_mbuf *m)
{
	/* common case: header is not fragmented */
	if (likely(rte_pktmbuf_data_len(m) >= m->l2_len + m->l3_len +
			m->l4_len)) {
		struct rte_ipv4_hdr *iph;
		struct rte_ipv6_hdr *ip6h;
		struct rte_tcp_hdr *th;
		uint16_t prev_cksum, new_cksum, ip_len, ip_paylen;
		uint32_t tmp;

		iph = rte_pktmbuf_mtod_offset(m,
					struct rte_ipv4_hdr *, m->l2_len);
		th = RTE_PTR_ADD(iph, m->l3_len);
		if ((iph->version_ihl >> 4) == 4) {
			iph->hdr_checksum = 0;
			iph->hdr_checksum = rte_ipv4_cksum(iph);
			ip_len = iph->total_length;
			ip_paylen = rte_cpu_to_be_16(rte_be_to_cpu_16(ip_len) -
				m->l3_len);
		} else {
			ip6h = (struct rte_ipv6_hdr *)iph;
			ip_paylen = ip6h->payload_len;
		}

		/* calculate the new phdr checksum not including ip_paylen */
		prev_cksum = th->cksum;
		tmp = prev_cksum;
		tmp += ip_paylen;
		tmp = (tmp & 0xffff) + (tmp >> 16);
		new_cksum = tmp;

		/* replace it in the packet */
		th->cksum = new_cksum;
	}
}

static uint16_t
lsxvio_rc_virtio_xmit_pkts_prepare(void *tx_queue __rte_unused,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint16_t nb_tx;
	int error;

	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		struct rte_mbuf *m = tx_pkts[nb_tx];

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
		error = rte_validate_tx_offload(m);
		if (unlikely(error)) {
			rte_errno = -error;
			break;
		}
#endif

		/* Do VLAN tag insertion */
		if (unlikely(m->ol_flags & RTE_MBUF_F_TX_VLAN)) {
			error = rte_vlan_insert(&m);
			/* rte_vlan_insert() may change pointer
			 * even in the case of failure
			 */
			tx_pkts[nb_tx] = m;

			if (unlikely(error)) {
				rte_errno = -error;
				break;
			}
		}

		error = rte_net_intel_cksum_prepare(m);
		if (unlikely(error)) {
			rte_errno = -error;
			break;
		}

		if (m->ol_flags & RTE_MBUF_F_TX_TCP_SEG)
			lsxvio_rc_virtio_tso_fix_cksum(m);
	}

	return nb_tx;
}

static uint16_t
lsxvio_rc_virtio_xmit_pkts_inorder(void *tx_queue,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct virtnet_tx *txvq = tx_queue;
	struct virtqueue *vq = virtnet_txq_to_vq(txvq);
	struct virtio_hw *hw = vq->hw;
	uint16_t hdr_size = hw->vtnet_hdr_size;
	uint16_t nb_used, nb_tx = 0, nb_inorder_pkts = 0;
	struct rte_mbuf *inorder_pkts[nb_pkts];
	int need;

	if (unlikely(hw->started == 0 && tx_pkts != hw->inject_pkts))
		return nb_tx;

	if (unlikely(nb_pkts < 1))
		return nb_pkts;

	LSXVIO_RC_VIRTQUEUE_DUMP(vq);
	LSXVIO_PMD_DBG("%d packets to xmit", nb_pkts);
	nb_used = virtqueue_nused(vq);

	if (likely(nb_used > vq->vq_nentries - vq->vq_free_thresh))
		virtio_xmit_cleanup_inorder(vq, nb_used);

	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		struct rte_mbuf *txm = tx_pkts[nb_tx];
		int slots;

		/* optimize ring usage */
		if ((virtio_with_feature(hw, VIRTIO_F_ANY_LAYOUT) ||
		     virtio_with_feature(hw, VIRTIO_F_VERSION_1)) &&
		     rte_mbuf_refcnt_read(txm) == 1 &&
		     RTE_MBUF_DIRECT(txm) &&
		     txm->nb_segs == 1 &&
		     rte_pktmbuf_headroom(txm) >= hdr_size &&
		     rte_is_aligned(rte_pktmbuf_mtod(txm, char *),
				__alignof__(struct virtio_net_hdr_mrg_rxbuf))) {
			inorder_pkts[nb_inorder_pkts] = txm;
			nb_inorder_pkts++;

			continue;
		}

		if (nb_inorder_pkts) {
			need = nb_inorder_pkts - vq->vq_free_cnt;
			if (unlikely(need > 0)) {
				need = lsxvio_rc_tx_cleanup_inorder(vq,
						need);
				if (unlikely(need > 0)) {
					LSXVIO_PMD_ERR("No free tx bd");
					break;
				}
			}
			lsxcio_rc_virtqueue_enqueue_xmit_inorder(txvq,
				inorder_pkts, nb_inorder_pkts);
			nb_inorder_pkts = 0;
		}

		slots = txm->nb_segs + 1;
		need = slots - vq->vq_free_cnt;
		if (unlikely(need > 0)) {
			need = lsxvio_rc_tx_cleanup_inorder(vq, slots);
			if (unlikely(need > 0)) {
				LSXVIO_PMD_ERR("No free tx bd");
				break;
			}
		}
		/* Enqueue Packet buffers */
		lsxvio_rc_virtqueue_enqueue_xmit(txvq, txm, slots, 0, 0, 1);

		lsxvio_rc_virtio_update_packet_stats(&txvq->stats, txm);
	}

	/* Transmit all inorder packets */
	if (nb_inorder_pkts) {
		need = nb_inorder_pkts - vq->vq_free_cnt;
		if (unlikely(need > 0)) {
			need = lsxvio_rc_tx_cleanup_inorder(vq,
					need);
			if (unlikely(need > 0)) {
				LSXVIO_PMD_ERR("No free tx bd");
				nb_inorder_pkts = vq->vq_free_cnt;
				nb_tx -= need;
			}
		}

		lsxcio_rc_virtqueue_enqueue_xmit_inorder(txvq,
			inorder_pkts, nb_inorder_pkts);
	}

	txvq->stats.packets += nb_tx;

	if (likely(nb_tx)) {
		vq_update_avail_idx(vq);

		if (unlikely(virtqueue_kick_prepare(vq))) {
			lsxvio_rc_virtqueue_notify(vq);
			LSXVIO_PMD_DBG("Notified backend after xmit");
		}
	}

	LSXVIO_RC_VIRTQUEUE_DUMP(vq);

	return nb_tx;
}

static uint16_t
lsxvio_rc_virtqueue_dequeue_burst_rx_packed(struct virtqueue *vq,
	struct rte_mbuf **rx_pkts, uint32_t *len, uint16_t num)
{
	struct rte_mbuf *cookie;
	uint16_t used_idx;
	uint16_t id;
	struct vring_packed_desc *desc;
	uint16_t i;

	desc = vq->vq_packed.ring.desc;

	for (i = 0; i < num; i++) {
		used_idx = vq->vq_used_cons_idx;
		/* desc_is_used has a load-acquire or rte_io_rmb inside
		 * and wait for used desc in virtqueue.
		 */
		if (!desc_is_used(&desc[used_idx], vq))
			return i;
		len[i] = desc[used_idx].len;
		id = desc[used_idx].id;
		cookie = (struct rte_mbuf *)vq->vq_descx[id].cookie;
		if (unlikely(!cookie)) {
			LSXVIO_PMD_ERR("vring bd with no mbuf cookie at %u",
				vq->vq_used_cons_idx);
			break;
		}
		rte_prefetch0(cookie);
		rte_packet_prefetch(rte_pktmbuf_mtod(cookie, void *));
		rx_pkts[i] = cookie;

		vq->vq_free_cnt++;
		vq->vq_used_cons_idx++;
		if (vq->vq_used_cons_idx >= vq->vq_nentries) {
			vq->vq_used_cons_idx -= vq->vq_nentries;
			vq->vq_packed.used_wrap_counter ^= 1;
		}
	}

	return i;
}

static inline void
lsxvio_rc_virtqueue_refill_single_packed(struct virtqueue *vq,
	struct vring_packed_desc *dp,
	struct rte_mbuf *cookie)
{
	uint16_t flags = vq->vq_packed.cached_flags;
	struct virtio_hw *hw = vq->hw;

	dp->addr = VIRTIO_MBUF_ADDR(cookie, vq) +
		RTE_PKTMBUF_HEADROOM - hw->vtnet_hdr_size;
	dp->len = cookie->buf_len - RTE_PKTMBUF_HEADROOM +
		hw->vtnet_hdr_size;

	virtqueue_store_flags_packed(dp, flags, hw->weak_barriers);

	if (++vq->vq_avail_idx >= vq->vq_nentries) {
		vq->vq_avail_idx -= vq->vq_nentries;
		vq->vq_packed.cached_flags ^=
			VRING_PACKED_DESC_F_AVAIL_USED;
		flags = vq->vq_packed.cached_flags;
	}
}

static inline int
lsxvio_rc_virtqueue_enqueue_recv_refill_packed(struct virtqueue *vq,
	struct rte_mbuf **cookie, uint16_t num)
{
	struct vring_packed_desc *start_dp = vq->vq_packed.ring.desc;
	struct vq_desc_extra *dxp;
	uint16_t idx, did;
	int i;

	if (unlikely(vq->vq_free_cnt == 0))
		return -ENOSPC;
	if (unlikely(vq->vq_free_cnt < num))
		return -EMSGSIZE;

	for (i = 0; i < num; i++) {
		idx = vq->vq_avail_idx;
		did = start_dp[idx].id;
		dxp = &vq->vq_descx[did];
		dxp->cookie = (void *)cookie[i];
		dxp->ndescs = 1;

		lsxvio_rc_virtqueue_refill_single_packed(vq,
			&start_dp[idx], cookie[i]);
	}
	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - num);
	return 0;
}

static inline int
lsxvio_rc_virtqueue_enqueue_recv_refill(struct virtqueue *vq,
	struct rte_mbuf **cookie, uint16_t num)
{
	struct vq_desc_extra *dxp;
	struct virtio_hw *hw = vq->hw;
	struct vring_desc *start_dp = vq->vq_split.ring.desc;
	uint16_t idx, i;

	if (unlikely(vq->vq_free_cnt == 0))
		return -ENOSPC;
	if (unlikely(vq->vq_free_cnt < num))
		return -EMSGSIZE;

	if (unlikely(vq->vq_desc_head_idx >= vq->vq_nentries))
		return -EFAULT;

	for (i = 0; i < num; i++) {
		idx = vq->vq_desc_head_idx;
		dxp = &vq->vq_descx[idx];
		dxp->cookie = (void *)cookie[i];
		dxp->ndescs = 1;

		start_dp[idx].addr = VIRTIO_MBUF_ADDR(cookie[i], vq) +
			RTE_PKTMBUF_HEADROOM - hw->vtnet_hdr_size;
		start_dp[idx].len = cookie[i]->buf_len - RTE_PKTMBUF_HEADROOM +
			hw->vtnet_hdr_size;
		start_dp[idx].flags = VRING_DESC_F_WRITE;
		vq->vq_desc_head_idx = start_dp[idx].next;
		vq_update_avail_ring(vq, idx);
		if (vq->vq_desc_head_idx == VQ_RING_DESC_CHAIN_END) {
			vq->vq_desc_tail_idx = vq->vq_desc_head_idx;
			break;
		}
	}

	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - num);

	return 0;
}

static inline void
lsxvio_rc_virtio_discard_rxbuf(struct virtqueue *vq,
	struct rte_mbuf *m)
{
	int error;
	/**
	 * Requeue the discarded mbuf. This should always be
	 * successful since it was just dequeued.
	 */
	if (virtio_with_packed_queue(vq->hw)) {
		error = lsxvio_rc_virtqueue_enqueue_recv_refill_packed(vq,
			&m, 1);
	} else {
		error = lsxvio_rc_virtqueue_enqueue_recv_refill(vq,
			&m, 1);
	}

	if (unlikely(error)) {
		LSXVIO_PMD_ERR("cannot requeue discarded mbuf");
		rte_pktmbuf_free(m);
	}
}

static inline int
lsxvio_rc_virtio_rx_offload(struct rte_mbuf *m,
	struct virtio_net_hdr *hdr)
{
	struct rte_net_hdr_lens hdr_lens;
	uint32_t hdrlen, ptype;
	int l4_supported = 0;

	/* nothing to do */
	if (hdr->flags == 0 && hdr->gso_type == VIRTIO_NET_HDR_GSO_NONE)
		return 0;

	m->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN;

	ptype = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_ALL_MASK);
	m->packet_type = ptype;
	if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP ||
	    (ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP ||
	    (ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_SCTP)
		l4_supported = 1;

	if (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
		hdrlen = hdr_lens.l2_len + hdr_lens.l3_len + hdr_lens.l4_len;
		if (hdr->csum_start <= hdrlen && l4_supported) {
			m->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_NONE;
		} else {
			/* Unknown proto or tunnel, do sw cksum. We can assume
			 * the cksum field is in the first segment since the
			 * buffers we provided to the host are large enough.
			 * In case of SCTP, this will be wrong since it's a CRC
			 * but there's nothing we can do.
			 */
			uint16_t csum = 0, off;

			if (rte_raw_cksum_mbuf(m, hdr->csum_start,
				rte_pktmbuf_pkt_len(m) - hdr->csum_start,
				&csum) < 0)
				return -EINVAL;
			if (likely(csum != 0xffff))
				csum = ~csum;
			off = hdr->csum_offset + hdr->csum_start;
			if (rte_pktmbuf_data_len(m) >= off + 1)
				*rte_pktmbuf_mtod_offset(m, uint16_t *,
					off) = csum;
		}
	} else if (hdr->flags & VIRTIO_NET_HDR_F_DATA_VALID && l4_supported) {
		m->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_GOOD;
	}

	/* GSO request, save required information in mbuf */
	if (hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
		/* Check unsupported modes */
		if ((hdr->gso_type & VIRTIO_NET_HDR_GSO_ECN) ||
		    !hdr->gso_size) {
			return -EINVAL;
		}

		/* Update mss lengthes in mbuf */
		m->tso_segsz = hdr->gso_size;
		switch (hdr->gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
		case VIRTIO_NET_HDR_GSO_TCPV4:
		case VIRTIO_NET_HDR_GSO_TCPV6:
			m->ol_flags |= RTE_MBUF_F_RX_LRO |
				RTE_MBUF_F_RX_L4_CKSUM_NONE;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static inline void
lsxvio_rc_virtio_rx_stats_updated(struct virtnet_rx *rxvq,
	struct rte_mbuf *m)
{
	lsxvio_rc_virtio_update_packet_stats(&rxvq->stats, m);
}

static uint16_t
lsxvio_rc_virtqueue_dequeue_burst_rx(struct virtqueue *vq,
	struct rte_mbuf **rx_pkts, uint32_t *len, uint16_t num)
{
	struct vring_used_elem *uep;
	struct rte_mbuf *cookie;
	uint16_t used_idx, desc_idx;
	uint16_t i;

	/*  Caller does the check */
	for (i = 0; i < num ; i++) {
		used_idx = (vq->vq_used_cons_idx & (vq->vq_nentries - 1));
		uep = &vq->vq_split.ring.used->ring[used_idx];
		desc_idx = (uint16_t)uep->id;
		len[i] = uep->len;
		cookie = (struct rte_mbuf *)vq->vq_descx[desc_idx].cookie;

		if (unlikely(!cookie)) {
			LSXVIO_PMD_ERR("vring bd with no mbuf cookie at %u",
				vq->vq_used_cons_idx);
			break;
		}

		rte_prefetch0(cookie);
		rte_packet_prefetch(rte_pktmbuf_mtod(cookie, void *));
		rx_pkts[i]  = cookie;
		vq->vq_used_cons_idx++;
		lsxvio_rc_vq_ring_free_chain(vq, desc_idx);
		vq->vq_descx[desc_idx].cookie = NULL;
	}

	return i;
}

#define VIO_DESC_PER_CACHELINE \
	(RTE_CACHE_LINE_SIZE / sizeof(struct vring_desc))

static inline void
lsxvio_rc_alloc_refill_buf(struct virtnet_rx *rxvq,
	uint32_t *nb_enqueued)
{
	struct virtqueue *vq = virtnet_rxq_to_vq(rxvq);
	uint16_t free_cnt = vq->vq_free_cnt;
	struct rte_mbuf *new_pkts[free_cnt];
	int ret, i;

	ret = rte_pktmbuf_alloc_bulk(rxvq->mpool,
		new_pkts, free_cnt);
	if (unlikely(ret)) {
		struct rte_eth_dev *dev =
			&rte_eth_devices[rxvq->port_id];

		dev->data->rx_mbuf_alloc_failed += free_cnt;
		return;
	}

	ret = lsxvio_rc_virtqueue_enqueue_recv_refill_packed(vq,
		new_pkts, free_cnt);
	if (unlikely(ret)) {
		for (i = 0; i < free_cnt; i++)
			rte_pktmbuf_free(new_pkts[i]);
	}
	if (likely(nb_enqueued))
		(*nb_enqueued) += free_cnt;
}

static uint16_t
lsxvio_rc_virtio_recv_pkts_packed(void *rx_queue,
	struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct virtnet_rx *rxvq = rx_queue;
	struct virtqueue *vq = virtnet_rxq_to_vq(rxvq);
	struct virtio_hw *hw = vq->hw;
	struct rte_mbuf *rxm;
	uint16_t num, nb_rx;
	uint32_t len[VIRTIO_MBUF_BURST_SZ];
	struct rte_mbuf *rcv_pkts[VIRTIO_MBUF_BURST_SZ];
	uint32_t i, nb_enqueued;
	uint32_t hdr_size;
	struct virtio_net_hdr *hdr;

	nb_rx = 0;
	if (unlikely(hw->started == 0))
		return nb_rx;

	num = RTE_MIN(VIRTIO_MBUF_BURST_SZ, nb_pkts);
	if (likely(num > VIO_DESC_PER_CACHELINE)) {
		num = num - ((vq->vq_used_cons_idx + num) %
			VIO_DESC_PER_CACHELINE);
	}

	num = lsxvio_rc_virtqueue_dequeue_burst_rx_packed(vq,
		rcv_pkts, len, num);
	LSXVIO_PMD_DBG("dequeue:%d", num);

	nb_enqueued = 0;
	hdr_size = hw->vtnet_hdr_size;

	for (i = 0; i < num; i++) {
		rxm = rcv_pkts[i];

		LSXVIO_PMD_DBG("packet len:%d", len[i]);

		if (unlikely(len[i] < hdr_size + RTE_ETHER_HDR_LEN)) {
			LSXVIO_PMD_ERR("Packet drop");
			nb_enqueued++;
			lsxvio_rc_virtio_discard_rxbuf(vq, rxm);
			rxvq->stats.errors++;
			continue;
		}

		rxm->port = rxvq->port_id;
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rxm->ol_flags = 0;
		rxm->vlan_tci = 0;

		rxm->pkt_len = (uint32_t)(len[i] - hdr_size);
		rxm->data_len = (uint16_t)(len[i] - hdr_size);

		hdr = (struct virtio_net_hdr *)((char *)rxm->buf_addr +
			RTE_PKTMBUF_HEADROOM - hdr_size);

		if (hw->vlan_strip)
			rte_vlan_strip(rxm);

		if (hw->has_rx_offload &&
			lsxvio_rc_virtio_rx_offload(rxm, hdr) < 0) {
			lsxvio_rc_virtio_discard_rxbuf(vq, rxm);
			rxvq->stats.errors++;
			continue;
		}

		lsxvio_rc_virtio_rx_stats_updated(rxvq, rxm);

		rx_pkts[nb_rx++] = rxm;
	}

	rxvq->stats.packets += nb_rx;

	/* Allocate new mbuf for the used descriptor */
	if (likely(!virtqueue_full(vq)))
		lsxvio_rc_alloc_refill_buf(rxvq, &nb_enqueued);

	if (likely(nb_enqueued)) {
		if (unlikely(virtqueue_kick_prepare_packed(vq))) {
			lsxvio_rc_virtqueue_notify(vq);
			LSXVIO_PMD_DBG("Notified");
		}
	}

	return nb_rx;
}

static uint16_t
lsxvio_rc_virtio_recv_pkts(void *rx_queue,
	struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct virtnet_rx *rxvq = rx_queue;
	struct virtqueue *vq = virtnet_rxq_to_vq(rxvq);
	struct virtio_hw *hw = vq->hw;
	struct rte_mbuf *rxm;
	uint16_t nb_used, num, nb_rx;
	uint32_t len[VIRTIO_MBUF_BURST_SZ];
	struct rte_mbuf *rcv_pkts[VIRTIO_MBUF_BURST_SZ];
	int error;
	uint32_t i, nb_enqueued;
	uint32_t hdr_size;
	struct virtio_net_hdr *hdr;

	nb_rx = 0;
	if (unlikely(hw->started == 0))
		return nb_rx;

	nb_used = virtqueue_nused(vq);

	num = likely(nb_used <= nb_pkts) ? nb_used : nb_pkts;
	if (unlikely(num > VIRTIO_MBUF_BURST_SZ))
		num = VIRTIO_MBUF_BURST_SZ;
	if (likely(num > VIO_DESC_PER_CACHELINE)) {
		num = num - ((vq->vq_used_cons_idx + num) %
			VIO_DESC_PER_CACHELINE);
	}

	num = lsxvio_rc_virtqueue_dequeue_burst_rx(vq, rcv_pkts, len, num);
	LSXVIO_PMD_DBG("used:%d dequeue:%d", nb_used, num);

	nb_enqueued = 0;
	hdr_size = hw->vtnet_hdr_size;

	for (i = 0; i < num ; i++) {
		rxm = rcv_pkts[i];

		LSXVIO_PMD_DBG("packet len:%d", len[i]);

		if (unlikely(len[i] < hdr_size + RTE_ETHER_HDR_LEN)) {
			LSXVIO_PMD_ERR("Packet drop");
			nb_enqueued++;
			lsxvio_rc_virtio_discard_rxbuf(vq, rxm);
			rxvq->stats.errors++;
			continue;
		}

		rxm->port = rxvq->port_id;
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rxm->ol_flags = 0;
		rxm->vlan_tci = 0;

		rxm->pkt_len = (uint32_t)(len[i] - hdr_size);
		rxm->data_len = (uint16_t)(len[i] - hdr_size);

		hdr = (struct virtio_net_hdr *)((char *)rxm->buf_addr +
			RTE_PKTMBUF_HEADROOM - hdr_size);

		if (hw->vlan_strip)
			rte_vlan_strip(rxm);

		if (hw->has_rx_offload &&
			lsxvio_rc_virtio_rx_offload(rxm, hdr) < 0) {
			lsxvio_rc_virtio_discard_rxbuf(vq, rxm);
			rxvq->stats.errors++;
			continue;
		}

		lsxvio_rc_virtio_rx_stats_updated(rxvq, rxm);

		rx_pkts[nb_rx++] = rxm;
	}

	rxvq->stats.packets += nb_rx;

	/* Allocate new mbuf for the used descriptor */
	if (likely(!virtqueue_full(vq))) {
		uint16_t free_cnt = vq->vq_free_cnt;
		struct rte_mbuf *new_pkts[free_cnt];

		if (likely(rte_pktmbuf_alloc_bulk(rxvq->mpool, new_pkts,
						free_cnt) == 0)) {
			error = lsxvio_rc_virtqueue_enqueue_recv_refill(vq,
				new_pkts, free_cnt);
			if (unlikely(error)) {
				for (i = 0; i < free_cnt; i++)
					rte_pktmbuf_free(new_pkts[i]);
			}
			nb_enqueued += free_cnt;
		} else {
			struct rte_eth_dev *dev =
				&rte_eth_devices[rxvq->port_id];
			dev->data->rx_mbuf_alloc_failed += free_cnt;
		}
	}

	if (likely(nb_enqueued)) {
		vq_update_avail_idx(vq);

		if (unlikely(virtqueue_kick_prepare(vq))) {
			lsxvio_rc_virtqueue_notify(vq);
			LSXVIO_PMD_DBG("Notified");
		}
	}

	return nb_rx;
}

/* set rx and tx handlers according to what is supported */
static void
lsxvio_rc_set_rxtx_funcs(struct rte_eth_dev *eth_dev)
{
	struct lsxvio_rc_pci_hw *lsx_hw = eth_dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->pci_dev.hw;
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw, true);

	eth_dev->tx_pkt_prepare = lsxvio_rc_virtio_xmit_pkts_prepare;

	if (lsx_feature & LSX_VIO_RC2EP_DMA_NORSP) {
		LSXVIO_PMD_INFO("%s: LSX VIO RC2EP help\n",
			eth_dev->data->name);

		if (hw->use_inorder_tx) {
			eth_dev->tx_pkt_burst =
				lsxvio_rc_xmit_pkts_inorder_help;
		} else {
			eth_dev->tx_pkt_burst =
				lsxvio_rc_xmit_pkts_help;
		}
	} else {
		if (hw->use_inorder_tx) {
			eth_dev->tx_pkt_burst =
				lsxvio_rc_virtio_xmit_pkts_inorder;
		} else {
			eth_dev->tx_pkt_burst = lsxvio_rc_virtio_xmit_pkts;
		}
	}
	if (lsx_feature & LSX_VIO_EP2RC_PACKED)
		eth_dev->rx_pkt_burst = lsxvio_rc_virtio_recv_pkts_packed;
	else
		eth_dev->rx_pkt_burst = lsxvio_rc_virtio_recv_pkts;
}

/* reset device and renegotiate features if needed */
static int
lsxvio_rc_init_device(struct rte_eth_dev *eth_dev,
	uint64_t req_features)
{
	struct lsxvio_rc_pci_hw *lsx_hw = eth_dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->pci_dev.hw;
	struct virtio_net_config *config;
	struct virtio_net_config local_config;
	struct rte_pci_device *pci_dev = NULL;
	int ret;

	/* Reset the device although not necessary at startup */

	lsxvio_rc_virtio_reset(hw);
	if (hw->vqs) {
		lsxvio_rc_free_mbufs(eth_dev);
		lsxvio_rc_free_queues(hw);
	}

	/* Tell the host we've noticed this device. */
	lsxvio_rc_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_ACK);

	/* Tell the host we've known how to drive the device. */
	lsxvio_rc_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER);
	ret = lsxvio_rc_negotiate_features(hw, req_features);
	if (ret)
		return ret;

	hw->weak_barriers = !virtio_with_feature(hw, VIRTIO_F_ORDER_PLATFORM);
	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	eth_dev->data->dev_flags &= ~RTE_ETH_DEV_INTR_LSC;

	/* Setting up rx_header size for the device */
	if (virtio_with_feature(hw, VIRTIO_NET_F_MRG_RXBUF) ||
		virtio_with_feature(hw, VIRTIO_F_VERSION_1) ||
		virtio_with_feature(hw, VIRTIO_F_RING_PACKED))
		hw->vtnet_hdr_size = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	else
		hw->vtnet_hdr_size = sizeof(struct virtio_net_hdr);

	/* Copy the permanent MAC address to: virtio_hw */
	lsxvio_rc_get_hwaddr(hw);
	rte_ether_addr_copy((struct rte_ether_addr *)hw->mac_addr,
		&eth_dev->data->mac_addrs[0]);
	LSXVIO_PMD_DBG("PORT MAC: %02X:%02X:%02X:%02X:%02X:%02X",
		hw->mac_addr[0], hw->mac_addr[1], hw->mac_addr[2],
		hw->mac_addr[3], hw->mac_addr[4], hw->mac_addr[5]);
	if (virtio_with_feature(hw, VIRTIO_NET_F_CTRL_VQ)) {
		config = &local_config;
		lsxvio_rc_virtio_read_dev_config(hw,
			offsetof(struct virtio_net_config, mac),
			&config->mac, sizeof(config->mac));
		if (virtio_with_feature(hw, VIRTIO_NET_F_STATUS)) {
			lsxvio_rc_virtio_read_dev_config(hw,
				offsetof(struct virtio_net_config, status),
				&config->status, sizeof(config->status));
		} else {
			LSXVIO_PMD_WARN("VIRTIO_NET_F_STATUS is not supported");
			config->status = 0;
		}

		if (virtio_with_feature(hw, VIRTIO_NET_F_MQ)) {
			lsxvio_rc_virtio_read_dev_config(hw,
				offsetof(struct virtio_net_config,
					max_virtqueue_pairs),
				&config->max_virtqueue_pairs,
				sizeof(config->max_virtqueue_pairs));
		} else {
			LSXVIO_PMD_WARN("VIRTIO_NET_F_MQ is not supported");
			config->max_virtqueue_pairs = 1;
		}

		hw->max_queue_pairs = config->max_virtqueue_pairs;
		if (virtio_with_feature(hw, VIRTIO_NET_F_MTU)) {
			lsxvio_rc_virtio_read_dev_config(hw,
				offsetof(struct virtio_net_config, mtu),
				&config->mtu,
				sizeof(config->mtu));
			if (config->mtu < RTE_ETHER_MIN_MTU) {
				LSXVIO_PMD_ERR("%s: invalid max MTU value (%u)",
					eth_dev->data->name,
					config->mtu);
				return -EINVAL;
			}
			hw->max_mtu = config->mtu;
			/* Set initial MTU to maximum one supported by vhost */
			eth_dev->data->mtu = config->mtu;
		} else {
			hw->max_mtu = VIRTIO_MAX_RX_PKTLEN -
				RTE_ETHER_HDR_LEN -
				VLAN_TAG_LEN - hw->vtnet_hdr_size;
		}
		LSXVIO_PMD_DBG("config->max_virtqueue_pairs=%d",
			config->max_virtqueue_pairs);
		LSXVIO_PMD_DBG("config->status=%d", config->status);
		LSXVIO_PMD_DBG("PORT MAC: %02X:%02X:%02X:%02X:%02X:%02X",
			config->mac[0], config->mac[1],
			config->mac[2], config->mac[3],
			config->mac[4], config->mac[5]);
	} else {
		LSXVIO_PMD_DBG("config->max_virtqueue_pairs=1");
		hw->max_queue_pairs = LSXVIO_MAX_QUEUE_PAIRS;
		hw->max_mtu = VIRTIO_MAX_RX_PKTLEN - RTE_ETHER_HDR_LEN -
			VLAN_TAG_LEN - hw->vtnet_hdr_size;
	}
	ret = lsxvio_rc_alloc_queues(eth_dev);
	if (ret < 0)
		return ret;

	if (eth_dev->data->dev_conf.intr_conf.rxq) {
		LSXVIO_PMD_ERR("%s: Not support interrupt",
			eth_dev->data->name);
		return -ENOTSUP;
	}
	lsxvio_rc_virtio_reinit_complete(hw);
	lsx_hw->local_lsx_cfg.lsx_feature =
		lsxvio_priv_feature(lsx_hw, true);
	if (pci_dev) {
		LSXVIO_PMD_DBG("port %d vendorID=0x%x deviceID=0x%x",
			eth_dev->data->port_id, pci_dev->id.vendor_id,
			pci_dev->id.device_id);
	}

	return 0;
}

static int
lsxvio_rc_remap_pci(struct rte_pci_device *pci_dev,
	__rte_unused struct virtio_hw *hw)
{
	if (rte_pci_map_device(pci_dev)) {
		LSXVIO_PMD_ERR("failed to map pci device!");
		return -EINVAL;
	}

	return 0;
}

static void
lsxvio_rc_modern_read_dev_config(struct virtio_hw *hw,
	size_t offset, void *dst, int length)
{
	int i;
	uint8_t *p, *src;
	uint8_t old_gen, new_gen;
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	struct lsxvio_common_cfg *cfg = &lsx_hw->lsx_cfg->common_cfg;

	src = (uint8_t *)pci_dev->dev_cfg + offset;
	do {
		old_gen = rte_read8(&cfg->config_generation);
		p = dst;
		for (i = 0; i < length; i++)
			*p++ = rte_read8(src + i);

		new_gen = rte_read8(&cfg->config_generation);
	} while (old_gen != new_gen);
}

static void
lsxvio_rc_modern_write_dev_config(struct virtio_hw *hw,
	size_t offset, const void *src, int length)
{
	int i;
	const uint8_t *p = src;
	uint8_t *dst;
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);

	dst = (uint8_t *)pci_dev->dev_cfg + offset;
	for (i = 0;  i < length; i++)
		rte_write8((*p++), (dst + i));
}

static uint64_t
lsxvio_rc_modern_get_features(struct virtio_hw *hw)
{
	uint64_t features;
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	struct lsxvio_common_cfg *cfg = &lsx_hw->lsx_cfg->common_cfg;

	features = rte_read64(&cfg->device_feature);
	return features;
}

static void
lsxvio_rc_modern_set_features(__rte_unused struct virtio_hw *hw,
	__rte_unused uint64_t features)
{
}

static uint8_t
lsxvio_rc_modern_get_status(struct virtio_hw *hw)
{
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	struct lsxvio_common_cfg *cfg = &lsx_hw->lsx_cfg->common_cfg;

	return rte_read8(&cfg->device_status);
}

static void
lsxvio_rc_modern_set_status(struct virtio_hw *hw, uint8_t status)
{
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	struct lsxvio_common_cfg *cfg = &lsx_hw->lsx_cfg->common_cfg;

	rte_write8(status, &cfg->device_status);
}

static uint8_t
lsxvio_rc_modern_get_isr(struct virtio_hw *hw)
{
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);

	return rte_read8(pci_dev->isr);
}

static uint16_t
lsxvio_rc_modern_set_config_irq(struct virtio_hw *hw,
	uint16_t vec)
{
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	struct lsxvio_common_cfg *cfg = &lsx_hw->lsx_cfg->common_cfg;

	rte_write16(vec, &cfg->msix_config);
	return rte_read16(&cfg->msix_config);
}

static uint16_t
lsxvio_rc_modern_set_queue_irq(struct virtio_hw *hw,
	struct virtqueue *vq, uint16_t vec)
{
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	struct lsxvio_queue_cfg *qcfg = lsx_hw->lsx_cfg->queue_cfg;
	uint16_t q_idx = vq->vq_queue_index;

	rte_write16(vec, &qcfg[q_idx].queue_msix_vector);
	return rte_read16(&qcfg[q_idx].queue_msix_vector);
}

static uint16_t
lsxvio_rc_modern_get_queue_num(struct virtio_hw *hw,
	uint16_t queue_id)
{
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	struct lsxvio_queue_cfg *qcfg = lsx_hw->lsx_cfg->queue_cfg;

	return rte_read16(&qcfg[queue_id].queue_size);
}

static int
lsxvio_rc_modern_setup_queue(struct virtio_hw *hw,
	struct virtqueue *vq)
{
	uint64_t desc_addr, avail_addr, used_addr;
	uint64_t avail_offset, used_offset;
	uint16_t notify_off;
	uint16_t q_idx = vq->vq_queue_index;
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	struct lsxvio_queue_cfg *qcfg = lsx_hw->lsx_cfg->queue_cfg;
	struct vring *sp_ring = &vq->vq_split.ring;

	desc_addr = vq->vq_ring_mem;
	avail_offset = (uint64_t)sp_ring->avail -
		(uint64_t)vq->vq_ring_virt_mem;
	used_offset = (uint64_t)sp_ring->used -
		(uint64_t)vq->vq_ring_virt_mem;
	avail_addr = desc_addr + avail_offset;
	used_addr = desc_addr + used_offset;
	lsxvio_write64_twopart(desc_addr, &qcfg[q_idx].queue_desc_lo,
		&qcfg[q_idx].queue_desc_hi);
	lsxvio_write64_twopart(avail_addr, &qcfg[q_idx].queue_avail_lo,
		&qcfg[q_idx].queue_avail_hi);
	lsxvio_write64_twopart(used_addr, &qcfg[q_idx].queue_used_lo,
		&qcfg[q_idx].queue_used_hi);
	notify_off = rte_read16(&qcfg[q_idx].queue_notify_off);
	vq->notify_addr = (void *)((uint8_t *)pci_dev->notify_base +
		notify_off * pci_dev->notify_off_multiplier);
	rte_write16(1, &qcfg[q_idx].queue_enable);

	return 0;
}

static void
lsxvio_rc_modern_del_queue(struct virtio_hw *hw,
	struct virtqueue *vq)
{
	uint16_t q_idx = vq->vq_queue_index;
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	struct lsxvio_queue_cfg *qcfg = lsx_hw->lsx_cfg->queue_cfg;

	lsxvio_write64_twopart(0, &qcfg[q_idx].queue_desc_lo,
		&qcfg[q_idx].queue_desc_hi);
	lsxvio_write64_twopart(0, &qcfg[q_idx].queue_avail_lo,
		&qcfg[q_idx].queue_avail_hi);
	lsxvio_write64_twopart(0, &qcfg[q_idx].queue_used_lo,
		&qcfg[q_idx].queue_used_hi);

	rte_write16(0, &qcfg[q_idx].queue_enable);
}

static inline void
lsxvio_rc_rx_sw_notify_addr_offset(struct virtqueue *vq,
	uint16_t current_idx, uint16_t last_avail_idx,
	uint32_t *remote, const uint32_t *local)
{
	if (current_idx > last_avail_idx) {
		lsinic_pcie_memcp_align(&remote[last_avail_idx],
			&local[last_avail_idx],
			(current_idx - last_avail_idx) *
			sizeof(uint32_t));
	} else {
		lsinic_pcie_memcp_align(&remote[last_avail_idx],
			&local[last_avail_idx],
			(vq->vq_nentries - last_avail_idx) *
			sizeof(uint32_t));
		if (current_idx > 0) {
			lsinic_pcie_memcp_align(&remote[0], &local[0],
				current_idx * sizeof(uint32_t));
		}
	}
}

static inline void
lsxvio_rc_rx_sw_notify_addr(struct virtqueue *vq,
	uint16_t current_idx, uint16_t last_avail_idx,
	uint64_t *remote, const uint64_t *local)
{
	if (current_idx > last_avail_idx) {
		lsinic_pcie_memcp_align(&remote[last_avail_idx],
			&local[last_avail_idx],
			(current_idx - last_avail_idx) *
			sizeof(uint64_t));
	} else {
		lsinic_pcie_memcp_align(&remote[last_avail_idx],
			&local[last_avail_idx],
			(vq->vq_nentries - last_avail_idx) *
			sizeof(uint64_t));
		if (current_idx > 0) {
			lsinic_pcie_memcp_align(&remote[0], &local[0],
				current_idx * sizeof(uint64_t));
		}
	}
}

static inline void
lsxvio_rc_rx_notify_addr(struct virtqueue *vq,
	struct lsxvio_rc_pci_hw *lsx_hw, int dma)
{
	uint8_t *ring_base = lsx_hw->ring_base;
	uint16_t qidx = vq->vq_queue_index, current_idx, i, j;
	uint16_t last_avail_idx = lsx_hw->last_avail_idx[qidx];
	uint64_t mem_base = lsx_hw->local_lsx_cfg.queue_mem_base[qidx];
	struct lsxvio_packed_notify *pnotify = (void *)(ring_base +
			qidx * LSXVIO_PER_RING_MEM_MAX_SIZE);
	uint16_t *pidx;
	uint16_t len;
	struct vring_packed_desc *pdesc = vq->vq_packed.ring.desc;
	uint64_t *addrs;
	uint32_t *addr_offs;

	last_avail_idx = last_avail_idx & (vq->vq_nentries - 1);
	current_idx = vq->vq_avail_idx & (vq->vq_nentries - 1);
	len = (current_idx - last_avail_idx) & (vq->vq_nentries - 1);
	if (!len)
		len = vq->vq_nentries;

	if (mem_base) {
		addr_offs = lsx_hw->local_lsx_cfg.shadow_desc[qidx];
		i = last_avail_idx;
		for (j = 0; j < len; j++) {
			addr_offs[i] = pdesc[i].addr - mem_base +
				lsx_hw->pci_dev.hw.vtnet_hdr_size;
			i = (i + 1) & (vq->vq_nentries - 1);
		}

		if (!dma || last_avail_idx == current_idx) {
			lsxvio_rc_rx_sw_notify_addr_offset(vq,
				current_idx, last_avail_idx,
				&pnotify->addr_offset[0],
				addr_offs);
		}
	} else {
		addrs = lsx_hw->local_lsx_cfg.shadow_desc[qidx];
		i = last_avail_idx;
		for (j = 0; j < len; j++) {
			addrs[i] = pdesc[i].addr +
				lsx_hw->pci_dev.hw.vtnet_hdr_size;
			i = (i + 1) & (vq->vq_nentries - 1);
		}
		if (!dma || last_avail_idx == current_idx) {
			lsxvio_rc_rx_sw_notify_addr(vq,
				current_idx, last_avail_idx,
				&pnotify->addr[0], addrs);
		}
	}

	lsx_hw->last_avail_idx[qidx] = vq->vq_avail_idx;
	if (dma) {
		pidx = lsx_hw->local_lsx_cfg.shadow_desc[qidx];
		pidx = (uint16_t *)((uint64_t *)pidx + vq->vq_nentries);
		pidx[vq->vq_avail_idx & (vq->vq_nentries - 1)] =
			vq->vq_avail_idx;
		rte_write16(vq->vq_avail_idx, &pnotify->dma_idx);
	} else {
		rte_write16(vq->vq_avail_idx, &pnotify->last_avail_idx);
	}
}

static inline void
lsxvio_rc_tx_sw_notify_sbd(struct virtqueue *vq,
	uint16_t current_idx, uint16_t last_avail_idx,
	struct lsxvio_short_desc *remote,
	const struct lsxvio_short_desc *local)
{
	if (current_idx > last_avail_idx) {
		lsinic_pcie_memcp_align(&remote[last_avail_idx],
			&local[last_avail_idx],
			(current_idx - last_avail_idx) *
			sizeof(struct lsxvio_short_desc));
	} else {
		lsinic_pcie_memcp_align(&remote[last_avail_idx],
			&local[last_avail_idx],
			(vq->vq_nentries - last_avail_idx) *
			sizeof(struct lsxvio_short_desc));
		if (current_idx > 0) {
			lsinic_pcie_memcp_align(&remote[0], &local[0],
				current_idx *
				sizeof(struct lsxvio_short_desc));
		}
	}
}

static inline void
lsxvio_rc_tx_sw_notify_bd(struct virtqueue *vq,
	uint16_t current_idx, uint16_t last_avail_idx,
	struct vring_desc *remote,
	const struct vring_desc *local)
{
	if (current_idx > last_avail_idx) {
		lsinic_pcie_memcp_align(&remote[last_avail_idx],
			&local[last_avail_idx],
			(current_idx - last_avail_idx) *
			sizeof(struct vring_desc));
	} else {
		lsinic_pcie_memcp_align(&remote[last_avail_idx],
			&local[last_avail_idx],
			(vq->vq_nentries - last_avail_idx) *
			sizeof(struct vring_desc));
		if (current_idx > 0) {
			lsinic_pcie_memcp_align(&remote[0], &local[0],
				current_idx *
				sizeof(struct vring_desc));
		}
	}
}

static inline void *
lsxvio_rc_tx_notify_bd_update(struct virtqueue *vq,
	struct lsxvio_rc_pci_hw *lsx_hw, int dma)
{
	uint16_t qidx = vq->vq_queue_index, i, j = 0, current_idx, len;
	uint16_t last_avail_idx = lsx_hw->last_avail_idx[qidx];
	uint64_t mem_base = lsx_hw->local_lsx_cfg.queue_mem_base[qidx];
	uint8_t *ring_base = lsx_hw->ring_base;
	struct vring_desc *desc = vq->vq_split.ring.desc;
	struct lsxvio_short_desc *remote_sdesc, *local_sdesc;
	struct vring_desc *remote_desc;
	void *next_ring_addr;

#ifndef LSXVIO_TX_PACKED_BD_NOTIFICATION_UPDATE
	remote_desc = (void *)(ring_base + qidx *
			LSXVIO_PER_RING_MEM_MAX_SIZE);
	next_ring_addr = remote_desc + vq->vq_nentries;

	return next_ring_addr;
#endif

	last_avail_idx = last_avail_idx & (vq->vq_nentries - 1);
	current_idx = vq->vq_split.ring.avail->idx & (vq->vq_nentries - 1);
	len = (current_idx - last_avail_idx) & (vq->vq_nentries - 1);
	if (!len)
		len = vq->vq_nentries;

	if (mem_base) {
		remote_sdesc = (void *)(ring_base + qidx *
			LSXVIO_PER_RING_MEM_MAX_SIZE);
		local_sdesc = lsx_hw->local_lsx_cfg.shadow_desc[qidx];
		i = last_avail_idx;
		for (j = 0; j < len; j++) {
			local_sdesc[i].addr_offset = desc[i].addr - mem_base +
				lsx_hw->pci_dev.hw.vtnet_hdr_size;
			local_sdesc[i].len = desc[i].len -
				lsx_hw->pci_dev.hw.vtnet_hdr_size;
			i = (i + 1) & (vq->vq_nentries - 1);
		}
		if (!dma) {
			lsxvio_rc_tx_sw_notify_sbd(vq, current_idx,
				last_avail_idx, remote_sdesc,
				local_sdesc);
		}
		next_ring_addr = remote_sdesc + vq->vq_nentries;
	} else {
		remote_desc = (void *)(ring_base + qidx *
			LSXVIO_PER_RING_MEM_MAX_SIZE);
		if (!dma) {
			lsxvio_rc_tx_sw_notify_bd(vq, current_idx,
				last_avail_idx, remote_desc,
				desc);
		}
		next_ring_addr = remote_desc + vq->vq_nentries;
	}

	lsx_hw->last_avail_idx[qidx] = vq->vq_split.ring.avail->idx;

	return next_ring_addr;
}

static void
lsxvio_rc_modern_notify_queue(struct virtio_hw *hw,
	struct virtqueue *vq)
{
	struct virtio_pci_dev *pci_dev = virtio_pci_get_dev(hw);
	struct lsxvio_rc_pci_hw *lsx_hw = lsxvio_rc_pci_dev(pci_dev);
	uint8_t *ring_base = lsx_hw->ring_base;
	struct vring_avail *avail_ring;
	int queue_type = virtio_get_queue_type(hw, vq->vq_queue_index);
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw, false);

	if (queue_type == VTNET_RQ &&
		lsx_feature & LSX_VIO_EP2RC_PACKED) {
		lsxvio_rc_rx_notify_addr(vq, lsx_hw,
			lsx_feature & LSX_VIO_EP2RC_DMA_ADDR_NOTIFY);
	} else if (queue_type == VTNET_TQ) {
		avail_ring = lsxvio_rc_tx_notify_bd_update(vq,
			lsx_hw, lsx_feature & LSX_VIO_RC2EP_DMA_BD_NOTIFY);
		if (lsx_feature & LSX_VIO_RC2EP_DMA_BD_NOTIFY) {
			rte_write16(vq->vq_split.ring.avail->idx,
				&avail_ring->flags);
		} else {
			rte_write16(vq->vq_split.ring.avail->idx,
				&avail_ring->idx);
		}
	} else {
		avail_ring = (void *)(ring_base +
			vq->vq_queue_index *
			LSXVIO_PER_RING_MEM_MAX_SIZE);
		rte_write16(vq->vq_split.ring.avail->idx, &avail_ring->idx);
		rte_write16(vq->vq_queue_index, vq->notify_addr);
	}
}

static const struct virtio_ops lsxvio_rc_modern_ops = {
	.read_dev_cfg	= lsxvio_rc_modern_read_dev_config,
	.write_dev_cfg	= lsxvio_rc_modern_write_dev_config,
	.get_status	= lsxvio_rc_modern_get_status,
	.set_status	= lsxvio_rc_modern_set_status,
	.get_features	= lsxvio_rc_modern_get_features,
	.set_features	= lsxvio_rc_modern_set_features,
	.get_isr	= lsxvio_rc_modern_get_isr,
	.set_config_irq	= lsxvio_rc_modern_set_config_irq,
	.set_queue_irq  = lsxvio_rc_modern_set_queue_irq,
	.get_queue_num	= lsxvio_rc_modern_get_queue_num,
	.setup_queue	= lsxvio_rc_modern_setup_queue,
	.del_queue	= lsxvio_rc_modern_del_queue,
	.notify_queue	= lsxvio_rc_modern_notify_queue,
};

static int
lsxvio_rc_pci_set_ops(struct virtio_hw *hw)
{
	LSX_VIO_OPS(hw) = &lsxvio_rc_modern_ops;

	return 0;
}

static int
lsxvio_rc_read_caps(struct rte_pci_device *dev,
	struct lsxvio_rc_pci_hw *lsx_hw)
{
	struct virtio_pci_dev *pci_dev = &lsx_hw->pci_dev;
	struct virtio_hw *hw = &pci_dev->hw;
	uint8_t *reg_base, *ring_base;

	reg_base = dev->mem_resource[LSXVIO_REG_BAR_IDX].addr;
	ring_base = dev->mem_resource[LSXVIO_RING_BAR_IDX].addr;

	lsx_hw->lsx_cfg = (void *)(reg_base + LSXVIO_COMMON_OFFSET);
	pci_dev->isr = reg_base + LSXVIO_ISR_OFFSET;
	pci_dev->notify_base = (void *)(reg_base + LSXVIO_NOTIFY_OFFSET);
	pci_dev->dev_cfg = (void *)(reg_base + LSXVIO_DEVICE_OFFSET);
	pci_dev->notify_off_multiplier = LSXVIO_NOTIFY_OFF_MULTI;

	lsx_hw->ring_base = ring_base;
	memset(lsx_hw->last_avail_idx, 0,
		LSXVIO_MAX_QUEUES * sizeof(uint16_t));

	if (!s_lsxvio_rc_sim) {
		if (rte_pci_map_device(dev)) {
			LSXVIO_PMD_ERR("failed to map pci device!");
			return -EIO;
		}
	}
	s_lsx_vio_hw[hw->port_id].virtio_ops = &lsxvio_rc_modern_ops;

	return 0;
}

static int
lsxvio_rc_pci_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct lsxvio_rc_pci_hw *lsx_hw = eth_dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->pci_dev.hw;
	int ret;
	size_t mac_buf_size;

	if (sizeof(struct virtio_net_hdr_mrg_rxbuf) >
		RTE_PKTMBUF_HEADROOM) {
		LSXVIO_PMD_ERR("Headroom required(%d) > avail(%d)",
			(int)sizeof(struct virtio_net_hdr_mrg_rxbuf),
			RTE_PKTMBUF_HEADROOM);

		return -EINVAL;
	}

	eth_dev->dev_ops = &lsxvio_rc_eth_dev_ops;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY &&
		!s_lsxvio_rc_2nd_proc_standalone) {
		ret = lsxvio_rc_remap_pci(RTE_ETH_DEV_TO_PCI(eth_dev),
			hw);
		if (ret)
			return ret;

		lsxvio_rc_pci_set_ops(hw);
		lsxvio_rc_set_rxtx_funcs(eth_dev);

		return 0;
	}

	/* Allocate memory for storing MAC addresses */
	mac_buf_size =
		VIRTIO_MAX_MAC_ADDRS * sizeof(struct rte_ether_addr);
	eth_dev->data->mac_addrs = rte_zmalloc("virtio",
		mac_buf_size, 0);
	if (!eth_dev->data->mac_addrs) {
		LSXVIO_PMD_ERR("Failed to allocate MAC buf(%d)",
			(int)mac_buf_size);
		return -ENOMEM;
	}

	hw->port_id = eth_dev->data->port_id;

	ret = lsxvio_rc_read_caps(RTE_ETH_DEV_TO_PCI(eth_dev),
			lsx_hw);
	if (ret)
		goto err_vtpci_init;

	rte_spinlock_init(&hw->state_lock);

	/* reset device and negotiate default features */
	ret = lsxvio_rc_init_device(eth_dev, VIRTIO_PMD_DEFAULT_GUEST_FEATURES);
	if (ret < 0)
		goto err_virtio_init;

	hw->opened = true;

	return 0;

err_virtio_init:
	rte_pci_unmap_device(RTE_ETH_DEV_TO_PCI(eth_dev));
err_vtpci_init:
	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;
	return ret;
}

static int
lsxvio_rc_eth_uninit(struct rte_eth_dev *eth_dev)
{
	int ret;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
		return 0;

	ret = lsxvio_rc_eth_stop(eth_dev);
	if (ret)
		return ret;
	ret = lsxvio_rc_eth_close(eth_dev);
	if (ret)
		return ret;

	eth_dev->dev_ops = NULL;
	eth_dev->tx_pkt_burst = NULL;
	eth_dev->rx_pkt_burst = NULL;

	LSXVIO_PMD_DBG("%s un-init", eth_dev->data->name);

	return 0;
}

static int
lsxvio_rc_sim_pci_resource_set(struct rte_pci_device *dev)
{
	int i, map_idx = 0;
	void *mapaddr;

	LSXVIO_PMD_INFO("LSXVIO Simulator: vendor: 0x%04x\n",
		dev->id.vendor_id);

	/* Map all BARs */
	for (i = 0; i != PCI_MAX_RESOURCE; i++) {
		/* skip empty BAR */
		if (dev->mem_resource[i].phys_addr == 0)
			continue;

		mapaddr = rte_mem_iova2virt(dev->mem_resource[i].phys_addr);
		dev->mem_resource[i].addr = mapaddr;
		map_idx++;
	}

	return 0;
}

static uint16_t
lsxvio_rc_2nd_proc_find_free_port(void)
{
	uint32_t i;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!rte_eth_devices[i].data)
			return i;
	}
	return RTE_MAX_ETHPORTS;
}

static struct rte_eth_dev *
lsxvio_rc_2nd_proc_eth_dev_allocate(const char *name)
{
	const struct rte_memzone *mz;
	struct rte_eth_dev *eth_dev = NULL;
	size_t name_len, size;
	uint16_t port_id;

	name_len = strlen(name);
	if (name_len == 0) {
		LSXVIO_PMD_ERR("Zero length lsxvio RC device name\n");
		return NULL;
	}

	if (name_len >= RTE_ETH_NAME_MAX_LEN) {
		LSXVIO_PMD_ERR("lsxvio RC device name(%s) len(%d) > %d",
			name, (int)name_len, RTE_ETH_NAME_MAX_LEN);
		return NULL;
	}

	rte_spinlock_lock(&s_lsxvio_rc_lock);

	if (!s_lsxvio_rc_eth_data) {
		size = sizeof(struct rte_eth_dev_data);
		size = size * RTE_MAX_ETHPORTS;
		mz = rte_memzone_reserve("lsxvio_rc_eth_dev_data",
				size, rte_socket_id(), 0);
		if (!mz) {
			LSXVIO_PMD_ERR("data alloc failed for %s",
				name);
			rte_spinlock_unlock(&s_lsxvio_rc_lock);
			return NULL;
		}
		s_lsxvio_rc_eth_data = mz->addr;
	}

	port_id = lsxvio_rc_2nd_proc_find_free_port();
	eth_dev = &rte_eth_devices[port_id];
	eth_dev->data = &s_lsxvio_rc_eth_data[port_id];

	strcpy(eth_dev->data->name, name);
	eth_dev->data->port_id = port_id;
	eth_dev->data->mtu = RTE_ETHER_MTU;

	rte_spinlock_unlock(&s_lsxvio_rc_lock);

	return eth_dev;
}

static int
lsxvio_rc_eth_2nd_proc_probe(struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *eth_dev;
	int ret;

	eth_dev = lsxvio_rc_2nd_proc_eth_dev_allocate(pci_dev->name);
	if (!eth_dev) {
		LSXVIO_PMD_ERR("%s eth dev alloc failed for %s",
			__func__, pci_dev->name);
		return -ENOMEM;
	}
	eth_dev->data->dev_private = rte_zmalloc_socket(pci_dev->name,
		sizeof(struct lsxvio_rc_pci_hw),
		RTE_CACHE_LINE_SIZE,
		pci_dev->device.numa_node);
	if (!eth_dev->data->dev_private) {
		LSXVIO_PMD_ERR("%s dev private alloc failed for %s",
			__func__, pci_dev->name);
		rte_eth_dev_release_port(eth_dev);
		return -ENOMEM;
	}
	eth_dev->device = &pci_dev->device;
	rte_eth_copy_pci_info(eth_dev, pci_dev);
	ret = lsxvio_rc_pci_eth_dev_init(eth_dev);
	if (ret) {
		LSXVIO_PMD_ERR("%s: eth dev init failed for %s",
			__func__, pci_dev->name);
	} else {
		rte_eth_dev_probing_finish(eth_dev);
	}

	return ret;
}

static int
lsxvio_rc_eth_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	int snoop;

	if (s_lsxvio_rc_sim)
		lsxvio_rc_sim_pci_resource_set(pci_dev);

	snoop = lxsnic_br_of_dev_snoop(pci_dev);
	if (snoop < 0) {
		LSXVIO_PMD_ERR("Read snoop attr of bridge failed(%d)",
			snoop);
		return snoop;
	}
	if (!snoop)
		LSXVIO_PMD_WARN("NoSnoop+ TBD.");

	if (s_lsxvio_rc_2nd_proc_standalone)
		return lsxvio_rc_eth_2nd_proc_probe(pci_dev);

	return rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(struct lsxvio_rc_pci_hw),
		lsxvio_rc_pci_eth_dev_init);
}

static int
lsxvio_rc_eth_pci_remove(struct rte_pci_device *pci_dev)
{
	int ret;

	ret = rte_eth_dev_pci_generic_remove(pci_dev,
		lsxvio_rc_eth_uninit);
	/* Port has already been released by close. */
	if (ret == -ENODEV)
		ret = 0;
	return ret;
}

static struct rte_pci_driver rte_lsxvio_pci_pmd = {
	.driver = {
		.name = RTE_STR(lsxvio_net),
	},
	.id_table = lsxvio_pci_id_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = lsxvio_rc_eth_pci_probe,
	.remove = lsxvio_rc_eth_pci_remove,
};

RTE_INIT(rte_lsxvio_pci_pmd_init)
{
	rte_eal_iopl_init();
	rte_pci_register(&rte_lsxvio_pci_pmd);
}

static bool
lsxvio_rc_rx_offload_enabled(struct virtio_hw *hw)
{
	return virtio_with_feature(hw, VIRTIO_NET_F_GUEST_CSUM) ||
		virtio_with_feature(hw, VIRTIO_NET_F_GUEST_TSO4) ||
		virtio_with_feature(hw, VIRTIO_NET_F_GUEST_TSO6);
}

static bool
lsxvio_rc_tx_offload_enabled(struct virtio_hw *hw)
{
	return virtio_with_feature(hw, VIRTIO_NET_F_CSUM) ||
		virtio_with_feature(hw, VIRTIO_NET_F_HOST_TSO4) ||
		virtio_with_feature(hw, VIRTIO_NET_F_HOST_TSO6);
}

static void
lsxvio_rc_virtio_dev_cq_start(struct rte_eth_dev *dev)
{
	struct virtio_hw *hw = dev->data->dev_private;

	if (hw->cvq) {
		rte_spinlock_init(&hw->cvq->lock);
		LSXVIO_RC_VIRTQUEUE_DUMP(virtnet_cq_to_vq(hw->cvq));
	}
}

static int
lsxvio_rc_eth_configure(struct rte_eth_dev *dev)
{
	const struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
	const struct rte_eth_txmode *txmode = &dev->data->dev_conf.txmode;
	struct lsxvio_rc_pci_hw *lsx_hw = dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->pci_dev.hw;
	uint32_t ether_hdr_len = RTE_ETHER_HDR_LEN + VLAN_TAG_LEN +
		hw->vtnet_hdr_size;
	uint64_t rx_offloads = rxmode->offloads;
	uint64_t tx_offloads = txmode->offloads;
	uint64_t req_features, lsx_feature;
	int ret;

	LSXVIO_PMD_DBG("%s configure", dev->data->name);
	req_features = VIRTIO_PMD_DEFAULT_GUEST_FEATURES;

	if (dev->data->dev_conf.intr_conf.rxq) {
		LSXVIO_PMD_WARN("%s: Not support interrupt",
			dev->data->name);
	}

	if (rxmode->max_lro_pkt_size > hw->max_mtu + ether_hdr_len)
		req_features &= ~(1ULL << VIRTIO_NET_F_MTU);

	if (rx_offloads & (RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
			   RTE_ETH_RX_OFFLOAD_TCP_CKSUM))
		req_features |= (1ULL << VIRTIO_NET_F_GUEST_CSUM);

	if (rx_offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO)
		req_features |=
			(1ULL << VIRTIO_NET_F_GUEST_TSO4) |
			(1ULL << VIRTIO_NET_F_GUEST_TSO6);

	if (tx_offloads & (RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
			   RTE_ETH_TX_OFFLOAD_TCP_CKSUM))
		req_features |= (1ULL << VIRTIO_NET_F_CSUM);

	if (tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_TSO)
		req_features |=
			(1ULL << VIRTIO_NET_F_HOST_TSO4) |
			(1ULL << VIRTIO_NET_F_HOST_TSO6);

	/* if request features changed, reinit the device */
	if (req_features != hw->req_guest_features) {
		ret = lsxvio_rc_init_device(dev, req_features);
		if (ret < 0)
			return ret;
	}

	if ((rx_offloads & (RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
			RTE_ETH_RX_OFFLOAD_TCP_CKSUM)) &&
		!virtio_with_feature(hw, VIRTIO_NET_F_GUEST_CSUM)) {
		LSXVIO_PMD_ERR("%s: rx checksum not available",
			dev->data->name);
		return -ENOTSUP;
	}

	if ((rx_offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO) &&
		(!virtio_with_feature(hw, VIRTIO_NET_F_GUEST_TSO4) ||
		 !virtio_with_feature(hw, VIRTIO_NET_F_GUEST_TSO6))) {
		LSXVIO_PMD_ERR("%s: Large Receive Offload not available",
			dev->data->name);
		return -ENOTSUP;
	}

	/* start control queue */
	if (virtio_with_feature(hw, VIRTIO_NET_F_CTRL_VQ))
		lsxvio_rc_virtio_dev_cq_start(dev);

	if (rx_offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
		hw->vlan_strip = 1;

	hw->has_tx_offload = lsxvio_rc_tx_offload_enabled(hw);
	hw->has_rx_offload = lsxvio_rc_rx_offload_enabled(hw);

	if (dev->data->dev_flags & RTE_ETH_DEV_INTR_LSC)
		/* Enable vector (0) for Link State Intrerrupt */
		if (LSX_VIO_OPS(hw)->set_config_irq(hw, 0) ==
				VIRTIO_MSI_NO_VECTOR) {
			LSXVIO_PMD_ERR("%s: failed to set config vector",
				dev->data->name);
			return -EBUSY;
		}

	lsx_feature = lsxvio_priv_feature(lsx_hw, true);

	if (virtio_with_feature(hw, VIRTIO_F_IN_ORDER)) {
		hw->use_inorder_tx = 1;
		hw->use_inorder_rx = 1;
	} else if (lsx_feature & LSX_VIO_RC2EP_IN_ORDER) {
		hw->use_inorder_tx = 1;
	}

	if (virtio_with_packed_queue(hw) ||
		(lsx_feature & LSX_VIO_EP2RC_PACKED))
		hw->use_inorder_rx = 0;

	return 0;
}

static inline int
lsxvio_rc_recv_refill(struct virtqueue *vq,
	struct rte_mbuf **cookie, uint16_t num)
{
	struct vq_desc_extra *dxp;
	struct virtio_hw *hw = vq->hw;
	struct vring_desc *start_dp = vq->vq_split.ring.desc;
	uint16_t idx, i;

	if (unlikely(vq->vq_free_cnt == 0)) {
		LSXVIO_PMD_DBG("%s: no free count", __func__);
		return -ENOSPC;
	}
	if (unlikely(vq->vq_free_cnt < num)) {
		LSXVIO_PMD_DBG("%s: free count(%d) < %d",
			__func__, vq->vq_free_cnt, num);
		return -EMSGSIZE;
	}

	if (unlikely(vq->vq_desc_head_idx >= vq->vq_nentries)) {
		LSXVIO_PMD_DBG("%s: dsec header(%d) < %d",
			__func__, vq->vq_desc_head_idx,
			vq->vq_nentries);
		return -EFAULT;
	}

	for (i = 0; i < num; i++) {
		idx = vq->vq_desc_head_idx;
		dxp = &vq->vq_descx[idx];
		dxp->cookie = (void *)cookie[i];
		dxp->ndescs = 1;

		start_dp[idx].addr =
			VIRTIO_MBUF_ADDR(cookie[i], vq) +
			RTE_PKTMBUF_HEADROOM - hw->vtnet_hdr_size;
		start_dp[idx].len =
			cookie[i]->buf_len - RTE_PKTMBUF_HEADROOM +
			hw->vtnet_hdr_size;
		start_dp[idx].flags = VRING_DESC_F_WRITE;
		vq->vq_desc_head_idx = start_dp[idx].next;
		vq_update_avail_ring(vq, idx);
		if (vq->vq_desc_head_idx == VQ_RING_DESC_CHAIN_END) {
			vq->vq_desc_tail_idx = vq->vq_desc_head_idx;
			break;
		}
	}

	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - num);

	return 0;
}

static inline int
lsxvio_rc_recv_refill_packed(struct virtqueue *vq,
	struct rte_mbuf **cookie, uint16_t num)
{
	struct vring_packed_desc *start_dp = vq->vq_packed.ring.desc;
	uint16_t flags = vq->vq_packed.cached_flags;
	struct virtio_hw *hw = vq->hw;
	struct vq_desc_extra *dxp;
	uint16_t idx;
	int i;

	if (unlikely(vq->vq_free_cnt == 0)) {
		LSXVIO_PMD_DBG("%s: no free count", __func__);
		return -ENOSPC;
	}
	if (unlikely(vq->vq_free_cnt < num)) {
		LSXVIO_PMD_DBG("%s: free count(%d) < %d",
			__func__, vq->vq_free_cnt, num);
		return -EMSGSIZE;
	}

	for (i = 0; i < num; i++) {
		idx = vq->vq_avail_idx;
		dxp = &vq->vq_descx[idx];
		dxp->cookie = (void *)cookie[i];
		dxp->ndescs = 1;

		start_dp[idx].addr = VIRTIO_MBUF_ADDR(cookie[i], vq) +
				RTE_PKTMBUF_HEADROOM - hw->vtnet_hdr_size;
		start_dp[idx].len = cookie[i]->buf_len - RTE_PKTMBUF_HEADROOM
					+ hw->vtnet_hdr_size;

		vq->vq_desc_head_idx = dxp->next;
		if (vq->vq_desc_head_idx == VQ_RING_DESC_CHAIN_END)
			vq->vq_desc_tail_idx = vq->vq_desc_head_idx;

		virtqueue_store_flags_packed(&start_dp[idx], flags,
					     hw->weak_barriers);

		if (++vq->vq_avail_idx >= vq->vq_nentries) {
			vq->vq_avail_idx -= vq->vq_nentries;
			vq->vq_packed.cached_flags ^=
				VRING_PACKED_DESC_F_AVAIL_USED;
			flags = vq->vq_packed.cached_flags;
		}
	}
	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - num);
	return 0;
}

static int
lsxvio_rc_rx_queue_setup_finish(struct rte_eth_dev *dev,
	uint16_t queue_idx)
{
	uint16_t vtpci_queue_idx = 2 * queue_idx + VTNET_SQ_RQ_QUEUE_IDX;
	struct lsxvio_rc_pci_hw *lsx_hw = dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->pci_dev.hw;
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw, true);
	struct virtqueue *vq = hw->vqs[vtpci_queue_idx];
	struct virtnet_rx *rxvq = &vq->rxq;
	struct rte_mbuf *m;
	uint16_t desc_idx;
	int error, nbufs;

	/* Allocate blank mbufs for the each rx descriptor */
	nbufs = 0;

	memset(&rxvq->fake_mbuf, 0, sizeof(rxvq->fake_mbuf));
	for (desc_idx = 0; desc_idx < RTE_PMD_VIRTIO_RX_MAX_BURST;
	     desc_idx++) {
		vq->sw_ring[vq->vq_nentries + desc_idx] =
			rxvq->fake_mbuf;
	}

	while (!virtqueue_full(vq)) {
		m = rte_mbuf_raw_alloc(rxvq->mpool);
		if (!m)
			break;

		/* Enqueue allocated buffers */
		if (lsx_feature & LSX_VIO_EP2RC_PACKED)
			error = lsxvio_rc_recv_refill_packed(vq, &m, 1);
		else
			error = lsxvio_rc_recv_refill(vq, &m, 1);
		if (error) {
			rte_pktmbuf_free(m);
			break;
		}
		nbufs++;
	}

	if (lsx_feature & LSX_VIO_EP2RC_PACKED)
		virtqueue_enable_intr_packed(vq);
	else
		vq_update_avail_idx(vq);

	LSXVIO_PMD_DBG("Allocated %d bufs for %s rxq%d",
		nbufs, dev->data->name, queue_idx);

	LSXVIO_RC_VIRTQUEUE_DUMP(vq);

	return 0;
}

static int
lsxvio_rc_virtio_dev_tx_queue_setup_finish(struct rte_eth_dev *dev,
	uint16_t queue_idx)
{
	uint8_t vq_idx = 2 * queue_idx + VTNET_SQ_TQ_QUEUE_IDX;
	struct virtio_hw *hw = dev->data->dev_private;
	struct virtqueue *vq = hw->vqs[vq_idx];

	if (!virtio_with_packed_queue(hw)) {
		if (virtio_with_feature(hw, VIRTIO_F_IN_ORDER))
			vq->vq_split.ring.desc[vq->vq_nentries - 1].next = 0;
	}

	LSXVIO_RC_VIRTQUEUE_DUMP(vq);

	return 0;
}

static int
lsxvio_rc_eth_start(struct rte_eth_dev *dev)
{
	uint16_t i;
	struct virtnet_rx *rxvq;
	struct virtnet_tx *txvq;
	struct lsxvio_rc_pci_hw *lsx_hw = dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->pci_dev.hw;
	int ret;

	LSXVIO_PMD_DBG("%s: Start", dev->data->name);

	/* Finish the initialization of the queues */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		ret = lsxvio_rc_rx_queue_setup_finish(dev, i);
		if (ret < 0)
			return ret;
	}
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		ret = lsxvio_rc_virtio_dev_tx_queue_setup_finish(dev, i);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxvq = dev->data->rx_queues[i];
		/* Flush the old packets */
		lsxvio_rc_virtqueue_rxvq_flush(virtnet_rxq_to_vq(rxvq));
		lsxvio_rc_virtqueue_notify(virtnet_rxq_to_vq(rxvq));
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txvq = dev->data->tx_queues[i];
		lsxvio_rc_virtqueue_notify(virtnet_txq_to_vq(txvq));
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxvq = dev->data->rx_queues[i];
		LSXVIO_RC_VIRTQUEUE_DUMP(virtnet_rxq_to_vq(rxvq));
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txvq = dev->data->tx_queues[i];
		LSXVIO_RC_VIRTQUEUE_DUMP(virtnet_txq_to_vq(txvq));
	}

	lsxvio_rc_set_rxtx_funcs(dev);
	hw->started = true;
	lsxvio_rc_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_START);

	/* Initialize Link state */
	lsxvio_rc_eth_link_update(dev, 0);

	return 0;
}

static void
lsxvio_rc_free_mbufs(struct rte_eth_dev *dev)
{
	struct virtio_hw *hw = dev->data->dev_private;
	uint16_t nr_vq = lsxvio_rc_get_nr_vq(hw);
	uint32_t i, mbuf_num = 0;
	struct virtqueue *vq;
	struct rte_mbuf *buf;
	int queue_type;

	if (!hw->vqs)
		return;

	for (i = 0; i < nr_vq; i++) {
		vq = hw->vqs[i];
		if (!vq)
			continue;

		queue_type = virtio_get_queue_type(hw, i);
		if (queue_type != VTNET_RQ && queue_type != VTNET_TQ)
			continue;

		LSXVIO_RC_VIRTQUEUE_DUMP(vq);

		while ((buf = lsxvio_rc_virtqueue_detach_unused(vq)) != NULL) {
			rte_pktmbuf_free(buf);
			mbuf_num++;
		}

		LSXVIO_RC_VIRTQUEUE_DUMP(vq);
	}

	LSXVIO_PMD_DBG("%d mbufs freed for %s",
		mbuf_num, dev->data->name);
}

static int
lsxvio_rc_eth_stop(struct rte_eth_dev *dev)
{
	struct virtio_hw *hw = dev->data->dev_private;
	struct rte_eth_link link;

	LSXVIO_PMD_DBG("%s: Stop", dev->data->name);

	rte_spinlock_lock(&hw->state_lock);
	if (!hw->started)
		goto out_unlock;
	hw->started = false;

	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);
out_unlock:
	rte_spinlock_unlock(&hw->state_lock);

	return 0;
}

static int
lsxvio_rc_eth_link_update(struct rte_eth_dev *dev,
	__rte_unused int wait_to_complete)
{
	struct rte_eth_link link;
	uint16_t status;
	struct virtio_hw *hw = dev->data->dev_private;

	memset(&link, 0, sizeof(link));
	link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	link.link_speed  = RTE_ETH_SPEED_NUM_10G;
	link.link_autoneg = RTE_ETH_LINK_FIXED;

	if (!hw->started) {
		link.link_status = RTE_ETH_LINK_DOWN;
	} else if (virtio_with_feature(hw, VIRTIO_NET_F_STATUS)) {
		LSXVIO_PMD_INFO("%s: Get link status from hw",
			dev->data->name);
		lsxvio_rc_virtio_read_dev_config(hw,
			offsetof(struct virtio_net_config, status),
			&status, sizeof(status));
		if ((status & VIRTIO_NET_S_LINK_UP) == 0) {
			link.link_status = RTE_ETH_LINK_DOWN;
			LSXVIO_PMD_INFO("Port %d is down",
				dev->data->port_id);
		} else {
			link.link_status = RTE_ETH_LINK_UP;
			LSXVIO_PMD_INFO("Port %d is up",
				dev->data->port_id);
		}
	} else {
		link.link_status = RTE_ETH_LINK_UP;
	}

	return rte_eth_linkstatus_set(dev, &link);
}

static int
lsxvio_rc_eth_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info)
{
	uint64_t tso_mask, host_features;
	struct virtio_hw *hw = dev->data->dev_private;

	dev_info->speed_capa = RTE_ETH_LINK_SPEED_10G; /* fake value */

	dev_info->max_rx_queues =
		RTE_MIN(hw->max_queue_pairs, VIRTIO_MAX_RX_QUEUES);
	dev_info->max_tx_queues =
		RTE_MIN(hw->max_queue_pairs, VIRTIO_MAX_TX_QUEUES);
	dev_info->min_rx_bufsize = VIRTIO_MIN_RX_BUFSIZE;
	dev_info->max_rx_pktlen = VIRTIO_MAX_RX_PKTLEN;
	dev_info->max_mac_addrs = VIRTIO_MAX_MAC_ADDRS;

	host_features = LSX_VIO_OPS(hw)->get_features(hw);
	dev_info->rx_offload_capa = RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	if (host_features & (1ULL << VIRTIO_NET_F_GUEST_CSUM)) {
		dev_info->rx_offload_capa |=
			RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
			RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
	}
	if (host_features & (1ULL << VIRTIO_NET_F_CTRL_VLAN))
		dev_info->rx_offload_capa |= RTE_ETH_RX_OFFLOAD_VLAN_FILTER;
	tso_mask = (1ULL << VIRTIO_NET_F_GUEST_TSO4) |
		(1ULL << VIRTIO_NET_F_GUEST_TSO6);
	if ((host_features & tso_mask) == tso_mask)
		dev_info->rx_offload_capa |= RTE_ETH_RX_OFFLOAD_TCP_LRO;

	dev_info->tx_offload_capa = RTE_ETH_TX_OFFLOAD_MULTI_SEGS |
				    RTE_ETH_TX_OFFLOAD_VLAN_INSERT;
	if (host_features & (1ULL << VIRTIO_NET_F_CSUM)) {
		dev_info->tx_offload_capa |=
			RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
			RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
	}
	tso_mask = (1ULL << VIRTIO_NET_F_HOST_TSO4) |
		(1ULL << VIRTIO_NET_F_HOST_TSO6);
	if ((host_features & tso_mask) == tso_mask)
		dev_info->tx_offload_capa |= RTE_ETH_TX_OFFLOAD_TCP_TSO;

	return 0;
}

static void
lsxvio_rc_eth_construct(void)
{
	char *penv = getenv("LSXVIO_PCI_SIM");

	if (penv)
		s_lsxvio_rc_sim = atoi(penv);
	if (s_lsxvio_rc_sim)
		rte_lsxvio_pci_pmd.drv_flags &= (~RTE_PCI_DRV_NEED_MAPPING);

	penv = getenv("LSXVIO_RC_PROC_SECONDARY_STANDALONE");
	if (penv)
		s_lsxvio_rc_2nd_proc_standalone = atoi(penv);

	rte_lsxvio_pci_pmd.driver.name = RTE_STR(lsxvio_net);
	rte_pci_register(&rte_lsxvio_pci_pmd);
}

RTE_INIT(lsxvio_rc_eth_construct);
RTE_PMD_EXPORT_NAME(lsxvio_net, __COUNTER__);
RTE_PMD_REGISTER_PCI_TABLE(lsxvio_net, lsxvio_pci_id_map);

RTE_INIT(virtio_init_log)
{
	lsxvio_rc_logtype_init = rte_log_register("pmd.net.lsxvio.init");
	if (lsxvio_rc_logtype_init >= 0)
		rte_log_set_level(lsxvio_rc_logtype_init, RTE_LOG_NOTICE);
	lsxvio_rc_logtype_driver = rte_log_register("pmd.net.lsxvio.driver");
	if (lsxvio_rc_logtype_driver >= 0)
		rte_log_set_level(lsxvio_rc_logtype_driver, RTE_LOG_NOTICE);
}
