/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2024 NXP
 */

#ifndef _RTE_PMD_DPAA2_H
#define _RTE_PMD_DPAA2_H

/**
 * @file rte_pmd_dpaa2.h
 *
 * NXP dpaa2 PMD specific functions.
 */

#include <rte_compat.h>
#include <rte_flow.h>
#include <rte_ethdev.h>

/**
 * Create a flow rule to demultiplex ethernet traffic to separate network
 * interfaces.
 *
 * @param dpdmux_id
 *    ID of the DPDMUX MC object.
 * @param[in] pattern
 *    Pattern specification.
 * @param[in] actions
 *    Associated actions.
 *
 * @return
 *    0 in case of success,  otherwise failure.
 */
int
rte_pmd_dpaa2_mux_flow_create(uint32_t dpdmux_id,
	struct rte_flow_item pattern[],
	struct rte_flow_action actions[]);
int
rte_pmd_dpaa2_mux_flow_destroy(uint32_t dpdmux_id,
	uint16_t entry_index);
int
rte_pmd_dpaa2_mux_flow_l2(uint32_t dpdmux_id,
	uint8_t mac_addr[6], uint16_t vlan_id, int dest_if);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Dump demultiplex ethernet traffic counters
 *
 * @param f
 *    output stream
 * @param dpdmux_id
 *    ID of the DPDMUX MC object.
 * @param num_if
 *    number of interface in dpdmux object
 *
 */
__rte_experimental
void
rte_pmd_dpaa2_mux_dump_counter(FILE *f, uint32_t dpdmux_id, int num_if);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * demultiplex interface max rx frame length configure
 *
 * @param dpdmux_id
 *    ID of the DPDMUX MC object.
 * @param max_rx_frame_len
 *    maximum receive frame length (will be checked to be minimux of all dpnis)
 *
 */
__rte_experimental
int
rte_pmd_dpaa2_mux_rx_frame_len(uint32_t dpdmux_id, uint16_t max_rx_frame_len);

__rte_experimental
int
rte_pmd_dpaa2_mux_default_id(uint32_t dpdmux_id, uint16_t *id);

__rte_experimental
int
rte_pmd_dpaa2_mux_ep_name(uint32_t dpdmux_id,
	uint16_t id, const char **name);

/**
 * Create a custom hash key on basis of offset of start of packet and size.
 * for e.g. if we need GRE packets (non-vlan and without any extra headers)
 * to be hashed on basis of inner IP header, we will provide offset as:
 * 14 (eth) + 20 (IP) + 4 (GRE) + 12 (Inner Src offset) = 50 and size
 * as 8 bytes.
 *
 * @param port_id
 *    The port identifier of the Ethernet device.
 * @param offset
 *    Offset from the start of packet which needs to be included to
 *    calculate hash
 * @param size
 *    Size of the hash input key
 *
 * @return
 *   - 0 if successful.
 *   - Negative in case of failure.
 */
int
rte_pmd_dpaa2_set_custom_hash(uint16_t port_id,
			      uint16_t offset,
			      uint8_t size);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Do thread specific initialization
 */
__rte_experimental
void
rte_pmd_dpaa2_thread_init(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Generate the DPAA2 WRIOP based hash value
 *
 * @param key
 *    Array of key data
 * @param size
 *    Size of the hash input key in bytes
 *
 * @return
 *   - 0 if successful.
 *   - Negative in case of failure.
 */

__rte_experimental
uint32_t
rte_pmd_dpaa2_get_tlu_hash(uint8_t *key, int size);

__rte_experimental
int
rte_pmd_dpaa2_set_opr(uint16_t port_id, uint16_t rx_queue_id);

int
rte_pmd_dpaa2_dev_is_dpaa2(uint32_t eth_id);
const char *
rte_pmd_dpaa2_ep_name(uint32_t eth_id);
uint16_t
rte_pmd_dpaa2_clean_tx_conf(uint32_t eth_id,
	uint16_t txq_id);
int
rte_pmd_dpaa2_rx_get_offset(struct rte_mbuf *m,
	uint8_t *l3_off, uint8_t *l4_off, uint8_t *l5_off);

#if defined(RTE_LIBRTE_IEEE1588)
__rte_experimental
int
rte_pmd_dpaa2_set_one_step_ts(uint16_t port_id, uint16_t offset, uint8_t ch_update);

__rte_experimental
int
rte_pmd_dpaa2_get_one_step_ts(uint16_t port_id, bool mc_query);
#endif

#define RTE_DPAA2_DEV_TC_INFO_RSV_IDX 0
union rte_pmd_dpaa2_dev_tc_desc {
	uint64_t tc_info;
	struct {
		uint8_t rx_tc_num;
		uint8_t tx_tc_num;
		uint16_t qos_entries;
		uint16_t fs_entries;
		uint16_t dist_queues;
	};
} __rte_packed;

static inline void
rte_pmd_dpaa2_dev_parse_tc_info(const struct rte_eth_dev_info *dev_info,
	uint16_t *tc_num, uint16_t *qos_entries, uint16_t *fs_entries,
	uint16_t *entries_per_tc)
{
	union rte_pmd_dpaa2_dev_tc_desc desc;

	desc.tc_info = dev_info->reserved_64s[RTE_DPAA2_DEV_TC_INFO_RSV_IDX];
	if (tc_num)
		*tc_num = desc.rx_tc_num;
	if (qos_entries)
		*qos_entries = desc.qos_entries;
	if (fs_entries)
		*fs_entries = desc.fs_entries;
	if (entries_per_tc)
		*entries_per_tc = desc.dist_queues;
}

#define RTE_DPAA2_RXQ_TC_INFO_RSV_IDX 0
union rte_pmd_dpaa2_rxq_tc_desc {
	uint64_t tc_info;
	struct {
		uint8_t tc_id;
		uint8_t rsv0;
		uint16_t flow_id;
		uint32_t rsv1;
	};
} __rte_packed;

static inline void
rte_pmd_dpaa2_rxq_parse_tc_info(const struct rte_eth_rxq_info *rxq_info,
	uint8_t *tc_id, uint16_t *flow_id)
{
	union rte_pmd_dpaa2_rxq_tc_desc desc;

	desc.tc_info =
		rxq_info->conf.reserved_64s[RTE_DPAA2_RXQ_TC_INFO_RSV_IDX];
	if (tc_id)
		*tc_id = desc.tc_id;
	if (flow_id)
		*flow_id = desc.flow_id;
}

__rte_experimental
void *
rte_dpaa2_scheduler_init(void);
__rte_experimental
int
rte_dpaa2_scheduler_start(void *scheduler_handle);
__rte_experimental
int
rte_dpaa2_scheduler_destroy(void *scheduler_handle);
__rte_experimental
int32_t
rte_dpaa2_scheduler_rx(void *scheduler_handle, struct rte_mbuf **mbuf,
		       uint16_t nb_pkts);
__rte_experimental
int
rte_dpaa2_conf_scheduler(uint16_t port_id, uint16_t rx_queue_id,
			 int policer_unit, uint32_t options, int default_color,
			 uint32_t cir, uint32_t cbs, uint32_t pir, uint32_t pbs);

int
rte_pmd_dpaa2_flow_table_query(uint16_t portid);

#endif /* _RTE_PMD_DPAA2_H */
