/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019,2024 NXP
 */

#ifndef _ENETC_H_
#define _ENETC_H_

#include <rte_time.h>
#include "compat.h"
#include "base/enetc_hw.h"
#include "enetc_logs.h"
#include <linux/types.h>

#define PCI_VENDOR_ID_FREESCALE 0x1957

/* Max TX rings per ENETC. */
#define MAX_TX_RINGS	1

/* Max RX rings per ENTEC. */
#define MAX_RX_RINGS	1

/* Max BD counts per Ring. */
#define MAX_BD_COUNT   64000
/* Min BD counts per Ring. */
#define MIN_BD_COUNT   32
/* BD ALIGN */
#define BD_ALIGN       8

/* minimum frame size supported */
#define ENETC_MAC_MINFRM_SIZE	68
/* maximum frame size supported */
#define ENETC_MAC_MAXFRM_SIZE	9600

/* The max frame size with default MTU */
#define ENETC_ETH_MAX_LEN (RTE_ETHER_MTU + \
		RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN)

/* eth name size */
#define	ENETC_ETH_NAMESIZE	20

#define ENETC_DEFAULT_MSG_SIZE  1024    /* max size */

/* size for marking hugepage non-cacheable */
#define SIZE_2MB	0x200000

#define ENETC_TXBD(BDR, i) (&(((struct enetc_tx_bd *)((BDR).bd_base))[i]))
#define ENETC_RXBD(BDR, i) (&(((union enetc_rx_bd *)((BDR).bd_base))[i]))

#define ENETC4_MBUF_F_TX_IP_IPV4 (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4)
#define ENETC4_TX_CKSUM_OFFLOAD_MASK (RTE_MBUF_F_TX_IP_CKSUM | \
				    RTE_MBUF_F_TX_TCP_CKSUM | \
				    RTE_MBUF_F_TX_UDP_CKSUM)
struct enetc_swbd {
	struct rte_mbuf *buffer_addr;
};

struct enetc_bdr {
	void *bd_base;			/* points to Rx or Tx BD ring */
	struct enetc_swbd *q_swbd;
	union {
		void *tcir;
		void *rcir;
	};
	int bd_count; /* # of BDs */
	int next_to_use;
	int next_to_clean;
	uint16_t index;
	uint8_t	crc_len; /* 0 if CRC stripped, 4 otherwise */
	union {
		void *tcisr; /* Tx */
		int next_to_alloc; /* Rx */
	};
	struct rte_mempool *mb_pool;   /* mbuf pool to populate RX ring. */
	struct rte_eth_dev *ndev;
	const struct rte_memzone *mz;
	uint64_t ierrors;
};

/*
 * Structure to store private data for each driver instance (for each port).
 */
struct enetc_eth_adapter {
	struct rte_eth_dev *ndev;
	struct enetc_eth_hw hw;
};

#define ENETC_DEV_PRIVATE(adapter) \
	((struct enetc_eth_adapter *)adapter)

#define ENETC_DEV_PRIVATE_TO_HW(adapter) \
	(&((struct enetc_eth_adapter *)adapter)->hw)

#define ENETC_DEV_PRIVATE_TO_STATS(adapter) \
	(&((struct enetc_eth_adapter *)adapter)->stats)

#define ENETC_DEV_PRIVATE_TO_INTR(adapter) \
	(&((struct enetc_eth_adapter *)adapter)->intr)

/* Command completion status */
enum enetc_msg_cmd_status {
	ENETC_MSG_CMD_STATUS_OK,
	ENETC_MSG_CMD_STATUS_FAIL,
	ENETC_MSG_CMD_NOT_SUPPORT
};

/* VSI-PSI command message types */
enum enetc_msg_cmd_type {
	ENETC_MSG_CMD_MNG_MAC = 1, /* manage MAC address */
	ENETC_MSG_CMD_MNG_RX_MAC_FILTER,/* manage RX MAC table */
	ENETC_MSG_CMD_MNG_RX_VLAN_FILTER /* manage RX VLAN table */
};

/* VSI-PSI command action types */
enum enetc_msg_cmd_action_type {
	ENETC_MSG_CMD_MNG_ADD = 1,
	ENETC_MSG_CMD_MNG_REMOVE
};

/* PSI-VSI command header format */
struct enetc_msg_cmd_header {
	uint16_t type;       /* command class type */
	uint16_t id;         /* denotes the specific required action */
};

/* VF-PF set primary MAC address message format */
struct enetc_msg_cmd_set_primary_mac {
	struct enetc_msg_cmd_header header;
	struct sockaddr mac;
};

/* VSI-to-PSI Messaging: set MAC filter message format */
struct enetc_msg_config_mac_filter {
        struct enetc_msg_cmd_header header;
        uint8_t uc_promisc;
        uint8_t mc_promisc;
};

/* msg size encoding: default and max msg value of 1024B encoded as 0 */
static inline uint32_t enetc_vsi_set_msize(uint32_t size)
{
	return size < ENETC_DEFAULT_MSG_SIZE ? size >> 5 : 0;
}

/*
 * ENETC4 function prototypes
 */
int enetc4_pci_remove(struct rte_pci_device *pci_dev);
int enetc4_dev_configure(struct rte_eth_dev *dev);
int enetc4_dev_close(struct rte_eth_dev *dev);
int enetc4_link_update(struct rte_eth_dev *dev, int wait_to_complete __rte_unused);
int enetc4_dev_infos_get(struct rte_eth_dev *dev __rte_unused,
			 struct rte_eth_dev_info *dev_info);
int enetc4_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
			  uint16_t nb_rx_desc, unsigned int socket_id __rte_unused,
			  const struct rte_eth_rxconf *rx_conf,
			  struct rte_mempool *mb_pool);
int enetc4_rx_queue_start(struct rte_eth_dev *dev, uint16_t qidx);
int enetc4_rx_queue_stop(struct rte_eth_dev *dev, uint16_t qidx);
void enetc4_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid);
int enetc4_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			  uint16_t nb_desc, unsigned int socket_id __rte_unused,
			  const struct rte_eth_txconf *tx_conf);
int enetc4_tx_queue_start(struct rte_eth_dev *dev, uint16_t qidx);
int enetc4_tx_queue_stop(struct rte_eth_dev *dev, uint16_t qidx);
void enetc4_tx_queue_release(struct rte_eth_dev *dev, uint16_t qid);
const uint32_t *enetc4_supported_ptypes_get(struct rte_eth_dev *dev __rte_unused);

/*
 * enetc4_vf function prototype
 */
int enetc4_vf_dev_stop(struct rte_eth_dev *dev);

/*
 * RX/TX ENETC function prototypes
 */
uint16_t enetc_xmit_pkts(void *txq, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);
uint16_t enetc_xmit_pkts_nc(void *txq, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);
uint16_t enetc_recv_pkts(void *rxq, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);
uint16_t enetc_recv_pkts_nc(void *rxq, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);

int enetc_refill_rx_ring(struct enetc_bdr *rx_ring, const int buff_cnt);
void enetc4_dev_hw_init(struct rte_eth_dev *eth_dev);
void print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr);

static inline int
enetc_bd_unused(struct enetc_bdr *bdr)
{
	if (bdr->next_to_clean > bdr->next_to_use)
		return bdr->next_to_clean - bdr->next_to_use - 1;

	return bdr->bd_count + bdr->next_to_clean - bdr->next_to_use - 1;
}
#endif /* _ENETC_H_ */
