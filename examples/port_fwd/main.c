/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 * Code was mostly borrowed from examples/l3fwd/main.c
 * See examples/l3fwd/main.c for additional Copyrights.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_pmd_dpaa2.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>
#include <rte_pdump.h>

#include "port_fwd.h"
#include "nxp/rte_remote_direct_flow.h"

#define RTE_LOGTYPE_port_fwd RTE_LOGTYPE_USER1

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

uint32_t max_pkt_burst = MAX_PKT_BURST;
uint32_t max_tx_burst = MAX_TX_BURST;
uint32_t max_rx_burst = MAX_PKT_BURST;

enum port_fwd_proc_type {
	proc_primary = 0,
	proc_attach_secondary = 1,
	proc_standalone_secondary = 2,
};
static uint8_t s_proc_type = proc_primary;
static uint8_t s_ring_fwd;
static enum rte_remote_dir_cfg s_remote_dir;

static uint32_t s_data_room_size;

#define SEC_2_PRI "SEC_2_PRI_p%d_q%d"
#define PRI_2_SEC "PRI_2_SEC_p%d_q%d"

/* Global variables. */

static bool force_quit;

/* mask of enabled ports */
static uint32_t enabled_port_mask;
static uint16_t enabled_port_num;

struct port_queue_lcore_param {
	int port_id;
	int queue_id;
	int lcore_id;
} __rte_cache_aligned;

static struct port_queue_lcore_param s_pqc[MAX_LCORE_PARAMS];
static uint16_t s_pqc_num;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,
		.max_lro_pkt_size = RTE_MBUF_DEFAULT_DATAROOM,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_IP,
		},
	},
};

static struct lcore_conf s_lcore_conf[RTE_MAX_LCORE];

static int fwd_dst_port[RTE_MAX_ETHPORTS];

static int rx_seg_port[RTE_MAX_ETHPORTS];

static struct rte_mempool *pktmbuf_pool;
static struct rte_mempool *default_pktmbuf_pool;

static struct rte_mempool *pktmbuf_pool_for_2nd;

#define RTE_MAX_QUEUES 128
static uint16_t s_pq_map[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES];

static uint64_t max_mbuf_addr;
static uint64_t min_mbuf_addr = (~((uint64_t)0));

static int s_dump_mbuf;
static int s_inject;
static uint16_t s_inject_pkt_size = 64;

static uint8_t s_inject_pkt_base[] = {
	0x00, 0xE0, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x10,
	0x94, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFD,
	0xED, 0x40, 0xC0, 0xA8, 0x0B, 0x02, 0x01, 0x01,
	0x01, 0x01
};

struct loop_mode {
	int (*parse_fwd_dst)(int portid);
	rte_rx_callback_fn cb_parse_ptype;
	int (*main_loop)(void *dummy);
};

#define PORT_FWD_MBUF_FCS(mbuf) \
	(mbuf->pkt_len + PKTGEN_ETH_FCS_SIZE * mbuf->nb_segs)

#define PORT_FWD_MBUF_OVERHEAD(mbuf) \
	(mbuf->pkt_len + PKTGEN_ETH_OVERHEAD_SIZE * mbuf->nb_segs)

static int parse_port_fwd_dst(int portid)
{
	char *penv;
	char env_name[64];

	fwd_dst_port[portid] = -1;
	sprintf(env_name, "PORT%d_FWD", portid);
	penv = getenv(env_name);
	if (penv)
		fwd_dst_port[portid] = atoi(penv);

	if (fwd_dst_port[portid] < 0) {
		RTE_LOG(WARNING, port_fwd,
			"Drop packets from port %d\r\n", portid);
		return 0;
	}

	RTE_LOG(INFO, port_fwd,
		"Forward traffic from port %d to port %d\r\n",
		portid, fwd_dst_port[portid]);

	return 0;
}

static int parse_seg_rx_port(int portid)
{
	char *penv;
	char env_name[64];

	sprintf(env_name, "PORT%d_RX_SEG", portid);
	penv = getenv(env_name);
	if (penv)
		rx_seg_port[portid] = atoi(penv);

	if (rx_seg_port[portid]) {
		RTE_LOG(INFO, port_fwd,
			"Gather rx frames from port%d\r\n",
			portid);
	}

	return 0;
}

static int
port_fwd_dst_port(uint16_t src_port)
{
	return fwd_dst_port[src_port];
}

static int
port_fwd_rx_seg_port(uint16_t rx_port)
{
	return rx_seg_port[rx_port];
}

static void
port_fwd_drain_tx_cnf(struct lcore_conf *qconf)
{
	uint16_t drain, i, portid, queueid;
	int dstportid;

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		dstportid = port_fwd_dst_port(portid);
		if (dstportid < 0)
			continue;
		queueid = qconf->tx_queue_id[dstportid];
		if (!rte_pmd_dpaa2_dev_is_dpaa2(dstportid))
			continue;
		rte_delay_us(10000);
drain_again:
		drain = rte_pmd_dpaa2_clean_tx_conf(dstportid,
				queueid);
		if (drain)
			goto drain_again;
	}
}

static uint16_t
port_fwd_dup_mbufs(uint32_t eth_id,
	uint16_t txq_id, struct rte_mbuf *mbuf_to[],
	struct rte_mbuf *mbuf_from[], uint16_t count)
{
	uint16_t tx_clean, clean_count, alloc_count, i;
	int ret;
	struct rte_mempool *pool;

	pool = default_pktmbuf_pool ?
		default_pktmbuf_pool : pktmbuf_pool;

	if (!mbuf_from) {
		alloc_count = 0;
alloc_again:
		if (alloc_count > 10)
			return 0;
		ret = rte_pktmbuf_alloc_bulk(pool,
				mbuf_to, count);
		if (ret) {
			clean_count = 0;
alloc_clean_again:
			tx_clean = rte_pmd_dpaa2_clean_tx_conf(eth_id,
						txq_id);
			if (!tx_clean) {
				clean_count++;
				if (clean_count < 100)
					goto alloc_clean_again;
			}
			alloc_count++;
			goto alloc_again;
		}

		return count;
	}

	for (i = 0; i < count; i++) {
		alloc_count = 0;
copy_again:
		if (alloc_count > 10)
			break;
		mbuf_to[i] = rte_pktmbuf_copy(mbuf_from[i],
			pool, 0,
			mbuf_from[i]->pkt_len);
		if (!mbuf_to[i]) {
			clean_count = 0;
copy_clean_again:
			tx_clean = rte_pmd_dpaa2_clean_tx_conf(eth_id, txq_id);
			if (!tx_clean) {
				clean_count++;
				if (clean_count < 100)
					goto copy_clean_again;
			}
			alloc_count++;
			goto copy_again;
		}
	}

	rte_pktmbuf_free_bulk(mbuf_from, count);

	return i;
}

static int
main_injection_test_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t tx_len[MAX_PKT_BURST];
	unsigned int lcore_id;
	int i, nb_rx, j;
	uint16_t nb_tx, sent;
	uint16_t portid;
	int dstportid;
	uint8_t queueid;
	struct lcore_conf *qconf;
	char *penv;
	uint16_t burst_size = MAX_PKT_BURST;
	uint16_t inject_size = s_inject_pkt_size - PKTGEN_ETH_FCS_SIZE;

	penv = getenv("PORT_FWD_INJECTION_BURST_SIZE");
	if (penv) {
		burst_size = atoi(penv);
		if (burst_size < 1 || burst_size > MAX_PKT_BURST)
			burst_size = MAX_PKT_BURST;
	}
	RTE_LOG(INFO, port_fwd,
		"Inject pkt size is %d and burst size is %d\n",
		s_inject_pkt_size, burst_size);

	lcore_id = rte_lcore_id();
	qconf = &s_lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, port_fwd,
			"lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, port_fwd,
		"entering injection test loop on lcore %u\n",
		lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, port_fwd,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {
		/* Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; i++) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;

			dstportid = port_fwd_dst_port(portid);

			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				MAX_PKT_BURST);

			for (j = 0; j < nb_rx; j++) {
				if (unlikely(inject_size !=
					pkts_burst[j]->pkt_len)) {
					RTE_LOG(WARNING, port_fwd,
						"PKT len(%d) received is not expected(%d)\n",
						pkts_burst[j]->pkt_len,
						inject_size);
				}
				qconf->rx_statistic[portid].bytes +=
					pkts_burst[j]->pkt_len;
				qconf->rx_statistic[portid].bytes_fcs +=
					PORT_FWD_MBUF_FCS(pkts_burst[j]);
				qconf->rx_statistic[portid].bytes_overhead +=
					PORT_FWD_MBUF_OVERHEAD(pkts_burst[j]);
			}
			qconf->rx_statistic[portid].packets += nb_rx;

			rte_pktmbuf_free_bulk(pkts_burst, nb_rx);

			burst_size = port_fwd_dup_mbufs(dstportid,
				qconf->tx_queue_id[dstportid],
				pkts_burst, NULL, burst_size);
			if (!burst_size)
				continue;

			nb_tx = burst_size;

			for (j = 0; j < nb_tx; j++) {
				pkts_burst[j]->data_off = RTE_PKTMBUF_HEADROOM;
				pkts_burst[j]->pkt_len = inject_size;
				pkts_burst[j]->data_len = inject_size;
				tx_len[j] = inject_size;
			}

			sent = rte_eth_tx_burst(dstportid,
					qconf->tx_queue_id[dstportid],
					pkts_burst, nb_tx);
			for (j = 0; j < sent; j++) {
				qconf->tx_statistic[dstportid].bytes +=
					tx_len[j];
				qconf->tx_statistic[dstportid].bytes_fcs +=
					tx_len[j] + PKTGEN_ETH_FCS_SIZE;
				qconf->tx_statistic[dstportid].bytes_overhead +=
					tx_len[j] + PKTGEN_ETH_OVERHEAD_SIZE;
			}
			qconf->tx_statistic[dstportid].packets += sent;

			/* Free any unsent packets. */
			if (unlikely(sent < nb_tx)) {
				rte_pktmbuf_free_bulk(&pkts_burst[sent],
					nb_tx - sent);
			}
		}
	}

	if (qconf->dump_buf) {
		rte_free(qconf->dump_buf);
		qconf->dump_buf = NULL;
	}

	if (default_pktmbuf_pool)
		port_fwd_drain_tx_cnf(qconf);

	return 0;
}

static inline void
dump_mbuf_data(struct rte_mbuf *pkt, int tx_rx,
	uint16_t portid, struct lcore_conf *qconf)
{
	uint32_t i, off = 0;
	uint8_t *data = (uint8_t *)pkt->buf_addr +
		pkt->data_off;

	if (likely(!s_dump_mbuf))
		return;

	if (!qconf->dump_buf)
		qconf->dump_buf = rte_malloc(NULL, 4096, 0);

	RTE_LOG(INFO, port_fwd,
		"%s %d pkt len:%d\r\n", tx_rx ?
		"Send to" : "Recv from",
		portid, pkt->pkt_len);
	if (!qconf->dump_buf)
		return;
	for (i = 0; i < pkt->pkt_len; i++) {
		off += sprintf(&qconf->dump_buf[off],
			"%02x ", data[i]);
		if ((i + 1) % 16 == 0)
			off += sprintf(&qconf->dump_buf[off], "\r\n");
	}

	RTE_LOG(INFO, port_fwd,
		"%s\r\n", qconf->dump_buf);
}

static uint16_t
port_fwd_xmit_burst(struct rte_mbuf *pkts_burst[],
	uint16_t expected_nb, uint16_t rx_portid, int dstportid,
	uint16_t queue_id, uint8_t sents[],
	int re_send_max)
{
	uint16_t nb_tx = 0, ret, burst_nb = 0, sent, re_send;
	uint32_t max_size = 0;
	int i, j;
	struct rte_mbuf **tx_pkts;

	if (dstportid < 0) {
		rte_pktmbuf_free_bulk(pkts_burst, expected_nb);

		return 0;
	}

	if (port_fwd_rx_seg_port(rx_portid)) {
		for (j = (expected_nb - 1); j >= 0; j--) {
			max_size += pkts_burst[j]->data_len;
			if ((j - 1) >= 0 &&
				(max_size + pkts_burst[j - 1]->data_len) <
				s_data_room_size) {
				pkts_burst[j - 1]->next = pkts_burst[j];
				pkts_burst[j - 1]->pkt_len +=
					pkts_burst[j]->pkt_len;
				pkts_burst[j - 1]->nb_segs +=
					pkts_burst[j]->nb_segs;
				burst_nb++;
			} else {
				max_size = 0;
				burst_nb++;
				ret = rte_eth_tx_burst(dstportid,
					queue_id,
					&pkts_burst[j], 1);
				if (unlikely(ret < 1)) {
					rte_pktmbuf_free(pkts_burst[j]);
					for (i = j; i < (j + burst_nb); i++)
						sents[i] = 0;
				} else {
					nb_tx += burst_nb;
					for (i = j; i < (j + burst_nb); i++)
						sents[i] = 1;
				}
				burst_nb = 0;
			}
		}
	} else {
		tx_pkts = pkts_burst;
		sent = 0;
		re_send = 0;
tx_again:
		nb_tx = rte_eth_tx_burst(dstportid, queue_id,
				tx_pkts, expected_nb - sent);
		sent += nb_tx;
		if (sent < expected_nb && re_send < re_send_max) {
			tx_pkts = &pkts_burst[sent];
			re_send++;
			goto tx_again;
		}
		/* Free any unsent packets. */
		if (unlikely(nb_tx < expected_nb)) {
			rte_pktmbuf_free_bulk(&pkts_burst[nb_tx],
				expected_nb - nb_tx);
		}
		for (i = 0; i < nb_tx; i++)
			sents[i] = 1;
		for (i = nb_tx; i < expected_nb; i++)
			sents[i] = 0;
	}

	return nb_tx;
}

static uint16_t
port_fwd_handle_seg_rx(struct rte_mbuf **pkts_rx,
	struct rte_mbuf *pkts_single[], struct lcore_conf *qconf,
	uint16_t rx_portid, uint16_t nb_rx,
	int re_send_max)
{
	uint16_t i, single_nb = 0, j, nb_tx, nb_tx_expected;
	struct rte_mbuf *pkts_tx[MAX_PKT_BURST];
	struct rte_mbuf *curr, *tmp;
	int dstportid = port_fwd_dst_port(rx_portid);
	uint64_t bytes_overhead[MAX_PKT_BURST];
	uint64_t bytes_fcs[MAX_PKT_BURST];
	uint64_t bytes[MAX_PKT_BURST];
	uint8_t sent[MAX_PKT_BURST];

	for (i = 0; i < nb_rx; i++) {
		if (!pkts_rx[i]->next) {
			pkts_single[single_nb] = pkts_rx[i];
			single_nb++;
			continue;
		}
		curr = pkts_rx[i];
		j = 0;
		while (curr) {
			pkts_tx[j] = curr;
			pkts_tx[j]->pkt_len = pkts_tx[j]->data_len;
			pkts_tx[j]->nb_segs = 1;
			tmp = curr;
			curr = curr->next;
			tmp->next = NULL;

			bytes[j] = pkts_tx[j]->pkt_len;
			bytes_fcs[j] = PORT_FWD_MBUF_FCS(pkts_tx[j]);
			bytes_overhead[j] = PORT_FWD_MBUF_OVERHEAD(pkts_tx[j]);
			qconf->rx_statistic[rx_portid].bytes +=
					bytes[j];
			qconf->rx_statistic[rx_portid].bytes_fcs +=
					bytes_fcs[j];
			qconf->rx_statistic[rx_portid].bytes_overhead +=
					bytes_overhead[j];
			j++;
		}
		qconf->rx_statistic[rx_portid].packets += j;
		nb_tx_expected = j;
		if (unlikely(s_dump_mbuf)) {
			for (j = 0; j < nb_tx_expected; j++)
				dump_mbuf_data(pkts_tx[j], 1, dstportid,
					qconf);
		}
		if (dstportid < 0)
			continue;
		nb_tx = port_fwd_xmit_burst(pkts_tx, nb_tx_expected,
			rx_portid, dstportid, qconf->tx_queue_id[rx_portid],
			sent, re_send_max);
		for (j = 0; j < nb_tx_expected; j++) {
			if (!sent[j])
				continue;
			qconf->tx_statistic[dstportid].bytes +=
				bytes[j];
			qconf->tx_statistic[dstportid].bytes_fcs +=
				bytes_fcs[j];
			qconf->tx_statistic[dstportid].bytes_overhead +=
				bytes_overhead[j];
		}
		qconf->tx_statistic[dstportid].packets += nb_tx;
	}

	return single_nb;
}

static int
main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *tx_burst[MAX_PKT_BURST];
	struct rte_mbuf *tx_burst_dup[MAX_PKT_BURST];
	struct rte_mbuf **tx_pkts;
	unsigned int lcore_id;
	int i, nb_rx, j;
	uint16_t idx;
	uint16_t nb_tx, rx_left, re_send, sent;
	uint16_t portid, rx_burst;
	int dstportid;
	uint8_t queueid;
	struct lcore_conf *qconf;
	char *penv;
	uint64_t bytes_overhead[MAX_PKT_BURST];
	uint64_t bytes_fcs[MAX_PKT_BURST];
	uint64_t bytes[MAX_PKT_BURST];
	struct rte_ring *tx_ring, *rx_ring;
	uint8_t sents[MAX_PKT_BURST];
	int re_send_max = 0;

	if (s_inject) {
		main_injection_test_loop();
		return 0;
	}

	penv = getenv("PORT_FWD_RX_BURST");
	if (penv && atoi(penv) > 0 && atoi(penv) <= MAX_PKT_BURST)
		rx_burst = atoi(penv);
	else
		rx_burst = MAX_PKT_BURST;

	penv = getenv("PORT_FWD_RE_SEND_MAX");
	if (penv) {
		re_send_max = atoi(penv);
		if (re_send_max < 0)
			re_send_max = 0;
	}

	lcore_id = rte_lcore_id();
	qconf = &s_lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, port_fwd,
			"lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, port_fwd,
		"entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, port_fwd,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {
		if (!s_ring_fwd)
			goto port_forwarding;

		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;

			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				rx_burst);
			for (j = 0; j < nb_rx; j++) {
				bytes[j] = pkts_burst[j]->pkt_len;
				bytes_fcs[j] =
					PORT_FWD_MBUF_FCS(pkts_burst[j]);
				bytes_overhead[j] =
					PORT_FWD_MBUF_OVERHEAD(pkts_burst[j]);
				qconf->rx_statistic[portid].bytes +=
					bytes[j];
				qconf->rx_statistic[portid].bytes_fcs +=
					bytes_fcs[j];
				qconf->rx_statistic[portid].bytes_overhead +=
					bytes_overhead[j];
			}
			qconf->rx_statistic[portid].packets += nb_rx;
			if (nb_rx > 0) {
				tx_ring = qconf->rx_queue_list[i].send_q;
				nb_tx = rte_ring_enqueue_burst(tx_ring,
						(void * const *)pkts_burst,
						nb_rx, NULL);
				for (idx = nb_tx; idx < nb_rx; idx++)
					rte_pktmbuf_free(pkts_burst[idx]);
			}

			rx_ring = qconf->rx_queue_list[i].recv_q;
			nb_rx = rte_ring_dequeue_burst(rx_ring,
				(void **)pkts_burst,
				rx_burst, NULL);
			if (nb_rx == 0)
				continue;

			tx_pkts = pkts_burst;
			sent = 0;
			re_send = 0;
ring_fwd_tx_again:
			nb_tx = rte_eth_tx_burst(portid,
					qconf->tx_queue_id[portid],
					tx_pkts, nb_rx - sent);
			for (j = sent; j < sent + nb_tx; j++) {
				qconf->tx_statistic[portid].bytes +=
					bytes[j];
				qconf->tx_statistic[portid].bytes_fcs +=
					bytes_fcs[j];
				qconf->tx_statistic[portid].bytes_overhead +=
					bytes_overhead[j];
			}
			sent += nb_tx;
			qconf->tx_statistic[portid].packets += nb_tx;
			if (sent < nb_rx && re_send < re_send_max) {
				tx_pkts = &pkts_burst[sent];
				re_send++;
				goto ring_fwd_tx_again;
			}

			/* Free any unsent packets. */
			if (unlikely(sent < nb_rx)) {
				for (idx = sent; idx < nb_rx; idx++)
					rte_pktmbuf_free(pkts_burst[idx]);
			}
		}
		continue;

port_forwarding:
		/* Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;

			dstportid = port_fwd_dst_port(portid);

			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				rx_burst);
			if (nb_rx == 0)
				continue;

			rx_left = port_fwd_handle_seg_rx(pkts_burst,
				tx_burst, qconf, portid, nb_rx,
				re_send_max);

			for (j = 0; j < rx_left; j++) {
				bytes[j] = tx_burst[j]->pkt_len;
				bytes_fcs[j] =
					PORT_FWD_MBUF_FCS(tx_burst[j]);
				bytes_overhead[j] =
					PORT_FWD_MBUF_OVERHEAD(tx_burst[j]);
				qconf->rx_statistic[portid].bytes +=
					bytes[j];
				qconf->rx_statistic[portid].bytes_fcs +=
					bytes_fcs[j];
				qconf->rx_statistic[portid].bytes_overhead +=
					bytes_overhead[j];
				dump_mbuf_data(tx_burst[j], 0, portid,
					qconf);
			}
			qconf->rx_statistic[portid].packets += rx_left;

			if (dstportid < 0) {
				rte_pktmbuf_free_bulk(tx_burst, rx_left);
				continue;
			}

			tx_pkts = tx_burst;
			if (default_pktmbuf_pool) {
				rx_left = port_fwd_dup_mbufs(dstportid,
					qconf->tx_queue_id[dstportid],
					tx_burst_dup, tx_burst, rx_left);
				if (!rx_left)
					continue;
				tx_pkts = tx_burst_dup;
			}

			nb_tx = port_fwd_xmit_burst(tx_pkts, rx_left,
				portid, dstportid,
				qconf->tx_queue_id[dstportid], sents,
				re_send_max);
			for (j = 0; j < rx_left; j++) {
				if (!sents[j])
					continue;
				qconf->tx_statistic[dstportid].bytes +=
					bytes[j];
				qconf->tx_statistic[dstportid].bytes_fcs +=
					bytes_fcs[j];
				qconf->tx_statistic[dstportid].bytes_overhead +=
					bytes_overhead[j];
			}
			qconf->tx_statistic[dstportid].packets += nb_tx;
		}
	}

	if (default_pktmbuf_pool)
		port_fwd_drain_tx_cnf(qconf);

	if (qconf->dump_buf) {
		rte_free(qconf->dump_buf);
		qconf->dump_buf = NULL;
	}

	return 0;
}

static struct loop_mode port_fwd_demo = {
	.parse_fwd_dst = parse_port_fwd_dst,
	.main_loop = main_loop,
};

static int
check_lcore_params(void)
{
	int lcore;
	uint16_t i;

	for (i = 0; i < s_pqc_num; ++i) {
		lcore = s_pqc[i].lcore_id;
		if (lcore < 0)
			continue;
		if (!rte_lcore_is_enabled(lcore)) {
			RTE_LOG(ERR, port_fwd,
				"lcore %hhu is not enabled\n", lcore);
			return -EINVAL;
		}
	}
	return 0;
}

static int
check_port_config(void)
{
	uint16_t portid;
	uint16_t i;

	for (i = 0; i < s_pqc_num; ++i) {
		portid = s_pqc[i].port_id;
		if ((enabled_port_mask & (1 << portid)) == 0) {
			RTE_LOG(ERR, port_fwd,
				"port %u is not enabled in port mask\n",
				portid);
			return -EINVAL;
		}
		if (!rte_eth_dev_is_valid_port(portid)) {
			RTE_LOG(ERR, port_fwd,
				"port %u is not present on the board\n",
				portid);
			return -EINVAL;
		}
	}
	return 0;
}

static uint16_t
get_port_n_rx_queues(const uint16_t port,
	uint16_t queue[])
{
	uint16_t queue_num = 0, i, j;

	for (i = 0; i < s_pqc_num; ++i) {
		if (s_pqc[i].port_id == port) {
			queue[queue_num] = s_pqc[i].queue_id;
			for (j = 0; j < queue_num; j++) {
				if (queue[j] == s_pqc[i].queue_id) {
					rte_exit(EXIT_FAILURE,
						"duplicated rxq(%d) on port%d\n",
						queue[j], port);
					return 0;
				}
			}
			queue_num++;
		}
	}

	return queue_num;
}

static int
port_fwd_port_queue_mapping(uint16_t port_id, uint16_t queue_id,
	uint16_t *port_idx, uint16_t *queue_idx)
{
	int i, j;
	uint16_t pidx = 0, qidx = 0;

	if (port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, port_fwd,
			"Too large port ID(%d) >= %d\n",
			port_id, RTE_MAX_ETHPORTS);
		return -EINVAL;
	}

	if (queue_id >= RTE_MAX_QUEUES) {
		RTE_LOG(ERR, port_fwd,
			"Too large queue ID(%d) >= %d\n",
			queue_id, RTE_MAX_QUEUES);
		return -EINVAL;
	}

	if (s_pq_map[port_id][queue_id]) {
		for (i = 0; i <= port_id; i++) {
			for (j = 0; j <= queue_id; j++) {
				if (s_pq_map[i][j]) {
					pidx++;
					break;
				}
			}
		}
		for (j = 0; j <= queue_id; j++) {
			if (s_pq_map[port_id][j])
				qidx++;
		}
		if (port_idx)
			*port_idx = pidx;
		if (queue_idx)
			*queue_idx = qidx;

		return 0;
	}

	return -EINVAL;
}

static int
init_lcore_rxq_ring(struct lcore_rx_queue *rx_queue)
{
	char send_name[64];
	char recv_name[64];
	struct rte_ring *send_q, *recv_q;
	int err;
	uint16_t port_idx, queue_idx;

	if (s_proc_type == proc_standalone_secondary)
		return -EINVAL;

	err = port_fwd_port_queue_mapping(rx_queue->port_id,
		rx_queue->queue_id, &port_idx, &queue_idx);
	if (err) {
		rte_exit(0, "port(%d)-queue(%d) mapping failed\n",
			rx_queue->port_id, rx_queue->queue_id);

		return err;
	}

	if (s_proc_type == proc_primary) {
		snprintf(send_name, sizeof(send_name), PRI_2_SEC,
			port_idx, queue_idx);
		send_q = rte_ring_create(send_name, 512, 0, 0);
		snprintf(recv_name, sizeof(recv_name), SEC_2_PRI,
			port_idx, queue_idx);
		recv_q = rte_ring_create(recv_name, 512, 0, 0);
		rx_queue->send_q = send_q;
		rx_queue->recv_q = recv_q;
		if (!send_q) {
			RTE_LOG(ERR, port_fwd,
				"send_q(%s) created failed\n",
				send_name);
			goto clear_proxy_q;
		}
		if (!recv_q) {
			RTE_LOG(ERR, port_fwd,
				"recv_q(%s) created failed\n",
				recv_name);
			goto clear_proxy_q;
		}
		RTE_LOG(INFO, port_fwd,
			"send_q(%s):%p, recv_q(%s):%p created\r\n",
			send_name, send_q, recv_name, recv_q);
	} else if (s_proc_type == proc_attach_secondary) {
		snprintf(recv_name, sizeof(recv_name), PRI_2_SEC,
			port_idx, queue_idx);
		recv_q = rte_ring_lookup(recv_name);
		snprintf(send_name, sizeof(send_name), SEC_2_PRI,
			port_idx, queue_idx);
		send_q = rte_ring_lookup(send_name);
		rx_queue->send_q = send_q;
		rx_queue->recv_q = recv_q;
		if (!send_q) {
			RTE_LOG(ERR, port_fwd,
				"send_q(%s) lookup failed\n",
				send_name);
			goto clear_proxy_q;
		}
		if (!recv_q) {
			RTE_LOG(ERR, port_fwd,
				"recv_q(%s) lookup failed\n",
				recv_name);
			goto clear_proxy_q;
		}
		RTE_LOG(INFO, port_fwd,
			"send_q(%s):%p, recv_q(%s):%p detected\r\n",
			send_name, send_q, recv_name, recv_q);
	}

	return 0;

clear_proxy_q:
	if (rx_queue->send_q)
		rte_ring_free(rx_queue->send_q);
	if (rx_queue->recv_q)
		rte_ring_free(rx_queue->recv_q);

	if (s_proc_type == proc_primary)
		rte_exit(0, "port(%d)queue(%d) ring create failed\n",
			port_idx, queue_idx);
	else
		rte_exit(0, "port(%d)queue(%d) ring lookup failed\n",
			port_idx, queue_idx);
	return -EINVAL;
}

static int
init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < s_pqc_num; ++i) {
		if (s_pqc[i].lcore_id < 0) {
			/**Don't handle this queue by core.*/
			continue;
		}
		lcore = s_pqc[i].lcore_id;
		nb_rx_queue = s_lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			RTE_LOG(ERR, port_fwd,
				"too many queues (%u) for lcore: %u\n",
				nb_rx_queue + 1, lcore);
			return -EINVAL;
		}

		s_lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
				s_pqc[i].port_id;
		s_lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
				s_pqc[i].queue_id;
		s_lcore_conf[lcore].n_rx_queue++;
	}

	return 0;
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -EINVAL;

	if (pm == 0)
		return -EINVAL;

	return pm;
}

static int
parse_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_QUEUE,
		FLD_LCORE,
		_NUM_FLD
	};
	int int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i, num;
	unsigned int size;
	struct port_queue_lcore_param *param;

	s_pqc_num = 0;

	for (i = 0; i < MAX_LCORE_PARAMS; i++) {
		s_pqc[i].port_id = -1;
		s_pqc[i].queue_id = -1;
		s_pqc[i].lcore_id = -1;
	}
	param = s_pqc;

	p = strchr(p0, '(');
	while (p) {
		++p;
		p0 = strchr(p, ')');
		if (!p0)
			return -EINVAL;

		size = p0 - p;
		if (size >= sizeof(s))
			return -EINVAL;

		snprintf(s, sizeof(s), "%.*s", size, p);
		num = rte_strsplit(s, sizeof(s), str_fld,
			_NUM_FLD, ',');
		if (num > _NUM_FLD || num <= 0)
			return -EINVAL;
		for (i = 0; i < num; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno || end == str_fld[i])
				return -EINVAL;
		}
		if (s_pqc_num >= MAX_LCORE_PARAMS) {
			RTE_LOG(ERR, port_fwd,
				"exceeded max number port/queue/core params: %hu\n",
				s_pqc_num);
			return -EINVAL;
		}
		if (num > FLD_PORT)
			param->port_id = int_fld[FLD_PORT];
		if (num > FLD_QUEUE)
			param->queue_id = int_fld[FLD_QUEUE];
		if (num > FLD_LCORE)
			param->lcore_id = int_fld[FLD_LCORE];
		if (param->port_id >= 0 && param->queue_id >= 0)
			s_pq_map[param->port_id][param->queue_id] = 1;

		s_pqc_num++;
		param++;
		p = strchr(p0, '(');
	}

	return 0;
}

#define MEMPOOL_CACHE_SIZE 256

static const char short_options[] =
	"p:"  /* portmask */
	"b:"  /* burst size */
	;

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_DIRECT_RSP_CONFIG "direct-rsp"
#define CMD_LINE_OPT_DIRECT_REMOTE_CONFIG "direct-remote"
#define CMD_LINE_OPT_DIRECT_DEF_CONFIG "direct-def"

#define CMD_LINE_OPT_PER_PORT_POOL "enable-per-port-pool"
enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_DIRECT_RSP_CONFIG_NUM,
	CMD_LINE_OPT_DIRECT_REMOTE_CONFIG_NUM,
	CMD_LINE_OPT_DIRECT_DEF_CONFIG_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_CONFIG, 1, 0,
		CMD_LINE_OPT_CONFIG_NUM},
	{CMD_LINE_OPT_DIRECT_RSP_CONFIG, 0, 0,
		CMD_LINE_OPT_DIRECT_RSP_CONFIG_NUM},
	{CMD_LINE_OPT_DIRECT_REMOTE_CONFIG, 1, 0,
		CMD_LINE_OPT_DIRECT_REMOTE_CONFIG_NUM},
	{CMD_LINE_OPT_DIRECT_DEF_CONFIG, 1, 0,
		CMD_LINE_OPT_DIRECT_DEF_CONFIG_NUM},
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	unsigned int burst_size;

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options,
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				RTE_LOG(ERR, port_fwd, "Invalid portmask\n");
				return -EINVAL;
			}
			break;

		/* max_burst_size */
		case 'b':
			burst_size = (unsigned int)atoi(optarg);
			if (burst_size > max_pkt_burst) {
				RTE_LOG(ERR, port_fwd,
					"invalid burst size(%d) > %d\n",
					burst_size, max_pkt_burst);
				return -EINVAL;
			}
			max_pkt_burst = burst_size;
			max_rx_burst = max_pkt_burst;
			max_tx_burst = max_rx_burst / 2;
			break;

		/* long options */
		case CMD_LINE_OPT_CONFIG_NUM:
			ret = parse_config(optarg);
			if (ret) {
				RTE_LOG(ERR, port_fwd, "Invalid config\n");
				return ret;
			}
			break;
		case CMD_LINE_OPT_DIRECT_RSP_CONFIG_NUM:
			s_remote_dir |= RTE_REMOTE_DIR_RSP;
			break;
		case CMD_LINE_OPT_DIRECT_REMOTE_CONFIG_NUM:
			ret = rte_remote_direct_parse_config(optarg, 1);
			if (ret) {
				RTE_LOG(ERR, port_fwd,
					"Invalid direct config\n");
				return ret;
			}
			s_remote_dir |= RTE_REMOTE_DIR_REQ;
			break;
		case CMD_LINE_OPT_DIRECT_DEF_CONFIG_NUM:
			ret = rte_remote_direct_parse_config(optarg, 0);
			if (ret) {
				RTE_LOG(ERR, port_fwd,
					"Invalid default direct config\n");
				return ret;
			}
			break;

		default:
			return -EINVAL;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 1; /* reset getopt lib */
	return ret;
}

static void
port_fwd_inject_gen_pkt(struct rte_mbuf *mbuf)
{
	struct rte_ether_hdr *eth_header;
	struct rte_ipv4_hdr *ipv4_header;
	uint64_t rand = rte_rand();
	uint8_t *payload = rte_pktmbuf_mtod(mbuf, void *);
	const uint16_t len = s_inject_pkt_size -
		sizeof(struct rte_ether_hdr) - PKTGEN_ETH_FCS_SIZE;

	rte_memcpy(payload, s_inject_pkt_base,
		sizeof(s_inject_pkt_base));
	eth_header = (struct rte_ether_hdr *)payload;
	ipv4_header = (struct rte_ipv4_hdr *)(eth_header + 1);
	ipv4_header->total_length = rte_cpu_to_be_16(len);
	ipv4_header->src_addr = (rte_be32_t)(rand & 0xffffffff);
	ipv4_header->dst_addr = (rte_be32_t)((rand >> 32) & 0xffffffff);
	ipv4_header->hdr_checksum = 0;
	ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);

	mbuf->pkt_len = s_inject_pkt_size - PKTGEN_ETH_FCS_SIZE;
	mbuf->data_len = s_inject_pkt_size - PKTGEN_ETH_FCS_SIZE;
}

static void
port_fwd_mp_max_min_addr(struct rte_mempool *mp)
{
	uint32_t num = mp->size, i, alloced = 0, bulk_size;
	int ret;
	struct rte_mbuf **mbuf_arry =
		malloc(sizeof(struct rte_mbuf *) * num);

	if (!mbuf_arry)
		return;

	while (num) {
		bulk_size = num > RTE_MEMPOOL_CACHE_MAX_SIZE ?
			RTE_MEMPOOL_CACHE_MAX_SIZE : num;
		ret = rte_pktmbuf_alloc_bulk(mp,
			&mbuf_arry[alloced], bulk_size);
		if (ret) {
			RTE_LOG(ERR, port_fwd,
				"Drain %d bufs from %s failed\r\n",
				num, mp->name);
			if (alloced)
				rte_pktmbuf_free_bulk(mbuf_arry, alloced);
			free(mbuf_arry);
			return;
		}
		alloced += bulk_size;
		num -= bulk_size;
	}

	for (i = 0; i < mp->size; i++) {
		if (mbuf_arry[i]->buf_iova > max_mbuf_addr)
			max_mbuf_addr = mbuf_arry[i]->buf_iova;
		if (mbuf_arry[i]->buf_iova < min_mbuf_addr)
			min_mbuf_addr = mbuf_arry[i]->buf_iova;
		if (s_inject)
			port_fwd_inject_gen_pkt(mbuf_arry[i]);
	}
	rte_pktmbuf_free_bulk(mbuf_arry, mp->size);
	free(mbuf_arry);
}

static int
init_mem(unsigned int nb_mbuf, uint16_t buf_size)
{
	char s[64];
	char s_tx[64];
	char s_2nd[64];
	char s_tx_2nd[64];
	char s_generic[64];
	char *penv;

	snprintf(s, sizeof(s), "port_fwd_mbuf_pool");
	snprintf(s_tx, sizeof(s_tx), "port_fwd_mbuf_tx_pool");
	snprintf(s_2nd, sizeof(s_2nd), "port_fwd_2nd_mbuf_pool");
	snprintf(s_tx_2nd, sizeof(s_tx_2nd), "port_fwd_2nd_mbuf_tx_pool");
	snprintf(s_generic, sizeof(s_generic), "port_fwd_generic_pool");

	if (s_proc_type == proc_attach_secondary) {
		pktmbuf_pool = rte_mempool_lookup(s_2nd);
		if (!pktmbuf_pool) {
			pktmbuf_pool = rte_mempool_lookup(s);
			if (!pktmbuf_pool) {
				rte_exit(EXIT_FAILURE, "Lookup mbuf pool(%s) failed\n",
					s);
			}
		}
		RTE_LOG(INFO, port_fwd,
			"mbuf pool(%s)(count=%d) lookup success\n",
			pktmbuf_pool->name, pktmbuf_pool->size);
	} else if (s_proc_type == proc_standalone_secondary) {
		pktmbuf_pool =
			rte_pktmbuf_pool_create_by_ops(s_2nd,
				nb_mbuf,
				MEMPOOL_CACHE_SIZE, 0,
				buf_size, 0,
				RTE_MBUF_DEFAULT_MEMPOOL_OPS);
		if (pktmbuf_pool) {
			RTE_LOG(INFO, port_fwd,
				"mbuf pool(%s)(count=%d) created\n",
				s_2nd, nb_mbuf);
		}
	} else {
		pktmbuf_pool =
			rte_pktmbuf_pool_create(s,
				nb_mbuf,
				MEMPOOL_CACHE_SIZE, 0,
				buf_size, 0);
		if (pktmbuf_pool) {
			RTE_LOG(INFO, port_fwd,
				"mbuf pool(%s)(count=%d) created\n",
				s, nb_mbuf);
		}

		penv = getenv("PRIMARY_FOR_SECONDARY_POOL_BUF_NB");
		if (penv && atoi(penv) > 0) {
			pktmbuf_pool_for_2nd =
				rte_pktmbuf_pool_create(s_2nd,
					atoi(penv),
					MEMPOOL_CACHE_SIZE, 0,
					buf_size, 0);
			if (pktmbuf_pool_for_2nd) {
				RTE_LOG(INFO, port_fwd,
					"mbuf pool(%s)(count=%d) created\n",
					s_2nd, atoi(penv));
			}
		}
	}

	penv = getenv("TX_FROM_DEFAULT_BUF_POOL");
	if (penv && atoi(penv) > 0) {
		default_pktmbuf_pool =
			rte_pktmbuf_pool_create_by_ops(s_generic,
				nb_mbuf,
				MEMPOOL_CACHE_SIZE, 0,
				buf_size, 0,
				RTE_MBUF_DEFAULT_MEMPOOL_OPS);
		if (default_pktmbuf_pool) {
			RTE_LOG(INFO, port_fwd,
				"default mbuf pool(%s)(count=%d) created\n",
				s_generic, nb_mbuf);
		}
	}
	if (!pktmbuf_pool)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool(%s)\n", s);

	port_fwd_mp_max_min_addr(pktmbuf_pool);
	if (default_pktmbuf_pool)
		port_fwd_mp_max_min_addr(default_pktmbuf_pool);

	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		RTE_LOG(INFO, port_fwd,
			"\n\nSignal %d received, preparing to exit...\n",
			signum);
		force_quit = true;
	}
}

static int
parse_dst_port(uint16_t portid)
{
	if (port_fwd_demo.parse_fwd_dst(portid))
		return 1;

	return 0;
}

#define PKTGEN_STATISTICS_INTERVAL 5

#define G_BITS_SIZE ((double)(1000 * 1000 * 1000))

#include <unistd.h>

static inline void
port_fwd_dump_port_status(struct rte_eth_stats *stats)
{
	RTE_LOG(INFO, port_fwd,
		"Input: %ld bytes, %ld packets, %ld missed, %ld error\n",
		(unsigned long)stats->ibytes,
		(unsigned long)stats->ipackets,
		(unsigned long)stats->imissed,
		(unsigned long)stats->ierrors);
	RTE_LOG(INFO, port_fwd,
		"Output: %ld bytes, %ld packets, %ld error\n",
		(unsigned long)stats->obytes,
		(unsigned long)stats->opackets,
		(unsigned long)stats->oerrors);
}

static void *perf_statistics(void *arg)
{
	cpu_set_t cpuset;
	unsigned int lcore_id, port_id;
	int port_num, ret;
	struct lcore_conf *qconf;
	struct lcore_statistic *rxs, *txs;
	uint64_t rx_pkts[RTE_MAX_ETHPORTS];
	uint64_t tx_pkts[RTE_MAX_ETHPORTS];
	uint64_t rx_bytes_fcs[RTE_MAX_ETHPORTS];
	uint64_t tx_bytes_fcs[RTE_MAX_ETHPORTS];
	uint64_t rx_bytes_oh[RTE_MAX_ETHPORTS];
	uint64_t tx_bytes_oh[RTE_MAX_ETHPORTS];
	uint64_t rx_bytes_oh_old[RTE_MAX_ETHPORTS];
	uint64_t tx_bytes_oh_old[RTE_MAX_ETHPORTS];

	memset(rx_bytes_oh_old, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(tx_bytes_oh_old, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));

	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(cpu_set_t), &cpuset);
	RTE_LOG(INFO, port_fwd,
		"affinity statistics thread to cpu 0 %s\r\n",
		ret ? "failed" : "success");

loop:
	if (force_quit)
		return arg;

	sleep(PKTGEN_STATISTICS_INTERVAL);
	memset(rx_pkts, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(tx_pkts, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(rx_bytes_fcs, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(tx_bytes_fcs, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(rx_bytes_oh, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));
	memset(tx_bytes_oh, 0, RTE_MAX_ETHPORTS * sizeof(uint64_t));

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &s_lcore_conf[lcore_id];
		port_num = enabled_port_num;
		for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
			rxs = &qconf->rx_statistic[port_id];
			txs = &qconf->tx_statistic[port_id];
			if (enabled_port_mask & (1 << port_id) &&
				port_num > 0) {
				rx_pkts[port_id] += rxs->packets;
				tx_pkts[port_id] += txs->packets;
				rx_bytes_fcs[port_id] += rxs->bytes_fcs;
				tx_bytes_fcs[port_id] += txs->bytes_fcs;
				rx_bytes_oh[port_id] +=	rxs->bytes_overhead;
				tx_bytes_oh[port_id] +=	txs->bytes_overhead;
				port_num--;
			}
		}
	}

	port_num = enabled_port_num;
	port_id = 0;
	while (port_num > 0) {
		if (enabled_port_mask & (1 << port_id)) {
			struct rte_eth_stats stats;
			int get_st_ret;

			RTE_LOG(INFO, port_fwd,
				"PORT%d:\r\n", port_id);
			get_st_ret = rte_eth_stats_get(port_id, &stats);
			if (get_st_ret)
				goto skip_print_hw_status;

			port_fwd_dump_port_status(&stats);

skip_print_hw_status:
			RTE_LOG(INFO, port_fwd,
				"TX: %lld pkts, %lld bits, %fGbps\r\n",
				(unsigned long long)tx_pkts[port_id],
				(unsigned long long)tx_bytes_fcs[port_id] * 8,
				(double)(tx_bytes_oh[port_id] -
				tx_bytes_oh_old[port_id]) * 8 /
				(PKTGEN_STATISTICS_INTERVAL * G_BITS_SIZE));
			RTE_LOG(INFO, port_fwd,
				"RX: %lld pkts, %lld bits, %fGbps\r\n\r\n",
				(unsigned long long)rx_pkts[port_id],
				(unsigned long long)rx_bytes_fcs[port_id] * 8,
				(double)(rx_bytes_oh[port_id] -
				rx_bytes_oh_old[port_id]) * 8 /
				(PKTGEN_STATISTICS_INTERVAL * G_BITS_SIZE));
			tx_bytes_oh_old[port_id] = tx_bytes_oh[port_id];
			rx_bytes_oh_old[port_id] = rx_bytes_oh[port_id];
			port_num--;
		}
		port_id++;
	}

	goto loop;

	return arg;
}

#define CHECK_INTERVAL 1 /* 1s */

static void *
port_fwd_check_link_stat(void *arg)
{
	uint16_t portid;
	struct rte_eth_link link[32], link_get;
	int ret;

	memset(link, 0, sizeof(link));

loop:
	if (force_quit)
		goto quit;

	RTE_ETH_FOREACH_DEV(portid) {
		if (force_quit)
			goto quit;
		if (!(enabled_port_mask & (1 << portid)))
			continue;
		ret = rte_eth_link_get_nowait(portid, &link_get);
		if (ret < 0) {
			RTE_LOG(WARNING, port_fwd,
				"Port %u link get failed: %s\n",
				portid, rte_strerror(-ret));
			continue;
		}
		if (memcmp(&link_get, &link[portid],
			sizeof(struct rte_eth_link))) {
			if (link_get.link_status) {
				RTE_LOG(INFO, port_fwd,
					"Port%d Link Up. Speed %u Mbps -%s\n",
					portid, link_get.link_speed,
					(link_get.link_duplex ==
					RTE_ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") :
					("half-duplex"));
			} else {
				RTE_LOG(WARNING, port_fwd,
					"Port %d Link Down\n", portid);
			}
		}
		rte_memcpy(&link[portid], &link_get,
			sizeof(struct rte_eth_link));
	}

	sleep(CHECK_INTERVAL);
	goto loop;

quit:

	return arg;
}

int
main(int argc, char **argv)
{
	struct lcore_conf *qconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	int ret;
	uint32_t nb_ports;
	uint16_t queueid, portid;
	uint32_t lcore_id;
	uint32_t nb_lcores;
	uint8_t queue;
	struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
	uint16_t nb_rx_queue[RTE_MAX_ETHPORTS];
	uint16_t nb_tx_queue[RTE_MAX_ETHPORTS];
	uint32_t socketid[RTE_MAX_ETHPORTS][MAX_LCORE_PARAMS];
	uint16_t rx_queues[RTE_MAX_ETHPORTS][MAX_LCORE_PARAMS];
	uint16_t tx_queues[RTE_MAX_ETHPORTS][MAX_LCORE_PARAMS];
	uint32_t total_tx_queues = 0, total_rx_queues = 0;
	uint32_t nb_mbuf;
	struct rte_eth_conf local_port_conf[RTE_MAX_ETHPORTS];
	uint16_t data_room_size = RTE_MBUF_DEFAULT_DATAROOM;
	char *penv;
	struct lcore_rx_queue *rx_queue;
	pthread_t pid;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Port fwd invalid parameters\n");

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		penv = getenv("PORT_FWD_SECONDARY_STANDALONE");
		if (penv)
			s_proc_type = proc_standalone_secondary;
		else
			s_proc_type = proc_attach_secondary;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = rte_pdump_init();
		if (ret) {
			rte_exit(EXIT_FAILURE, "Failed to init pdump(%d)\n",
				ret);
		}
	}

	penv = getenv("PORT_FWD_RING_FWD");
	if (penv)
		s_ring_fwd = 1;

	penv = getenv("PORT_FWD_DUMP_MBUF");
	if (penv)
		s_dump_mbuf = atoi(penv);

	penv = getenv("PORT_FWD_INJECTION_TEST");
	if (penv) {
		s_inject = atoi(penv);
		if (s_inject) {
			penv = getenv("PORT_FWD_INJECTION_PKT_SIZE");
			if (penv) {
				s_inject_pkt_size = atoi(penv);
				if (s_inject_pkt_size < 64 ||
					s_inject_pkt_size > 1518)
					s_inject_pkt_size = 64;
			}
		}
	}

	ret = init_lcore_rx_queues();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

	nb_ports = rte_eth_dev_count_avail();

	if (check_port_config() < 0)
		rte_exit(EXIT_FAILURE, "check_port_config failed\n");

	nb_lcores = rte_lcore_count();

	penv = getenv("PORT_FWD_DATA_ROOM_SIZE");
	if (penv) {
		data_room_size = atoi(penv);
		if (data_room_size < RTE_MBUF_DEFAULT_DATAROOM)
			data_room_size = RTE_MBUF_DEFAULT_DATAROOM;
		else
			data_room_size = RTE_ALIGN(data_room_size, 1024);
	}
	port_conf.rxmode.max_lro_pkt_size = data_room_size;

	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;

		nb_rx_queue[portid] = get_port_n_rx_queues(portid,
			rx_queues[portid]);
		nb_tx_queue[portid] = nb_rx_queue[portid];
		rte_memcpy(tx_queues[portid], rx_queues[portid],
			nb_tx_queue[portid] * sizeof(uint16_t));
		total_rx_queues += nb_rx_queue[portid];
		total_tx_queues += nb_tx_queue[portid];
	}

	nb_mbuf = total_rx_queues * nb_rxd + total_tx_queues * nb_txd;
	nb_mbuf = nb_ports * nb_mbuf;
	nb_mbuf += nb_ports * nb_lcores * MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE;
	nb_mbuf = nb_mbuf > 2048 ? nb_mbuf : 2048;
	s_data_room_size = data_room_size;
	ret = init_mem(nb_mbuf, data_room_size + RTE_PKTMBUF_HEADROOM);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"global mem pool(count=%d) init failed\n",
			nb_mbuf);

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &s_lcore_conf[lcore_id];
		/* init RX queues */
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			socketid[portid][queueid] =
				rte_lcore_to_socket_id(lcore_id);

			RTE_LOG(INFO, port_fwd,
				"rxq/txq=%d,%d,%d\r\n",
				portid, queueid, socketid[portid][queueid]);

			qconf->tx_queue_id[portid] = queueid;

			qconf->tx_port_id[qconf->n_tx_port] = portid;
			qconf->n_tx_port++;
		}
	}

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid) {
		char env_name[64];
		struct rte_eth_rxconf rxq_conf;
		uint16_t q_nb;

		memcpy(&local_port_conf[portid], &port_conf,
			sizeof(struct rte_eth_conf));
		sprintf(env_name, "PORT_FWD_PORT%d_LPBK", portid);
		penv = getenv(env_name);
		if (penv)
			local_port_conf[portid].lpbk_mode = atoi(penv);
		else
			local_port_conf[portid].lpbk_mode = 0;

		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			RTE_LOG(INFO, port_fwd,
				"\nSkipping disabled port %d\n", portid);
			continue;
		}
		enabled_port_num++;

		/* init port */
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));
		/* Enable Receive side SCATTER, if supported by NIC,
		 * when jumbo packet is enabled.
		 */
		if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER)
			local_port_conf[portid].rxmode.offloads |=
				RTE_ETH_RX_OFFLOAD_SCATTER;

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf[portid].txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		local_port_conf[portid].rx_adv_conf.rss_conf.rss_hf &=
			dev_info.flow_type_rss_offloads;

		ret = rte_eth_dev_configure(portid, nb_rx_queue[portid],
				nb_tx_queue[portid], &local_port_conf[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"Cannot configure device: err=%d, port=%d\n",
				ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
				&nb_txd);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Err(%d) adjust number of descriptors on port%d\n",
				ret, portid);
		}

		ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Err(%d) get MAC address of port%d\n",
				ret, portid);
		}
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));
		}
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_conf.rxmode.offloads;
		rxq_conf.reserved_64s[0] = min_mbuf_addr;
		rxq_conf.reserved_64s[1] = max_mbuf_addr;
		for (q_nb = 0; q_nb < nb_rx_queue[portid]; q_nb++) {
			ret = rte_eth_rx_queue_setup(portid,
				rx_queues[portid][q_nb],
				nb_rxd, socketid[portid][q_nb],
				&rxq_conf,
				pktmbuf_pool);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE,
					"port%d rxq%d setup failed(%d)\n",
					portid, rx_queues[portid][q_nb], ret);
			}
		}
		txconf = &dev_info.default_txconf;
		txconf->offloads =
				local_port_conf[portid].txmode.offloads;
		for (q_nb = 0; q_nb < nb_tx_queue[portid]; q_nb++) {
			ret = rte_eth_tx_queue_setup(portid,
				tx_queues[portid][q_nb], nb_txd,
					socketid[portid][q_nb],
					txconf);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE,
					"port%d rxq%d setup failed(%d)\n",
					portid, rx_queues[portid][q_nb], ret);
			}
		}
	}

	/* start ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start: err=%d, port=%d\n",
				ret, portid);

		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_promiscuous_enable: err=%s, port=%u\n",
				rte_strerror(-ret), portid);
	}

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &s_lcore_conf[lcore_id];
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			portid = qconf->rx_queue_list[queue].port_id;
			rx_queue = &qconf->rx_queue_list[queue];
			portid = rx_queue->port_id;
			if (s_ring_fwd) {
				init_lcore_rxq_ring(rx_queue);
			} else {
				if (parse_dst_port(portid)) {
					rte_exit(0, "port%d fwd error\n",
						portid);
				}
				if (parse_seg_rx_port(portid)) {
					rte_exit(0, "port%d seg rx error\n",
						portid);
				}
			}
		}
	}

	ret = pthread_create(&pid, NULL,
			port_fwd_check_link_stat, NULL);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"check link thread create failed(%d)\n", ret);
	}

	if (getenv("PORT_FWD_PERF_STATISTICS")) {
		ret = pthread_create(&pid, NULL, perf_statistics,
				NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"perf statistics thread create failed(%d)\n",
				ret);
		}
	}

	ret = rte_remote_direct_traffic(s_remote_dir);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"direct traffic failed!(%d)\n", ret);
	}

	/* launch per-lcore init on every lcore */
	ret = rte_eal_mp_remote_launch(port_fwd_demo.main_loop,
			NULL, CALL_MAIN);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"remote launch thread failed!(%d)\n", ret);
	}

	if (default_pktmbuf_pool) {
		uint32_t avail;

		avail = rte_mempool_avail_count(default_pktmbuf_pool);
		RTE_LOG(INFO, port_fwd,
			"default pool(%s) avail=%d, total=%d\n",
			default_pktmbuf_pool->name,
			avail, nb_mbuf);
		if (avail != nb_mbuf) {
			RTE_LOG(ERR, port_fwd,
				"Leak or(and) duplicated buf error!\n");
		}
	}

	/* stop ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if (!(enabled_port_mask & (1 << portid)))
			continue;
		RTE_LOG(INFO, port_fwd, "Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		RTE_LOG(INFO, port_fwd, " Done\n");
	}

	rte_eal_cleanup();
	RTE_LOG(INFO, port_fwd, "Bye...\n");

	return ret;
}
