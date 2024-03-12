/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 * Copyright 2018-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
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
#include <rte_pmd_dpaax_qdma.h>
#include <rte_dmadev.h>

#define RTE_LOGTYPE_l2fwd_qdma RTE_LOGTYPE_USER1

static volatile bool force_quit;

struct l2fwd_dma_job {
	/** Source Address from where DMA is (to be) performed */
	uint64_t src;
	/** Destination Address where DMA is (to be) done */
	uint64_t dest;
	/** Length of the DMA operation in bytes. */
	uint32_t len;
	uint32_t idx;
	/** Flags corresponding to an DMA operation */
	uint32_t flags;
	uint32_t port_id;
	struct rte_mbuf *in_mbuf;
	struct rte_mbuf *out_mbuf;
};

#define MAX_JOBS_PER_RING 1024

static int qdma_dev_id;
static int g_vqid[RTE_MAX_LCORE];
static struct l2fwd_dma_job *g_l2fwd_dma_jobs[RTE_MAX_LCORE];
static struct rte_ring *g_l2fwd_dma_job_ring[RTE_MAX_LCORE];
static uint16_t *g_l2fwd_dma_idx[RTE_MAX_LCORE];
static int L2FWD_QDMA_DMA_INIT_FLAG;

/* MAC updating enabled by default */
static int mac_updating = 1;

#define NB_MBUF   8192

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t port_mask;

/* list of enabled ports */
static uint32_t dst_ports[RTE_MAX_ETHPORTS];

static unsigned int rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned int n_rx_port;
	unsigned int rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf s_lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *s_pktmbuf_pool;
struct rte_mempool *s_pktmbuf_qdma_pool;

/* Per-port statistics struct */
struct port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct port_statistics s_port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */

/* Determines H/W or virtual mode */
static uint8_t qdma_sg;

static int s_flags_cntx;

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned int portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   s_port_statistics[portid].tx,
			   s_port_statistics[portid].rx,
			   s_port_statistics[portid].dropped);

		total_packets_dropped += s_port_statistics[portid].dropped;
		total_packets_tx += s_port_statistics[portid].tx;
		total_packets_rx += s_port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
}

static void
l2fwd_qdma_mac_updating(struct rte_mbuf *m, unsigned int dest_portid)
{
	struct rte_ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->dst_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	rte_ether_addr_copy(&ports_eth_addr[dest_portid], &eth->src_addr);
}

static void
l2fwd_qdma_forward(uint16_t vq_id, int nb_jobs)
{
	struct rte_mbuf *out_mbuf[nb_jobs];
	struct rte_mbuf *mbuf;
	uint32_t dst_port = 0;
	int to_sent = 0, sent, num_rx, i;
	uint16_t dq_idx[nb_jobs];

	num_rx = rte_dma_completed(qdma_dev_id,
			g_vqid[vq_id], nb_jobs, dq_idx,
			NULL);

	for (i = 0; i < num_rx; i++) {
		mbuf = g_l2fwd_dma_jobs[vq_id][dq_idx[i]].out_mbuf;
		out_mbuf[to_sent++] = mbuf;
		rte_pktmbuf_free(g_l2fwd_dma_jobs[vq_id][dq_idx[i]].in_mbuf);

		dst_port = g_l2fwd_dma_jobs[vq_id][dq_idx[i]].port_id;
		if (mac_updating)
			l2fwd_qdma_mac_updating(mbuf, dst_port);

		rte_ring_enqueue(g_l2fwd_dma_job_ring[vq_id],
			&g_l2fwd_dma_jobs[vq_id][dq_idx[i]]);
	}
	if (!to_sent)
		return;

	sent = rte_eth_tx_burst(dst_port, 0, out_mbuf, to_sent);
	if (sent)
		s_port_statistics[dst_port].tx += sent;
}

static void
l2fwd_qdma_copy(struct rte_mbuf **m, unsigned int portid,
		uint16_t vq_id, uint8_t nb_jobs)
{
	struct rte_mbuf *m_new[nb_jobs];
	uint64_t m_data, m_new_data, flags;
	struct l2fwd_dma_job *qdma_job[nb_jobs];
	struct rte_dma_sge src_sge[nb_jobs];
	struct rte_dma_sge dst_sge[nb_jobs];
	int i, ret = 0;
	uint32_t q_ret;

	ret = rte_pktmbuf_alloc_bulk(s_pktmbuf_qdma_pool,
		m_new, nb_jobs);
	if (ret) {
		rte_pktmbuf_free_bulk(m, nb_jobs);
		return;
	}
	q_ret = rte_ring_dequeue_bulk(g_l2fwd_dma_job_ring[vq_id],
			(void **)qdma_job, nb_jobs, NULL);
	if (q_ret < nb_jobs) {
		rte_pktmbuf_free_bulk(&m[q_ret], nb_jobs - q_ret);
		rte_pktmbuf_free_bulk(&m_new[q_ret], nb_jobs - q_ret);
		nb_jobs = q_ret;
		if (!q_ret)
			return;
	}

	for (i = 0; i < nb_jobs; i++) {
		m_new[i]->nb_segs = m[i]->nb_segs;
		m_new[i]->ol_flags = m[i]->ol_flags;
		m_new[i]->data_off = m[i]->data_off;
		m_new[i]->data_len = m[i]->data_len;
		m_new[i]->pkt_len = m[i]->pkt_len;
		m_new[i]->next = m[i]->next;
		rte_mbuf_refcnt_set(m_new[i], 1);

		m_data = rte_pktmbuf_iova(m[i]);
		m_new_data = rte_pktmbuf_iova(m_new[i]);

		qdma_job[i]->src = m_data;
		qdma_job[i]->dest = m_new_data;
		g_l2fwd_dma_idx[vq_id][i] = qdma_job[i]->idx;
		qdma_job[i]->len = m[i]->data_len;
		qdma_job[i]->port_id = portid;
		qdma_job[i]->in_mbuf = m[i];
		qdma_job[i]->out_mbuf = m_new[i];
		flags = qdma_job[i]->flags;
		if (i == (nb_jobs - 1) && s_flags_cntx)
			flags |= RTE_DPAAX_QDMA_COPY_SUBMIT(qdma_job[i]->idx,
				RTE_DMA_OP_FLAG_SUBMIT);
		else if (s_flags_cntx)
			flags |= RTE_DPAAX_QDMA_COPY_SUBMIT(qdma_job[i]->idx,
				0);
		else if (i == (nb_jobs - 1))
			flags |= RTE_DMA_OP_FLAG_SUBMIT;

		if (qdma_sg) {
			src_sge[i].addr = qdma_job[i]->src;
			src_sge[i].length = qdma_job[i]->len;

			dst_sge[i].addr = qdma_job[i]->dest;
			dst_sge[i].length = qdma_job[i]->len;
			continue;
		}

		ret = rte_dma_copy(qdma_dev_id,
				g_vqid[vq_id],
				qdma_job[i]->src, qdma_job[i]->dest,
				qdma_job[i]->len, flags);
		if (ret < 0)
			break;
	}

	if (qdma_sg) {
		if (s_flags_cntx)
			flags = RTE_DPAAX_QDMA_SG_SUBMIT(g_l2fwd_dma_idx[vq_id],
				RTE_DMA_OP_FLAG_SUBMIT);
		else
			flags = RTE_DMA_OP_FLAG_SUBMIT;
		ret = rte_dma_copy_sg(qdma_dev_id,
				g_vqid[vq_id], src_sge, dst_sge,
				nb_jobs, nb_jobs,
				flags);
	}

	if (ret < 0) {
		rte_pktmbuf_free_bulk(m, nb_jobs);
		rte_pktmbuf_free_bulk(m_new, nb_jobs);
		q_ret = rte_ring_enqueue_bulk(g_l2fwd_dma_job_ring[vq_id],
			(void * const *)qdma_job, nb_jobs, NULL);
		if (q_ret != nb_jobs) {
			rte_exit(EXIT_FAILURE,
				"recycle %d jobs to ring[%d] failed\n",
				nb_jobs, vq_id);
		}
		return;
	}
}

/* main processing loop */
static void
l2fwd_qdma_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	int sent;
	unsigned int lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned int i, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc =
			(rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;
	int vq_id;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &s_lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, l2fwd_qdma, "lcore %u has nothing to do\n",
			lcore_id);
		return;
	}

	RTE_LOG(INFO, l2fwd_qdma, "entering main loop on lcore %u\n",
		lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, l2fwd_qdma, " -- lcoreid=%u portid=%u\n",
			lcore_id, portid);

	}

	vq_id = lcore_id;

	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_rx_port; i++) {

				portid = dst_ports[qconf->rx_port_list[i]];
				buffer = tx_buffer[portid];

				sent = rte_eth_tx_buffer_flush(portid,
								0, buffer);
				if (sent)
					s_port_statistics[portid].tx += sent;

			}

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on main core */
					if (lcore_id == rte_get_main_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {
			l2fwd_qdma_forward(vq_id, MAX_PKT_BURST);
			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(portid, 0,
						 pkts_burst, MAX_PKT_BURST);

			s_port_statistics[portid].rx += nb_rx;
			if (nb_rx)
				l2fwd_qdma_copy(pkts_burst,
						portid, vq_id, nb_rx);
		}
	}
}

static int
l2fwd_qdma_launch_one_lcore(__attribute__((unused))void *dummy)
{
	l2fwd_qdma_main_loop();
	return 0;
}

/* display usage */
static void
l2fwd_qdma_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ] [-s qdma_sg]\n"
	"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	"  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
	"  -T PERIOD: statistics will be refreshed each PERIOD seconds"
	" (0 to disable, 10 default, 86400 maximum)\n"
	"  --[no-]mac-updating: Enable or disable MAC addresses updating"
	"(enabled by default)\n"
	"   When enabled:\n"
	"     - The source MAC address is replaced by the TX port MAC address\n"
	"     - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n"
	"  -s scatter gather: 0 to disable(default) and 1 for enable\n",
	prgname);
}

static int
l2fwd_qdma_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static unsigned int
l2fwd_qdma_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_qdma_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static int
l2fwd_qdma_parse_mode(const char *mode)
{
	char *end = NULL;
	int m;

	/* parse hexadecimal string */
	m = strtoul(mode, &end, 16);
	if ((mode[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	return m;
}

static const char short_options[] =
	"p:"  /* portmask */
	"q:"  /* number of queues */
	"T:"  /* timer period */
	"s:"  /* scatter gather */
	;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
};

static const struct option lgopts[] = {
	{ CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_qdma_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs, sg;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			port_mask = l2fwd_qdma_parse_portmask(optarg);
			if (!port_mask) {
				RTE_LOG(ERR, l2fwd_qdma,
					"invalid portmask\n");
				l2fwd_qdma_usage(prgname);
				return -EINVAL;
			}
			break;

		/* nqueue */
		case 'q':
			rx_queue_per_lcore = l2fwd_qdma_parse_nqueue(optarg);
			if (!rx_queue_per_lcore) {
				RTE_LOG(ERR, l2fwd_qdma,
					"invalid queue number\n");
				l2fwd_qdma_usage(prgname);
				return -EINVAL;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_qdma_parse_timer_period(optarg);
			if (timer_secs < 0) {
				RTE_LOG(ERR, l2fwd_qdma,
					"invalid timer period\n");
				l2fwd_qdma_usage(prgname);
				return -EINVAL;
			}
			timer_period = timer_secs;
			break;

		/* scatter gather */
		case 's':
			sg = l2fwd_qdma_parse_mode(optarg);
			if (sg < 0) {
				RTE_LOG(ERR, l2fwd_qdma,
					"invalid mode\n");
				l2fwd_qdma_usage(prgname);
				return -EINVAL;
			}
			qdma_sg = sg;
			break;
		/* long options */
		case 0:
			break;

		default:
			l2fwd_qdma_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	RTE_LOG(INFO, l2fwd_qdma, "Checking link status\n");
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status &&
					link.link_duplex ==
					RTE_ETH_LINK_FULL_DUPLEX) {
					RTE_LOG(INFO, l2fwd_qdma,
						"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
						"full-duplex");
				} else if (link.link_status &&
					link.link_duplex ==
					RTE_ETH_LINK_HALF_DUPLEX) {
					RTE_LOG(INFO, l2fwd_qdma,
						"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
						"half-duplex");
				} else {
					RTE_LOG(INFO, l2fwd_qdma,
						"Port %d Link Down\n",
						portid);
				}
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static int
l2fwd_qdma_dma_init(void)
{
	struct rte_dma_conf dma_config;
	struct rte_dma_info dma_info;
	int ret, i = 0, max_avail = rte_dma_count_avail();

	if (L2FWD_QDMA_DMA_INIT_FLAG)
		return 0;

init_dma:
	if (i >= max_avail)
		return -EBUSY;
	qdma_dev_id = i;

	ret = rte_dma_info_get(qdma_dev_id, &dma_info);
	if (ret) {
		RTE_LOG(ERR, l2fwd_qdma, "Failed to get DMA[%d] info(%d)\n",
			qdma_dev_id, ret);
		return ret;
	}
	if (dma_info.dev_capa & RTE_DMA_CAPA_DPAAX_QDMA_FLAGS_INDEX)
		s_flags_cntx = 1;
	dma_config.nb_vchans = dma_info.max_vchans;
	dma_config.enable_silent = 0;

	ret = rte_dma_configure(qdma_dev_id, &dma_config);
	if (ret) {
		RTE_LOG(WARNING, l2fwd_qdma,
			"Failed to configure DMA[%d](%d)\n",
			qdma_dev_id, ret);
		goto init_dma;
	}

	L2FWD_QDMA_DMA_INIT_FLAG = 1;

	return 0;
}

static int
l2fwd_qdma_job_ring_init(uint32_t lcore_id)
{
	uint32_t i;
	char nm[RTE_MEMZONE_NAMESIZE];
	struct l2fwd_dma_job *job;
	int ret = 0;

	sprintf(nm, "job-ring-%d", lcore_id);
	g_l2fwd_dma_job_ring[lcore_id] = rte_ring_create(nm,
			MAX_JOBS_PER_RING * 2, 0, 0);
	if (!g_l2fwd_dma_job_ring[lcore_id]) {
		RTE_LOG(ERR, l2fwd_qdma,
			"job ring created failed on core%d\n",
			lcore_id);
		ret = -ENOMEM;
		goto err_free;
	}
	g_l2fwd_dma_jobs[lcore_id] = rte_zmalloc(NULL,
		MAX_JOBS_PER_RING * sizeof(struct l2fwd_dma_job),
		4096);
	if (!g_l2fwd_dma_jobs[lcore_id]) {
		RTE_LOG(ERR, l2fwd_qdma,
			"jobs created failed on core%d\n",
			lcore_id);
		ret = -ENOMEM;
		goto err_free;
	}

	if (s_flags_cntx) {
		g_l2fwd_dma_idx[lcore_id] = rte_zmalloc(NULL,
			MAX_JOBS_PER_RING * sizeof(uint16_t),
			RTE_DPAAX_QDMA_SG_IDX_ADDR_ALIGN);
		if (!g_l2fwd_dma_idx[lcore_id]) {
			RTE_LOG(ERR, l2fwd_qdma,
				"dma index created failed on core%d\n",
				lcore_id);
			ret = -ENOMEM;
			goto err_free;
		}
	}

	job = g_l2fwd_dma_jobs[lcore_id];
	for (i = 0; i < MAX_JOBS_PER_RING; i++) {
		job->idx = i;
		ret = rte_ring_enqueue(g_l2fwd_dma_job_ring[lcore_id], job);
		if (ret) {
			RTE_LOG(ERR, l2fwd_qdma,
				"eq job[%d] failed on core%d, err(%d)\n",
				i, lcore_id, ret);
			goto err_free;
		}
		job++;
	}

	return 0;

err_free:
	if (g_l2fwd_dma_job_ring[lcore_id]) {
		rte_ring_free(g_l2fwd_dma_job_ring[lcore_id]);
		g_l2fwd_dma_job_ring[lcore_id] = NULL;
	}
	if (g_l2fwd_dma_jobs[lcore_id]) {
		rte_free(g_l2fwd_dma_jobs[lcore_id]);
		g_l2fwd_dma_jobs[lcore_id] = NULL;
	}
	if (g_l2fwd_dma_idx[lcore_id]) {
		rte_free(g_l2fwd_dma_idx[lcore_id]);
		g_l2fwd_dma_idx[lcore_id] = NULL;
	}

	return ret;
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int ret, i;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid, last_port;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;
	struct rte_dma_vchan_conf conf;
	struct rte_dma_info info;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_qdma_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid l2fwd qdma arguments\n");

	RTE_LOG(INFO, l2fwd_qdma,
		"MAC updating %s\n", mac_updating ? "enabled" : "disabled");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	/* create the mbuf pool */
	s_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (!s_pktmbuf_pool)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* create the QDMA mbuf pool */
	s_pktmbuf_qdma_pool = rte_pktmbuf_pool_create("qdma_mbuf_pool",
		NB_MBUF + MEMPOOL_CACHE_SIZE, MEMPOOL_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (!s_pktmbuf_qdma_pool)
		rte_exit(EXIT_FAILURE, "Cannot init qdma mbuf pool\n");

	nb_ports = rte_eth_dev_count_avail();
	if (!nb_ports)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* check port mask to possible port mask */
	if (port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);

	/* reset l2fwd qdma dst ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		dst_ports[portid] = 0;
	last_port = 0;

	/*
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((port_mask & (1 << portid)) == 0)
			continue;

		if (nb_ports_in_mask % 2) {
			dst_ports[portid] = last_port;
			dst_ports[last_port] = portid;
		} else
			last_port = portid;

		nb_ports_in_mask++;
	}
	if (nb_ports_in_mask % 2) {
		RTE_LOG(INFO, l2fwd_qdma,
			"Notice: odd number of ports in portmask.\n");
		dst_ports[last_port] = last_port;
	}

	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((port_mask & (1 << portid)) == 0)
			continue;

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       s_lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &s_lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &s_lcore_queue_conf[rx_lcore_id];
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		RTE_LOG(INFO, l2fwd_qdma,
			"Lcore %u: RX port %u\n", rx_lcore_id, portid);
	}

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((port_mask & (1 << portid)) == 0) {
			RTE_LOG(INFO, l2fwd_qdma,
				"Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		RTE_LOG(INFO, l2fwd_qdma, "Initializing port %u...\n",
			portid);
		rte_eth_dev_info_get(portid, &dev_info);
		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Port%d configure failed(%d)\n",
				 portid, ret);
		}

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
				&nb_txd);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Port%d adjust descriptor number failed(%d)\n",
				portid, ret);
		}

		ret = rte_eth_macaddr_get(portid,
			&ports_eth_addr[portid]);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Port%d get max address failed(%d)\n",
				portid, ret);
		}

		/* init one RX queue */
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
				rte_eth_dev_socket_id(portid),
				&rxq_conf,
				s_pktmbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Port%d rxq setup failed(%d)\n",
				portid, ret);
		}

		/* init one TX queue on each port */
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Port%d txq setup failed(%d)\n",
				portid, ret);
		}

		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket(NULL,
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (!tx_buffer[portid]) {
			rte_exit(EXIT_FAILURE,
				"Port%d TX buffer alloc failed\n",
				portid);
		}

		ret = rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Port%d TX buffer init failed(%d)\n",
				portid, ret);
		}

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&s_port_statistics[portid].dropped);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Port%d set TX error callback failed(%d)\n",
				portid, ret);
		}

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Port%d start failed(%d)\n",
				portid, ret);
		}

		ret = rte_eth_promiscuous_enable(portid);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Port%d promiscuous set failed(%d)\n",
				portid, ret);
		}

		RTE_LOG(INFO, l2fwd_qdma,
			"Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			portid,
			ports_eth_addr[portid].addr_bytes[0],
			ports_eth_addr[portid].addr_bytes[1],
			ports_eth_addr[portid].addr_bytes[2],
			ports_eth_addr[portid].addr_bytes[3],
			ports_eth_addr[portid].addr_bytes[4],
			ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&s_port_statistics, 0, sizeof(s_port_statistics));
	}

	if (!nb_ports_available)
		rte_exit(EXIT_FAILURE, "No port is selected\n");

	check_all_ports_link_status(port_mask);

	l2fwd_qdma_dma_init();

	/* setup QDMA queues */
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (!rte_lcore_is_enabled(i))
			continue;

		ret = rte_dma_info_get(qdma_dev_id, &info);
		if (ret)
			return ret;

		conf.direction = RTE_DMA_DIR_MEM_TO_MEM;
		conf.nb_desc = info.max_desc;
		conf.src_port.port_type = RTE_DMA_PORT_NONE;
		conf.dst_port.port_type = RTE_DMA_PORT_NONE;
		g_vqid[i] = i;
		ret = rte_dma_vchan_setup(qdma_dev_id, g_vqid[i], &conf);
		if (ret) {
			RTE_LOG(ERR, l2fwd_qdma,
				"vchan[%d] setup failed(%d)\n", i, ret);
			return ret;
		}
		ret = l2fwd_qdma_job_ring_init(i);
		if (ret) {
			RTE_LOG(ERR, l2fwd_qdma,
				"Failed to init job ring[%d](%d)\n",
				i, ret);
			return ret;
		}
	}

	ret = rte_dma_start(qdma_dev_id);
	if (ret) {
		RTE_LOG(ERR, l2fwd_qdma, "Failed to start DMA(%d)\n",
			ret);
		return ret;
	}

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_qdma_launch_one_lcore,
		NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if ((port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	RTE_LOG(INFO, l2fwd_qdma, "Bye...\n");

	return ret;
}
