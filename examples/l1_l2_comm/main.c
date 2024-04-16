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

#include <dev_driver.h>
#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include "l1_l2_comm.h"

#define RTE_LOGTYPE_L1_L2 RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_L1 RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_L2 RTE_LOGTYPE_USER1

/* ISC UPLINK: From air to core, DOWNLINK: From core to air*/

#define RTE_TEST_RX_DESC_DEFAULT 512
#define RTE_TEST_TX_DESC_DEFAULT 512

#define TIME_STAMP_OFFSET 64

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

enum l1_l2_proc_type {
	proc_primary = 0,
	proc_standalone_secondary = 1,
};
static uint8_t s_proc_type = proc_primary;

static uint8_t s_layer = 1;

static uint8_t s_core = 1;

static uint16_t s_port_id;

static char s_port_name[64];

static uint8_t s_l2_uplink_print;

static uint8_t s_l1_downlink_print;

enum up_down_handle {
	LINK_DISABLE = 0,
	UP_LINK_ENABLE = 1 << 0,
	DOWN_LINK_ENABLE = 1 << 1
};

static enum up_down_handle s_l1_l2_handle = \
	(UP_LINK_ENABLE | DOWN_LINK_ENABLE);

/* Global variables. */

static bool force_quit;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_IP,
		},
	},
};

static struct rte_mempool *l1_l2_mpool;

static struct data_loop_conf s_data_loop_conf;

static uint64_t s_l1_l2_cycs_per_us;

static int s_calculate_latency = 1;

static int s_l2_sync = 1;

#define L1_TB_SIZE 17500

#define L2_SDU_SIZE 1500

uint32_t s_l1_tb_size =  L1_TB_SIZE;
uint32_t s_l2_sdu_size =  L2_SDU_SIZE;

#define L1_L2_MAX_CHAIN_NB (s_l1_tb_size / s_l2_sdu_size + 1)

static void
l1_l2_calculate_cycles_per_us(void)
{
	uint64_t start_cycles, end_cycles;

	start_cycles = rte_get_timer_cycles();
	rte_delay_ms(1000);
	end_cycles = rte_get_timer_cycles();
	s_l1_l2_cycs_per_us = (end_cycles - start_cycles) / (1000 * 1000);
	RTE_LOG(INFO, L1_L2,
		"Cycles per us is: %ld\n", s_l1_l2_cycs_per_us);
}

static int
l2_app_downlink_data_prepare(struct rte_mbuf **mbufs, int count)
{
	int i;
	uint32_t remain_len = s_l1_tb_size, nb_segs;
	uint64_t *ptick;
	uint64_t tick = 0;

	if (s_calculate_latency)
		tick = rte_get_timer_cycles();
	if (remain_len % s_l2_sdu_size)
		nb_segs = remain_len / s_l2_sdu_size + 1;
	else
		nb_segs = remain_len / s_l2_sdu_size;

	for (i = 0; i < count; i++) {
		mbufs[i]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[i]->pkt_len = remain_len;
		mbufs[i]->nb_segs = nb_segs;
		if (s_calculate_latency) {
			ptick = rte_pktmbuf_mtod_offset(mbufs[i],
				uint64_t *, TIME_STAMP_OFFSET);
			*ptick = tick;
		}
		nb_segs--;
		if (nb_segs) {
			mbufs[i]->data_len = s_l2_sdu_size;
			if ((i + 1) >= count)
				return -ENOMEM;
			mbufs[i]->next = mbufs[i + 1];
		} else {
			mbufs[i]->data_len = remain_len;
			mbufs[i]->next = NULL;
			break;
		}
		remain_len -= s_l2_sdu_size;
	}

	return (i + 1);
}

static uint16_t
l2_app_downlink_data_ready(struct rte_mbuf *mbufs)
{
	return rte_eth_tx_burst(s_port_id, 0, &mbufs, 1);
}

static void
mbufs_free_prepare(struct rte_mbuf **mbufs, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		mbufs[i]->nb_segs = 1;
		mbufs[i]->next = NULL;
	}
}

static void
l2_app_downlink_prepare(void)
{
	struct rte_mbuf *mbufs[L1_L2_MAX_CHAIN_NB];
	int ret, chain_count;
	uint32_t tx_pkts, tx_bytes;

	ret = rte_pktmbuf_alloc_bulk(l1_l2_mpool,
		mbufs, L1_L2_MAX_CHAIN_NB);
	if (ret)
		return;

	chain_count = l2_app_downlink_data_prepare(mbufs,
		L1_L2_MAX_CHAIN_NB);
	if (unlikely(chain_count <= 0)) {
		mbufs_free_prepare(mbufs, L1_L2_MAX_CHAIN_NB);
		rte_pktmbuf_free_bulk(mbufs, L1_L2_MAX_CHAIN_NB);
		return;
	}
	if (chain_count < (int)L1_L2_MAX_CHAIN_NB) {
		mbufs_free_prepare(&mbufs[chain_count],
			L1_L2_MAX_CHAIN_NB - chain_count);
		rte_pktmbuf_free_bulk(&mbufs[chain_count],
			L1_L2_MAX_CHAIN_NB - chain_count);
	}

	tx_pkts = mbufs[0]->nb_segs;
	tx_bytes = mbufs[0]->pkt_len;
	ret = l2_app_downlink_data_ready(mbufs[0]);
	if (unlikely(ret != 1)) {
		mbufs_free_prepare(&mbufs[0], chain_count);
		rte_pktmbuf_free_bulk(&mbufs[0], chain_count);
	} else {
		s_data_loop_conf.tx_statistic.packets += tx_pkts;
		s_data_loop_conf.tx_statistic.bytes += tx_bytes;
	}
}

static uint16_t
l2_app_uplink_recv(struct rte_mbuf **mbufs,
	int wait)
{
	uint16_t ret;

recv_again:
	ret = rte_eth_rx_burst(s_port_id, 0, mbufs, 1);
	if (ret)
		return ret;

	if (wait)
		goto recv_again;

	return 0;
}

static void
l2_app_uplink_data_process(struct rte_mbuf *mbuf)
{
	struct rte_mbuf *next_mbuf = NULL;
	uint32_t seg_idx = 0, total_len = 0, pkt_len, nb_segs;
	uint64_t current_tick = rte_get_timer_cycles();
	uint64_t tick_send, *ptick, tick_diff = 0;
	double this_latency;

	pkt_len = mbuf->pkt_len;
	nb_segs = mbuf->nb_segs;
	if (s_l2_uplink_print) {
		RTE_LOG(INFO, L2,
			"l2_rx_from_l1 total len:%d, segs:%d\r\n",
			pkt_len, nb_segs);
	}
	while (1) {
		if (s_l2_uplink_print) {
			RTE_LOG(INFO, L2,
				"l2_rx_from_l1 len[%d]:%d\r\n",
				seg_idx, mbuf->data_len);
		}
		total_len += mbuf->data_len;
		if (s_calculate_latency) {
			ptick = rte_pktmbuf_mtod_offset(mbuf,
				uint64_t *, TIME_STAMP_OFFSET);
			tick_send = *ptick;
			tick_diff = (current_tick - tick_send);
			this_latency = ((double)tick_diff) /
				s_l1_l2_cycs_per_us;
			s_data_loop_conf.cyc_diff_total += tick_diff;
			s_data_loop_conf.valid_latency = 1;
			if (this_latency > s_data_loop_conf.max_latency)
				s_data_loop_conf.max_latency = this_latency;
			if (this_latency < s_data_loop_conf.min_latency)
				s_data_loop_conf.min_latency = this_latency;
		}
		if (mbuf->next) {
			next_mbuf = mbuf->next;
			mbuf->next = NULL;
			mbuf->nb_segs = 0;
			rte_pktmbuf_free(mbuf);
			mbuf = next_mbuf;
			seg_idx++;
		} else {
			mbuf->nb_segs = 0;
			rte_pktmbuf_free(mbuf);
			break;
		}
	}

	if (total_len != pkt_len) {
		RTE_LOG(ERR, L2,
			"TB len from L1 total_len(%d) != pkt_len(%d)\r\n",
			total_len, pkt_len);
	}

	if (nb_segs != (seg_idx + 1)) {
		RTE_LOG(ERR, L2,
			"TB chain number from L1 nb_segs(%d) != seg_idx++(%d)\r\n",
			nb_segs, seg_idx + 1);
	}

	s_data_loop_conf.rx_statistic.packets += nb_segs;
	s_data_loop_conf.rx_statistic.bytes += total_len;

	s_data_loop_conf.avg_latency =
		((double)s_data_loop_conf.cyc_diff_total) /
		(s_data_loop_conf.rx_statistic.packets) / s_l1_l2_cycs_per_us;
}

static void
l2_app_uplink_handle(void)
{
	struct rte_mbuf *mbufs = NULL;
	uint16_t recv_nb;
	int wait = 0;

	if (s_l2_sync && (s_l1_l2_handle & UP_LINK_ENABLE))
		wait = 1;

	/**Receive from L1*/
	recv_nb = l2_app_uplink_recv(&mbufs, wait);
	if (!recv_nb)
		return;

	/**Send to core*/
	l2_app_uplink_data_process(mbufs);
}

static void l2_app_handle(void)
{
	while (!force_quit) {
		if (s_l1_l2_handle & DOWN_LINK_ENABLE)
			l2_app_downlink_prepare(); /* Send to L1*/
		/** Always receive.*/
		l2_app_uplink_handle(); /* Recv from L1*/
	}
}

static uint16_t
l1_app_downlink_recv(struct rte_mbuf **mbufs)
{
	uint16_t ret;

	ret = rte_eth_rx_burst(s_port_id, 0, mbufs, 1);

	return ret;
}

static void
l1_app_downlink_data_process(struct rte_mbuf *mbuf)
{
	uint32_t pkt_len, data_len, nb_segs;

	pkt_len = mbuf->pkt_len;
	data_len = mbuf->data_len;
	nb_segs = mbuf->nb_segs;
	if (s_l1_downlink_print) {
		RTE_LOG(INFO, L1,
			"RX from L2 total len:%d(%d), segs:%d\r\n",
			pkt_len, data_len, nb_segs);
	}

	if (pkt_len != data_len) {
		RTE_LOG(ERR, L1,
			"TB is not continue pkt_len(%d) != data_len(%d)\r\n",
			pkt_len, data_len);
	}
	s_data_loop_conf.rx_statistic.packets++;
	s_data_loop_conf.rx_statistic.bytes += pkt_len;

	if (s_calculate_latency)
		rte_ring_enqueue(s_data_loop_conf.mbuf_ring, mbuf);
	else
		rte_pktmbuf_free(mbuf);
}

static void
l1_app_downlink_handle(void)
{
	struct rte_mbuf *mbufs = NULL;
	uint16_t recv_nb;

	/**Receive from L2*/
	recv_nb = l1_app_downlink_recv(&mbufs);
	if (!recv_nb)
		return;

	/** Send to air.*/
	l1_app_downlink_data_process(mbufs);
}

static int
l1_app_uplink_data_prepare(struct rte_mbuf *mbuf)
{
	mbuf->pkt_len = s_l1_tb_size;
	mbuf->data_len = s_l1_tb_size;
	mbuf->data_off = RTE_PKTMBUF_HEADROOM;
	mbuf->tso_segsz = s_l2_sdu_size;
	/**Process data*/

	return 0;
}

static uint16_t
l1_app_uplink_send(struct rte_mbuf *mbufs)
{
	return rte_eth_tx_burst(s_port_id, 0, &mbufs, 1);
}

static void
l1_app_uplink_process(void)
{
	struct rte_mbuf *mbuf = NULL;
	int ret;
	uint16_t sent;
	uint32_t tx_pkts, tx_bytes;

	if (s_calculate_latency) {
		ret = rte_ring_dequeue(s_data_loop_conf.mbuf_ring,
			(void **)&mbuf);
		if (ret)
			return;
	} else {
		mbuf = rte_pktmbuf_alloc(l1_l2_mpool);
	}
	if (!mbuf)
		return;

	if (mbuf->buf_len < (s_l1_tb_size + RTE_PKTMBUF_HEADROOM)) {
		RTE_LOG(ERR, L1,
			"Buf(len = %d) < TB(len = %d) + header room(%d)\r\n",
			mbuf->buf_len, s_l1_tb_size, RTE_PKTMBUF_HEADROOM);
		rte_pktmbuf_free(mbuf);
		return;
	}

	ret = l1_app_uplink_data_prepare(mbuf);
	if (ret) {
		rte_pktmbuf_free(mbuf);
		return;
	}

	tx_pkts = 1;
	tx_bytes = mbuf->pkt_len;
	sent = l1_app_uplink_send(mbuf);
	if (sent != 1) {
		rte_pktmbuf_free(mbuf);

		return;
	}

	s_data_loop_conf.tx_statistic.packets += tx_pkts;
	s_data_loop_conf.tx_statistic.bytes += tx_bytes;
}


static void l1_app_handle(void)
{
	while (!force_quit) {
		/* Recv from L2 then send to air.*/
		/** Always receive.*/
		l1_app_downlink_handle();
		if (s_l1_l2_handle & UP_LINK_ENABLE) {
			/* Recv from air then send to L2*/
			l1_app_uplink_process();
		}
	}
}

static int
main_loop(__attribute__((unused)) void *dummy)
{
	char nm[RTE_MEMZONE_NAMESIZE];

	l1_l2_calculate_cycles_per_us();
	if (s_calculate_latency && s_layer == 1) {
		sprintf(nm, "l1_mbuf_ring");
		s_data_loop_conf.mbuf_ring = rte_ring_create(nm,
				1024, -1, RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (!s_data_loop_conf.mbuf_ring) {
			fprintf(stderr, "creat %s failed\n", nm);

			return 0;
		}
	}
	s_data_loop_conf.max_latency = 0;
	s_data_loop_conf.min_latency = 0xffffffff;

	if (s_layer == 1)
		l1_app_handle();
	else if (s_layer == 2)
		l2_app_handle();

	if (s_data_loop_conf.mbuf_ring) {
		rte_ring_free(s_data_loop_conf.mbuf_ring);
		s_data_loop_conf.mbuf_ring = NULL;
	}

	return 0;
}

static int
parse_port_name(const char *sname)
{
	strcpy(s_port_name, sname);

	return 0;
}

static int
parse_link_disable(const char *link_name)
{
	if (!strcmp("up", link_name)) {
		s_l1_l2_handle &= ~UP_LINK_ENABLE;
	} else if (!strcmp("down", link_name)) {
		s_l1_l2_handle &= ~DOWN_LINK_ENABLE;
	} else if (!strcmp("bi", link_name)) {
		s_l1_l2_handle = LINK_DISABLE;
	} else {
		RTE_LOG(ERR, L1_L2,
			"link-disable supports up/down/bi\r\n");
		return -EINVAL;
	}

	return 0;
}

static int
parse_core(const char *score)
{
	int core = atoi(score);

	if (core > RTE_MAX_LCORE)
		return -EINVAL;

	s_core = core;

	return 0;
}

static int
parse_layer(const char *slayer)
{
	int layer = atoi(slayer);

	if (layer != 1 && layer != 2)
		return -EINVAL;

	s_layer = layer;
	return 0;
}

#define MEMPOOL_CACHE_SIZE 256

#define CMD_LINE_OPT_PNAME "port-nm"
#define CMD_LINE_OPT_CORE "core"
#define CMD_LINE_OPT_LAYER "layer"
#define CMD_LINE_OPT_LINK_DIS "link-disable"
#define CMD_LINE_OPT_L1_TB "tb-size"
#define CMD_LINE_OPT_L2_SDU "sdu-size"
#define CMD_LINE_OPT_LATENCY "latency-test"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_PNAME_NUM,
	CMD_LINE_OPT_CORE_NUM,
	CMD_LINE_OPT_LAYER_NUM,
	CMD_LINE_OPT_LINK_DIS_NUM,
	CMD_LINE_OPT_L1_TB_NUM,
	CMD_LINE_OPT_L2_SDU_NUM,
	CMD_LINE_OPT_LATENCY_NUM
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_PNAME, 1, 0, CMD_LINE_OPT_PNAME_NUM},
	{CMD_LINE_OPT_CORE, 1, 0, CMD_LINE_OPT_CORE_NUM},
	{CMD_LINE_OPT_LAYER, 1, 0, CMD_LINE_OPT_LAYER_NUM},
	{CMD_LINE_OPT_LINK_DIS, 1, 0, CMD_LINE_OPT_LINK_DIS_NUM},
	{CMD_LINE_OPT_L1_TB, 1, 0, CMD_LINE_OPT_L1_TB_NUM},
	{CMD_LINE_OPT_L2_SDU, 1, 0, CMD_LINE_OPT_L2_SDU_NUM},
	{CMD_LINE_OPT_LATENCY, 1, 0, CMD_LINE_OPT_LATENCY_NUM},
	{NULL, 0, 0, 0}
};

const char sopts[] = "h";

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, sopts,
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* long options */
		case CMD_LINE_OPT_PNAME_NUM:
			ret = parse_port_name(optarg);
			if (ret) {
				fprintf(stderr, "Invalid name\n");
				return ret;
			}
			break;

		case CMD_LINE_OPT_CORE_NUM:
			ret = parse_core(optarg);
			if (ret) {
				fprintf(stderr, "Invalid core\n");
				return ret;
			}
			break;

		case CMD_LINE_OPT_LAYER_NUM:
			ret = parse_layer(optarg);
			if (ret) {
				fprintf(stderr, "Invalid layer(%d)\n",
					atoi(optarg));
				return ret;
			}
			break;

		case CMD_LINE_OPT_LINK_DIS_NUM:
			ret = parse_link_disable(optarg);
			if (ret) {
				fprintf(stderr,
					"Invalid link disable\n");
				return ret;
			}
			break;
		case CMD_LINE_OPT_L1_TB_NUM:
			s_l1_tb_size = atoi(optarg);
			break;
		case CMD_LINE_OPT_L2_SDU_NUM:
			s_l2_sdu_size = atoi(optarg);
			break;
		case CMD_LINE_OPT_LATENCY_NUM:
			s_calculate_latency = atoi(optarg);
			break;
		default:
			return -ENOTSUP;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 1; /* reset getopt lib */
	return ret;
}

static int
init_l1_l2_mem(unsigned int nb_mbuf, uint32_t buf_size)
{
	char s[64];

	if (s_layer == 1)
		sprintf(s, "layer1_mpool");
	else if (s_layer == 2)
		sprintf(s, "layer2_mpool");
	else
		return -EINVAL;

	if (s_proc_type == proc_standalone_secondary) {
		l1_l2_mpool = rte_pktmbuf_pool_create_by_ops(s,
			nb_mbuf,
			MEMPOOL_CACHE_SIZE, 0,
			buf_size, 0,
			RTE_MBUF_DEFAULT_MEMPOOL_OPS);
	} else {
		l1_l2_mpool = rte_pktmbuf_pool_create(s,
			nb_mbuf,
			MEMPOOL_CACHE_SIZE, 0,
			buf_size, 0);
	}
	if (!l1_l2_mpool)
		rte_exit(EXIT_FAILURE, "Cannot init l1/l2 mpool(%s)\n", s);
	else
		RTE_LOG(INFO, L1_L2, "mpool(count=%d) created\n", nb_mbuf);

	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		RTE_LOG(INFO, L1_L2,
			"\n\nSignal %d received, preparing to exit...\n",
			signum);
		force_quit = true;
	}
}

#define PERF_STATISTICS_INTERVAL 5

#define G_BITS_SIZE ((double)(1000 * 1000 * 1000))

#include <unistd.h>

static void *perf_statistics(void *arg)
{
	cpu_set_t cpuset;
	int ret, off;
	struct perf_statistic *rxs, *txs;
	uint64_t rx_pkts = 0;
	uint64_t tx_pkts = 0;
	uint64_t rx_bytes = 0;
	uint64_t tx_bytes = 0;
	uint64_t rx_bytes_old = 0;
	uint64_t tx_bytes_old = 0;
	struct rte_eth_stats stats;
	uint8_t layer = *((uint8_t *)arg);
	char buf[4096];
	char new_line_space[strlen("L1: ")];

	memset(new_line_space, ' ', sizeof(new_line_space));
	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(cpu_set_t), &cpuset);
	printf("affinity statistics thread to cpu 0 %s\r\n",
		ret ? "failed" : "success");

loop:
	if (force_quit)
		return arg;

	sleep(PERF_STATISTICS_INTERVAL);

	rxs = &s_data_loop_conf.rx_statistic;
	txs = &s_data_loop_conf.tx_statistic;
	rx_pkts = rxs->packets;
	tx_pkts = txs->packets;
	rx_bytes = rxs->bytes;
	tx_bytes = txs->bytes;

	off = 0;
	ret = rte_eth_stats_get(s_port_id, &stats);
	if (ret)
		goto skip_print_hw_status;

	off = sprintf(buf,
		"Input: %ld bytes, %ld packets, %ld missed, %ld error\n",
		stats.ibytes, stats.ipackets, stats.imissed, stats.ierrors);

	off += sprintf(&buf[off],
		"%sOutput: %ld bytes, %ld packets, %ld error\n",
		new_line_space, stats.obytes, stats.opackets, stats.oerrors);

	off += sprintf(&buf[off], "%s", new_line_space);

skip_print_hw_status:
	off += sprintf(&buf[off],
		"TX: %ld pkts, %ld bits, %fGbps\r\n",
		tx_pkts, tx_bytes * 8,
		(double)(tx_bytes - tx_bytes_old) * 8 /
		(PERF_STATISTICS_INTERVAL * G_BITS_SIZE));

	off += sprintf(&buf[off],
		"%sRX: %ld pkts, %ld bits, %fGbps\r\n",
		new_line_space, rx_pkts, rx_bytes * 8,
		(double)(rx_bytes - rx_bytes_old) * 8 /
		(PERF_STATISTICS_INTERVAL * G_BITS_SIZE));

	if (s_data_loop_conf.valid_latency) {
		sprintf(&buf[off],
			"%sLatency avg=%f us, max=%f us, min=%f us\r\n\r\n",
			new_line_space, s_data_loop_conf.avg_latency,
			s_data_loop_conf.max_latency,
			s_data_loop_conf.min_latency);
	} else {
		sprintf(&buf[off], "\r\n");
	}
	if (layer == 1)
		RTE_LOG(INFO, L1, "%s", buf);
	else
		RTE_LOG(INFO, L2, "%s", buf);
	tx_bytes_old = tx_bytes;
	rx_bytes_old = rx_bytes;

	goto loop;

	return arg;
}

int
main(int argc, char **argv)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	int ret, port_found = 0;
	uint16_t portid;
	uint32_t nb_buf;
	struct rte_eth_conf local_port_conf;
	struct rte_eth_rxconf rxq_conf;
	uint32_t data_room_size;
	struct rte_eth_link link;

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
		rte_exit(EXIT_FAILURE, "l1_l2_comm invalid parameters\n");

	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
		s_proc_type = proc_standalone_secondary;

	port_conf.rxmode.max_lro_pkt_size = RTE_MBUF_DEFAULT_DATAROOM;

	if (s_layer == 1) {
		nb_buf = (nb_txd + nb_rxd) * 2;
		data_room_size = (s_l1_tb_size + RTE_PKTMBUF_HEADROOM +
			MEMPOOL_CACHE_SIZE) /
			MEMPOOL_CACHE_SIZE * MEMPOOL_CACHE_SIZE;
	} else {
		nb_buf = (nb_txd + nb_rxd) * 2 * 32;
		data_room_size = (s_l2_sdu_size + RTE_PKTMBUF_HEADROOM);
	}

	if (data_room_size < RTE_MBUF_DEFAULT_DATAROOM)
		data_room_size = RTE_MBUF_DEFAULT_DATAROOM;
	else
		data_room_size = RTE_ALIGN(data_room_size, 1024);

	ret = init_l1_l2_mem(nb_buf, data_room_size);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"l1/l2 mem pool(count = %d) init failed\n",
			nb_buf);
	}

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid) {
		/* init port */
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret) {
			fprintf(stderr, "Failed to get info of port%d\n",
				portid);
			continue;
		}
		if (strcmp(s_port_name, dev_info.device->name))
			continue;
		memset(&local_port_conf, 0, sizeof(struct rte_eth_conf));

		/* Enable Receive side SCATTER, if supported by NIC,
		 * when jumbo packet is enabled.
		 */
		if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) {
			local_port_conf.rxmode.offloads |=
				RTE_ETH_RX_OFFLOAD_SCATTER;
		}

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		}

		local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
			dev_info.flow_type_rss_offloads;

		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Cannot configure device: err=%d, port=%d\n",
				ret, portid);
		}

		if (!rte_lcore_is_enabled(s_core)) {
			rte_exit(EXIT_FAILURE,
				"Core %d is not enabled\n",
				s_core);
		}

		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, 0, &rxq_conf,
			l1_l2_mpool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"port%d rxq%d setup failed(%d)\n",
				portid, 0, ret);
		}
		txconf = &dev_info.default_txconf;
		txconf->offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd, 0, txconf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"port%d txq%d setup failed(%d)\n",
				portid, 0, ret);
		}

		ret = rte_eth_dev_start(portid);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start: err=%d, port=%d\n",
				ret, portid);
		}

		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE,
				"rte_eth_promiscuous_enable: err=%s, port=%u\n",
				rte_strerror(-ret), portid);
		}

		ret = rte_eth_link_get_nowait(portid, &link);
		if (ret < 0) {
			RTE_LOG(ERR, L1_L2,
				"Port %u link get failed: %s\n",
				portid, rte_strerror(-ret));
		} else {
			if (link.link_status) {
				RTE_LOG(INFO, L1_L2,
					"Port%d Link Up. Speed %u Mbps -%s\n",
					portid, link.link_speed,
					(link.link_duplex ==
					RTE_ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex"));
			} else {
				RTE_LOG(INFO, L1_L2,
					"Port %d Link Down\n", portid);
			}
		}
		port_found = 1;
		break;
	}

	if (!port_found) {
		RTE_LOG(ERR, L1_L2, "port %s NOT found\n", s_port_name);
		RTE_LOG(ERR, L1_L2, "Bye...\n");
		return 0;
	}

	s_port_id = portid;
	ret = 0;

	if (getenv("L1_L2_PERF_STATISTICS")) {
		pthread_t pid;

		pthread_create(&pid, NULL, perf_statistics, &s_layer);
	}

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);

	RTE_LOG(INFO, L1_L2, "Closing port %d...", portid);
	rte_eth_dev_stop(portid);
	rte_eth_dev_close(portid);
	RTE_LOG(INFO, L1_L2, " Done\n");

	RTE_LOG(INFO, L1_L2, "Bye...\n");

	return ret;
}
