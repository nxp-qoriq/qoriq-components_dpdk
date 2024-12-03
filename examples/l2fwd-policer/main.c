/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
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
#include <rte_string_fns.h>
#include <rte_pmd_dpaa2.h>

#define POLICER_RFC_NUM           2698
#define SHIFT_RESERVED_PRIORITY    16

/* Set to select color aware mode (otherwise - color blind) */
#define POLICER_OPT_COLOR_AWARE 0x00000001
/* Set to discard frame with RED color */
#define POLICER_OPT_DISCARD_RED 0x00000002

/* policer units */
#define POLICER_UNIT_BYTES  0
#define POLICER_UNIT_FRAMES 1

/* policer color */
#define POLICER_COLOR_GREEN  0
#define POLICER_COLOR_YELLOW 1
#define POLICER_COLOR_RED    2

#define MAX_NUM_OF_VLAN_PRIORITY 8
#define MAX_VLAN_ID 4095
#define VLAN_PRIO_0 0
#define VLAN_PRIO_1 0x2000
#define VLAN_PRIO_2 0x4000
#define VLAN_PRIO_3 0x6000
#define VLAN_PRIO_4 0x8000
#define VLAN_PRIO_5 0xA000
#define VLAN_PRIO_6 0xC000
#define VLAN_PRIO_7 0xE000

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

static volatile bool force_quit;

/* MAC updating enabled by default */
static int mac_updating = 1;

/* Ports set in promiscuous mode off by default. */
static int promiscuous_on;

/* Flow classification enabled by default */
uint8_t enable_flow = 1;

/* port and vlan id pair configuration */
struct port_vlan_pair_params {
	uint16_t port_id;
	uint16_t vlan_id;
	uint16_t vlan_prio;
}__rte_cache_aligned;

static struct port_vlan_pair_params port_vlan_pair_params_array[RTE_MAX_ETHPORTS];
static struct port_vlan_pair_params *port_vlan_pair_params;
static uint16_t nb_port_vlan_pair_params;

/* policer default configuration */
int policer_unit = POLICER_UNIT_BYTES;
int default_color = POLICER_COLOR_RED;
uint32_t policer_option = POLICER_OPT_DISCARD_RED;
uint32_t cir;
uint32_t cbs;
uint32_t pir;
uint32_t pbs;

void *sch_handle;

static int max_burst_size = MAX_PKT_BURST;
/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_policer_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_policer_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_policer_dst_ports[RTE_MAX_ETHPORTS];

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
/* List of queues to be polled for a given lcore. 8< */
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
/* >8 End of list of queues to be polled for a given lcore. */

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * l2fwd_policer_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct l2fwd_policer_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_policer_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */

/* Traffic classes */
enum {
	TC0 = 0,
	TC1,
	TC2,
	TC3,
	TC4,
	TC5,
	TC6,
	TC7
};

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");

	fflush(stdout);
}

/* set the scheduler WQ priority in reserved_64s[0] */
static inline void
set_scheduler_wq_prio(struct rte_eth_rxconf *rx_conf, int priority)
{
	rx_conf->reserved_64s[0] = priority;
	rx_conf->reserved_64s[0] = rx_conf->reserved_64s[0] << SHIFT_RESERVED_PRIORITY;
	rx_conf->reserved_64s[0] |= POLICER_RFC_NUM;
	if (priority > 7)
		rte_exit(EXIT_FAILURE, "Acceptable scheduler WQ priority are 0-7!\n");
}

/* set the initialized scheduler handle in reserved_64s[1] */
static inline void
set_scheduler_handle(struct rte_eth_rxconf *rx_conf, void *sch_handle)
{
	rx_conf->reserved_64s[1] = (uint64_t)sch_handle;
	if (rx_conf->reserved_64s[1] == 0)
		rte_exit(EXIT_FAILURE, "Scheduler handle not set!\n");
}

static void
l2fwd_policer_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
	struct rte_ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->dst_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	rte_ether_addr_copy(&l2fwd_policer_ports_eth_addr[dest_portid], &eth->src_addr);
}

/* Simple forward. 8< */
static void
l2fwd_policer_simple_forward(struct rte_mbuf *m, unsigned portid)
{
	unsigned dst_port;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;

	dst_port = l2fwd_policer_dst_ports[portid];

	if (mac_updating)
		l2fwd_policer_mac_updating(m, dst_port);

	buffer = tx_buffer[dst_port];
	sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);
	if (sent)
		port_statistics[dst_port].tx += sent;
}
/* >8 End of simple forward. */

/* main processing loop */
static void
l2fwd_policer_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	int sent;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}

	while (!force_quit) {

		/* Drains TX queue in its main loop. 8< */
		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_rx_port; i++) {

				portid = l2fwd_policer_dst_ports[qconf->rx_port_list[i]];
				buffer = tx_buffer[portid];

				sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
				if (sent)
					port_statistics[portid].tx += sent;

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
		/* >8 End of draining TX queue. */

		/* sleep(5);
		 * can be used for sanity test: high priority packets receive first.
		 *
		 * Read packet from RX queues
		 */
		nb_rx = rte_dpaa2_scheduler_rx(sch_handle, pkts_burst, max_burst_size);
		if (unlikely(nb_rx == 0))
			continue;

		for (j = 0; j < nb_rx; j++) {
			m = pkts_burst[j];
			portid = pkts_burst[j]->port;
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			l2fwd_policer_simple_forward(m, portid);
		}
		port_statistics[portid].rx += nb_rx;
		/* End of read packet from RX queues. */
	}
}

static int
l2fwd_policer_launch_one_lcore(__rte_unused void *dummy)
{
	l2fwd_policer_main_loop();
	return 0;
}

/* display usage */
static void
l2fwd_policer_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-P] [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -P : Enable promiscuous mode\n"
	       "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
	       "  --no-mac-updating: Disable MAC addresses updating (enabled by default)\n"
	       "      When enabled:\n"
	       "       - The source MAC address is replaced by the TX port MAC address\n"
	       "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n"
	       "  --no-enable-flow: Disable vlan flow control (default is enable)\n"
	       "  --config:(portid,vlanid,vlan_prio)[,(portid,vlanid,vlan_prio)]\n"
	       "      Example: --config='(0,100,8),(1,400,8)'\n"
	       "      portid are acceptable which are used in portmask\n"
	       "      vlanid in int, acceptable range 0 to 4095\n"
	       "      vlan_prio is number of vlan priorities, maximum is 8 i.e.(0 to 7)"
	       "  --policer_option: configure policer options (opt_discard_red, opt_color_aware or opt_both)\n"
	       "      Default: opt_discard_red\n"
	       "  --policer_unit: configure policer unit (bytes, frames)\n"
	       "      Default: bytes\n"
	       "  --default_color: configure policer default color (red, yellow or green)\n"
	       "      Default: red\n"
	       "  -cir NUM in bytes/frames as selected\n"
	       "  -cbs NUM bytes/frames as selected\n"
	       "  -pir NUM bytes/frames as selected\n"
	       "  -pbs NUM bytes/frames as selected\n"
	       "  NOTE: In bytes mode, configure L3 rate(kbps) in cir and pir\n"
	       "  -b NUM: burst size for receive packet (default is 32)\n"
	       "  -r NUM: RX queue size (default is 1024)\n"
	       "  -t NUM: TX queue size (default is 1024)\n\n",
	       prgname);
}

static int
l2fwd_policer_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

static int
l2fwd_policer_parse_port_vlan_config(const char *q_arg)
{
	enum fieldnames {
		FLD_PORT = 0,
		FLD_VLAN_ID,
		FLD_FLOW_NUM,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	unsigned int size;
	char s[256];
	char *end;
	int i;

	nb_port_vlan_pair_params = 0;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld,
				 _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i])
				return -1;
		}

		if (nb_port_vlan_pair_params >= RTE_MAX_ETHPORTS) {
			printf("exceeded max number of port-vlan pair params: %hu\n",
				nb_port_vlan_pair_params);
			return -1;
		}
		port_vlan_pair_params_array[nb_port_vlan_pair_params].port_id =
				(uint16_t)int_fld[FLD_PORT];
		port_vlan_pair_params_array[nb_port_vlan_pair_params].vlan_id =
				(uint16_t)int_fld[FLD_VLAN_ID];
		port_vlan_pair_params_array[nb_port_vlan_pair_params].vlan_prio =
				(uint16_t)int_fld[FLD_FLOW_NUM];
		++nb_port_vlan_pair_params;
	}
	port_vlan_pair_params = port_vlan_pair_params_array;

	return 0;
}

static int
l2fwd_policer_parse_timer_period(const char *q_arg)
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

static void
l2fwd_policer_parse_scheduler_unit(const char *optarg)
{
	if (!strcmp(optarg, "frames"))
		policer_unit = POLICER_UNIT_FRAMES;
	else if (!strcmp(optarg, "bytes"))
		policer_unit = POLICER_UNIT_BYTES;
	else
		printf("Invalid Policer Unit, default set to Bytes!!\n");
}

static void
l2fwd_policer_parse_scheduler_option(const char *optarg)
{
	if (!strcmp(optarg, "opt_discard_red"))
		policer_option = POLICER_OPT_DISCARD_RED;
	else if (!strcmp(optarg, "opt_color_aware"))
		policer_option = POLICER_OPT_COLOR_AWARE;
	else if (!strcmp(optarg, "opt_both"))
		policer_option = POLICER_OPT_DISCARD_RED | POLICER_OPT_COLOR_AWARE;
	else
		printf("Invalid policer option, default set to discard_red!!\n");
}

static void
l2fwd_policer_parse_scheduler_default_color(const char *optarg)
{
	if (!strcmp(optarg, "red"))
		default_color = POLICER_COLOR_RED;
	else if (!strcmp(optarg, "yellow"))
		default_color = POLICER_COLOR_YELLOW;
	else if (!strcmp(optarg, "green"))
		default_color = POLICER_COLOR_GREEN;
	else
		printf("Invalid policer_default_color, default set to RED!!\n");
}

static const char short_options[] =
	"p:"  /* portmask */
	"P"   /* promiscuous */
	"T:"  /* timer period */
	"b:"  /* burst size */
	"r:"  /* RX queue size */
	"t:"  /* TX queue size */
	;

#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_ENABLE_FLOW "no-enable-flow"
#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_RATE_LIMIT_UNIT_CONFIG "policer_unit"
#define CMD_LINE_OPT_RATE_LIMIT_OPTION_CONFIG "policer_option"
#define CMD_LINE_OPT_RATE_LIMIT_COLOR_CONFIG "default_color"
#define CMD_LINE_OPT_CIR_CONFIG "cir"
#define CMD_LINE_OPT_CBS_CONFIG "cbs"
#define CMD_LINE_OPT_PIR_CONFIG "pir"
#define CMD_LINE_OPT_PBS_CONFIG "pbs"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_NO_MAC_UPDATING_NUM = 256,
	CMD_LINE_OPT_ENABLE_FLOW_CTL,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_RATE_LIMIT_UNIT,
	CMD_LINE_OPT_RATE_LIMIT_OPTION,
	CMD_LINE_OPT_RATE_LIMIT_DEFAULT_COLOR,
	CMD_LINE_OPT_CIR,
	CMD_LINE_OPT_CBS,
	CMD_LINE_OPT_PIR,
	CMD_LINE_OPT_PBS,
};

static const struct option lgopts[] = {
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, 0,
		CMD_LINE_OPT_NO_MAC_UPDATING_NUM},
	{ CMD_LINE_OPT_ENABLE_FLOW, no_argument, 0, CMD_LINE_OPT_ENABLE_FLOW_CTL},
	{ CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
	{ CMD_LINE_OPT_RATE_LIMIT_UNIT_CONFIG, 1, 0, CMD_LINE_OPT_RATE_LIMIT_UNIT},
	{ CMD_LINE_OPT_RATE_LIMIT_OPTION_CONFIG, 1, 0, CMD_LINE_OPT_RATE_LIMIT_OPTION},
	{ CMD_LINE_OPT_RATE_LIMIT_COLOR_CONFIG, 1, 0, CMD_LINE_OPT_RATE_LIMIT_DEFAULT_COLOR},
	{ CMD_LINE_OPT_CIR_CONFIG, 1, 0, CMD_LINE_OPT_CIR},
	{ CMD_LINE_OPT_CBS_CONFIG, 1, 0, CMD_LINE_OPT_CBS},
	{ CMD_LINE_OPT_PIR_CONFIG, 1, 0, CMD_LINE_OPT_PIR},
	{ CMD_LINE_OPT_PBS_CONFIG, 1, 0, CMD_LINE_OPT_PBS},
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_policer_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs, burst_size;
	unsigned long rx_size, tx_size;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;
	port_vlan_pair_params = NULL;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_policer_enabled_port_mask = l2fwd_policer_parse_portmask(optarg);
			if (l2fwd_policer_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_policer_usage(prgname);
				return -1;
			}
			break;
		case 'P':
			promiscuous_on = 1;
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_policer_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				l2fwd_policer_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* max_burst_size */
		case 'b':
			burst_size = (unsigned int)atoi(optarg);
			if (burst_size < 0 || burst_size > max_burst_size) {
				printf("invalid burst size\n");
				l2fwd_policer_usage(prgname);
				return -1;
			}
			max_burst_size = burst_size;
			break;

		/* RX queue size */
		case 'r':
			rx_size = (unsigned int)atoi(optarg);
			if (rx_size == 0 || rx_size > UINT16_MAX) {
				printf("invalid RX queue size\n");
				l2fwd_policer_usage(prgname);
				return -1;
			}
			nb_rxd = rx_size;
			break;

		/* TX queue size */
		case 't':
			tx_size = (unsigned int)atoi(optarg);
			if (tx_size == 0 || tx_size > UINT16_MAX) {
				printf("invalid TX queue size\n");
				l2fwd_policer_usage(prgname);
				return -1;
			}
			nb_txd = tx_size;
			break;

		case CMD_LINE_OPT_NO_MAC_UPDATING_NUM:
			mac_updating = 0;
			break;

		case CMD_LINE_OPT_ENABLE_FLOW_CTL:
			enable_flow = 0;
			break;

		/* long options */
		case CMD_LINE_OPT_CONFIG_NUM:
			ret = l2fwd_policer_parse_port_vlan_config(optarg);
			if (ret) {
				fprintf(stderr, "Invalid config\n");
				l2fwd_policer_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_RATE_LIMIT_UNIT:
			l2fwd_policer_parse_scheduler_unit(optarg);
			break;

		case CMD_LINE_OPT_RATE_LIMIT_OPTION:
			l2fwd_policer_parse_scheduler_option(optarg);
			break;

		case CMD_LINE_OPT_RATE_LIMIT_DEFAULT_COLOR:
			l2fwd_policer_parse_scheduler_default_color(optarg);
			break;

		case CMD_LINE_OPT_CIR:
			cir = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_CBS:
			cbs = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_PIR:
			pir = (uint32_t)atoi(optarg);
			break;

		case CMD_LINE_OPT_PBS:
			pbs = (uint32_t)atoi(optarg);
			break;

		default:
			l2fwd_policer_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/*
 * Check port config with enabled port mask,
 * and for valid port vlan pair combinations.
 */
static int
check_port_vlan_pair_config(void)
{
	uint16_t index, portid, vlanid, vlan_prio;

	for (index = 0; index < nb_port_vlan_pair_params; index++) {
		portid = port_vlan_pair_params[index].port_id;
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0) {
			printf("port %u is not enabled in port mask\n",
			       portid);
			return -1;
		}
		if (!rte_eth_dev_is_valid_port(portid)) {
			printf("port %u is not present on the board\n",
			       portid);
			return -1;
		}

		vlanid = port_vlan_pair_params[index].vlan_id;
		if (vlanid > MAX_VLAN_ID) {
			printf("Invalid vlan id %u\n",
			       vlanid);
			return -1;
		}

		vlan_prio = port_vlan_pair_params[index].vlan_prio;
		if (vlan_prio > MAX_NUM_OF_VLAN_PRIORITY) {
			printf("Invalid number of vlan priority %u\n",
			       vlan_prio);
			return -1;
		}
	}
	return 0;
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
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);
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
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text,
					sizeof(link_status_text), &link);
				printf("Port %d %s\n", portid,
				       link_status_text);
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

/*
 * Creating 8 classification rules based on vlan priorities-
 * 1. vlan0 (ID=100; priority=0) traffic go to TC[0]->q0
 *    dest_queue.index = 0;
 * 2. vlan1 (ID=100; priority=1) traffic go to TC[1]->q0
 *    dest_queue.index = 1;
 *    and so on.
 * 3. All other traffic go to TC[7]
 *  On all TC flow_attr.priority = 0;
 */

#define MAX_PATTERN_NUM 3
#define DEFAULT_TC 7
static void
vlan_port_flow_configure(uint16_t portid, uint8_t nb_rx_queue,
			 uint16_t vlan_id, uint16_t vlan_prio)
{
	struct rte_flow_item_vlan vlan_item[MAX_PATTERN_NUM];
	struct rte_flow_item_vlan vlan_mask[MAX_PATTERN_NUM];
	struct rte_flow_action flow_action[MAX_PATTERN_NUM];
	struct rte_flow_item flow_item[MAX_PATTERN_NUM];
	struct rte_flow_action_queue dest_queue;
	struct rte_flow_attr flow_attr;
	struct rte_flow_error error;
	void *flow;
	uint8_t i;

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	memset(flow_item, 0, MAX_PATTERN_NUM * sizeof(struct rte_flow_item));
	memset(flow_action, 0, MAX_PATTERN_NUM * sizeof(struct rte_flow_action));
	memset(&error, 0, sizeof(struct rte_flow_error));
	memset(vlan_item, 0, sizeof(vlan_item));
	memset(vlan_mask, 0, sizeof(vlan_mask));

	flow_attr.ingress = 1;
	for (i = 0; i < vlan_prio; i++) {
		/* RXQ0 is in TC0,  RXQ1 is in TC1 and so on*/
		flow_attr.group = i;
		/* priority is set to 0 because using single queue */
		flow_attr.priority = 0;
		dest_queue.index = i;

		switch (flow_attr.group) {
		case TC0:
			/* vlan ID 100 & priority 0 */
			vlan_item[0].hdr.vlan_tci =
					rte_cpu_to_be_16((uint16_t)(VLAN_PRIO_0 + vlan_id));
			break;
		case TC1:
			/* vlan ID 100 & priority 1 */
			vlan_item[0].hdr.vlan_tci =
					rte_cpu_to_be_16((uint16_t)(VLAN_PRIO_1 + vlan_id));
			break;
		case TC2:
			/* vlan ID 100 & priority 2 */
			vlan_item[0].hdr.vlan_tci =
					rte_cpu_to_be_16((uint16_t)(VLAN_PRIO_2 + vlan_id));
			break;
		case TC3:
			/* vlan ID 100 & priority 3 */
			vlan_item[0].hdr.vlan_tci =
					rte_cpu_to_be_16((uint16_t)(VLAN_PRIO_3 + vlan_id));
			break;
		case TC4:
			/* vlan ID 100 & priority 4 */
			vlan_item[0].hdr.vlan_tci =
					rte_cpu_to_be_16((uint16_t)(VLAN_PRIO_4 + vlan_id));
			break;
		case TC5:
			/* vlan ID 100 & priority 5 */
			vlan_item[0].hdr.vlan_tci =
					rte_cpu_to_be_16((uint16_t)(VLAN_PRIO_5 + vlan_id));
			break;
		case TC6:
			/* vlan ID 100 & priority 6 */
			vlan_item[0].hdr.vlan_tci =
					rte_cpu_to_be_16((uint16_t)(VLAN_PRIO_6 + vlan_id));
			break;
		case TC7:
			/* vlan ID 100 & priority 7 */
			vlan_item[0].hdr.vlan_tci =
					rte_cpu_to_be_16((uint16_t)(VLAN_PRIO_7 + vlan_id));
			break;
		default:
			rte_exit(EXIT_FAILURE, "vlan_item not set\n");
		}

		vlan_item[0].hdr.eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
		vlan_mask[0].hdr.vlan_tci = RTE_BE16(0xffff);

		flow_item[0].spec = &vlan_item[0];
		flow_item[0].mask = &vlan_mask[0];
		flow_item[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
		flow_item[1].type = RTE_FLOW_ITEM_TYPE_ANY;
		flow_item[2].type = RTE_FLOW_ITEM_TYPE_END;
		flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
		flow_action[0].conf = &dest_queue;
		flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

		flow_attr.reserved = DEFAULT_TC;

		/* validate and create the flow rule */
		if (!rte_flow_validate(portid, &flow_attr, flow_item, flow_action, &error)) {
			flow = rte_flow_create(portid, &flow_attr, flow_item, flow_action, &error);
			if (!flow) {
				rte_exit(EXIT_FAILURE,
					 "Cannot create flow to RXQ%d on port=%d\n",
					 nb_rx_queue, portid);
			}
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

int
main(int argc, char **argv)
{
	uint16_t nb_ports_available = 0;
	struct lcore_queue_conf *qconf;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;
	uint16_t portid, last_port;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;
	uint16_t nb_ports;
	int i, ret;


	/* Init EAL. 8< */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_policer_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD-POLICER arguments\n");
	/* >8 End of init EAL. */

	printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");
	printf("Flow classification %s\n", enable_flow ? "enabled" : "disabled");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	if (port_vlan_pair_params != NULL) {
		if (check_port_vlan_pair_config() < 0)
			rte_exit(EXIT_FAILURE, "Invalid port vlan pair config\n");
	}

	/* check port mask to possible port mask */
	if (l2fwd_policer_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);

	/* Initialization of the driver. 8< */

	/* reset l2fwd_policer_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_policer_dst_ports[portid] = 0;
	last_port = 0;

	/* initialize the scheduler and get the handle */
	sch_handle = rte_dpaa2_scheduler_init();

	/* populate destination port details */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0)
			continue;

		if (nb_ports_in_mask % 2) {
			l2fwd_policer_dst_ports[portid] = last_port;
			l2fwd_policer_dst_ports[last_port] = portid;
		} else {
			last_port = portid;
		}
		nb_ports_in_mask++;
	}

	if (nb_ports_in_mask % 2) {
		printf("Notice: odd number of ports in portmask.\n");
		l2fwd_policer_dst_ports[last_port] = last_port;
	}
	/* >8 End of initialization of the driver. */

	rx_lcore_id = rte_lcore_id();
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0)
			continue;
		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u TX port %u\n", rx_lcore_id,
		       portid, l2fwd_policer_dst_ports[portid]);
	}

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);

	/* Create the mbuf pool. 8< */
	l2fwd_policer_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_policer_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	/* >8 End of create the mbuf pool. */

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		/* Configure the number of queues for a port. */
		ret = rte_eth_dev_configure(portid, dev_info.max_rx_queues,
					    dev_info.max_tx_queues, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);
		/* >8 End of configuration of the number of queues for a port. */

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);

		ret = rte_eth_macaddr_get(portid,
					  &l2fwd_policer_ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err=%d, port=%u\n",
				 ret, portid);

		if (enable_flow) {
			if ((dev_info.max_rx_queues % 2) != 0)
				rte_exit(EXIT_FAILURE,
					 "Flow enabled, but RX queues not even for port=%d\n",
					 portid);

			else if (dev_info.max_rx_queues != 1) {
				for (i = 0; i < nb_port_vlan_pair_params; i++) {
					if (portid ==
						port_vlan_pair_params[i].port_id)
						vlan_port_flow_configure(portid,
							dev_info.max_rx_queues,
							port_vlan_pair_params[i].vlan_id,
							port_vlan_pair_params[i].vlan_prio);
				}
			}
		}

		/* init one RX queue */
		fflush(stdout);

		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;

		/* set the initialized scheduler handle */
		set_scheduler_handle(&rxq_conf, sch_handle);

		for (i = 0; i < dev_info.max_rx_queues; i++) {
			/* set the scheduler WQ priority
			 * TC[0] traffic in WQ prio 0, TC[1] traffic in WQ prio 1 and so on
			 */
			set_scheduler_wq_prio(&rxq_conf, i);

			/* RX queue setup. 8< */
			ret = rte_eth_rx_queue_setup(portid, i, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     l2fwd_policer_pktmbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
					 ret, portid);

			/* configure scheduler on each Rx queue */
			ret = rte_dpaa2_conf_scheduler(portid, i, policer_unit,
						       policer_option,
						       default_color,
						       cir, cbs, pir, pbs);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_dpaa2_policer:err=%d,\n", ret);
			/* >8 End of RX queue setup. */
		}

		/* Init one TX queue on each port. 8< */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);
		/* >8 End of init one TX queue on each port. */

		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n",
				 portid);

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL,
					     0);
		if (ret < 0)
			printf("Port %u, Failed to disable Ptype parsing\n",
					portid);
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done: \n");
		if (promiscuous_on) {
			ret = rte_eth_promiscuous_enable(portid);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"rte_eth_promiscuous_enable:err=%s, port=%u\n",
					rte_strerror(-ret), portid);
		}

		printf("Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
			portid,
			RTE_ETHER_ADDR_BYTES(&l2fwd_policer_ports_eth_addr[portid]));

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	/* start the scheduler */
	ret = rte_dpaa2_scheduler_start(sch_handle);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_dpaa2_scheduler_start:err=%d,\n", ret);


	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(l2fwd_policer_enabled_port_mask);

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_policer_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if ((l2fwd_policer_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n",
			       ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}
