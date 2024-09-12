/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/queue.h>
#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdbool.h>
#include <ftw.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "dfe_host_if.h"
#include "dfe_app.h"
#include "logging.h"
#include "cmd_timer.h"
#include "cmd_line.h"
#include "ipc.h"
#include "tti.h"

#define APP_VERSION       "0.5"

int cpu_id = 0;
int cpu_mask = 0x3;
int log_level = APP_DBG_LOG_ERROR;
int rte_log_level = RTE_LOGTYPE_EAL;
static struct cmdline *cl;
struct dfe_state state;

#define MAX_CMD_LEN 100
char cmd_line_to_run[MAX_CMD_LEN];
int interactive = 1;
int wait_response = 0;

uint32_t tti_irq_count = 0;
uint32_t tti_msg_count = 0;
uint16_t sfn_no = 0;
uint16_t slot_no = 0;

struct sched_param param_new = { .sched_priority = APP_SCHED_PRIORITY };

/* error to string helper */
static const char *modem_error_to_text(uint32_t status_code)
{
	switch(status_code) {
	case DFE_NO_ERROR:
		return "OK";
	case DFE_INVALID_COMMAND:
		return "Invalid command";
	case DFE_INVALID_PARAM:
		return "Invalid parameters";
	case DFE_ERROR_GENERIC:
		return "Generic error";
	case DFE_ERROR_VSPA_TIMEOUT:
		return "VSPA timeout error";
	case DFE_OPERATION_RUNNING:
		return "Another operation already running";
	default:
		return "N/A";
	}
}

static void print_version(void)
{
	printf("dfe-app: version %s (Built %s %s)\n",
	       APP_VERSION, __DATE__, __TIME__);
}

static void print_help(char *s)
{
	printf("%s -h\n"
		"\tShow this help\n", s);
	printf("%s -v\n"
		"\tShow version\n", s);
	printf("%s [-l <app_log_level>] [-r <rte_log_level>] [-c <command to execute >] [-i <core assignmnent>]\n\n\n", s);

	printf("When '-c' option is used, below is a list of available commands:\n"
		COMMAND_LIST
		"\n");

	printf("Example:\n"
		"\t%s -c \"config qec iq_taps [ 0 1.0 0 0 0 0 0 0 0 0 1.0 1.0 ]\"\n"
		"\t%s -c \"vspa benchmark size 4096 mode read dma 1 iter 1\"\n"
		"\t%s -c \"tdd config_pattern_fr1fr2 3,6,1,4,0,0\"\n"
		"\t%s -c \"tdd config_pattern D,D,D,S[0:5:10:13],U\"\n"
		"\t%s -c \"tdd start\"\n\n", s, s, s, s, s);

}

void reset_tti_stats(void)
{
	tti_msg_count = 0;
	tti_irq_count = 0;
	sfn_no = 0;
	slot_no = 0;
}

void dump_tti_stats(void)
{
	printf("tti_irq_count = %d\n", tti_irq_count);
	printf("tti_msg_count = %d\n", tti_msg_count);
	printf("       sfn_no = %d\n", sfn_no);
	printf("      slot_no = %d\n", slot_no);
}

/* wrapper on top of send_msg to accomodate user-dfined 'dfe_msg' structure */
static int send_dfe_command(struct dfe_msg *msg)
{
	int ret;

	ret = send_msg((char *)msg, DFE_MSG_SIZE);
	if (ret < 0)
		return ret;

	/*
	 * We expect a response from the modem for all commands
	 */
	arm_cmd_timer();

	return ret;
}

/* implementation for IPC reset message - user can tweak this, thus not part of ipc.c */
void signal_ipc_reset(void)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send IPC_RESET notification to modem\n");

	/* Notify FreeRTOS we're shutting down */
	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;
	msg->type = DFE_IPC_RESET;

	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC_RESET message\n");

	disarm_cmd_timer();
	rte_atomic16_clear(&state.is_active);
}

void process_msg_from_modem(struct rte_bbdev_op_data *in_buf)
{
	struct dfe_msg *msg = (struct dfe_msg *)in_buf->mem;

	/* artefacts from BBDEV IPC reset */
	if (msg->type == DFE_IPC_RESET)
		return;

	switch (msg->type) {
	/* TTI message from Modem */
	case DFE_TTI_MESSAGE:
		/* ulCurrentSlotInFrame, ulCurrentSfn */
		tti_msg_count++;
		slot_no = msg->payload[0];
		sfn_no = msg->payload[1];
		break;

	/* VSPA DMA to/from DDR benchmarking feature */
	case DFE_VSPA_DMA_BENCH:
		cmdline_printf(cl,
				"VSPA benchmark result = %d.%d Gb/s (%d VSPA cycles), parallel DMAs = %d, iterations = %d\n",
				msg->payload[0],
				msg->payload[1],
				msg->payload[2],
				msg->payload[3],
				msg->payload[4]
				);
		wait_response = 0;
		break;
	default:
		wait_response = 0;
		app_print_warn("received msg->type = %#x, msg->status = %#x (%s)\n",
			msg->type,
			msg->status,
			modem_error_to_text(msg->status));
		break;
	}
}

static void sig_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
		dfe_free();
}

/* TODO: add your CLI callbacks here */

/* api to send a simple command (no payload) to modem; avoid duplicated code */
void cmd_do_simple(int msg_type, const char *desc)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send %s command\n", desc);

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	wait_response = 1;
	msg->type = msg_type;
	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* debug */
void cmd_do_debug(uint32_t debug_cmd, const char *desc)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send %s command\n", desc);

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	wait_response = 1;
	msg->type = DFE_DEBUG_CMD;
	msg->payload[0] = debug_cmd;
	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* config rx antenna */
void cmd_do_rx_antenna_config(uint32_t rx_antenna_mask)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send VSPA DMA benchmark command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_CFG_RX_ANTENNA;
	msg->payload[0] = rx_antenna_mask;

	wait_response = 1;
	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* config symbol size */
void cmd_do_sym_size_config(uint32_t sym_size)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send sym_size cfg command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_CFG_SYM_SIZE;
	msg->payload[0] = sym_size;

	wait_response = 1;
	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* config tx/rx_addr */
void cmd_do_tx_rx_addr_config(int msg_type_tx_rx_addr, uint32_t addr)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send %s addr cfg command\n", (msg_type_tx_rx_addr == DFE_CFG_TX_ADDR) ? "TX" : "RX");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = msg_type_tx_rx_addr;
	msg->payload[0] = addr;

	wait_response = 1;
	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* config tx/rx_sym_nr */
void cmd_do_tx_rx_sym_nr_config(int msg_type_tx_rx_sym_nr, uint32_t num_syms_in_buffer)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send %s sym nr cfg command\n", (msg_type_tx_rx_sym_nr == DFE_CFG_TX_SYM_NUM) ? "TX" : "RX");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = msg_type_tx_rx_sym_nr;
	msg->payload[0] = num_syms_in_buffer;

	wait_response = 1;
	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* scs */
void cmd_do_config_scs(uint32_t scs)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send scs config command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_CFG_SCS;
	msg->payload[0] = scs; /* SCS */

	/* user wants his answer */
	wait_response = 1;

	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* pattern_new */
void cmd_do_config_pattern_new(uint32_t p0,
			       uint32_t p1,
			       uint32_t p2,
			       uint32_t p3,
			       uint32_t p4,
			       uint32_t p5,
			       uint32_t p6,
			       uint32_t p7)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send pattern config command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_TDD_CFG_PATTERN_NEW;
	msg->payload[0] = p0;
	msg->payload[1] = p1;
	msg->payload[2] = p2;
	msg->payload[3] = p3;
	msg->payload[4] = p4;
	msg->payload[5] = p5;
	msg->payload[6] = p6;
	msg->payload[7] = p7;

#if 0
	printf("\n");
	for (int k = 0; k < 8; k++)
		printf("%2d | ", msg->payload[k]);
	printf("\n");
#endif

	/* user wants his answer */
	wait_response = 1;

	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* tick keepalive  */
void cmd_do_config_tick_keepalive(uint32_t keepalive)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send tdd config tick keepalive command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_TDD_TICK_KEEPALIVE;
	msg->payload[0] = keepalive;

	/* user wants his answer */
	wait_response = 1;

	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* uplink time advance  */
void cmd_do_config_ul_ta(uint32_t ta)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send UL TA command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_TDD_UL_TIME_ADVANCE;
	msg->payload[0] = ta;

	/* user wants his answer */
	wait_response = 1;

	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* time offset correction command */
void cmd_do_config_time_offset(uint32_t time_offset)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send TO correction command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_TDD_TIME_OFFSET_CORR;
	msg->payload[0] = time_offset;

	/* user wants his answer */
	wait_response = 1;

	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* sfn-slot set command */
void cmd_do_config_sfn_slot(enum cmd_tdd_sfn_slot_action cmd_action, int32_t sfn, int32_t slot)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send SFN-SLOT command (action=%d sfn=%d slot=%d)\n", cmd_action, sfn, slot);

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = (cmd_action == CLI_TDD_CONFIG_SFN_SLOT_DELTA) ? DFE_TDD_SFN_SLOT_DELTA : DFE_TDD_SFN_SLOT_SET ;
	msg->payload[0] = sfn;
	msg->payload[1] = slot;

	/* user wants his answer */
	wait_response = 1;

	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* vspa dma benchmark */
void cmd_do_vspa_benchmark(uint32_t size_bytes, uint32_t mode, uint32_t parallel_dma_num, uint32_t iterations)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send VSPA DMA benchmark command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_VSPA_DMA_BENCH;
	msg->payload[0] = size_bytes;
	msg->payload[1] = mode;
	msg->payload[2] = parallel_dma_num;
	msg->payload[3] = iterations;

	/* user wants his answer */
	wait_response = 1;

	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

void cmd_do_vspa_fr1fr2_tool(uint16_t param)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send VSPA fr1fr2_test_tool host handshake bypass flag command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_VSPA_PROD_HOST_BYPASS;
	msg->payload[0] = param;

	wait_response = 1;
	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");
}

/* config qec parameters */
void cmd_do_qec_config(uint32_t tx_rx, uint32_t mode, uint32_t index, uint32_t value)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send QEC config command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_CFG_QEC_PARAM;
	msg->payload[0] = tx_rx;
	msg->payload[1] = mode;
	msg->payload[2] = index;
	msg->payload[3] = value;

	/* user wants his answer */
	wait_response = 1;

	ret = send_dfe_command(msg);
	if (ret < 0)
		app_print_err("Failed to send IPC message\n");

}

/* command to wait for msg response - helper when cmdline is flooded with cmds */
void cmd_do_wait_response(void)
{
	while (wait_response)
		rte_delay_us_sleep(100);
}

/* command-line arguments parsing */
static void parse_args(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, ":c:i:m:l:r:hv")) != -1) {
		switch (opt) {
		case 'v':
			print_version();
			exit(0);
		case 'c':
			interactive = 0;
			app_print_dbg("excuting command [%s]\n", optarg);
			snprintf(cmd_line_to_run, MAX_CMD_LEN - 1, "%s\n", optarg);
			break;
		case 'i':
			cpu_id = strtoul(optarg, NULL, 0);
			app_print_dbg("Assign to core [%d]\n", cpu_id);
			break;
		case 'm':
			cpu_mask = strtoul(optarg, NULL, 0);
			app_print_dbg("EAL core mask [%d]\n", cpu_mask);
			break;
		case 'r':
			rte_log_level = strtoul(optarg, NULL, 0);
			break;
		case 'l':
			log_level = strtoul(optarg, NULL, 0);
			break;
		case ':':
			printf("option requires a value!\n");
			exit(-1);
		case 'h':
		default:
			print_version();
			print_help(argv[0]);
			exit(0);
		}
	}
}

int rte_sys_get_tid(void)
{
	return rte_gettid();
	//return (int)syscall(SYS_gettid);
}

void assign_to_core(int core_id)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(core_id, &mask);
	sched_setaffinity(0, sizeof(mask), &mask);
}

#define MAX_EAL_ARGC 6
#define MAX_EAL_ARGV 32
int main(int argc, char **argv)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	/* avoid giving to app the eal arguments ; hardcode many of them here */
	char *eal_argv[MAX_EAL_ARGC] = {
		"dummy",
		"--vdev=bbdev_la93xx",
		"-c",
		NULL, // coremask
		"-n",
		"1"
	};
#pragma GCC diagnostic pop
	char syscmd[100] = { 0 };
	int eal_argc = MAX_EAL_ARGC;
	int tid;
	int ret;

	/* catch SIGINT/SIGTERM signals - free the resources */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* TODO: add your arguments parsing in below API */
	parse_args(argc, argv);

	/* set RTE log level */
	rte_log_set_global_level(rte_log_level);

	/* assign to core and modify pre-defined EAL params */
	eal_argv[3] = (char *) calloc (MAX_EAL_ARGV, sizeof(char));
	sprintf(eal_argv[3], "%#x", cpu_mask);
	assign_to_core(cpu_id);

	/* raise app priority to RT */
	sched_setscheduler(0, SCHED_FIFO, &param_new);

	/* chrt */
	tid = rte_sys_get_tid();
	sprintf(syscmd, "chrt -p %d %d", APP_SCHED_PRIORITY,tid);
	if (system(syscmd) < 0)
		printf("error setting chrt prio\n");

	/* warning due to hardcoding of EAL params */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	/* init EAL */
	ret = rte_eal_init(eal_argc, (char **) eal_argv);
#pragma GCC diagnostic pop
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	/* start IPC & other stuff */
	ret = dfe_init();
	if (ret < 0) {
		app_print_err("dfe_init failed\n");
		goto free_mem;
	}

	/* check if interactive mode (no -c param) */
	if (interactive) {
		/* start command line prompt */
		cl = cmdline_stdin_new(ctx, "DFE> ");
		if (!cl) {
			app_print_err("Cannot create command line interaface\n");
			goto byebye;
		}

#if 1
		cmdline_interact(cl);
#else
		while (cmdline_poll(cl) != RDLINE_EXITED) {
		}
#endif

		cmdline_stdin_exit(cl);
	} else {
		cl = cmdline_new(ctx, "DFE>", 0, 1);
		if (cl == NULL) {
			ret = -1;
			goto byebye;
		}

		if (cmdline_parse_check(cl, cmd_line_to_run) < 0) {
			printf("Error: invalid command: '%s'\n", cmd_line_to_run);
			ret = -1;
		} else if (cmdline_in(cl, cmd_line_to_run, strlen(cmd_line_to_run)) < 0) {
			printf("input error\n");
			ret = -1;
		}

		/* wait for anwer on given command */
		while (wait_response)
			rte_delay_us_sleep(100);

		cmdline_free(cl);
	}

byebye:
	/* clean-up everything before exiting */
	dfe_free();

free_mem:
	free(eal_argv[3]);

	return 0;
}
