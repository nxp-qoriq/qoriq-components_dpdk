/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

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

#include "dfe_host_if.h"
#include "dfe_app.h"
#include "logging.h"
#include "cmd_timer.h"
#include "cmd_line.h"
#include "ipc.h"

#define APP_VERSION       "0.2.1-fr1fr2_test_tool"

int log_level = APP_DBG_LOG_ERROR;
int rte_log_level = RTE_LOGTYPE_EAL;
static struct cmdline *cl;
struct dfe_state state;

#define MAX_CMD_LEN 100
char cmd_line_to_run[MAX_CMD_LEN];
int interactive = 1;
int wait_response = 0;

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
	printf("%s [-l <app_log_level>] [-r <rte_log_level>] [-c <command to execute >]\n", s);

	printf("When '-c' option is used, below is a list of available commands:\n"
		COMMAND_LIST
		"\n");

	printf("Example:\n"
		"\t%s -c \"config qec iq_taps [ 0 1.0 0 0 0 0 0 0 0 0 1.0 1.0 ]\"\n"
		"\t%s -c \"vspa benchmark size 4096 mode read dma 1 iter 1\"\n"
		"\t%s -c \"tdd start\"\n\n", s, s, s);

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

/* config rx antenna */
void cmd_do_rx_antenna_config(uint32_t rx_antenna)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send VSPA DMA benchmark command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_CFG_RX_ANTENNA;
	msg->payload[0] = rx_antenna;

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

/* pattern */
void cmd_do_config_pattern(uint32_t p0, uint32_t p1, uint32_t p2,
			uint32_t p3, uint32_t p4, uint32_t p5, uint32_t p6)
{
	struct dfe_msg *msg;
	int ret;

	app_print_info("Send pattern config command\n");

	msg = (struct dfe_msg *)get_tx_buf(BBDEV_IPC_H2M_QUEUE);
	if (!msg)
		return;

	msg->type = DFE_TDD_CFG_PATTERN;
	msg->payload[0] = p0; /* SCS */
	msg->payload[1] = p1;
	msg->payload[2] = p2;
	msg->payload[3] = p3;
	msg->payload[4] = p4;
	msg->payload[5] = p5;
	msg->payload[6] = p6;

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

	while ((opt = getopt(argc, argv, ":c:l:r:hv")) != -1) {
		switch (opt) {
		case 'v':
			print_version();
			exit(0);
		case 'c':
			interactive = 0;
			app_print_dbg("excuting command [%s]\n", optarg);
			snprintf(cmd_line_to_run, MAX_CMD_LEN - 1, "%s\n", optarg);
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

int main(int argc, char **argv)
{
	/* avoid giving to app the eal arguments ; hardcode them here */
	const char* const eal_argv[] = { "dummy", "--vdev=bbdev_la93xx", "-c", "0xF", "-n", "1" };
	int eal_argc = 6;

	int ret;

	/* catch SIGINT/SIGTERM signals - free the resources */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* TODO: add your arguments parsing in below API */
	parse_args(argc, argv);

	/* set RTE log level */
	rte_log_set_global_level(rte_log_level);

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
		return ret;
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

	return 0;
}
