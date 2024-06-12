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

void
cmd_quit_parsed(__attribute__((unused)) void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	cmdline_quit(cl);
}

void
cmd_wait_response_parsed(__attribute__((unused)) void *parsed_result,
			 __attribute__((unused)) struct cmdline *cl,
			 __attribute__((unused)) void *data)
{
	cmd_do_wait_response();
}

void
cmd_help_parsed(__attribute__((unused)) void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	cmdline_printf(cl, "\n"
		"Available commands:\n"
		COMMAND_LIST
		"\n");
}
void
cmd_fdd_start_parsed(__attribute__((unused)) void *parsed_result,
		     __attribute__((unused)) struct cmdline *cl,
		     __attribute__((unused)) void *data)
{
	cmd_do_simple(DFE_FDD_START, "FDD start");
}

void
cmd_fdd_stop_parsed(__attribute__((unused)) void *parsed_result,
		    __attribute__((unused)) struct cmdline *cl,
		    __attribute__((unused)) void *data)
{
	cmd_do_simple(DFE_FDD_STOP, "FDD stop");
}

void
cmd_tdd_start_parsed(__attribute__((unused)) void *parsed_result,
		     __attribute__((unused)) struct cmdline *cl,
		     __attribute__((unused)) void *data)
{
	cmd_do_simple(DFE_TDD_START, "TDD start");
}

void
cmd_tdd_stop_parsed(__attribute__((unused)) void *parsed_result,
		    __attribute__((unused)) struct cmdline *cl,
		    __attribute__((unused)) void *data)
{
	cmd_do_simple(DFE_TDD_STOP, "TDD stop");
}

void
cmd_tdd_tti_parsed(__attribute__((unused)) void *parsed_result,
		     __attribute__((unused)) struct cmdline *cl,
		     __attribute__((unused)) void *data)
{
	struct cmd_tdd_tti_result *res = parsed_result;

	if (!strncmp(res->action, "stop", 4)) {
		cmd_do_simple(DFE_TDD_STOP, "TDD stop");
		cmd_do_wait_response();
		sleep(1);
		cmd_do_simple(DFE_IPC_HOST_DISCONNECT, "Stop TTI msgs");
		sleep(1);
		stop_tti_thread();

		return;
	}

	/* reset the stats */
	reset_tti_stats();

	start_tti_thread();

	/* given that start/stop are the possible options... */
	cmd_do_simple(DFE_IPC_HOST_CONNECT, "Receive TTI msgs");
	cmd_do_wait_response();
	cmd_do_simple(DFE_TDD_START, "TDD start");
}

void
cmd_config_scs_parsed(void *parsed_result,
		      __attribute__((unused)) struct cmdline *cl,
		      __attribute__((unused)) void *data)
{
	struct cmd_config_scs_result *res = parsed_result;

	/* res->scs_value = {15,30} */
	cmd_do_config_scs(atoi(res->scs_value));
}

void
cmd_tdd_config_pattern_new_parsed(void *parsed_result,
				  __attribute__((unused)) struct cmdline *cl,
				  __attribute__((unused)) void *data)
{
	struct cmd_tdd_config_pattern_new_result *res = parsed_result;
	int i;

	char *slots_config[MAX_SLOTS];
	int total_slots = rte_strsplit(res->args, strlen(res->args), slots_config, MAX_SLOTS, ',');

	for (i = 0; i < total_slots; i++) {
		printf("slots_config[%d] = {%s}\n", i, slots_config[i]);
		char *syms_config[5];
		int syms = rte_strsplit(slots_config[i], strlen(slots_config[i]), syms_config, 4, ':');
		uint32_t payload[8] = {
			0,  //slot_no
			0,  //is_dl
			0,  //is_ul
			0,  //start_sym_dl
			13, //end_sym_dl
			0,  //start_sym_ul
			13, //end_sym_ul
			0,  //not_used
		};

		payload[0] = i; /* slot_no */
		switch (slots_config[i][0]) {
			case 'D':
				payload[1] = 1; /* is_dl */
				break;
			case 'U':
				payload[2] = 1; /* is_ul */
				break;
			case 'S':
				payload[1] = 1; /* is_dl */
				payload[2] = 1; /* is_ul */
				break;
			case 'G':
			default:
				break;
		}

		/* no custom allocation[ ] nor mixed slot */
		if (syms < 2)
			goto _send_slot_info;

		/* populate custom allocation if specified */
		switch (slots_config[i][0]) {
			case 'D':
				payload[3] = atoi((char *) &syms_config[0][2]); /* remove prefix 'X[' */
				payload[4] = atoi(syms_config[1]);
				break;
			case 'U':
				payload[5] = atoi((char *) &syms_config[0][2]); /* remove prefix 'X[' */
				payload[6] = atoi(syms_config[1]);
				break;
			case 'S':
				payload[3] = atoi((char *) &syms_config[0][2]); /* remove prefix 'X[' */
				payload[4] = atoi(syms_config[1]);
				payload[5] = atoi(syms_config[2]);
				payload[6] = atoi(syms_config[3]);
				break;
			case 'G':
			default:
				break;
		}

#if 0 /* debug */
		for (int j = 0; j < syms; j++) {
			if (j == 0) {
				printf("\tsyms_config[%d] = {%s}\n", j, (char *) &syms_config[j][2]);
			} else if (j == (syms - 1)) {
				syms_config[j][strlen(syms_config[j]) - 1] = '\0';
				printf("\tsyms_config[%d] = {%s}\n", j, syms_config[j]);
			} else {
				printf("\tsyms_config[%d] = {%s}\n", j, syms_config[j]);
			}
		}
#endif

_send_slot_info:
		/* prevent flooding M4 with messages */
		cmd_do_wait_response();

		cmd_do_config_pattern_new(payload[0],
					  payload[1],
					  payload[2],
					  payload[3],
					  payload[4],
					  payload[5],
					  payload[6],
					  payload[7]);
	}


}

void
cmd_tdd_config_pattern_fr1fr2_parsed(void *parsed_result,
				     __attribute__((unused)) struct cmdline *cl,
				     __attribute__((unused)) void *data)
{
	struct cmd_tdd_config_pattern_fr1fr2_result *res = parsed_result;
	struct slot_cfg {
		uint16_t is_dl;
		uint16_t is_ul;
		uint16_t start_dl, stop_dl;
		uint16_t start_ul, stop_ul;
	} s[MAX_SLOTS];
	uint16_t slot_count = 0;

	memset(s, 0, sizeof(s));

	char *tokens[12];
	int total_tokens = rte_strsplit(res->args, strlen(res->args), tokens, 12, ',');

	if ((total_tokens != 6) && (total_tokens != 12)) {
		printf("expected 6 or 12 params\r\n");
		return;
	}

	for (int j = 0, k = 0; j < (total_tokens / 6); j++, k = j * 6)
	{
		// D - fill non-zero fields
		for (int i = 0; i < atoi(tokens[0+k]); i++)
		{
			s[slot_count].is_dl = 1;
			s[slot_count].stop_dl = 13;
			slot_count++;
		}

		// G after D
		for (int i = 0; i < atoi(tokens[4+k]); i++)
		{
			slot_count++;
		}

		// S
		if ((atoi(tokens[1+k]) != 0) || (atoi(tokens[3+k]) != 0))
		{
			s[slot_count].is_dl = !!atoi(tokens[1+k]);
			s[slot_count].is_ul = !!atoi(tokens[3+k]);
			s[slot_count].stop_dl = atoi(tokens[1+k]) - 1;
			s[slot_count].start_ul = 13 - atoi(tokens[3+k]) + 1;
			s[slot_count].stop_ul = 13;
			slot_count++;
		}

		// U - fill non-zero fields
		for (int i = 0; i < atoi(tokens[2+k]); i++)
		{
			s[slot_count].is_ul = 1;
			s[slot_count].stop_ul = 13;
			slot_count++;
		}

		// G after U - fill non-zero fields
		for (int i = 0; i < atoi(tokens[5+k]); i++)
		{
			slot_count++;
		}
	}

	for (int j = 0; j < slot_count; j++)
	{
		uint32_t payload[8] = {
			j,              //slot_no
			s[j].is_dl,     //is_dl
			s[j].is_ul,     //is_ul
			s[j].start_dl,  //start_sym_dl
			s[j].stop_dl,   //end_sym_dl
			s[j].start_ul,  //start_sym_ul
			s[j].stop_ul,   //end_sym_ul
			0,  //not_used
		};

		/* prevent flooding M4 with messages */
		cmd_do_wait_response();

		cmd_do_config_pattern_new(payload[0],
					payload[1],
					payload[2],
					payload[3],
					payload[4],
					payload[5],
					payload[6],
					payload[7]);
	}
}

void
cmd_tdd_config_tick_parsed(void *parsed_result,
			   __attribute__((unused)) struct cmdline *cl,
			   __attribute__((unused)) void *data)
{
	struct cmd_tdd_config_tick_result *res = parsed_result;

	printf("res->args = %s\n", res->args);
	cmd_do_config_tick_keepalive(atoi(res->args));
}

void
cmd_tdd_config_ul_ta_parsed(void *parsed_result,
			   __attribute__((unused)) struct cmdline *cl,
			   __attribute__((unused)) void *data)
{
	struct cmd_tdd_config_ta_result *res = parsed_result;

	printf("res->ta = %d\n", res->ta);
	cmd_do_config_ul_ta(res->ta);
}

void
cmd_tdd_time_offset_parsed(void *parsed_result,
			   __attribute__((unused)) struct cmdline *cl,
			   __attribute__((unused)) void *data)
{
	struct cmd_tdd_time_offset_result *res = parsed_result;

	printf("res->to = %d\n", res->to);
	cmd_do_config_time_offset(res->to);
}

void
cmd_tdd_sfn_slot_parsed(void *parsed_result,
			   __attribute__((unused)) struct cmdline *cl,
			   __attribute__((unused)) void *data)
{
	struct cmd_tdd_sfn_slot_result *res = parsed_result;
	enum cmd_tdd_sfn_slot_action cmd_action = CLI_TDD_CONFIG_SFN_SLOT_SET;

	printf("res->action = %s\n", res->action);
	printf("res->sfn = %d\n", res->sfn);
	printf("res->slot = %d\n", res->slot);

	if (!strcmp(res->action, "delta"))
		cmd_action = CLI_TDD_CONFIG_SFN_SLOT_DELTA;

	cmd_do_config_sfn_slot(cmd_action, res->sfn, res->slot);
}

#if 0 /* future */
void
cmd_cell_search_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_cell_search_result *res = parsed_result;

	printf("res->action = %s\n", res->action);
	printf("res->args = %s\n", res->args);

	//cmd_do_simple(DFE_IPC_HOST_CONNECTED, "IPC host connected");
	//cmd_do_wait_response();
	//cmd_do_simple(DFE_CELL_SEARCH_START, "CellSearch start");
}

void
cmd_cell_attach_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_cell_search_result *res = parsed_result;

	printf("res->action = %s\n", res->action);
	printf("res->args = %s\n", res->args);
}
#endif

void
cmd_rf_switch_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_rf_switch_result *res = parsed_result;

	printf("res->action = %s\n", res->action);

	if (!strncmp(res->action, "tx", 2))
		cmd_do_simple(DFE_TDD_SWITCH_TX, "TDD switch TX");
	else if (!strncmp(res->action, "rx", 2))
		cmd_do_simple(DFE_TDD_SWITCH_RX, "TDD switch RX");
}

void
cmd_tti_stats_parsed(__attribute__((unused)) void *parsed_result,
			 __attribute__((unused)) struct cmdline *cl,
			 __attribute__((unused)) void *data)
{
	dump_tti_stats();
}

void
cmd_config_symbol_size_parsed(__attribute__((unused)) void *parsed_result,
			      __attribute__((unused)) struct cmdline *cl,
			      __attribute__((unused)) void *data)
{
	struct cmd_config_symbol_size_result *res = parsed_result;

	cmd_do_sym_size_config(res->sym_size);
}

void
cmd_config_rx_ant_parsed(void *parsed_result,
			 __attribute__((unused))struct cmdline *cl,
			 __attribute__((unused)) void *data)
{
	struct cmd_config_rx_ant_result *res = parsed_result;

	cmd_do_rx_antenna_config(res->rx_antenna);
}

void
cmd_config_rx_addr_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_config_rx_addr_result *res = parsed_result;

	/* TODO: make use of memory mapping between host CPU and la93xx */
	cmd_do_tx_rx_addr_config(DFE_CFG_RX_ADDR, res->rx_addr);
}

void
cmd_config_rx_sym_num_parsed(void *parsed_result,
			     __attribute__((unused)) struct cmdline *cl,
			     __attribute__((unused)) void *data)
{
	struct cmd_config_rx_sym_num_result *res = parsed_result;
	cmd_do_tx_rx_sym_nr_config(DFE_CFG_RX_SYM_NUM, res->rx_sym_num);
}

void
cmd_config_tx_addr_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_config_tx_addr_result *res = parsed_result;

	/* TODO: make use of memory mapping between host CPU and la93xx */
	cmd_do_tx_rx_addr_config(DFE_CFG_TX_ADDR, res->tx_addr);
}

void
cmd_config_tx_sym_num_parsed(void *parsed_result,
			     __attribute__((unused)) struct cmdline *cl,
			     __attribute__((unused)) void *data)
{
	struct cmd_config_tx_sym_num_result *res = parsed_result;
	cmd_do_tx_rx_sym_nr_config(DFE_CFG_TX_SYM_NUM, res->tx_sym_num);
}

void
cmd_axiq_lb_enable_parsed(__attribute__((unused)) void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	cmd_do_simple(DFE_CFG_AXIQ_LB_ENABLE,"AXIQ LB enable [CH2(rx)-CH5(tx)]");
}

void
cmd_axiq_lb_disable_parsed(__attribute__((unused)) void *parsed_result,
			   __attribute__((unused)) struct cmdline *cl,
			   __attribute__((unused)) void *data)
{
	cmd_do_simple(DFE_CFG_AXIQ_LB_DISABLE,"AXIQ LB disable [CH2(rx)-CH5(tx)]");
}

void
cmd_vspa_debug_parsed(__attribute__((unused)) void *parsed_result,
		      __attribute__((unused)) struct cmdline *cl,
		      __attribute__((unused)) void *data)
{
	cmd_do_simple(DFE_VSPA_DEBUG_BP,"VSPA debug break-point");
}

void
cmd_vspa_benchmark_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_vspa_benchmark_result *res = parsed_result;

	if (!strncmp(res->mode_rd_wr, "read", strlen("read"))) {
		cmd_do_vspa_benchmark(res->size_bytes, 1, res->parallel_dma_num, res->iterations_num);
	} else if (!strncmp(res->mode_rd_wr, "write", strlen("write"))) {
		cmd_do_vspa_benchmark(res->size_bytes, 2, res->parallel_dma_num, res->iterations_num);
	} else {
		cmdline_printf(cl, "wrong argument\n");
	}
}


void
cmd_vspa_fr1fr2_tool_parsed(__attribute__((unused)) void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	struct cmd_vspa_fr1fr2_tool_result *res = parsed_result;

	app_print_info("cmd_vspa_fr1fr2_tool_parsed: res->flag = %d\n", res->flag);
	cmd_do_vspa_fr1fr2_tool(res->flag);
}

void
cmd_config_qec_pt_parsed(void *parsed_result,
			 __attribute__((unused)) struct cmdline *cl,
			 __attribute__((unused)) void *data)
{
	struct cmd_config_qec_pt_result *res = parsed_result;
	uint32_t txrx;

	app_print_info("cmd_config_qec_pt_parsed: res->txrx = %s\n", res->txrx);

	if (!strncmp(res->txrx, "tx", strlen("tx"))) {
		txrx = QEC_TX_CORR;
	} else if (!strncmp(res->txrx, "rx", strlen("rx"))) {
		txrx = QEC_RX_CORR;
	} else {
		printf("wrong argument\r");
		return;
	}

	/* send qec pass-through for tx or rx */
	cmd_do_qec_config(txrx, QEC_IQ_DC_OFFSET_PASSTHROUGH, 0, 0);
}

void cmd_config_qec_dco_parsed(void *parsed_result,
			       __attribute__((unused)) struct cmdline *cl,
			       __attribute__((unused)) void *data)
{
	struct cmd_config_qec_dco_result *res = parsed_result;
	uint32_t txrx;
	float dc_i, dc_q;

	app_print_info("cmd_config_qec_pt_parsed: res->txrx = %s\n", res->txrx);

	if (!strncmp(res->txrx, "tx", strlen("tx"))) {
		txrx = QEC_TX_CORR;
	} else if (!strncmp(res->txrx, "rx", strlen("rx"))) {
		txrx = QEC_RX_CORR;
	} else {
		printf("wrong argument\r");
		return;
	}

	dc_i = strtof(res->dc_i, NULL);
	dc_q = strtof(res->dc_q, NULL);

/* converting float to uint32_t value triggers a strict-aliasing compiler error */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"

	/* send qec dco for tx or rx with given values, converted to uint32 storage (1 -> 0x3f800000*/
	cmd_do_qec_config(txrx, QEC_IQ_DC_OFFSET_CORR, MBOX_IQ_CORR_DC_I, *(uint32_t *) &dc_i);
	cmd_do_qec_config(txrx, QEC_IQ_DC_OFFSET_CORR, MBOX_IQ_CORR_DC_Q, *(uint32_t *) &dc_q);
#pragma GCC diagnostic pop
}

void cmd_config_qec_fdelay_parsed(void *parsed_result,
				  __attribute__((unused)) struct cmdline *cl,
				  __attribute__((unused)) void *data)
{
	struct cmd_config_qec_fdelay_result *res = parsed_result;
	uint32_t txrx;

	app_print_info("cmd_config_qec_fdelay_parsed: res->txrx = %s\n", res->txrx);
	app_print_info("cmd_config_qec_fdelay_parsed: res->fdelay = %d\n", res->fdelay);

	if (!strncmp(res->txrx, "tx", strlen("tx"))) {
		txrx = QEC_TX_CORR;
	} else if (!strncmp(res->txrx, "rx", strlen("rx"))) {
		txrx = QEC_RX_CORR;
	} else {
		printf("wrong argument\r");
		return;
	}

	/* send qec fractional delay for tx or rx with given values */
	cmd_do_qec_config(txrx, QEC_IQ_DC_OFFSET_CORR, MBOX_IQ_CORR_FDELAY, res->fdelay);
}

void cmd_config_qec_iqtaps_parsed(void *parsed_result,
				  __attribute__((unused)) struct cmdline *cl,
				  __attribute__((unused)) void *data)
{
	struct cmd_config_qec_iqtaps_result *res = parsed_result;
	uint32_t txrx;
	float iqtap_tmp_val;

	app_print_info("cmd_config_qec_iqtaps_parsed: res->txrx = %s\n", res->txrx);

	for (int i = 0; i <= MBOX_IQ_CORR_FTAP11; i++)
		app_print_info("cmd_config_qec_iqtaps_parsed: res->t[%d] = %s\n", i, res->t[i]);

	if (!strncmp(res->txrx, "tx", strlen("tx"))) {
		txrx = QEC_TX_CORR;
	} else if (!strncmp(res->txrx, "rx", strlen("rx"))) {
		txrx = QEC_RX_CORR;
	} else {
		printf("wrong argument\r");
		return;
	}

/* converting float to uint32_t value triggers a strict-aliasing compiler error */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"

	for (int i = 0; i <= MBOX_IQ_CORR_FTAP11; i++) {
		iqtap_tmp_val = strtof(res->t[i], NULL);
		app_print_info("iqtap_tmp_val[%d] = %f (%#x)\n", i, iqtap_tmp_val, *(uint32_t*)&iqtap_tmp_val);

		/* prevent flooding VSPA & M4 with messages */
		cmd_do_wait_response();
		/* send qec iq taps for tx or rx */
		cmd_do_qec_config(txrx, QEC_IQ_DC_OFFSET_CORR, i, *(uint32_t *) &iqtap_tmp_val);
	}
#pragma GCC diagnostic pop
}
