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
cmd_tdd_config_pattern_parsed(void *parsed_result,
			      __attribute__((unused)) struct cmdline *cl,
			      __attribute__((unused)) void *data)
{
	struct cmd_tdd_config_pattern_result *res = parsed_result;

	cmd_do_config_pattern(res->scs,
			res->dl1,
			res->g1,
			res->ul1,
			res->g2,
			res->ul2,
			res->g3);

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
