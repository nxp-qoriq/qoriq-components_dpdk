/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#ifndef __CMDLINE_H
#define __CMDLINE_H

#include <rte_common.h>
#include <cmdline.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_ipaddr.h>

#include <cmdline_rdline.h>
#include <cmdline_socket.h>
#include <cmdline_private.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <cmdline.h>
#include <termios.h>

/* Command line interface */

#define COMMAND_LIST \
	"\tquit\n" \
	"\thelp\n" \
	"\tfdd start/stop\n" \
	"\ttdd start/stop\n" \
	"\ttdd start/stop\n" \
	"\ttdd_tti start/stop\n" \
	"\ttdd config pattern <D/U>[start_sym:stop_sym],S[start_sym_dl:stop_sym_dl:start_sym_ul:stop_sym_ul],G,...\n" \
	"\ttdd config pattern_fr1fr2 <dl_slots,dl_syms,ul_slots,ul_syms,g_after_d,g_after_u> ...\n" \
	"\ttdd time-offset <value>\n" \
	"\ttdd config ul-time-advance <value>\n" \
	"\ttdd config tick keep-alive <0/1>\n" \
	"\ttdd sfn-slot set <sfn> <slot>\n" \
	"\ttdd sfn-slot delta <sfn_diff> <slot_diff>\n" \
	"\tconfig scs <scs>\n" \
	"\tconfig symbol_size <sym_size/128>\n" \
	"\tconfig rx ant <1-4>\n" \
	"\tconfig rx addr <rx_addr>\n" \
	"\tconfig rx sym_num <rx_sym_num>\n" \
	"\tconfig tx addr <tx_addr>\n" \
	"\tconfig tx sym_num <tx_sym_num>\n" \
	"\taxiq_lb enable/disable\n" \
	"\tconfig qec <tx/rx> passthrough\n" \
	"\tconfig qec <tx/rx> dc_offset <dc_i> <dc_q>\n" \
	"\tconfig qec <tx/rx> f_delay <value>\n" \
	"\tconfig qec <tx/rx> iq_taps [ 0 f2 h2(4) h1(4) h2(3) h1(3) h2(2) h1(2) h2(1) h1(1) h2(0) h1(0)]\n" \
	"\tvspa debug\n" \
	"\tvspa benchmark size <size_bytes> mode <read/write> dma <num of DMAs> iter <number of iterations>\n" \
	"\tvspa fr1fr2_test_tool host-handshake-bypass-flag <0/1>\n"

/* add your callbacks here */
extern void cmd_quit_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_help_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_fdd_start_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_fdd_stop_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_tdd_start_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_tdd_stop_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_tdd_tti_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_scs_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_symbol_size_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_rx_ant_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_rx_addr_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_rx_sym_num_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_tx_addr_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_tx_sym_num_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_axiq_lb_enable_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_axiq_lb_disable_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_debug_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_vspa_debug_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_vspa_benchmark_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_vspa_fr1fr2_tool_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_qec_pt_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_qec_dco_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_qec_fdelay_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_qec_iqtaps_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_tdd_config_pattern_new_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_tdd_config_tick_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_tdd_config_pattern_fr1fr2_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_tdd_config_ul_ta_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_tdd_time_offset_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_tdd_sfn_slot_parsed(void *parsed_result, struct cmdline *cl, void *data);

#if 0
extern void cmd_cell_search_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_cell_attach_parsed(void *parsed_result, struct cmdline *cl, void *data);
#endif
extern void cmd_rf_switch_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_tti_stats_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_wait_response_parsed(void *parsed_result, struct cmdline *cl, void *data);


struct cmd_wait_response_result {
	cmdline_fixed_string_t wait;
};

static cmdline_parse_token_string_t cmd_wait_wait_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_wait_response_result, wait, "wait");

static cmdline_parse_inst_t cmd_wait = {
	.f = cmd_wait_response_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_wait_wait_tok,
		NULL,
	}
};

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static cmdline_parse_token_string_t cmd_quit_quit_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

static cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_quit_quit_tok,
		NULL,
	}
};

struct cmd_help_result {
	cmdline_fixed_string_t help;
};

static cmdline_parse_token_string_t cmd_help_help_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_help_result, help, "help");

static cmdline_parse_inst_t cmd_help = {
	.f = cmd_help_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_help_help_tok,
		NULL,
	}
};

struct cmd_fdd_start_result {
	cmdline_fixed_string_t fdd;
	cmdline_fixed_string_t start;
};

static cmdline_parse_token_string_t cmd_fdd_start_fdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_fdd_start_result, fdd, "fdd");
static cmdline_parse_token_string_t cmd_fdd_start_start_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_fdd_start_result, start, "start");

static cmdline_parse_inst_t cmd_fdd_start = {
	.f = cmd_fdd_start_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_fdd_start_fdd_tok,
		(void *)&cmd_fdd_start_start_tok,
		NULL,
	}
};

struct cmd_fdd_stop_result {
	cmdline_fixed_string_t fdd;
	cmdline_fixed_string_t stop;
};

static cmdline_parse_token_string_t cmd_fdd_stop_fdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_fdd_stop_result, fdd, "fdd");
static cmdline_parse_token_string_t cmd_fdd_stop_stop_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_fdd_stop_result, stop, "stop");

static cmdline_parse_inst_t cmd_fdd_stop = {
	.f = cmd_fdd_stop_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_fdd_stop_fdd_tok,
		(void *)&cmd_fdd_stop_stop_tok,
		NULL,
	}
};

struct cmd_tdd_start_result {
	cmdline_fixed_string_t tdd;
	cmdline_fixed_string_t start;
};

static cmdline_parse_token_string_t cmd_tdd_start_tdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_start_result, tdd, "tdd");
static cmdline_parse_token_string_t cmd_tdd_start_start_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_start_result, start, "start");

static cmdline_parse_inst_t cmd_tdd_start = {
	.f = cmd_tdd_start_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tdd_start_tdd_tok,
		(void *)&cmd_tdd_start_start_tok,
		NULL,
	}
};

struct cmd_tdd_stop_result {
	cmdline_fixed_string_t tdd;
	cmdline_fixed_string_t stop;
};

static cmdline_parse_token_string_t cmd_tdd_stop_tdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_stop_result, tdd, "tdd");
static cmdline_parse_token_string_t cmd_tdd_stop_stop_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_stop_result, stop, "stop");

static cmdline_parse_inst_t cmd_tdd_stop = {
	.f = cmd_tdd_stop_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tdd_stop_tdd_tok,
		(void *)&cmd_tdd_stop_stop_tok,
		NULL,
	}
};

struct cmd_tdd_tti_result {
	cmdline_fixed_string_t tdd_tti;
	cmdline_fixed_string_t action;
};

static cmdline_parse_token_string_t cmd_tdd_tti_tdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_tti_result, tdd_tti, "tdd_tti");
static cmdline_parse_token_string_t cmd_tdd_tti_action_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_tti_result, action, "start#stop");

static cmdline_parse_inst_t cmd_tdd_tti = {
	.f = cmd_tdd_tti_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tdd_tti_tdd_tok,
		(void *)&cmd_tdd_tti_action_tok,
		NULL,
	}
};

struct cmd_config_scs_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t scs;
	cmdline_fixed_string_t scs_value;

};

static cmdline_parse_token_string_t cmd_config_scs_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_scs_result, config, "config");
static cmdline_parse_token_string_t cmd_config_scs_scs_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_scs_result, scs, "scs");
static cmdline_parse_token_string_t cmd_config_scs_scs_value_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_scs_result, scs_value, "15#30#60");

static cmdline_parse_inst_t cmd_config_scs = {
	.f = cmd_config_scs_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_scs_config_tok,
		(void *)&cmd_config_scs_scs_tok,
		(void *)&cmd_config_scs_scs_value_tok,
		NULL,
	}
};

struct cmd_config_symbol_size_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t symbol_size;
	uint16_t sym_size;
};

static cmdline_parse_token_string_t cmd_config_symbol_size_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_symbol_size_result, config, "config");
static cmdline_parse_token_string_t cmd_config_symbol_size_symbol_size_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_symbol_size_result, symbol_size, "symbol_size");
static cmdline_parse_token_num_t cmd_config_symbol_size_sym_size_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_config_symbol_size_result, sym_size, RTE_UINT16);

static cmdline_parse_inst_t cmd_config_symbol_size = {
	.f = cmd_config_symbol_size_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_symbol_size_config_tok,
		(void *)&cmd_config_symbol_size_symbol_size_tok,
		(void *)&cmd_config_symbol_size_sym_size_tok,
		NULL,
	}
};

struct cmd_config_rx_ant_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t rx;
	cmdline_fixed_string_t ant;
	uint32_t rx_antenna_mask;
};

static cmdline_parse_token_string_t cmd_config_rx_ant_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_ant_result, config, "config");
static cmdline_parse_token_string_t cmd_config_rx_ant_rx_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_ant_result, rx, "rx");
static cmdline_parse_token_string_t cmd_config_rx_ant_ant_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_ant_result, ant, "ant");
static cmdline_parse_token_num_t cmd_config_rx_ant_rx_antenna_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rx_ant_result, rx_antenna_mask, RTE_UINT32);

static cmdline_parse_inst_t cmd_config_rx_ant = {
	.f = cmd_config_rx_ant_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_rx_ant_config_tok,
		(void *)&cmd_config_rx_ant_rx_tok,
		(void *)&cmd_config_rx_ant_ant_tok,
		(void *)&cmd_config_rx_ant_rx_antenna_tok,
		NULL,
	}
};

struct cmd_config_rx_addr_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t rx;
	cmdline_fixed_string_t addr;
	uint32_t rx_addr;
};

static cmdline_parse_token_string_t cmd_config_rx_addr_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_addr_result, config, "config");
static cmdline_parse_token_string_t cmd_config_rx_addr_rx_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_addr_result, rx, "rx");
static cmdline_parse_token_string_t cmd_config_rx_addr_addr_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_addr_result, addr, "addr");
static cmdline_parse_token_num_t cmd_config_rx_addr_rx_addr_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rx_addr_result, rx_addr, RTE_UINT32);

static cmdline_parse_inst_t cmd_config_rx_addr = {
	.f = cmd_config_rx_addr_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_rx_addr_config_tok,
		(void *)&cmd_config_rx_addr_rx_tok,
		(void *)&cmd_config_rx_addr_addr_tok,
		(void *)&cmd_config_rx_addr_rx_addr_tok,
		NULL,
	}
};

struct cmd_config_rx_sym_num_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t rx;
	cmdline_fixed_string_t sym_num;
	uint32_t rx_sym_num;
};

static cmdline_parse_token_string_t cmd_config_rx_sym_num_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_sym_num_result, config, "config");
static cmdline_parse_token_string_t cmd_config_rx_sym_num_rx_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_sym_num_result, rx, "rx");
static cmdline_parse_token_string_t cmd_config_rx_sym_num_sym_num_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_sym_num_result, sym_num, "sym_num");
static cmdline_parse_token_num_t cmd_config_rx_sym_num_rx_sym_num_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rx_sym_num_result, rx_sym_num, RTE_UINT32);

static cmdline_parse_inst_t cmd_config_rx_sym_num = {
	.f = cmd_config_rx_sym_num_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_rx_sym_num_config_tok,
		(void *)&cmd_config_rx_sym_num_rx_tok,
		(void *)&cmd_config_rx_sym_num_sym_num_tok,
		(void *)&cmd_config_rx_sym_num_rx_sym_num_tok,
		NULL,
	}
};

struct cmd_config_tx_addr_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t addr;
	uint32_t tx_addr;
};

static cmdline_parse_token_string_t cmd_config_tx_addr_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tx_addr_result, config, "config");
static cmdline_parse_token_string_t cmd_config_tx_addr_tx_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tx_addr_result, tx, "tx");
static cmdline_parse_token_string_t cmd_config_tx_addr_addr_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tx_addr_result, addr, "addr");
static cmdline_parse_token_num_t cmd_config_tx_addr_tx_addr_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_config_tx_addr_result, tx_addr, RTE_UINT32);

static cmdline_parse_inst_t cmd_config_tx_addr = {
	.f = cmd_config_tx_addr_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_tx_addr_config_tok,
		(void *)&cmd_config_tx_addr_tx_tok,
		(void *)&cmd_config_tx_addr_addr_tok,
		(void *)&cmd_config_tx_addr_tx_addr_tok,
		NULL,
	}
};

struct cmd_config_tx_sym_num_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t sym_num;
	uint32_t tx_sym_num;
};

static cmdline_parse_token_string_t cmd_config_tx_sym_num_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tx_sym_num_result, config, "config");
static cmdline_parse_token_string_t cmd_config_tx_sym_num_tx_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tx_sym_num_result, tx, "tx");
static cmdline_parse_token_string_t cmd_config_tx_sym_num_sym_num_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tx_sym_num_result, sym_num, "sym_num");
static cmdline_parse_token_num_t cmd_config_tx_sym_num_tx_sym_num_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_config_tx_sym_num_result, tx_sym_num, RTE_UINT32);

static cmdline_parse_inst_t cmd_config_tx_sym_num = {
	.f = cmd_config_tx_sym_num_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_tx_sym_num_config_tok,
		(void *)&cmd_config_tx_sym_num_tx_tok,
		(void *)&cmd_config_tx_sym_num_sym_num_tok,
		(void *)&cmd_config_tx_sym_num_tx_sym_num_tok,
		NULL,
	}
};

struct cmd_axiq_lb_enable_result {
	cmdline_fixed_string_t axiq_lb;
	cmdline_fixed_string_t enable;
};

static cmdline_parse_token_string_t cmd_axiq_lb_enable_axiq_lb_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_axiq_lb_enable_result, axiq_lb, "axiq_lb");
static cmdline_parse_token_string_t cmd_axiq_lb_enable_enable_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_axiq_lb_enable_result, enable, "enable");

static cmdline_parse_inst_t cmd_axiq_lb_enable = {
	.f = cmd_axiq_lb_enable_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_axiq_lb_enable_axiq_lb_tok,
		(void *)&cmd_axiq_lb_enable_enable_tok,
		NULL,
	}
};

struct cmd_axiq_lb_disable_result {
	cmdline_fixed_string_t axiq_lb;
	cmdline_fixed_string_t disable;
};

static cmdline_parse_token_string_t cmd_axiq_lb_disable_axiq_lb_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_axiq_lb_disable_result, axiq_lb, "axiq_lb");
static cmdline_parse_token_string_t cmd_axiq_lb_disable_disable_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_axiq_lb_disable_result, disable, "disable");

static cmdline_parse_inst_t cmd_axiq_lb_disable = {
	.f = cmd_axiq_lb_disable_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_axiq_lb_disable_axiq_lb_tok,
		(void *)&cmd_axiq_lb_disable_disable_tok,
		NULL,
	}
};

struct cmd_debug_result {
	cmdline_fixed_string_t debug;
	uint32_t cmd;
};

static cmdline_parse_token_string_t cmd_debug_debug_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_debug_result, debug, "debug");
static cmdline_parse_token_num_t cmd_debug_cmd_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_debug_result, cmd, RTE_UINT32);

static cmdline_parse_inst_t cmd_debug = {
	.f = cmd_debug_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_debug_debug_tok,
		(void *)&cmd_debug_cmd_tok,
		NULL,
	}
};

struct cmd_vspa_debug_result {
	cmdline_fixed_string_t vspa;
	cmdline_fixed_string_t debug;
};

static cmdline_parse_token_string_t cmd_vspa_debug_vspa_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_debug_result, vspa, "vspa");
static cmdline_parse_token_string_t cmd_vspa_debug_debug_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_debug_result, debug, "debug");

static cmdline_parse_inst_t cmd_vspa_debug = {
	.f = cmd_vspa_debug_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_vspa_debug_vspa_tok,
		(void *)&cmd_vspa_debug_debug_tok,
		NULL,
	}
};

struct cmd_vspa_benchmark_result {
	cmdline_fixed_string_t vspa;
	cmdline_fixed_string_t benchmark;
	cmdline_fixed_string_t size;
	uint16_t size_bytes;
	cmdline_fixed_string_t mode;
	cmdline_fixed_string_t mode_rd_wr;
	cmdline_fixed_string_t dma_num;
	uint16_t parallel_dma_num;
	cmdline_fixed_string_t iterations;
	uint16_t iterations_num;

};

static cmdline_parse_token_string_t cmd_vspa_benchmark_size_vspa_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_benchmark_result, vspa, "vspa");
static cmdline_parse_token_string_t cmd_vspa_benchmark_size_benchmark_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_benchmark_result, benchmark, "benchmark");
static cmdline_parse_token_string_t cmd_vspa_benchmark_size_size_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_benchmark_result, size, "size");
static cmdline_parse_token_num_t cmd_vspa_benchmark_size_size_bytes_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_vspa_benchmark_result, size_bytes, RTE_UINT16);
static cmdline_parse_token_string_t cmd_vspa_benchmark_size_mode_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_benchmark_result, mode, "mode");
static cmdline_parse_token_string_t cmd_vspa_benchmark_size_mode_rd_wr_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_benchmark_result, mode_rd_wr, "read#write");
static cmdline_parse_token_string_t cmd_vspa_benchmark_size_dma_num_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_benchmark_result, dma_num, "dma");
static cmdline_parse_token_num_t cmd_vspa_benchmark_size_size_parallel_dma_num_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_vspa_benchmark_result, parallel_dma_num, RTE_UINT16);
static cmdline_parse_token_string_t cmd_vspa_benchmark_size_iterations_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_benchmark_result, iterations, "iter");
static cmdline_parse_token_num_t cmd_vspa_benchmark_size_size_iterations_num_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_vspa_benchmark_result, iterations_num, RTE_UINT16);

static cmdline_parse_inst_t cmd_vspa_benchmark = {
	.f = cmd_vspa_benchmark_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_vspa_benchmark_size_vspa_tok,
		(void *)&cmd_vspa_benchmark_size_benchmark_tok,
		(void *)&cmd_vspa_benchmark_size_size_tok,
		(void *)&cmd_vspa_benchmark_size_size_bytes_tok,
		(void *)&cmd_vspa_benchmark_size_mode_tok,
		(void *)&cmd_vspa_benchmark_size_mode_rd_wr_tok,
		(void *)&cmd_vspa_benchmark_size_dma_num_tok,
		(void *)&cmd_vspa_benchmark_size_size_parallel_dma_num_tok,
		(void *)&cmd_vspa_benchmark_size_iterations_tok,
		(void *)&cmd_vspa_benchmark_size_size_iterations_num_tok,
		NULL,
	}
};

struct cmd_vspa_fr1fr2_tool_result {
	cmdline_fixed_string_t vspa;
	cmdline_fixed_string_t fr1fr2_test_tool;
	cmdline_fixed_string_t host_bypass_flag;
	uint16_t flag;
};

static cmdline_parse_token_string_t cmd_vspa_fr1fr2_tool_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_fr1fr2_tool_result, vspa, "vspa");
static cmdline_parse_token_string_t cmd_vspa_fr1fr2_test_tool_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_fr1fr2_tool_result, fr1fr2_test_tool, "fr1fr2_test_tool");
static cmdline_parse_token_string_t cmd_vspa_fr1fr2_tool_host_flag_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_vspa_fr1fr2_tool_result, host_bypass_flag, "host-handshake-bypass-flag");
static cmdline_parse_token_num_t cmd_vspa_handshake_flag_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_vspa_fr1fr2_tool_result, flag, RTE_UINT16);

static cmdline_parse_inst_t cmd_vspa_fr1fr2 = {
	.f = cmd_vspa_fr1fr2_tool_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_vspa_fr1fr2_tool_tok,
		(void *)&cmd_vspa_fr1fr2_test_tool_tok,
		(void *)&cmd_vspa_fr1fr2_tool_host_flag_tok,
		(void *)&cmd_vspa_handshake_flag_tok,
		NULL,
	}
};

struct cmd_config_qec_pt_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t qec;
	cmdline_fixed_string_t txrx;
	cmdline_fixed_string_t passthrough;
};

static cmdline_parse_token_string_t cmd_config_qec_config_pt_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_pt_result, config, "config");
static cmdline_parse_token_string_t cmd_config_qec_qec_pt_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_pt_result, qec, "qec");
static cmdline_parse_token_string_t cmd_config_qec_txrx_pt_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_pt_result, txrx, NULL);
static cmdline_parse_token_string_t cmd_config_qec_passthrough_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_pt_result, passthrough, "passthrough");

static cmdline_parse_inst_t cmd_config_qec_pt = {
	.f = cmd_config_qec_pt_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_qec_config_pt_tok,
		(void *)&cmd_config_qec_qec_pt_tok,
		(void *)&cmd_config_qec_txrx_pt_tok,
		(void *)&cmd_config_qec_passthrough_tok,
		NULL,
	}
};

struct cmd_config_qec_dco_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t qec_dco;
	cmdline_fixed_string_t txrx;
	cmdline_fixed_string_t dc_offset;
	cmdline_fixed_string_t dc_i;
	cmdline_fixed_string_t dc_q;
};

static cmdline_parse_token_string_t cmd_config_qec_dco_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_dco_result, config, "config");
static cmdline_parse_token_string_t cmd_config_qec_dco_qec_dco_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_dco_result, qec_dco, "qec");
static cmdline_parse_token_string_t cmd_config_qec_dco_txrx_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_dco_result, txrx, "tx#rx");
static cmdline_parse_token_string_t cmd_config_qec_dco_dc_offset_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_dco_result, dc_offset, "dc_offset");
static cmdline_parse_token_string_t cmd_config_qec_dco_dc_i_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_dco_result, dc_i, NULL);
static cmdline_parse_token_string_t cmd_config_qec_dco_dc_q_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_dco_result, dc_q, NULL);

static cmdline_parse_inst_t cmd_config_qec_dco = {
	.f = cmd_config_qec_dco_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_qec_dco_config_tok,
		(void *)&cmd_config_qec_dco_qec_dco_tok,
		(void *)&cmd_config_qec_dco_txrx_tok,
		(void *)&cmd_config_qec_dco_dc_offset_tok,
		(void *)&cmd_config_qec_dco_dc_i_tok,
		(void *)&cmd_config_qec_dco_dc_q_tok,
		NULL,
	}
};

struct cmd_config_qec_fdelay_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t qec_fdelay;
	cmdline_fixed_string_t txrx;
	cmdline_fixed_string_t f_delay;
	uint32_t fdelay;
};

static cmdline_parse_token_string_t cmd_config_qec_fdelay_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_fdelay_result, config, "config");
static cmdline_parse_token_string_t cmd_config_qec_fdelay_qec_fdelay_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_fdelay_result, qec_fdelay, "qec");
static cmdline_parse_token_string_t cmd_config_qec_fdelay_txrx_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_fdelay_result, txrx, "tx#rx");
static cmdline_parse_token_string_t cmd_config_qec_fdelay_f_delay_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_fdelay_result, f_delay, "f_delay");
static cmdline_parse_token_num_t cmd_config_qec_fdelay_fdelay_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_config_qec_fdelay_result, fdelay, RTE_UINT32);

static cmdline_parse_inst_t cmd_config_qec_fdelay = {
	.f = cmd_config_qec_fdelay_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_qec_fdelay_config_tok,
		(void *)&cmd_config_qec_fdelay_qec_fdelay_tok,
		(void *)&cmd_config_qec_fdelay_txrx_tok,
		(void *)&cmd_config_qec_fdelay_f_delay_tok,
		(void *)&cmd_config_qec_fdelay_fdelay_tok,
		NULL,
	}
};

struct cmd_config_qec_iqtaps_result {
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t qec_iqtaps;
	cmdline_fixed_string_t txrx;
	cmdline_fixed_string_t iq_taps;
	cmdline_fixed_string_t array_start;
	cmdline_fixed_string_t t[12];
	cmdline_fixed_string_t array_end;
};

static cmdline_parse_token_string_t cmd_config_qec_iqtaps_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, config, "config");
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_qec_iqtaps_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, qec_iqtaps, "qec");
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_txrx_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, txrx, "tx#rx");
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_iq_taps_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, iq_taps, "iq_taps");
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_array_start_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, array_start, "[");
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t0_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[0], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t1_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[1], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t2_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[2], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t3_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[3], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t4_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[4], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t5_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[5], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t6_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[6], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t7_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[7], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t8_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[8], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t9_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[9], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t10_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[10], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_t11_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, t[11], NULL);
static cmdline_parse_token_string_t cmd_config_qec_iqtaps_array_end_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_qec_iqtaps_result, array_end, "]");

static cmdline_parse_inst_t cmd_config_qec_iqtaps = {
	.f = cmd_config_qec_iqtaps_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_config_qec_iqtaps_config_tok,
		(void *)&cmd_config_qec_iqtaps_qec_iqtaps_tok,
		(void *)&cmd_config_qec_iqtaps_txrx_tok,
		(void *)&cmd_config_qec_iqtaps_iq_taps_tok,
		(void *)&cmd_config_qec_iqtaps_array_start_tok,
		(void *)&cmd_config_qec_iqtaps_t0_tok,
		(void *)&cmd_config_qec_iqtaps_t1_tok,
		(void *)&cmd_config_qec_iqtaps_t2_tok,
		(void *)&cmd_config_qec_iqtaps_t3_tok,
		(void *)&cmd_config_qec_iqtaps_t4_tok,
		(void *)&cmd_config_qec_iqtaps_t5_tok,
		(void *)&cmd_config_qec_iqtaps_t6_tok,
		(void *)&cmd_config_qec_iqtaps_t7_tok,
		(void *)&cmd_config_qec_iqtaps_t8_tok,
		(void *)&cmd_config_qec_iqtaps_t9_tok,
		(void *)&cmd_config_qec_iqtaps_t10_tok,
		(void *)&cmd_config_qec_iqtaps_t11_tok,
		(void *)&cmd_config_qec_iqtaps_array_end_tok,
		NULL,
	}
};

struct cmd_tdd_config_pattern_new_result {
	cmdline_fixed_string_t tdd;
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t pattern_new;
	cmdline_fixed_string_t args;
};

static cmdline_parse_token_string_t cmd_tdd_config_pattern_new_tdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_new_result, tdd, "tdd");
static cmdline_parse_token_string_t cmd_tdd_config_pattern_new_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_new_result, config, "config");
static cmdline_parse_token_string_t cmd_tdd_config_pattern_pattern_new_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_new_result, pattern_new, "pattern");
static cmdline_parse_token_string_t cmd_tdd_config_pattern_new_args_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_new_result, args, NULL);

static cmdline_parse_inst_t cmd_tdd_config_pattern_new = {
	.f = cmd_tdd_config_pattern_new_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tdd_config_pattern_new_tdd_tok,
		(void *)&cmd_tdd_config_pattern_new_config_tok,
		(void *)&cmd_tdd_config_pattern_pattern_new_tok,
		(void *)&cmd_tdd_config_pattern_new_args_tok,
		NULL,
	}
};

struct cmd_tdd_config_pattern_fr1fr2_result {
	cmdline_fixed_string_t tdd;
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t pattern_fr1fr2;
	cmdline_fixed_string_t args;
};

static cmdline_parse_token_string_t cmd_tdd_config_pattern_fr1fr2_tdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_fr1fr2_result, tdd, "tdd");
static cmdline_parse_token_string_t cmd_tdd_config_pattern_fr1fr2_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_fr1fr2_result, config, "config");
static cmdline_parse_token_string_t cmd_tdd_config_pattern_pattern_fr1fr2_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_fr1fr2_result, pattern_fr1fr2, "pattern_fr1fr2");
static cmdline_parse_token_string_t cmd_tdd_config_pattern_fr1fr2_args_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_fr1fr2_result, args, NULL);

static cmdline_parse_inst_t cmd_tdd_config_pattern_fr1fr2 = {
	.f = cmd_tdd_config_pattern_fr1fr2_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tdd_config_pattern_fr1fr2_tdd_tok,
		(void *)&cmd_tdd_config_pattern_fr1fr2_config_tok,
		(void *)&cmd_tdd_config_pattern_pattern_fr1fr2_tok,
		(void *)&cmd_tdd_config_pattern_fr1fr2_args_tok,
		NULL,
	}
};

struct cmd_tdd_config_tick_result {
	cmdline_fixed_string_t tdd;
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t tick;
	cmdline_fixed_string_t keepalive;
	cmdline_fixed_string_t args;
};

static cmdline_parse_token_string_t cmd_tdd_config_tick_tdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_tick_result, tdd, "tdd");
static cmdline_parse_token_string_t cmd_tdd_config_tick_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_tick_result, config, "config");
static cmdline_parse_token_string_t cmd_tdd_config_tick_tick_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_tick_result, tick, "tick");
static cmdline_parse_token_string_t cmd_tdd_config_tick_keepalive_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_tick_result, keepalive, "keep-alive");
static cmdline_parse_token_string_t cmd_tdd_config_tick_args_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_tick_result, args, "0#1");

static cmdline_parse_inst_t cmd_tdd_config_tick = {
	.f = cmd_tdd_config_tick_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tdd_config_tick_tdd_tok,
		(void *)&cmd_tdd_config_tick_config_tok,
		(void *)&cmd_tdd_config_tick_tick_tok,
		(void *)&cmd_tdd_config_tick_keepalive_tok,
		(void *)&cmd_tdd_config_tick_args_tok,
		NULL,
	}
};

struct cmd_tdd_config_ta_result {
	cmdline_fixed_string_t tdd;
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t ul_ta;
	uint32_t ta;
};

static cmdline_parse_token_string_t cmd_tdd_config_ta_tdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_ta_result, tdd, "tdd");
static cmdline_parse_token_string_t cmd_tdd_config_ta_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_ta_result, config, "config");
static cmdline_parse_token_string_t cmd_tdd_config_ta_ul_ta_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_ta_result, ul_ta, "ul-time-advance");
static cmdline_parse_token_num_t cmd_tdd_config_ta_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_config_ta_result, ta, RTE_UINT32);

static cmdline_parse_inst_t cmd_tdd_config_ta = {
	.f = cmd_tdd_config_ul_ta_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tdd_config_ta_tdd_tok,
		(void *)&cmd_tdd_config_ta_config_tok,
		(void *)&cmd_tdd_config_ta_ul_ta_tok,
		(void *)&cmd_tdd_config_ta_tok,
		NULL,
	}
};

struct cmd_tdd_time_offset_result {
	cmdline_fixed_string_t tdd;
	cmdline_fixed_string_t time_offset;
	int32_t to;
};

static cmdline_parse_token_string_t cmd_tdd_time_offset_tdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_time_offset_result, tdd, "tdd");
static cmdline_parse_token_string_t cmd_tdd_time_offset_time_offset_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_time_offset_result, time_offset, "time-offset");
static cmdline_parse_token_num_t cmd_tdd_time_offset_to_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_time_offset_result, to, RTE_INT32);

static cmdline_parse_inst_t cmd_tdd_time_offset = {
	.f = cmd_tdd_time_offset_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tdd_time_offset_tdd_tok,
		(void *)&cmd_tdd_time_offset_time_offset_tok,
		(void *)&cmd_tdd_time_offset_to_tok,
		NULL,
	}
};

struct cmd_tdd_sfn_slot_result {
	cmdline_fixed_string_t tdd;
	cmdline_fixed_string_t sfn_slot;
	cmdline_fixed_string_t action;
	int32_t sfn;
	int32_t slot;
};

enum cmd_tdd_sfn_slot_action {
	CLI_TDD_CONFIG_SFN_SLOT_SET,
	CLI_TDD_CONFIG_SFN_SLOT_DELTA,
};

static cmdline_parse_token_string_t cmd_tdd_sfn_slot_tdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_sfn_slot_result, tdd, "tdd");
static cmdline_parse_token_string_t cmd_tdd_sfn_slot_sfn_slot_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_sfn_slot_result, sfn_slot, "sfn-slot");
static cmdline_parse_token_string_t cmd_tdd_sfn_slot_action_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_sfn_slot_result, action, "set#delta");
static cmdline_parse_token_num_t cmd_tdd_sfn_slot_sfn_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_sfn_slot_result, sfn, RTE_INT32);
static cmdline_parse_token_num_t cmd_tdd_sfn_slot_slot_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_sfn_slot_result, slot, RTE_INT32);

static cmdline_parse_inst_t cmd_tdd_sfn_slot = {
	.f = cmd_tdd_sfn_slot_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tdd_sfn_slot_tdd_tok,
		(void *)&cmd_tdd_sfn_slot_sfn_slot_tok,
		(void *)&cmd_tdd_sfn_slot_action_tok,
		(void *)&cmd_tdd_sfn_slot_sfn_tok,
		(void *)&cmd_tdd_sfn_slot_slot_tok,
		NULL,
	}
};

#if 0 /* future */
struct cmd_cell_search_result {
	cmdline_fixed_string_t cell ;
	cmdline_fixed_string_t search;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t args;
};

static cmdline_parse_token_string_t cmd_cell_search_cell_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_cell_search_result, cell, "cell");
static cmdline_parse_token_string_t cmd_cell_search_search_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_cell_search_result, search, "search");
static cmdline_parse_token_string_t cmd_cell_search_cell_action_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_cell_search_result, action, "start#stop");
static cmdline_parse_token_string_t cmd_cell_search_cell_args_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_cell_search_result, args, NULL);

static cmdline_parse_inst_t cmd_cell_search = {
	.f = cmd_cell_search_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_cell_search_cell_tok,
		(void *)&cmd_cell_search_search_tok,
		(void *)&cmd_cell_search_cell_action_tok,
		(void *)&cmd_cell_search_cell_args_tok,
		NULL,
	}
};

struct cmd_cell_attach_result {
	cmdline_fixed_string_t cell ;
	cmdline_fixed_string_t attach;
	uint16_t sfn;
	uint16_t slot;
};

static cmdline_parse_token_string_t cmd_cell_attach_cell_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_cell_attach_result, cell, "cell");
static cmdline_parse_token_string_t cmd_cell_attach_search_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_cell_attach_result, attach, "attach");
static cmdline_parse_token_num_t cmd_cell_attach_sfn_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_cell_attach_result, sfn, RTE_UINT16);
static cmdline_parse_token_num_t cmd_cell_attach_slot_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_cell_attach_result, slot, RTE_UINT16);

static cmdline_parse_inst_t cmd_cell_attach = {
	.f = cmd_cell_attach_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_cell_attach_cell_tok,
		(void *)&cmd_cell_attach_search_tok,
		(void *)&cmd_cell_attach_sfn_tok,
		(void *)&cmd_cell_attach_slot_tok,
		NULL,
	}
};
#endif

struct cmd_rf_switch_result {
	cmdline_fixed_string_t rf_switch ;
	cmdline_fixed_string_t action;
};

static cmdline_parse_token_string_t cmd_rf_switch_rf_switch_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_rf_switch_result, rf_switch, "rf_switch");
static cmdline_parse_token_string_t cmd_rf_switch_action_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_rf_switch_result, action, "tx#rx");


static cmdline_parse_inst_t cmd_rf_switch = {
	.f = cmd_rf_switch_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_rf_switch_rf_switch_tok,
		(void *)&cmd_rf_switch_action_tok,
		NULL,
	}
};

struct cmd_tti_stats_result {
	cmdline_fixed_string_t tti_stats ;
};

static cmdline_parse_token_string_t cmd_tti_stats_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tti_stats_result, tti_stats, "tti_stats");

static cmdline_parse_inst_t cmd_tti_stats = {
	.f = cmd_tti_stats_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tti_stats_tok,
		NULL,
	}
};

static __rte_used cmdline_parse_ctx_t ctx[] = {
	&cmd_quit,
	&cmd_help,
	&cmd_wait,
	&cmd_fdd_start,
	&cmd_fdd_stop,
	&cmd_tdd_start,
	&cmd_tdd_stop,
	&cmd_config_scs,
	&cmd_config_symbol_size,
	&cmd_config_rx_ant,
	&cmd_config_rx_addr,
	&cmd_config_rx_sym_num,
	&cmd_config_tx_addr,
	&cmd_config_tx_sym_num,
	&cmd_axiq_lb_enable,
	&cmd_axiq_lb_disable,
	&cmd_vspa_debug,
	&cmd_vspa_benchmark,
	&cmd_vspa_fr1fr2,
	&cmd_config_qec_pt,
	&cmd_config_qec_dco,
	&cmd_config_qec_fdelay,
	&cmd_config_qec_iqtaps,
	&cmd_tdd_config_pattern_new,
	&cmd_tdd_config_pattern_fr1fr2,
	&cmd_tdd_config_tick,
	&cmd_tdd_config_ta,
	&cmd_tdd_time_offset,
	&cmd_tdd_sfn_slot,
#if 0 /* future */
	&cmd_cell_search,
	&cmd_cell_attach,
#endif
	&cmd_rf_switch,
	&cmd_tdd_tti,
	&cmd_tti_stats,
	&cmd_debug,
	NULL
};

#endif
