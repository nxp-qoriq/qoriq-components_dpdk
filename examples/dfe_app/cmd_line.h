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
	"\ttdd config pattern <scs> <dl1> <g1> <ul1> <dl2> <g2> <ul2>\n" \
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
extern void cmd_tdd_config_pattern_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_symbol_size_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_rx_ant_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_rx_addr_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_rx_sym_num_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_tx_addr_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_tx_sym_num_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_axiq_lb_enable_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_axiq_lb_disable_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_vspa_debug_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_vspa_benchmark_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_vspa_fr1fr2_tool_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_qec_pt_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_qec_dco_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_qec_fdelay_parsed(void *parsed_result, struct cmdline *cl, void *data);
extern void cmd_config_qec_iqtaps_parsed(void *parsed_result, struct cmdline *cl, void *data);
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

struct cmd_tdd_config_pattern_result {
	cmdline_fixed_string_t tdd;
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t pattern;
	uint16_t scs;
	uint16_t dl1;
	uint16_t g1;
	uint16_t ul1;
	uint16_t dl2;
	uint16_t g2;
	uint16_t ul2;
};

static cmdline_parse_token_string_t cmd_tdd_config_pattern_tdd_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_result, tdd, "tdd");
static cmdline_parse_token_string_t cmd_tdd_config_pattern_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_result, config, "config");
static cmdline_parse_token_string_t cmd_tdd_config_pattern_pattern_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_tdd_config_pattern_result, pattern, "pattern");
static cmdline_parse_token_num_t cmd_tdd_config_pattern_scs_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_config_pattern_result, scs, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdd_config_pattern_dl1_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_config_pattern_result, dl1, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdd_config_pattern_g1_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_config_pattern_result, g1, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdd_config_pattern_ul1_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_config_pattern_result, ul1, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdd_config_pattern_dl2_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_config_pattern_result, dl2, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdd_config_pattern_g2_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_config_pattern_result, g2, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdd_config_pattern_ul2_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_tdd_config_pattern_result, ul2, RTE_UINT16);

static cmdline_parse_inst_t cmd_tdd_config_pattern = {
	.f = cmd_tdd_config_pattern_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *)&cmd_tdd_config_pattern_tdd_tok,
		(void *)&cmd_tdd_config_pattern_config_tok,
		(void *)&cmd_tdd_config_pattern_pattern_tok,
		(void *)&cmd_tdd_config_pattern_scs_tok,
		(void *)&cmd_tdd_config_pattern_dl1_tok,
		(void *)&cmd_tdd_config_pattern_g1_tok,
		(void *)&cmd_tdd_config_pattern_ul1_tok,
		(void *)&cmd_tdd_config_pattern_dl2_tok,
		(void *)&cmd_tdd_config_pattern_g2_tok,
		(void *)&cmd_tdd_config_pattern_ul2_tok,
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
	uint16_t rx_antenna;
};

static cmdline_parse_token_string_t cmd_config_rx_ant_config_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_ant_result, config, "config");
static cmdline_parse_token_string_t cmd_config_rx_ant_rx_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_ant_result, rx, "rx");
static cmdline_parse_token_string_t cmd_config_rx_ant_ant_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_ant_result, ant, "ant");
static cmdline_parse_token_num_t cmd_config_rx_ant_rx_antenna_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rx_ant_result, rx_antenna, RTE_UINT16);

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

static __rte_used cmdline_parse_ctx_t ctx[] = {
	&cmd_quit,
	&cmd_help,
	&cmd_wait,
	&cmd_fdd_start,
	&cmd_fdd_stop,
	&cmd_tdd_start,
	&cmd_tdd_stop,
	&cmd_tdd_config_pattern,
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
	NULL
};

#endif
