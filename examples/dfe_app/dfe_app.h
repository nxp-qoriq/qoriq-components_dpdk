/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#ifndef __DFE_APP_H
#define __DFE_APP_H

#include <rte_memory.h>
#include <rte_bbdev.h>

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

/* BBDEV */
#define BBDEV_QUEUE_COUNT		2
#define OPS_POOL_SIZE			16
#define OPS_CACHE_SIZE			4

#define DFE_NO_OF_RETRIES		(210)
#define DFE_CF_NO_OF_RETRIES		(3 * DFE_NO_OF_RETRIES)

/* app specific */
struct dfe_state {
	rte_atomic16_t initialized;	/* dfe_init() can only be called once */
	rte_atomic16_t is_active;	/* card state */
	rte_atomic16_t do_poll;
	rte_atomic16_t do_tti_poll;
	unsigned int ipc_lcore;
	unsigned int tti_lcore;
	uint8_t stop_in_progress;
	uint8_t reset_in_progress;
	uint8_t reset_via_timeout;
	uint32_t crt_cmd;
};

extern struct dfe_state state;
extern uint32_t tti_irq_count;

void process_msg_from_modem(struct rte_bbdev_op_data *in_buf);
void signal_ipc_reset(void);

void cmd_do_wait_response(void);
void cmd_do_simple(int msg_type, const char *desc);
void cmd_do_config_pattern_new(uint32_t p0, uint32_t p1, uint32_t p2, uint32_t p3, uint32_t p4, uint32_t p5, uint32_t p6, uint32_t p7);
void cmd_do_config_scs(uint32_t scs);
void cmd_do_vspa_benchmark(uint32_t size_bytes, uint32_t mode, uint32_t parallel_dma_num, uint32_t iterations);
void cmd_do_vspa_fr1fr2_tool(uint16_t param);
void cmd_do_tx_rx_sym_nr_config(int msg_type_tx_rx_sym_nr, uint32_t num_syms_in_buffer);
void cmd_do_tx_rx_addr_config(int msg_type_tx_rx_addr, uint32_t addr);
void cmd_do_sym_size_config(uint32_t sym_size);
void cmd_do_rx_antenna_config(uint32_t rx_antenna);
void cmd_do_qec_config(uint32_t tx_rx, uint32_t mode, uint32_t index, uint32_t value);
void cmd_do_config_tick_keepalive(uint32_t keepalive);
void cmd_do_config_ul_ta(uint32_t ta);
void cmd_do_config_time_offset(uint32_t time_offset);
void cmd_do_config_sfn_slot(/*enum cmd_tdd_sfn_slot_action*/ uint32_t cmd_action, int32_t sfn, int32_t slot);
void cmd_do_debug(uint32_t cmd, const char *desc);
void reset_tti_stats(void);
void dump_tti_stats(void);
int rte_sys_get_tid(void);
void assign_to_core(int core_id);
#endif
