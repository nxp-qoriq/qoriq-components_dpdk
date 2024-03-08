/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#ifndef __IPC_H
#define __IPC_H

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_malloc.h>
#include <rte_string_fns.h>
#include <rte_bbdev.h>
#include <rte_cycles.h>
#include <rte_errno.h>

#define ENQUEUE_RETRIES         100
#define GET_BUF_RETRIES         10

extern uint32_t dev_id;

int init_bbdev(void);
int dfe_init(void);
void dfe_free(void);

int send_msg(void *msg, uint32_t len);

void *get_tx_buf(int qid);

#endif
