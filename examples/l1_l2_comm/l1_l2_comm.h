/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022-2024 NXP
 * Code was mostly borrowed from examples/l3fwd/l3fwd.h
 * See examples/l3fwd/l3fwd.h for additional Copyrights.
 */

#ifndef __L1_L2_COMM_H__
#define __L1_L2_COMM_H__

#define MAX_PKT_BURST     32

struct perf_statistic {
	uint64_t packets;
	uint64_t bytes;
};

#include "rte_tm.h"

struct data_loop_conf {
	struct rte_ring *mbuf_ring;
	uint64_t cyc_diff_total;
	double avg_latency;
	double max_latency;
	double min_latency;
	int valid_latency;
	struct perf_statistic tx_statistic;
	struct perf_statistic rx_statistic;
} __rte_cache_aligned;

#endif  /* __L1_L2_COMM_H__ */
