/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 * Copyright 2020-2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_launch.h>
#include <rte_bbdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_hexdump.h>
#include <rte_interrupts.h>
#include <rte_pmd_bbdev_la12xx.h>
#include <rte_bbuf.h>

#ifdef RTE_LIBRTE_PMD_BBDEV_FPGA_LTE_FEC
#include <fpga_lte_fec.h>
#endif

#include "main.h"
#include "test_bbdev_vector.h"

#define GET_SOCKET(socket_id) (((socket_id) == SOCKET_ID_ANY) ? 0 : (socket_id))

/* None device Macros */
struct rte_mempool *bbdev_bbuf_pool;
/* BBUF pool related counts */
#define BBUF_POOL_CACHE_SIZE    0
#define POISON 0x12

#define MAX_QUEUES RTE_MAX_LCORE
/* Keeping repetition as odd number so that
 * reset is properly verified.
 */
#define TEST_REPETITIONS 10009

#ifdef RTE_LIBRTE_PMD_BBDEV_FPGA_LTE_FEC
#define FPGA_PF_DRIVER_NAME ("intel_fpga_lte_fec_pf")
#define FPGA_VF_DRIVER_NAME ("intel_fpga_lte_fec_vf")
#define VF_UL_QUEUE_VALUE 4
#define VF_DL_QUEUE_VALUE 4
#define UL_BANDWIDTH 3
#define DL_BANDWIDTH 3
#define UL_LOAD_BALANCE 128
#define DL_LOAD_BALANCE 128
#define FLR_TIMEOUT 610
#endif

#define OPS_CACHE_SIZE 256U
#define OPS_POOL_SIZE_MIN 511U /* 0.5K per queue */

#define SYNC_WAIT 0
#define SYNC_START 1

#define INVALID_QUEUE_ID -1

static struct test_bbdev_vector test_vector[MAX_VECTORS];

/* Switch between PMD and Interrupt for throughput TC */
static bool intr_enabled;

/* Sync for SD-CD demux case. Currenlty there is a limitation that
 * we need to submit SD job and gets its output, before sending the
 * CD command. This variable is to synchronize the same.
 */
rte_atomic16_t sd_cd_demux_sync_var;
rte_atomic16_t se_ce_mux_sync_var;
int ack_sync_var;
int csi1_sync_var;
int csi2_sync_var;
int num_polar_decode_tests;

/* Flag in case llr input scaling is required */
int scale_llr_input;

/* Represents tested active devices */
static struct active_device {
	const char *driver_name;
	uint8_t dev_id;
	uint16_t supported_ops;
	uint16_t queue_ids[MAX_QUEUES];
	uint16_t nb_queues;
	struct rte_mempool *ops_mempool[RTE_BBDEV_OP_TYPE_COUNT];
	struct rte_mempool *in_bbuf_pool;
	struct rte_mempool *hard_out_bbuf_pool;
	struct rte_mempool *partial_out_bbuf_pool;
	struct rte_mempool *soft_out_bbuf_pool;
	struct rte_mempool *harq_in_bbuf_pool;
	struct rte_mempool *harq_out_bbuf_pool;
} active_devs[RTE_BBDEV_MAX_DEVS];

static uint8_t nb_active_devs;

/* Data buffers used by BBDEV ops */
struct test_buffers {
	struct rte_bbdev_op_data *inputs;
	struct rte_bbdev_op_data *hard_outputs;
	struct rte_bbdev_op_data *partial_outputs;
	struct rte_bbdev_op_data *soft_outputs;
	struct rte_bbdev_op_data *harq_inputs;
	struct rte_bbdev_op_data *harq_outputs;
};

/* Operation parameters specific for given test case */
struct test_op_params {
	struct rte_mempool *mp;
	struct rte_bbdev_dec_op *ref_dec_op;
	struct rte_bbdev_enc_op *ref_enc_op;
	struct rte_pmd_la12xx_op *ref_la12xx_op;
	uint16_t burst_sz;
	uint16_t num_to_process;
	uint16_t num_lcores;
	uint64_t vector_mask;
	struct test_bbdev_vector *vector;
	rte_atomic16_t sync;
	struct test_buffers q_bufs[RTE_MAX_NUMA_NODES][MAX_QUEUES];
};

/* Contains per lcore params */
struct thread_params {
	uint8_t dev_id;
	uint16_t queue_id;
	uint32_t lcore_id;
	uint64_t start_time;
	double ops_per_sec;
	double mbps;
	uint64_t iter_count;
	rte_atomic16_t nb_dequeued;
	rte_atomic16_t processing_status;
	rte_atomic16_t burst_sz;
	struct test_op_params *op_params;
	struct rte_bbdev_dec_op *dec_ops[MAX_BURST];
	struct rte_bbdev_enc_op *enc_ops[MAX_BURST];
	struct rte_pmd_la12xx_op *polar_ops[MAX_BURST];
	uint64_t *total_time;
	uint64_t *min_time;
	uint64_t *max_time;
};

#ifdef RTE_BBDEV_OFFLOAD_COST
/* Stores time statistics */
struct test_time_stats {
	/* Stores software enqueue total working time */
	uint64_t enq_sw_total_time;
	/* Stores minimum value of software enqueue working time */
	uint64_t enq_sw_min_time;
	/* Stores maximum value of software enqueue working time */
	uint64_t enq_sw_max_time;
	/* Stores turbo enqueue total working time */
	uint64_t enq_acc_total_time;
	/* Stores minimum value of accelerator enqueue working time */
	uint64_t enq_acc_min_time;
	/* Stores maximum value of accelerator enqueue working time */
	uint64_t enq_acc_max_time;
	/* Stores dequeue total working time */
	uint64_t deq_total_time;
	/* Stores minimum value of dequeue working time */
	uint64_t deq_min_time;
	/* Stores maximum value of dequeue working time */
	uint64_t deq_max_time;
};
#endif

typedef int (test_case_function)(struct active_device *ad,
		struct test_op_params *op_params);

static inline void
bbuf_reset(struct rte_bbuf *b)
{
	uint8_t *data;

	b->pkt_len = 0;

	do {
		data = rte_bbuf_mtod(b, uint8_t *);
		memset(data, 0, b->pkt_len);
		b->data_len = 0;
		b = b->next;
	} while (b != NULL);
}

/* Read flag value 0/1 from bitmap */
static inline bool
check_bit(uint32_t bitmap, uint32_t bitmask)
{
	return bitmap & bitmask;
}

static inline void
set_avail_op(struct active_device *ad, enum rte_bbdev_op_type op_type)
{
	ad->supported_ops |= (1 << op_type);
}

static inline bool
is_avail_op(struct active_device *ad, enum rte_bbdev_op_type op_type)
{
	return ad->supported_ops & (1 << op_type);
}

static inline bool
flags_match(uint32_t flags_req, uint32_t flags_present)
{
	return (flags_req & flags_present) == flags_req;
}

static void
clear_soft_out_cap(uint32_t *op_flags)
{
	*op_flags &= ~RTE_BBDEV_TURBO_SOFT_OUTPUT;
	*op_flags &= ~RTE_BBDEV_TURBO_POS_LLR_1_BIT_SOFT_OUT;
	*op_flags &= ~RTE_BBDEV_TURBO_NEG_LLR_1_BIT_SOFT_OUT;
}

static int
check_dev_cap(const struct rte_bbdev_info *dev_info,
	      struct test_bbdev_vector *vector)
{
	unsigned int i;
	unsigned int nb_inputs, nb_soft_outputs, nb_hard_outputs,
		nb_harq_inputs, nb_harq_outputs;
	const struct rte_bbdev_op_cap *op_cap = dev_info->drv.capabilities;

	nb_inputs = vector->entries[DATA_INPUT].nb_segments;
	nb_soft_outputs = vector->entries[DATA_SOFT_OUTPUT].nb_segments;
	nb_hard_outputs = vector->entries[DATA_HARD_OUTPUT].nb_segments;
	nb_harq_inputs  = vector->entries[DATA_HARQ_INPUT].nb_segments;
	nb_harq_outputs = vector->entries[DATA_HARQ_OUTPUT].nb_segments;

	for (i = 0; op_cap->type != RTE_BBDEV_OP_NONE; ++i, ++op_cap) {
		if (op_cap->type != vector->op_type)
			continue;

		if (op_cap->type == RTE_BBDEV_OP_TURBO_DEC) {
			const struct rte_bbdev_op_cap_turbo_dec *cap =
					&op_cap->cap.turbo_dec;
			/* Ignore lack of soft output capability, just skip
			 * checking if soft output is valid.
			 */
			if ((vector->turbo_dec.op_flags &
					RTE_BBDEV_TURBO_SOFT_OUTPUT) &&
					!(cap->capability_flags &
					RTE_BBDEV_TURBO_SOFT_OUTPUT)) {
				printf(
					"INFO: Device \"%s\" does not support soft output - soft output flags will be ignored.\n",
					dev_info->dev_name);
				clear_soft_out_cap(
					&vector->turbo_dec.op_flags);
			}

			if (!flags_match(vector->turbo_dec.op_flags,
					cap->capability_flags))
				return TEST_FAILED;
			if (nb_inputs > cap->num_buffers_src) {
				printf("Too many inputs defined: %u, max: %u\n",
					nb_inputs, cap->num_buffers_src);
				return TEST_FAILED;
			}
			if (nb_soft_outputs > cap->num_buffers_soft_out &&
					(vector->turbo_dec.op_flags &
					RTE_BBDEV_TURBO_SOFT_OUTPUT)) {
				printf(
					"Too many soft outputs defined: %u, max: %u\n",
						nb_soft_outputs,
						cap->num_buffers_soft_out);
				return TEST_FAILED;
			}
			if (nb_hard_outputs > cap->num_buffers_hard_out) {
				printf(
					"Too many hard outputs defined: %u, max: %u\n",
						nb_hard_outputs,
						cap->num_buffers_hard_out);
				return TEST_FAILED;
			}
			if (intr_enabled && !(cap->capability_flags &
					RTE_BBDEV_TURBO_DEC_INTERRUPTS)) {
				printf(
					"Dequeue interrupts are not supported!\n");
				return TEST_FAILED;
			}

			return TEST_SUCCESS;
		} else if (op_cap->type == RTE_BBDEV_OP_TURBO_ENC) {
			const struct rte_bbdev_op_cap_turbo_enc *cap =
					&op_cap->cap.turbo_enc;

			if (!flags_match(vector->turbo_enc.op_flags,
					cap->capability_flags))
				return TEST_FAILED;
			if (nb_inputs > cap->num_buffers_src) {
				printf("Too many inputs defined: %u, max: %u\n",
					nb_inputs, cap->num_buffers_src);
				return TEST_FAILED;
			}
			if (nb_hard_outputs > cap->num_buffers_dst) {
				printf(
					"Too many hard outputs defined: %u, max: %u\n",
					nb_hard_outputs, cap->num_buffers_dst);
				return TEST_FAILED;
			}
			if (intr_enabled && !(cap->capability_flags &
					RTE_BBDEV_TURBO_ENC_INTERRUPTS)) {
				printf(
					"Dequeue interrupts are not supported!\n");
				return TEST_FAILED;
			}

			return TEST_SUCCESS;
		} else if (op_cap->type == RTE_BBDEV_OP_LDPC_ENC) {
			const struct rte_bbdev_op_cap_ldpc_enc *cap =
					&op_cap->cap.ldpc_enc;

			if (!flags_match(vector->ldpc_enc.op_flags,
					cap->capability_flags)){
				printf("Flag Mismatch\n");
				return TEST_FAILED;
			}
			if (nb_inputs > cap->num_buffers_src) {
				printf("Too many inputs defined: %u, max: %u\n",
					nb_inputs, cap->num_buffers_src);
				return TEST_FAILED;
			}
			if (nb_hard_outputs > cap->num_buffers_dst) {
				printf(
					"Too many hard outputs defined: %u, max: %u\n",
					nb_hard_outputs, cap->num_buffers_dst);
				return TEST_FAILED;
			}
			if (intr_enabled && !(cap->capability_flags &
					RTE_BBDEV_TURBO_ENC_INTERRUPTS)) {
				printf(
					"Dequeue interrupts are not supported!\n");
				return TEST_FAILED;
			}

			return TEST_SUCCESS;
		} else if (op_cap->type == RTE_BBDEV_OP_LDPC_DEC) {
			const struct rte_bbdev_op_cap_ldpc_dec *cap =
					&op_cap->cap.ldpc_dec;

			if (!flags_match(vector->ldpc_dec.op_flags,
					cap->capability_flags)){
				printf("Flag Mismatch\n");
				return TEST_FAILED;
			}
			if (nb_inputs > cap->num_buffers_src) {
				printf("Too many inputs defined: %u, max: %u\n",
					nb_inputs, cap->num_buffers_src);
				return TEST_FAILED;
			}
			if (nb_hard_outputs > cap->num_buffers_hard_out) {
				printf(
					"Too many hard outputs defined: %u, max: %u\n",
					nb_hard_outputs,
					cap->num_buffers_hard_out);
				return TEST_FAILED;
			}
			if (nb_harq_inputs > cap->num_buffers_hard_out) {
				printf(
					"Too many HARQ inputs defined: %u, max: %u\n",
					nb_hard_outputs,
					cap->num_buffers_hard_out);
				return TEST_FAILED;
			}
			if (nb_harq_outputs > cap->num_buffers_hard_out) {
				printf(
					"Too many HARQ outputs defined: %u, max: %u\n",
					nb_hard_outputs,
					cap->num_buffers_hard_out);
				return TEST_FAILED;
			}
			if (intr_enabled && !(cap->capability_flags &
					RTE_BBDEV_TURBO_DEC_INTERRUPTS)) {
				printf(
					"Dequeue interrupts are not supported!\n");
				return TEST_FAILED;
			}

			return TEST_SUCCESS;
		} else if (op_cap->type == RTE_BBDEV_OP_POLAR_DEC) {
			num_polar_decode_tests++;
			if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_ACK(&vector->la12xx_op))
				ack_sync_var = num_polar_decode_tests;
			if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_CSI1(&vector->la12xx_op))
				csi1_sync_var = num_polar_decode_tests;
			if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_CSI2(&vector->la12xx_op))
				csi2_sync_var = num_polar_decode_tests;
			return TEST_SUCCESS;
		} else if (op_cap->type == RTE_BBDEV_OP_POLAR_ENC) {
			return TEST_SUCCESS;
		}
	}

	if (vector->op_type == RTE_BBDEV_OP_NONE ||
			vector->op_type == RTE_BBDEV_OP_LA12XX_VSPA ||
			vector->op_type == RTE_BBDEV_OP_RAW)
		return TEST_SUCCESS;

	return TEST_FAILED;
}

/* calculates optimal mempool size not smaller than the val */
static unsigned int
optimal_mempool_size(unsigned int val)
{
	return rte_align32pow2(val + 1) - 1;
}

/* allocates bbuf mempool for inputs and outputs */
static struct rte_mempool *
create_bbuf_pool(unsigned int len, uint8_t dev_id,
		int socket_id, unsigned int bbuf_pool_size,
		const char *op_type_str, unsigned int bbuf_size)
{
	char pool_name[RTE_MEMPOOL_NAMESIZE];

	snprintf(pool_name, sizeof(pool_name), "%s_pool_%u", op_type_str,
			dev_id);
	return rte_bbuf_pool_create(pool_name, bbuf_pool_size, 0, 0,
			RTE_MAX(len + RTE_BBUF_HEADROOM,
			(unsigned int)bbuf_size), socket_id);
}

static void
get_max_len_sg(struct op_data_entries *entry, unsigned int *max_len,
		    unsigned int *max_seg)
{
	unsigned int i;

	if (entry->nb_segments > *max_seg)
		*max_seg = entry->nb_segments;
	for (i = 0; i < entry->nb_segments; ++i)
		if (entry->segments[i].length > *max_len)
			*max_len = entry->segments[i].length;
}

static int
create_mempools(struct active_device *ad, int socket_id,
		struct test_bbdev_vector *vector, uint16_t num_ops)
{
	struct rte_mempool *mp;
	unsigned int i, v, mp_idx = 0, ops_pool_size, bbuf_pool_size = 0,
		     bbuf_size;
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	uint8_t op_pool_mask = 0;
	const char *op_type_str;
	enum rte_bbdev_op_type op_type, org_op_type = RTE_BBDEV_OP_NONE;
	unsigned int in_maxl = 0, hard_out_maxl = 0, soft_out_maxl = 0,
		harq_in_maxl = 0, harq_out_maxl = 0, in_seg = 0,
		hard_out_seg = 0, soft_out_seg = 0,
		harq_in_seg = 0, harq_out_seg = 0;
	static int init_once;

	if (!init_once && get_multi_hugepages()) {
		/* Allocate 1G of memory so that memory from second
		 * hugepage is also consumed
		 */
		void *dummy = rte_malloc_socket(NULL, 1000 * 1024 * 1024, 0,
						socket_id);
		if (!dummy)
			printf("dummy allocation failed\n");
		RTE_SET_USED(dummy);
		init_once = 1;
	}

	/* Finding the maximum length and segments from all vectors */
	for (v = 0; v < get_vector_count(); v++) {
		struct op_data_entries *in = &(&vector[v])->entries[DATA_INPUT];
		struct op_data_entries *hard_out =
				&(&vector[v])->entries[DATA_HARD_OUTPUT];
		struct op_data_entries *soft_out =
				&(&vector[v])->entries[DATA_SOFT_OUTPUT];
		struct op_data_entries *harq_in =
				&(&vector[v])->entries[DATA_HARQ_INPUT];
		struct op_data_entries *harq_out =
				&(&vector[v])->entries[DATA_HARQ_OUTPUT];

		get_max_len_sg(in, &in_maxl, &in_seg);
		get_max_len_sg(hard_out, &hard_out_maxl, &hard_out_seg);
		get_max_len_sg(soft_out, &soft_out_maxl, &soft_out_seg);
		get_max_len_sg(harq_in, &harq_in_maxl, &harq_in_seg);
		get_max_len_sg(harq_out, &harq_out_maxl, &harq_out_seg);
	}

	/* allocate ops mempool */
	ops_pool_size = optimal_mempool_size(RTE_MAX(
			/* Ops used plus 1 reference op */
			(unsigned int)(ad->nb_queues * num_ops + 1),
			OPS_POOL_SIZE_MIN));


	for (i = 0; i < get_vector_count(); i++) {
		op_type = (&vector[i])->op_type;
		if (op_pool_mask & (1 << op_type))
			continue;

		op_type_str = rte_bbdev_op_type_str(op_type);
		TEST_ASSERT_NOT_NULL(op_type_str, "Invalid op type: %u",
				     op_type);

		snprintf(pool_name, sizeof(pool_name), "pool_%u_%u",
			ad->dev_id, i);

		if (op_type >= RTE_BBDEV_OP_POLAR_DEC) {
			mp = rte_mempool_create(pool_name, ops_pool_size,
				sizeof(struct rte_pmd_la12xx_op),
				OPS_CACHE_SIZE,
				sizeof(struct rte_bbdev_op_pool_private),
				NULL, NULL, rte_pmd_la12xx_op_init, &op_type,
				socket_id, 0);
		} else {
			mp = rte_bbdev_op_pool_create(pool_name, op_type,
				ops_pool_size, OPS_CACHE_SIZE, socket_id);
		}

		TEST_ASSERT_NOT_NULL(mp,
				"ERROR Failed to create %u"
				" items ops pool for dev %u on socket %u.",
				ops_pool_size,
				ad->dev_id,
				socket_id);
		ad->ops_mempool[op_type] = mp;
		op_pool_mask |= (1 << op_type);

		if (op_type == RTE_BBDEV_OP_LDPC_ENC) {
			org_op_type = RTE_BBDEV_OP_LDPC_ENC;
		} else if (op_type != RTE_BBDEV_OP_NONE &&
			  org_op_type != RTE_BBDEV_OP_LDPC_ENC) {
			org_op_type = -1;
		}
	}


	bbuf_size = get_buf_size();
	if (org_op_type == RTE_BBDEV_OP_LDPC_ENC)
		/* Add buffer into the bbuf_size required by
		 * rte_pmd_la12xx_ldpc_enc_adj_bbuf() API
		 */
		bbuf_size += 4096;

	/* Do not create inputs and outputs bbufs for BaseBand Null Device */
	if (org_op_type == RTE_BBDEV_OP_NONE) {
		int ret, data_size;
		unsigned int i, j, nb_seg;
		char *data;
		struct rte_bbdev_enc_op **ops;
		struct rte_bbuf *bbufs[2 * BBUF_MAX_SEGS];

		nb_seg = get_num_seg();

		printf("bbuf size =%d and seg = %d\n", bbuf_size, nb_seg);
		ops = rte_malloc_socket(NULL, sizeof(struct rte_bbdev_enc_op *) *  ops_pool_size,
				RTE_CACHE_LINE_SIZE, socket_id);
		TEST_ASSERT_NOT_NULL(ops,
				     "cannot allocate memory to hold buffers");
		/* Create a bbuf pool */
		bbdev_bbuf_pool = rte_bbuf_pool_create("bbuf_pool",
				(2 * nb_seg * ops_pool_size),
				BBUF_POOL_CACHE_SIZE, 0, bbuf_size,
				socket_id);
		if (bbdev_bbuf_pool == NULL)
			TEST_ASSERT_NOT_NULL(bbdev_bbuf_pool,
					     "cannot init bbuf pool of size :%u", ops_pool_size);

		/* Now fill the ops */
		ret = rte_mempool_get_bulk(ad->ops_mempool[mp_idx],
					   (void **)ops, ops_pool_size);
		TEST_ASSERT_SUCCESS(ret, "Cannot get ops element from pool %d", ret);

		for (i = 0; i < ops_pool_size; i++) {
			ret = rte_bbuf_alloc_bulk(bbdev_bbuf_pool, bbufs,
						     (2 * nb_seg));
			TEST_ASSERT_SUCCESS(ret, "Cannot get bbuf element from pool");

			data_size = bbuf_size - RTE_BBUF_HEADROOM;
			data = rte_bbuf_append(bbufs[0], data_size);
			memset(data, POISON, data_size);

			for (j = 1; j <= nb_seg - 1; j++) {
				/* Set the value */
				data_size = bbuf_size - RTE_BBUF_HEADROOM;
				data = rte_bbuf_append(bbufs[j], data_size);
				memset(data, j, data_size);
				/* Create input buffer chain */
				ret = rte_bbuf_chain(bbufs[0], bbufs[j]);
				TEST_ASSERT_SUCCESS(ret, "Cannot chain bbuf");

				/* Create output buffer chain */
				ret = rte_bbuf_chain(bbufs[nb_seg],
							bbufs[nb_seg + j]);
				TEST_ASSERT_SUCCESS(ret, "Cannot chain bbuf");
			}

			ops[i]->ldpc_enc.input.bdata = bbufs[0];
			ops[i]->ldpc_enc.input.length = bbuf_size;
			ops[i]->ldpc_enc.input.offset = 0;
			ops[i]->ldpc_enc.output.bdata = bbufs[nb_seg];
		}
		rte_mempool_put_bulk(ad->ops_mempool[mp_idx], (void **)ops,
				     ops_pool_size);
		rte_free(ops);
		return TEST_SUCCESS;
	}

	/* Inputs */
	bbuf_pool_size = optimal_mempool_size(ops_pool_size * in_seg);
	if (bbuf_pool_size) {
		mp = create_bbuf_pool(in_maxl, ad->dev_id, socket_id,
				      bbuf_pool_size, "in", bbuf_size);
		TEST_ASSERT_NOT_NULL(mp,
				"ERROR Failed to create %u items input bbuf pool for dev %u on socket %u.",
				bbuf_pool_size,
				ad->dev_id,
				socket_id);
		ad->in_bbuf_pool = mp;
	}

	/* Hard outputs */
	bbuf_pool_size = optimal_mempool_size(ops_pool_size *
			hard_out_seg);
	if (bbuf_pool_size) {
		mp = create_bbuf_pool(hard_out_maxl, ad->dev_id, socket_id,
				bbuf_pool_size,
				"hard_out", bbuf_size);
		TEST_ASSERT_NOT_NULL(mp,
				"ERROR Failed to create %u items hard output bbuf pool for dev %u on socket %u.",
				bbuf_pool_size,
				ad->dev_id,
				socket_id);
		ad->hard_out_bbuf_pool = mp;

		mp = create_bbuf_pool(soft_out_maxl, ad->dev_id, socket_id,
				bbuf_pool_size,
				"partial_out", bbuf_size);
		TEST_ASSERT_NOT_NULL(mp,
				"ERROR Failed to create %uB partial output bbuf pool for dev %u on socket %u.",
				bbuf_pool_size,
				ad->dev_id,
				socket_id);
		ad->partial_out_bbuf_pool = mp;
	}

	/* Soft outputs */
	if (soft_out_seg > 0) {
		bbuf_pool_size = optimal_mempool_size(ops_pool_size *
				soft_out_seg);
		mp = create_bbuf_pool(soft_out_maxl, ad->dev_id, socket_id,
				bbuf_pool_size,
				"soft_out", bbuf_size);
		TEST_ASSERT_NOT_NULL(mp,
				"ERROR Failed to create %uB soft output bbuf pool for dev %u on socket %u.",
				bbuf_pool_size,
				ad->dev_id,
				socket_id);
		ad->soft_out_bbuf_pool = mp;
	}

	/* HARQ inputs */
	if (harq_in_seg > 0) {
		bbuf_pool_size = optimal_mempool_size(ops_pool_size *
				harq_in_seg);
		mp = create_bbuf_pool(harq_in_maxl, ad->dev_id, socket_id,
				bbuf_pool_size,
				"harq_in", bbuf_size);
		TEST_ASSERT_NOT_NULL(mp,
				"ERROR Failed to create %uB harq input bbuf pool for dev %u on socket %u.",
				bbuf_pool_size,
				ad->dev_id,
				socket_id);
		ad->harq_in_bbuf_pool = mp;
	}

	/* HARQ outputs */
	if (harq_out_seg > 0) {
		bbuf_pool_size = optimal_mempool_size(ops_pool_size *
				harq_out_seg);
		mp = create_bbuf_pool(harq_out_maxl, ad->dev_id, socket_id,
				bbuf_pool_size,
				"harq_out", bbuf_size);
		TEST_ASSERT_NOT_NULL(mp,
				"ERROR Failed to create %uB harq output bbuf pool for dev %u on socket %u.",
				bbuf_pool_size,
				ad->dev_id,
				socket_id);
		ad->harq_out_bbuf_pool = mp;
	}

	return TEST_SUCCESS;
}

static int
add_bbdev_dev(uint8_t dev_id, struct rte_bbdev_info *info,
		struct test_bbdev_vector *vector)
{
	int ret;
	unsigned int queue_id, v;
	struct rte_bbdev_queue_conf qconf;
	struct active_device *ad = &active_devs[nb_active_devs];
	unsigned int nb_queues;
	uint32_t lcore_id = -1;
	uint32_t vector_count;
	struct core_params *cp;

/* Configure fpga lte fec with PF & VF values
 * if '-i' flag is set and using fpga device
 */
#ifdef RTE_LIBRTE_PMD_BBDEV_FPGA_LTE_FEC
	if ((get_init_device() == true) &&
		(!strcmp(info->drv.driver_name, FPGA_PF_DRIVER_NAME))) {
		struct fpga_lte_fec_conf conf;
		unsigned int i;

		printf("Configure FPGA FEC Driver %s with default values\n",
				info->drv.driver_name);

		/* clear default configuration before initialization */
		memset(&conf, 0, sizeof(struct fpga_lte_fec_conf));

		/* Set PF mode :
		 * true if PF is used for data plane
		 * false for VFs
		 */
		conf.pf_mode_en = true;

		for (i = 0; i < FPGA_LTE_FEC_NUM_VFS; ++i) {
			/* Number of UL queues per VF (fpga supports 8 VFs) */
			conf.vf_ul_queues_number[i] = VF_UL_QUEUE_VALUE;
			/* Number of DL queues per VF (fpga supports 8 VFs) */
			conf.vf_dl_queues_number[i] = VF_DL_QUEUE_VALUE;
		}

		/* UL bandwidth. Needed for schedule algorithm */
		conf.ul_bandwidth = UL_BANDWIDTH;
		/* DL bandwidth */
		conf.dl_bandwidth = DL_BANDWIDTH;

		/* UL & DL load Balance Factor to 64 */
		conf.ul_load_balance = UL_LOAD_BALANCE;
		conf.dl_load_balance = DL_LOAD_BALANCE;

		/**< FLR timeout value */
		conf.flr_time_out = FLR_TIMEOUT;

		/* setup FPGA PF with configuration information */
		ret = fpga_lte_fec_configure(info->dev_name, &conf);
		TEST_ASSERT_SUCCESS(ret,
				"Failed to configure 4G FPGA PF for bbdev %s",
				info->dev_name);
	}
#endif
	nb_queues = RTE_MIN(rte_lcore_count(), info->drv.max_num_queues);
	nb_queues = RTE_MIN(nb_queues, (unsigned int) MAX_QUEUES);

	/* setup device */
	ret = rte_bbdev_setup_queues(dev_id, nb_queues, info->socket_id);
	if (ret < 0) {
		printf("rte_bbdev_setup_queues(%u, %u, %d) ret %i\n",
				dev_id, nb_queues, info->socket_id, ret);
		return TEST_FAILED;
	}

	/* configure interrupts if needed */
	if (intr_enabled) {
		ret = rte_bbdev_intr_enable(dev_id);
		if (ret < 0) {
			printf("rte_bbdev_intr_enable(%u) ret %i\n", dev_id,
					ret);
			return TEST_FAILED;
		}
	}

	/* setup device queues */
	qconf.socket = info->socket_id;
	qconf.queue_size = info->drv.default_queue_conf.queue_size;
	qconf.priority = 0;
	qconf.deferred_start = 0;
	qconf.raw_queue_conf.conf_enable = 1;
	qconf.raw_queue_conf.modem_core_id = 0;

	vector_count = get_vector_count();
	if (vector_count > nb_queues) {
		printf("ERROR: Number of vectors more than queues/cores\n");
		return TEST_FAILED;
	}


	for (queue_id = 0; queue_id < nb_queues; ++queue_id) {
		for (v = 0; v < vector_count; v++) {
			/* Currently assuming one queue is on one core.
			 * Below code to be updated when multi queues per
			 * core be supported
			 */
			if ((&vector[v])->core_mask == 0) {
				lcore_id = rte_get_next_lcore(lcore_id, 0, 0);
				(&vector[v])->core_mask = (1 << lcore_id);
			}

			if ((&vector[v])->core_mask & (1 << queue_id))
				break;
		}
		qconf.op_type = (&vector[v])->op_type;
		ret = rte_bbdev_queue_configure(dev_id, queue_id, &qconf);
		if (ret != 0) {
			printf(
					"Allocated all queues (id=%u) at prio%u on dev%u\n",
					queue_id, qconf.priority, dev_id);
			qconf.priority++;
			ret = rte_bbdev_queue_configure(ad->dev_id, queue_id,
					&qconf);
		}
		if (ret != 0) {
			printf("All queues on dev %u allocated: %u\n",
					dev_id, queue_id);
			break;
		}
		ad->queue_ids[queue_id] = queue_id;
		set_avail_op(ad, (&vector[v])->op_type);
	}
	TEST_ASSERT(queue_id != 0,
			"ERROR Failed to configure any queues on dev %u",
			dev_id);
	ad->nb_queues = queue_id;

	if (getenv("LA12XX_ENABLE_FECA_SD_SINGLE_QDMA"))
		rte_pmd_la12xx_ldpc_dec_single_input_dma(dev_id);

	cp = get_core_params();
	if (cp->nb_params > 0) {
		printf("cp->nb_params: %d\n\r", cp->nb_params);
		rte_pmd_la12xx_queue_core_config(dev_id, cp->queue_ids,
			cp->core_ids, cp->nb_params);
	}

	return TEST_SUCCESS;
}

static int
add_active_device(uint8_t dev_id, struct rte_bbdev_info *info,
		struct test_bbdev_vector *vector)
{
	int ret;

	active_devs[nb_active_devs].driver_name = info->drv.driver_name;
	active_devs[nb_active_devs].dev_id = dev_id;

	ret = add_bbdev_dev(dev_id, info, vector);
	if (ret == TEST_SUCCESS)
		++nb_active_devs;
	return ret;
}

static uint8_t
populate_active_devices(void)
{
	int ret;
	uint8_t dev_id;
	uint8_t nb_devs_added = 0;
	struct rte_bbdev_info info;
	unsigned int v;

	RTE_BBDEV_FOREACH(dev_id) {
		rte_bbdev_info_get(dev_id, &info);

		num_polar_decode_tests = 0;
		for (v = 0; v < get_vector_count(); v++) {
			if (check_dev_cap(&info, &test_vector[v])) {
				printf(
					"Device %d (%s) does not support specified capabilities\n",
						dev_id, info.dev_name);
				continue;
			}
		}

		ret = add_active_device(dev_id, &info, test_vector);
		if (ret != 0) {
			printf("Adding active bbdev %s skipped\n",
					info.dev_name);
			continue;
		}
		nb_devs_added++;
	}

	return nb_devs_added;
}

static int
read_test_vector(const char *file, struct test_bbdev_vector *vector)
{
	int ret;

	memset(vector, 0, sizeof(struct test_bbdev_vector));
	printf("Test vector file = %s\n", file);
	ret = test_bbdev_vector_read(file, vector);
	TEST_ASSERT_SUCCESS(ret, "Failed to parse file %s\n",
			file);

	return TEST_SUCCESS;
}

static int
testsuite_setup(void)
{
	if (!strcmp(get_vector_filename(), "no-file")) {
		unsigned int i, v_count;
		char v_file[52];

		v_count = get_vector_count();
		for (i = 0; i < v_count; i++) {
			snprintf(v_file, sizeof(v_file),
				"./test_vector_%u.data", i);
			TEST_ASSERT_SUCCESS(read_test_vector(v_file,
					    &test_vector[i]),
					    "Test suite setup failed\n");
		}
	} else {
		TEST_ASSERT_SUCCESS(read_test_vector(get_vector_filename(),
				    &test_vector[0]),
				    "Test suite setup failed\n");
	}

	if (populate_active_devices() == 0) {
		printf("No suitable devices found!\n");
		return TEST_SKIPPED;
	}

	return TEST_SUCCESS;
}

static void
testsuite_teardown(void)
{
	uint8_t dev_id;

	/* Unconfigure devices */
	RTE_BBDEV_FOREACH(dev_id)
		rte_bbdev_close(dev_id);

	/* Clear active devices structs. */
	memset(active_devs, 0, sizeof(active_devs));
	nb_active_devs = 0;
}

static int
ut_setup(void)
{
	uint8_t i, dev_id;

	for (i = 0; i < nb_active_devs; i++) {
		dev_id = active_devs[i].dev_id;
		/* reset bbdev stats */
		TEST_ASSERT_SUCCESS(rte_bbdev_stats_reset(dev_id),
				"Failed to reset stats of bbdev %u", dev_id);
		/* start the device */
		TEST_ASSERT_SUCCESS(rte_bbdev_start(dev_id),
				"Failed to start bbdev %u", dev_id);
	}

	return TEST_SUCCESS;
}

static void
ut_teardown(void)
{
	uint8_t i, dev_id;
	struct rte_bbdev_stats stats;

	for (i = 0; i < nb_active_devs; i++) {
		dev_id = active_devs[i].dev_id;
		/* read stats and print */
		rte_bbdev_stats_get(dev_id, &stats);
		/* Stop the device */
		rte_bbdev_stop(dev_id);
	}
}

static int
init_op_data_objs(struct rte_bbdev_op_data *bufs,
		struct op_data_entries *ref_entries,
		enum rte_bbdev_op_type bbdev_op_type,
		struct rte_mempool *bbuf_pool, const uint16_t n,
		enum op_data_type op_type, uint16_t min_alignment)
{
	int ret;
	unsigned int i, j;

	for (i = 0; i < n; ++i) {
		char *data;
		struct op_data_buf *seg = &ref_entries->segments[0];
		struct rte_bbuf *b_head = rte_bbuf_alloc(bbuf_pool);
		TEST_ASSERT_NOT_NULL(b_head,
				"Not enough bbufs in %d data type bbuf pool (needed %u, available %u)",
				op_type, n * ref_entries->nb_segments,
				bbuf_pool->size);

		TEST_ASSERT_SUCCESS(((seg->length + RTE_BBUF_HEADROOM) >
				(uint32_t)UINT32_MAX),
				"Given data is bigger than allowed bbuf segment size");

		bufs[i].bdata = b_head;
		bufs[i].offset = 0;
		bufs[i].length = 0;

		if (op_type == DATA_INPUT &&
		    bbdev_op_type == RTE_BBDEV_OP_LDPC_ENC) {
			/* Adjust the bbuf as a W.A. for FECA FDMA hang
			 * in some cases for LDPC Encode (SE). The W.A.
			 * adjust the starting address on the basis of
			 * previous start address and input buffer
			 * length.
			 */
			ret = rte_pmd_la12xx_ldpc_enc_adj_bbuf(b_head,
				seg->length);
			TEST_ASSERT_SUCCESS(ret,
					"rte_pmd_la12xx_ldpc_enc_adj_bbuf API failed");
		}

		if ((op_type == DATA_INPUT) || (op_type == DATA_HARQ_INPUT)) {
			data = rte_bbuf_append(b_head, seg->length);
			TEST_ASSERT_NOT_NULL(data,
					"Couldn't append %u bytes to bbuf from %d data type bbuf pool",
					seg->length, op_type);

			TEST_ASSERT(data == RTE_PTR_ALIGN(data, min_alignment),
					"Data addr in bbuf (%p) is not aligned to device min alignment (%u)",
					data, min_alignment);
			rte_memcpy(data, seg->addr, seg->length);
			bufs[i].length += seg->length;

			for (j = 1; j < ref_entries->nb_segments; ++j) {
				struct rte_bbuf *b_tail =
						rte_bbuf_alloc(bbuf_pool);
				TEST_ASSERT_NOT_NULL(b_tail,
						"Not enough bbufs in %d data type bbuf pool (needed %u, available %u)",
						op_type,
						n * ref_entries->nb_segments,
						bbuf_pool->size);
				seg += 1;

				data = rte_bbuf_append(b_tail, seg->length);
				TEST_ASSERT_NOT_NULL(data,
						"Couldn't append %u bytes to bbuf from %d data type bbuf pool",
						seg->length, op_type);

				TEST_ASSERT(data == RTE_PTR_ALIGN(data,
						min_alignment),
						"Data addr in bbuf (%p) is not aligned to device min alignment (%u)",
						data, min_alignment);
				rte_memcpy(data, seg->addr, seg->length);
				bufs[i].length += seg->length;

				ret = rte_bbuf_chain(b_head, b_tail);
				TEST_ASSERT_SUCCESS(ret,
						"Couldn't chain bbufs from %d data type bbuf pool",
						op_type);
			}
		} else {

			/* allocate chained-bbuf for output buffer */
			for (j = 1; j < ref_entries->nb_segments; ++j) {
				struct rte_bbuf *b_tail =
						rte_bbuf_alloc(bbuf_pool);
				TEST_ASSERT_NOT_NULL(b_tail,
						"Not enough bbufs in %d data type bbuf pool (needed %u, available %u)",
						op_type,
						n * ref_entries->nb_segments,
						bbuf_pool->size);

				ret = rte_bbuf_chain(b_head, b_tail);
				TEST_ASSERT_SUCCESS(ret,
						"Couldn't chain bbufs from %d data type bbuf pool",
						op_type);
			}
		}
	}

	return 0;
}

static int
allocate_buffers_on_socket(struct rte_bbdev_op_data **buffers, const int len,
		const int socket)
{
	int i;

	*buffers = rte_zmalloc_socket(NULL, len, 0, socket);
	if (*buffers == NULL) {
		printf("WARNING: Failed to allocate op_data on socket %d\n",
				socket);
		/* try to allocate memory on other detected sockets */
		for (i = 0; i < socket; i++) {
			*buffers = rte_zmalloc_socket(NULL, len, 0, i);
			if (*buffers != NULL)
				break;
		}
	}

	return (*buffers == NULL) ? TEST_FAILED : TEST_SUCCESS;
}

static void
limit_input_llr_val_range(struct rte_bbdev_op_data *input_ops,
		const uint16_t n, const int8_t max_llr_modulus)
{
	uint16_t i, byte_idx;

	for (i = 0; i < n; ++i) {
		struct rte_bbuf *b = input_ops[i].bdata;
		while (b != NULL) {
			int8_t *llr = rte_bbuf_mtod_offset(b, int8_t *,
					input_ops[i].offset);
			for (byte_idx = 0; byte_idx < rte_bbuf_data_len(b);
					++byte_idx)
				llr[byte_idx] = round((double)max_llr_modulus *
						llr[byte_idx] / INT8_MAX);

			b = b->next;
		}
	}
}

static void
ldpc_input_llr_scaling(struct rte_bbdev_op_data *input_ops,
		const uint16_t n, const int8_t llr_size,
		const int8_t llr_decimals)
{
	if (input_ops == NULL)
		return;

	uint16_t i, byte_idx;

	int16_t llr_max, llr_min, llr_tmp;
	llr_max = (1 << (llr_size - 1)) - 1;
	llr_min = -llr_max;
	for (i = 0; i < n; ++i) {
		struct rte_bbuf *b = input_ops[i].bdata;
		while (b != NULL) {
			int8_t *llr = rte_bbuf_mtod_offset(b, int8_t *,
					input_ops[i].offset);
			for (byte_idx = 0; byte_idx < rte_bbuf_data_len(b);
					++byte_idx) {

				llr_tmp = llr[byte_idx];
				if (llr_decimals == 2)
					llr_tmp *= 2;
				else if (llr_decimals == 0)
					llr_tmp /= 2;
				llr_tmp = RTE_MIN(llr_max,
						RTE_MAX(llr_min, llr_tmp));
				llr[byte_idx] = (int8_t) llr_tmp;
			}

			b = b->next;
		}
	}
}



static int
fill_queue_buffers(struct test_op_params *op_params,
		struct rte_mempool *in_mp, struct rte_mempool *hard_out_mp,
		struct rte_mempool *partial_out_mp,
		struct rte_mempool *soft_out_mp,
		struct rte_mempool *harq_in_mp, struct rte_mempool *harq_out_mp,
		uint16_t queue_id,
		const struct rte_bbdev_op_cap *capabilities,
		uint16_t min_alignment, const int socket_id,
		struct test_bbdev_vector *vector)
{
	int ret;
	enum op_data_type type;
	const uint16_t n = op_params->num_to_process;

	struct rte_mempool *bbuf_pools[DATA_NUM_TYPES] = {
		in_mp,
		soft_out_mp,
		hard_out_mp,
		partial_out_mp,
		harq_in_mp,
		harq_out_mp,
	};

	struct rte_bbdev_op_data **queue_ops[DATA_NUM_TYPES] = {
		&op_params->q_bufs[socket_id][queue_id].inputs,
		&op_params->q_bufs[socket_id][queue_id].soft_outputs,
		&op_params->q_bufs[socket_id][queue_id].hard_outputs,
		&op_params->q_bufs[socket_id][queue_id].partial_outputs,
		&op_params->q_bufs[socket_id][queue_id].harq_inputs,
		&op_params->q_bufs[socket_id][queue_id].harq_outputs,
	};

	if (partial_out_mp) {
		vector->entries[DATA_PARTIAL_OUTPUT].segments[0].addr =
			vector->entries[DATA_HARD_OUTPUT].segments[0].addr;
		vector->entries[DATA_PARTIAL_OUTPUT].segments[0].length =
			vector->entries[DATA_HARD_OUTPUT].segments[0].length;
		vector->entries[DATA_PARTIAL_OUTPUT].nb_segments =
			vector->entries[DATA_HARD_OUTPUT].nb_segments;
	}

	for (type = DATA_INPUT; type < DATA_NUM_TYPES; ++type) {
		struct op_data_entries *ref_entries =
				&vector->entries[type];
		if (ref_entries->nb_segments == 0)
			continue;

		ret = allocate_buffers_on_socket(queue_ops[type],
				n * sizeof(struct rte_bbdev_op_data),
				socket_id);
		TEST_ASSERT_SUCCESS(ret,
				"Couldn't allocate memory for rte_bbdev_op_data structs");

		ret = init_op_data_objs(*queue_ops[type], ref_entries,
				vector->op_type, bbuf_pools[type], n,
				type, min_alignment);
		TEST_ASSERT_SUCCESS(ret,
				"Couldn't init rte_bbdev_op_data structs");
	}

	if (vector->op_type == RTE_BBDEV_OP_TURBO_DEC)
		limit_input_llr_val_range(*queue_ops[DATA_INPUT], n,
			capabilities->cap.turbo_dec.max_llr_modulus);

	if (vector->op_type == RTE_BBDEV_OP_LDPC_DEC &&
	    !(capabilities->cap.ldpc_dec.capability_flags &
	    RTE_BBDEV_LDPC_DEC_LLR_CONV_OFFLOAD))
		scale_llr_input = 1;

	if ((vector->op_type == RTE_BBDEV_OP_LDPC_DEC) && scale_llr_input) {
		ldpc_input_llr_scaling(*queue_ops[DATA_INPUT], n,
			capabilities->cap.ldpc_dec.llr_size,
			capabilities->cap.ldpc_dec.llr_decimals);
		ldpc_input_llr_scaling(*queue_ops[DATA_HARQ_INPUT], n,
				capabilities->cap.ldpc_dec.llr_size,
				capabilities->cap.ldpc_dec.llr_decimals);
	}

	return 0;
}

static void
free_buffers(struct active_device *ad, struct test_op_params *op_params)
{
	unsigned int i, j;

	for (i = 0; i < RTE_BBDEV_OP_TYPE_COUNT; i++) {
		if (ad->ops_mempool[i])
			rte_mempool_free(ad->ops_mempool[i]);
	}

	rte_mempool_free(ad->in_bbuf_pool);
	rte_mempool_free(ad->hard_out_bbuf_pool);
	rte_mempool_free(ad->partial_out_bbuf_pool);
	rte_mempool_free(ad->soft_out_bbuf_pool);
	rte_mempool_free(ad->harq_in_bbuf_pool);
	rte_mempool_free(ad->harq_out_bbuf_pool);

	for (i = 0; i < rte_lcore_count(); ++i) {
		for (j = 0; j < RTE_MAX_NUMA_NODES; ++j) {
			rte_free(op_params->q_bufs[j][i].inputs);
			rte_free(op_params->q_bufs[j][i].hard_outputs);
			rte_free(op_params->q_bufs[j][i].partial_outputs);
			rte_free(op_params->q_bufs[j][i].soft_outputs);
			rte_free(op_params->q_bufs[j][i].harq_inputs);
			rte_free(op_params->q_bufs[j][i].harq_outputs);
		}
	}
}

static void
copy_reference_dec_op(struct rte_bbdev_dec_op **ops, unsigned int n,
		unsigned int start_idx,
		struct rte_bbdev_op_data *inputs,
		struct rte_bbdev_op_data *hard_outputs,
		struct rte_bbdev_op_data *soft_outputs,
		struct rte_bbdev_dec_op *ref_op)
{
	unsigned int i;
	struct rte_bbdev_op_turbo_dec *turbo_dec = &ref_op->turbo_dec;

	for (i = 0; i < n; ++i) {
		if (turbo_dec->code_block_mode == 0) {
			ops[i]->turbo_dec.tb_params.ea =
					turbo_dec->tb_params.ea;
			ops[i]->turbo_dec.tb_params.eb =
					turbo_dec->tb_params.eb;
			ops[i]->turbo_dec.tb_params.k_pos =
					turbo_dec->tb_params.k_pos;
			ops[i]->turbo_dec.tb_params.k_neg =
					turbo_dec->tb_params.k_neg;
			ops[i]->turbo_dec.tb_params.c =
					turbo_dec->tb_params.c;
			ops[i]->turbo_dec.tb_params.c_neg =
					turbo_dec->tb_params.c_neg;
			ops[i]->turbo_dec.tb_params.cab =
					turbo_dec->tb_params.cab;
			ops[i]->turbo_dec.tb_params.r =
					turbo_dec->tb_params.r;
		} else {
			ops[i]->turbo_dec.cb_params.e = turbo_dec->cb_params.e;
			ops[i]->turbo_dec.cb_params.k = turbo_dec->cb_params.k;
		}

		ops[i]->turbo_dec.ext_scale = turbo_dec->ext_scale;
		ops[i]->turbo_dec.iter_max = turbo_dec->iter_max;
		ops[i]->turbo_dec.iter_min = turbo_dec->iter_min;
		ops[i]->turbo_dec.op_flags = turbo_dec->op_flags;
		ops[i]->turbo_dec.rv_index = turbo_dec->rv_index;
		ops[i]->turbo_dec.num_maps = turbo_dec->num_maps;
		ops[i]->turbo_dec.code_block_mode = turbo_dec->code_block_mode;

		ops[i]->turbo_dec.hard_output = hard_outputs[start_idx + i];
		ops[i]->turbo_dec.input = inputs[start_idx + i];
		if (soft_outputs != NULL)
			ops[i]->turbo_dec.soft_output =
				soft_outputs[start_idx + i];
	}
}

static void
copy_reference_enc_op(struct rte_bbdev_enc_op **ops, unsigned int n,
		unsigned int start_idx,
		struct rte_bbdev_op_data *inputs,
		struct rte_bbdev_op_data *outputs,
		struct rte_bbdev_enc_op *ref_op)
{
	unsigned int i;
	struct rte_bbdev_op_turbo_enc *turbo_enc = &ref_op->turbo_enc;
	for (i = 0; i < n; ++i) {
		if (turbo_enc->code_block_mode == 0) {
			ops[i]->turbo_enc.tb_params.ea =
					turbo_enc->tb_params.ea;
			ops[i]->turbo_enc.tb_params.eb =
					turbo_enc->tb_params.eb;
			ops[i]->turbo_enc.tb_params.k_pos =
					turbo_enc->tb_params.k_pos;
			ops[i]->turbo_enc.tb_params.k_neg =
					turbo_enc->tb_params.k_neg;
			ops[i]->turbo_enc.tb_params.c =
					turbo_enc->tb_params.c;
			ops[i]->turbo_enc.tb_params.c_neg =
					turbo_enc->tb_params.c_neg;
			ops[i]->turbo_enc.tb_params.cab =
					turbo_enc->tb_params.cab;
			ops[i]->turbo_enc.tb_params.ncb_pos =
					turbo_enc->tb_params.ncb_pos;
			ops[i]->turbo_enc.tb_params.ncb_neg =
					turbo_enc->tb_params.ncb_neg;
			ops[i]->turbo_enc.tb_params.r = turbo_enc->tb_params.r;
		} else {
			ops[i]->turbo_enc.cb_params.e = turbo_enc->cb_params.e;
			ops[i]->turbo_enc.cb_params.k = turbo_enc->cb_params.k;
			ops[i]->turbo_enc.cb_params.ncb =
					turbo_enc->cb_params.ncb;
		}
		ops[i]->turbo_enc.rv_index = turbo_enc->rv_index;
		ops[i]->turbo_enc.op_flags = turbo_enc->op_flags;
		ops[i]->turbo_enc.code_block_mode = turbo_enc->code_block_mode;

		ops[i]->turbo_enc.output = outputs[start_idx + i];
		ops[i]->turbo_enc.input = inputs[start_idx + i];
	}
}

static void
copy_reference_ldpc_dec_op(struct rte_bbdev_dec_op **ops, unsigned int n,
		unsigned int start_idx,
		struct rte_bbdev_op_data *inputs,
		struct rte_bbdev_op_data *hard_outputs,
		struct rte_bbdev_op_data *partial_outputs,
		struct rte_bbdev_op_data *soft_outputs,
		struct rte_bbdev_op_data *harq_inputs,
		struct rte_bbdev_op_data *harq_outputs,
		struct rte_bbdev_dec_op *ref_op)
{
	unsigned int i, j;
	struct rte_bbdev_op_ldpc_dec *ldpc_dec = &ref_op->ldpc_dec;

	for (i = 0; i < n; ++i) {
		if (ldpc_dec->code_block_mode == 0) {
			ops[i]->ldpc_dec.tb_params.ea =
					ldpc_dec->tb_params.ea;
			ops[i]->ldpc_dec.tb_params.eb =
					ldpc_dec->tb_params.eb;
			ops[i]->ldpc_dec.tb_params.c =
					ldpc_dec->tb_params.c;
			ops[i]->ldpc_dec.tb_params.cab =
					ldpc_dec->tb_params.cab;
			ops[i]->ldpc_dec.tb_params.r =
					ldpc_dec->tb_params.r;
		} else {
			ops[i]->ldpc_dec.cb_params.e = ldpc_dec->cb_params.e;
		}

		ops[i]->ldpc_dec.basegraph = ldpc_dec->basegraph;
		ops[i]->ldpc_dec.z_c = ldpc_dec->z_c;
		ops[i]->ldpc_dec.q_m = ldpc_dec->q_m;
		ops[i]->ldpc_dec.n_filler = ldpc_dec->n_filler;
		ops[i]->ldpc_dec.n_cb = ldpc_dec->n_cb;
		ops[i]->ldpc_dec.iter_max = ldpc_dec->iter_max;
		ops[i]->ldpc_dec.rv_index = ldpc_dec->rv_index;
		ops[i]->ldpc_dec.op_flags = ldpc_dec->op_flags;
		ops[i]->ldpc_dec.en_scramble = ldpc_dec->en_scramble;
		ops[i]->ldpc_dec.sd_cd_demux = ldpc_dec->sd_cd_demux;
		ops[i]->ldpc_dec.q = ldpc_dec->q;
		ops[i]->ldpc_dec.n_id = ldpc_dec->n_id;
		ops[i]->ldpc_dec.n_rnti = ldpc_dec->n_rnti;
		ops[i]->ldpc_dec.code_block_mode = ldpc_dec->code_block_mode;

		ops[i]->ldpc_dec.hard_output = hard_outputs[start_idx + i];
		if (ldpc_dec->op_flags & RTE_BBDEV_LDPC_PARTIAL_COMPACT_HARQ)
			ops[i]->ldpc_dec.partial_output =
				partial_outputs[start_idx + i];
		ops[i]->ldpc_dec.input = inputs[start_idx + i];
		if (soft_outputs != NULL)
			ops[i]->ldpc_dec.soft_output =
				soft_outputs[start_idx + i];
		if (harq_inputs != NULL)
			ops[i]->ldpc_dec.harq_combined_input =
					harq_inputs[start_idx + i];
		if (harq_outputs != NULL)
			ops[i]->ldpc_dec.harq_combined_output =
				harq_outputs[start_idx + i];
		if (ops[i]->ldpc_dec.sd_cd_demux) {
			ops[i]->ldpc_dec.sd_llrs_per_re = ldpc_dec->sd_llrs_per_re;
			rte_memcpy(&ops[i]->ldpc_dec.demux[0].sd_n_re_ack_re,
				&ldpc_dec->demux[0].sd_n_re_ack_re, 70 * 4);
		}
		for (j = 0; j < RTE_BBDEV_LDPC_MAX_CODE_BLOCKS/32; j++)
			ops[i]->ldpc_dec.codeblock_mask[j] =
				ldpc_dec->codeblock_mask[j];
	}
}


static void
copy_reference_ldpc_enc_op(struct rte_bbdev_enc_op **ops, unsigned int n,
		unsigned int start_idx,
		struct rte_bbdev_op_data *inputs,
		struct rte_bbdev_op_data *outputs,
		struct rte_bbdev_enc_op *ref_op)
{
	unsigned int i;
	struct rte_bbdev_op_ldpc_enc *ldpc_enc = &ref_op->ldpc_enc;
	for (i = 0; i < n; ++i) {
		if (ldpc_enc->code_block_mode == 0) {
			ops[i]->ldpc_enc.tb_params.ea = ldpc_enc->tb_params.ea;
			ops[i]->ldpc_enc.tb_params.eb = ldpc_enc->tb_params.eb;
			ops[i]->ldpc_enc.tb_params.cab =
					ldpc_enc->tb_params.cab;
			ops[i]->ldpc_enc.tb_params.c = ldpc_enc->tb_params.c;
			ops[i]->ldpc_enc.tb_params.r = ldpc_enc->tb_params.r;
		} else {
			ops[i]->ldpc_enc.cb_params.e = ldpc_enc->cb_params.e;
		}
		ops[i]->ldpc_enc.basegraph = ldpc_enc->basegraph;
		ops[i]->ldpc_enc.z_c = ldpc_enc->z_c;
		ops[i]->ldpc_enc.q_m = ldpc_enc->q_m;
		ops[i]->ldpc_enc.n_filler = ldpc_enc->n_filler;
		ops[i]->ldpc_enc.n_cb = ldpc_enc->n_cb;
		ops[i]->ldpc_enc.rv_index = ldpc_enc->rv_index;
		ops[i]->ldpc_enc.op_flags = ldpc_enc->op_flags;
		ops[i]->ldpc_enc.en_scramble = ldpc_enc->en_scramble;
		ops[i]->ldpc_enc.se_ce_mux = ldpc_enc->se_ce_mux;
		ops[i]->ldpc_enc.q = ldpc_enc->q;
		ops[i]->ldpc_enc.n_id = ldpc_enc->n_id;
		ops[i]->ldpc_enc.n_rnti = ldpc_enc->n_rnti;
		ops[i]->ldpc_enc.code_block_mode = ldpc_enc->code_block_mode;
		ops[i]->ldpc_enc.output = outputs[start_idx + i];
		ops[i]->ldpc_enc.input = inputs[start_idx + i];
		ops[i]->ldpc_enc.se_ce_mux_output_size = ldpc_enc->se_ce_mux_output_size;
		if (ops[i]->ldpc_enc.se_ce_mux) {
			ops[i]->ldpc_enc.se_bits_per_re = ldpc_enc->se_bits_per_re;
			rte_memcpy(&ops[i]->ldpc_enc.mux[0].se_n_re_ack_re,
				&ldpc_enc->mux[0].se_n_re_ack_re, 70 * 4);
		}
	}
}

static void
copy_reference_polar_op(struct rte_pmd_la12xx_op **ops, unsigned int n,
		unsigned int start_idx,
		struct rte_bbdev_op_data *inputs,
		struct rte_bbdev_op_data *outputs,
		struct rte_pmd_la12xx_op *ref_op)
{
	unsigned int i;
	for (i = 0; i < n; ++i) {
		ops[i]->polar_params.feca_obj = ref_op->polar_params.feca_obj;
		if (outputs)
			ops[i]->polar_params.output = outputs[start_idx + i];
		if (inputs)
			ops[i]->polar_params.input = inputs[start_idx + i];
		ops[i]->polar_params.dequeue_polar_deq_llrs =
			ref_op->polar_params.dequeue_polar_deq_llrs;
	}
}

static void
copy_reference_la12xx_raw_op(struct rte_pmd_la12xx_op **ops, unsigned int n,
		unsigned int start_idx,
		struct rte_bbdev_op_data *inputs,
		struct rte_bbdev_op_data *outputs)
{
	unsigned int i;

	for (i = 0; i < n; ++i) {
		if (outputs)
			ops[i]->raw_params.output = outputs[start_idx + i];
		if (inputs)
			ops[i]->raw_params.input = inputs[start_idx + i];
	}
}

static void
copy_reference_la12xx_vspa_op(struct rte_pmd_la12xx_op **ops, unsigned int n,
		unsigned int start_idx,
		struct rte_bbdev_op_data *inputs,
		struct rte_bbdev_op_data *outputs)
{
	unsigned int i;

	for (i = 0; i < n; ++i) {
		if (outputs)
			ops[i]->vspa_params.output = outputs[start_idx + i];
		if (inputs)
			ops[i]->vspa_params.input = inputs[start_idx + i];
	}
}

static int
check_dec_status_and_ordering(struct rte_bbdev_dec_op *op,
		unsigned int order_idx, const int expected_status)
{
	TEST_ASSERT(op->status == expected_status,
			"op_status (%d) != expected_status (%d)",
			op->status, expected_status);

	TEST_ASSERT((void *)(uintptr_t)order_idx == op->opaque_data,
			"Ordering error, expected %p, got %p",
			(void *)(uintptr_t)order_idx, op->opaque_data);

	return TEST_SUCCESS;
}

static int
check_enc_status_and_ordering(struct rte_bbdev_enc_op *op,
		unsigned int order_idx, const int expected_status)
{
	TEST_ASSERT(op->status == expected_status,
			"op_status (%d) != expected_status (%d)",
			op->status, expected_status);

	TEST_ASSERT((void *)(uintptr_t)order_idx == op->opaque_data,
			"Ordering error, expected %p, got %p",
			(void *)(uintptr_t)order_idx, op->opaque_data);

	return TEST_SUCCESS;
}

static int
check_polar_status_and_ordering(struct rte_pmd_la12xx_op *op,
		unsigned int order_idx, const int expected_status)
{
	TEST_ASSERT(op->status == expected_status,
			"op_status (%d) != expected_status (%d)",
			op->status, expected_status);

	TEST_ASSERT((void *)(uintptr_t)order_idx == op->opaque_data,
			"Ordering error, expected %p, got %p",
			(void *)(uintptr_t)order_idx, op->opaque_data);

	return TEST_SUCCESS;
}
static inline int
validate_op_chain(struct rte_bbdev_op_data *op,
		struct op_data_entries *orig_op)
{
	uint8_t i;
	struct rte_bbuf *b = op->bdata;
	uint8_t nb_dst_segments = orig_op->nb_segments;
	uint32_t total_data_size = 0;

	TEST_ASSERT(nb_dst_segments == op->is_direct_mem ? 1 : b->nb_segs,
			"Number of segments differ in original (%u) and filled (%u) op",
			nb_dst_segments, op->is_direct_mem ? 1 : b->nb_segs);

	/* Validate each bbuf segment length */
	for (i = 0; i < nb_dst_segments; ++i) {
		/* Apply offset to the first bbuf segment */
		uint16_t offset = (i == 0) ? op->offset : 0;
		uint32_t data_len = op->is_direct_mem ? op->length : rte_bbuf_data_len(b) - offset;
		total_data_size += orig_op->segments[i].length;
		TEST_ASSERT(orig_op->segments[i].length == data_len,
				"Length of segment differ in original (%u) and filled (%u) op",
				orig_op->segments[i].length, data_len);
		TEST_ASSERT_BUFFERS_ARE_EQUAL(orig_op->segments[i].addr,
				op->is_direct_mem ? op->mem :
				rte_bbuf_mtod_offset(b, uint32_t *, offset),
				data_len,
				"Output buffers (CB=%u) are not equal", i);
		b = b->next;
	}

	/* Validate total bbuf pkt length */
	uint32_t pkt_len = op->is_direct_mem ? op->length :
			rte_bbuf_pkt_len(op->bdata) - op->offset;
	TEST_ASSERT(total_data_size == pkt_len,
			"Length of data differ in original (%u) and filled (%u) op",
			total_data_size, pkt_len);

	return TEST_SUCCESS;
}

static int
validate_dec_op(struct rte_bbdev_dec_op **ops, const uint16_t n,
		struct rte_bbdev_dec_op *ref_op, const int vector_mask,
		struct test_bbdev_vector *vector)
{
	unsigned int i;
	int ret;
	struct op_data_entries *hard_data_orig =
			&vector->entries[DATA_HARD_OUTPUT];
	struct op_data_entries *soft_data_orig =
			&vector->entries[DATA_SOFT_OUTPUT];
	struct rte_bbdev_op_turbo_dec *ops_td;
	struct rte_bbdev_op_data *hard_output;
	struct rte_bbdev_op_data *soft_output;
	struct rte_bbdev_op_turbo_dec *ref_td = &ref_op->turbo_dec;

	for (i = 0; i < n; ++i) {
		ops_td = &ops[i]->turbo_dec;
		hard_output = &ops_td->hard_output;
		soft_output = &ops_td->soft_output;

		if (vector_mask & TEST_BBDEV_VF_EXPECTED_ITER_COUNT)
			TEST_ASSERT(ops_td->iter_count <= ref_td->iter_count,
					"Returned iter_count (%d) > expected iter_count (%d)",
					ops_td->iter_count, ref_td->iter_count);
		ret = check_dec_status_and_ordering(ops[i], i, ref_op->status);
		TEST_ASSERT_SUCCESS(ret,
				"Checking status and ordering for decoder failed");

		TEST_ASSERT_SUCCESS(validate_op_chain(hard_output,
				hard_data_orig),
				"Hard output buffers (CB=%u) are not equal",
				i);

		if (ref_op->turbo_dec.op_flags & RTE_BBDEV_TURBO_SOFT_OUTPUT)
			TEST_ASSERT_SUCCESS(validate_op_chain(soft_output,
					soft_data_orig),
					"Soft output buffers (CB=%u) are not equal",
					i);
	}

	return TEST_SUCCESS;
}


static int
validate_ldpc_dec_op(struct rte_bbdev_dec_op **ops, const uint16_t n,
		struct rte_bbdev_dec_op *ref_op, const int vector_mask,
		struct test_bbdev_vector *vector)
{
	unsigned int i;
	int ret;
	struct op_data_entries *hard_data_orig =
			&vector->entries[DATA_HARD_OUTPUT];
	struct op_data_entries *soft_data_orig =
			&vector->entries[DATA_SOFT_OUTPUT];
	struct op_data_entries *harq_data_orig =
				&vector->entries[DATA_HARQ_OUTPUT];
	struct rte_bbdev_op_ldpc_dec *ops_td;
	struct rte_bbdev_op_data *hard_output;
	struct rte_bbdev_op_data *harq_output;
	struct rte_bbdev_op_data *soft_output;
	struct rte_bbdev_op_ldpc_dec *ref_td = &ref_op->ldpc_dec;

	for (i = 0; i < n; ++i) {
		ops_td = &ops[i]->ldpc_dec;
		hard_output = &ops_td->hard_output;
		harq_output = &ops_td->harq_combined_output;
		soft_output = &ops_td->soft_output;

		ret = check_dec_status_and_ordering(ops[i], i, ref_op->status);
		TEST_ASSERT_SUCCESS(ret,
				"Checking status and ordering for decoder failed");
		if (vector_mask & TEST_BBDEV_VF_EXPECTED_ITER_COUNT)
			TEST_ASSERT(ops_td->iter_count <= ref_td->iter_count,
					"Returned iter_count (%d) > expected iter_count (%d)",
					ops_td->iter_count, ref_td->iter_count);
		/* We can ignore data when the decoding failed to converge */
		if ((ops[i]->status &  (1 << RTE_BBDEV_SYNDROME_ERROR)) == 0)
			TEST_ASSERT_SUCCESS(validate_op_chain(hard_output,
					hard_data_orig),
					"Hard output buffers (CB=%u) are not equal",
					i);

		if (ref_op->ldpc_dec.op_flags & RTE_BBDEV_LDPC_SOFT_OUT_ENABLE)
			TEST_ASSERT_SUCCESS(validate_op_chain(soft_output,
					soft_data_orig),
					"Soft output buffers (CB=%u) are not equal",
					i);
		if (ref_op->ldpc_dec.op_flags &
				RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE) {
			if (scale_llr_input)
				ldpc_input_llr_scaling(harq_output, 1, 8, 0);
			TEST_ASSERT_SUCCESS(validate_op_chain(harq_output,
					harq_data_orig),
					"HARQ output buffers (CB=%u) are not equal",
					i);
		}
	}

	return TEST_SUCCESS;
}


static int
validate_enc_op(struct rte_bbdev_enc_op **ops, const uint16_t n,
		struct rte_bbdev_enc_op *ref_op,
		struct test_bbdev_vector *vector)
{
	unsigned int i;
	int ret;
	struct op_data_entries *hard_data_orig =
			&vector->entries[DATA_HARD_OUTPUT];

	for (i = 0; i < n; ++i) {
		ret = check_enc_status_and_ordering(ops[i], i, ref_op->status);
		TEST_ASSERT_SUCCESS(ret,
				"Checking status and ordering for encoder failed");
		TEST_ASSERT_SUCCESS(validate_op_chain(
				&ops[i]->turbo_enc.output,
				hard_data_orig),
				"Output buffers (CB=%u) are not equal",
				i);
	}

	return TEST_SUCCESS;
}

static int
validate_polar_op(struct rte_pmd_la12xx_op **ops, const uint16_t n,
		struct rte_pmd_la12xx_op *ref_op,
		struct test_bbdev_vector *vector)
{
	unsigned int i;
	int ret;
	struct op_data_entries *hard_data_orig =
			&vector->entries[DATA_HARD_OUTPUT];

	for (i = 0; i < n; ++i) {
		ret = check_polar_status_and_ordering(ops[i], i, ref_op->status);
		TEST_ASSERT_SUCCESS(ret,
				"Checking status and ordering for encoder failed");
		TEST_ASSERT_SUCCESS(validate_op_chain(
				&ops[i]->polar_params.output,
				hard_data_orig),
				"Output buffers (CB=%u) are not equal",
				i);
	}

	return TEST_SUCCESS;
}

static int
validate_raw_op(struct rte_pmd_la12xx_op **ops, const uint16_t n,
		struct test_bbdev_vector *vector)
{
	unsigned int i;
	struct op_data_entries *hard_data_orig =
			&vector->entries[DATA_HARD_OUTPUT];

	for (i = 0; i < n; ++i) {
		TEST_ASSERT_SUCCESS(validate_op_chain(
				&ops[i]->raw_params.output,
				hard_data_orig),
				"Output buffers (CB=%u) are not equal",
				i);
	}

	return TEST_SUCCESS;
}

static int
validate_ldpc_enc_op(struct rte_bbdev_enc_op **ops, const uint16_t n,
		struct rte_bbdev_enc_op *ref_op,
		struct test_bbdev_vector *vector)
{
	unsigned int i;
	int ret;
	struct op_data_entries *hard_data_orig =
			&vector->entries[DATA_HARD_OUTPUT];

	for (i = 0; i < n; ++i) {
		ret = check_enc_status_and_ordering(ops[i], i, ref_op->status);
		TEST_ASSERT_SUCCESS(ret,
				"Checking status and ordering for encoder failed");
		TEST_ASSERT_SUCCESS(validate_op_chain(
				&ops[i]->ldpc_enc.output,
				hard_data_orig),
				"Output buffers (CB=%u) are not equal",
				i);
	}

	return TEST_SUCCESS;
}

static void
create_reference_dec_op(struct rte_bbdev_dec_op *op,
			struct test_bbdev_vector *vector)
{
	unsigned int i;
	struct op_data_entries *entry;

	op->turbo_dec = vector->turbo_dec;
	entry = &vector->entries[DATA_INPUT];
	for (i = 0; i < entry->nb_segments; ++i)
		op->turbo_dec.input.length +=
				entry->segments[i].length;
}

static void
create_reference_ldpc_dec_op(struct rte_bbdev_dec_op *op,
			     struct test_bbdev_vector *vector)
{
	unsigned int i;
	struct op_data_entries *entry;

	op->ldpc_dec = vector->ldpc_dec;
	entry = &vector->entries[DATA_INPUT];
	for (i = 0; i < entry->nb_segments; ++i)
		op->ldpc_dec.input.length +=
				entry->segments[i].length;
	if (vector->ldpc_dec.op_flags &
			RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) {
		entry = &vector->entries[DATA_HARQ_INPUT];
		for (i = 0; i < entry->nb_segments; ++i)
			op->ldpc_dec.harq_combined_input.length +=
				entry->segments[i].length;
	}
}


static void
create_reference_enc_op(struct rte_bbdev_enc_op *op,
			struct test_bbdev_vector *vector)
{
	unsigned int i;
	struct op_data_entries *entry;

	op->turbo_enc = vector->turbo_enc;
	entry = &vector->entries[DATA_INPUT];
	for (i = 0; i < entry->nb_segments; ++i)
		op->turbo_enc.input.length +=
				entry->segments[i].length;
}

static void
create_reference_ldpc_enc_op(struct rte_bbdev_enc_op *op,
			     struct test_bbdev_vector *vector)
{
	unsigned int i;
	struct op_data_entries *entry;

	op->ldpc_enc = vector->ldpc_enc;
	entry = &vector->entries[DATA_INPUT];
	for (i = 0; i < entry->nb_segments; ++i)
		op->ldpc_enc.input.length +=
				entry->segments[i].length;
}

static void
create_reference_polar_op(struct rte_pmd_la12xx_op *op,
			  struct test_bbdev_vector *vector)
{
	unsigned int i;
	struct op_data_entries *entry;

	RTE_PMD_LA12xx_POLAR_OP_DESC(op) =
			RTE_PMD_LA12xx_POLAR_OP_DESC(&vector->la12xx_op);
	entry = &vector->entries[DATA_INPUT];
	for (i = 0; i < entry->nb_segments; ++i)
		op->polar_params.input.length +=
				entry->segments[i].length;
	op->polar_params.dequeue_polar_deq_llrs =
		vector->la12xx_op.polar_params.dequeue_polar_deq_llrs;
	op->status = vector->expected_status;
}

static void
create_reference_la12xx_raw_op(struct rte_pmd_la12xx_op *op,
			  struct test_bbdev_vector *vector)
{
	unsigned int i;
	struct op_data_entries *entry;

	entry = &vector->entries[DATA_INPUT];
	for (i = 0; i < entry->nb_segments; ++i)
		op->polar_params.input.length +=
				entry->segments[i].length;
}

static void
create_reference_la12xx_vspa_op(struct rte_pmd_la12xx_op *op,
			  struct test_bbdev_vector *vector)
{
	unsigned int i;
	struct op_data_entries *entry;

	entry = &vector->entries[DATA_INPUT];
	for (i = 0; i < entry->nb_segments; ++i)
		op->polar_params.input.length +=
				entry->segments[i].length;
}

static uint32_t
calc_dec_TB_size(struct rte_bbdev_dec_op *op)
{
	uint8_t i;
	uint32_t c, r, tb_size = 0;

	if (op->turbo_dec.code_block_mode) {
		tb_size = op->turbo_dec.tb_params.k_neg;
	} else {
		c = op->turbo_dec.tb_params.c;
		r = op->turbo_dec.tb_params.r;
		for (i = 0; i < c-r; i++)
			tb_size += (r < op->turbo_dec.tb_params.c_neg) ?
				op->turbo_dec.tb_params.k_neg :
				op->turbo_dec.tb_params.k_pos;
	}
	return tb_size;
}

static uint32_t
calc_ldpc_dec_TB_size(struct rte_bbdev_dec_op *op)
{
	uint8_t i;
	uint32_t c, r, tb_size = 0;
	uint16_t sys_cols = (op->ldpc_dec.basegraph == 1) ? 22 : 10;

	if (op->ldpc_dec.code_block_mode) {
		tb_size = sys_cols * op->ldpc_dec.z_c - op->ldpc_dec.n_filler;
	} else {
		c = op->ldpc_dec.tb_params.c;
		r = op->ldpc_dec.tb_params.r;
		for (i = 0; i < c-r; i++)
			tb_size += sys_cols * op->ldpc_dec.z_c
					- op->ldpc_dec.n_filler;
	}
	return tb_size;
}

static uint32_t
calc_enc_TB_size(struct rte_bbdev_enc_op *op)
{
	uint8_t i;
	uint32_t c, r, tb_size = 0;

	if (op->turbo_enc.code_block_mode) {
		tb_size = op->turbo_enc.tb_params.k_neg;
	} else {
		c = op->turbo_enc.tb_params.c;
		r = op->turbo_enc.tb_params.r;
		for (i = 0; i < c-r; i++)
			tb_size += (r < op->turbo_enc.tb_params.c_neg) ?
				op->turbo_enc.tb_params.k_neg :
				op->turbo_enc.tb_params.k_pos;
	}
	return tb_size;
}

static uint32_t
calc_ldpc_enc_TB_size(struct rte_bbdev_enc_op *op)
{
	uint8_t i;
	uint32_t c, r, tb_size = 0;
	uint16_t sys_cols = (op->ldpc_enc.basegraph == 1) ? 22 : 10;

	if (op->ldpc_enc.code_block_mode) {
		tb_size = sys_cols * op->ldpc_enc.z_c - op->ldpc_enc.n_filler;
	} else {
		c = op->ldpc_enc.tb_params.c;
		r = op->ldpc_enc.tb_params.r;
		for (i = 0; i < c-r; i++)
			tb_size += sys_cols * op->ldpc_enc.z_c
					- op->ldpc_enc.n_filler;
	}
	return tb_size;
}


static int
init_test_op_params(struct test_op_params *op_params,
		enum rte_bbdev_op_type op_type, const int expected_status,
		const uint64_t vector_mask, struct rte_mempool *ops_mp,
		uint16_t burst_sz, uint16_t num_to_process, uint16_t num_lcores)
{
	int ret = 0;
	if (op_type == RTE_BBDEV_OP_TURBO_DEC ||
			op_type == RTE_BBDEV_OP_LDPC_DEC)
		ret = rte_bbdev_dec_op_alloc_bulk(ops_mp,
				&op_params->ref_dec_op, 1);
	else if (op_type == RTE_BBDEV_OP_TURBO_ENC ||
			op_type == RTE_BBDEV_OP_LDPC_ENC)
		ret = rte_bbdev_enc_op_alloc_bulk(ops_mp,
				&op_params->ref_enc_op, 1);
	else
		ret = rte_mempool_get_bulk(ops_mp,
			(void **)&op_params->ref_la12xx_op, 1);

	TEST_ASSERT_SUCCESS(ret, "rte_bbdev_op_alloc_bulk() failed");

	op_params->mp = ops_mp;
	op_params->burst_sz = burst_sz;
	op_params->num_to_process = num_to_process;
	op_params->num_lcores = num_lcores;
	op_params->vector_mask = vector_mask;
	if (op_type == RTE_BBDEV_OP_TURBO_DEC ||
			op_type == RTE_BBDEV_OP_LDPC_DEC)
		op_params->ref_dec_op->status = expected_status;
	else if (op_type == RTE_BBDEV_OP_TURBO_ENC
			|| op_type == RTE_BBDEV_OP_LDPC_ENC)
		op_params->ref_enc_op->status = expected_status;
	else
		op_params->ref_la12xx_op->status = expected_status;

	return 0;
}

static int
run_test_case_on_device(test_case_function *test_case_func, uint8_t dev_id,
		struct test_op_params *op_params)
{
	int t_ret, f_ret, socket_id = SOCKET_ID_ANY;
	unsigned int i, lcore_id, v;
	struct active_device *ad;
	unsigned int burst_sz = get_burst_sz();
	const struct rte_bbdev_op_cap *capabilities = NULL;
	enum rte_bbdev_op_type op_type;

	ad = &active_devs[dev_id];

	for (i = 0; i < get_vector_count(); i++) {
		/* Check if device supports op_type */
		if (!is_avail_op(ad, test_vector[i].op_type)) {
			printf("not supported test vector\n");
			return TEST_FAILED;
		}
	}

	struct rte_bbdev_info info;
	rte_bbdev_info_get(ad->dev_id, &info);
	socket_id = GET_SOCKET(info.socket_id);

	f_ret = create_mempools(ad, socket_id, test_vector,
			get_num_ops());
	if (f_ret != TEST_SUCCESS) {
		printf("Couldn't create mempools");
		goto fail;
	}

	/* currently only one op_param/vector supported per core,
	 * in future for multi vectors per core, multi op_params
	 * to be supported per core.
	 */
	RTE_LCORE_FOREACH(lcore_id) {
		for (v = 0; v < get_vector_count(); v++) {
			if ((&test_vector[v])->core_mask & (1 << lcore_id))
				break;
		}

		if (v >= get_vector_count()) {
			printf("No Vector available for Core %u\n", lcore_id);
			goto fail;
		}
		op_type = test_vector[v].op_type;
		if (op_type == RTE_BBDEV_OP_NONE)
			op_type = RTE_BBDEV_OP_TURBO_ENC;
		f_ret = init_test_op_params(&op_params[lcore_id], op_type,
				test_vector[v].expected_status,
				test_vector[v].mask,
				ad->ops_mempool[op_type],
				burst_sz,
				get_num_ops(),
				get_num_lcores());
		if (f_ret != TEST_SUCCESS) {
			printf("Couldn't init test op params");
			goto fail;
		}

		op_params[lcore_id].vector = &test_vector[v];

		/* Find capabilities */
		const struct rte_bbdev_op_cap *cap = info.drv.capabilities;
		for (i = 0; i < RTE_BBDEV_OP_TYPE_COUNT; i++) {
			if (cap->type == test_vector[v].op_type) {
				capabilities = cap;
				break;
			}
			cap++;
		}
		TEST_ASSERT_NOT_NULL(capabilities,
					"Couldn't find capabilities");

		if (op_type == RTE_BBDEV_OP_TURBO_DEC) {
			create_reference_dec_op(
			(&op_params[lcore_id])->ref_dec_op, &test_vector[v]);
		} else if (op_type == RTE_BBDEV_OP_TURBO_ENC) {
			create_reference_enc_op(
			(&op_params[lcore_id])->ref_enc_op, &test_vector[v]);
		} else if (op_type == RTE_BBDEV_OP_LDPC_ENC) {
			create_reference_ldpc_enc_op(
			(&op_params[lcore_id])->ref_enc_op, &test_vector[v]);
		} else if (op_type == RTE_BBDEV_OP_LDPC_DEC) {
			create_reference_ldpc_dec_op(
			(&op_params[lcore_id])->ref_dec_op, &test_vector[v]);
		} else if (op_type == RTE_BBDEV_OP_RAW) {
			create_reference_la12xx_raw_op(
			(&op_params[lcore_id])->ref_la12xx_op, &test_vector[v]);
		} else if (op_type == RTE_BBDEV_OP_LA12XX_VSPA) {
			create_reference_la12xx_vspa_op(
			(&op_params[lcore_id])->ref_la12xx_op, &test_vector[v]);
		} else {
			create_reference_polar_op(
			(&op_params[lcore_id])->ref_la12xx_op, &test_vector[v]);
		}

		for (i = 0; i < ad->nb_queues; ++i) {
			f_ret = fill_queue_buffers(&op_params[lcore_id],
					ad->in_bbuf_pool,
					ad->hard_out_bbuf_pool,
					ad->partial_out_bbuf_pool,
					ad->soft_out_bbuf_pool,
					ad->harq_in_bbuf_pool,
					ad->harq_out_bbuf_pool,
					ad->queue_ids[i],
					capabilities,
					info.drv.min_alignment,
					socket_id,
					&test_vector[v]);
			if (f_ret != TEST_SUCCESS) {
				printf("Couldn't init queue buffers");
				goto fail;
			}
		}
	}

	/* Run test case function */
	t_ret = test_case_func(ad, op_params);

	/* Free active device resources and return */
	free_buffers(ad, op_params);
	rte_mempool_free(bbdev_bbuf_pool);
	return t_ret;

fail:
	free_buffers(ad, op_params);
	return TEST_FAILED;
}

/* Run given test function per active device per supported op type
 * per burst size.
 */
static int
run_test_case(test_case_function *test_case_func)
{
	int ret = 0;
	uint8_t dev;

	/* Alloc op_params */
	struct test_op_params *op_params = rte_zmalloc(NULL,
			sizeof(struct test_op_params) * RTE_MAX_LCORE,
			RTE_CACHE_LINE_SIZE);
	TEST_ASSERT_NOT_NULL(op_params, "Failed to alloc %zuB for op_params",
			RTE_ALIGN(sizeof(struct test_op_params) * RTE_MAX_LCORE,
				RTE_CACHE_LINE_SIZE));

	/* For each device run test case function */
	for (dev = 0; dev < nb_active_devs; ++dev)
		ret |= run_test_case_on_device(test_case_func, dev, op_params);

	rte_free(op_params);

	return ret;
}

static void
update_orig_ldpc_dec_out_data(struct rte_bbdev_dec_op **ops, const uint16_t n)
{
	struct rte_bbdev_dec_op *op;
	struct rte_bbdev_op_data *hard_output, *partial_output;
	int op_index, i, num_cbs, cb_size;
	int bit_index, byte_index;
	int start_index = -1, end_index = -1;
	uint8_t *cb_mask, *crc_mask;
	uint8_t *hard_data, *partial_data;
	uint64_t len_to_copy, addr_off;

	for (op_index = 0; op_index < n; op_index++) {
		op = ops[op_index];
		hard_output = &op->ldpc_dec.hard_output;
		partial_output = &op->ldpc_dec.partial_output;

		num_cbs = op->ldpc_dec.tb_params.c;
		cb_size = (hard_output->length + 3)/num_cbs;	/* Add 3 for CRC */

		cb_mask = (uint8_t *)op->ldpc_dec.codeblock_mask;
		crc_mask = (uint8_t *)op->crc_stat;

		hard_data = hard_output->is_direct_mem ? hard_output->mem :
			rte_bbuf_mtod((struct rte_bbuf *)(hard_output->bdata),
				      uint8_t *);
		partial_data = partial_output->is_direct_mem ?
			partial_output->mem :
			rte_bbuf_mtod((struct rte_bbuf *)(partial_output->bdata),
				      uint8_t *);

		byte_index = 0;
		bit_index = 0;

		/* Check all code blocks */
		for (i = 0; i < num_cbs; i++) {
			if (((crc_mask[byte_index] & (1 << bit_index)) == 1) &&
			    ((cb_mask[byte_index] & (1 << bit_index)) == 1)) {
				if (start_index == -1)
					start_index = i;
				end_index = i;
			}

			if ((start_index != -1) && ((end_index != i) ||
			    (end_index == (num_cbs - 1)))) {
				addr_off = (uint64_t)start_index * cb_size;
				len_to_copy = (uint64_t)(end_index - start_index + 1) *
					cb_size;
				memcpy(hard_data + addr_off, partial_data +
				       addr_off, len_to_copy);
				start_index = -1;
			}

			/* Update bit and byte index */
			bit_index++;
			if (bit_index == 8) {
				byte_index++;
				bit_index = 0;
			}
		}
	}
}

static void
dequeue_event_callback(uint16_t dev_id,
		enum rte_bbdev_event_type event, void *cb_arg,
		void *ret_param)
{
	int ret;
	uint16_t i;
	uint64_t total_time;
	uint16_t deq, burst_sz, num_ops;
	uint16_t queue_id = *(uint16_t *) ret_param;
	struct rte_bbdev_info info;
	double tb_len_bits;
	struct thread_params *tp = cb_arg;
	struct test_bbdev_vector *vector;

	vector = tp->op_params->vector;
	/* Find matching thread params using queue_id */
	for (i = 0; i < MAX_QUEUES; ++i, ++tp)
		if (tp->queue_id == queue_id)
			break;

	if (i == MAX_QUEUES) {
		printf("%s: Queue_id from interrupt details was not found!\n",
				__func__);
		return;
	}

	if (unlikely(event != RTE_BBDEV_EVENT_DEQUEUE)) {
		rte_atomic16_set(&tp->processing_status, TEST_FAILED);
		printf(
			"Dequeue interrupt handler called for incorrect event!\n");
		return;
	}

	burst_sz = rte_atomic16_read(&tp->burst_sz);
	num_ops = tp->op_params->num_to_process;

	if (vector->op_type == RTE_BBDEV_OP_TURBO_DEC ||
			vector->op_type == RTE_BBDEV_OP_LDPC_DEC)
		deq = rte_bbdev_dequeue_dec_ops(dev_id, queue_id,
				&tp->dec_ops[
					rte_atomic16_read(&tp->nb_dequeued)],
				burst_sz);
	else if ((vector->op_type == RTE_BBDEV_OP_POLAR_DEC) ||
				(vector->op_type == RTE_BBDEV_OP_POLAR_ENC))
		deq = rte_pmd_la12xx_dequeue_ops(dev_id, queue_id,
				&tp->polar_ops[rte_atomic16_read(&tp->nb_dequeued)],
				burst_sz);
	else
		deq = rte_bbdev_dequeue_enc_ops(dev_id, queue_id,
				&tp->enc_ops[
					rte_atomic16_read(&tp->nb_dequeued)],
				burst_sz);

	if (deq < burst_sz) {
		printf(
			"After receiving the interrupt all operations should be dequeued. Expected: %u, got: %u\n",
			burst_sz, deq);
		rte_atomic16_set(&tp->processing_status, TEST_FAILED);
		return;
	}

	if (rte_atomic16_read(&tp->nb_dequeued) + deq < num_ops) {
		rte_atomic16_add(&tp->nb_dequeued, deq);
		return;
	}

	total_time = rte_rdtsc_precise() - tp->start_time;

	rte_bbdev_info_get(dev_id, &info);

	ret = TEST_SUCCESS;

	if (vector->op_type == RTE_BBDEV_OP_TURBO_DEC) {
		struct rte_bbdev_dec_op *ref_op = tp->op_params->ref_dec_op;
		ret = validate_dec_op(tp->dec_ops, num_ops, ref_op,
				tp->op_params->vector_mask,
				tp->op_params->vector);
		/* get the max of iter_count for all dequeued ops */
		for (i = 0; i < num_ops; ++i)
			tp->iter_count = RTE_MAX(
					tp->dec_ops[i]->turbo_dec.iter_count,
					tp->iter_count);
		rte_bbdev_dec_op_free_bulk(tp->dec_ops, deq);
	} else if (vector->op_type == RTE_BBDEV_OP_TURBO_ENC) {
		struct rte_bbdev_enc_op *ref_op = tp->op_params->ref_enc_op;
		ret = validate_enc_op(tp->enc_ops, num_ops, ref_op, vector);
		rte_bbdev_enc_op_free_bulk(tp->enc_ops, deq);
	} else if (vector->op_type == RTE_BBDEV_OP_LDPC_ENC) {
		struct rte_bbdev_enc_op *ref_op = tp->op_params->ref_enc_op;
		ret = validate_ldpc_enc_op(tp->enc_ops, num_ops, ref_op,
					   vector);
		rte_bbdev_enc_op_free_bulk(tp->enc_ops, deq);
	} else if (vector->op_type == RTE_BBDEV_OP_LDPC_DEC) {
		struct rte_bbdev_dec_op *ref_op = tp->op_params->ref_dec_op;
		ret = validate_ldpc_dec_op(tp->dec_ops, num_ops, ref_op,
				tp->op_params->vector_mask, vector);
		rte_bbdev_dec_op_free_bulk(tp->dec_ops, deq);
	} else if ((vector->op_type == RTE_BBDEV_OP_POLAR_DEC) ||
			(vector->op_type == RTE_BBDEV_OP_POLAR_ENC)) {
		struct rte_pmd_la12xx_op *ref_op = tp->op_params->ref_la12xx_op;
		ret = validate_polar_op(tp->polar_ops, num_ops, ref_op, vector);
		rte_mempool_put_bulk(tp->polar_ops[0]->polar_params.mempool,
				     (void **)tp->dec_ops, deq);
	}

	if (ret) {
		printf("Buffers validation failed\n");
		rte_atomic16_set(&tp->processing_status, TEST_FAILED);
	}

	switch (vector->op_type) {
	case RTE_BBDEV_OP_TURBO_DEC:
		tb_len_bits = calc_dec_TB_size(tp->op_params->ref_dec_op);
		break;
	case RTE_BBDEV_OP_TURBO_ENC:
		tb_len_bits = calc_enc_TB_size(tp->op_params->ref_enc_op);
		break;
	case RTE_BBDEV_OP_LDPC_DEC:
		tb_len_bits = calc_ldpc_dec_TB_size(tp->op_params->ref_dec_op);
		break;
	case RTE_BBDEV_OP_LDPC_ENC:
		tb_len_bits = calc_ldpc_enc_TB_size(tp->op_params->ref_enc_op);
		break;
	case RTE_BBDEV_OP_NONE:
		tb_len_bits = 0.0;
		break;
	default:
		printf("Unknown op type: %d\n", vector->op_type);
		rte_atomic16_set(&tp->processing_status, TEST_FAILED);
		return;
	}

	tp->ops_per_sec += ((double)num_ops) /
			((double)total_time / (double)rte_get_tsc_hz());
	tp->mbps += (((double)(num_ops * tb_len_bits)) / 1000000.0) /
			((double)total_time / (double)rte_get_tsc_hz());

	rte_atomic16_add(&tp->nb_dequeued, deq);
}

static int
throughput_intr_lcore_dec(void *arg)
{
	struct thread_params *tp = arg;
	unsigned int enqueued;
	const uint16_t queue_id = tp->queue_id;
	const uint16_t burst_sz = tp->op_params->burst_sz;
	const uint16_t num_to_process = tp->op_params->num_to_process;
	struct rte_bbdev_dec_op *ops[num_to_process];
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	int ret, i, j;
	uint16_t num_to_enq, enq;

	TEST_ASSERT_SUCCESS((burst_sz > MAX_BURST),
			"BURST_SIZE should be <= %u", MAX_BURST);

	TEST_ASSERT_SUCCESS(rte_bbdev_queue_intr_enable(tp->dev_id, queue_id),
			"Failed to enable interrupts for dev: %u, queue_id: %u",
			tp->dev_id, queue_id);

	rte_bbdev_info_get(tp->dev_id, &info);

	TEST_ASSERT_SUCCESS((num_to_process > info.drv.queue_size_lim),
			"NUM_OPS cannot exceed %u for this device",
			info.drv.queue_size_lim);

	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	rte_atomic16_clear(&tp->processing_status);
	rte_atomic16_clear(&tp->nb_dequeued);

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_bbdev_dec_op_alloc_bulk(tp->op_params->mp, ops,
				num_to_process);
	TEST_ASSERT_SUCCESS(ret, "Allocation failed for %d ops",
			num_to_process);
	if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_dec_op(ops, num_to_process, 0, bufs->inputs,
				bufs->hard_outputs, bufs->soft_outputs,
				tp->op_params->ref_dec_op);

	/* Set counter to validate the ordering */
	for (j = 0; j < num_to_process; ++j)
		ops[j]->opaque_data = (void *)(uintptr_t)j;

	for (j = 0; j < TEST_REPETITIONS; ++j) {
		for (i = 0; i < num_to_process; ++i)
			rte_bbuf_reset(ops[i]->turbo_dec.hard_output.bdata);

		tp->start_time = rte_rdtsc_precise();
		for (enqueued = 0; enqueued < num_to_process;) {
			num_to_enq = burst_sz;

			if (unlikely(num_to_process - enqueued < num_to_enq))
				num_to_enq = num_to_process - enqueued;

			enq = 0;
			do {
				enq += rte_bbdev_enqueue_dec_ops(tp->dev_id,
						queue_id, &ops[enqueued],
						num_to_enq);
			} while (unlikely(num_to_enq != enq));
			enqueued += enq;

			/* Write to thread burst_sz current number of enqueued
			 * descriptors. It ensures that proper number of
			 * descriptors will be dequeued in callback
			 * function - needed for last batch in case where
			 * the number of operations is not a multiple of
			 * burst size.
			 */
			rte_atomic16_set(&tp->burst_sz, num_to_enq);

			/* Wait until processing of previous batch is
			 * completed
			 */
			while (rte_atomic16_read(&tp->nb_dequeued) !=
					(int16_t) enqueued)
				rte_pause();
		}
		if (j != TEST_REPETITIONS - 1)
			rte_atomic16_clear(&tp->nb_dequeued);
	}

	return TEST_SUCCESS;
}

static int
throughput_intr_lcore_enc(void *arg)
{
	struct thread_params *tp = arg;
	unsigned int enqueued;
	const uint16_t queue_id = tp->queue_id;
	const uint16_t burst_sz = tp->op_params->burst_sz;
	const uint16_t num_to_process = tp->op_params->num_to_process;
	struct rte_bbdev_enc_op *ops[num_to_process];
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	int ret, i, j;
	uint16_t num_to_enq, enq;

	TEST_ASSERT_SUCCESS((burst_sz > MAX_BURST),
			"BURST_SIZE should be <= %u", MAX_BURST);

	TEST_ASSERT_SUCCESS(rte_bbdev_queue_intr_enable(tp->dev_id, queue_id),
			"Failed to enable interrupts for dev: %u, queue_id: %u",
			tp->dev_id, queue_id);

	rte_bbdev_info_get(tp->dev_id, &info);

	TEST_ASSERT_SUCCESS((num_to_process > info.drv.queue_size_lim),
			"NUM_OPS cannot exceed %u for this device",
			info.drv.queue_size_lim);

	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	rte_atomic16_clear(&tp->processing_status);
	rte_atomic16_clear(&tp->nb_dequeued);

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_bbdev_enc_op_alloc_bulk(tp->op_params->mp, ops,
			num_to_process);
	TEST_ASSERT_SUCCESS(ret, "Allocation failed for %d ops",
			num_to_process);
	if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_enc_op(ops, num_to_process, 0, bufs->inputs,
				bufs->hard_outputs, tp->op_params->ref_enc_op);

	/* Set counter to validate the ordering */
	for (j = 0; j < num_to_process; ++j)
		ops[j]->opaque_data = (void *)(uintptr_t)j;

	for (j = 0; j < TEST_REPETITIONS; ++j) {
		for (i = 0; i < num_to_process; ++i)
			rte_bbuf_reset(ops[i]->turbo_enc.output.bdata);

		tp->start_time = rte_rdtsc_precise();
		for (enqueued = 0; enqueued < num_to_process;) {
			num_to_enq = burst_sz;

			if (unlikely(num_to_process - enqueued < num_to_enq))
				num_to_enq = num_to_process - enqueued;

			enq = 0;
			do {
				enq += rte_bbdev_enqueue_enc_ops(tp->dev_id,
						queue_id, &ops[enqueued],
						num_to_enq);
			} while (unlikely(enq != num_to_enq));
			enqueued += enq;

			/* Write to thread burst_sz current number of enqueued
			 * descriptors. It ensures that proper number of
			 * descriptors will be dequeued in callback
			 * function - needed for last batch in case where
			 * the number of operations is not a multiple of
			 * burst size.
			 */
			rte_atomic16_set(&tp->burst_sz, num_to_enq);

			/* Wait until processing of previous batch is
			 * completed
			 */
			while (rte_atomic16_read(&tp->nb_dequeued) !=
					(int16_t) enqueued)
				rte_pause();
		}
		if (j != TEST_REPETITIONS - 1)
			rte_atomic16_clear(&tp->nb_dequeued);
	}

	return TEST_SUCCESS;
}

static int
throughput_intr_lcore_polar(void *arg)
{
	struct thread_params *tp = arg;
	unsigned int enqueued;
	const uint16_t queue_id = tp->queue_id;
	const uint16_t burst_sz = tp->op_params->burst_sz;
	const uint16_t num_to_process = tp->op_params->num_to_process;
	struct rte_pmd_la12xx_op *ops[num_to_process];
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	int ret, i, j;
	uint16_t num_to_enq, enq;

	TEST_ASSERT_SUCCESS((burst_sz > MAX_BURST),
			"BURST_SIZE should be <= %u", MAX_BURST);

	TEST_ASSERT_SUCCESS(rte_bbdev_queue_intr_enable(tp->dev_id, queue_id),
			"Failed to enable interrupts for dev: %u, queue_id: %u",
			tp->dev_id, queue_id);

	rte_bbdev_info_get(tp->dev_id, &info);

	TEST_ASSERT_SUCCESS((num_to_process > info.drv.queue_size_lim),
			"NUM_OPS cannot exceed %u for this device",
			info.drv.queue_size_lim);

	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	rte_atomic16_clear(&tp->processing_status);
	rte_atomic16_clear(&tp->nb_dequeued);

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_mempool_get_bulk(tp->op_params->mp, (void **)ops,
			num_to_process);
	TEST_ASSERT_SUCCESS(ret, "Allocation failed for %d ops",
			num_to_process);
	if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_polar_op(ops, num_to_process, 0, bufs->inputs,
				bufs->hard_outputs, tp->op_params->ref_la12xx_op);

	/* Set counter to validate the ordering */
	for (j = 0; j < num_to_process; ++j)
		ops[j]->opaque_data = (void *)(uintptr_t)j;

	for (j = 0; j < TEST_REPETITIONS; ++j) {
		for (i = 0; i < num_to_process; ++i)
			bbuf_reset(ops[i]->polar_params.output.bdata);

		tp->start_time = rte_rdtsc_precise();
		for (enqueued = 0; enqueued < num_to_process;) {
			num_to_enq = burst_sz;

			if (unlikely(num_to_process - enqueued < num_to_enq))
				num_to_enq = num_to_process - enqueued;

			enq = 0;
			do {
				enq += rte_pmd_la12xx_enqueue_ops(tp->dev_id,
						queue_id, &ops[enqueued],
						num_to_enq);
			} while (unlikely(enq != num_to_enq));
			enqueued += enq;

			/* Write to thread burst_sz current number of enqueued
			 * descriptors. It ensures that proper number of
			 * descriptors will be dequeued in callback
			 * function - needed for last batch in case where
			 * the number of operations is not a multiple of
			 * burst size.
			 */
			rte_atomic16_set(&tp->burst_sz, num_to_enq);

			/* Wait until processing of previous batch is
			 * completed
			 */
			while (rte_atomic16_read(&tp->nb_dequeued) !=
					(int16_t) enqueued)
				rte_pause();
		}
		if (j != TEST_REPETITIONS - 1)
			rte_atomic16_clear(&tp->nb_dequeued);
	}

	return TEST_SUCCESS;
}

static int
throughput_pmd_lcore_dec(void *arg)
{
	struct thread_params *tp = arg;
	uint16_t enq, deq;
	uint64_t total_time = 0, start_time;
	const uint16_t queue_id = tp->queue_id;
	const uint16_t burst_sz = tp->op_params->burst_sz;
	const uint16_t num_ops = tp->op_params->num_to_process;
	struct rte_bbdev_dec_op *ops_enq[num_ops];
	struct rte_bbdev_dec_op *ops_deq[num_ops];
	struct rte_bbdev_dec_op *ref_op = tp->op_params->ref_dec_op;
	struct test_buffers *bufs = NULL;
	int i, j, ret;
	struct rte_bbdev_info info;
	uint16_t num_to_enq;

	TEST_ASSERT_SUCCESS((burst_sz > MAX_BURST),
			"BURST_SIZE should be <= %u", MAX_BURST);

	rte_bbdev_info_get(tp->dev_id, &info);

	TEST_ASSERT_SUCCESS((num_ops > info.drv.queue_size_lim),
			"NUM_OPS cannot exceed %u for this device",
			info.drv.queue_size_lim);

	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_bbdev_dec_op_alloc_bulk(tp->op_params->mp, ops_enq, num_ops);
	TEST_ASSERT_SUCCESS(ret, "Allocation failed for %d ops", num_ops);

	if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_dec_op(ops_enq, num_ops, 0, bufs->inputs,
				bufs->hard_outputs, bufs->soft_outputs, ref_op);

	/* Set counter to validate the ordering */
	for (j = 0; j < num_ops; ++j)
		ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

	for (i = 0; i < TEST_REPETITIONS; ++i) {

		for (j = 0; j < num_ops; ++j)
			bbuf_reset(ops_enq[j]->turbo_dec.hard_output.bdata);

		start_time = rte_rdtsc_precise();

		for (enq = 0, deq = 0; enq < num_ops;) {
			num_to_enq = burst_sz;

			if (unlikely(num_ops - enq < num_to_enq))
				num_to_enq = num_ops - enq;

			enq += rte_bbdev_enqueue_dec_ops(tp->dev_id,
					queue_id, &ops_enq[enq], num_to_enq);

			deq += rte_bbdev_dequeue_dec_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		/* dequeue the remaining */
		while (deq < enq) {
			deq += rte_bbdev_dequeue_dec_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		total_time += rte_rdtsc_precise() - start_time;
	}

	tp->iter_count = 0;
	/* get the max of iter_count for all dequeued ops */
	for (i = 0; i < num_ops; ++i) {
		tp->iter_count = RTE_MAX(ops_enq[i]->turbo_dec.iter_count,
				tp->iter_count);
	}

	if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE) {
		ret = validate_dec_op(ops_deq, num_ops, ref_op,
				tp->op_params->vector_mask,
				tp->op_params->vector);
		TEST_ASSERT_SUCCESS(ret, "Validation failed!");
	}

	rte_bbdev_dec_op_free_bulk(ops_enq, num_ops);

	double tb_len_bits = calc_dec_TB_size(ref_op);

	tp->ops_per_sec = ((double)num_ops * TEST_REPETITIONS) /
			((double)total_time / (double)rte_get_tsc_hz());
	tp->mbps = (((double)(num_ops * TEST_REPETITIONS * tb_len_bits)) /
			1000000.0) / ((double)total_time /
			(double)rte_get_tsc_hz());

	return TEST_SUCCESS;
}

static int
throughput_pmd_lcore_ldpc_dec(void *arg)
{
	struct thread_params *tp = arg;
	uint16_t enq, deq;
	uint64_t total_time = 0, start_time;
	const uint16_t queue_id = tp->queue_id;
	const uint16_t burst_sz = tp->op_params->burst_sz;
	const uint16_t num_ops = tp->op_params->num_to_process;
	struct rte_bbdev_dec_op *ops_enq[num_ops];
	struct rte_bbdev_dec_op *ops_deq[num_ops];
	struct rte_bbdev_dec_op *ref_op = tp->op_params->ref_dec_op;
	struct test_buffers *bufs = NULL;
	int i, j, ret;
	struct rte_bbdev_info info;
	uint16_t num_to_enq;

	TEST_ASSERT_SUCCESS((burst_sz > MAX_BURST),
			"BURST_SIZE should be <= %u", MAX_BURST);

	rte_bbdev_info_get(tp->dev_id, &info);

	TEST_ASSERT_SUCCESS((num_ops > info.drv.queue_size_lim),
			"NUM_OPS cannot exceed %u for this device",
			info.drv.queue_size_lim);

	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_bbdev_dec_op_alloc_bulk(tp->op_params->mp, ops_enq, num_ops);
	TEST_ASSERT_SUCCESS(ret, "Allocation failed for %d ops", num_ops);

	/* For throughput tests we need to disable early termination */
	if (check_bit(ref_op->ldpc_dec.op_flags,
			RTE_BBDEV_LDPC_ITERATION_STOP_ENABLE))
		ref_op->ldpc_dec.op_flags -=
				RTE_BBDEV_LDPC_ITERATION_STOP_ENABLE;

	if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_ldpc_dec_op(ops_enq, num_ops, 0, bufs->inputs,
				bufs->hard_outputs, bufs->partial_outputs,
				bufs->soft_outputs, bufs->harq_inputs,
				bufs->harq_outputs, ref_op);

	/* Set counter to validate the ordering */
	for (j = 0; j < num_ops; ++j)
		ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

	for (i = 0; i < TEST_REPETITIONS; ++i) {
		for (j = 0; j < num_ops; ++j) {
			bbuf_reset(ops_enq[j]->ldpc_dec.hard_output.bdata);
			ops_enq[j]->ldpc_dec.hard_output.length = 0;
			if (check_bit(ref_op->ldpc_dec.op_flags,
					RTE_BBDEV_LDPC_HQ_COMBINE_OUT_ENABLE))
				bbuf_reset(
				ops_enq[j]->ldpc_dec.harq_combined_output.bdata);
		}

		if (ref_op->ldpc_dec.sd_cd_demux) {
			while (rte_atomic16_read(&sd_cd_demux_sync_var) != 0)
				;
		}

		start_time = rte_rdtsc_precise();

		for (enq = 0, deq = 0; enq < num_ops;) {
			num_to_enq = burst_sz;

			if (unlikely(num_ops - enq < num_to_enq))
				num_to_enq = num_ops - enq;

			enq += rte_bbdev_enqueue_ldpc_dec_ops(tp->dev_id,
					queue_id, &ops_enq[enq], num_to_enq);

			deq += rte_bbdev_dequeue_ldpc_dec_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		/* dequeue the remaining */
		while (deq < enq) {
			deq += rte_bbdev_dequeue_ldpc_dec_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		/* In case of partial compact HARQ, update original
		 * data with partial output.
		 */
		if ((ref_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
		    (ref_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_PARTIAL_COMPACT_HARQ))
			update_orig_ldpc_dec_out_data(ops_deq, num_ops);

		total_time += rte_rdtsc_precise() - start_time;
		if (ref_op->ldpc_dec.sd_cd_demux)
			rte_atomic16_inc(&sd_cd_demux_sync_var);

		if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE &&
		    tp->op_params->vector->ldpc_dec.tb_params.c != 0) {
			ret = validate_ldpc_dec_op(ops_deq, num_ops, ref_op,
					tp->op_params->vector_mask,
					tp->op_params->vector);
			TEST_ASSERT_SUCCESS(ret, "Validation failed!");
		}
	}

	tp->iter_count = 0;
	/* get the max of iter_count for all dequeued ops */
	for (i = 0; i < num_ops; ++i) {
		tp->iter_count = RTE_MAX(ops_enq[i]->ldpc_dec.iter_count,
				tp->iter_count);
	}

	rte_bbdev_dec_op_free_bulk(ops_enq, num_ops);

	double tb_len_bits = calc_ldpc_dec_TB_size(ref_op);

	tp->ops_per_sec = ((double)num_ops * TEST_REPETITIONS) /
			((double)total_time / (double)rte_get_tsc_hz());
	tp->mbps = (((double)(num_ops * TEST_REPETITIONS * tb_len_bits)) /
			1000000.0) / ((double)total_time /
			(double)rte_get_tsc_hz());

	return TEST_SUCCESS;
}

static int
throughput_pmd_lcore_enc(void *arg)
{
	struct thread_params *tp = arg;
	uint16_t enq, deq;
	uint64_t total_time = 0, start_time;
	const uint16_t queue_id = tp->queue_id;
	const uint16_t burst_sz = tp->op_params->burst_sz;
	const uint16_t num_ops = tp->op_params->num_to_process;
	struct rte_bbdev_enc_op *ops_enq[num_ops];
	struct rte_bbdev_enc_op *ops_deq[num_ops];
	struct rte_bbdev_enc_op *ref_op = tp->op_params->ref_enc_op;
	struct test_buffers *bufs = NULL;
	int i, j, ret;
	struct rte_bbdev_info info;
	uint16_t num_to_enq;

	TEST_ASSERT_SUCCESS((burst_sz > MAX_BURST),
			"BURST_SIZE should be <= %u", MAX_BURST);

	rte_bbdev_info_get(tp->dev_id, &info);

	TEST_ASSERT_SUCCESS((num_ops > info.drv.queue_size_lim),
			"NUM_OPS cannot exceed %u for this device",
			info.drv.queue_size_lim);

	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_bbdev_enc_op_alloc_bulk(tp->op_params->mp, ops_enq,
			num_ops);
	TEST_ASSERT_SUCCESS(ret, "Allocation failed for %d ops",
			num_ops);
	if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_enc_op(ops_enq, num_ops, 0, bufs->inputs,
				bufs->hard_outputs, ref_op);

	/* Set counter to validate the ordering */
	for (j = 0; j < num_ops; ++j)
		ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

	for (i = 0; i < TEST_REPETITIONS; ++i) {

		if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE)
			for (j = 0; j < num_ops; ++j)
				bbuf_reset(ops_enq[j]->turbo_enc.output.bdata);

		start_time = rte_rdtsc_precise();

		for (enq = 0, deq = 0; enq < num_ops;) {
			num_to_enq = burst_sz;

			if (unlikely(num_ops - enq < num_to_enq))
				num_to_enq = num_ops - enq;

			enq += rte_bbdev_enqueue_enc_ops(tp->dev_id,
					queue_id, &ops_enq[enq], num_to_enq);

			deq += rte_bbdev_dequeue_enc_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		/* dequeue the remaining */
		while (deq < enq) {
			deq += rte_bbdev_dequeue_enc_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		total_time += rte_rdtsc_precise() - start_time;
	}

	if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE) {
		ret = validate_enc_op(ops_deq, num_ops, ref_op,
				      tp->op_params->vector);
		TEST_ASSERT_SUCCESS(ret, "Validation failed!");
	}

	rte_bbdev_enc_op_free_bulk(ops_enq, num_ops);

	double tb_len_bits = calc_enc_TB_size(ref_op);

	tp->ops_per_sec = ((double)num_ops * TEST_REPETITIONS) /
			((double)total_time / (double)rte_get_tsc_hz());
	tp->mbps = (((double)(num_ops * TEST_REPETITIONS * tb_len_bits))
			/ 1000000.0) / ((double)total_time /
			(double)rte_get_tsc_hz());

	return TEST_SUCCESS;
}

static int
throughput_pmd_lcore_ldpc_enc(void *arg)
{
	struct thread_params *tp = arg;
	uint16_t enq, deq;
	uint64_t total_time = 0, start_time;
	const uint16_t queue_id = tp->queue_id;
	const uint16_t burst_sz = tp->op_params->burst_sz;
	const uint16_t num_ops = tp->op_params->num_to_process;
	struct rte_bbdev_enc_op *ops_enq[num_ops];
	struct rte_bbdev_enc_op *ops_deq[num_ops];
	struct rte_bbdev_enc_op *ref_op = tp->op_params->ref_enc_op;
	struct test_buffers *bufs = NULL;
	int i, j, ret;
	struct rte_bbdev_info info;
	uint16_t num_to_enq;

	TEST_ASSERT_SUCCESS((burst_sz > MAX_BURST),
			"BURST_SIZE should be <= %u", MAX_BURST);

	rte_bbdev_info_get(tp->dev_id, &info);

	TEST_ASSERT_SUCCESS((num_ops > info.drv.queue_size_lim),
			"NUM_OPS cannot exceed %u for this device",
			info.drv.queue_size_lim);

	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_bbdev_enc_op_alloc_bulk(tp->op_params->mp, ops_enq,
			num_ops);
	TEST_ASSERT_SUCCESS(ret, "Allocation failed for %d ops",
			num_ops);
	if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_ldpc_enc_op(ops_enq, num_ops, 0, bufs->inputs,
				bufs->hard_outputs, ref_op);

	/* Set counter to validate the ordering */
	for (j = 0; j < num_ops; ++j)
		ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

	for (i = 0; i < TEST_REPETITIONS; ++i) {

		if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE)
			for (j = 0; j < num_ops; ++j)
				bbuf_reset(ops_enq[j]->turbo_enc.output.bdata);

		if (ref_op->ldpc_enc.se_ce_mux) {
			while (rte_atomic16_read(&se_ce_mux_sync_var) == 0)
				;
		}

		start_time = rte_rdtsc_precise();

		for (enq = 0, deq = 0; enq < num_ops;) {
			num_to_enq = burst_sz;

			if (unlikely(num_ops - enq < num_to_enq))
				num_to_enq = num_ops - enq;

			enq += rte_bbdev_enqueue_ldpc_enc_ops(tp->dev_id,
					queue_id, &ops_enq[enq], num_to_enq);

			deq += rte_bbdev_dequeue_ldpc_enc_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		/* dequeue the remaining */
		while (deq < enq) {
			deq += rte_bbdev_dequeue_ldpc_enc_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		total_time += rte_rdtsc_precise() - start_time;
		if (ref_op->ldpc_enc.se_ce_mux)
			rte_atomic16_set(&se_ce_mux_sync_var, 0);

		if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE) {
			ret = validate_ldpc_enc_op(ops_deq, num_ops, ref_op,
						   tp->op_params->vector);
			TEST_ASSERT_SUCCESS(ret, "Validation failed!");
		}
	}

	rte_bbdev_enc_op_free_bulk(ops_enq, num_ops);

	double tb_len_bits = calc_ldpc_enc_TB_size(ref_op);

	tp->ops_per_sec = ((double)num_ops * TEST_REPETITIONS) /
			((double)total_time / (double)rte_get_tsc_hz());
	tp->mbps = (((double)(num_ops * TEST_REPETITIONS * tb_len_bits))
			/ 1000000.0) / ((double)total_time /
			(double)rte_get_tsc_hz());

	return TEST_SUCCESS;
}

static int
throughput_pmd_lcore_polar(void *arg)
{
	struct thread_params *tp = arg;
	uint16_t enq, deq;
	uint64_t total_time = 0, start_time;
	const uint16_t queue_id = tp->queue_id;
	const uint16_t burst_sz = tp->op_params->burst_sz;
	const uint16_t num_ops = tp->op_params->num_to_process;
	struct rte_pmd_la12xx_op *ops_enq[num_ops];
	struct rte_pmd_la12xx_op *ops_deq[num_ops];
	struct rte_pmd_la12xx_op *ref_op = tp->op_params->ref_la12xx_op;
	struct test_buffers *bufs = NULL;
	int i, j, ret;
	struct rte_bbdev_info info;
	uint16_t num_to_enq;

	TEST_ASSERT_SUCCESS((burst_sz > MAX_BURST),
			"BURST_SIZE should be <= %u", MAX_BURST);

	rte_bbdev_info_get(tp->dev_id, &info);

	TEST_ASSERT_SUCCESS((num_ops > info.drv.queue_size_lim),
			"NUM_OPS cannot exceed %u for this device",
			info.drv.queue_size_lim);

	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_mempool_get_bulk(tp->op_params->mp, (void **)ops_enq, num_ops);
	TEST_ASSERT_SUCCESS(ret, "Allocation failed for %d ops",
			num_ops);
	if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_polar_op(ops_enq, num_ops, 0, bufs->inputs,
				bufs->hard_outputs, ref_op);

	/* Set counter to validate the ordering */
	for (j = 0; j < num_ops; ++j)
		ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

	for (i = 0; i < TEST_REPETITIONS; ++i) {
		if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE &&
		    ops_enq[0]->polar_params.output.bdata)
			for (j = 0; j < num_ops; ++j)
				bbuf_reset(ops_enq[j]->polar_params.output.bdata);

		if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_ACK(ref_op)) {
			while (rte_atomic16_read(&sd_cd_demux_sync_var) !=
			       ack_sync_var)
				;
		} else if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_CSI1(ref_op)) {
			while (rte_atomic16_read(&sd_cd_demux_sync_var) !=
			       csi1_sync_var)
				;
		} else if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_CSI2(ref_op)) {
			while (rte_atomic16_read(&sd_cd_demux_sync_var) !=
			       csi2_sync_var)
				;
		} else if (RTE_PMD_LA12xx_IS_POLAR_ENC_MUX(ref_op)) {
			while (rte_atomic16_read(&se_ce_mux_sync_var) == 1)
				;
		}

		start_time = rte_rdtsc_precise();

		for (enq = 0, deq = 0; enq < num_ops;) {
			num_to_enq = burst_sz;

			if (unlikely(num_ops - enq < num_to_enq))
				num_to_enq = num_ops - enq;

			enq += rte_pmd_la12xx_enqueue_ops(tp->dev_id,
					queue_id, &ops_enq[enq], num_to_enq);

			deq += rte_pmd_la12xx_dequeue_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		/* dequeue the remaining */
		while (deq < enq) {
			deq += rte_pmd_la12xx_dequeue_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		total_time += rte_rdtsc_precise() - start_time;

		if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX(ref_op)) {
			if (rte_atomic16_read(&sd_cd_demux_sync_var) ==
			    num_polar_decode_tests)
				rte_atomic16_set(&sd_cd_demux_sync_var, 0);
			else
				rte_atomic16_inc(&sd_cd_demux_sync_var);
		}

		if (RTE_PMD_LA12xx_IS_POLAR_ENC_MUX(ref_op))
			rte_atomic16_set(&se_ce_mux_sync_var, 1);

		if (ops_enq[0]->polar_params.output.bdata) {
			if (tp->op_params->vector->op_type != RTE_BBDEV_OP_NONE) {
				ret = validate_polar_op(ops_deq, num_ops, ref_op,
							tp->op_params->vector);
				TEST_ASSERT_SUCCESS(ret, "Validation failed!");
			}
		}
	}

	tp->ops_per_sec = ((double)num_ops * TEST_REPETITIONS) /
			((double)total_time / (double)rte_get_tsc_hz());
	if (ops_enq[0]->polar_params.output.bdata) {
		/* FIXME : Need to calculate data length for throughput */
		double tb_len_bits =
			rte_bbuf_pkt_len(ops_enq[0]->polar_params.output.bdata) -
					 ops_enq[0]->polar_params.output.offset;

		tp->mbps = (((double)(num_ops * TEST_REPETITIONS * tb_len_bits))
				/ 1000000.0) / ((double)total_time /
				(double)rte_get_tsc_hz());
	} else {
		tp->mbps = 0;
	}

	rte_mempool_put_bulk(tp->op_params->mp, (void **)ops_enq, num_ops);

	return TEST_SUCCESS;
}

static int
throughput_pmd_lcore_la12xx_raw(void *arg)
{
	struct thread_params *tp = arg;
	uint16_t enq, deq;
	uint64_t total_time = 0, start_time;
	const uint16_t queue_id = tp->queue_id;
	const uint16_t burst_sz = tp->op_params->burst_sz;
	const uint16_t num_ops = tp->op_params->num_to_process;
	struct rte_pmd_la12xx_op *ops_enq[num_ops];
	struct rte_pmd_la12xx_op *ops_deq[num_ops];
	struct test_buffers *bufs = NULL;
	int i, j, ret;
	struct rte_bbdev_info info;
	uint16_t num_to_enq;

	TEST_ASSERT_SUCCESS((burst_sz > MAX_BURST),
			"BURST_SIZE should be <= %u", MAX_BURST);

	rte_bbdev_info_get(tp->dev_id, &info);

	TEST_ASSERT_SUCCESS((num_ops > info.drv.queue_size_lim),
			"NUM_OPS cannot exceed %u for this device",
			info.drv.queue_size_lim);

	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_mempool_get_bulk(tp->op_params->mp,
			(void **)ops_enq, num_ops);
	TEST_ASSERT_SUCCESS(ret, "Allocation failed for %d ops",
			num_ops);
	copy_reference_la12xx_raw_op(ops_enq, num_ops, 0, bufs->inputs,
				bufs->hard_outputs);

	/* Set counter to validate the ordering */
	for (j = 0; j < num_ops; ++j)
		ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

	for (i = 0; i < TEST_REPETITIONS; ++i) {
		if (ops_enq[0]->raw_params.output.bdata)
			for (j = 0; j < num_ops; ++j)
				bbuf_reset(ops_enq[j]->raw_params.output.bdata);

		start_time = rte_rdtsc_precise();

		for (enq = 0, deq = 0; enq < num_ops;) {
			num_to_enq = burst_sz;

			if (unlikely(num_ops - enq < num_to_enq))
				num_to_enq = num_ops - enq;

			enq += rte_pmd_la12xx_enqueue_ops(tp->dev_id,
					queue_id, &ops_enq[enq], num_to_enq);

			deq += rte_pmd_la12xx_dequeue_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		/* dequeue the remaining */
		while (deq < enq) {
			deq += rte_pmd_la12xx_dequeue_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		total_time += rte_rdtsc_precise() - start_time;

		if (ops_enq[0]->raw_params.output.bdata) {
			ret = validate_raw_op(ops_deq, num_ops,	tp->op_params->vector);
			TEST_ASSERT_SUCCESS(ret, "Validation failed!");
		}
	}

	tp->ops_per_sec = ((double)num_ops * TEST_REPETITIONS) /
			((double)total_time / (double)rte_get_tsc_hz());

	if (ops_enq[0]->raw_params.output.bdata) {
		/* FIXME : Need to calculate data length for throughput */
		double tb_len_bits =
			rte_bbuf_pkt_len(ops_enq[0]->raw_params.output.bdata) -
					 ops_enq[0]->raw_params.output.offset;

		tp->mbps = (((double)(num_ops * TEST_REPETITIONS * tb_len_bits))
				/ 1000000.0) / ((double)total_time /
				(double)rte_get_tsc_hz());
	} else {
		tp->mbps = 0;
	}

	rte_mempool_put_bulk(tp->op_params->mp, (void **)ops_enq, num_ops);

	return TEST_SUCCESS;
}

static int
throughput_pmd_lcore_la12xx_vspa(void *arg)
{
	struct thread_params *tp = arg;
	uint16_t enq, deq;
	uint64_t total_time = 0, start_time;
	const uint16_t queue_id = tp->queue_id;
	const uint16_t burst_sz = tp->op_params->burst_sz;
	const uint16_t num_ops = tp->op_params->num_to_process;
	struct rte_pmd_la12xx_op *ops_enq[num_ops];
	struct rte_pmd_la12xx_op *ops_deq[num_ops];
	struct test_buffers *bufs = NULL;
	int i, j, ret;
	struct rte_bbdev_info info;
	uint16_t num_to_enq;

	TEST_ASSERT_SUCCESS((burst_sz > MAX_BURST),
			"BURST_SIZE should be <= %u", MAX_BURST);

	rte_bbdev_info_get(tp->dev_id, &info);

	TEST_ASSERT_SUCCESS((num_ops > info.drv.queue_size_lim),
			"NUM_OPS cannot exceed %u for this device",
			info.drv.queue_size_lim);

	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_mempool_get_bulk(tp->op_params->mp,
			(void **)ops_enq, num_ops);
	TEST_ASSERT_SUCCESS(ret, "Allocation failed for %d ops",
			num_ops);
	copy_reference_la12xx_vspa_op(ops_enq, num_ops, 0, bufs->inputs,
				bufs->hard_outputs);

	/* Set counter to validate the ordering */
	for (j = 0; j < num_ops; ++j)
		ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

	for (i = 0; i < TEST_REPETITIONS; ++i) {
		if (ops_enq[0]->vspa_params.output.bdata)
			for (j = 0; j < num_ops; ++j)
				bbuf_reset(ops_enq[j]->vspa_params.output.bdata);

		start_time = rte_rdtsc_precise();

		for (enq = 0, deq = 0; enq < num_ops;) {
			num_to_enq = burst_sz;

			if (unlikely(num_ops - enq < num_to_enq))
				num_to_enq = num_ops - enq;

			enq += rte_pmd_la12xx_enqueue_ops(tp->dev_id,
					queue_id, &ops_enq[enq], num_to_enq);

			deq += rte_pmd_la12xx_dequeue_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		/* dequeue the remaining */
		while (deq < enq) {
			deq += rte_pmd_la12xx_dequeue_ops(tp->dev_id,
					queue_id, &ops_deq[deq], enq - deq);
		}

		total_time += rte_rdtsc_precise() - start_time;
	}

	tp->ops_per_sec = ((double)num_ops * TEST_REPETITIONS) /
			((double)total_time / (double)rte_get_tsc_hz());

	if (ops_enq[0]->polar_params.output.bdata) {
		/* FIXME : Need to calculate data length for throughput */
		double tb_len_bits =
			rte_bbuf_pkt_len(ops_enq[0]->polar_params.output.bdata) -
					 ops_enq[0]->polar_params.output.offset;

		tp->mbps = (((double)(num_ops * TEST_REPETITIONS * tb_len_bits))
				/ 1000000.0) / ((double)total_time /
				(double)rte_get_tsc_hz());
	} else {
		tp->mbps = 0;
	}

	rte_mempool_put_bulk(tp->op_params->mp, (void **)ops_enq, num_ops);

	return TEST_SUCCESS;
}

static void
print_throughput(struct thread_params *t_params, unsigned int used_cores)
{
	unsigned int iter = 0;
	double total_mops = 0, total_mbps = 0;
	enum rte_bbdev_op_type op_type;
	uint8_t iter_count = 0;
	const char *op_type_str;

	for (iter = 0; iter < used_cores; iter++) {
		op_type = t_params[iter].op_params->vector->op_type;
		op_type_str = rte_bbdev_op_type_str(op_type);
		if (op_type == RTE_BBDEV_OP_TURBO_DEC ||
		    op_type == RTE_BBDEV_OP_LDPC_DEC) {
			printf(
				"Op Type: %s Throughput for core (%u): %.8lg Ops/s, %.8lg Mbps @ max %lu iterations\n",
				op_type_str,
				t_params[iter].lcore_id,
				t_params[iter].ops_per_sec,
				t_params[iter].mbps, t_params[iter].iter_count);
			iter_count = RTE_MAX(iter_count,
					     t_params[iter].iter_count);
		} else {
			printf(
				"Op Type: %s Throughput for core (%u): %.8lg Ops/s, %.8lg Mbps\n",
				op_type_str,
				t_params[iter].lcore_id,
				t_params[iter].ops_per_sec,
				t_params[iter].mbps);
		}
		total_mops += t_params[iter].ops_per_sec;
		total_mbps += t_params[iter].mbps;
	}
	if (iter_count)
		printf(
			"\nTotal throughput for %u cores: %.8lg MOPS, %.8lg Mbps @ max %u iterations\n",
			used_cores, total_mops, total_mbps, iter_count);
	else
		printf(
			"\nTotal throughput for %u cores: %.8lg MOPS, %.8lg Mbps\n",
			used_cores, total_mops, total_mbps);
}

/*
 * Test function that determines how long an enqueue + dequeue of a burst
 * takes on available lcores.
 */
static int
throughput_test(struct active_device *ad,
		struct test_op_params *op_params)
{
	int ret = 0;
	unsigned int lcore_id, used_cores = 0;
	unsigned int master_lcore_id;
	struct thread_params *t_params, *tp;
	struct rte_bbdev_info info;
	lcore_function_t *throughput_function[RTE_MAX_LCORE];
	uint16_t num_lcores;
	enum rte_bbdev_op_type op_type;
	int socket_id;

	rte_bbdev_info_get(ad->dev_id, &info);
	socket_id = GET_SOCKET(info.socket_id);

	/* Set number of lcores */
	num_lcores = get_vector_count();
	master_lcore_id = rte_lcore_id();

	printf("+ ------------------------------------------------------- +\n");
	printf("== test: throughput\ndev: %s, nb_queues: %u, burst size: %u, num ops: %u, num_lcores: %u, itr mode: %s, GHz: %lg\n",
			info.dev_name, ad->nb_queues, op_params[master_lcore_id].burst_sz,
			op_params[master_lcore_id].num_to_process, num_lcores,
			intr_enabled ? "Interrupt mode" : "PMD mode",
			(double)rte_get_tsc_hz() / 1000000000.0);

	/* Allocate memory for thread parameters structure */
	t_params = rte_zmalloc_socket(NULL, num_lcores * sizeof(struct thread_params),
			RTE_CACHE_LINE_SIZE, socket_id);
	TEST_ASSERT_NOT_NULL(t_params, "Failed to alloc %zuB for t_params",
			RTE_ALIGN(sizeof(struct thread_params) * num_lcores,
				RTE_CACHE_LINE_SIZE));

	RTE_LCORE_FOREACH(lcore_id) {
		if (used_cores > num_lcores)
			break;

		t_params[used_cores].dev_id = ad->dev_id;
		t_params[used_cores].lcore_id = lcore_id;
		t_params[used_cores].op_params = &op_params[lcore_id];
		t_params[used_cores].queue_id = ad->queue_ids[used_cores];
		t_params[used_cores].iter_count = 0;

		op_type = op_params[lcore_id].vector->op_type;
		if (intr_enabled) {
			if (op_type == RTE_BBDEV_OP_TURBO_DEC)
				throughput_function[used_cores] =
					throughput_intr_lcore_dec;
			else if (op_type == RTE_BBDEV_OP_LDPC_DEC)
				throughput_function[used_cores] =
					throughput_intr_lcore_dec;
			else if (op_type == RTE_BBDEV_OP_TURBO_ENC)
				throughput_function[used_cores] =
					throughput_intr_lcore_enc;
			else if (op_type == RTE_BBDEV_OP_LDPC_ENC)
				throughput_function[used_cores] =
					throughput_intr_lcore_enc;
			else if ((op_type == RTE_BBDEV_OP_POLAR_DEC) ||
				(op_type == RTE_BBDEV_OP_POLAR_ENC))
				throughput_function[used_cores] =
					throughput_intr_lcore_polar;
			else
				throughput_function[used_cores] =
					throughput_intr_lcore_enc;

			/* Dequeue interrupt callback registration */
			ret = rte_bbdev_callback_register(ad->dev_id,
					RTE_BBDEV_EVENT_DEQUEUE,
					dequeue_event_callback,
					&t_params[used_cores]);
			if (ret < 0) {
				rte_free(t_params);
				return ret;
			}
		} else {
			if (op_type == RTE_BBDEV_OP_TURBO_DEC)
				throughput_function[used_cores] =
					throughput_pmd_lcore_dec;
			else if (op_type == RTE_BBDEV_OP_LDPC_DEC)
				throughput_function[used_cores] =
					throughput_pmd_lcore_ldpc_dec;
			else if (op_type == RTE_BBDEV_OP_TURBO_ENC)
				throughput_function[used_cores] =
					throughput_pmd_lcore_enc;
			else if (op_type == RTE_BBDEV_OP_LDPC_ENC)
				throughput_function[used_cores] =
					throughput_pmd_lcore_ldpc_enc;
			else if ((op_type == RTE_BBDEV_OP_POLAR_DEC) ||
				(op_type == RTE_BBDEV_OP_POLAR_ENC))
				throughput_function[used_cores] =
					throughput_pmd_lcore_polar;
			else if (op_type == RTE_BBDEV_OP_RAW)
				throughput_function[used_cores] =
					throughput_pmd_lcore_la12xx_raw;
			else if (op_type == RTE_BBDEV_OP_LA12XX_VSPA)
				throughput_function[used_cores] =
					throughput_pmd_lcore_la12xx_vspa;
			else
				throughput_function[used_cores] =
					throughput_pmd_lcore_enc;
		}

		rte_atomic16_set(&(&op_params[lcore_id])->sync, SYNC_WAIT);

		if (used_cores != 0) {
			rte_eal_remote_launch(throughput_function[used_cores],
				&t_params[used_cores], lcore_id);
		}
		used_cores++;
	}

	rte_atomic16_set(&sd_cd_demux_sync_var, 0);
	rte_atomic16_set(&se_ce_mux_sync_var, 0);

	RTE_LCORE_FOREACH(lcore_id) {
		rte_atomic16_set(&(&op_params[lcore_id])->sync, SYNC_START);
	}
	ret = throughput_function[0](&t_params[0]);

	/* Master core is always used */
	for (used_cores = 1; used_cores < num_lcores; used_cores++)
		ret |= rte_eal_wait_lcore(t_params[used_cores].lcore_id);

	/* Return if test failed */
	if (ret) {
		rte_free(t_params);
		return ret;
	}

	/* Print throughput if interrupts are disabled and test passed */
	if (!intr_enabled) {
		print_throughput(t_params, num_lcores);
		rte_free(t_params);
		return ret;
	}

	/* In interrupt TC we need to wait for the interrupt callback to deqeue
	 * all pending operations. Skip waiting for queues which reported an
	 * error using processing_status variable.
	 * Wait for master lcore operations.
	 */
	tp = &t_params[0];
	while ((rte_atomic16_read(&tp->nb_dequeued) <
			op_params->num_to_process) &&
			(rte_atomic16_read(&tp->processing_status) !=
			TEST_FAILED))
		rte_pause();

	tp->ops_per_sec /= TEST_REPETITIONS;
	tp->mbps /= TEST_REPETITIONS;
	ret |= (int)rte_atomic16_read(&tp->processing_status);

	/* Wait for slave lcores operations */
	for (used_cores = 1; used_cores < num_lcores; used_cores++) {
		tp = &t_params[used_cores];

		while ((rte_atomic16_read(&tp->nb_dequeued) <
				op_params->num_to_process) &&
				(rte_atomic16_read(&tp->processing_status) !=
				TEST_FAILED))
			rte_pause();

		tp->ops_per_sec /= TEST_REPETITIONS;
		tp->mbps /= TEST_REPETITIONS;
		ret |= (int)rte_atomic16_read(&tp->processing_status);
	}

	/* Print throughput if test passed */
	if (!ret)
		print_throughput(t_params, num_lcores);

	rte_free(t_params);
	return ret;
}

static int
latency_test_dec(void *arg)
{
	struct thread_params *tp = arg;
	struct rte_bbdev_dec_op *ref_op = tp->op_params->ref_dec_op;
	struct test_bbdev_vector *vector = tp->op_params->vector;
	struct rte_mempool *mempool = tp->op_params->mp;
	int vector_mask = tp->op_params->vector_mask;
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	uint16_t dev_id = tp->dev_id;
	uint16_t queue_id = tp->queue_id;
	uint64_t num_to_process = tp->iter_count;
	uint16_t burst_sz = tp->op_params->burst_sz;
	uint64_t *total_time = tp->total_time;
	uint64_t *min_time = tp->min_time;
	uint64_t *max_time = tp->max_time;

	int ret = TEST_SUCCESS;
	uint64_t i, j, dequeued;
	struct rte_bbdev_dec_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t start_time = 0, last_time = 0;

	rte_bbdev_info_get(tp->dev_id, &info);
	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_bbdev_dec_op_alloc_bulk(mempool, ops_enq, burst_sz);
	TEST_ASSERT_SUCCESS(ret,
			"rte_bbdev_dec_op_alloc_bulk() failed");
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_dec_op(ops_enq, burst_sz, 0,
				bufs->inputs,
				bufs->hard_outputs,
				bufs->soft_outputs,
				ref_op);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;
		last_time = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Set counter to validate the ordering */
		for (j = 0; j < burst_sz; ++j)
			ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

		start_time = rte_rdtsc_precise();

		enq = rte_bbdev_enqueue_dec_ops(dev_id, queue_id, &ops_enq[enq],
				burst_sz);
		TEST_ASSERT(enq == burst_sz,
				"Error enqueueing burst, expected %u, got %u",
				burst_sz, enq);

		/* Dequeue */
		do {
			deq += rte_bbdev_dequeue_dec_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);
		} while (unlikely(burst_sz != deq));

		last_time = rte_rdtsc_precise() - start_time;

		*max_time = RTE_MAX(*max_time, last_time);
		*min_time = RTE_MIN(*min_time, last_time);
		*total_time += last_time;

		if (vector->op_type != RTE_BBDEV_OP_NONE) {
			ret = validate_dec_op(ops_deq, burst_sz, ref_op,
					vector_mask, vector);
			TEST_ASSERT_SUCCESS(ret, "Validation failed!");
		}

		dequeued += deq;
	}
	rte_bbdev_dec_op_free_bulk(ops_enq, burst_sz);

	return TEST_SUCCESS;
}

static int
latency_test_ldpc_dec(void *arg)
{
	struct thread_params *tp = arg;
	struct rte_bbdev_dec_op *ref_op = tp->op_params->ref_dec_op;
	struct test_bbdev_vector *vector = tp->op_params->vector;
	struct rte_mempool *mempool = tp->op_params->mp;
	int vector_mask = tp->op_params->vector_mask;
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	uint16_t dev_id = tp->dev_id;
	uint16_t queue_id = tp->queue_id;
	uint64_t num_to_process = tp->iter_count;
	uint16_t burst_sz = tp->op_params->burst_sz;
	uint64_t *total_time = tp->total_time;
	uint64_t *min_time = tp->min_time;
	uint64_t *max_time = tp->max_time;

	int ret = TEST_SUCCESS;
	uint64_t i, j, dequeued;
	struct rte_bbdev_dec_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t start_time = 0, last_time = 0;

	rte_bbdev_info_get(tp->dev_id, &info);
	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_bbdev_dec_op_alloc_bulk(mempool, ops_enq, burst_sz);
	TEST_ASSERT_SUCCESS(ret,
			"rte_bbdev_dec_op_alloc_bulk() failed");
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_ldpc_dec_op(ops_enq, burst_sz, 0,
				bufs->inputs,
				bufs->hard_outputs,
				bufs->partial_outputs,
				bufs->soft_outputs,
				bufs->harq_inputs,
				bufs->harq_outputs,
				ref_op);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;
		last_time = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Set counter to validate the ordering */
		for (j = 0; j < burst_sz; ++j)
			ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

		if (vector->op_type != RTE_BBDEV_OP_NONE && i == 0) {
			for (j = 0; j < burst_sz; ++j) {
				/* Use data pointer for this test */

				/* Input buffer */
				ops_enq[j]->ldpc_dec.input.is_direct_mem = 1;
				ops_enq[j]->ldpc_dec.input.mem =
					rte_bbuf_mtod((struct rte_bbuf *)ops_enq[j]->ldpc_dec.input.bdata,
						      char *);

				/* Hard Output buffer */
				ops_enq[j]->ldpc_dec.hard_output.is_direct_mem = 1;
				ops_enq[j]->ldpc_dec.hard_output.mem =
					rte_bbuf_mtod((struct rte_bbuf *)ops_enq[j]->ldpc_dec.hard_output.bdata,
						      char *);
				ops_enq[j]->ldpc_dec.hard_output.length = 0;

				/* Soft Output buffer */
				if (ops_enq[j]->ldpc_dec.soft_output.bdata) {
					ops_enq[j]->ldpc_dec.soft_output.is_direct_mem = 1;
					ops_enq[j]->ldpc_dec.soft_output.mem =
						rte_bbuf_mtod((struct rte_bbuf *)ops_enq[j]->ldpc_dec.soft_output.bdata,
							      char *);
					ops_enq[j]->ldpc_dec.soft_output.length = 0;
				}

				/* HARQ input buffer */
				if (ops_enq[j]->ldpc_dec.harq_combined_input.bdata) {
					ops_enq[j]->ldpc_dec.harq_combined_input.is_direct_mem = 1;
					ops_enq[j]->ldpc_dec.harq_combined_input.mem =
						rte_bbuf_mtod((struct rte_bbuf *)ops_enq[j]->ldpc_dec.harq_combined_input.bdata,
							      char *);
				}

				/* HARQ output buffer */
				if (ops_enq[j]->ldpc_dec.harq_combined_output.bdata) {
					ops_enq[j]->ldpc_dec.harq_combined_output.is_direct_mem = 1;
					ops_enq[j]->ldpc_dec.harq_combined_output.mem =
						rte_bbuf_mtod((struct rte_bbuf *)ops_enq[j]->ldpc_dec.harq_combined_output.bdata,
							      char *);
					ops_enq[j]->ldpc_dec.harq_combined_output.length = 0;
				}
			}
		}

		if (vector->op_type != RTE_BBDEV_OP_NONE) {
			for (j = 0; j < burst_sz; ++j) {
				memset(ops_enq[j]->ldpc_dec.hard_output.mem, 0,
				       ops_enq[j]->ldpc_dec.hard_output.length);
				ops_enq[j]->ldpc_dec.hard_output.length = 0;

				if (ops_enq[j]->ldpc_dec.soft_output.bdata) {
					memset(ops_enq[j]->ldpc_dec.soft_output.mem, 0,
					       ops_enq[j]->ldpc_dec.soft_output.length);
					ops_enq[j]->ldpc_dec.soft_output.length = 0;
				}

				if (ops_enq[j]->ldpc_dec.harq_combined_output.bdata) {
					memset(ops_enq[j]->ldpc_dec.harq_combined_output.mem, 0,
					       ops_enq[j]->ldpc_dec.harq_combined_output.length);
					ops_enq[j]->ldpc_dec.harq_combined_output.length = 0;
				}
			}
		}

		if (ref_op->ldpc_dec.sd_cd_demux) {
			while (rte_atomic16_read(&sd_cd_demux_sync_var) != 0)
				;
		}

		start_time = rte_rdtsc_precise();

		enq = rte_bbdev_enqueue_ldpc_dec_ops(dev_id, queue_id,
				&ops_enq[enq], burst_sz);
		TEST_ASSERT(enq == burst_sz,
				"Error enqueueing burst, expected %u, got %u",
				burst_sz, enq);

		/* Dequeue */
		do {
			deq += rte_bbdev_dequeue_ldpc_dec_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);
		} while (unlikely(burst_sz != deq));

		/* In case of partial compact HARQ, update original
		 * data with partial output.
		 */
		if ((ref_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_HQ_COMBINE_IN_ENABLE) &&
		    (ref_op->ldpc_dec.op_flags &
		    RTE_BBDEV_LDPC_PARTIAL_COMPACT_HARQ))
			update_orig_ldpc_dec_out_data(ops_deq, burst_sz);

		last_time = rte_rdtsc_precise() - start_time;

		*max_time = RTE_MAX(*max_time, last_time);
		*min_time = RTE_MIN(*min_time, last_time);
		*total_time += last_time;

		if (ref_op->ldpc_dec.sd_cd_demux)
			rte_atomic16_inc(&sd_cd_demux_sync_var);

		if (vector->op_type != RTE_BBDEV_OP_NONE &&
		    vector->ldpc_dec.tb_params.c != 0) {
			ret = validate_ldpc_dec_op(ops_deq, burst_sz, ref_op,
					vector_mask, vector);
			TEST_ASSERT_SUCCESS(ret, "Validation failed!");
		}

		dequeued += deq;
	}
	rte_bbdev_dec_op_free_bulk(ops_enq, burst_sz);

	return TEST_SUCCESS;
}

static int
latency_test_ldpc_polar(void *arg)
{
	struct thread_params *tp = arg;
	struct rte_pmd_la12xx_op *ref_op = tp->op_params->ref_la12xx_op;
	struct test_bbdev_vector *vector = tp->op_params->vector;
	struct rte_mempool *mempool = tp->op_params->mp;
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	uint16_t dev_id = tp->dev_id;
	uint16_t queue_id = tp->queue_id;
	uint64_t num_to_process = tp->iter_count;
	uint16_t burst_sz = tp->op_params->burst_sz;
	uint64_t *total_time = tp->total_time;
	uint64_t *min_time = tp->min_time;
	uint64_t *max_time = tp->max_time;

	int ret = TEST_SUCCESS;
	uint64_t i, j, dequeued;
	struct rte_pmd_la12xx_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t start_time = 0, last_time = 0;

	rte_bbdev_info_get(tp->dev_id, &info);
	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_mempool_get_bulk(mempool, (void **)ops_enq, burst_sz);
	TEST_ASSERT_SUCCESS(ret,
			"rte_bbdev_dec_op_alloc_bulk() failed");
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_polar_op(ops_enq, burst_sz, 0,
				bufs->inputs,
				bufs->hard_outputs,
				ref_op);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;
		last_time = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Set counter to validate the ordering */
		for (j = 0; j < burst_sz; ++j)
			ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

		if (vector->op_type != RTE_BBDEV_OP_NONE &&
			    ops_enq[0]->polar_params.output.bdata) {
			for (j = 0; j < burst_sz; ++j) {
				bbuf_reset(ops_enq[j]->polar_params.output.bdata);
			}
		}

		if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_ACK(ref_op)) {
			while (rte_atomic16_read(&sd_cd_demux_sync_var) !=
			       ack_sync_var)
				;
		} else if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_CSI1(ref_op)) {
			while (rte_atomic16_read(&sd_cd_demux_sync_var) !=
			       csi1_sync_var)
				;
		} else if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX_CSI2(ref_op)) {
			while (rte_atomic16_read(&sd_cd_demux_sync_var) !=
			       csi2_sync_var)
				;
		} else if (RTE_PMD_LA12xx_IS_POLAR_ENC_MUX(ref_op)) {
			while (rte_atomic16_read(&se_ce_mux_sync_var) == 1)
				;
		}

		start_time = rte_rdtsc_precise();

		enq = rte_pmd_la12xx_enqueue_ops(dev_id, queue_id,
				&ops_enq[enq], burst_sz);
		TEST_ASSERT(enq == burst_sz,
				"Error enqueueing burst, expected %u, got %u",
				burst_sz, enq);

		/* Dequeue */
		do {
			deq += rte_pmd_la12xx_dequeue_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);
		} while (unlikely(burst_sz != deq));

		last_time = rte_rdtsc_precise() - start_time;

		*max_time = RTE_MAX(*max_time, last_time);
		*min_time = RTE_MIN(*min_time, last_time);
		*total_time += last_time;

		if (RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX(ref_op)) {
			if (rte_atomic16_read(&sd_cd_demux_sync_var) ==
			    num_polar_decode_tests)
				rte_atomic16_set(&sd_cd_demux_sync_var, 0);
			else
				rte_atomic16_inc(&sd_cd_demux_sync_var);
		}

		if (RTE_PMD_LA12xx_IS_POLAR_ENC_MUX(ref_op))
			rte_atomic16_set(&se_ce_mux_sync_var, 1);

		if (vector->op_type != RTE_BBDEV_OP_NONE &&
				ops_enq[0]->polar_params.output.bdata) {
			ret = validate_polar_op(ops_deq, burst_sz, ref_op,
						vector);
			TEST_ASSERT_SUCCESS(ret, "Validation failed!");
		}

		dequeued += deq;
	}
	rte_mempool_put_bulk(mempool, (void **)ops_enq, burst_sz);

	return TEST_SUCCESS;
}

static int
latency_test_la12xx_raw(void *arg)
{
	struct thread_params *tp = arg;
	struct test_bbdev_vector *vector = tp->op_params->vector;
	struct rte_mempool *mempool = tp->op_params->mp;
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	uint16_t dev_id = tp->dev_id;
	uint16_t queue_id = tp->queue_id;
	uint64_t num_to_process = tp->iter_count;
	uint16_t burst_sz = tp->op_params->burst_sz;
	uint64_t *total_time = tp->total_time;
	uint64_t *min_time = tp->min_time;
	uint64_t *max_time = tp->max_time;

	int ret = TEST_SUCCESS;
	uint64_t i, j, dequeued;
	struct rte_pmd_la12xx_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t start_time = 0, last_time = 0;

	rte_bbdev_info_get(tp->dev_id, &info);
	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_mempool_get_bulk(mempool, (void **)ops_enq, burst_sz);
	TEST_ASSERT_SUCCESS(ret,
			"rte_bbdev_dec_op_alloc_bulk() failed");
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_la12xx_raw_op(ops_enq, burst_sz, 0,
				bufs->inputs, bufs->hard_outputs);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;

		last_time = 0;
		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Set counter to validate the ordering */
		for (j = 0; j < burst_sz; ++j)
			ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

		if (ops_enq[0]->raw_params.output.bdata)
			for (j = 0; j < burst_sz; ++j)
				bbuf_reset(ops_enq[j]->raw_params.output.bdata);

		start_time = rte_rdtsc_precise();

		enq = rte_pmd_la12xx_enqueue_ops(dev_id, queue_id,
				&ops_enq[enq], burst_sz);
		TEST_ASSERT(enq == burst_sz,
				"Error enqueueing burst, expected %u, got %u",
				burst_sz, enq);

		/* Dequeue */
		do {
			deq += rte_pmd_la12xx_dequeue_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);
		} while (unlikely(burst_sz != deq));

		last_time = rte_rdtsc_precise() - start_time;

		*max_time = RTE_MAX(*max_time, last_time);
		*min_time = RTE_MIN(*min_time, last_time);
		*total_time += last_time;

		if (ops_enq[0]->raw_params.output.bdata) {
			ret = validate_raw_op(ops_deq, burst_sz, vector);
			TEST_ASSERT_SUCCESS(ret, "Validation failed!");
		}

		dequeued += deq;
	}
	rte_mempool_put_bulk(mempool, (void **)ops_enq, burst_sz);

	return TEST_SUCCESS;
}

static int
latency_test_la12xx_vspa(void *arg)
{
	struct thread_params *tp = arg;
	struct test_bbdev_vector *vector = tp->op_params->vector;
	struct rte_mempool *mempool = tp->op_params->mp;
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	uint16_t dev_id = tp->dev_id;
	uint16_t queue_id = tp->queue_id;
	uint64_t num_to_process = tp->iter_count;
	uint16_t burst_sz = tp->op_params->burst_sz;
	uint64_t *total_time = tp->total_time;
	uint64_t *min_time = tp->min_time;
	uint64_t *max_time = tp->max_time;

	int ret = TEST_SUCCESS;
	uint64_t i, j, dequeued;
	struct rte_pmd_la12xx_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t start_time = 0, last_time = 0;

	rte_bbdev_info_get(tp->dev_id, &info);
	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_mempool_get_bulk(mempool, (void **)ops_enq, burst_sz);
	TEST_ASSERT_SUCCESS(ret,
			"rte_bbdev_dec_op_alloc_bulk() failed");
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_la12xx_vspa_op(ops_enq, burst_sz, 0,
				bufs->inputs, bufs->hard_outputs);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;

		last_time = 0;
		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Set counter to validate the ordering */
		for (j = 0; j < burst_sz; ++j)
			ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

		if (ops_enq[0]->vspa_params.output.bdata)
			for (j = 0; j < burst_sz; ++j)
				bbuf_reset(ops_enq[j]->vspa_params.output.bdata);

		start_time = rte_rdtsc_precise();

		enq = rte_pmd_la12xx_enqueue_ops(dev_id, queue_id,
				&ops_enq[enq], burst_sz);
		TEST_ASSERT(enq == burst_sz,
				"Error enqueueing burst, expected %u, got %u",
				burst_sz, enq);

		/* Dequeue */
		do {
			deq += rte_pmd_la12xx_dequeue_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);
		} while (unlikely(burst_sz != deq));

		last_time = rte_rdtsc_precise() - start_time;

		*max_time = RTE_MAX(*max_time, last_time);
		*min_time = RTE_MIN(*min_time, last_time);
		*total_time += last_time;

		dequeued += deq;
	}
	rte_mempool_put_bulk(mempool, (void **)ops_enq, burst_sz);

	return TEST_SUCCESS;
}

static int
latency_test_enc(void *arg)
{
	struct thread_params *tp = arg;
	struct rte_bbdev_enc_op *ref_op = tp->op_params->ref_enc_op;
	struct test_bbdev_vector *vector = tp->op_params->vector;
	struct rte_mempool *mempool = tp->op_params->mp;
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	uint16_t dev_id = tp->dev_id;
	uint16_t queue_id = tp->queue_id;
	uint64_t num_to_process = tp->iter_count;
	uint16_t burst_sz = tp->op_params->burst_sz;
	uint64_t *total_time = tp->total_time;
	uint64_t *min_time = tp->min_time;
	uint64_t *max_time = tp->max_time;

	int ret = TEST_SUCCESS;
	uint64_t i, j, dequeued;
	struct rte_bbdev_enc_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t start_time = 0, last_time = 0;

	rte_bbdev_info_get(tp->dev_id, &info);
	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_bbdev_enc_op_alloc_bulk(mempool, ops_enq, burst_sz);
	TEST_ASSERT_SUCCESS(ret,
			"rte_bbdev_enc_op_alloc_bulk() failed");
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_enc_op(ops_enq, burst_sz, 0,
				bufs->inputs,
				bufs->hard_outputs,
				ref_op);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;
		last_time = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Set counter to validate the ordering */
		for (j = 0; j < burst_sz; ++j)
			ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

		start_time = rte_rdtsc_precise();

		enq = rte_bbdev_enqueue_enc_ops(dev_id, queue_id, &ops_enq[enq],
				burst_sz);
		TEST_ASSERT(enq == burst_sz,
				"Error enqueueing burst, expected %u, got %u",
				burst_sz, enq);

		/* Dequeue */
		do {
			deq += rte_bbdev_dequeue_enc_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);
		} while (unlikely(burst_sz != deq));

		last_time += rte_rdtsc_precise() - start_time;

		*max_time = RTE_MAX(*max_time, last_time);
		*min_time = RTE_MIN(*min_time, last_time);
		*total_time += last_time;

		if (vector->op_type != RTE_BBDEV_OP_NONE) {
			ret = validate_enc_op(ops_deq, burst_sz, ref_op,
					      vector);
			TEST_ASSERT_SUCCESS(ret, "Validation failed!");
		}

		dequeued += deq;
	}
	rte_bbdev_enc_op_free_bulk(ops_enq, burst_sz);

	return TEST_SUCCESS;
}

static int
latency_test_ldpc_enc(void *arg)
{
	struct thread_params *tp = arg;
	struct rte_bbdev_enc_op *ref_op = tp->op_params->ref_enc_op;
	struct test_bbdev_vector *vector = tp->op_params->vector;
	struct rte_mempool *mempool = tp->op_params->mp;
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	uint16_t dev_id = tp->dev_id;
	uint16_t queue_id = tp->queue_id;
	uint16_t burst_sz = tp->op_params->burst_sz;
	uint64_t num_to_process = tp->iter_count;
	uint64_t *total_time = tp->total_time;
	uint64_t *min_time = tp->min_time;
	uint64_t *max_time = tp->max_time;

	int ret = TEST_SUCCESS;
	uint64_t i, j, dequeued;
	struct rte_bbdev_enc_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t start_time = 0, last_time = 0;

	rte_bbdev_info_get(tp->dev_id, &info);
	bufs = &tp->op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	while (rte_atomic16_read(&tp->op_params->sync) == SYNC_WAIT)
		rte_pause();

	ret = rte_bbdev_enc_op_alloc_bulk(mempool, ops_enq, burst_sz);
	TEST_ASSERT_SUCCESS(ret,
			"rte_bbdev_enc_op_alloc_bulk() failed");
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_ldpc_enc_op(ops_enq, burst_sz, 0,
				bufs->inputs,
				bufs->hard_outputs,
				ref_op);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;
		last_time = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Set counter to validate the ordering */
		for (j = 0; j < burst_sz; ++j)
			ops_enq[j]->opaque_data = (void *)(uintptr_t)j;

		if (vector->op_type != RTE_BBDEV_OP_NONE)
			for (j = 0; j < burst_sz; ++j)
				bbuf_reset(ops_enq[j]->ldpc_enc.output.bdata);

		if (ref_op->ldpc_enc.se_ce_mux) {
			while (rte_atomic16_read(&se_ce_mux_sync_var) == 0)
				;
		}

		start_time = rte_rdtsc_precise();

		enq = rte_bbdev_enqueue_ldpc_enc_ops(dev_id, queue_id,
				&ops_enq[enq], burst_sz);
		TEST_ASSERT(enq == burst_sz,
				"Error enqueueing burst, expected %u, got %u",
				burst_sz, enq);

		/* Dequeue */
		do {
			deq += rte_bbdev_dequeue_ldpc_enc_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);
		} while (unlikely(burst_sz != deq));

		last_time += rte_rdtsc_precise() - start_time;

		*max_time = RTE_MAX(*max_time, last_time);
		*min_time = RTE_MIN(*min_time, last_time);
		*total_time += last_time;

		if (ref_op->ldpc_enc.se_ce_mux)
			rte_atomic16_set(&se_ce_mux_sync_var, 0);

		if (vector->op_type != RTE_BBDEV_OP_NONE) {
			ret = validate_enc_op(ops_deq, burst_sz, ref_op,
					      vector);
			TEST_ASSERT_SUCCESS(ret, "Validation failed!");
		}

		/*
		 * printf("Ready to free - deq %d num_to_process %d\n", FIXME
		 *		deq, num_to_process);
		 * printf("cache %d\n", ops_enq[0]->mempool->cache_size);
		 */
		dequeued += deq;
	}
	rte_bbdev_enc_op_free_bulk(ops_enq, burst_sz);

	return TEST_SUCCESS;
}

static int
latency_test(struct active_device *ad,
		struct test_op_params *op_params)
{
	int iter, ret;
	uint16_t burst_sz = op_params->burst_sz;
	uint64_t num_to_process;
	enum rte_bbdev_op_type op_type;
	struct thread_params *t_params;
	struct rte_bbdev_info info;
	lcore_function_t *latency_function[RTE_MAX_LCORE];
	uint64_t total_time[RTE_MAX_LCORE];
	uint64_t min_time[RTE_MAX_LCORE];
	uint64_t max_time[RTE_MAX_LCORE];
	const char *op_type_str;
	unsigned int lcore_id, used_cores = 0;
	unsigned int master_lcore_id;
	uint16_t num_lcores;
	int socket_id;

	rte_bbdev_info_get(ad->dev_id, &info);
	socket_id = GET_SOCKET(info.socket_id);
	/* Set number of lcores */
	num_lcores = get_vector_count();
	master_lcore_id = rte_lcore_id();

	printf("+ ------------------------------------------------------- +\n");
	printf("== test: latency\ndev: %s, burst size: %u, num ops: %u, num_lcores: %u:\n",
		info.dev_name, burst_sz, op_params[master_lcore_id].num_to_process,
		num_lcores);

	/* Allocate memory for thread parameters structure */
	t_params = rte_zmalloc_socket(NULL, num_lcores * sizeof(struct thread_params),
			RTE_CACHE_LINE_SIZE, socket_id);
	TEST_ASSERT_NOT_NULL(t_params, "Failed to alloc %zuB for t_params",
			RTE_ALIGN(sizeof(struct thread_params) * num_lcores,
				RTE_CACHE_LINE_SIZE));

	if (get_reset_param() == RESTORE_RESET_CFG)
		rte_pmd_la12xx_reset_restore_cfg(ad->dev_id);
	else if (get_reset_param() == FECA_RESET) {
		uint64_t start_time = 0, last_time = 0;
		start_time = rte_rdtsc_precise();
		rte_pmd_la12xx_feca_reset(ad->dev_id);
		last_time = rte_rdtsc_precise() - start_time;
		printf("FECA reset latency: %lg us\n",
			(double)(last_time * 1000000) /
			(double)rte_get_tsc_hz());
	}

	RTE_LCORE_FOREACH(lcore_id) {
		if (used_cores > num_lcores)
			break;

		num_to_process = op_params[lcore_id].num_to_process *
					TEST_REPETITIONS;

		t_params[used_cores].dev_id = ad->dev_id;
		t_params[used_cores].lcore_id = lcore_id;
		t_params[used_cores].op_params = &op_params[lcore_id];
		t_params[used_cores].queue_id = ad->queue_ids[used_cores];
		t_params[used_cores].iter_count = num_to_process;
		t_params[used_cores].total_time = &total_time[used_cores];
		t_params[used_cores].min_time = &min_time[used_cores];
		t_params[used_cores].max_time = &max_time[used_cores];

		total_time[used_cores] = max_time[used_cores] = 0;
		min_time[used_cores] = UINT64_MAX;

		op_type = op_params[lcore_id].vector->op_type;
		op_type_str = rte_bbdev_op_type_str(op_type);
		TEST_ASSERT_NOT_NULL(op_type_str, "Invalid op type: %u", op_type);

		if (op_type == RTE_BBDEV_OP_TURBO_DEC)
			latency_function[used_cores] = latency_test_dec;
		else if (op_type == RTE_BBDEV_OP_TURBO_ENC)
			latency_function[used_cores] = latency_test_enc;
		else if (op_type == RTE_BBDEV_OP_LDPC_ENC)
			latency_function[used_cores] = latency_test_ldpc_enc;
		else if (op_type == RTE_BBDEV_OP_LDPC_DEC)
			latency_function[used_cores] = latency_test_ldpc_dec;
		else if ((op_type == RTE_BBDEV_OP_POLAR_DEC) ||
					(op_type == RTE_BBDEV_OP_POLAR_ENC))
			latency_function[used_cores] = latency_test_ldpc_polar;
		else if (op_type == RTE_BBDEV_OP_RAW)
			latency_function[used_cores] = latency_test_la12xx_raw;
		else if (op_type == RTE_BBDEV_OP_LA12XX_VSPA)
			latency_function[used_cores] = latency_test_la12xx_vspa;
		else
			latency_function[used_cores] = latency_test_enc;

		rte_atomic16_set(&(&op_params[lcore_id])->sync, SYNC_WAIT);

		if (used_cores != 0) {
			rte_eal_remote_launch(latency_function[used_cores],
				&t_params[used_cores], lcore_id);
		}
		used_cores++;
	}

	rte_atomic16_set(&sd_cd_demux_sync_var, 0);
	rte_atomic16_set(&se_ce_mux_sync_var, 0);

	RTE_LCORE_FOREACH(lcore_id) {
		rte_atomic16_set(&(&op_params[lcore_id])->sync, SYNC_START);
	}
	ret = latency_function[0](&t_params[0]);

	/* Master core is always used */
	for (used_cores = 1; used_cores < num_lcores; used_cores++)
		ret |= rte_eal_wait_lcore(t_params[used_cores].lcore_id);

	/* Return if test failed */
	if (ret) {
		rte_free(t_params);
		return ret;
	}

	used_cores = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (used_cores > num_lcores)
			break;

		iter = t_params[used_cores].iter_count/burst_sz;
		printf("[core %d] Operation latency with burst_sz <%d>:\n"
				"\tavg per packet: %lg cycles, %lg us\n"
				"\tavg per burst: %lg cycles, %lg us\n"
				"\tmin for burst: %lg cycles, %lg us\n"
				"\tmax for burst: %lg cycles, %lg us\n",
				lcore_id, burst_sz,
				(double)total_time[used_cores] / (double)iter / burst_sz,
				(double)(total_time[used_cores] * 1000000) / (double)iter /
				(double)rte_get_tsc_hz() / burst_sz,
				(double)total_time[used_cores] / (double)iter,
				(double)(total_time[used_cores] * 1000000) / (double)iter /
				(double)rte_get_tsc_hz(), (double)min_time[used_cores],
				(double)(min_time[used_cores] * 1000000) / (double)rte_get_tsc_hz(),
				(double)max_time[used_cores], (double)(max_time[used_cores] * 1000000) /
				(double)rte_get_tsc_hz());
		used_cores++;
	}

	return TEST_SUCCESS;
}

#if 0
#ifdef RTE_BBDEV_OFFLOAD_COST
static int
get_bbdev_queue_stats(uint16_t dev_id, uint16_t queue_id,
		struct rte_bbdev_stats *stats)
{
	struct rte_bbdev *dev = &rte_bbdev_devices[dev_id];
	struct rte_bbdev_stats *q_stats;

	if (queue_id >= dev->data->num_queues)
		return -1;

	q_stats = &dev->data->queues[queue_id].queue_stats;

	stats->enqueued_count = q_stats->enqueued_count;
	stats->dequeued_count = q_stats->dequeued_count;
	stats->enqueue_err_count = q_stats->enqueue_err_count;
	stats->dequeue_err_count = q_stats->dequeue_err_count;
	stats->acc_offload_cycles = q_stats->acc_offload_cycles;

	return 0;
}

static int
offload_latency_test_fft(struct rte_mempool *mempool, struct test_buffers *bufs,
		struct rte_bbdev_fft_op *ref_op, uint16_t dev_id,
		uint16_t queue_id, const uint16_t num_to_process,
		uint16_t burst_sz, struct test_time_stats *time_st)
{
	int i, dequeued, ret;
	struct rte_bbdev_fft_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t enq_start_time, deq_start_time;
	uint64_t enq_sw_last_time, deq_last_time;
	struct rte_bbdev_stats stats;

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		rte_bbdev_fft_op_alloc_bulk(mempool, ops_enq, burst_sz);
		if (test_vector.op_type != RTE_BBDEV_OP_NONE)
			copy_reference_fft_op(ops_enq, burst_sz, dequeued,
					bufs->inputs,
					bufs->hard_outputs, bufs->soft_outputs,
					ref_op);

		/* Start time meas for enqueue function offload latency */
		enq_start_time = rte_rdtsc_precise();
		do {
			enq += rte_bbdev_enqueue_fft_ops(dev_id, queue_id,
					&ops_enq[enq], burst_sz - enq);
		} while (unlikely(burst_sz != enq));

		ret = get_bbdev_queue_stats(dev_id, queue_id, &stats);
		TEST_ASSERT_SUCCESS(ret,
				"Failed to get stats for queue (%u) of device (%u)",
				queue_id, dev_id);

		enq_sw_last_time = rte_rdtsc_precise() - enq_start_time -
				stats.acc_offload_cycles;
		time_st->enq_sw_max_time = RTE_MAX(time_st->enq_sw_max_time,
				enq_sw_last_time);
		time_st->enq_sw_min_time = RTE_MIN(time_st->enq_sw_min_time,
				enq_sw_last_time);
		time_st->enq_sw_total_time += enq_sw_last_time;

		time_st->enq_acc_max_time = RTE_MAX(time_st->enq_acc_max_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_min_time = RTE_MIN(time_st->enq_acc_min_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_total_time += stats.acc_offload_cycles;

		/* give time for device to process ops */
		rte_delay_us(WAIT_OFFLOAD_US);

		/* Start time meas for dequeue function offload latency */
		deq_start_time = rte_rdtsc_precise();
		/* Dequeue one operation */
		do {
			deq += rte_bbdev_dequeue_fft_ops(dev_id, queue_id,
					&ops_deq[deq], enq);
		} while (unlikely(deq == 0));

		deq_last_time = rte_rdtsc_precise() - deq_start_time;
		time_st->deq_max_time = RTE_MAX(time_st->deq_max_time,
				deq_last_time);
		time_st->deq_min_time = RTE_MIN(time_st->deq_min_time,
				deq_last_time);
		time_st->deq_total_time += deq_last_time;

		/* Dequeue remaining operations if needed*/
		while (burst_sz != deq)
			deq += rte_bbdev_dequeue_fft_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);

		rte_bbdev_fft_op_free_bulk(ops_enq, deq);
		dequeued += deq;
	}

	return i;
}

static int
offload_latency_test_dec(struct rte_mempool *mempool, struct test_buffers *bufs,
		struct rte_bbdev_dec_op *ref_op, uint16_t dev_id,
		uint16_t queue_id, const uint16_t num_to_process,
		uint16_t burst_sz, struct test_time_stats *time_st,
		struct test_bbdev_vector *vector)
{
	int i, dequeued, ret;
	struct rte_bbdev_dec_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t enq_start_time, deq_start_time;
	uint64_t enq_sw_last_time, deq_last_time;
	struct rte_bbdev_stats stats;

	rte_bbdev_dec_op_alloc_bulk(mempool, ops_enq, burst_sz);
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_dec_op(ops_enq, burst_sz, 0,
				bufs->inputs,
				bufs->hard_outputs,
				bufs->soft_outputs,
				ref_op);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Start time meas for enqueue function offload latency */
		enq_start_time = rte_rdtsc_precise();
		do {
			enq += rte_bbdev_enqueue_dec_ops(dev_id, queue_id,
					&ops_enq[enq], burst_sz - enq);
		} while (unlikely(burst_sz != enq));

		ret = get_bbdev_queue_stats(dev_id, queue_id, &stats);
		TEST_ASSERT_SUCCESS(ret,
				"Failed to get stats for queue (%u) of device (%u)",
				queue_id, dev_id);

		enq_sw_last_time = rte_rdtsc_precise() - enq_start_time -
				stats.acc_offload_cycles;
		time_st->enq_sw_max_time = RTE_MAX(time_st->enq_sw_max_time,
				enq_sw_last_time);
		time_st->enq_sw_min_time = RTE_MIN(time_st->enq_sw_min_time,
				enq_sw_last_time);
		time_st->enq_sw_total_time += enq_sw_last_time;

		time_st->enq_acc_max_time = RTE_MAX(time_st->enq_acc_max_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_min_time = RTE_MIN(time_st->enq_acc_min_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_total_time += stats.acc_offload_cycles;

		/* give time for device to process ops */
		rte_delay_us(200);

		/* Start time meas for dequeue function offload latency */
		deq_start_time = rte_rdtsc_precise();
		/* Dequeue one operation */
		do {
			deq += rte_bbdev_dequeue_dec_ops(dev_id, queue_id,
					&ops_deq[deq], 1);
		} while (unlikely(deq != 1));

		deq_last_time = rte_rdtsc_precise() - deq_start_time;
		time_st->deq_max_time = RTE_MAX(time_st->deq_max_time,
				deq_last_time);
		time_st->deq_min_time = RTE_MIN(time_st->deq_min_time,
				deq_last_time);
		time_st->deq_total_time += deq_last_time;

		/* Dequeue remaining operations if needed*/
		while (burst_sz != deq)
			deq += rte_bbdev_dequeue_dec_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);

		dequeued += deq;
	}
	rte_bbdev_dec_op_free_bulk(ops_enq, burst_sz);

	return i;
}

static int
offload_latency_test_ldpc_dec(struct rte_mempool *mempool,
		struct test_buffers *bufs,
		struct rte_bbdev_dec_op *ref_op, uint16_t dev_id,
		uint16_t queue_id, const uint16_t num_to_process,
		uint16_t burst_sz, struct test_time_stats *time_st,
		struct test_bbdev_vector *vector)
{
	int i, dequeued, ret;
	struct rte_bbdev_dec_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t enq_start_time, deq_start_time;
	uint64_t enq_sw_last_time, deq_last_time;
	struct rte_bbdev_stats stats;

	rte_bbdev_dec_op_alloc_bulk(mempool, ops_enq, burst_sz);
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_ldpc_dec_op(ops_enq, burst_sz, 0,
				bufs->inputs,
				bufs->hard_outputs,
				bufs->soft_outputs,
				bufs->harq_inputs,
				bufs->harq_outputs,
				ref_op);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Start time meas for enqueue function offload latency */
		enq_start_time = rte_rdtsc_precise();
		do {
			enq += rte_bbdev_enqueue_ldpc_dec_ops(dev_id, queue_id,
					&ops_enq[enq], burst_sz - enq);
		} while (unlikely(burst_sz != enq));

		ret = get_bbdev_queue_stats(dev_id, queue_id, &stats);
		TEST_ASSERT_SUCCESS(ret,
				"Failed to get stats for queue (%u) of device (%u)",
				queue_id, dev_id);

		enq_sw_last_time = rte_rdtsc_precise() - enq_start_time -
				stats.acc_offload_cycles;
		time_st->enq_sw_max_time = RTE_MAX(time_st->enq_sw_max_time,
				enq_sw_last_time);
		time_st->enq_sw_min_time = RTE_MIN(time_st->enq_sw_min_time,
				enq_sw_last_time);
		time_st->enq_sw_total_time += enq_sw_last_time;

		time_st->enq_acc_max_time = RTE_MAX(time_st->enq_acc_max_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_min_time = RTE_MIN(time_st->enq_acc_min_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_total_time += stats.acc_offload_cycles;

		/* give time for device to process ops */
		rte_delay_us(200);

		/* Start time meas for dequeue function offload latency */
		deq_start_time = rte_rdtsc_precise();
		/* Dequeue one operation */
		do {
			deq += rte_bbdev_dequeue_ldpc_dec_ops(dev_id, queue_id,
					&ops_deq[deq], 1);
		} while (unlikely(deq != 1));

		deq_last_time = rte_rdtsc_precise() - deq_start_time;
		time_st->deq_max_time = RTE_MAX(time_st->deq_max_time,
				deq_last_time);
		time_st->deq_min_time = RTE_MIN(time_st->deq_min_time,
				deq_last_time);
		time_st->deq_total_time += deq_last_time;

		/* Dequeue remaining operations if needed*/
		while (burst_sz != deq)
			deq += rte_bbdev_dequeue_dec_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);

		dequeued += deq;
	}
	rte_bbdev_dec_op_free_bulk(ops_enq, burst_sz);

	return i;
}

static int
offload_latency_test_polar(struct rte_mempool *mempool,
		struct test_buffers *bufs,
		struct rte_pmd_la12xx_op *ref_op, uint16_t dev_id,
		uint16_t queue_id, const uint16_t num_to_process,
		uint16_t burst_sz, struct test_time_stats *time_st,
		struct test_bbdev_vector *vector)
{
	int i, dequeued, ret;
	struct rte_pmd_la12xx_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t enq_start_time, deq_start_time;
	uint64_t enq_sw_last_time, deq_last_time;
	struct rte_bbdev_stats stats;

	ret = rte_mempool_get_bulk(mempool, (void **)ops_enq, burst_sz);
	TEST_ASSERT_SUCCESS(ret, "rte_bbdev_op_alloc_bulk() failed");

	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_polar_op(ops_enq, burst_sz, 0,
				bufs->inputs,
				bufs->hard_outputs,
				ref_op);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Start time meas for enqueue function offload latency */
		enq_start_time = rte_rdtsc_precise();
		do {
			enq += rte_pmd_la12xx_enqueue_ops(dev_id, queue_id,
					&ops_enq[enq], burst_sz - enq);
		} while (unlikely(burst_sz != enq));

		ret = get_bbdev_queue_stats(dev_id, queue_id, &stats);
		TEST_ASSERT_SUCCESS(ret,
				"Failed to get stats for queue (%u) of device (%u)",
				queue_id, dev_id);

		enq_sw_last_time = rte_rdtsc_precise() - enq_start_time -
				stats.acc_offload_cycles;
		time_st->enq_sw_max_time = RTE_MAX(time_st->enq_sw_max_time,
				enq_sw_last_time);
		time_st->enq_sw_min_time = RTE_MIN(time_st->enq_sw_min_time,
				enq_sw_last_time);
		time_st->enq_sw_total_time += enq_sw_last_time;

		time_st->enq_acc_max_time = RTE_MAX(time_st->enq_acc_max_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_min_time = RTE_MIN(time_st->enq_acc_min_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_total_time += stats.acc_offload_cycles;

		/* give time for device to process ops */
		rte_delay_us(200);

		/* Start time meas for dequeue function offload latency */
		deq_start_time = rte_rdtsc_precise();
		/* Dequeue one operation */
		do {
			deq += rte_pmd_la12xx_dequeue_ops(dev_id, queue_id,
					&ops_deq[deq], 1);
		} while (unlikely(deq != 1));

		deq_last_time = rte_rdtsc_precise() - deq_start_time;
		time_st->deq_max_time = RTE_MAX(time_st->deq_max_time,
				deq_last_time);
		time_st->deq_min_time = RTE_MIN(time_st->deq_min_time,
				deq_last_time);
		time_st->deq_total_time += deq_last_time;

		/* Dequeue remaining operations if needed*/
		while (burst_sz != deq)
			deq += rte_pmd_la12xx_dequeue_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);

		dequeued += deq;
	}
	rte_mempool_put_bulk(mempool, (void **)ops_enq, burst_sz);

	return i;
}
static int
offload_latency_test_enc(struct rte_mempool *mempool, struct test_buffers *bufs,
		struct rte_bbdev_enc_op *ref_op, uint16_t dev_id,
		uint16_t queue_id, const uint16_t num_to_process,
		uint16_t burst_sz, struct test_time_stats *time_st,
		struct test_bbdev_vector *vector)
{
	int i, dequeued, ret;
	struct rte_bbdev_enc_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t enq_start_time, deq_start_time;
	uint64_t enq_sw_last_time, deq_last_time;
	struct rte_bbdev_stats stats;

	ret = rte_bbdev_enc_op_alloc_bulk(mempool, ops_enq, burst_sz);
	TEST_ASSERT_SUCCESS(ret, "rte_bbdev_op_alloc_bulk() failed");
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_enc_op(ops_enq, burst_sz, 0,
				bufs->inputs,
				bufs->hard_outputs,
				ref_op);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Start time meas for enqueue function offload latency */
		enq_start_time = rte_rdtsc_precise();
		do {
			enq += rte_bbdev_enqueue_enc_ops(dev_id, queue_id,
					&ops_enq[enq], burst_sz - enq);
		} while (unlikely(burst_sz != enq));

		ret = get_bbdev_queue_stats(dev_id, queue_id, &stats);
		TEST_ASSERT_SUCCESS(ret,
				"Failed to get stats for queue (%u) of device (%u)",
				queue_id, dev_id);

		enq_sw_last_time = rte_rdtsc_precise() - enq_start_time -
				stats.acc_offload_cycles;
		time_st->enq_sw_max_time = RTE_MAX(time_st->enq_sw_max_time,
				enq_sw_last_time);
		time_st->enq_sw_min_time = RTE_MIN(time_st->enq_sw_min_time,
				enq_sw_last_time);
		time_st->enq_sw_total_time += enq_sw_last_time;

		time_st->enq_acc_max_time = RTE_MAX(time_st->enq_acc_max_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_min_time = RTE_MIN(time_st->enq_acc_min_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_total_time += stats.acc_offload_cycles;

		/* give time for device to process ops */
		rte_delay_us(200);

		/* Start time meas for dequeue function offload latency */
		deq_start_time = rte_rdtsc_precise();
		/* Dequeue one operation */
		do {
			deq += rte_bbdev_dequeue_enc_ops(dev_id, queue_id,
					&ops_deq[deq], 1);
		} while (unlikely(deq != 1));

		deq_last_time = rte_rdtsc_precise() - deq_start_time;
		time_st->deq_max_time = RTE_MAX(time_st->deq_max_time,
				deq_last_time);
		time_st->deq_min_time = RTE_MIN(time_st->deq_min_time,
				deq_last_time);
		time_st->deq_total_time += deq_last_time;

		while (burst_sz != deq)
			deq += rte_bbdev_dequeue_enc_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);

		dequeued += deq;
	}
	rte_bbdev_enc_op_free_bulk(ops_enq, burst_sz);

	return i;
}

static int
offload_latency_test_ldpc_enc(struct rte_mempool *mempool,
		struct test_buffers *bufs,
		struct rte_bbdev_enc_op *ref_op, uint16_t dev_id,
		uint16_t queue_id, const uint16_t num_to_process,
		uint16_t burst_sz, struct test_time_stats *time_st,
		struct test_bbdev_vector *vector)
{
	int i, dequeued, ret;
	struct rte_bbdev_enc_op *ops_enq[MAX_BURST], *ops_deq[MAX_BURST];
	uint64_t enq_start_time, deq_start_time;
	uint64_t enq_sw_last_time, deq_last_time;
	struct rte_bbdev_stats stats;

	ret = rte_bbdev_enc_op_alloc_bulk(mempool, ops_enq, burst_sz);
	TEST_ASSERT_SUCCESS(ret, "rte_bbdev_op_alloc_bulk() failed");
	if (vector->op_type != RTE_BBDEV_OP_NONE)
		copy_reference_ldpc_enc_op(ops_enq, burst_sz, 0,
				bufs->inputs,
				bufs->hard_outputs,
				ref_op);

	for (i = 0, dequeued = 0; dequeued < num_to_process; ++i) {
		uint16_t enq = 0, deq = 0;

		if (unlikely(num_to_process - dequeued < burst_sz))
			burst_sz = num_to_process - dequeued;

		/* Start time meas for enqueue function offload latency */
		enq_start_time = rte_rdtsc_precise();
		do {
			enq += rte_bbdev_enqueue_ldpc_enc_ops(dev_id, queue_id,
					&ops_enq[enq], burst_sz - enq);
		} while (unlikely(burst_sz != enq));

		ret = get_bbdev_queue_stats(dev_id, queue_id, &stats);
		TEST_ASSERT_SUCCESS(ret,
				"Failed to get stats for queue (%u) of device (%u)",
				queue_id, dev_id);

		enq_sw_last_time = rte_rdtsc_precise() - enq_start_time -
				stats.acc_offload_cycles;
		time_st->enq_sw_max_time = RTE_MAX(time_st->enq_sw_max_time,
				enq_sw_last_time);
		time_st->enq_sw_min_time = RTE_MIN(time_st->enq_sw_min_time,
				enq_sw_last_time);
		time_st->enq_sw_total_time += enq_sw_last_time;

		time_st->enq_acc_max_time = RTE_MAX(time_st->enq_acc_max_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_min_time = RTE_MIN(time_st->enq_acc_min_time,
				stats.acc_offload_cycles);
		time_st->enq_acc_total_time += stats.acc_offload_cycles;

		/* give time for device to process ops */
		rte_delay_us(200);

		/* Start time meas for dequeue function offload latency */
		deq_start_time = rte_rdtsc_precise();
		/* Dequeue one operation */
		do {
			deq += rte_bbdev_dequeue_ldpc_enc_ops(dev_id, queue_id,
					&ops_deq[deq], 1);
		} while (unlikely(deq != 1));

		deq_last_time = rte_rdtsc_precise() - deq_start_time;
		time_st->deq_max_time = RTE_MAX(time_st->deq_max_time,
				deq_last_time);
		time_st->deq_min_time = RTE_MIN(time_st->deq_min_time,
				deq_last_time);
		time_st->deq_total_time += deq_last_time;

		while (burst_sz != deq)
			deq += rte_bbdev_dequeue_ldpc_enc_ops(dev_id, queue_id,
					&ops_deq[deq], burst_sz - deq);

		dequeued += deq;
	}
	rte_bbdev_enc_op_free_bulk(ops_enq, burst_sz);

	return i;
}
#endif

static int
offload_cost_test(struct active_device *ad,
		struct test_op_params *op_params)
{
#ifndef RTE_BBDEV_OFFLOAD_COST
	RTE_SET_USED(ad);
	RTE_SET_USED(op_params);
	printf("Offload latency test is disabled.\n");
	printf("Set RTE_BBDEV_OFFLOAD_COST to 'y' to turn the test on.\n");
	return TEST_SKIPPED;
#else
	int iter;
	uint16_t burst_sz = 1;
	struct test_bbdev_vector *vector = op_params->vector;
	const uint16_t num_to_process = op_params->num_to_process *
					TEST_REPETITIONS;
	const enum rte_bbdev_op_type op_type = vector->op_type;
	const uint16_t queue_id = ad->queue_ids[0];
	struct test_buffers *bufs = NULL;
	struct rte_bbdev_info info;
	const char *op_type_str;
	struct test_time_stats time_st;

	if (((vector->op_type == RTE_BBDEV_OP_LDPC_DEC) &&
	    vector->ldpc_dec.sd_cd_demux) ||
	    ((vector->op_type == RTE_BBDEV_OP_POLAR_DEC) &&
	    RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX(&vector->polar_op)))
		TEST_ASSERT(0, "SD CD DEMUX not supported for offload latency test");

	if (((vector->op_type == RTE_BBDEV_OP_LDPC_ENC) &&
	    vector->ldpc_enc.se_ce_mux) ||
	    ((vector->op_type == RTE_BBDEV_OP_POLAR_ENC) &&
	    RTE_PMD_LA12xx_IS_POLAR_ENC_MUX(&vector->polar_op)))
		TEST_ASSERT(0, "SE CE MUX not supported for offload latency test");

	memset(&time_st, 0, sizeof(struct test_time_stats));
	time_st.enq_sw_min_time = UINT64_MAX;
	time_st.enq_acc_min_time = UINT64_MAX;
	time_st.deq_min_time = UINT64_MAX;

	rte_bbdev_info_get(ad->dev_id, &info);
	bufs = &op_params->q_bufs[GET_SOCKET(info.socket_id)][queue_id];

	op_type_str = rte_bbdev_op_type_str(op_type);
	TEST_ASSERT_NOT_NULL(op_type_str, "Invalid op type: %u", op_type);

	printf("+ ------------------------------------------------------- +\n");
	printf("== test: offload latency test\ndev: %s, burst size: %u, num ops: %u, op type: %s\n",
			info.dev_name, burst_sz, num_to_process, op_type_str);

	if (op_type == RTE_BBDEV_OP_TURBO_DEC)
		iter = offload_latency_test_dec(op_params->mp, bufs,
				op_params->ref_dec_op, ad->dev_id, queue_id,
				num_to_process, burst_sz, &time_st, vector);
	else if (op_type == RTE_BBDEV_OP_TURBO_ENC)
		iter = offload_latency_test_enc(op_params->mp, bufs,
				op_params->ref_enc_op, ad->dev_id, queue_id,
				num_to_process, burst_sz, &time_st, vector);
	else if (op_type == RTE_BBDEV_OP_LDPC_ENC)
		iter = offload_latency_test_ldpc_enc(op_params->mp, bufs,
				op_params->ref_enc_op, ad->dev_id, queue_id,
				num_to_process, burst_sz, &time_st, vector);
	else if (op_type == RTE_BBDEV_OP_LDPC_DEC)
		iter = offload_latency_test_ldpc_dec(op_params->mp, bufs,
			op_params->ref_dec_op, ad->dev_id, queue_id,
			num_to_process, burst_sz, &time_st, vector);
	else if ((op_type == RTE_BBDEV_OP_POLAR_DEC) || (op_type == RTE_BBDEV_OP_POLAR_ENC))
		iter = offload_latency_test_polar(op_params->mp, bufs,
				op_params->ref_la12xx_op, ad->dev_id, queue_id,
				num_to_process, burst_sz, &time_st, vector);
	else
		iter = offload_latency_test_enc(op_params->mp, bufs,
				op_params->ref_enc_op, ad->dev_id, queue_id,
				num_to_process, burst_sz, &time_st, vector);

	if (iter <= 0)
		return TEST_FAILED;

	printf("Enqueue driver offload cost latency:\n"
			"\tavg: %lg cycles, %lg us\n"
			"\tmin: %lg cycles, %lg us\n"
			"\tmax: %lg cycles, %lg us\n"
			"Enqueue accelerator offload cost latency:\n"
			"\tavg: %lg cycles, %lg us\n"
			"\tmin: %lg cycles, %lg us\n"
			"\tmax: %lg cycles, %lg us\n",
			(double)time_st.enq_sw_total_time / (double)iter,
			(double)(time_st.enq_sw_total_time * 1000000) /
			(double)iter / (double)rte_get_tsc_hz(),
			(double)time_st.enq_sw_min_time,
			(double)(time_st.enq_sw_min_time * 1000000) /
			rte_get_tsc_hz(), (double)time_st.enq_sw_max_time,
			(double)(time_st.enq_sw_max_time * 1000000) /
			rte_get_tsc_hz(), (double)time_st.enq_acc_total_time /
			(double)iter,
			(double)(time_st.enq_acc_total_time * 1000000) /
			(double)iter / (double)rte_get_tsc_hz(),
			(double)time_st.enq_acc_min_time,
			(double)(time_st.enq_acc_min_time * 1000000) /
			rte_get_tsc_hz(), (double)time_st.enq_acc_max_time,
			(double)(time_st.enq_acc_max_time * 1000000) /
			rte_get_tsc_hz());

	printf("Dequeue offload cost latency - one op:\n"
			"\tavg: %lg cycles, %lg us\n"
			"\tmin: %lg cycles, %lg us\n"
			"\tmax: %lg cycles, %lg us\n",
			(double)time_st.deq_total_time / (double)iter,
			(double)(time_st.deq_total_time * 1000000) /
			(double)iter / (double)rte_get_tsc_hz(),
			(double)time_st.deq_min_time,
			(double)(time_st.deq_min_time * 1000000) /
			rte_get_tsc_hz(), (double)time_st.deq_max_time,
			(double)(time_st.deq_max_time * 1000000) /
			rte_get_tsc_hz());

	return TEST_SUCCESS;
#endif
}

#ifdef RTE_BBDEV_OFFLOAD_COST
static int
offload_latency_empty_q_test_dec(uint16_t dev_id, uint16_t queue_id,
		const uint16_t num_to_process, uint16_t burst_sz,
		uint64_t *deq_total_time, uint64_t *deq_min_time,
		uint64_t *deq_max_time)
{
	int i, deq_total;
	struct rte_bbdev_dec_op *ops[MAX_BURST];
	uint64_t deq_start_time, deq_last_time;

	/* Test deq offload latency from an empty queue */

	for (i = 0, deq_total = 0; deq_total < num_to_process;
			++i, deq_total += burst_sz) {
		deq_start_time = rte_rdtsc_precise();

		if (unlikely(num_to_process - deq_total < burst_sz))
			burst_sz = num_to_process - deq_total;
		rte_bbdev_dequeue_dec_ops(dev_id, queue_id, ops, burst_sz);

		deq_last_time = rte_rdtsc_precise() - deq_start_time;
		*deq_max_time = RTE_MAX(*deq_max_time, deq_last_time);
		*deq_min_time = RTE_MIN(*deq_min_time, deq_last_time);
		*deq_total_time += deq_last_time;
	}

	return i;
}

static int
offload_latency_empty_q_test_enc(uint16_t dev_id, uint16_t queue_id,
		const uint16_t num_to_process, uint16_t burst_sz,
		uint64_t *deq_total_time, uint64_t *deq_min_time,
		uint64_t *deq_max_time)
{
	int i, deq_total;
	struct rte_bbdev_enc_op *ops[MAX_BURST];
	uint64_t deq_start_time, deq_last_time;

	/* Test deq offload latency from an empty queue */
	for (i = 0, deq_total = 0; deq_total < num_to_process;
			++i, deq_total += burst_sz) {
		deq_start_time = rte_rdtsc_precise();

		if (unlikely(num_to_process - deq_total < burst_sz))
			burst_sz = num_to_process - deq_total;
		rte_bbdev_dequeue_enc_ops(dev_id, queue_id, ops, burst_sz);

		deq_last_time = rte_rdtsc_precise() - deq_start_time;
		*deq_max_time = RTE_MAX(*deq_max_time, deq_last_time);
		*deq_min_time = RTE_MIN(*deq_min_time, deq_last_time);
		*deq_total_time += deq_last_time;
	}

	return i;
}
#endif

static int
offload_latency_empty_q_test(struct active_device *ad,
		struct test_op_params *op_params)
{
#ifndef RTE_BBDEV_OFFLOAD_COST
	RTE_SET_USED(ad);
	RTE_SET_USED(op_params);
	printf("Offload latency empty dequeue test is disabled.\n");
	printf("Set RTE_BBDEV_OFFLOAD_COST to 'y' to turn the test on.\n");
	return TEST_SKIPPED;
#else
	int iter;
	struct test_bbdev_vector *vector = op_params->vector;
	uint64_t deq_total_time, deq_min_time, deq_max_time;
	uint16_t burst_sz = 1;
	const uint16_t num_to_process = op_params->num_to_process *
					TEST_REPETITIONS;
	const enum rte_bbdev_op_type op_type = vector->op_type;
	const uint16_t queue_id = ad->queue_ids[0];
	struct rte_bbdev_info info;
	const char *op_type_str;

	if (((vector->op_type == RTE_BBDEV_OP_LDPC_DEC) &&
	    vector->ldpc_dec.sd_cd_demux) ||
	    ((vector->op_type == RTE_BBDEV_OP_POLAR_DEC) &&
	    RTE_PMD_LA12xx_IS_POLAR_DEC_DEMUX(&vector->polar_op)))
		TEST_ASSERT(0, "SD CD DEMUX not supported for offload latency empty queue test");

	if (((vector->op_type == RTE_BBDEV_OP_LDPC_ENC) &&
	    vector->ldpc_enc.se_ce_mux) ||
	    ((vector->op_type == RTE_BBDEV_OP_POLAR_ENC) &&
	    RTE_PMD_LA12xx_IS_POLAR_ENC_MUX(&vector->polar_op)))
		TEST_ASSERT(0, "SE CE MUX not supported for offload latency empty queue test");

	deq_total_time = deq_max_time = 0;
	deq_min_time = UINT64_MAX;

	rte_bbdev_info_get(ad->dev_id, &info);

	op_type_str = rte_bbdev_op_type_str(op_type);
	TEST_ASSERT_NOT_NULL(op_type_str, "Invalid op type: %u", op_type);

	printf("+ ------------------------------------------------------- +\n");
	printf("== test: offload latency empty dequeue\ndev: %s, burst size: %u, num ops: %u, op type: %s\n",
			info.dev_name, burst_sz, num_to_process, op_type_str);

	if (op_type == RTE_BBDEV_OP_TURBO_DEC)
		iter = offload_latency_empty_q_test_dec(ad->dev_id, queue_id,
				num_to_process, burst_sz, &deq_total_time,
				&deq_min_time, &deq_max_time);
	else
		iter = offload_latency_empty_q_test_enc(ad->dev_id, queue_id,
				num_to_process, burst_sz, &deq_total_time,
				&deq_min_time, &deq_max_time);

	if (iter <= 0)
		return TEST_FAILED;

	printf("Empty dequeue offload:\n"
			"\tavg: %lg cycles, %lg us\n"
			"\tmin: %lg cycles, %lg us\n"
			"\tmax: %lg cycles, %lg us\n",
			(double)deq_total_time / (double)iter,
			(double)(deq_total_time * 1000000) / (double)iter /
			(double)rte_get_tsc_hz(), (double)deq_min_time,
			(double)(deq_min_time * 1000000) / rte_get_tsc_hz(),
			(double)deq_max_time, (double)(deq_max_time * 1000000) /
			rte_get_tsc_hz());

	return TEST_SUCCESS;
#endif
}
#endif

static int
throughput_tc(void)
{
	return run_test_case(throughput_test);
}

#if 0
static int
offload_cost_tc(void)
{
	return run_test_case(offload_cost_test);
}

static int
offload_latency_empty_q_tc(void)
{
	return run_test_case(offload_latency_empty_q_test);
}
#endif

static int
latency_tc(void)
{
	return run_test_case(latency_test);
}

#if 0
static int
interrupt_tc(void)
{
	return run_test_case(throughput_test);
}
#endif

static struct unit_test_suite bbdev_throughput_testsuite = {
	.suite_name = "BBdev Throughput Tests",
	.setup = testsuite_setup,
	.unit_test_cases = {
		TEST_CASE_ST(ut_setup, ut_teardown, throughput_tc),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static struct unit_test_suite bbdev_latency_testsuite = {
	.suite_name = "BBdev Latency Tests",
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(ut_setup, ut_teardown, latency_tc),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

#if 0
static struct unit_test_suite bbdev_validation_testsuite = {
	.suite_name = "BBdev Validation Tests",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(ut_setup, ut_teardown, latency_tc),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static struct unit_test_suite bbdev_offload_cost_testsuite = {
	.suite_name = "BBdev Offload Cost Tests",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(ut_setup, ut_teardown, offload_cost_tc),
		TEST_CASE_ST(ut_setup, ut_teardown, offload_latency_empty_q_tc),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static struct unit_test_suite bbdev_interrupt_testsuite = {
	.suite_name = "BBdev Interrupt Tests",
	.setup = interrupt_testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(ut_setup, ut_teardown, interrupt_tc),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
#endif

REGISTER_TEST_COMMAND(throughput, bbdev_throughput_testsuite);
REGISTER_TEST_COMMAND(latency, bbdev_latency_testsuite);
#if 0
REGISTER_TEST_COMMAND(validation, bbdev_validation_testsuite);
REGISTER_TEST_COMMAND(offload, bbdev_offload_cost_testsuite);
REGISTER_TEST_COMMAND(interrupt, bbdev_interrupt_testsuite);
#endif
