/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

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

#include "dfe_host_if.h"
#include "dfe_app.h"
#include "logging.h"
#include "cmd_timer.h"
#include "ipc.h"
#include "tti.h"

struct rte_mempool *mp[BBDEV_QUEUE_COUNT];

uint16_t raw_buf_size;
uint32_t dev_id = BBDEV_IPC_DEV_ID_0;

int stop_tti_thread(void);
int start_tti_thread(void);

void *get_tx_buf(int qid)
{
	void *buf;
	uint32_t len;
	int retries = GET_BUF_RETRIES;

	while (retries--) {
		buf = rte_bbdev_get_next_internal_buf(dev_id, qid, &len);
		if (buf) {
			memset(buf, 0, len);
			return buf;
		}
	}

	app_print_err("Failed to get internal buffer\n");
	return NULL;
}

static int setup_raw_queue(struct rte_bbdev_info *info, uint32_t qid, bool dir)
{
	struct rte_bbdev_queue_conf qconf =  {0};
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	int ret;

	/* setup device queues */
	qconf.socket = 0;
	qconf.queue_size = info->drv.default_queue_conf.queue_size;
	qconf.priority = 0;
	qconf.deferred_start = 0;
	qconf.op_type = RTE_BBDEV_OP_RAW;

	qconf.raw_queue_conf.direction = dir;
	qconf.raw_queue_conf.conf_enable = 0;

	ret = rte_bbdev_queue_configure(dev_id, qid, &qconf);
	if (ret != 0) {
		app_print_err("Failure allocating queue 0 on dev%u\n", dev_id);
		return ret;
	}

	if (dir == RTE_BBDEV_DIR_MODEM_TO_HOST) {
		mp[qid] = NULL;
		return 0;
	}

	snprintf(pool_name, sizeof(pool_name), "pool_%u", dev_id);
	mp[qid] = rte_mempool_create(pool_name, OPS_POOL_SIZE,
				     sizeof(struct rte_bbdev_raw_op),
				     OPS_CACHE_SIZE, 0, NULL, NULL,
				     NULL, NULL, info->socket_id, 0);
	if (!mp[qid])
		return -rte_errno;

	return 0;
}

static unsigned int get_first_free_lcore(void)
{
	static unsigned int lcore_id;

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_get_lcore_state(lcore_id) == WAIT)
			break;
	}

	app_print_dbg("get_first_free_lcore: lcore_id = %d\n", lcore_id);
	return lcore_id;
}

static void process_rx(struct rte_bbdev_op_data *in_buf)
{
	/*
	 * Ignore empty messages. These may happen on modem reset if
	 * new producer/consumer indexes don't match the old ones
	 */
	if (!in_buf->length) {
		app_print_dbg("Received empty message, possibly reset artifact\n");
		return;
	}

	/* If truncated message, show a warning then exit */
	if (in_buf->length != DFE_MSG_SIZE) {
		app_print_err("Received truncated message (%uB, expect %luB)\n",
			  in_buf->length, DFE_MSG_SIZE);
		return;
	}

	disarm_cmd_timer();

	hexdump(in_buf->mem, in_buf->length);

	/* implement this in your application */
	process_msg_from_modem(in_buf);
}

/* ipc thread - can be modified as needed */
static int ipc_poll_loop(__attribute__((unused)) void *dummy)
{
	struct rte_bbdev_raw_op *raw_ops_deq = NULL;
	int qid = BBDEV_IPC_M2H_QUEUE;
	int ret;

	app_print_dbg("%s: hello from core %u\n", __func__, rte_lcore_id());

	while (!rte_atomic16_read(&state.do_poll));
	app_print_dbg("%s: hello again from core %u\n", __func__, rte_lcore_id());
	while (rte_atomic16_read(&state.do_poll)) {
		do {
			rte_delay_us_sleep(1);
			if (state.reset_in_progress)
				continue;
			if (!rte_atomic16_read(&state.do_poll))
				return 0;
			raw_ops_deq = rte_bbdev_dequeue_raw_op(dev_id, qid);
		} while (!raw_ops_deq);

		/* this is where the message is processed */
		process_rx(&raw_ops_deq->input);

		/* Don't consume stale dequeue op if modem was reset */
		if (state.reset_via_timeout) {
			state.reset_via_timeout = 0;
			continue;
		}
		ret = rte_bbdev_consume_raw_op(dev_id, qid, raw_ops_deq);
		if (ret < 0)
			app_print_err("rte_bbdev_consume_raw_op failed (%d)\n", ret);
	}

	return 0;
}

/* tti thread - can be modified as needed */
static int tti_poll_loop(__attribute__((unused)) void *dummy)
{
	int ret = 0;

	/* init TTI here */
	tti_init();

	while (!rte_atomic16_read(&state.do_tti_poll));

	app_print_dbg("%s: hello from core %u\n", __func__, rte_lcore_id());

	while (rte_atomic16_read(&state.do_tti_poll)) {
		ret = tti_wait();
		if (ret != 0) {
			app_print_err("%s: TTI wait retcode %d core %u\n", __func__, ret, rte_lcore_id());
			break;
		}
		tti_irq_count++;
	}

	tti_close();

	return 0;
}

static int launch_thread(unsigned int *lcore, lcore_function_t *f, const char *name)
{
	unsigned int lcore_id;
	int ret;

	lcore_id = get_first_free_lcore();
	if (lcore_id == RTE_MAX_LCORE) {
		app_print_err("No lcore available for %s thread\n", name);
		return -EINVAL;
	}

	ret = rte_eal_remote_launch(f, NULL, lcore_id);
	if (ret < 0) {
		app_print_err("Failed to start %s thread on core %d\n",
			      name, rte_lcore_index(lcore_id));
		return ret;
	}
	app_print_dbg("Started %s thread on core %d\n", name,
		      rte_lcore_index(lcore_id));

	*lcore = lcore_id;
	return 0;
}

static int start_secondary_threads(void)
{
	int ret;

	/* IPC polling thread */
	ret = launch_thread(&state.ipc_lcore, ipc_poll_loop, "IPC polling");
	if (ret < 0)
		return ret;

	return 0;
}

int start_tti_thread(void)
{
	int ret = 0;

	/* TTI polling thread */
	ret = launch_thread(&state.tti_lcore, tti_poll_loop, "TTI polling");
	if (ret < 0)
		return ret;

	rte_atomic16_set(&state.do_tti_poll, 1);

	return 0;
}

int stop_tti_thread(void)
{
	/* signal TTI thread to end graciously */
	rte_atomic16_set(&state.do_tti_poll, 0);
	signal_close();

	/* wait for everything to finish */
	rte_eal_wait_lcore(state.tti_lcore);

	return 0;
}

static void stop_secondary_threads(void)
{
	rte_atomic16_set(&state.do_poll, 0);

	/* Wait for any ongoing processing to end */
	rte_eal_wait_lcore(state.ipc_lcore);

	stop_tti_thread();
}

int init_bbdev(void)
{
	const struct rte_bbdev_op_cap *op_cap;

	struct rte_bbdev_info info;
	int i, ret;

	/* Check if BBDEV device is present */
	if (!rte_bbdev_count()) {
		app_print_err("No BBDEV device detected\n");
		return -ENODEV;
	}

	ret = rte_bbdev_info_get(0, &info);
	if (ret < 0) {
		app_print_err("rte_bbdev_info_get failed, ret: %d\n", ret);
		return ret;
	}

	/* Get maximum buffer size */
	op_cap = info.drv.capabilities;
	for (i = 0; op_cap->type != RTE_BBDEV_OP_NONE; ++i, ++op_cap) {
		if (op_cap->type == RTE_BBDEV_OP_RAW &&
		    (op_cap->cap.raw.capability_flags &
		     RTE_BBDEV_RAW_CAP_INTERNAL_MEM))
			raw_buf_size =
				op_cap->cap.raw.max_internal_buffer_size;
	}

	if (raw_buf_size < DFE_MSG_SIZE) {
		app_print_err("BBDEV IPC buffers too small (%u), need %lu bytes\n",
		       raw_buf_size, DFE_MSG_SIZE);
		ret = -EINVAL;
		return ret;
	}

	/* setup device */
	ret = rte_bbdev_setup_queues(dev_id, BBDEV_QUEUE_COUNT, info.socket_id);
	if (ret < 0) {
		app_print_err("rte_bbdev_setup_queues failed, ret %d\n", ret);
		return ret;
	}

	/* Host to modem queue */
	ret = setup_raw_queue(&info, BBDEV_IPC_H2M_QUEUE,
			      RTE_BBDEV_DIR_HOST_TO_MODEM);
	if (ret != 0) {
		app_print_err("Failure configuring queue %d on dev%u\n",
			  BBDEV_IPC_H2M_QUEUE, dev_id);
		return ret;
	}

	/* Modem to host queue */
	ret = setup_raw_queue(&info, BBDEV_IPC_M2H_QUEUE,
			      RTE_BBDEV_DIR_MODEM_TO_HOST);
	if (ret != 0) {
		app_print_err("Failure allocating queue %d on dev%u\n",
			  BBDEV_IPC_M2H_QUEUE, dev_id);
		return ret;
	}

	/* Start bbdev */
	app_print_info("Preparing for BBDEV handshake\n");
	ret = rte_bbdev_start(dev_id);
	if (ret < 0) {
		app_print_err("rte_bbdev_start failed (%d)\n", ret);
		return ret;
	}
	app_print_info("BBDEV initialized\n");

	return 0;
}

int send_msg(void *msg, uint32_t len)
{
	struct rte_bbdev_raw_op *raw_ops_enq[1] = {NULL};
	uint32_t qid = BBDEV_IPC_H2M_QUEUE;
	int retries = ENQUEUE_RETRIES;
	int ret = 0;

	if (state.reset_in_progress)
		return -EBUSY;

	ret = rte_mempool_get_bulk(mp[qid], (void **)raw_ops_enq, 1);
	if (ret < 0) {
		app_print_err("rte_mempool_get_bulk failed (%d)\n", ret);
		return ret;
	}

	raw_ops_enq[0]->input.is_direct_mem = 1;
	raw_ops_enq[0]->input.length = len;
	raw_ops_enq[0]->input.mem = msg;
	raw_ops_enq[0]->output.mem = NULL;
	raw_ops_enq[0]->output.length = 0;

	app_print_dbg("preparing to send msg: buf = %p, len = %d\n",
		      raw_ops_enq[0]->input.mem, raw_ops_enq[0]->input.length);
	hexdump(raw_ops_enq[0]->input.mem, len);

	while (retries--) {
		ret = rte_bbdev_enqueue_raw_op(dev_id, qid, raw_ops_enq[0]);
		if (ret == 0)
			break;
		if (ret == -EBUSY)
			continue;
	}
	if (ret < 0)
		app_print_err("rte_bbdev_enqueue_raw_op failed (%d)\n", ret);

	rte_mempool_put_bulk(mp[qid], (void **)raw_ops_enq, 1);

	return ret;
}

int dfe_init(void)
{
	int ret;

	memset(&state, 0, sizeof(state));
	if (rte_atomic16_test_and_set(&state.initialized) == 0) {
		app_print_err("Internals already initialized!\n");
		return -EINVAL;
	}

	ret = create_cmd_timer();
	if (ret < 0)
		goto out_free_timer;

	/* initialize IPC */
	ret = init_bbdev();
	if (ret < 0)
		goto out_free_timer;

	/* Start the secondary routines; assume enough cores available */
	ret = start_secondary_threads();
	if (ret < 0)
		goto out_close_bbdev;

	/* give "go" command to threads */
	rte_atomic16_set(&state.do_poll, 1);

	app_print_info("DFE lib initialized\n");

	return 0;

out_close_bbdev:
	rte_bbdev_close(dev_id);

out_free_timer:
	delete_cmd_timer();

	return ret;
}

void dfe_free(void)
{
	stop_secondary_threads();

	/* implement this in your application */
	signal_ipc_reset();

	/* wait for everything to finish */
	sleep(1);

	/* close bbdev */
	rte_bbdev_close(dev_id);

	/* stop any command timer */
	delete_cmd_timer();
	rte_atomic16_clear(&state.initialized);

	rte_eal_cleanup();
	app_print_info("DFE resources are being freed...\n");
}

/* TODO: implement below APIs in your application*/
__attribute__((weak))
void signal_ipc_reset(void)
{
	/* please add a message in your protocol for reseting the IPC */
}

__attribute__((weak))
void process_msg_from_modem(struct rte_bbdev_op_data *in_buf)
{
	UNUSED(in_buf);
	/* different actions for different message types */
}
