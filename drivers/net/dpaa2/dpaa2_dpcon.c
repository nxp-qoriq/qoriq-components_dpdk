/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_mbuf.h>
#include <dev_driver.h>
#include <rte_hexdump.h>
#include <dev_driver.h>
#include <ethdev_driver.h>
#include <compat.h>

#include <bus_fslmc_driver.h>
#include <mc/fsl_dpcon.h>
#include <portal/dpaa2_hw_pvt.h>
#include <dpaa2_hw_dpio.h>
#include "dpaa2_ethdev.h"
#include "dpaa2_pmd_logs.h"

TAILQ_HEAD(dpcon_dev_list, dpaa2_dpcon_dev);
static struct dpcon_dev_list dpcon_dev_list =
		TAILQ_HEAD_INITIALIZER(dpcon_dev_list); /*!< DPCON device list */


/* Create storage for dpcon entries per lcore */
static struct qbman_result *dq_storage[RTE_MAX_LCORE];

static
int rte_dpaa2_schedule_storage_info_init(void)
{
	int i;

	/* TODO: Replace RTE_MAX_LCORE with mask lcore value */
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		dq_storage[i] = (struct qbman_result *)rte_zmalloc(NULL,
				sizeof(struct qbman_result) * DPAA2_LX2_DQRR_RING_SIZE,
				RTE_CACHE_LINE_SIZE);
		if (!dq_storage[i])
			goto err;
	}
	return 0;
err:
	while (--i >= 0) {
		rte_free(dq_storage[i]);
		dq_storage[i] = NULL;
	}
	return -1;
}

int32_t
dpaa2_dpcon_start(struct dpaa2_dpcon_dev *dpcon_dev)
{
	int32_t ret;

	ret = dpcon_enable(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
	if (ret != 0) {
		DPAA2_PMD_ERR("DPCONC is not enabled at MC: Error code = %0x\n",
			      ret);
		return -1;
	}

	return 0;
}

int32_t
dpaa2_dpcon_stop(struct dpaa2_dpcon_dev *dpcon_dev)
{
	int32_t ret;

	ret = dpcon_disable(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
	if (ret != 0) {
		DPAA2_PMD_ERR("Device cannot be disabled:Error Code = %0x\n", ret);
		return -1;
	}

	return 0;
}

static inline void
dpaa2_qbman_pull_desc_channel_set(struct qbman_pull_desc *pulldesc,
				  uint32_t num, uint16_t ch_id,
				  struct qbman_result *dq_sch_storage)
{
	qbman_pull_desc_clear(pulldesc);
	qbman_pull_desc_set_numframes(pulldesc, num);
	qbman_pull_desc_set_channel(pulldesc, ch_id,
				    qbman_pull_type_active_noics);
	qbman_pull_desc_set_storage(pulldesc, dq_sch_storage,
				    (dma_addr_t)(DPAA2_VADDR_TO_IOVA(dq_sch_storage)),
				    1);
}

int
dpaa2_dpcon_recv(struct dpaa2_dpcon_dev *dpcon_dev,
		 struct rte_mbuf **mbuf,
		 uint16_t nb_pkts)
{
	struct qbman_swp *swp;
	struct qbman_result *dq_sch_storage;
	uint16_t ch_id = dpcon_dev->qbman_ch_id;
	int ret, qbman_try_again = 0, rcvd_pkts = 0;
	uint8_t is_last = 0, status;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct dpaa2_queue *rvq;

	if (unlikely(!DPAA2_PER_LCORE_ETHRX_DPIO)) {
		ret = dpaa2_affine_qbman_ethrx_swp();
		if (ret) {
			DPAA2_PMD_ERR("Failure in affining portal");
			return 0;
		}
	}

	swp = DPAA2_PER_LCORE_ETHRX_PORTAL;
	dq_sch_storage = dq_storage[rte_lcore_id()];

	dpaa2_qbman_pull_desc_channel_set(&pulldesc, nb_pkts, ch_id, dq_sch_storage);

try_again:
	ret = qbman_swp_pull(swp, &pulldesc);
	if (unlikely(ret < 0)) {
		if (ret == -EBUSY) {
			DPAA2_PMD_INFO("VDQ command is not issued. QBMAN is busy\n");
			qbman_try_again++;
			if (qbman_try_again > 50)
				return -1;
		} else {
			DPAA2_PMD_ERR("VDQ command is not issued. Err Code = %0x\n",
				ret);
			return -1;
		}
		goto try_again;
	}

	/* Receive the packets till Last Dequeue entry is found with
	 * respect to the above issues PULL command.
	 */
	while (!is_last) {
		/* Loop until the dq_storage is updated with
		 * new result by QBMAN
		 */
		while (!qbman_result_has_new_result(swp, dq_sch_storage))
			;

		/* Check whether Last Pull command is Expired and
		 * setting Condition for Loop termination
		 */
		if (qbman_result_DQ_is_pull_complete(dq_sch_storage)) {
			is_last = 1;
			/* Check for valid frame. */
			status = (uint8_t)qbman_result_DQ_flags(dq_sch_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
				DPAA2_PMD_DP_DEBUG("No frame is delivered\n");
				continue;
			}
		}

		fd = qbman_result_DQ_fd(dq_sch_storage);
		rvq = (struct dpaa2_queue *)(size_t)qbman_result_DQ_fqd_ctx(dq_sch_storage);
		if (rvq) {
			mbuf[rcvd_pkts] = eth_fd_to_mbuf(fd, rvq->eth_data->port_id);
		} else {
			DPAA2_PMD_WARN("Null Return VQ received\n");
			dq_sch_storage++;
			continue;
		}
		if (mbuf[rcvd_pkts])
			rcvd_pkts++;
		dq_sch_storage++;
	} /* End of Packet Rx loop */

	DPAA2_PMD_DP_DEBUG("DPCONC Received %d Packets\n", rcvd_pkts);

	return rcvd_pkts;
}

static int
dpaa2_create_dpcon_device(int dev_fd __rte_unused,
	struct vfio_device_info *obj_info __rte_unused,
	struct rte_dpaa2_device *obj)
{
	struct dpaa2_dpcon_dev *dpcon_dev;
	struct dpcon_attr attr;
	int ret, dpcon_id = obj->object_id;

	/* Allocate DPAA2 dpcon handle */
	dpcon_dev = rte_malloc(NULL, sizeof(struct dpaa2_dpcon_dev), 0);
	if (!dpcon_dev) {
		DPAA2_PMD_ERR("Memory allocation failed for dpcon device");
		return -1;
	}

	/* Open the dpcon object via MC and save handle for further use */
	dpcon_dev->dpcon.regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	ret = dpcon_open(&dpcon_dev->dpcon,
			CMD_PRI_LOW, dpcon_id, &dpcon_dev->token);
	if (ret) {
		DPAA2_PMD_ERR("Unable to open dpcon device: err(%d)",
		ret);
		rte_free(dpcon_dev);
		return -1;
	}

	/* Get the resource information i.e. Channel ID, dpconc ID, priority*/
	ret = dpcon_get_attributes(&dpcon_dev->dpcon,
	CMD_PRI_LOW, dpcon_dev->token, &attr);
	if (ret != 0) {
		DPAA2_PMD_ERR("dpcon attribute fetch failed: err(%d)", ret);
		rte_free(dpcon_dev);
		goto get_attr_failure;
	}

	/* Updating device specific private information*/
	dpcon_dev->dpcon_id = dpcon_id;
	dpcon_dev->qbman_ch_id = attr.qbman_ch_id;
	dpcon_dev->num_priorities = attr.num_priorities;
	DPAA2_PMD_DEBUG("Channel ID = %d\t Priority Num = %d Object ID = %d",
			dpcon_dev->qbman_ch_id, dpcon_dev->num_priorities,
			dpcon_dev->dpcon_id);

	ret = rte_dpaa2_schedule_storage_info_init();
	if (ret < 0)
		printf("rte_dpaa2_schedule_storage_info_init: err(%d)", ret);

	rte_atomic16_init(&dpcon_dev->in_use);
	TAILQ_INSERT_TAIL(&dpcon_dev_list, dpcon_dev, next);
	return 0;

get_attr_failure:
	dpcon_close(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
	return -1;
}

struct dpaa2_dpcon_dev *dpaa2_alloc_dpcon_dev(void)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;

	/* Get DPCON dev handle from list using index */
	TAILQ_FOREACH(dpcon_dev, &dpcon_dev_list, next) {
		if (dpcon_dev && rte_atomic16_test_and_set(&dpcon_dev->in_use))
			break;
	}

	return dpcon_dev;
}

void
dpaa2_free_dpcon_dev(struct dpaa2_dpcon_dev *dpcon)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;

	/* Match DPCON handle and mark it free */
	TAILQ_FOREACH(dpcon_dev, &dpcon_dev_list, next) {
		if (dpcon_dev == dpcon) {
			rte_atomic16_dec(&dpcon_dev->in_use);
			return;
		}
	}
}

static struct dpaa2_dpcon_dev
*get_dpcon_from_id(uint32_t dpcon_id)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;

	/* Get DPCONC dev handle from list using index */
	TAILQ_FOREACH(dpcon_dev, &dpcon_dev_list, next) {
		if (dpcon_dev->dpcon_id == dpcon_id)
			break;
	}

	return dpcon_dev;
}

static void
dpaa2_close_dpcon_device(int object_id)
{
	struct dpaa2_dpcon_dev *dpcon_dev = NULL;
	int32_t ret;

	dpcon_dev = get_dpcon_from_id((uint32_t)object_id);
	if (dpcon_dev) {
		/*Reset the device to it's default state*/
		ret = dpcon_reset(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
		if (ret != 0)
			DPAA2_PMD_ERR("Error in resetting  the device: err(%d)", ret);

		dpaa2_free_dpcon_dev(dpcon_dev);
		dpcon_close(&dpcon_dev->dpcon, CMD_PRI_LOW, dpcon_dev->token);
		if (ret != 0)
			DPAA2_PMD_ERR("Error in closing the device: err(%d)", ret);
		TAILQ_REMOVE(&dpcon_dev_list, dpcon_dev, next);
		rte_free(dpcon_dev);
	}
}

static struct rte_dpaa2_object rte_dpaa2_dpcon_obj = {
	.dev_type = DPAA2_CON,
	.create = dpaa2_create_dpcon_device,
	.close = dpaa2_close_dpcon_device,
};

RTE_PMD_REGISTER_DPAA2_OBJECT(dpaa2_dpcon, rte_dpaa2_dpcon_obj);
