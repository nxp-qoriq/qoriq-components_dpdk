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
#include <dev_driver.h>
#include <ethdev_driver.h>

#include <bus_fslmc_driver.h>
#include <mc/fsl_dpcon.h>
#include <portal/dpaa2_hw_pvt.h>
#include <dpaa2_hw_dpio.h>
#include <compat.h>
#include "dpaa2_ethdev.h"
#include "dpaa2_pmd_logs.h"
#include "rte_pmd_dpaa2.h"

__rte_experimental
void *
rte_dpaa2_scheduler_init(void)
{
	struct dpaa2_dpcon_dev *dpcon_dev;
	void *scheduler_handle;

	dpcon_dev = dpaa2_alloc_dpcon_dev();
	if (!dpcon_dev)
		DPAA2_PMD_ERR("Failed dpaa2_alloc_dpcon_dev!!");

	scheduler_handle = (void *)dpcon_dev;
	return scheduler_handle;
}

__rte_experimental
int
rte_dpaa2_scheduler_start(void *scheduler_handle)
{
	uint32_t ret;
	struct dpaa2_dpcon_dev *dpcon_dev =
				(struct dpaa2_dpcon_dev *)scheduler_handle;

	ret = dpaa2_dpcon_start(dpcon_dev);
	if (ret) {
		DPAA2_PMD_ERR("Failed Conc - dpaa2_dev_start\n");
		return -1;
	}
	return 0;
}

__rte_experimental
int
rte_dpaa2_conf_scheduler(uint16_t port_id, uint16_t rx_queue_id,
			 int policer_unit, uint32_t options, int default_color,
			 uint32_t cir, uint32_t cbs, uint32_t pir, uint32_t pbs)
{
	struct rte_eth_dev *dev;
	dev = &rte_eth_devices[port_id];
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	struct dpni_rx_tc_policing_cfg policing_cfg;
	struct dpaa2_queue *dpaa2_q;
	int ret;

	dpaa2_q = priv->rx_vq[rx_queue_id];
	policing_cfg.mode = DPNI_POLICER_MODE_RFC_2698;
	policing_cfg.options = options;
	policing_cfg.units = policer_unit;
	policing_cfg.default_color = default_color;
	policing_cfg.cir = cir;
	policing_cfg.cbs = cbs;
	policing_cfg.eir = pir;
	policing_cfg.ebs = pbs;

	ret = dpni_set_rx_tc_policing(dpni, CMD_PRI_LOW, priv->token,
				      dpaa2_q->tc_index, &policing_cfg);
	if (ret) {
		DPAA2_PMD_ERR("Error in setting policy rule: = %d", ret);
		return ret;
	}

	return 0;
}

__rte_experimental
int
rte_dpaa2_scheduler_destroy(void *scheduler_handle)
{
	struct dpaa2_dpcon_dev *dpcon_dev =
				(struct dpaa2_dpcon_dev *)scheduler_handle;
	int32_t ret;

	ret = dpaa2_dpcon_stop(dpcon_dev);
	if (ret) {
		DPAA2_PMD_ERR("Failed Conc - rte_dpaa2_schedule_destroy\n");
		return -1;
	}
	dpcon_dev = NULL;

	return 0;
}

__rte_experimental
int32_t
rte_dpaa2_scheduler_rx(void *scheduler_handle, struct rte_mbuf **mbuf,
		       uint16_t nb_pkts)
{
	struct dpaa2_dpcon_dev *dpcon_dev =
				(struct dpaa2_dpcon_dev *)scheduler_handle;
	int ret = 0;
	ret = dpaa2_dpcon_recv(dpcon_dev, mbuf, nb_pkts);
	if (ret > 0)
		return ret;
	return 0;
}
