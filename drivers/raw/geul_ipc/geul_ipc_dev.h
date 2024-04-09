/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

#ifndef __GUEL_IPCDEV_H__
#define __GUEL_IPCDEV_H__

#include <rte_rawdev.h>

extern int geulipc_pmd_logtype;

#define GEULIPC_PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, geulipc_pmd_logtype, "%s(): " fmt "\n", \
		__func__, ##args)

#define GEULIPC_PMD_FUNC_TRACE() GEULIPC_PMD_LOG(DEBUG, ">>")

#define GEULIPC_PMD_DEBUG(fmt, args...) \
	GEULIPC_PMD_LOG(DEBUG, fmt, ## args)
#define GEULIPC_PMD_INFO(fmt, args...) \
	GEULIPC_PMD_LOG(INFO, fmt, ## args)
#define GEULIPC_PMD_ERR(fmt, args...) \
	GEULIPC_PMD_LOG(ERR, fmt, ## args)
#define GEULIPC_PMD_WARN(fmt, args...) \
	GEULIPC_PMD_LOG(WARNING, fmt, ## args)

#define GEULIPC_DEVICE_ID 0x0

struct geulipc_rawdev {
	uint16_t device_id;
	ipc_t instance_handle;
	struct rte_device *device;
};

static inline struct geulipc_rawdev *
geulipc_rawdev_get_priv(const struct rte_rawdev *rawdev)
{
	return rawdev->dev_private;
}

#endif /* __GUEL_IPCDEV_H__ */
