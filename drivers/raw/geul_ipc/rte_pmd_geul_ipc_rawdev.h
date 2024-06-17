/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

#ifndef __RTE_PMD_GEUL_IPC_RAWDEV_H__
#define __RTE_PMD_GEUL_IPC_RAWDEV_H__

/**
 * @file
 *
 * GEUL IPC Driver exposed APIs
 * These APIs are to be used by the application layer for
 * IPC functions/features.
 *
 */
#include <gul_host_if.h>

#define GEUL_IPC_RAWDEV_NAME_PREFIX "geul_ipc_dev"

#define POISON 0x12345678 /* Fills all bytes of a word */

typedef struct geulipc_channel {
#define CHANNEL_NAME_LEN 32
	char name[CHANNEL_NAME_LEN];
	uint8_t en_napi; /* 0: napi disabled, 1: napi enabled */
	uint16_t depth;	/**< Depth of the channel, for PTR channel case */
	uint32_t channel_id;	/**< Channel ID */
	int32_t eventfd;	/**< Event FD value */
	enum ipc_ch_type type;  /**< Channel type */
	struct rte_mempool *mp; /**< Pool from where buffers would be cut */
} geulipc_channel_t;

/* Configuration structure for Geul Device */
typedef struct geulipc_rawdev_config {
	uint32_t device_id;
	ipc_t instance_handle;
} geulipc_rawdev_config_t;

#endif /* __RTE_PMD_GEUL_IPC_RAWDEV_H__*/
