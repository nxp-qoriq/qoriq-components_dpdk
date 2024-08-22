/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2024 NXP
 */

#ifndef _PMD_LA12XX_H_
#define _PMD_LA12XX_H_

#include "la93xx_bbdev_ipc.h"

__rte_experimental
mem_range_t *rte_pmd_la93xx_get_nlm_mem(uint16_t dev_id);

/**
 * Reset (reboot to default state) LA93xx device.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   0 - Success, otherwise Failure
 */
__rte_experimental
int
rte_pmd_la93xx_reset(uint16_t dev_id);

/**
 * Reset (reboot) LA93xx device and restore the configuration.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   0 - Success, otherwise Failure
 */
__rte_experimental
int
rte_pmd_la93xx_reset_restore_cfg(uint16_t dev_id);

/**
 * Get the value of PPS_OUT counter from LA9310 PHY TIMER
 *
 * @param dev_id   The identifier of the device.
 *
 * @return PPS_OUT counter value
 */
__rte_experimental
uint32_t rte_pmd_get_pps_out_count(uint16_t dev_id);
#endif
