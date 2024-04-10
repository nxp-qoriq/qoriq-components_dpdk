/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2024 NXP
 */

#ifndef __BBDEV_LA93XX_WDOG_H__
#define __BBDEV_LA93XX_WDOG_H__

#include <linux/ioctl.h>
#include "la9310_wdog_ioctl.h"
/**
 * Maximum number of watchdog instances
 */
#define MAX_WDOG_COUNT   1


int la93xx_wdog_open(struct wdog *wdog_t, int modem_id);
int la93xx_wdog_close(struct wdog *wdog_t);
int la93xx_wdog_register(struct wdog *wdog_t);
int la93xx_wdog_reinit_modem(struct wdog *wdog_t, uint32_t timeout);
int la93xx_wdog_deregister(struct wdog *wdog_t);
int la93xx_wdog_get_modem_status(struct wdog *wdog_t);
int la93xx_wdog_readwait(int dev_wdog_handle, void *buf, int count);

#endif /*__BBDEV_LA93XX_WDOG_H__*/

