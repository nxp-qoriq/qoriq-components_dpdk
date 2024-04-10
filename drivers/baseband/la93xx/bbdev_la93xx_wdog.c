/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <rte_log.h>
#include "la9310_host_if.h"
#include "bbdev_la93xx_wdog.h"
#include "bbdev_la93xx_pmd_logs.h"

static inline int open_devwdog(int modem_id)
{
	char wdog_dev_name[50];
	int devwdog;

	sprintf(wdog_dev_name, "/dev/%s%s%d",
		 LA9310_DEV_NAME_PREFIX, LA9310_WDOG_DEVNAME_PREFIX, modem_id);
	BBDEV_LA93XX_PMD_INFO("%s:Trying to open device : %s",
			      __func__, wdog_dev_name);
	devwdog = open(wdog_dev_name, O_RDWR);
	if (devwdog < 0) {
		BBDEV_LA93XX_PMD_ERR("Error(%d): Cannot open %s",
				     devwdog, wdog_dev_name);
		return devwdog;
	}
	return devwdog;
}

int la93xx_wdog_open(struct wdog *wdog_t, int modem_id)
{
	int32_t ret = MODEM_WDOG_OK;

	wdog_t->wdogid = modem_id;
	/* Register Watchdog */
	wdog_t->dev_wdog_handle = open_devwdog(modem_id);
	if (wdog_t->dev_wdog_handle < 0) {
		BBDEV_LA93XX_PMD_ERR("Unable to open Watchdog device.");
		ret = -MODEM_WDOG_OPEN_FAIL;
		goto err;
	}
	wdog_t->wdog_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

	if (wdog_t->wdog_eventfd < 0)
		BBDEV_LA93XX_PMD_WARN("Failed to create wdog eventfd.");
err:
	return ret;
}

int la93xx_wdog_register(struct wdog *wdog_t)
{
	int32_t ret = MODEM_WDOG_OK;
	/* IOCTL - register FD with kernel */
	ret = ioctl(wdog_t->dev_wdog_handle,
			IOCTL_LA9310_MODEM_WDOG_REGISTER, wdog_t);
	if (ret < 0)
		BBDEV_LA93XX_PMD_ERR("IOCTL_LA9310_MODEM_WDOG_REGISTER failed");
	return ret;
}

static inline int close_devwdog(int dev_wdog_handle)
{
	return close(dev_wdog_handle);
}

static int get_pci_domain_nr(struct wdog *wdog_t)
{
	int32_t ret = MODEM_WDOG_OK;
	/* get pci slot (domain_nr) */
	ret = ioctl(wdog_t->dev_wdog_handle,
			IOCTL_LA9310_MODEM_WDOG_GET_DOMAIN, wdog_t);
	if (ret < 0)
		BBDEV_LA93XX_PMD_ERR("IOCTL_LA9310_MODEM_WDOG_GET_DOMAIN failed");
	return ret;
}

int la93xx_wdog_deregister(struct wdog *wdog_t)
{
	int32_t ret = MODEM_WDOG_OK;
	/* Free IRQs */
	ret = ioctl(wdog_t->dev_wdog_handle,
			IOCTL_LA9310_MODEM_WDOG_DEREGISTER, wdog_t);
	if (ret < 0)
		BBDEV_LA93XX_PMD_ERR("IOCTL_LA9310_MODEM_WDOG_DEREGISTER failed");
	return ret;
}

int la93xx_wdog_close(struct wdog *wdog_t)
{

	/* Close event fd */
	if (wdog_t->wdog_eventfd >= 0) {
		close(wdog_t->wdog_eventfd);
		wdog_t->wdog_eventfd = -1;
	}

	return close_devwdog(wdog_t->dev_wdog_handle);
}

int la93xx_wdog_readwait(int dev_wdog_handle, void *buf, int count)
{
	int32_t ret = MODEM_WDOG_OK;
	ret = read(dev_wdog_handle, buf, count);
	if (ret < 0) {
			BBDEV_LA93XX_PMD_ERR("wdog read failed.");
		goto err;
	}
err:
	return ret;
}

static int la93xx_wdog_reset_modem(struct wdog *wdog_t)
{
	int32_t ret = MODEM_WDOG_OK;
	/* Call IOCTL for Watchdog Reset Modem */
	ret = ioctl(wdog_t->dev_wdog_handle,
			IOCTL_LA9310_MODEM_WDOG_RESET, wdog_t);
	if (ret < 0)
		BBDEV_LA93XX_PMD_ERR("IOCTL_LA9310_MODEM_WDOG_RESET failed");
	return ret;
}

int la93xx_wdog_get_modem_status(struct wdog *wdog_t)
{
	int32_t ret = MODEM_WDOG_OK;

	ret = ioctl(wdog_t->dev_wdog_handle,
			IOCTL_LA9310_MODEM_WDOG_GET_STATUS,
			wdog_t);
	if (ret < 0)
		BBDEV_LA93XX_PMD_ERR("IOCTL_LA9310_MODEM_WDOG_GET_STATUS failed");
	return ret;
}

static int la93xx_wdog_remove_modem(struct wdog *wdog_t)
{
	int fd;
	char sys_name[128] = {'\0'};
	char value = '1';
	int ret = MODEM_WDOG_OK;

	ret = get_pci_domain_nr(wdog_t);
	if (ret < 0)
		goto err;

	if (wdog_t->domain_nr < 0)
		goto err;

	snprintf(sys_name, sizeof(sys_name), "%s/%04x:00:00.0/remove",
					MODEM_PCI_DEVICE_PATH,
					wdog_t->domain_nr);
	fd = open(sys_name, O_WRONLY);
	if (fd < 0) {
		ret = -MODEM_WDOG_OPEN_FAIL;
		goto err;
	}
	ret = write(fd, &value, 1);
	if (ret < 0) {
		close(fd);
		goto err;
	}
	close(fd);
err:
	return ret;
}

static int la93xx_wdog_rescan_modem(void)
{
	int fd;
	char value = '1';
	int ret = MODEM_WDOG_OK;

	fd = open(MODEM_PCI_RESCAN_FILE, O_WRONLY);
	if (fd < 0) {
		ret = -MODEM_WDOG_OPEN_FAIL;
		goto err;
	}

	ret = write(fd, &value, 1);
	if (ret <= 0) {
		close(fd);
		ret = -MODEM_WDOG_WRITE_FAIL;
		goto err;
	}
	close(fd);
err:
	return ret;
}

static int la93xx_wdog_rescan_modem_blocking(struct wdog *wdog_t, uint32_t timeout)
{
	int ret = MODEM_WDOG_OK;

	if (timeout > 0) {
		while (timeout--) {
			BBDEV_LA93XX_PMD_INFO("Scanning %d", timeout);
			/* rescan pci */
			ret = la93xx_wdog_rescan_modem();
			if (ret < 0)
				goto err;

			/* check if modem already in ready state */
			ret = la93xx_wdog_get_modem_status(wdog_t);
			if (ret < 0)
				goto err;
			if (wdog_t->wdog_modem_status == WDOG_MODEM_READY)
				break;
			sleep(1);
		}
	} else {
		/* rescan pci */
		ret = la93xx_wdog_rescan_modem();
		if (ret < 0)
			goto err;

		sleep(1);
		/* check if modem alreay in ready state */
		ret = la93xx_wdog_get_modem_status(wdog_t);
		if (ret < 0)
			goto err;
	}
err:
	return ret;
}

int la93xx_wdog_reinit_modem(struct wdog *wdog_t, uint32_t timeout)
{
	int ret = MODEM_WDOG_OK;

	/* Remove device from pci subsystem */
	la93xx_wdog_remove_modem(wdog_t);

	/* Give reset pulse on MODEM_HRESET */
	ret = la93xx_wdog_reset_modem(wdog_t);
	if (ret < 0) {
		BBDEV_LA93XX_PMD_ERR("Modem_wdog: modem reset failed");
		goto err;
	}
	sleep(1);
	/* Wait for modem to finish boot */
	ret = la93xx_wdog_rescan_modem_blocking(wdog_t, timeout);
	if (ret < 0) {
		BBDEV_LA93XX_PMD_ERR("Modem_wdog: modem rescan failed");
		goto err;
	}
err:
	return ret;
}
