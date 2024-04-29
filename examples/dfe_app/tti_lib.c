/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <la9310_modinfo.h>
#include <la9310_tti_ioctl.h>

struct la9310_ccsr_info *ccsr_info[MAX_MODEM] = {NULL};
void *addr[MAX_MODEM] = {NULL};
static int tti_fd[MAX_MODEM];

static inline int open_devtti(__attribute__((unused)) struct tti *tti_t, int modem_id)
{
	char tti_dev_name[50];
	int devtti;

	sprintf(tti_dev_name, "/dev/%s%s%d",
		LA9310_DEV_NAME_PREFIX, LA9310_TTI_DEVNAME_PREFIX, modem_id);

	printf("Trying to open device : %s\n", tti_dev_name);
	devtti = open(tti_dev_name, O_RDWR);
	if (devtti < 0) {
		printf("Error(%d): Cannot open %s\n", devtti, tti_dev_name);
		return devtti;
	}
	return devtti;
}

int modem_tti_register(struct tti *tti_t, int modem_id, int tti_event_flag)
{
	int32_t ret = 0;

	/* Register TTI */
	tti_t->dev_tti_handle = open_devtti(tti_t, modem_id);
	if (tti_t->dev_tti_handle < 0) {
		printf("Unable to open device.\n");
		ret = -2;
		goto err;
	}

	if (tti_event_flag) {
		tti_t->tti_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (tti_t->tti_eventfd < 0) {
			printf("Failed to create eventfd\n");
			close(tti_t->dev_tti_handle);
			ret = tti_t->tti_eventfd;
			goto err;
		}
	}

	/* IOCTL - register FD with kernel */
	ret = ioctl(tti_t->dev_tti_handle, IOCTL_LA9310_MODEM_TTI_REGISTER, tti_t);
	if (ret < 0) {
		printf("IOCTL_LA9310_MODEM_TTI_REGISTER failed.\n");
		close(tti_t->dev_tti_handle);
		goto err;
	}
err:
	return ret;
}
void *get_ccsr_addr(int modem_id)
{
	if (addr[modem_id] != NULL)
		return addr[modem_id];

	char dev_name[32];
	int fd, ret;
	modinfo_t mil = {0};
	modinfo_t *mi = &mil;

	sprintf(dev_name, "/dev/la9310%d", modem_id);
	fd = open(dev_name, O_RDONLY);
	if (-1 == fd) {
		perror("dev open failed:");
		return NULL;
	}
	ret = ioctl(fd, IOCTL_LA93XX_MODINFO_GET, (modinfo_t *) &mil);
	if (ret < 0) {
		printf("IOCTL_LA93XX_MODINFO_GET failed.\n");
		close(fd);
		return NULL;
	}
	if (ccsr_info[modem_id] == NULL)
		ccsr_info[modem_id] =
			(struct la9310_ccsr_info *)
			malloc(sizeof(struct la9310_ccsr_info));

	ccsr_info[modem_id]->offset = mi->ccsr.host_phy_addr;
	ccsr_info[modem_id]->size = mi->ccsr.size;
	close(fd);

	tti_fd[modem_id] = open("/dev/mem", O_RDWR);
	if (-1 == tti_fd[modem_id]) {
		perror("dev open failed:");
		return NULL;
	}
	addr[modem_id] = mmap(NULL, ccsr_info[modem_id]->size,
			PROT_READ | PROT_WRITE, MAP_SHARED,
			tti_fd[modem_id], ccsr_info[modem_id]->offset);
	if (addr == MAP_FAILED) {
		perror("mmap failed:");
		close(tti_fd[modem_id]);
		return NULL;
	}
	return addr[modem_id];
}

static inline int close_devtti(int dev_tti_handle)
{
	return close(dev_tti_handle);
}

int modem_tti_deregister(struct tti *tti_t)
{
	int32_t ret = 0;

	/* Free IRQs */
	ret = ioctl(tti_t->dev_tti_handle, IOCTL_LA9310_MODEM_TTI_DEREGISTER,
			tti_t);
	if (ret < 0) {
		printf("IOCTL_LA9310_MODEM_TTI_DEREGISTER failed.\n");
		goto err;
	}

	if (!(tti_t->tti_eventfd < 0)) {
		close(tti_t->tti_eventfd);
		tti_t->tti_eventfd = -1;
	}

	/* Close Dev TTI File */
	ret = close_devtti(tti_t->dev_tti_handle);
	if (ret < 0) {
		printf("Error closing TTI device.\n");
		goto err;
	}
err:
	return ret;
}
