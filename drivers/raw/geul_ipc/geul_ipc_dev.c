/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>

#include <bus_vdev_driver.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>
#include <gul_pci_def.h>
#include <gul_host_if.h>
#include <geul_cpe_ipc.h>
#include <geul_cpe_ipc_api.h>
#include <rte_pmd_geul_ipc_rawdev.h>
#include <geul_ipc_dev.h>

/* Dynamic log type identifier */
int geulipc_pmd_logtype;

/* Count of instances */
static uint16_t geuldev_dev_count;

#define GEULIPC_PMD_NAME geul_ipc_dev

/**
 * Configure the host channel by calling ipc_host_init
 */
static int
geulipc_rawdev_configure(const struct rte_rawdev *dev,
			 rte_rawdev_obj_t config, size_t config_size)
{
	struct geulipc_rawdev *geuldev;
	geulipc_rawdev_config_t *gc;

	GEULIPC_PMD_FUNC_TRACE();

	gc = (geulipc_rawdev_config_t *)config;

	if (config_size != sizeof(*gc)) {
		GEULIPC_PMD_ERR("Invalid size parameter to %s", __func__);
		return -EINVAL;
	}

	geuldev = geulipc_rawdev_get_priv(dev);

	geuldev->device_id = gc->device_id;
	geuldev->instance_handle = gc->instance_handle;

	GEULIPC_PMD_INFO("Configured Host for device:%d\n", gc->device_id);

	return 0;
}

static void geulipc_rawdev_info_get(struct rte_rawdev *dev,
				rte_rawdev_obj_t dev_info,
				size_t dev_info_size)
{
	struct geulipc_rawdev *geuldev;
	geulipc_rawdev_config_t *gc = (geulipc_rawdev_config_t *)dev_info;;

	GEULIPC_PMD_FUNC_TRACE();

	if (!dev_info) {
		GEULIPC_PMD_ERR("Invalid request");
		return;
	}

	if (dev_info_size != sizeof(*gc)) {
		GEULIPC_PMD_ERR("Invalid size parameter to %s", __func__);
		return -EINVAL;
	}
	geuldev = geulipc_rawdev_get_priv(dev);

	gc->instance_handle = geuldev->instance_handle;
	gc->device_id = geuldev->device_id;
}

static const struct rte_rawdev_ops geulipc_rawdev_ops = {
	.dev_info_get = geulipc_rawdev_info_get,
	.dev_configure = geulipc_rawdev_configure,
};

static int
geulipc_rawdev_create(const char *name,
		      struct rte_vdev_device *vdev,
		  int socket_id)
{
	int ret = 0;
	struct rte_rawdev *rawdev = NULL;
	struct geulipc_rawdev *geuldev = NULL;

	if (!name) {
		GEULIPC_PMD_ERR("Invalid name of the device (NULL)!");
		return -EINVAL;
	}

	/* Allocate device structure */
	rawdev = rte_rawdev_pmd_allocate(name, sizeof(struct geulipc_rawdev),
					 socket_id);
	if (rawdev == NULL) {
		GEULIPC_PMD_ERR("Unable to allocate rawdevice");
		return -EINVAL;
	}

	rawdev->dev_ops = &geulipc_rawdev_ops;
	rawdev->device = &vdev->device;

	geuldev = geulipc_rawdev_get_priv(rawdev);
	/* TODO: Only a single device is supported. If not, this needs to be
	 * extracted from the name of the device, probably: geulipc_rawdev_0
	 */
	geuldev->device_id = GEULIPC_DEVICE_ID;

	return ret;
}

static int
geulipc_rawdev_probe(struct rte_vdev_device *vdev)
{
	const char *name;
	int ret;

	name = rte_vdev_device_name(vdev);

	GEULIPC_PMD_INFO("Init %s on NUMA node %d", name, rte_socket_id());

	ret = geulipc_rawdev_create(name, vdev, rte_socket_id());
	if (ret) {
		return -1;
	}

	/* Increment the device instance count */
	geuldev_dev_count ++;

	return ret;
}

static int
geulipc_rawdev_remove(struct rte_vdev_device *vdev __rte_unused)
{
	return 0;
}

static struct rte_vdev_driver geulipc_pmd_drv = {
	.probe = geulipc_rawdev_probe,
	.remove = geulipc_rawdev_remove
};

RTE_PMD_REGISTER_VDEV(GEULIPC_PMD_NAME, geulipc_pmd_drv);
RTE_LOG_REGISTER(geulipc_pmd_logtype, pmd.raw.geulipc, INFO);
