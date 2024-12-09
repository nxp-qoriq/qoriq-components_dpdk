/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_log.h>
#include <rte_bus.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_io.h>
#include <rte_byteorder.h>
#include <rte_memzone.h>
#include <rte_log.h>
#include <rte_kvargs.h>
#include <rte_string_fns.h>

#include "lsx_pciep_dev.h"

#define PAGE_SIZE   (sysconf(_SC_PAGESIZE))
#define PAGE_MASK   (~(PAGE_SIZE - 1))

#define LSX_PCIEP_BUS_NAME	lsx_pciep

static struct rte_lsx_pciep_bus lsx_pciep_bus;

static int s_lsx_pciep_disable;

static int
lsx_pciep_compare_devname(struct rte_lsx_pciep_device *dev1,
		      struct rte_lsx_pciep_device *dev2)
{
	int comp = 0;

	if (!strncmp(dev1->name, dev2->name, RTE_DEV_NAME_MAX_LEN))
		comp = 1;

	if (dev1->pcie_id == dev2->pcie_id &&
		dev1->pf == dev2->pf &&
		!dev1->is_vf && !dev2->is_vf)
		comp = 1;

	if (dev1->pcie_id == dev2->pcie_id &&
		dev1->pf == dev2->pf &&
		dev1->vf == dev2->vf && dev1->is_vf && dev2->is_vf)
		comp = 1;

	return comp;
}

static void
lsx_pciep_insert_device_list(struct rte_lsx_pciep_device *newdev)
{
	int comp, inserted = 0;
	struct rte_lsx_pciep_device *dev = NULL;
	struct rte_lsx_pciep_device *tdev = NULL;

	RTE_TAILQ_FOREACH_SAFE(dev, &lsx_pciep_bus.device_list, next, tdev) {
		comp = lsx_pciep_compare_devname(newdev, dev);
		if (comp) {
			inserted = 1;
			break;
		}
	}

	if (!inserted)
		TAILQ_INSERT_TAIL(&lsx_pciep_bus.device_list,
		newdev, next);
}

static struct rte_device *
lsx_pciep_find_device(const struct rte_device *start, rte_dev_cmp_t cmp,
		      const void *data)
{
	struct rte_lsx_pciep_device *dev;

	TAILQ_FOREACH(dev, &lsx_pciep_bus.device_list, next) {
		if (start && &dev->device == start) {
			start = NULL;  /* starting point found */
			continue;
		}

		if (cmp(&dev->device, data) == 0)
			return &dev->device;
	}

	return NULL;
}

/* Create all the PF and VF device(s) of the PCIe controller.*/
static int lsx_pciep_create_dev(uint8_t pcie_idx)
{
	struct rte_lsx_pciep_device *ep_dev;
	struct lsx_pciep_ctl_hw *ctlhw;
	uint32_t i;
	int ret = 0;

	ctlhw = lsx_pciep_get_dev(pcie_idx);
	if (!ctlhw)
		return -ENODEV;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY && ctlhw->sim) {
		/*PCIe EP simulator is supported only in primary process.*/
		return -ENODEV;
	}

	if (!ctlhw->ep_enable)
		return -ENODEV;

	if (ctlhw->pf_enable[PF0_IDX]) {
		ep_dev = calloc(1, sizeof(struct rte_lsx_pciep_device));
		if (!ep_dev) {
			LSX_PCIEP_BUS_ERR("%s line:%d Out of memory",
				__func__, __LINE__);

			return -ENOMEM;
		}

		memset(ep_dev, 0, sizeof(struct rte_lsx_pciep_device));

		ep_dev->pf = PF0_IDX;
		ep_dev->is_vf = 0;

		if (lsx_pciep_hw_vio_get(pcie_idx, PF0_IDX))
			snprintf(ep_dev->name, RTE_DEV_NAME_MAX_LEN,
				LSX_PCIEP_VIRT_NAME_PREFIX "_%d_pf0",
				ctlhw->hw.index);
		else
			snprintf(ep_dev->name, RTE_DEV_NAME_MAX_LEN,
				LSX_PCIEP_NXP_NAME_PREFIX "_%d_pf0",
				ctlhw->hw.index);

		ep_dev->pcie_id = ctlhw->hw.index;

		ep_dev->device.name = ep_dev->name;

		lsx_pciep_insert_device_list(ep_dev);
		ret++;
	}

	if (ctlhw->pf_enable[PF1_IDX]) {
		ep_dev = calloc(1, sizeof(struct rte_lsx_pciep_device));
		if (!ep_dev) {
			LSX_PCIEP_BUS_ERR("%s line:%d Out of memory",
				__func__, __LINE__);

			return -ENOMEM;
		}

		memset(ep_dev, 0, sizeof(struct rte_lsx_pciep_device));

		ep_dev->pf = PF1_IDX;
		ep_dev->is_vf = 0;

		if (lsx_pciep_hw_vio_get(pcie_idx, PF1_IDX))
			snprintf(ep_dev->name, RTE_DEV_NAME_MAX_LEN,
					LSX_PCIEP_VIRT_NAME_PREFIX "_%d_pf1",
					ctlhw->hw.index);
		else
			snprintf(ep_dev->name, RTE_DEV_NAME_MAX_LEN,
					LSX_PCIEP_NXP_NAME_PREFIX "_%d_pf1",
					ctlhw->hw.index);

		ep_dev->pcie_id = ctlhw->hw.index;

		ep_dev->device.name = ep_dev->name;

		lsx_pciep_insert_device_list(ep_dev);
		ret++;
	}

	for (i = 0; i < PCIE_MAX_VF_NUM; i++) {
		if (!ctlhw->vf_enable[PF0_IDX][i])
			continue;
		ep_dev = calloc(1, sizeof(struct rte_lsx_pciep_device));
		if (!ep_dev) {
			LSX_PCIEP_BUS_ERR("%s line:%d Out of memory",
				__func__, __LINE__);

			return -ENOMEM;
		}

		memset(ep_dev, 0, sizeof(struct rte_lsx_pciep_device));

		ep_dev->pf = PF0_IDX;
		ep_dev->is_vf = 1;
		ep_dev->vf = i;
		if (lsx_pciep_hw_vio_get(pcie_idx, PF0_IDX))
			snprintf(ep_dev->name,
				RTE_DEV_NAME_MAX_LEN,
				LSX_PCIEP_VIRT_NAME_PREFIX
				"_%d_pf0_vf%d",
				ctlhw->hw.index, i);
		else
			snprintf(ep_dev->name,
				RTE_DEV_NAME_MAX_LEN,
				LSX_PCIEP_NXP_NAME_PREFIX
				"_%d_pf0_vf%d",
				ctlhw->hw.index, i);

		ep_dev->pcie_id = ctlhw->hw.index;
		ep_dev->device.name = ep_dev->name;

		lsx_pciep_insert_device_list(ep_dev);
		ret++;
	}

	for (i = 0; i < PCIE_MAX_VF_NUM; i++) {
		if (!ctlhw->vf_enable[PF1_IDX][i])
			continue;
		ep_dev = calloc(1, sizeof(struct rte_lsx_pciep_device));
		if (!ep_dev) {
			LSX_PCIEP_BUS_ERR("%s line:%d Out of memory",
				__func__, __LINE__);

			return -ENOMEM;
		}

		memset(ep_dev, 0, sizeof(struct rte_lsx_pciep_device));

		ep_dev->pf = PF1_IDX;
		ep_dev->is_vf = 1;
		ep_dev->vf = i;
		if (lsx_pciep_hw_vio_get(pcie_idx, PF1_IDX))
			snprintf(ep_dev->name,
				RTE_DEV_NAME_MAX_LEN,
				LSX_PCIEP_VIRT_NAME_PREFIX
				"_%d_pf1_vf%d",
				ctlhw->hw.index, i);
		else
			snprintf(ep_dev->name,
				RTE_DEV_NAME_MAX_LEN,
				LSX_PCIEP_NXP_NAME_PREFIX
				"_%d_pf1_vf%d",
				ctlhw->hw.index, i);

		ep_dev->pcie_id = ctlhw->hw.index;
		ep_dev->device.name = ep_dev->name;

		lsx_pciep_insert_device_list(ep_dev);
		ret++;
	}

	return ret;
}

void *lsx_pciep_map_region(uint64_t addr, size_t len)
{
	int fd;
	void *tmp;
	uint64_t start;
	uint64_t offset;

	fd = open("/dev/mem", O_RDWR);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Fail to open /dev/mem\n");
		return NULL;
	}

	start = addr & PAGE_MASK;
	offset = addr - start;
	len = len & PAGE_MASK;
	if (len < (size_t)PAGE_SIZE)
		len = PAGE_SIZE;

	tmp = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, start);

	close(fd);

	if (tmp != MAP_FAILED)
		return (uint8_t *)tmp + offset;
	else
		return NULL;
}

int lsx_pciep_unmap_region(void *vaddr, size_t len)
{
	return munmap(vaddr, len);
}

static int
lsx_pciep_scan(void)
{
	uint8_t pcie_idx = 0;
	int ret;
	char *penv;

	penv = getenv("LSX_PCIEP_BUS_DISABLE");
	if ((penv && atoi(penv)) || s_lsx_pciep_disable) {
		s_lsx_pciep_disable = 1;
		return 0;
	}

	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
		return 0;

	ret = lsx_pciep_primary_init();
	if (ret) {
		if (ret == -ENOTSUP) {
			LSX_PCIEP_BUS_DBG("PCIEP bus is not supported");
			return 0;
		}
		if (ret == -ENODEV) {
			LSX_PCIEP_BUS_DBG("PCIEP bus is not available");
			return 0;
		}
		return ret;
	}

	while (1) {
		if (!lsx_pciep_ctl_idx_validated(pcie_idx))
			break;
		ret = lsx_pciep_create_dev(pcie_idx);
		if (!ret)
			LSX_PCIEP_BUS_INFO("EP device on PEX%d", pcie_idx);
		pcie_idx++;
	}

	return 0;
}

static int
lsx_pciep_match(struct rte_lsx_pciep_driver *ep_drv,
		struct rte_lsx_pciep_device *ep_dev)
{
	int ret = 1;
	static int s_cnt;

	if (!strncmp(ep_drv->name, ep_dev->name,
			strlen(LSX_PCIEP_NXP_NAME_PREFIX) - 1))
		ret = 0;

	if (!strncmp(ep_drv->name, ep_dev->name,
			strlen(LSX_PCIEP_VIRT_NAME_PREFIX) - 1))
		ret = 0;

	if (strstr(ep_dev->name, "_vf"))
		ret = 0;

	if (s_cnt > RTE_MAX_ETHPORTS)
		return 1;

	s_cnt++;
	return ret;
}

struct rte_lsx_pciep_device *
rte_lsx_pciep_first_dev(void)
{
	return (struct rte_lsx_pciep_device *)
			TAILQ_FIRST(&lsx_pciep_bus.device_list);
}

#define ATTACH_DEV_FORMAT(pci_id, dev_nb) \
	"Secondary process attached %d devices of PCIe%d", \
	(int)dev_nb, \
	(int)pci_id

static int
lsx_pciep_probe(void)
{
	int ret = 0, i, added;
	struct rte_lsx_pciep_device *dev;
	struct rte_lsx_pciep_driver *drv;

	if (s_lsx_pciep_disable)
		return 0;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		ret = lsx_pciep_share_info_init();
		if (ret) {
			LSX_PCIEP_BUS_DBG("PCIEP not available on the 2nd proc");

			return 0;
		}
		for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
			added = lsx_pciep_create_dev(i);
			if (added > 0)
				LSX_PCIEP_BUS_INFO(ATTACH_DEV_FORMAT(i, added));
		}
	}

	if (TAILQ_EMPTY(&lsx_pciep_bus.device_list))
		return 0;

	/** Reserve shared memory when PCIe EP device is detected.*/
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = lsx_pciep_share_info_init();
		if (ret) {
			LSX_PCIEP_BUS_ERR("%s share info init err(%d)\n",
				__func__, ret);

			return ret;
		}
	}

	TAILQ_FOREACH(dev, &lsx_pciep_bus.device_list, next) {
		TAILQ_FOREACH(drv, &lsx_pciep_bus.driver_list, next) {
			ret = lsx_pciep_match(drv, dev);
			if (ret)
				continue;

			lsx_pciep_ctl_init_win(dev->pcie_id);

			if (!drv->probe)
				continue;

			ret = drv->probe(drv, dev);
			if (ret)
				LSX_PCIEP_BUS_LOG(ERR, "Unable to probe.\n");
			break;  /* note this  */
		}
	}

	return 0;
}

static int
lsx_pciep_close(void)
{
	int ret = 0;

	ret = lsx_pciep_uninit();
	if (ret)
		LSX_PCIEP_BUS_ERR("Uninit failed.");

	lsx_pciep_free_shared_mem();

	return 0;
}

static int
lsx_pciep_parse(const char *name, void *out_name)
{
	int i, j;

	LSX_PCIEP_BUS_INFO("PCIe EP bus parse name %s", name);

	/* Check for lsxep_nxp_2_pf0 style */

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		for (j = 0; j < PF_MAX_NB; j++) {
			char tmp_name[32];

			snprintf(tmp_name, 16, "lsxep_nxp_%d_pf%d", i, j);
			if (strcmp(tmp_name, name) == 0) {
				if (out_name)
					strcpy(out_name, name);
				return 0;
			}
		}
	}

	return -EINVAL;
}

static void *
lsx_pciep_dev_iterate(const void *start, const char *str,
	const struct rte_dev_iterator *it __rte_unused)
{
	const struct rte_lsx_pciep_device *dstart;
	struct rte_lsx_pciep_device *dev;
	char *dup, *dev_name = NULL;

	/* Expectation is that device would be name=device_name */
	if (strncmp(str, "name=", 5) != 0) {
		LSX_PCIEP_BUS_ERR("Invalid device string (%s)\n", str);
		return NULL;
	}

	/* Now that name=device_name format is available, split */
	dup = strdup(str);
	dev_name = dup + strlen("name=");

	if (start != NULL) {
		dstart = RTE_DEV_TO_LSX_PCIEP_CONST(start);
		dev = TAILQ_NEXT(dstart, next);
	} else {
		dev = TAILQ_FIRST(&lsx_pciep_bus.device_list);
	}

	while (dev != NULL) {
		if (strcmp(dev->device.name, dev_name) == 0) {
			free(dup);
			return &dev->device;
		}
		dev = TAILQ_NEXT(dev, next);
	}

	free(dup);
	return NULL;
}

static struct rte_lsx_pciep_bus lsx_pciep_bus = {
	.bus = {
		.scan = lsx_pciep_scan,
		.probe = lsx_pciep_probe,
		.close = lsx_pciep_close,
		.parse = lsx_pciep_parse,
		.dev_iterate = lsx_pciep_dev_iterate,
		.find_device = lsx_pciep_find_device,
	},
	.device_list = TAILQ_HEAD_INITIALIZER(lsx_pciep_bus.device_list),
	.driver_list = TAILQ_HEAD_INITIALIZER(lsx_pciep_bus.driver_list),
};

/* register a lsinic_vdev bus based lsinic driver */
void
rte_lsx_pciep_driver_register(struct rte_lsx_pciep_driver *driver)
{
	RTE_VERIFY(driver);

	TAILQ_INSERT_TAIL(&lsx_pciep_bus.driver_list, driver, next);
	/* Update Bus references */
	driver->lsx_pciep_bus = &lsx_pciep_bus;
}

/* un-register a lsinic_vdev bus based lsinic driver */
void
rte_lsx_pciep_driver_unregister(struct rte_lsx_pciep_driver *driver)
{
	struct rte_lsx_pciep_bus *bus;

	bus = driver->lsx_pciep_bus;

	TAILQ_REMOVE(&bus->driver_list, driver, next);
	/* Update Bus references */
	driver->lsx_pciep_bus = NULL;
}

RTE_REGISTER_BUS(LSX_PCIEP_BUS_NAME, lsx_pciep_bus.bus);
