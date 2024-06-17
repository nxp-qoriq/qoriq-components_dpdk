/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#include <bus_pci_driver.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include "lsxinic_rc_hw.h"
#define SVR_LSX_MASK 0x87000000

static const char *
lxsnic_find_parent_of_this(const char *root_path,
	const char *parent_path, const char *this_dev)
{
	DIR *dir;
	struct dirent *entry;
	char next_path[PATH_MAX];
	int offset, i, continue_flag;
	const char *dup;
	struct stat path_stat;
	const char *format = "xxxx:xx:xx.xx";

	dir = opendir(parent_path);
	if (!dir) {
		LSXINIC_PMD_ERR("Cannot open directory: %s\n", parent_path);
		return NULL;
	}

	while ((entry = readdir(dir))) {
		if (!strcmp(entry->d_name, this_dev)) {
			if (!strcmp(root_path, parent_path))
				continue;

			dup = strdup(parent_path);
			return dup;
		}
		if (strlen(entry->d_name) != strlen(format) &&
			strlen(entry->d_name) != (strlen(format) - 1))
			continue;

		continue_flag = 0;
		for (i = 0; i < (int)strlen(entry->d_name); i++) {
			if (entry->d_name[i] != format[i] &&
				format[i] != 'x') {
				continue_flag = 1;
				break;
			}
		}
		if (continue_flag)
			continue;

		offset = sprintf(next_path, "%s", parent_path);
		sprintf(&next_path[offset], "/%s", entry->d_name);
		stat(next_path, &path_stat);

		if (S_ISDIR(path_stat.st_mode)) {
			dup = lxsnic_find_parent_of_this(root_path,
				next_path, this_dev);
			if (dup)
				return dup;
		}
	}

	closedir(dir);

	return NULL;
}

int
lxsnic_br_of_dev_snoop(struct rte_pci_device *pci_dev)
{
	const char *dirpath;
	const char *bridge_path;
	char dev_name[PATH_MAX];
	char bridge_cfg_path[PATH_MAX];
	int fd;
	uint8_t cap[PCI_CONFIG_SPACE_SIZE];
	uint16_t cap_ctl;
	ssize_t size;
	FILE *svr_file = NULL;
	uint32_t svr_ver = 0;
	char *penv;

	penv = getenv("LSXINIC_RC_NOSNOOP_IGNORE");
	if (penv)
		return 1;

	svr_file = fopen("/sys/devices/soc0/soc_id", "r");
	if (!svr_file)
		goto check_bridge_nosnoop;

	if (fscanf(svr_file, "svr:%x", &svr_ver) < 0)
		goto check_bridge_nosnoop;

	if ((svr_ver & SVR_LSX_MASK) == SVR_LSX_MASK)
		return 1;

check_bridge_nosnoop:
	sprintf(dev_name, PCI_PRI_FMT, pci_dev->addr.domain,
		pci_dev->addr.bus, pci_dev->addr.devid,
		pci_dev->addr.function);

	dirpath = rte_pci_get_sysfs_path();
	bridge_path = lxsnic_find_parent_of_this(dirpath,
		dirpath, dev_name);

	if (!bridge_path)
		return -EIO;

	sprintf(bridge_cfg_path, "%s/config", bridge_path);
	fd = open(bridge_cfg_path, O_RDONLY);
	if (fd < 0)
		return fd;

	size = read(fd, cap, PCI_CONFIG_LINK_CAP_OFFSET);
	if (size != PCI_CONFIG_LINK_CAP_OFFSET)
		return -EIO;

	cap_ctl = *((uint16_t *)&cap[PCI_CONFIG_CAP_CTL_OFFSET]);
	close(fd);

	if (cap_ctl & PCI_DEVCTL_NOSNOOP) {
		LSXINIC_PMD_WARN("Bridge(%s) is NoSnoop+\n", bridge_path);
		return 0;
	}

	return 1;
}
