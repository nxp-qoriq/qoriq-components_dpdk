/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 *   Copyright 2022-2024 NXP
 *
 */

#ifndef KPG_NC_MODULE_H
#define KPG_NC_MODULE_H

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>


#define KPG_NC_DEVICE_NAME "page_ncache"
#define KPG_NC_DEVICE_PATH "/dev/" KPG_NC_DEVICE_NAME

/* IOCTL */
#define KPG_NC_MAGIC_NUM		0xf0f0
#define KPG_NC_IOCTL_UPDATE  _IOWR(KPG_NC_MAGIC_NUM, 1, size_t)


#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#if defined(RTE_ARCH_ARM) && defined(RTE_ARCH_64)
static inline void flush_tlb(void *p)
{
	asm volatile("dc civac, %0" ::"r"(p));
	asm volatile("dsb ish");
	asm volatile("isb");
}
#endif

static inline void mark_kpage_ncache(uint64_t huge_page)
{
	int fd, ret;

	fd = open(KPG_NC_DEVICE_PATH, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, KYEL "Error: " KNRM "Could not open: %s\n",
			KPG_NC_DEVICE_PATH);
		return;
	}
	fprintf(stdout, KCYN "%s: Huge_Page addr =" KNRM " 0x%lX\n",
		__func__, huge_page);
	ret = ioctl(fd, KPG_NC_IOCTL_UPDATE, (size_t)&huge_page);
	if (ret) {
		fprintf(stderr, KYEL "Error(%d): " KNRM "non-cachable set\n",
			ret);
		return;
	}
#if defined(RTE_ARCH_ARM) && defined(RTE_ARCH_64)
	flush_tlb((void *)huge_page);
#endif
	fprintf(stdout, KYEL "Page should be non-cachable now" KNRM "\n");

	close(fd);
}
#endif // KPG_NC_MODULE_H
