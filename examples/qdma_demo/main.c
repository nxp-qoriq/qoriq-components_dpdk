/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2024 NXP
 */

/* System headers */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_dmadev.h>
#include <rte_dmadev_pmd.h>

#include <rte_interrupts.h>
#include <stdint.h>
#include <sys/queue.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <ethdev_driver.h>

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <dirent.h>
#include <bus_pci_driver.h>
#include <bus_fslmc_driver.h>
#include <rte_pmd_dpaa2_qdma.h>
#include "qdma_demo.h"
#include <rte_pmd_lsxinic.h>

static int qdma_dev_id;
static float s_ns_per_cyc;
static rte_atomic32_t synchro;
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_IP,
		},
	},
};

#define NS_PER_US 1000
#define NS_PER_MS (NS_PER_US * 1000)
#ifndef NS_PER_S
#define NS_PER_S (NS_PER_MS * 1000)
#endif

static uint64_t g_dq_num[RTE_MAX_LCORE];
static uint64_t g_dq_num_last[RTE_MAX_LCORE];

static int g_vqid[RTE_MAX_LCORE];

#define CPU_INFO_FREQ_FILE \
	"/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq"

#define RTE_LOGTYPE_qdma_demo RTE_LOGTYPE_USER1

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

enum qdma_demo_test_mode {
	QDMA_DEMO_DMA_MODE = (1 << 0),
	QDMA_DEMO_CPU_MODE = (1 << 1),
};

struct qdma_demo_latency {
	double min;
	double max;
	double total;
	int count;
};
static struct qdma_demo_latency latency_data[RTE_MAX_LCORE];

static struct qdma_test_case s_test_case[] = {
	{"mem_to_mem", "Host mem to Host mem done, pci_addr not needed",
		 MEM_TO_MEM},
	{"mem_to_pci", "Host mem to EP mem done from host", MEM_TO_PCI},
	{"pci_to_mem", "EP me to host mem done from host", PCI_TO_MEM},
	{"pci_to_pci", "EP mem to EP mem done from host", PCI_TO_PCI},
};

static struct qdma_test_mode s_test_mode[] = {
	{"dma_mode", QDMA_DEMO_DMA_MODE},
	{"cpu_mode", QDMA_DEMO_CPU_MODE},
	{"mix_mode", QDMA_DEMO_DMA_MODE | QDMA_DEMO_CPU_MODE},
};

/*Configurable options*/
static int g_test_path = MEM_TO_PCI;
static uint32_t g_arg_mask;
static uint32_t g_burst = BURST_NB_MAX;
static uint64_t g_pci_phy = RTE_BAD_IOVA;
static uint64_t g_packet_dma_size = 1024;
static uint64_t g_packet_cpu_size = 64;
static uint64_t g_packet_elem_size = 1024;
static uint64_t g_pci_size = 0x1000000;
static uint64_t g_pci_bus;
static void *g_pci_vir;

static uint32_t g_packet_num = (1 * 1024);
static int g_latency;
static int g_test_mode = QDMA_DEMO_DMA_MODE;
static int g_validate;
static int g_seg_iova;
static int g_scatter_gather;
static int g_silent;
static int g_dma_prep_latency;

static int g_pci_ep;
static int g_pci_ep_rbp;
static int g_pci_ep_pci_id;
static int g_pci_ep_pf_id;
static int g_pci_ep_vf_id;
static int g_pci_ep_is_vf;

static struct dma_job *g_jobs[RTE_MAX_LCORE];
static struct rte_ring *g_job_ring[RTE_MAX_LCORE];
static const struct rte_memzone *g_memz_src[RTE_MAX_LCORE];
static const struct rte_memzone *g_memz_dst[RTE_MAX_LCORE];
static uint16_t *g_dma_idx[RTE_MAX_LCORE];

static uint8_t quit_signal;
static uint32_t core_count;

static int TEST_DMA_INIT_FLAG;
#define LATENCY_TEST_SRC_DATA 1
#define LATENCY_TEST_DST_DATA 0

#define START_ADDR(base, num, type) \
	((type)((uint64_t)base + g_packet_elem_size * num))

struct qdma_demo_pci_bar {
	uint64_t phy_start[PCI_MAX_RESOURCE];
	uint64_t len[PCI_MAX_RESOURCE];
};

#define QDMA_DEMO_MAX_PCI_DEV 64
static struct qdma_demo_pci_bar g_pci_bar[QDMA_DEMO_MAX_PCI_DEV];

static int s_flags_cntx;

static inline unsigned int
log2above(uint32_t v)
{
	uint32_t l, r;

	for (l = 0, r = 0; (v >> 1); ++l, v >>= 1)
		r |= (v & 1);
	return l + r;
}

static inline uint64_t
qdma_demo_roundup_pow_of_two(uint64_t n)
{
	return n == 1 ? 1 : 1ULL << log2above(n);
}

static int
test_dma_init(struct rte_dma_info *dma_info)
{
	struct rte_dma_conf dma_config;
	struct rte_dma_info local_dma_info;
	int ret, i = 0, max_avail = rte_dma_count_avail();

	if (TEST_DMA_INIT_FLAG) {
		ret = rte_dma_info_get(qdma_dev_id, &local_dma_info);
		if (ret) {
			RTE_LOG(ERR, qdma_demo,
				"Failed to get DMA[%d] info(%d)\n",
				qdma_dev_id, ret);
			return ret;
		}
		if (dma_info) {
			rte_memcpy(dma_info, &local_dma_info,
				sizeof(struct rte_dma_info));
		}
		return 0;
	}

init_dma:
	if (i >= max_avail)
		return -EBUSY;
	qdma_dev_id = i;

	ret = rte_dma_info_get(qdma_dev_id, &local_dma_info);
	if (ret) {
		RTE_LOG(ERR, qdma_demo,
			"Failed to get DMA[%d] info(%d)\n",
			qdma_dev_id, ret);
		return ret;
	}
	if (local_dma_info.dev_capa & RTE_DMA_CAPA_DPAA2_QDMA_FLAGS_INDEX)
		s_flags_cntx = 1;
	dma_config.nb_vchans = local_dma_info.max_vchans;
	dma_config.enable_silent = g_silent;

	ret = rte_dma_configure(qdma_dev_id, &dma_config);
	if (ret) {
		RTE_LOG(WARNING, qdma_demo,
			"Failed to configure DMA[%d](%d)\n",
			qdma_dev_id, ret);
		goto init_dma;
	}
	if (dma_info) {
		rte_memcpy(dma_info, &local_dma_info,
			sizeof(struct rte_dma_info));
	}

	TEST_DMA_INIT_FLAG = 1;

	return 0;
}

static int
qdma_demo_pci_parse_one_sysfs_resource(char *line,
	size_t len, uint64_t *phys_addr,
	uint64_t *end_addr)
{
	char *ptrs[PCI_RESOURCE_FMT_NVAL];
	int ret;

	ret = rte_strsplit(line, len, ptrs, PCI_RESOURCE_FMT_NVAL, ' ');
	if (ret != PCI_RESOURCE_FMT_NVAL) {
		RTE_LOG(ERR, qdma_demo,
			"%s(): bad resource format\n", __func__);
		return -ENOTSUP;
	}

	errno = 0;
	*phys_addr = strtoull(ptrs[0], NULL, 16);
	*end_addr = strtoull(ptrs[1], NULL, 16);
	if (errno != 0) {
		RTE_LOG(ERR, qdma_demo,
			"%s(): bad resource format\n", __func__);
		return -ENOTSUP;
	}

	return 0;
}

static int
qdma_demo_pci_parse_sysfs_resource(const char *filename,
	int dev_idx)
{
	FILE *f;
	char buf[BUFSIZ];
	int i, ret;
	uint64_t phys_addr, end_addr;
	struct qdma_demo_pci_bar *pci_bar;

	if (dev_idx >= QDMA_DEMO_MAX_PCI_DEV) {
		RTE_LOG(ERR, qdma_demo, "Too many PCI devices\n");
		return -ENOTSUP;
	}

	pci_bar = &g_pci_bar[dev_idx];

	f = fopen(filename, "r");
	if (!f) {
		RTE_LOG(ERR, qdma_demo, "Cannot open %s\n", filename);
		return -errno;
	}

	for (i = 0; i < PCI_MAX_RESOURCE; i++) {
		if (!fgets(buf, sizeof(buf), f)) {
			RTE_LOG(ERR, qdma_demo,
				"%s(): cannot read resource\n", __func__);
			fclose(f);
			return -EIO;
		}
		ret = qdma_demo_pci_parse_one_sysfs_resource(buf,
				sizeof(buf), &phys_addr,
				&end_addr);
		if (ret < 0) {
			fclose(f);
			return ret;
		}

		pci_bar->phy_start[i] = phys_addr;
		pci_bar->len[i] = end_addr - phys_addr + 1;
	}

	fclose(f);
	return 0;
}

static int
qdma_demo_pci_scan_one(const char *dirname, int dev_idx)
{
	char filename[PATH_MAX];
	int ret;

	/* parse resources */
	snprintf(filename, sizeof(filename), "%s/resource", dirname);
	ret = qdma_demo_pci_parse_sysfs_resource(filename, dev_idx);
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "%s(): cannot parse resource\n",
			__func__);
		return ret;
	}

	return 0;
}

static int
qdma_demo_pci_scan(void)
{
	struct dirent *e;
	DIR *dir;
	char dirname[PATH_MAX];
	int ret, dev_nb = 0;

	/* for debug purposes, PCI can be disabled */
	if (!rte_eal_has_pci())
		return 0;

	dir = opendir(rte_pci_get_sysfs_path());
	if (!dir) {
		RTE_LOG(ERR, EAL, "%s(): opendir failed: %s\n",
			__func__, strerror(errno));
		return -errno;
	}

	while ((e = readdir(dir)) != NULL) {
		if (e->d_name[0] == '.')
			continue;

		snprintf(dirname, sizeof(dirname), "%s/%s",
			rte_pci_get_sysfs_path(), e->d_name);

		ret = qdma_demo_pci_scan_one(dirname, dev_nb);
		if (ret) {
			closedir(dir);
			return ret;
		}
		dev_nb++;
	}

	closedir(dir);
	return 0;
}

static uint64_t
pci_find_bar_available_size(uint64_t pci_addr)
{
	uint64_t start, end, len;
	int i, j, ret;

	ret = qdma_demo_pci_scan();
	if (ret)
		return 0;

	for (i = 0; i < QDMA_DEMO_MAX_PCI_DEV; i++) {
		for (j = 0; j < PCI_MAX_RESOURCE; j++) {
			start = g_pci_bar[i].phy_start[j];
			len = g_pci_bar[i].len[j];
			end = start + len;
			if (pci_addr >= start && pci_addr < end)
				return len - (pci_addr - start);
		}
	}

	return 0;
}

static void *
pci_addr_mmap(void *start, size_t length, int prot,
	int flags, off_t offset, void **map_addr, int *retfd)
{
	off_t newoff = 0;
	off_t diff = 0;
	off_t mask = PAGE_MASK;
	void *p = NULL;
	int fd = 0;

	fd = open("/dev/mem", O_RDWR|O_SYNC);
	if (fd < 0) {
		RTE_LOG(ERR, qdma_demo,
			"Error in opening /dev/mem(fd=%d)\n", fd);
		return NULL;
	}

	newoff = offset & mask;
	if (newoff != offset)
		diff = offset - newoff;

	p = mmap(start, length, prot, flags, fd, newoff);
	if (p == MAP_FAILED) {
		RTE_LOG(ERR, qdma_demo, "Error in mmap address(%p + %lx)\n",
			start, newoff);
		close(fd);
		return NULL;
	}

	if (map_addr)
		*map_addr = (void *)((uint64_t)p + diff);

	if (retfd)
		*retfd = fd;
	else
		close(fd);

	return p;
}

#define LATENCY_WARMUP_COUNT 3
static void
calculate_latency(unsigned int lcore_id,
	uint64_t cycle1, uint64_t cycle2,
	struct dma_job *job[], int pkt_cnt, uint32_t miss_time)
{
	uint64_t burst_size = 0;
	uint64_t my_time_diff;
	int i;
	static uint64_t s_cnt;
	struct qdma_demo_latency *core_latency = &latency_data[lcore_id];

	float time_us = 0.0;

	my_time_diff = cycle2 - cycle1;
	time_us = s_ns_per_cyc * my_time_diff / 1000;

	s_cnt++;

	if (s_cnt < LATENCY_WARMUP_COUNT) {
		rte_delay_ms(1000);
		return;
	}

	if (time_us < core_latency->min)
		core_latency->min = time_us;
	if (time_us > core_latency->max)
		core_latency->max = time_us;
	core_latency->total += time_us;
	core_latency->count++;

	for (i = 0; i < pkt_cnt; i++) {
		if (job[i]->dma_len > 0) {
			RTE_LOG(INFO, qdma_demo,
				"DMA job[%d]: src(%lx)->size(%d)->dst(%lx)\n",
				i, job[i]->src, job[i]->dma_len, job[i]->dest);
			burst_size += job[i]->dma_len;
		}
		if (job[i]->cpu_len > 0) {
			RTE_LOG(INFO, qdma_demo,
				"CPU job[%d]: src(%lx)->size(%d)->dst(%lx)\n",
				i, job[i]->src + job[i]->dma_len,
				job[i]->cpu_len,
				job[i]->dest + job[i]->dma_len);
			burst_size += job[i]->cpu_len;
		}
	}
	RTE_LOG(INFO, qdma_demo,
		"cpu=%d burst size %ld, miss_time %d\n",
		lcore_id, burst_size, miss_time);
	RTE_LOG(INFO, qdma_demo,
		"this %.1f, min %.1f, max %.1f, mean %.1f\n\r\n",
		time_us, core_latency->min, core_latency->max,
		core_latency->total / core_latency->count);
	rte_delay_ms(1000);
}

static inline void
qdma_demo_validate_set(struct dma_job *job)
{
	int r_num;
	uint32_t i, j;

	if (!g_validate)
		return;

	if (!job->dma_len)
		goto cpu_validate_set;

	r_num = rand();
	for (i = 0; i < job->dma_len / 4; i++) {
		*((int *)(job->vdmasrc) + i) = r_num;
		*((int *)(job->vdmadst) + i) = 0;
	}
	j = 0;
	while ((i * 4 + j) < job->dma_len) {
		*(job->vdmasrc + i * 4 + j) = r_num;
		*(job->vdmadst + i * 4 + j) = 0;
		j++;
	}

cpu_validate_set:
	if (!job->cpu_len)
		return;

	r_num = rand();
	for (i = 0; i < job->cpu_len / 4; i++) {
		*((int *)(job->vcpusrc) + i) = r_num;
		*((int *)(job->vcpudst) + i) = 0;
	}
	j = 0;
	while ((i * 4 + j) < job->cpu_len) {
		*(job->vcpusrc + i * 4 + j) = r_num;
		*(job->vcpudst + i * 4 + j) = 0;
		j++;
	}
}

static int
qdma_demo_validate_check(struct dma_job *job[],
	uint32_t job_num)
{
	int cmp_src, cmp_dst;
	uint32_t i, j, k;

	if (!g_validate)
		return 0;

	for (i = 0; i < job_num; i++) {
		if (!job[i]->dma_len)
			goto cpu_validate;

		for (j = 0; j < job[i]->dma_len / 4; j++) {
			cmp_src = *((int *)(job[i]->vdmasrc) + j);
			cmp_dst = *((int *)(job[i]->vdmadst) + j);
			if (cmp_src != cmp_dst) {
				RTE_LOG(ERR, qdma_demo,
					"cmp_src(%p)(0x%08x) != cmp_dst(%p)(0x%08x)\n",
					job[i]->vdmasrc + j, cmp_src,
					job[i]->vdmadst + j, cmp_dst);

				rte_exit(EXIT_FAILURE, "Validate failed\n");
				return -EINVAL;
			}
		}
		k = 0;
		while ((j * 4 + k) < job[i]->dma_len) {
			cmp_src = *(job[i]->vdmasrc + j * 4 + k);
			cmp_dst = *(job[i]->vdmadst + j * 4 + k);
			if (cmp_src != cmp_dst) {
				RTE_LOG(ERR, qdma_demo,
					"cmp_src(0x%08x) != cmp_dst(0x%08x)\n",
					cmp_src, cmp_dst);
				rte_exit(EXIT_FAILURE, "Validate failed\n");
				return -EINVAL;
			}
			k++;
		}

cpu_validate:
		if (!job[i]->cpu_len)
			continue;

		for (j = 0; j < job[i]->cpu_len / 4; j++) {
			cmp_src = *((int *)(job[i]->vcpusrc) + j);
			cmp_dst = *((int *)(job[i]->vcpudst) + j);
			if (cmp_src != cmp_dst) {
				RTE_LOG(ERR, qdma_demo,
					"cmp_src(%p)(0x%08x) != cmp_dst(%p)(0x%08x)\n",
					job[i]->vcpusrc + j, cmp_src,
					job[i]->vcpudst + j, cmp_dst);

				rte_exit(EXIT_FAILURE, "Validate failed\n");
				return -EINVAL;
			}
		}
		k = 0;
		while ((j * 4 + k) < job[i]->cpu_len) {
			cmp_src = *(job[i]->vcpusrc + j * 4 + k);
			cmp_dst = *(job[i]->vcpudst + j * 4 + k);
			if (cmp_src != cmp_dst) {
				RTE_LOG(ERR, qdma_demo,
					"cmp_src(0x%08x) != cmp_dst(0x%08x)\n",
					cmp_src, cmp_dst);
				rte_exit(EXIT_FAILURE, "Validate failed\n");
				return -EINVAL;
			}
			k++;
		}
	}

	return 0;
}

static int
qdma_demo_memcpy_process(struct dma_job *job[],
	uint32_t job_num)
{
	uint32_t i, lcore_id, eq_ret;
	uint64_t cycle1, cycle2;
	int ret;

	lcore_id = rte_lcore_id();

	for (i = 0; i < job_num; i++) {
		qdma_demo_validate_set(job[i]);
	}

	cycle1 = rte_get_timer_cycles();
	for (i = 0; i < job_num; i++) {
		rte_memcpy(job[i]->vcpudst,
			job[i]->vcpusrc, job[i]->cpu_len);
	}
	cycle2 = rte_get_timer_cycles();
	if (g_latency)
		calculate_latency(lcore_id, cycle1, cycle2, job, job_num, 0);

	ret = qdma_demo_validate_check(job, job_num);

	eq_ret = rte_ring_enqueue_bulk(g_job_ring[lcore_id],
			(void **)job, job_num, NULL);
	if (job_num != eq_ret) {
		RTE_LOG(ERR, qdma_demo,
			"memcpy job recycle failed\n");
		rte_exit(EXIT_FAILURE,
			"memcpy job recycle failed\n");
		return -EINVAL;
	}
	g_dq_num[lcore_id] += job_num;

	return ret;
}

static int
lcore_qdma_iova_seg_to_continue(void)
{
	uint8_t *vir_base, *dst, *src, *vir;
	uint64_t iova_base, src_iova, iova_offset, iova[g_burst];
	int ret = 0;
	uint32_t seg_size, seg_num, total_size, i, j, src_idx;
	uint64_t page_size = sysconf(_SC_PAGESIZE);

	if (rte_eal_iova_mode() != RTE_IOVA_PA) {
		RTE_LOG(ERR, qdma_demo,
			"IOVA PA mode support only\n");
		return -ENOMEM;
	}

	seg_size = g_packet_dma_size;

	if (seg_size < page_size)
		seg_size = page_size;

	while (seg_size & ~page_size)
		seg_size--;

	if (g_packet_dma_size != seg_size) {
		RTE_LOG(WARNING, qdma_demo,
			"Adjust segment size(%lx) to (%x)\n",
			g_packet_dma_size, seg_size);
	}

	seg_num = g_burst;
	total_size = seg_size * seg_num;

	vir_base = mmap(NULL, total_size, PROT_WRITE | PROT_READ,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (vir_base == MAP_FAILED) {
		RTE_LOG(ERR, qdma_demo,
			"mmap %d bytes size failed\n",
			total_size);
		return -ENOMEM;
	}

	memset(vir_base, 0, total_size);
	iova_offset = 0;
	memset(iova, 0, sizeof(uint64_t) * g_burst);
	iova_base = (uint64_t)vir_base;
	for (i = 0; i < seg_num; i++) {
		if (i % 2) {
			/** Map interval segments to continue space.*/
			continue;
		}

		vir = vir_base + i * seg_size;
		iova[i] = iova_base + iova_offset;
		ret = rte_fslmc_vfio_mem_dmamap((uint64_t)vir,
			iova[i], seg_size);
		if (ret) {
			RTE_LOG(ERR, qdma_demo,
				"IOVA map(va:%p, iova:0x%lx, size:%d) failed(%d)\n",
				vir, iova[i], seg_size, ret);
			iova[i] = 0;
			goto quit;
		}
		iova_offset += seg_size;
	}

	src = rte_zmalloc(NULL, iova_offset, RTE_CACHE_LINE_SIZE);
	for (i = 0; i < iova_offset; i++)
		src[i] = i;
	src_iova = rte_fslmc_mem_vaddr_to_iova(src);

	ret = rte_dma_copy(qdma_dev_id,
			g_vqid[rte_lcore_id()],
			src_iova, iova_base,
			iova_offset, RTE_DMA_OP_FLAG_SUBMIT);
	if (ret) {
		RTE_LOG(ERR, qdma_demo,
			"DMA copy failed(%d)\n",
			ret);
		goto quit;
	}
	sleep(1);
	ret = rte_dma_completed(qdma_dev_id,
			g_vqid[rte_lcore_id()], 1,
			NULL,
			NULL);
	if (ret != 1) {
		RTE_LOG(ERR, qdma_demo,
			"DMA complete failed(%d)\n",
			ret);
		goto quit;
	}

	src_idx = 0;

	for (i = 0; i < seg_num; i++) {
		if (i % 2)
			continue;
		dst = vir_base + i * seg_size;
		for (j = 0; j < seg_size; j++) {
			if (dst[j] != src[src_idx]) {
				RTE_LOG(ERR, qdma_demo,
					"SEG[%d][%d](%d) != SRC[%d](%d)\n",
					i, j, dst[j],
					src_idx, src[src_idx]);
				ret = -EIO;
				goto quit;
			}
			src_idx++;
		}
	}
	RTE_LOG(INFO, qdma_demo,
		"Single DMA R/W %d segment(s) by IOMMU complete\n",
		seg_num);

quit:
	for (i = 0; i < seg_num; i++) {
		if (iova[i]) {
			ret = rte_fslmc_vfio_mem_dmaunmap(iova[i], seg_size);
			if (ret) {
				RTE_LOG(ERR, qdma_demo,
					"IOVA unmap(iova:0x%lx, size:%d) failed(%d)\n",
					iova[i], seg_size, ret);
			}
		}
	}
	munmap(vir_base, total_size);

	return ret;
}

#ifdef RTE_ARCH_ARM64
#define dccivac(p) \
	{ asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#endif

static int
lcore_qdma_process_loop(__attribute__((unused)) void *arg)
{
	uint32_t lcore_id;
	uint64_t cycle1 = 0, cycle2 = 0, cycle3 = 0, cycle4 = 0;
	int ret = 0;

	uint32_t dq_num = 0, miss_time = 0;
	uint32_t burst_nb = g_scatter_gather ? 32 : g_burst;
	uint8_t *vsrc, *vdst;

	lcore_id = rte_lcore_id();

	/* wait synchro for slaves */
	do {
		ret = rte_atomic32_read(&synchro);
	} while (!ret);
	RTE_LOG(INFO, qdma_demo,
		"Processing coreid: %d ready, now!\n",
		lcore_id);

	if (g_seg_iova)
		return lcore_qdma_iova_seg_to_continue();

	latency_data[lcore_id].min = 9999999.0;
	while (!quit_signal) {
		struct dma_job *job[burst_nb];
		struct rte_dma_sge src_sge[burst_nb];
		struct rte_dma_sge dst_sge[burst_nb];
		uint32_t i, j, job_num;
		uint64_t flags;
		bool error = false;
		uint16_t dq_idx[burst_nb];

		job_num = rte_ring_dequeue_bulk(g_job_ring[lcore_id],
			(void **)job, burst_nb, NULL);
		if (g_test_mode == QDMA_DEMO_CPU_MODE) {
			ret = qdma_demo_memcpy_process(job, job_num);
			if (ret)
				return ret;
			continue;
		}

		for (i = 0; i < job_num; i++) {
			qdma_demo_validate_set(job[i]);

			if (g_scatter_gather) {
				if (s_flags_cntx)
					g_dma_idx[lcore_id][i] = job[i]->idx;
				src_sge[i].addr = job[i]->src;
				src_sge[i].length = job[i]->dma_len;

				dst_sge[i].addr = job[i]->dest;
				dst_sge[i].length = job[i]->dma_len;
				continue;
			}

			flags = job[i]->flags;
			if (i == (job_num - 1) && s_flags_cntx)
				flags |= RTE_DPAA2_QDMA_COPY_SUBMIT(job[i]->idx,
						RTE_DMA_OP_FLAG_SUBMIT);
			else if (s_flags_cntx)
				flags |= RTE_DPAA2_QDMA_COPY_SUBMIT(job[i]->idx,
						0);
			else if (i == (job_num - 1))
				flags |= RTE_DMA_OP_FLAG_SUBMIT;

			if (g_latency && (flags & RTE_DMA_OP_FLAG_SUBMIT))
				cycle1 = rte_get_timer_cycles();
			ret = rte_dma_copy(qdma_dev_id,
					g_vqid[lcore_id],
					job[i]->src, job[i]->dest,
					job[i]->dma_len, flags);
			if ((flags & RTE_DMA_OP_FLAG_SUBMIT) &&
				(g_test_mode & QDMA_DEMO_CPU_MODE)) {
				for (j = 0; j < i; j++) {
					rte_memcpy(job[j]->vcpudst,
						job[j]->vcpusrc,
						job[j]->cpu_len);
				}
			}
			if (unlikely(ret < 0) && i > 0) {
				ret = rte_dma_submit(qdma_dev_id,
						g_vqid[lcore_id]);
				if (ret) {
					RTE_LOG(ERR, qdma_demo,
						"DMA submit error(%d)\n", ret);
					rte_exit(EXIT_FAILURE,
						"Job submit failed\n");
				}
				if ((flags & RTE_DMA_OP_FLAG_SUBMIT) &&
					(g_test_mode & QDMA_DEMO_CPU_MODE)) {
					for (j = 0; j < i; j++) {
						rte_memcpy(job[j]->vcpudst,
							job[j]->vcpusrc,
							job[j]->cpu_len);
					}
				}
				goto dequeue;
			}
			if (unlikely(ret < 0))
				goto dequeue;
		}

		if (!g_scatter_gather || !job_num)
			goto dequeue;

		if (s_flags_cntx) {
			flags = RTE_DPAA2_QDMA_SG_SUBMIT(g_dma_idx[lcore_id],
				RTE_DMA_OP_FLAG_SUBMIT);
		} else {
			flags = RTE_DMA_OP_FLAG_SUBMIT;
		}
		if (g_latency)
			cycle1 = rte_get_timer_cycles();
		ret = rte_dma_copy_sg(qdma_dev_id,
				g_vqid[lcore_id], src_sge, dst_sge,
				job_num, job_num,
				flags);
		if (unlikely(ret)) {
			RTE_LOG(ERR, qdma_demo,
				"SG DMA submit %d jobs error(%d)\n",
				job_num, ret);
			rte_exit(EXIT_FAILURE,
				"Job submit failed\n");
		}
		if ((flags & RTE_DMA_OP_FLAG_SUBMIT) &&
			(g_test_mode & QDMA_DEMO_CPU_MODE)) {
			for (j = 0; j < job_num; j++) {
				rte_memcpy(job[j]->vcpudst,
					job[j]->vcpusrc,
					job[j]->cpu_len);
			}
		}
dequeue:
		if (g_latency)
			cycle2 = rte_get_timer_cycles();
		if (g_silent) {
			dq_num = job_num;
			goto skip_dq;
		}
		if (!dq_num && g_latency)
			cycle3 = rte_get_timer_cycles();
		ret = rte_dma_completed(qdma_dev_id,
			g_vqid[lcore_id], burst_nb - dq_num,
			&dq_idx[dq_num],
			&error);
		if (ret > 0)
			dq_num += ret;
		if (g_latency && dq_num < burst_nb)
			goto dequeue;
		for (i = 0; i < dq_num; i++)
			job[i] = &g_jobs[lcore_id][dq_idx[i]];
		ret = qdma_demo_validate_check(job, dq_num);
		if (ret)
			return ret;
		if (error) {
			RTE_LOG(ERR, qdma_demo, "DMA complete error\n");
			rte_exit(EXIT_FAILURE, "Job Processing Error\n");
		}
skip_dq:
		if (g_silent) {
			miss_time = 0;
			if (g_latency)
				cycle3 = rte_get_timer_cycles();
			for (i = 0; i < dq_num; i++) {
				if (!job[i]->dma_len)
					goto cpu_check;

				vsrc = job[i]->vdmasrc + job[i]->dma_len - 1;
				vdst = job[i]->vdmadst + job[i]->dma_len - 1;
				while ((*vsrc) != (*vdst)) {
#ifdef RTE_ARCH_ARM64
					dccivac(vdst);
#endif
					miss_time++;
					if (quit_signal)
						break;
				}

cpu_check:
				if (!job[i]->cpu_len)
					continue;

				vsrc = job[i]->vcpusrc + job[i]->cpu_len - 1;
				vdst = job[i]->vcpudst + job[i]->cpu_len - 1;
				while ((*vsrc) != (*vdst)) {
#ifdef RTE_ARCH_ARM64
					dccivac(vdst);
#endif
					miss_time++;
					if (quit_signal)
						break;
				}
			}
		}

		if (g_latency) {
			cycle4 = rte_get_timer_cycles();
			calculate_latency(lcore_id,
				g_dma_prep_latency ? cycle1 : cycle2,
				cycle4, job, dq_num, miss_time);
			RTE_LOG(INFO, qdma_demo,
				"DMA prepare:%ld, check:%ld\n",
				cycle2 - cycle1, cycle4 - cycle3);
			for (i = 0; i < dq_num; i++) {
				if (!job[i]->dma_len)
					goto cpu_set;
				vsrc = job[i]->vdmasrc + job[i]->dma_len - 1;
				vdst = job[i]->vdmadst + job[i]->dma_len - 1;
				(*vsrc) = LATENCY_TEST_SRC_DATA;
				(*vdst) = LATENCY_TEST_DST_DATA;

cpu_set:
				if (!job[i]->cpu_len)
					continue;
				vsrc = job[i]->vcpusrc + job[i]->cpu_len - 1;
				vdst = job[i]->vcpudst + job[i]->cpu_len - 1;
				(*vsrc) = LATENCY_TEST_SRC_DATA;
				(*vdst) = LATENCY_TEST_DST_DATA;
			}
			rte_wmb();
			rte_rmb();
		}
		job_num = rte_ring_enqueue_bulk(g_job_ring[lcore_id],
			(void **)job, dq_num, NULL);
		if (job_num != dq_num) {
			RTE_LOG(ERR, qdma_demo, "job recycle failed\n");
			rte_exit(EXIT_FAILURE, "job recycle failed\n");
		}

		g_dq_num[lcore_id] += dq_num;
		dq_num = 0;
		error = false;
	}
	RTE_LOG(INFO, qdma_demo, "exit core %d\n", lcore_id);

	return 0;
}

static int
qdma_demo_jobs_init(struct dma_job *jobs,
	uint32_t lcore_id, uint64_t pci_src_iova,
	uint64_t pci_dst_iova, void *pci_src_vir,
	void *pci_dst_vir, uint64_t total_size,
	uint32_t num, uint32_t dma_len, uint32_t cpu_len)
{
	char nm[RTE_MEMZONE_NAMESIZE];
	uint32_t i;
	uint64_t src_iova, dst_iova;
	void *src_va, *dst_va;
	uint8_t *dmasrc_last, *dmadst_last, *cpusrc_last, *cpudst_last;
	int ret = 0;

	if (pci_src_iova == RTE_BAD_IOVA) {
		sprintf(nm, "memz-src-%d", lcore_id);
		g_memz_src[lcore_id] = rte_memzone_reserve_aligned(nm,
			total_size, 0,
			RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!g_memz_src[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"src mem zone created failed on core%d\n",
				lcore_id);
			ret = -ENOMEM;
			goto err_free;
		}
		src_iova = g_memz_src[lcore_id]->iova;
		src_va = g_memz_src[lcore_id]->addr;
	} else {
		src_iova = pci_src_iova;
		src_va = pci_src_vir;
	}

	if (pci_dst_iova == RTE_BAD_IOVA) {
		sprintf(nm, "memz-dst-%d", lcore_id);
		g_memz_dst[lcore_id] = rte_memzone_reserve_aligned(nm,
			total_size, 0,
			RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!g_memz_dst[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"src mem zone created failed on core%d\n",
				lcore_id);
			ret = -ENOMEM;
			goto err_free;
		}
		dst_iova = g_memz_dst[lcore_id]->iova;
		dst_va = g_memz_dst[lcore_id]->addr;
	} else {
		dst_iova = pci_dst_iova;
		dst_va = pci_dst_vir;
	}

	g_dma_idx[lcore_id] = rte_malloc(NULL,
		sizeof(uint16_t) * g_packet_num,
		RTE_DPAA2_QDMA_SG_IDX_ADDR_ALIGN);
	if (!g_dma_idx[lcore_id]) {
		RTE_LOG(ERR, qdma_demo,
			"DMA index created failed on core%d\n",
			lcore_id);
		ret = -ENOMEM;
		goto err_free;
	}

	for (i = 0; i < num; i++) {
		dmasrc_last = NULL;
		dmadst_last = NULL;
		cpusrc_last = NULL;
		cpudst_last = NULL;
		jobs[i].src = START_ADDR(src_iova, i, uint64_t);
		jobs[i].dest = START_ADDR(dst_iova, i, uint64_t);
		if (dma_len > 0) {
			jobs[i].vdmasrc = START_ADDR(src_va, i, uint8_t *);
			jobs[i].vdmadst = START_ADDR(dst_va, i, uint8_t *);
			dmasrc_last = jobs[i].vdmasrc + dma_len - 1;
			dmadst_last = jobs[i].vdmadst + dma_len - 1;
		}
		if (cpu_len > 0) {
			jobs[i].vcpusrc = START_ADDR(src_va, i, uint8_t *) +
				dma_len;
			jobs[i].vcpudst = START_ADDR(dst_va, i, uint8_t *) +
				dma_len;
			cpusrc_last = jobs[i].vcpusrc + cpu_len - 1;
			cpudst_last = jobs[i].vcpudst + cpu_len - 1;
		}

		jobs[i].dma_len = dma_len;
		jobs[i].cpu_len = cpu_len;
		jobs[i].idx = i;
		if (g_latency || g_silent) {
			if (dmasrc_last && dmadst_last) {
				*dmasrc_last = LATENCY_TEST_SRC_DATA;
				*dmadst_last = LATENCY_TEST_DST_DATA;
			}
			if (cpusrc_last && cpudst_last) {
				*cpusrc_last = LATENCY_TEST_SRC_DATA;
				*cpudst_last = LATENCY_TEST_DST_DATA;
			}
			rte_wmb();
			rte_rmb();
		}
	}

	return 0;
err_free:
	if (g_memz_src[lcore_id]) {
		rte_memzone_free(g_memz_src[lcore_id]);
		g_memz_src[lcore_id] = NULL;
	}
	if (g_memz_dst[lcore_id]) {
		rte_memzone_free(g_memz_dst[lcore_id]);
		g_memz_dst[lcore_id] = NULL;
	}
	if (g_dma_idx[lcore_id]) {
		rte_free(g_dma_idx[lcore_id]);
		g_dma_idx[lcore_id] = NULL;
	}

	return ret;
}

static int
qdma_demo_job_ring_init(uint32_t max_desc)
{
	uint32_t lcore_id, cores = core_count, i, idx = 0;
	char nm[RTE_MEMZONE_NAMESIZE];
	struct dma_job *job;
	int ret;
	uint64_t core_size = g_packet_num * g_packet_elem_size;
	uint64_t pci_iova = RTE_BAD_IOVA;
	uint64_t pci_src_iova = RTE_BAD_IOVA, pci_dst_iova = RTE_BAD_IOVA;
	char *pci_vir = NULL;
	char *pci_src_vir = NULL, *pci_dst_vir = NULL;

	if (g_test_path != MEM_TO_MEM && g_pci_phy == RTE_BAD_IOVA) {
		RTE_LOG(ERR, qdma_demo,
			"PCIe addree unavailable for test path(%d)\n",
			g_test_path);
		return -EINVAL;
	}

	if (g_test_path != MEM_TO_MEM) {
		if (g_pci_vir) {
			pci_vir = g_pci_vir;
		} else {
			if (g_pci_phy == RTE_BAD_IOVA) {
				RTE_LOG(ERR, qdma_demo,
					"PCIe addree unavailable for test path(%d)\n",
					g_test_path);
				return -EINVAL;
			}
			pci_vir = pci_addr_mmap(NULL, g_pci_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				g_pci_phy, NULL, NULL);
		}
		if (!pci_vir) {
			RTE_LOG(ERR, qdma_demo,
				"Failed to mmap PCI addr %lx\n",
				g_pci_phy);
			return -ENOMEM;
		}
		if (g_pci_ep) {
			if (g_pci_ep_rbp)
				pci_iova = g_pci_bus;
			else
				pci_iova = g_pci_phy;
		} else {
			if (rte_eal_iova_mode() == RTE_IOVA_PA)
				pci_iova = g_pci_phy;
			else
				pci_iova = (uint64_t)pci_vir;
			ret = rte_fslmc_vfio_mem_dmamap((uint64_t)pci_vir,
				pci_iova, g_pci_size);
			if (ret) {
				RTE_LOG(ERR, qdma_demo,
					"VFIO map failed(%d)\n", ret);
				return ret;
			}
		}
	}

	if (g_test_path == MEM_TO_PCI) {
		pci_dst_iova = pci_iova;
		pci_dst_vir = pci_vir;
		core_size = g_pci_size / (core_count - 1);
		g_packet_num = core_size / g_packet_elem_size;
		if (g_packet_num > max_desc) {
			g_packet_num = max_desc;
			core_size = g_packet_num * g_packet_elem_size;
		}
	} else if (g_test_path == PCI_TO_MEM) {
		pci_src_iova = pci_iova;
		pci_src_vir = pci_vir;
		core_size = g_pci_size / (core_count - 1);
		g_packet_num = core_size / g_packet_elem_size;
		if (g_packet_num > max_desc) {
			g_packet_num = max_desc;
			core_size = g_packet_num * g_packet_elem_size;
		}
	} else if (g_test_path == PCI_TO_PCI) {
		pci_src_iova = pci_iova;
		pci_src_vir = pci_vir;
		pci_dst_iova = pci_src_iova + g_pci_size / 2;
		pci_dst_vir = pci_src_vir + g_pci_size / 2;
		core_size = g_pci_size / 2 / (core_count - 1);
		g_packet_num = core_size / g_packet_elem_size;
		if (g_packet_num > max_desc) {
			g_packet_num = max_desc;
			core_size = g_packet_num * g_packet_elem_size;
		}
	} else {
		if (g_packet_num > max_desc)
			g_packet_num = max_desc;
		core_size = g_packet_num * g_packet_elem_size;
	}

	if (g_packet_num < g_burst)
		g_burst = g_packet_num;

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (cores == 1)
			break;
		cores--;
		sprintf(nm, "job-ring-%d", lcore_id);
		g_job_ring[lcore_id] = rte_ring_create(nm,
			g_packet_num * 2, 0, 0);
		if (!g_job_ring[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"job ring created failed on core%d\n",
				lcore_id);
			return -ENOMEM;
		}
		g_jobs[lcore_id] = rte_zmalloc("test qdma",
			g_packet_num * sizeof(struct dma_job),
			RTE_CACHE_LINE_SIZE);
		if (!g_jobs[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"jobs created failed on core%d\n",
				lcore_id);
			return -ENOMEM;
		}

		ret = qdma_demo_jobs_init(g_jobs[lcore_id], lcore_id,
			pci_src_iova == RTE_BAD_IOVA ?
			RTE_BAD_IOVA :
			pci_src_iova + idx * core_size,
			pci_dst_iova == RTE_BAD_IOVA ?
			RTE_BAD_IOVA :
			pci_dst_iova + idx * core_size,
			pci_src_vir == NULL ?
			NULL : pci_src_vir + idx * core_size,
			pci_dst_vir == NULL ?
			NULL : pci_dst_vir + idx * core_size,
			core_size, g_packet_num,
			g_packet_dma_size, g_packet_cpu_size);
		if (ret)
			return ret;

		job = g_jobs[lcore_id];
		for (i = 0; i < g_packet_num; i++) {
			ret = rte_ring_enqueue(g_job_ring[lcore_id], job);
			if (ret) {
				RTE_LOG(ERR, qdma_demo,
					"eq job[%d] failed on core%d, err(%d)\n",
					i, lcore_id, ret);
				return ret;
			}
			job++;
		}

		idx++;
	}

	return 0;
}

static int
lcore_qdma_control_loop(void)
{
	unsigned int lcore_id;
	struct rte_dma_vchan_conf conf;
	struct rte_dma_info info;
	uint64_t diff;
	uint64_t cycle1 = 0, cycle2 = 0, cycle_diff;
	float speed;
	int ret, offset, log_len;
	uint32_t i;
	char perf_buf[1024];

	lcore_id = rte_lcore_id();

	/* wait synchro for slaves */
	memset(&info, 0, sizeof(struct rte_dma_info));
	if (g_test_mode & QDMA_DEMO_DMA_MODE) {
		ret = test_dma_init(&info);
		if (ret)
			return ret;
		memset(&conf, 0, sizeof(struct rte_dma_vchan_conf));

		if (g_test_path == MEM_TO_PCI &&
			g_pci_ep && g_pci_ep_rbp) {
			conf.direction = RTE_DMA_DIR_MEM_TO_DEV;
			conf.nb_desc = info.max_desc;
			conf.src_port.port_type = RTE_DMA_PORT_NONE;
			conf.dst_port.port_type = RTE_DMA_PORT_PCIE;
			conf.dst_port.pcie.coreid = g_pci_ep_pci_id;
			conf.dst_port.pcie.pfid = g_pci_ep_pf_id;
			conf.dst_port.pcie.vfen = g_pci_ep_is_vf;
			if (g_pci_ep_is_vf)
				conf.dst_port.pcie.vfid = g_pci_ep_vf_id;
		} else if (g_test_path == PCI_TO_MEM &&
			g_pci_ep && g_pci_ep_rbp) {
			conf.direction = RTE_DMA_DIR_DEV_TO_MEM;
			conf.nb_desc = info.max_desc;
			conf.src_port.port_type = RTE_DMA_PORT_PCIE;
			conf.dst_port.port_type = RTE_DMA_PORT_NONE;
			conf.src_port.pcie.coreid = g_pci_ep_pci_id;
			conf.src_port.pcie.pfid = g_pci_ep_pf_id;
			conf.src_port.pcie.vfen = g_pci_ep_is_vf;
			if (g_pci_ep_is_vf)
				conf.src_port.pcie.vfid = g_pci_ep_vf_id;
		} else if (g_test_path == PCI_TO_PCI &&
			g_pci_ep && g_pci_ep_rbp) {
			conf.direction = RTE_DMA_DIR_DEV_TO_DEV;
			conf.nb_desc = info.max_desc;
			conf.src_port.port_type = RTE_DMA_PORT_PCIE;
			conf.dst_port.port_type = RTE_DMA_PORT_PCIE;
			conf.src_port.pcie.coreid = g_pci_ep_pci_id;
			conf.src_port.pcie.pfid = g_pci_ep_pf_id;
			conf.src_port.pcie.vfen = g_pci_ep_is_vf;
			if (g_pci_ep_is_vf)
				conf.src_port.pcie.vfid = g_pci_ep_vf_id;
			conf.dst_port.pcie.coreid = g_pci_ep_pci_id;
			conf.dst_port.pcie.pfid = g_pci_ep_pf_id;
			conf.dst_port.pcie.vfen = g_pci_ep_is_vf;
			if (g_pci_ep_is_vf)
				conf.dst_port.pcie.vfid = g_pci_ep_vf_id;
		} else {
			conf.direction = RTE_DMA_DIR_MEM_TO_MEM;
			conf.nb_desc = info.max_desc;
			conf.src_port.port_type = RTE_DMA_PORT_NONE;
			conf.dst_port.port_type = RTE_DMA_PORT_NONE;
		}

		for (i = 0; i < RTE_MAX_LCORE; i++) {
			if (!rte_lcore_is_enabled(i))
				continue;

			g_vqid[i] = i;
			ret = rte_dma_vchan_setup(qdma_dev_id, g_vqid[i],
					&conf);
			if (ret) {
				RTE_LOG(ERR, qdma_demo,
					"Vchan setup failed(%d)\n", ret);
				return ret;
			}
		}

		ret = rte_dma_start(qdma_dev_id);
		if (ret) {
			RTE_LOG(ERR, qdma_demo, "Failed to start DMA[%d](%d)\n",
				qdma_dev_id, ret);
			return ret;
		}
	}

	ret = qdma_demo_job_ring_init(info.max_desc > 0 ?
			info.max_desc : 4096);
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "Failed to init job ring(%d)\n",
			ret);
		return ret;
	}

	switch (g_test_path) {
	case PCI_TO_MEM:
		RTE_LOG(INFO, qdma_demo, "PCI_TO_MEM\n");
		break;
	case MEM_TO_PCI:
		RTE_LOG(INFO, qdma_demo, "MEM_TO_PCI\n");
		break;
	case MEM_TO_MEM:
		RTE_LOG(INFO, qdma_demo, "MEM_TO_MEM\n");
		break;
	case PCI_TO_PCI:
		RTE_LOG(INFO, qdma_demo, "PCI_TO_PCI\n");
		break;
	default:
		RTE_LOG(INFO, qdma_demo, "unknown test case!\n");
	}
	RTE_LOG(INFO, qdma_demo,
		"Master coreid: %d ready, now!\n", lcore_id);

	rte_atomic32_set(&synchro, 1);

	while (!quit_signal) {
		if (g_seg_iova) {
			rte_delay_ms(1);
			continue;
		}
		cycle1 = rte_get_timer_cycles();
		rte_delay_ms(4000);
		diff = 0;

		if (g_latency)
			goto skip_print;

		cycle2 = rte_get_timer_cycles();
		cycle_diff = cycle2 - cycle1;
		for (i = 0; i < RTE_MAX_LCORE; i++) {
			diff += g_dq_num[i] - g_dq_num_last[i];
			g_dq_num_last[i] = g_dq_num[i];
		}

		offset = 0;

		log_len = sprintf(&perf_buf[offset], "Statistics:\n");
		offset += log_len;

		log_len = sprintf(&perf_buf[offset],
			"Time Spend :%.3f ms rcvd cnt:%ld\n",
			(s_ns_per_cyc * cycle_diff) / NS_PER_MS,
			diff);
		offset += log_len;

		if (g_packet_dma_size > 0) {
			speed = (float)diff /
				(s_ns_per_cyc * cycle_diff / NS_PER_S);
			speed = speed * g_packet_dma_size;

			log_len = sprintf(&perf_buf[offset],
				"DMA Rate: %.3f Mbps OR %.3f Kpps\n",
				8 * speed / NS_PER_MS,
				speed / (g_packet_dma_size * 1000));
			offset += log_len;
		}

		if (g_packet_cpu_size > 0) {
			speed = (float)diff /
				(s_ns_per_cyc * cycle_diff / NS_PER_S);
			speed = speed * g_packet_cpu_size;

			log_len = sprintf(&perf_buf[offset],
				"CPU Rate: %.3f Mbps OR %.3f Kpps\n",
				8 * speed / NS_PER_MS,
				speed / (g_packet_cpu_size * 1000));
			offset += log_len;
		}

		RTE_LCORE_FOREACH_WORKER(lcore_id) {
			log_len = sprintf(&perf_buf[offset],
				"processed on core %d pkt cnt: %ld\n",
				lcore_id, g_dq_num[lcore_id]);
			offset += log_len;
		}
		log_len = sprintf(&perf_buf[offset], "\n");
		offset += log_len;
		RTE_LOG(INFO, qdma_demo, "%s", perf_buf);

skip_print:
		cycle1 = cycle2 = 0;
	}
	RTE_LOG(INFO, qdma_demo, "exit core %d\n", rte_lcore_id());

	return 0;
}

/* launch all the per-lcore test, and display the result */
static int
launch_cores(unsigned int cores)
{
	unsigned lcore_id;
	int ret;
	unsigned cores_save = cores;

	rte_atomic32_set(&synchro, 0);

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (cores == 1)
			break;
		cores--;
		rte_eal_remote_launch(lcore_qdma_process_loop, NULL, lcore_id);
	}

	/* start synchro and launch test on master */
	ret = lcore_qdma_control_loop();
	if (ret < 0)
		return ret;
	cores = cores_save;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (cores == 1)
			break;
		cores--;

		ret = rte_eal_wait_lcore(lcore_id);
		if (ret < 0)
			break;
	}

	if (ret < 0) {
		RTE_LOG(ERR, qdma_demo, "per-lcore test error(%d)\n", ret);
		return ret;
	}

	return 0;
}

static void
int_handler(int sig_num)
{
	RTE_LOG(INFO, qdma_demo, "Exiting on signal %d\n", sig_num);
	/* set quit flag for rx thread to exit */
	quit_signal = 1;
}

static uint64_t
get_tsc_freq_from_cpuinfo(void)
{
	char line[256];
	FILE *stream;
	double dmhz;
	uint64_t freq = 0;

	stream = fopen(CPU_INFO_FREQ_FILE, "r");
	if (!stream) {
		RTE_LOG(WARNING, qdma_demo,
			"WARNING: Unable to open %s\n",
			CPU_INFO_FREQ_FILE);
		return 0;
	}

	while (fgets(line, sizeof line, stream)) {
		if (sscanf(line, "%lf", &dmhz) == 1) {
			freq = (uint64_t)(dmhz / 1000);
			break;
		}
	}

	fclose(stream);
	return freq;
}

static void qdma_demo_usage(void)
{
	size_t i;
	char buf[4096];
	int pos = 0, j;

	j = sprintf(&buf[pos],
		"./qdma_demo [EAL options] -- -option --<args>=<value>\n");
	pos += j;
	j = sprintf(&buf[pos], "options	:\n");
	pos += j;
	j = sprintf(&buf[pos], "	: -c <hex core mask>\n");
	pos += j;
	j = sprintf(&buf[pos], "	: -h print usage\n");
	pos += j;
	j = sprintf(&buf[pos], "Args	:\n");
	pos += j;
	j = sprintf(&buf[pos], ": --pci_addr=<hex pci start addr>\n");
	pos += j;
	j = sprintf(&buf[pos], ": --pci_size=<hex pci space size>\n");
	pos += j;
	j = sprintf(&buf[pos], ": --packet_size=<bytes>\n");
	pos += j;
	j = sprintf(&buf[pos], ": --test_case=<test_case_name>\n");
	pos += j;
	for (i = 0; i < ARRAY_SIZE(s_test_case); i++) {
		j = sprintf(&buf[pos], "	%s - %s\n",
			s_test_case[i].name, s_test_case[i].help);
		pos += j;
	}
	j = sprintf(&buf[pos], ": --latency_test\n");
	pos += j;
	j = sprintf(&buf[pos], ": --sg\n");
	pos += j;
	j = sprintf(&buf[pos], ": --burst\n");
	pos += j;
	j = sprintf(&buf[pos], ": --packet_num=<number>\n");
	pos += j;
	j = sprintf(&buf[pos], ": --validate\n");
	pos += j;
	j = sprintf(&buf[pos], ": --seg_iova\n");
	pos += j;
	j = sprintf(&buf[pos], ": --pci_ep\n");
	pos += j;
	j = sprintf(&buf[pos], ": --pci_ep_rbp\n");
	pos += j;
	j = sprintf(&buf[pos], ": --silent\n");
	pos += j;
	j = sprintf(&buf[pos], ": --dma_latency\n");
	pos += j;
	j = sprintf(&buf[pos], ": --test_mode=<test_mode_name>\n");
	pos += j;
	for (i = 0; i < ARRAY_SIZE(s_test_mode); i++) {
		j = sprintf(&buf[pos], "	%s\n",
			s_test_mode[i].name);
		pos += j;
	}
	pos += j;
	j = sprintf(&buf[pos], ": --cpu_packet_size=<bytes>\n");

	RTE_LOG(WARNING, qdma_demo, "%s", buf);
}

static int
qdma_parse_long_arg(char *optarg, struct option *lopt)
{
	int ret = 0;
	size_t i;

	switch (lopt->val) {
	case ARG_PCI_ADDR:
		ret = sscanf(optarg, "%lx", &g_pci_phy);
		if (ret != 1) {
			RTE_LOG(ERR, qdma_demo, "Invalid PCI address\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "PCI addr %lx\n", g_pci_phy);
		break;
	case ARG_PCI_EP:
		g_pci_ep = 1;
		RTE_LOG(INFO, qdma_demo, "PCI EP test\n");
		break;
	case ARG_PCI_EP_RBP:
		g_pci_ep_rbp = 1;
		RTE_LOG(INFO, qdma_demo, "PCI EP RBP mode\n");
		break;
	case ARG_SILENT:
		g_silent = 1;
		RTE_LOG(INFO, qdma_demo, "DMA silent mode\n");
		break;
	case ARG_PCI_SIZE:
		ret = sscanf(optarg, "%lx", &g_pci_size);
		if (ret != 1) {
			RTE_LOG(ERR, qdma_demo, "Invalid PCI size\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "PCI size %ld\n", g_pci_size);
		break;
	case ARG_SIZE:
		ret = sscanf(optarg, "%ld", &g_packet_dma_size);
		if (ret != 1) {
			RTE_LOG(ERR, qdma_demo, "Invalid DMA Packet size\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "DMA Pkt size %ld\n",
			g_packet_dma_size);
		break;
	case ARG_CPU_SIZE:
		ret = sscanf(optarg, "%ld", &g_packet_cpu_size);
		if (ret != 1) {
			RTE_LOG(ERR, qdma_demo, "Invalid SW Packet size\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "SW Pkt size %ld, elem size %ld\n",
			g_packet_cpu_size, g_packet_elem_size);
		break;
	case ARG_TEST_ID:
		for (i = 0; i < ARRAY_SIZE(s_test_case); i++) {
			ret = strncmp(s_test_case[i].name, optarg,
				TEST_ARG_NAME_SIZE);
			if (!ret) {
				g_test_path = s_test_case[i].id;
				break;
			}
		}
		if (i == ARRAY_SIZE(s_test_case)) {
			RTE_LOG(ERR, qdma_demo, "Invalid test case\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "test case %s\n", s_test_case[i].name);
		break;
	case ARG_LATENCY:
		g_latency = 1;
		RTE_LOG(INFO, qdma_demo, "Latency test mode\n");
		break;
	case ARG_DMA_LATENCY:
		g_dma_prep_latency = 1;
		RTE_LOG(INFO, qdma_demo, "DMA prepare latency included\n");
		break;
	case ARG_TEST_MODE:
		for (i = 0; i < ARRAY_SIZE(s_test_mode); i++) {
			ret = strncmp(s_test_mode[i].name, optarg,
				TEST_ARG_NAME_SIZE);
			if (!ret) {
				g_test_mode = s_test_mode[i].id;
				break;
			}
		}
		if (i == ARRAY_SIZE(s_test_mode)) {
			RTE_LOG(ERR, qdma_demo, "Invalid test mode\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "test mode %s\n", s_test_mode[i].name);
		break;
	case ARG_SCATTER_GATHER:
		g_scatter_gather = 1;
		RTE_LOG(INFO, qdma_demo, "qdma scatter gather mode\n");
		break;
	case ARG_BURST:
		ret = sscanf(optarg, "%u", &g_burst);
		if (ret != 1) {
			RTE_LOG(ERR, qdma_demo, "Invalid burst size\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		if (g_burst > BURST_NB_MAX || g_burst < 1)
			g_burst = BURST_NB_MAX;

		RTE_LOG(INFO, qdma_demo, "burst size %u\n", g_burst);
		break;
	case ARG_NUM:
		ret = sscanf(optarg, "%d", &g_packet_num);
		if (ret != 1) {
			RTE_LOG(ERR, qdma_demo, "Invalid Packet number\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "Pkt num %d\n", g_packet_num);
		break;
	case ARG_VALIDATE:
		g_validate = 1;
		RTE_LOG(INFO, qdma_demo, "Validate data transfer\n");
		break;
	case ARG_SEG_IOVA:
		g_seg_iova = 1;
		RTE_LOG(INFO, qdma_demo, "IOVA segments test\n");
		break;
	default:
		RTE_LOG(ERR, qdma_demo, "Unknown Argument\n");
		ret = -EINVAL;
		qdma_demo_usage();
		goto out;
	}

	g_arg_mask |= lopt->val;
out:
	return ret;
}

static int
qdma_demo_parse_args(int argc, char **argv)
{
	int opt, ret = 0, flg, option_index;
	struct option lopts[] = {
		{"pci_addr", optional_argument, &flg, ARG_PCI_ADDR},
		{"pci_size", optional_argument, &flg, ARG_PCI_SIZE},
		{"packet_size", optional_argument, &flg, ARG_SIZE},
		{"cpu_packet_size", optional_argument, &flg, ARG_CPU_SIZE},
		{"test_case", required_argument, &flg, ARG_TEST_ID},
		{"latency_test", optional_argument, &flg, ARG_LATENCY},
		{"dma_latency", optional_argument, &flg, ARG_DMA_LATENCY},
		{"test_mode", optional_argument, &flg, ARG_TEST_MODE},
		{"sg", optional_argument, &flg, ARG_SCATTER_GATHER},
		{"burst", optional_argument, &flg, ARG_BURST},
		{"packet_num", optional_argument, &flg, ARG_NUM},
		{"validate", optional_argument, &flg, ARG_VALIDATE},
		{"seg_iova", optional_argument, &flg, ARG_SEG_IOVA},
		{"pci_ep", optional_argument, &flg, ARG_PCI_EP},
		{"pci_ep_rbp", optional_argument, &flg, ARG_PCI_EP_RBP},
		{"silent", optional_argument, &flg, ARG_SILENT},
		{0, 0, 0, 0},
	};
	struct option *lopt_cur;

	while ((opt = getopt_long(argc, argv, "h;",
				lopts, &option_index)) != EOF) {

		switch (opt) {
		case 'h':
			qdma_demo_usage();
			ret = 1;
			break;
		/* long options */
		case 0:
			lopt_cur = &lopts[option_index];
			ret = qdma_parse_long_arg(optarg, lopt_cur);
			if (ret)
				return ret;
			break;
		default:
			qdma_demo_usage();
			ret = -EINVAL;
		}
	}

	return ret;
}

/*Return 0 if arguments are valid, 1 otherwise */
static int qdma_demo_validate_args(void)
{
	int valid = 1;
	uint64_t size = 0;

	if (g_test_path != MEM_TO_MEM && !g_pci_ep)
		valid = !!(g_arg_mask & ARG_PCI_ADDR);

	if (!(g_arg_mask & ARG_SIZE)) {
		RTE_LOG(WARNING, qdma_demo,
			"Using Default packet size %ld bytes\n",
			g_packet_dma_size);
	}

	core_count = rte_lcore_count();
	if (core_count < 2) {
		RTE_LOG(ERR, qdma_demo, "Insufficient cores %d < 2\n",
			core_count);
		valid = 0;
		goto out;
	}

	if (!(g_test_mode & QDMA_DEMO_DMA_MODE))
		g_packet_dma_size = 0;
	if (!(g_test_mode & QDMA_DEMO_CPU_MODE))
		g_packet_cpu_size = 0;

	if (g_test_mode & QDMA_DEMO_DMA_MODE)
		size += g_packet_dma_size;
	if (g_test_mode & QDMA_DEMO_CPU_MODE)
		size += g_packet_cpu_size;

	g_packet_elem_size = qdma_demo_roundup_pow_of_two(size);
	RTE_LOG(INFO, qdma_demo, "Pkt element size %ld\n",
		g_packet_elem_size);

	RTE_LOG(INFO, qdma_demo, "Stats core id - %d\n",
		rte_get_main_lcore());
out:
	return !valid;
}

int
main(int argc, char *argv[])
{
	int ret = 0;
	uint64_t freq;
	float ns_per_cyc, rate;
	uint64_t start_cycles, end_cycles, pci_size;
	uint64_t time_diff;
	uint16_t portid;

	/* catch ctrl-c so we can print on exit */
	signal(SIGINT, int_handler);

	rte_atomic32_init(&synchro);

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	argc -= ret;
	argv += ret;

	ret = qdma_demo_parse_args(argc, argv);
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "Arg parsing failed(%d)\n", ret);
		goto out;
	}
	ret = qdma_demo_validate_args();
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "Arguments are invalid(%d)\n", ret);
		qdma_demo_usage();
		goto out;
	}

	if (g_pci_ep) {
		char pci_ep_port[128];
		char pci_ep_ob[128];

		ret = -EPERM;
		RTE_ETH_FOREACH_DEV(portid) {
			struct rte_eth_dev *dev;
			struct rte_eth_dev_info dev_info;
			struct rte_eth_conf local_port_conf;

			rte_memcpy(&local_port_conf, &port_conf,
				sizeof(struct rte_eth_conf));
			memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));

			ret = rte_eth_dev_info_get(portid, &dev_info);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Error during getting device (port %u) info: %s\n",
					portid, strerror(-ret));

			local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
				dev_info.flow_type_rss_offloads;

			ret = rte_eth_dev_configure(portid,
				1, 1, &local_port_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					"Cannot configure device: err=%d, port=%d\n",
					ret, portid);

			dev = &rte_eth_devices[portid];
			ret = rte_lsinic_dev_start_poll_rc(dev);
			if (!ret)
				RTE_LOG(INFO, qdma_demo,
					"%s starts poll RC\n",
					dev->data->name);
		}
		if (ret) {
			RTE_LOG(ERR, qdma_demo,
				"No PCIe EP port found\n");

			return 0;
		}

		while (1) {
			if (quit_signal)
				return 0;
			sleep(2);
			RTE_ETH_FOREACH_DEV(portid) {
				struct rte_eth_dev *dev;

				dev = &rte_eth_devices[portid];
				ret = rte_lsinic_dev_get_rc_dma(dev, &g_pci_vir,
					&g_pci_phy, &g_pci_bus, &g_pci_size,
					&g_pci_ep_pci_id, &g_pci_ep_pf_id,
					&g_pci_ep_is_vf, &g_pci_ep_vf_id);
				if (!ret && g_pci_size > 0)
					break;
			}
			if (g_pci_phy != RTE_BAD_IOVA && g_pci_phy)
				break;
			RTE_LOG(INFO, qdma_demo,
				"Waiting for loading RC driver\n");
		}

		if (!g_pci_ep_is_vf) {
			sprintf(pci_ep_port, "pci%d, pf%d",
				g_pci_ep_pci_id, g_pci_ep_pf_id);
		} else {
			sprintf(pci_ep_port, "pci%d, pf%d-vf%d",
				g_pci_ep_pci_id, g_pci_ep_pf_id,
				g_pci_ep_vf_id);
		}

		sprintf(pci_ep_ob,
			"phy(%lx), size(%lx), bus(%lx) vir(%p)",
			g_pci_phy, g_pci_size, g_pci_bus, g_pci_vir);

		RTE_LOG(INFO, qdma_demo,
			"PCIe EP: %s from %s\n", pci_ep_ob, pci_ep_port);
	}

	if (g_test_path != MEM_TO_MEM) {
		if (g_pci_phy == RTE_BAD_IOVA) {
			RTE_LOG(ERR, qdma_demo,
				"No PCIe address set for %s(%d)!\n",
				g_test_path == MEM_TO_PCI ? "mem2pci" :
				g_test_path == PCI_TO_MEM ? "pci2mem" :
				g_test_path == PCI_TO_PCI ? "pci2pci" :
				"invalid path", g_test_path);

			return 0;
		}
		if (!g_pci_ep) {
			pci_size = pci_find_bar_available_size(g_pci_phy);
			if (!pci_size) {
				RTE_LOG(ERR, qdma_demo,
					"PCI address 0x%lx not found for %s(%d)!\n",
					g_pci_phy,
					g_test_path == MEM_TO_PCI ? "mem2pci" :
					g_test_path == PCI_TO_MEM ? "pci2mem" :
					g_test_path == PCI_TO_PCI ? "pci2pci" :
					"invalid path", g_test_path);

				return 0;
			}
			if (pci_size < g_pci_size || !g_pci_size)
				g_pci_size = pci_size;
		}
		if (g_pci_phy & RTE_CACHE_LINE_MASK) {
			RTE_LOG(ERR, qdma_demo,
				"PCI addr(%lx) not multiple of cache size\n",
				g_pci_phy);
			return 0;
		}
		if (g_pci_size & RTE_CACHE_LINE_MASK) {
			RTE_LOG(ERR, qdma_demo,
				"PCI size(%lx) not multiple of cache size\n",
				g_pci_size);
			return 0;
		}
	}

	/*cycle correction */
	freq = get_tsc_freq_from_cpuinfo();

	ns_per_cyc = (float)1000 / (float)freq;
	start_cycles = rte_get_timer_cycles();
	rte_delay_ms(1000);
	end_cycles = rte_get_timer_cycles();
	time_diff = end_cycles - start_cycles;
	rate = (1000) / ((ns_per_cyc * time_diff) / NS_PER_MS);
	s_ns_per_cyc = (NS_PER_US * rate) / freq;
	RTE_LOG(INFO, qdma_demo,
		"Rate:%.5f cpu freq:%ld MHz, ns per cyc: %.5f\n",
		rate, freq, s_ns_per_cyc);

	start_cycles = rte_get_timer_cycles();
	rte_delay_ms(2000);
	end_cycles = rte_get_timer_cycles();
	time_diff = end_cycles - start_cycles;

	RTE_LOG(INFO, qdma_demo, "Spend :%.3f ms, cyc diff:%ld\n",
		(s_ns_per_cyc * time_diff), time_diff);

	ret = launch_cores(core_count);
	if (ret < 0)
		goto out;
	RTE_LOG(INFO, qdma_demo, "qdma_demo Finished.. bye!\n");
	return 0;
out:
	RTE_LOG(ERR, qdma_demo, "qdma_demo Failed!\n");
	return 0;
}
