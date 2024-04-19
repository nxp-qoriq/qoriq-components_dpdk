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
#include <rte_pmd_dpaax_qdma.h>
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

enum qdma_demo_validate_mode {
	QDMA_DEMO_NO_VALIDATE = 0,
	QDMA_DEMO_FULL_VALIDATE = 1,
	QDMA_DEMO_LAST_BYTE_VALIDATE = 2,
};

struct qdma_demo_latency {
	double min;
	double max;
	double total;
	int count;
};
static struct qdma_demo_latency latency_data[RTE_MAX_LCORE];

static struct qdma_test_case s_test_case[] = {
	{"mem_to_mem", "DDR to DDR", MEM_TO_MEM},
	{"mem_to_pci", "DDR to PCI", MEM_TO_PCI},
	{"pci_to_mem", "PCI to DDR", PCI_TO_MEM},
	{"pci_to_pci", "PCI to PCI", PCI_TO_PCI},
};

static struct qdma_test_mode s_test_mode[] = {
	{"dma_mode", QDMA_DEMO_DMA_MODE},
	{"cpu_mode", QDMA_DEMO_CPU_MODE},
	{"mix_mode", QDMA_DEMO_DMA_MODE | QDMA_DEMO_CPU_MODE},
};

static int s_opt_val;
static const struct option s_lopts[] = {
	{"pci_addr", required_argument, &s_opt_val, ARG_PCI_ADDR},
	{"pci_size", required_argument, &s_opt_val, ARG_PCI_SIZE},
	{"packet_size", required_argument, &s_opt_val, ARG_SIZE},
	{"cpu_packet_size", required_argument, &s_opt_val, ARG_CPU_SIZE},
	{"test_case", required_argument, &s_opt_val, ARG_TEST_ID},
	{"latency_test", optional_argument, &s_opt_val, ARG_LATENCY},
	{"dma_latency", optional_argument, &s_opt_val, ARG_DMA_LATENCY},
	{"test_mode", required_argument, &s_opt_val, ARG_TEST_MODE},
	{"sg", optional_argument, &s_opt_val, ARG_SCATTER_GATHER},
	{"burst", required_argument, &s_opt_val, ARG_BURST},
	{"validate", optional_argument, &s_opt_val, ARG_VALIDATE},
	{"seg_iova", optional_argument, &s_opt_val, ARG_SEG_IOVA},
	{"pci_ep", optional_argument, &s_opt_val, ARG_PCI_EP},
	{"pci_dma_rbp", optional_argument, &s_opt_val, ARG_PCI_DMA_RBP},
	{"silent", optional_argument, &s_opt_val, ARG_SILENT},
	{0, 0, 0, 0},
};

static const char * const s_lopts_help[] = {
	"<hex pci start addr>",
	"<hex pci size>",
	"<bytes>",
	"<bytes>",
	"[mem_to_mem], [mem_to_pci], [pci_to_mem], [pci_to_pci]",
	"",
	"",
	"[dma_mode], [cpu_mode], [mix_mode]",
	"",
	"<burst number>",
	"",
	"",
	"",
	"",
	""
};

static uint64_t g_mem_zone_size = (128 * 1024 * 1024);

/*Configurable options*/
static uint32_t g_burst = BURST_NB_MAX;
static uint64_t g_pci_phy = RTE_BAD_IOVA;
static uint64_t g_packet_dma_size = 1024;
static uint64_t g_packet_cpu_size = 64;
static uint64_t g_pci_size;
static uint64_t g_pci_bus = RTE_BAD_IOVA;
static void *g_pci_vir;
static char *g_test_case_str;

static int g_latency;
static int g_test_mode = QDMA_DEMO_DMA_MODE;
static int g_validate = QDMA_DEMO_NO_VALIDATE;
static int g_seg_iova;
static int g_scatter_gather;
static int g_silent;
static int g_dma_prep_latency;

static int g_pci_ep;
static int g_pci_dma_rbp;
static int g_pci_ep_pci_id;
static int g_pci_ep_pf_id;
static int g_pci_ep_vf_id;
static int g_pci_ep_is_vf;

static const struct rte_memzone *g_memz;

static uint8_t quit_signal;

static int TEST_DMA_INIT_FLAG;
#define LATENCY_TEST_SRC_DATA 1
#define LATENCY_TEST_DST_DATA 0

#define START_ADDR(base, num, type, elem_size) \
	((type)((uint64_t)base + (elem_size) * (num)))

struct qdma_demo_pci_bar {
	uint64_t phy_start[PCI_MAX_RESOURCE];
	uint64_t len[PCI_MAX_RESOURCE];
};

#define QDMA_DEMO_MAX_PCI_DEV 64
static struct qdma_demo_pci_bar g_pci_bar[QDMA_DEMO_MAX_PCI_DEV];

static int s_flags_cntx;

struct qdma_demo_core_cfg {
	int test_case;
	const char *test_case_nm;
	uint64_t pci_src;
	uint64_t pci_src_len;
	uint64_t pci_dst;
	uint64_t pci_dst_len;
	uint64_t mem_src;
	uint64_t mem_src_len;
	uint64_t mem_dst;
	uint64_t mem_dst_len;

	uint64_t v_pci_src;
	uint64_t v_pci_dst;
	uint64_t v_mem_src;
	uint64_t v_mem_dst;

	struct rte_dma_vchan_conf conf;
	struct rte_ring *job_ring;
	struct dma_job *jobs;
	uint32_t job_num;
	uint16_t *dma_idx;
	uint16_t vq_id;
	uint64_t dma_total_pkts;
	uint64_t dma_total_bytes;
	uint64_t cpu_total_pkts;
	uint64_t cpu_total_bytes;

	uint64_t check_count;
	uint32_t max_check;
};

struct qdma_demo_core_cfg g_core_cfg[RTE_MAX_LCORE];

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
	if (local_dma_info.dev_capa & RTE_DMA_CAPA_DPAAX_QDMA_FLAGS_INDEX)
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

	if (likely(g_validate == QDMA_DEMO_NO_VALIDATE))
		return;

	if (!job->dma_len)
		goto cpu_validate_set;

	if (g_validate == QDMA_DEMO_LAST_BYTE_VALIDATE) {
		*(job->vdmasrc + job->dma_len - 1) = LATENCY_TEST_SRC_DATA;
		*(job->vdmadst + job->dma_len - 1) = LATENCY_TEST_DST_DATA;
		goto cpu_validate_set;
	}

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

	if (g_validate == QDMA_DEMO_LAST_BYTE_VALIDATE) {
		*(job->vcpusrc + job->cpu_len - 1) = LATENCY_TEST_SRC_DATA;
		*(job->vcpudst + job->cpu_len - 1) = LATENCY_TEST_DST_DATA;
		return;
	}

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

#ifndef dccivac
#ifdef RTE_ARCH_ARM64
#define dccivac(p) \
	{ asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#else
#define dccivac(p) { (void)(p); }
#endif
#endif

#define VALIDATE_CHECK_COUNT_MAX 100000

static uint32_t
qdma_demo_validate_check(struct dma_job *job[],
	uint32_t job_num, uint32_t *max_check)
{
	uint32_t i = 0, j = 0, idx, check_count, total = 0, max = 0;
	int dma_err = 0, cpu_err = 0;

	if (likely(g_validate == QDMA_DEMO_NO_VALIDATE))
		return 0;

	if (g_validate == QDMA_DEMO_LAST_BYTE_VALIDATE) {
		for (i = 0; i < job_num; i++) {
			if (!job[i]->dma_len)
				goto cpu_last_byte_validate;
			idx = job[i]->dma_len - 1;
			check_count = 1;
			while (job[i]->vdmasrc[idx] != job[i]->vdmadst[idx]) {
				dccivac(&job[i]->vdmadst[idx]);
				check_count++;
				if (check_count > VALIDATE_CHECK_COUNT_MAX) {
					dma_err = 1;
					goto err_quit;
				}
			}
			if (check_count > max)
				max = check_count;
			total += check_count;

cpu_last_byte_validate:
			if (!job[i]->cpu_len)
				continue;

			idx = job[i]->cpu_len - 1;
			if (job[i]->vcpusrc[idx] != job[i]->vcpudst[idx]) {
				cpu_err = 1;
				goto err_quit;
			}
		}
		goto err_quit;
	}

	for (i = 0; i < job_num; i++) {
		if (!job[i]->dma_len)
			goto cpu_validate;

		for (j = 0; j < job[i]->dma_len; j++) {
			check_count = 1;
			while (job[i]->vdmasrc[j] != job[i]->vdmadst[j]) {
				dccivac(&job[i]->vdmadst[j]);
				check_count++;
				if (check_count > VALIDATE_CHECK_COUNT_MAX) {
					dma_err = 1;
					goto err_quit;
				}
			}
			if (check_count > max)
				max = check_count;
			total += check_count;
		}

cpu_validate:
		if (!job[i]->cpu_len)
			continue;

		for (j = 0; j < job[i]->cpu_len; j++) {
			if (job[i]->vcpusrc[j] != job[i]->vcpudst[j]) {
				cpu_err = 1;
				goto err_quit;
			}
		}
	}

err_quit:
	if (dma_err) {
		rte_exit(EXIT_FAILURE,
			"DMA job[%d]: src(%p)[%d](%d) != dst(%p)[%d](%d)\n",
			job[i]->idx, job[i]->vdmasrc, j,
			job[i]->vdmasrc[j], job[i]->vdmadst,
			j, job[i]->vdmadst[j]);
		return -EINVAL;
	}
	if (cpu_err) {
		rte_exit(EXIT_FAILURE,
			"CPU job[%d]: src(%p)[%d](%d) != dst(%p)[%d](%d)\n",
			job[i]->idx, job[i]->vcpusrc, j,
			job[i]->vcpusrc[j], job[i]->vcpudst,
			j, job[i]->vcpudst[j]);
		return -EINVAL;
	}
	if (max_check)
		*max_check = max;

	return total;
}

static int
qdma_demo_memcpy_process(uint16_t burst_nb,
	struct rte_ring *job_ring)
{
	uint32_t i, lcore_id, eq_ret, job_num;
	uint64_t cycle1, cycle2;
	int ret;
	struct dma_job *job[burst_nb];

	lcore_id = rte_lcore_id();

	job_num = rte_ring_dequeue_bulk(job_ring,
			(void **)job, burst_nb, NULL);

	for (i = 0; i < job_num; i++)
		qdma_demo_validate_set(job[i]);

	cycle1 = rte_get_timer_cycles();
	for (i = 0; i < job_num; i++) {
		rte_memcpy(job[i]->vcpudst,
			job[i]->vcpusrc, job[i]->cpu_len);
		g_core_cfg[lcore_id].cpu_total_pkts++;
		g_core_cfg[lcore_id].cpu_total_bytes +=
			job[i]->cpu_len;
	}
	cycle2 = rte_get_timer_cycles();
	if (g_latency)
		calculate_latency(lcore_id, cycle1, cycle2, job, job_num, 0);

	ret = qdma_demo_validate_check(job, job_num, NULL);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Validate failed\n");
		return ret;
	}
	g_core_cfg[lcore_id].check_count += ret;

	eq_ret = rte_ring_enqueue_bulk(g_core_cfg[lcore_id].job_ring,
			(void **)job, job_num, NULL);
	if (job_num != eq_ret) {
		RTE_LOG(ERR, qdma_demo,
			"memcpy job recycle failed\n");
		rte_exit(EXIT_FAILURE,
			"memcpy job recycle failed\n");
		return -EINVAL;
	}

	return 0;
}

static int
lcore_qdma_iova_seg_to_continue(uint32_t lcore_id)
{
	uint8_t *vir_base, *dst, *src, *vir;
	uint64_t iova_base, src_iova, iova_offset, iova[g_burst];
	int ret = 0;
	uint32_t seg_size, seg_num, total_size, i, j, src_idx;
	uint64_t page_size = sysconf(_SC_PAGESIZE);
	uint16_t vq_id;

	if (!rte_fslmc_bus_available()) {
		RTE_LOG(ERR, qdma_demo,
			"DPAA2 platform support only\n");
		return -ENOTSUP;
	}

	if (rte_eal_iova_mode() != RTE_IOVA_PA) {
		RTE_LOG(ERR, qdma_demo,
			"IOVA PA mode support only\n");
		return -ENOMEM;
	}

	seg_size = g_packet_dma_size;
	vq_id = g_core_cfg[lcore_id].vq_id;

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

	ret = rte_dma_copy(qdma_dev_id, vq_id,
			src_iova, iova_base,
			iova_offset, RTE_DMA_OP_FLAG_SUBMIT);
	if (ret < 0) {
		RTE_LOG(ERR, qdma_demo,
			"DMA copy failed(%d)\n",
			ret);
		goto quit;
	}
	sleep(1);
	ret = rte_dma_completed(qdma_dev_id, vq_id, 1,
			NULL, NULL);
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

static void
qdma_demo_silent_complete_check(uint32_t dq_num,
	struct dma_job *job[], uint32_t *miss_counts)
{
	uint32_t i, miss = 0;
	uint8_t *vsrc, *vdst;

	for (i = 0; i < dq_num; i++) {
		if (!job[i]->dma_len)
			goto cpu_check;

		vsrc = job[i]->vdmasrc + job[i]->dma_len - 1;
		vdst = job[i]->vdmadst + job[i]->dma_len - 1;
		while ((*vsrc) != (*vdst)) {
			miss++;
			dccivac(vdst);
			if (quit_signal)
				break;
		}

cpu_check:
		if (!job[i]->cpu_len)
			continue;

		vsrc = job[i]->vcpusrc + job[i]->cpu_len - 1;
		vdst = job[i]->vcpudst + job[i]->cpu_len - 1;
		while ((*vsrc) != (*vdst)) {
			dccivac(vdst);
			if (quit_signal)
				break;
		}
	}

	if (miss_counts)
		*miss_counts = miss;
}

static void
qdma_demo_silent_complete_recover(uint32_t num,
	struct dma_job *job[])
{
	uint32_t i;
	uint8_t *vsrc, *vdst;

	for (i = 0; i < num; i++) {
		if (!job[i]->dma_len)
			goto cpu_recover;

		vsrc = job[i]->vdmasrc + job[i]->dma_len - 1;
		vdst = job[i]->vdmadst + job[i]->dma_len - 1;
		(*vsrc) = LATENCY_TEST_SRC_DATA;
		(*vdst) = LATENCY_TEST_DST_DATA;

cpu_recover:
		if (!job[i]->cpu_len)
			continue;

		vsrc = job[i]->vcpusrc + job[i]->cpu_len - 1;
		vdst = job[i]->vcpudst + job[i]->cpu_len - 1;
		(*vsrc) = LATENCY_TEST_SRC_DATA;
		(*vdst) = LATENCY_TEST_DST_DATA;
	}
}

static void
qdma_demo_dump_job(struct dma_job *job[],
	uint32_t job_num)
{
	uint32_t i, pos = 0;
	char msg[4096];

	pos += sprintf(&msg[pos], "Dump %d jobs:\n", job_num);
	for (i = 0; i < job_num; i++) {
		pos += sprintf(&msg[pos],
			"job[%d]: src(0x%lx),dst(0x%lx),len(%d),idx(%d)\n",
			i, job[i]->src, job[i]->dest, job[i]->dma_len,
			job[i]->idx);
	}
	RTE_LOG(INFO, qdma_demo, "%s", msg);
}

static int
lcore_qdma_process_throughput(uint16_t burst_nb,
	struct rte_ring *job_ring, uint16_t vq_id,
	struct dma_job *jobs)
{
	struct dma_job *job[burst_nb];
	uint32_t i, j, job_num, lcore_id = rte_lcore_id(), dq_num = 0;
	uint64_t flags;
	bool error = false;
	uint16_t dq_idx[burst_nb];
	int ret;
	uint32_t max;

	job_num = rte_ring_dequeue_bulk(job_ring,
				(void **)job, burst_nb, NULL);
	for (i = 0; i < job_num; i++) {
		qdma_demo_validate_set(job[i]);
		flags = 0;
		if (i == (job_num - 1) && s_flags_cntx)
			flags |= RTE_DPAAX_QDMA_COPY_SUBMIT(job[i]->idx,
					RTE_DMA_OP_FLAG_SUBMIT);
		else if (s_flags_cntx)
			flags |= RTE_DPAAX_QDMA_COPY_SUBMIT(job[i]->idx, 0);
		else if (i == (job_num - 1))
			flags |= RTE_DMA_OP_FLAG_SUBMIT;

		ret = rte_dma_copy(qdma_dev_id,
				vq_id, job[i]->src, job[i]->dest,
				job[i]->dma_len, flags);
		if (ret < 0) {
			qdma_demo_dump_job(job, i + 1);
			rte_exit(EXIT_FAILURE,
				"DMA copy Job[%d](flags=%lx) err(%d)\n",
				i, flags, ret);
		}

		if ((flags & RTE_DMA_OP_FLAG_SUBMIT) &&
			(g_test_mode & QDMA_DEMO_CPU_MODE)) {
			for (j = 0; j < i; j++) {
				rte_memcpy(job[j]->vcpudst,
					job[j]->vcpusrc,
					job[j]->cpu_len);
				g_core_cfg[lcore_id].cpu_total_pkts++;
				g_core_cfg[lcore_id].cpu_total_bytes +=
					job[j]->cpu_len;
			}
		}
	}

	if (g_silent) {
		dq_num = job_num;
		goto skip_dq;
	}
	ret = rte_dma_completed(qdma_dev_id,
		vq_id, burst_nb - dq_num,
		&dq_idx[dq_num],
		&error);
	if (error)
		rte_exit(EXIT_FAILURE, "Job Processing Error\n");
	if (ret > 0)
		dq_num += ret;
	for (i = 0; i < dq_num; i++)
		job[i] = &jobs[dq_idx[i]];

	max = 0;
	ret = qdma_demo_validate_check(job, dq_num, &max);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Validate failed\n");
		return ret;
	}
	g_core_cfg[lcore_id].check_count += ret;
	if (max > g_core_cfg[lcore_id].max_check)
		g_core_cfg[lcore_id].max_check = max;
skip_dq:
	if (g_silent) {
		qdma_demo_silent_complete_check(dq_num, job, NULL);
		qdma_demo_silent_complete_recover(dq_num, job);
	}

	job_num = rte_ring_enqueue_bulk(job_ring,
			(void **)job, dq_num, NULL);
	if (job_num != dq_num)
		rte_exit(EXIT_FAILURE, "job recycle failed\n");

	g_core_cfg[lcore_id].dma_total_pkts += dq_num;
	g_core_cfg[lcore_id].dma_total_bytes +=
		g_packet_dma_size * dq_num;

	return 0;
}

static int
lcore_qdma_process_throughput_sg(uint16_t burst_nb,
	struct rte_ring *job_ring, uint16_t vq_id,
	struct dma_job *jobs, uint16_t *dma_idx)
{
	struct dma_job *job[burst_nb];
	struct rte_dma_sge src_sge[burst_nb];
	struct rte_dma_sge dst_sge[burst_nb];
	uint32_t i, j, job_num, dq_num = 0, lcore_id = rte_lcore_id();
	uint64_t flags;
	bool error = false;
	uint16_t dq_idx[burst_nb];
	int ret;
	uint32_t max;

	job_num = rte_ring_dequeue_bulk(job_ring,
			(void **)job, burst_nb, NULL);

	for (i = 0; i < job_num; i++) {
		qdma_demo_validate_set(job[i]);

		if (s_flags_cntx)
			dma_idx[i] = job[i]->idx;
		src_sge[i].addr = job[i]->src;
		src_sge[i].length = job[i]->dma_len;
		dst_sge[i].addr = job[i]->dest;
		dst_sge[i].length = job[i]->dma_len;
	}

	if (!job_num)
		goto dequeue;

	if (s_flags_cntx) {
		flags = RTE_DPAAX_QDMA_SG_SUBMIT(dma_idx,
				RTE_DMA_OP_FLAG_SUBMIT);
	} else {
		flags = RTE_DMA_OP_FLAG_SUBMIT;
	}
	ret = rte_dma_copy_sg(qdma_dev_id,
			vq_id, src_sge, dst_sge,
			job_num, job_num, flags);
	if (unlikely(ret < 0)) {
		qdma_demo_dump_job(job, job_num);
		rte_exit(EXIT_FAILURE,
			"SG DMA submit %d jobs error(%d)\n",
			job_num, ret);
	}
	if (g_test_mode & QDMA_DEMO_CPU_MODE) {
		for (j = 0; j < job_num; j++) {
			rte_memcpy(job[j]->vcpudst, job[j]->vcpusrc,
				job[j]->cpu_len);
		}
	}
dequeue:
	if (g_silent) {
		dq_num = job_num;
		goto skip_dq;
	}
	ret = rte_dma_completed(qdma_dev_id,
			vq_id, burst_nb - dq_num,
			&dq_idx[dq_num],
			&error);
	if (ret > 0)
		dq_num += ret;

	for (i = 0; i < dq_num; i++)
		job[i] = &jobs[dq_idx[i]];
	max = 0;
	ret = qdma_demo_validate_check(job, dq_num, &max);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Validate failed\n");
		return ret;
	}
	g_core_cfg[lcore_id].check_count += ret;
	if (max > g_core_cfg[lcore_id].max_check)
		g_core_cfg[lcore_id].max_check = max;
	if (error)
		rte_exit(EXIT_FAILURE, "Job Processing Error\n");
skip_dq:
	if (g_silent) {
		qdma_demo_silent_complete_check(dq_num, job, NULL);
		qdma_demo_silent_complete_recover(dq_num, job);
	}

	job_num = rte_ring_enqueue_bulk(job_ring,
			(void **)job, dq_num, NULL);
	if (job_num != dq_num)
		rte_exit(EXIT_FAILURE, "job recycle failed\n");

	g_core_cfg[lcore_id].dma_total_pkts += dq_num;
	g_core_cfg[lcore_id].dma_total_bytes +=
		g_packet_dma_size * dq_num;

	return 0;
}

static int
lcore_qdma_process_latency(uint16_t burst_nb,
	struct rte_ring *job_ring, uint16_t vq_id,
	struct dma_job *jobs, uint16_t *dma_idx)
{
	struct dma_job *job[burst_nb];
	struct rte_dma_sge src_sge[burst_nb];
	struct rte_dma_sge dst_sge[burst_nb];
	uint32_t i, job_num, dq_num = 0, miss = 0;
	uint64_t flags, cycle1 = 0, cycle2 = 0, cycle3, cycle4;
	uint32_t lcore_id = rte_lcore_id();
	bool error = false;
	uint16_t dq_idx[burst_nb];
	int ret;

	job_num = rte_ring_dequeue_bulk(job_ring,
				(void **)job, burst_nb, NULL);

	for (i = 0; i < job_num; i++) {
		if (g_scatter_gather) {
			if (s_flags_cntx)
				dma_idx[i] = job[i]->idx;
			src_sge[i].addr = job[i]->src;
			src_sge[i].length = job[i]->dma_len;
			dst_sge[i].addr = job[i]->dest;
			dst_sge[i].length = job[i]->dma_len;
			continue;
		}

		flags = 0;
		if (i == (job_num - 1) && s_flags_cntx)
			flags |= RTE_DPAAX_QDMA_COPY_SUBMIT(job[i]->idx,
					RTE_DMA_OP_FLAG_SUBMIT);
		else if (s_flags_cntx)
			flags |= RTE_DPAAX_QDMA_COPY_SUBMIT(job[i]->idx, 0);
		else if (i == (job_num - 1))
			flags |= RTE_DMA_OP_FLAG_SUBMIT;

		if (flags & RTE_DMA_OP_FLAG_SUBMIT)
			cycle1 = rte_get_timer_cycles();
		ret = rte_dma_copy(qdma_dev_id,
				vq_id, job[i]->src, job[i]->dest,
				job[i]->dma_len, flags);
	}

	if (!g_scatter_gather) {
		cycle2 = rte_get_timer_cycles();
		goto dequeue;
	}

	if (s_flags_cntx) {
		flags = RTE_DPAAX_QDMA_SG_SUBMIT(dma_idx,
				RTE_DMA_OP_FLAG_SUBMIT);
	} else {
		flags = RTE_DMA_OP_FLAG_SUBMIT;
	}
	cycle1 = rte_get_timer_cycles();
	ret = rte_dma_copy_sg(qdma_dev_id,
			vq_id, src_sge, dst_sge,
			job_num, job_num,
			flags);
	if (unlikely(ret < 0)) {
		rte_exit(EXIT_FAILURE,
			"SG DMA submit %d jobs error(%d)\n",
			job_num, ret);
	}
	cycle2 = rte_get_timer_cycles();
dequeue:
	if (g_silent) {
		dq_num = job_num;
		goto skip_dq;
	}
	cycle3 = rte_get_timer_cycles();
dequeue_again:
	ret = rte_dma_completed(qdma_dev_id,
		vq_id, burst_nb - dq_num,
		&dq_idx[dq_num],
		&error);
	if (ret > 0)
		dq_num += ret;
	if (dq_num < burst_nb)
		goto dequeue_again;
	for (i = 0; i < dq_num; i++)
		job[i] = &jobs[dq_idx[i]];
	if (error)
		rte_exit(EXIT_FAILURE, "Job Processing Error\n");
skip_dq:
	if (g_silent) {
		cycle3 = rte_get_timer_cycles();
		qdma_demo_silent_complete_check(dq_num, job, &miss);
	}

	cycle4 = rte_get_timer_cycles();
	calculate_latency(lcore_id,
		g_dma_prep_latency ? cycle1 : cycle2,
		cycle4, job, dq_num, miss);
	RTE_LOG(INFO, qdma_demo,
		"DMA prepare:%ld, check:%ld\n",
		cycle2 - cycle1, cycle4 - cycle3);
	if (g_silent)
		qdma_demo_silent_complete_recover(dq_num, job);

	job_num = rte_ring_enqueue_bulk(job_ring,
				(void **)job, dq_num, NULL);
	if (job_num != dq_num)
		rte_exit(EXIT_FAILURE, "job recycle failed\n");

	g_core_cfg[lcore_id].dma_total_pkts += dq_num;
	g_core_cfg[lcore_id].dma_total_bytes +=
		g_packet_dma_size * dq_num;

	return 0;
}

static int
lcore_qdma_process_loop(__attribute__((unused)) void *arg)
{
	uint32_t lcore_id;
	int ret = 0;
	const uint32_t burst_nb = g_burst;
	struct rte_ring *job_ring;
	uint16_t vq_id;
	uint16_t *dma_idx;
	struct dma_job *jobs;

	lcore_id = rte_lcore_id();

	/* wait synchro for slaves */
	do {
		ret = rte_atomic32_read(&synchro);
	} while (!ret);
	RTE_LOG(INFO, qdma_demo,
		"Processing coreid: %d ready, now!\n",
		lcore_id);

	if (g_seg_iova)
		return lcore_qdma_iova_seg_to_continue(lcore_id);

	job_ring = g_core_cfg[lcore_id].job_ring;
	vq_id = g_core_cfg[lcore_id].vq_id;
	dma_idx = g_core_cfg[lcore_id].dma_idx;
	jobs = g_core_cfg[lcore_id].jobs;

	latency_data[lcore_id].min = 9999999.0;
	while (!quit_signal) {
		if (g_test_mode == QDMA_DEMO_CPU_MODE) {
			ret = qdma_demo_memcpy_process(burst_nb, job_ring);
			if (ret)
				return ret;
		} else {
			if (g_latency) {
				ret = lcore_qdma_process_latency(burst_nb,
					job_ring, vq_id, jobs, dma_idx);
				if (ret)
					return ret;
			} else if (g_scatter_gather) {
				ret = lcore_qdma_process_throughput_sg(burst_nb,
					job_ring, vq_id, jobs, dma_idx);
				if (ret)
					return ret;
			} else {
				ret = lcore_qdma_process_throughput(burst_nb,
					job_ring, vq_id, jobs);
				if (ret)
					return ret;
			}
		}
	}

	RTE_LOG(INFO, qdma_demo, "exit core %d\n", lcore_id);

	return 0;
}

static int
lcore_qdma_control_loop(void)
{
	unsigned int lcore_id;
	uint64_t dma_old_pkts[RTE_MAX_LCORE];
	uint64_t dma_pkts_diff[RTE_MAX_LCORE];
	uint64_t dma_pkts_diff_total;
	uint64_t dma_old_bytes[RTE_MAX_LCORE];
	uint64_t dma_bytes_diff_total;
	uint64_t dma_bytes_diff[RTE_MAX_LCORE];

	uint64_t cpu_old_pkts[RTE_MAX_LCORE];
	uint64_t cpu_pkts_diff[RTE_MAX_LCORE];
	uint64_t cpu_pkts_diff_total;
	uint64_t cpu_old_bytes[RTE_MAX_LCORE];
	uint64_t cpu_bytes_diff_total;
	uint64_t cpu_bytes_diff[RTE_MAX_LCORE];

	uint64_t check_diff;
	uint64_t check_old_count[RTE_MAX_LCORE];

	uint64_t cycle1 = 0, cycle2 = 0, cycle_diff;
	float bytes_speed, pkts_speed;
	int ret, offset;
	uint32_t i, max;
	char perf_buf[1024];

	lcore_id = rte_lcore_id();

	memset(cpu_old_pkts, 0, sizeof(cpu_old_pkts));
	memset(cpu_old_bytes, 0, sizeof(cpu_old_bytes));
	memset(dma_old_pkts, 0, sizeof(dma_old_pkts));
	memset(dma_old_bytes, 0, sizeof(dma_old_bytes));
	memset(check_old_count, 0, sizeof(check_old_count));

	ret = rte_dma_start(qdma_dev_id);
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "Failed to start DMA[%d](%d)\n",
			qdma_dev_id, ret);
		return ret;
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

		if (g_latency)
			goto skip_print;

		cycle2 = rte_get_timer_cycles();
		cycle_diff = cycle2 - cycle1;
		offset = 0;
		dma_pkts_diff_total = 0;
		dma_bytes_diff_total = 0;
		cpu_pkts_diff_total = 0;
		cpu_bytes_diff_total = 0;
		check_diff = 0;
		max = 0;
		offset += sprintf(&perf_buf[offset], "Statistics:\n");
		RTE_LCORE_FOREACH_WORKER(i) {
			dma_pkts_diff[i] = g_core_cfg[i].dma_total_pkts -
				dma_old_pkts[i];
			dma_pkts_diff_total += dma_pkts_diff[i];
			dma_bytes_diff[i] = g_core_cfg[i].dma_total_bytes -
				dma_old_bytes[i];
			dma_bytes_diff_total += dma_bytes_diff[i];
			dma_old_pkts[i] = g_core_cfg[i].dma_total_pkts;
			dma_old_bytes[i] = g_core_cfg[i].dma_total_bytes;

			cpu_pkts_diff[i] = g_core_cfg[i].cpu_total_pkts -
				dma_old_pkts[i];
			cpu_pkts_diff_total += cpu_pkts_diff[i];
			cpu_bytes_diff[i] = g_core_cfg[i].cpu_total_bytes -
				cpu_old_bytes[i];
			cpu_bytes_diff_total += cpu_bytes_diff[i];
			cpu_old_pkts[i] = g_core_cfg[i].cpu_total_pkts;
			cpu_old_bytes[i] = g_core_cfg[i].cpu_total_bytes;

			check_diff += g_core_cfg[i].check_count -
				check_old_count[i];
			check_old_count[i] = g_core_cfg[i].check_count;
			if (g_core_cfg[i].max_check > max)
				max = g_core_cfg[i].max_check;

			if (g_packet_dma_size > 0) {
				bytes_speed = (float)dma_bytes_diff[i] /
					(s_ns_per_cyc * cycle_diff / NS_PER_S);
				pkts_speed = (float)dma_pkts_diff[i] /
					(s_ns_per_cyc * cycle_diff / NS_PER_S);

				offset += sprintf(&perf_buf[offset],
					"Core%d(%s): DMA Rate: %.3f Mbps OR %.3f Kpps\n",
					i, g_core_cfg[i].test_case_nm,
					8 * bytes_speed / NS_PER_MS,
					pkts_speed / NS_PER_MS);
			}

			if (g_packet_cpu_size > 0) {
				bytes_speed = (float)cpu_bytes_diff[i] /
					(s_ns_per_cyc * cycle_diff / NS_PER_S);
				pkts_speed = (float)cpu_pkts_diff[i] /
					(s_ns_per_cyc * cycle_diff / NS_PER_S);

				offset += sprintf(&perf_buf[offset],
					"Core%d(%s): CPU Rate: %.3f Mbps OR %.3f Kpps\n",
					i, g_core_cfg[i].test_case_nm,
					8 * bytes_speed / NS_PER_MS,
					pkts_speed / NS_PER_MS);
			}
		}

		if (g_packet_dma_size > 0) {
			bytes_speed = (float)dma_bytes_diff_total /
				(s_ns_per_cyc * cycle_diff / NS_PER_S);
			pkts_speed = (float)dma_pkts_diff_total /
				(s_ns_per_cyc * cycle_diff / NS_PER_S);

			offset += sprintf(&perf_buf[offset],
				"Total DMA Rate: %.3f Mbps OR %.3f Kpps\n",
				8 * bytes_speed / NS_PER_MS,
				pkts_speed / NS_PER_MS);
			if (g_validate != QDMA_DEMO_NO_VALIDATE) {
				offset += sprintf(&perf_buf[offset],
					"Average check times: %.3f, max times: %d\n",
					(float)check_diff / dma_pkts_diff_total,
					max);
			}
		}

		if (g_packet_cpu_size > 0) {
			bytes_speed = (float)cpu_bytes_diff_total /
				(s_ns_per_cyc * cycle_diff / NS_PER_S);
			pkts_speed = (float)cpu_pkts_diff_total /
				(s_ns_per_cyc * cycle_diff / NS_PER_S);

			offset += sprintf(&perf_buf[offset],
				"Total CPU Rate: %.3f Mbps OR %.3f Kpps\n",
				8 * bytes_speed / NS_PER_MS,
				pkts_speed / NS_PER_MS);
		}
		offset += sprintf(&perf_buf[offset], "\r\n");

		RTE_LOG(INFO, qdma_demo, "%s", perf_buf);

skip_print:
		cycle1 = cycle2 = 0;
	}
	RTE_LOG(INFO, qdma_demo, "exit core %d\n", rte_lcore_id());

	return 0;
}

/* launch all the per-lcore test, and display the result */
static int
launch_cores(void)
{
	unsigned lcore_id;
	int ret;

	rte_atomic32_set(&synchro, 0);

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (lcore_id == rte_lcore_id())
			continue;
		rte_eal_remote_launch(lcore_qdma_process_loop, NULL, lcore_id);
	}

	/* start synchro and launch test on master */
	ret = lcore_qdma_control_loop();
	if (ret < 0) {
		RTE_LOG(ERR, qdma_demo,
			"DMA control failed(%d)\n", ret);
		return ret;
	}
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (lcore_id == rte_lcore_id())
			continue;

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
	int pos = 0;

	pos += sprintf(&buf[pos],
		"./qdma_demo [EAL options] -- -option --<args>=<value>\n");

	pos += sprintf(&buf[pos], "options	:\n");
	pos += sprintf(&buf[pos], "	: -c <hex core mask>\n");
	pos += sprintf(&buf[pos], "	: -h print usage\n");

	pos += sprintf(&buf[pos], "Args	:\n");
	for (i = 0; i < sizeof(s_lopts) / sizeof(struct option); i++) {
		if (s_lopts[i].name &&
			s_lopts[i].has_arg == required_argument) {
			pos += sprintf(&buf[pos], "--%s=%s\n",
				s_lopts[i].name, s_lopts_help[i]);
		} else if (s_lopts[i].name) {
			pos += sprintf(&buf[pos], "--%s\n", s_lopts[i].name);
		}
	}
	RTE_LOG(WARNING, qdma_demo, "%s\n", buf);
}

static void
qdma_demo_dma_vchan_init(int test_case,
	struct rte_dma_vchan_conf *conf,
	struct rte_dma_info *dma_info)
{
	int pci_bus_access = 0;

	if (!conf || !dma_info)
		return;

	if (g_pci_bus != RTE_BAD_IOVA && g_pci_dma_rbp)
		pci_bus_access = 1;
	if (pci_bus_access && test_case == MEM_TO_PCI) {
		conf->direction = RTE_DMA_DIR_MEM_TO_DEV;
		conf->nb_desc = dma_info->max_desc;
		conf->src_port.port_type = RTE_DMA_PORT_NONE;
		conf->dst_port.port_type = RTE_DMA_PORT_PCIE;
		conf->dst_port.pcie.coreid = g_pci_ep_pci_id;
		conf->dst_port.pcie.pfid = g_pci_ep_pf_id;
		conf->dst_port.pcie.vfen = g_pci_ep_is_vf;
		if (g_pci_ep_is_vf)
			conf->dst_port.pcie.vfid = g_pci_ep_vf_id;
	} else if (pci_bus_access && test_case == PCI_TO_MEM) {
		conf->direction = RTE_DMA_DIR_DEV_TO_MEM;
		conf->nb_desc = dma_info->max_desc;
		conf->src_port.port_type = RTE_DMA_PORT_PCIE;
		conf->dst_port.port_type = RTE_DMA_PORT_NONE;
		conf->src_port.pcie.coreid = g_pci_ep_pci_id;
		conf->src_port.pcie.pfid = g_pci_ep_pf_id;
		conf->src_port.pcie.vfen = g_pci_ep_is_vf;
		if (g_pci_ep_is_vf)
			conf->src_port.pcie.vfid = g_pci_ep_vf_id;
	} else if (pci_bus_access && test_case == PCI_TO_PCI) {
		conf->direction = RTE_DMA_DIR_DEV_TO_DEV;
		conf->nb_desc = dma_info->max_desc;
		conf->src_port.port_type = RTE_DMA_PORT_PCIE;
		conf->dst_port.port_type = RTE_DMA_PORT_PCIE;
		conf->src_port.pcie.coreid = g_pci_ep_pci_id;
		conf->src_port.pcie.pfid = g_pci_ep_pf_id;
		conf->src_port.pcie.vfen = g_pci_ep_is_vf;
		conf->dst_port.pcie.coreid = g_pci_ep_pci_id;
		conf->dst_port.pcie.pfid = g_pci_ep_pf_id;
		conf->dst_port.pcie.vfen = g_pci_ep_is_vf;
		if (g_pci_ep_is_vf) {
			conf->src_port.pcie.vfid = g_pci_ep_vf_id;
			conf->dst_port.pcie.vfid = g_pci_ep_vf_id;
		}
	} else {
		conf->direction = RTE_DMA_DIR_MEM_TO_MEM;
		conf->nb_desc = dma_info->max_desc;
		conf->src_port.port_type = RTE_DMA_PORT_NONE;
		conf->dst_port.port_type = RTE_DMA_PORT_NONE;
	}
}

static int
qdma_demo_job_desc_init(struct dma_job *job,
	uint64_t src_iova, uint64_t dst_iova,
	uint64_t src_va, uint64_t dst_va,
	uint64_t elem_size, uint32_t idx, int test_case,
	uint16_t core, uint64_t end_mem, uint64_t end_pci)
{
	uint8_t *dmasrc_last = NULL, *dmadst_last = NULL;
	uint8_t *cpusrc_last = NULL, *cpudst_last = NULL;
	uint8_t *vsrc_start, *vdst_start;

	job->src = START_ADDR(src_iova, idx, uint64_t, elem_size);
	job->dest = START_ADDR(dst_iova, idx, uint64_t, elem_size);
	vsrc_start = START_ADDR(src_va, idx, uint8_t *, elem_size);
	vdst_start = START_ADDR(dst_va, idx, uint8_t *, elem_size);
	if (g_packet_dma_size > 0) {
		job->vdmasrc = vsrc_start;
		job->vdmadst = vdst_start;
		dmasrc_last = job->vdmasrc + g_packet_dma_size - 1;
		dmadst_last = job->vdmadst + g_packet_dma_size - 1;
	}
	if (g_packet_cpu_size > 0) {
		job->vcpusrc = vsrc_start + g_packet_dma_size;
		job->vcpudst = vdst_start + g_packet_dma_size;
		cpusrc_last = job->vcpusrc + g_packet_cpu_size - 1;
		cpudst_last = job->vcpudst + g_packet_cpu_size - 1;
	}

	job->dma_len = g_packet_dma_size;
	job->cpu_len = g_packet_cpu_size;
	job->idx = idx;
	if ((test_case == MEM_TO_PCI || test_case == MEM_TO_MEM) &&
		(job->src + elem_size) > end_mem) {
		RTE_LOG(ERR, qdma_demo,
			"Core%d job[%d] mem src(%lx) + %lx > %lx\n",
			core, idx, job->src, elem_size, end_mem);
			return -EINVAL;
	}
	if ((test_case == MEM_TO_MEM || test_case == PCI_TO_MEM) &&
		(job->dest + elem_size) > end_mem) {
		RTE_LOG(ERR, qdma_demo,
			"Core%d job[%d] mem dst(%lx) + %lx > %lx\n",
			core, idx, job->dest, elem_size, end_mem);
		return -EINVAL;
	}
	if ((test_case == PCI_TO_PCI || test_case == PCI_TO_MEM) &&
		(job->src + elem_size) > end_pci) {
		RTE_LOG(ERR, qdma_demo,
			"Core%d job[%d] pci src(%lx) + %lx > %lx\n",
			core, idx, job->src, elem_size, end_pci);
		return -EINVAL;
	}
	if ((test_case == PCI_TO_PCI || test_case == MEM_TO_PCI) &&
		(job->dest + elem_size) > end_pci) {
		RTE_LOG(ERR, qdma_demo,
			"Core%d job[%d] pci dst(%lx) + %lx > %lx\n",
			core, idx, job->dest, elem_size, end_pci);
		return -EINVAL;
	}
	if (g_latency || g_silent) {
		if (dmasrc_last && dmadst_last) {
			*dmasrc_last = LATENCY_TEST_SRC_DATA;
			*dmadst_last = LATENCY_TEST_DST_DATA;
		}
		if (cpusrc_last && cpudst_last) {
			*cpusrc_last = LATENCY_TEST_SRC_DATA;
			*cpudst_last = LATENCY_TEST_DST_DATA;
		}
	}

	return 0;
}

static int
qdma_demo_core_configure(char *optarg,
	struct rte_dma_info *dma_info)
{
	int num, ids[MAX_TEST_CASES], ret;
	char *str_fld[MAX_TEST_CASES];
	uint32_t seg_len, i, j, core, jobs_nb;
	uint16_t mem_seg = 0, pci_seg = 0;
	uint64_t pci_addr, end_pci = RTE_BAD_IOVA;
	uint64_t mem_addr = 0, end_mem = 0;
	uint64_t v_pci_addr = (uint64_t)g_pci_vir;
	uint64_t v_mem_addr = 0;
	uint64_t elem_size = 0;
	uint64_t src_iova = 0, dst_iova = 0;
	uint64_t src_va = 0, dst_va = 0;
	char nm[RTE_MEMZONE_NAMESIZE];
	struct dma_job *jobs;
	uint16_t vq_id = 0;

	if (g_pci_bus != RTE_BAD_IOVA && g_pci_dma_rbp)
		pci_addr = g_pci_bus;
	else
		pci_addr = g_pci_phy;

	if (g_test_mode & QDMA_DEMO_DMA_MODE)
		elem_size += g_packet_dma_size;
	if (g_test_mode & QDMA_DEMO_CPU_MODE)
		elem_size += g_packet_cpu_size;

	num = rte_strsplit(optarg, strlen(optarg), str_fld,
			MAX_TEST_CASES, ',');
	if (num <= 0) {
		RTE_LOG(ERR, qdma_demo,
			"Parse test IDs(%s) failed(%d)\n", optarg, num);
		return -EINVAL;
	}
	for (i = 0; i < (uint32_t)num; i++) {
		ids[i] = INVALID_TEST_CASE;
		for (j = 0; j < (int)ARRAY_SIZE(s_test_case); j++) {
			ret = strncmp(s_test_case[j].name, str_fld[i],
				TEST_ARG_NAME_SIZE);
			if (!ret) {
				ids[i] = s_test_case[j].id;
				break;
			}
		}
		if (ids[i] == INVALID_TEST_CASE) {
			RTE_LOG(ERR, qdma_demo,
				"Test ID[%d](%s) not found!\n",
				i, str_fld[i]);
			return -EINVAL;
		}
	}
	i = 0;

	for (core = 0; core < RTE_MAX_LCORE; core++)
		g_core_cfg[core].test_case = INVALID_TEST_CASE;

	for (core = 0; core < RTE_MAX_LCORE; core++) {
		if (!rte_lcore_is_enabled(core))
			continue;
		if (core == rte_lcore_id())
			continue;
		g_core_cfg[core].test_case = ids[i];
		g_core_cfg[core].test_case_nm = str_fld[i];
		RTE_LOG(INFO, qdma_demo,
			"Run %s on core%d\n", str_fld[i], core);
		i++;
		if ((int)i == num)
			i = 0;
		if (g_core_cfg[core].test_case == PCI_TO_PCI) {
			pci_seg += 2;
		} else if (g_core_cfg[core].test_case == MEM_TO_MEM) {
			mem_seg += 2;
		} else if (g_core_cfg[core].test_case == MEM_TO_PCI ||
			g_core_cfg[core].test_case == PCI_TO_MEM) {
			mem_seg++;
			pci_seg++;
		}
	}

	if (g_pci_size) {
		seg_len = g_pci_size / pci_seg;
		g_mem_zone_size = seg_len * mem_seg;
		end_pci = pci_addr + g_pci_size;
	} else {
		seg_len = g_mem_zone_size / mem_seg;
	}

	for (core = 0; core < RTE_MAX_LCORE; core++) {
		if (!rte_lcore_is_enabled(core))
			continue;
		if (core == rte_lcore_id())
			continue;
		if (g_core_cfg[core].test_case == PCI_TO_PCI) {
			g_core_cfg[core].pci_src_len = seg_len;
			g_core_cfg[core].pci_dst_len = seg_len;
		} else if (g_core_cfg[core].test_case == MEM_TO_MEM) {
			g_core_cfg[core].mem_src_len = seg_len;
			g_core_cfg[core].mem_dst_len = seg_len;
		} else if (g_core_cfg[core].test_case == MEM_TO_PCI) {
			g_core_cfg[core].mem_src_len = seg_len;
			g_core_cfg[core].pci_dst_len = seg_len;
		} else {
			g_core_cfg[core].pci_src_len = seg_len;
			g_core_cfg[core].mem_dst_len = seg_len;
		}
	}

	if (mem_seg > 0) {
		sprintf(nm, "qdma_demo_memz");
		g_memz = rte_memzone_reserve_aligned(nm,
				g_mem_zone_size, 0,
				RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!g_memz) {
			RTE_LOG(ERR, qdma_demo,
				"Reserved %s (size-%ld)failed\n",
				nm, g_mem_zone_size);
			return -ENOMEM;
		}
		mem_addr = g_memz->iova;
		v_mem_addr = g_memz->addr_64;
		end_mem = mem_addr + g_memz->len;
	}

	elem_size = qdma_demo_roundup_pow_of_two(elem_size);
	jobs_nb = seg_len / elem_size;
	if (dma_info && jobs_nb > dma_info->max_desc)
		jobs_nb = dma_info->max_desc;
	if (!rte_is_power_of_2(jobs_nb))
		jobs_nb = rte_align32prevpow2(jobs_nb);
	RTE_LOG(INFO, qdma_demo,
		"Jobs per thread:%d, element size(%ld)\n",
		jobs_nb, elem_size);

	for (core = 0; core < RTE_MAX_LCORE; core++) {
		if (!rte_lcore_is_enabled(core))
			continue;
		if (core == rte_lcore_id())
			continue;
		g_core_cfg[core].job_num = jobs_nb;
		if (g_core_cfg[core].test_case == MEM_TO_PCI) {
			g_core_cfg[core].mem_src = mem_addr;
			mem_addr += seg_len;
			g_core_cfg[core].pci_dst = pci_addr;
			pci_addr += seg_len;
			g_core_cfg[core].v_mem_src = v_mem_addr;
			v_mem_addr += seg_len;
			g_core_cfg[core].v_pci_dst = v_pci_addr;
			v_pci_addr += seg_len;
			src_iova = g_core_cfg[core].mem_src;
			dst_iova = g_core_cfg[core].pci_dst;
			src_va = g_core_cfg[core].v_mem_src;
			dst_va = g_core_cfg[core].v_pci_dst;
		} else if (g_core_cfg[core].test_case == PCI_TO_MEM) {
			g_core_cfg[core].pci_src = pci_addr;
			pci_addr += seg_len;
			g_core_cfg[core].mem_dst = mem_addr;
			mem_addr += seg_len;
			g_core_cfg[core].v_pci_src = v_pci_addr;
			v_pci_addr += seg_len;
			g_core_cfg[core].v_mem_dst = v_mem_addr;
			v_mem_addr += seg_len;
			src_iova = g_core_cfg[core].pci_src;
			dst_iova = g_core_cfg[core].mem_dst;
			src_va = g_core_cfg[core].v_pci_src;
			dst_va = g_core_cfg[core].v_mem_dst;
		} else if (g_core_cfg[core].test_case == MEM_TO_MEM) {
			g_core_cfg[core].mem_src = mem_addr;
			mem_addr += seg_len;
			g_core_cfg[core].mem_dst = mem_addr;
			mem_addr += seg_len;
			g_core_cfg[core].v_mem_src = v_mem_addr;
			v_mem_addr += seg_len;
			g_core_cfg[core].v_mem_dst = v_mem_addr;
			v_mem_addr += seg_len;
			src_iova = g_core_cfg[core].mem_src;
			dst_iova = g_core_cfg[core].mem_dst;
			src_va = g_core_cfg[core].v_mem_src;
			dst_va = g_core_cfg[core].v_mem_dst;
		} else if (g_core_cfg[core].test_case == PCI_TO_PCI) {
			g_core_cfg[core].pci_src = pci_addr;
			pci_addr += seg_len;
			g_core_cfg[core].pci_dst = pci_addr;
			pci_addr += seg_len;
			g_core_cfg[core].v_pci_src = v_pci_addr;
			v_pci_addr += seg_len;
			g_core_cfg[core].v_pci_dst = v_pci_addr;
			v_pci_addr += seg_len;
			src_iova = g_core_cfg[core].pci_src;
			dst_iova = g_core_cfg[core].pci_dst;
			src_va = g_core_cfg[core].v_pci_src;
			dst_va = g_core_cfg[core].v_pci_dst;
		}
		if (dma_info) {
			qdma_demo_dma_vchan_init(g_core_cfg[core].test_case,
				&g_core_cfg[core].conf, dma_info);
			g_core_cfg[core].vq_id = vq_id;
			ret = rte_dma_vchan_setup(qdma_dev_id, vq_id,
					&g_core_cfg[core].conf);
			if (ret) {
				RTE_LOG(ERR, qdma_demo,
					"Vchan setup failed(%d)\n", ret);
				goto quit;
			}
			vq_id++;
		}
		sprintf(nm, "job-ring-%d", core);
		g_core_cfg[core].job_ring = rte_ring_create(nm,
			g_core_cfg[core].job_num * 2, 0, 0);
		if (!g_core_cfg[core].job_ring) {
			RTE_LOG(ERR, qdma_demo,
				"job ring created failed on core%d\n",
				core);
			ret = -ENOMEM;
			goto quit;
		}
		g_core_cfg[core].jobs = rte_zmalloc(NULL,
			g_core_cfg[core].job_num * sizeof(struct dma_job),
			RTE_CACHE_LINE_SIZE);
		if (!g_core_cfg[core].jobs) {
			RTE_LOG(ERR, qdma_demo,
				"jobs created failed on core%d\n",
				core);
			ret = -ENOMEM;
			goto quit;
		}

		g_core_cfg[core].dma_idx = rte_malloc(NULL,
			sizeof(uint16_t) * g_core_cfg[core].job_num,
			RTE_DPAAX_QDMA_SG_IDX_ADDR_ALIGN);
		if (!g_core_cfg[core].dma_idx) {
			RTE_LOG(ERR, qdma_demo,
				"DMA index created failed on core%d\n",
				core);
			ret = -ENOMEM;
			goto quit;
		}
		jobs = g_core_cfg[core].jobs;

		for (i = 0; i < g_core_cfg[core].job_num; i++) {
			ret = qdma_demo_job_desc_init(&jobs[i],
				src_iova, dst_iova, src_va, dst_va,
				elem_size, i, g_core_cfg[core].test_case,
				core, end_mem, end_pci);
			if (ret)
				goto quit;
			ret = rte_ring_enqueue(g_core_cfg[core].job_ring,
					&jobs[i]);
			if (ret) {
				RTE_LOG(ERR, qdma_demo,
					"eq job[%d] failed on core%d, err(%d)\n",
					i, core, ret);
				goto quit;
			}
		}

		RTE_LOG(INFO, qdma_demo,
			"Core%d: Create %d jobs, dma(=%ld)/cpu(%ld) per job\n",
			core, g_core_cfg[core].job_num,
			g_packet_dma_size, g_packet_cpu_size);
	}

quit:
	if (ret) {
		for (core = 0; core < RTE_MAX_LCORE; core++) {
			if (g_core_cfg[core].jobs)
				rte_free(g_core_cfg[core].jobs);
			if (g_core_cfg[core].dma_idx)
				rte_free(g_core_cfg[core].dma_idx);
			if (g_core_cfg[core].job_ring)
				rte_ring_free(g_core_cfg[core].job_ring);
			g_core_cfg[core].jobs = NULL;
			g_core_cfg[core].dma_idx = NULL;
			g_core_cfg[core].job_ring = NULL;
		}
		rte_memzone_free(g_memz);
		g_memz = NULL;
	}
	return 0;
}

static int
qdma_parse_long_arg(char *optarg, const struct option *lopt)
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
	case ARG_PCI_DMA_RBP:
		g_pci_dma_rbp = 1;
		RTE_LOG(INFO, qdma_demo, "PCI DMA RBP mode\n");
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
		RTE_LOG(INFO, qdma_demo, "SW Pkt size %ld\n",
			g_packet_cpu_size);
		break;
	case ARG_TEST_ID:
		g_test_case_str = optarg;
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "test case %s\n", g_test_case_str);
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
	case ARG_VALIDATE:
		if (!optarg) {
			g_validate = QDMA_DEMO_FULL_VALIDATE;
		} else {
			ret = sscanf(optarg, "%d", &g_validate);
			if (ret != 1) {
				RTE_LOG(ERR, qdma_demo, "Invalid validate size\n");
				ret = -EINVAL;
				goto out;
			}
		}
		ret = 0;
		if (g_validate == QDMA_DEMO_NO_VALIDATE) {
			RTE_LOG(INFO, qdma_demo,
				"Don't validate data after DMA complete.\n");
		} else if (g_validate == QDMA_DEMO_FULL_VALIDATE) {
			RTE_LOG(INFO, qdma_demo,
				"Validate full data after DMA complete.\n");
		} else if (g_validate == QDMA_DEMO_LAST_BYTE_VALIDATE) {
			RTE_LOG(INFO, qdma_demo,
				"Validate last byte after DMA complete.\n");
		} else {
			RTE_LOG(INFO, qdma_demo,
				"Invalid validation type(%d)\n", g_validate);
			ret = -EINVAL;
			goto out;
		}
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

out:
	return ret;
}

static int
qdma_demo_parse_args(int argc, char **argv)
{
	int opt, ret = 0, option_index;
	const struct option *lopt_cur;

	while ((opt = getopt_long(argc, argv, "h;",
				s_lopts, &option_index)) != EOF) {

		switch (opt) {
		case 'h':
			qdma_demo_usage();
			ret = 1;
			break;
		/* long options */
		case 0:
			lopt_cur = &s_lopts[option_index];
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
	int valid = 1, core_count;

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
	uint64_t time_diff, pci_iova;
	uint16_t portid;
	struct rte_dma_info dma_info;

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
			g_pci_size = 0;
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
			if (!ret && g_pci_size > 0)
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
	} else if (g_pci_phy != RTE_BAD_IOVA) {
		pci_size = pci_find_bar_available_size(g_pci_phy);
		if (!pci_size) {
			RTE_LOG(ERR, qdma_demo,
				"PCI address 0x%lx not found!\n",
				g_pci_phy);

			return 0;
		}
		if (pci_size < g_pci_size || !g_pci_size)
			g_pci_size = pci_size;

		g_pci_vir = pci_addr_mmap(NULL, g_pci_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				g_pci_phy, NULL, NULL);
		if (rte_eal_iova_mode() == RTE_IOVA_PA) {
			pci_iova = g_pci_phy;
		} else {
			if (!rte_fslmc_bus_available()) {
				RTE_LOG(ERR, qdma_demo,
					"IOVA spuuort on DPAA2 platform only\n");
				return -ENOTSUP;
			}
			pci_iova = (uint64_t)g_pci_vir;
		}
		if (rte_fslmc_bus_available()) {
			ret = rte_fslmc_vfio_mem_dmamap((uint64_t)g_pci_vir,
				pci_iova, g_pci_size);
			if (ret) {
				RTE_LOG(ERR, qdma_demo,
					"VFIO map failed(%d)\n", ret);
				return ret;
			}
		}
	}

	if (g_test_mode & QDMA_DEMO_DMA_MODE) {
		ret = test_dma_init(&dma_info);
		if (ret) {
			RTE_LOG(ERR, qdma_demo, "DMA init failed(%d)\n", ret);
			return ret;
		}
	}
	ret = qdma_demo_core_configure(g_test_case_str,
		g_test_mode & QDMA_DEMO_DMA_MODE ?
		&dma_info : NULL);
	if (ret) {
		RTE_LOG(ERR, qdma_demo,
			"Core configured failed(%d)\n", ret);
		return ret;
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

	ret = launch_cores();
	if (ret < 0)
		goto out;
	RTE_LOG(INFO, qdma_demo, "qdma_demo Finished.. bye!\n");
	return 0;
out:
	RTE_LOG(ERR, qdma_demo, "qdma_demo Failed!\n");
	return 0;
}
