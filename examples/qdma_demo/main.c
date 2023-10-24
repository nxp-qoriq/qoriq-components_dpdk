/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2023 NXP
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

static int qdma_dev_id;
static float rate;
static uint64_t freq;
static rte_atomic32_t synchro;

static uint64_t g_dq_num[RTE_MAX_LCORE];
static uint64_t g_dq_num_last[RTE_MAX_LCORE];

static int g_vqid[RTE_MAX_LCORE];

#define CPU_INFO_FREQ_FILE \
	"/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq"

#define RTE_LOGTYPE_qdma_demo RTE_LOGTYPE_USER1

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

struct qdma_demo_latency {
	double min;
	double max;
	double total;
	int count;
};
static struct qdma_demo_latency latency_data[RTE_MAX_LCORE];

static struct qdma_test_case test_case[] = {
	{"mem_to_mem", "Host mem to Host mem done, pci_addr not needed",
		 MEM_TO_MEM},
	{"mem_to_pci", "Host mem to EP mem done from host", MEM_TO_PCI},
	{"pci_to_mem", "EP me to host mem done from host", PCI_TO_MEM},
	{"pci_to_pci", "EP mem to EP mem done from host", PCI_TO_PCI},
};

/*Configurable options*/
static int g_test_path = MEM_TO_PCI;
static uint32_t g_arg_mask;
static uint32_t g_burst = BURST_NB_MAX;
static uint64_t g_pci_phy = RTE_BAD_IOVA;
static uint8_t *g_pci_vir;
static uint64_t g_pci_iova;
static uint64_t g_packet_size = 1024;
static uint64_t g_pci_size = TEST_PCI_DEFAULT_SIZE;
static uint32_t g_packet_num = (1 * 1024);
static int g_latency;
static int g_memcpy;
static int g_validate;
static int g_scatter_gather;

static struct dma_job *g_jobs[RTE_MAX_LCORE];
static struct rte_ring *g_job_ring[RTE_MAX_LCORE];
static const struct rte_memzone *g_memz_src[RTE_MAX_LCORE];
static const struct rte_memzone *g_memz_dst[RTE_MAX_LCORE];

static uint8_t quit_signal;
static uint32_t core_count;

static int TEST_DMA_INIT_FLAG;

#define START_ADDR(base, num) \
	((uint64_t)base + TEST_PACKET_SIZE * num)

struct qdma_demo_pci_bar {
	uint64_t phy_start[PCI_MAX_RESOURCE];
	uint64_t len[PCI_MAX_RESOURCE];
};

#define QDMA_DEMO_MAX_PCI_DEV 64
static struct qdma_demo_pci_bar g_pci_bar[QDMA_DEMO_MAX_PCI_DEV];

static int
test_dma_init(void)
{
	struct rte_dma_conf dma_config;
	struct rte_dma_info dma_info;
	int ret, i = 0, max_avail = rte_dma_count_avail();

	if (TEST_DMA_INIT_FLAG)
		return 0;

init_dma:
	if (i >= max_avail)
		return -EBUSY;
	qdma_dev_id = i;

	ret = rte_dma_info_get(qdma_dev_id, &dma_info);
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "Failed to get DMA[%d] info(%d)\n",
			qdma_dev_id, ret);
		return ret;
	}
	dma_config.nb_vchans = dma_info.max_vchans;
	dma_config.enable_silent = 0;

	ret = rte_dma_configure(qdma_dev_id, &dma_config);
	if (ret) {
		RTE_LOG(WARNING, qdma_demo,
			"Failed to configure DMA[%d](%d)\n",
			qdma_dev_id, ret);
		goto init_dma;
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

static void
calculate_latency(unsigned int lcore_id, uint64_t cycle1,
	int pkt_cnt)
{
	uint64_t cycle2 = 0;
	uint64_t my_time_diff;
	struct qdma_demo_latency *core_latency = &latency_data[lcore_id];

	float ns_per_cyc = (1000 * rate) / freq;
	float time_us = 0.0;

	cycle2 = rte_get_timer_cycles();
	my_time_diff = cycle2 - cycle1;
	time_us = ns_per_cyc * my_time_diff / 1000;

	if (time_us < core_latency->min)
		core_latency->min = time_us;
	if (time_us > core_latency->max)
		core_latency->max = time_us;
	core_latency->total += time_us;
	core_latency->count++;

	RTE_LOG(INFO, qdma_demo,
		"cpu=%d pkt_cnt:%d, pkt_size %ld\n",
		lcore_id, pkt_cnt, TEST_PACKET_SIZE);
	RTE_LOG(INFO, qdma_demo,
		"min %.1f, max %.1f, mean %.1f\n",
		core_latency->min, core_latency->max,
		core_latency->total / core_latency->count);
	rte_delay_ms(1000);
}

static inline void
qdma_demo_validate_set(struct dma_job *job)
{
	int r_num;
	uint32_t i, j, len;

	if (!g_validate)
		return;

	r_num = rand();
	len = RTE_DPAA2_QDMA_LEN_FROM_LENGTH(job->len);
	for (i = 0; i < len / 4; i++) {
		*((int *)(job->vsrc) + i) = r_num;
		*((int *)(job->vdst) + i) = 0;
	}
	j = 0;
	while ((i * 4 + j) < len) {
		*(uint8_t *)(job->vsrc + i * 4 + j) = r_num;
		*(uint8_t *)(job->vdst + i * 4 + j) = r_num;
		j++;
	}
}

static int
qdma_demo_validate_check(struct dma_job *job[],
	uint32_t job_num)
{
	int cmp_src, cmp_dst;
	uint32_t i, j, k, len;

	if (!g_validate)
		return 0;

	for (i = 0; i < job_num; i++) {
		len = RTE_DPAA2_QDMA_LEN_FROM_LENGTH(job[i]->len);
		for (j = 0; j < len / 4; j++) {
			cmp_src = *((int *)(job[i]->vsrc) + j);
			cmp_dst = *((int *)(job[i]->vdst) + j);
			if (cmp_src != cmp_dst) {
				RTE_LOG(ERR, qdma_demo,
					"cmp_src(0x%08x) != cmp_dst(0x%08x)\n",
					cmp_src, cmp_dst);
				rte_exit(EXIT_FAILURE, "Validate failed\n");
				return -EINVAL;
			}
		}
		k = 0;
		while ((j * 4 + k) < len) {
			cmp_src = *(uint8_t *)(job[i]->vsrc + j * 4 + k);
			cmp_dst = *(uint8_t *)(job[i]->vdst + j * 4 + k);
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
	uint64_t cycle;
	int ret;

	lcore_id = rte_lcore_id();
	cycle = rte_get_timer_cycles();

	for (i = 0; i < job_num; i++) {
		qdma_demo_validate_set(job[i]);
		rte_memcpy((void *)job[i]->vdst,
			(void *)job[i]->vsrc,
			RTE_DPAA2_QDMA_LEN_FROM_LENGTH(job[i]->len));
	}
	if (g_latency)
		calculate_latency(lcore_id, cycle, job_num);

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
lcore_qdma_process_loop(__attribute__((unused)) void *arg)
{
	uint32_t lcore_id;
	uint64_t cycle1 = 0;
	int ret = 0;

	uint32_t dq_num = 0;
	uint32_t burst_nb = g_scatter_gather ? 32 : g_burst;

	lcore_id = rte_lcore_id();

	/* wait synchro for slaves */
	do {
		ret = rte_atomic32_read(&synchro);
	} while (!ret);
	RTE_LOG(INFO, qdma_demo,
		"Processing coreid: %d ready, now!\n",
		lcore_id);

	latency_data[lcore_id].min = 9999999.0;
	cycle1 = rte_get_timer_cycles();
	while (!quit_signal) {
		struct dma_job *job[burst_nb];
		struct rte_dma_sge src_sge[burst_nb];
		struct rte_dma_sge dst_sge[burst_nb];
		uint32_t flags, i, job_num;
		bool error = false;
		uint16_t dq_idx[burst_nb];

		job_num = rte_ring_dequeue_bulk(g_job_ring[lcore_id],
			(void **)job, burst_nb, NULL);
		if (g_memcpy) {
			ret = qdma_demo_memcpy_process(job, job_num);
			if (ret)
				return ret;
			continue;
		}

		for (i = 0; i < job_num; i++) {
			qdma_demo_validate_set(job[i]);

			if (g_scatter_gather) {
				src_sge[i].addr = job[i]->src;
				src_sge[i].length = job[i]->len;

				dst_sge[i].addr = job[i]->dest;
				dst_sge[i].length = job[i]->len;
				continue;
			}

			flags = job[i]->flags;
			if (i == job_num - 1)
				flags |= RTE_DMA_OP_FLAG_SUBMIT;

			ret = rte_dma_copy(qdma_dev_id,
					g_vqid[lcore_id],
					job[i]->src, job[i]->dest,
					job[i]->len, flags);
			if (unlikely(ret < 0) && i > 0) {
				ret = rte_dma_submit(qdma_dev_id,
						g_vqid[lcore_id]);
				if (ret) {
					RTE_LOG(ERR, qdma_demo,
						"DMA submit error(%d)\n", ret);
					rte_exit(EXIT_FAILURE,
						"Job submit failed\n");
				}
				goto dequeue;
			}
			if (unlikely(ret < 0))
				goto dequeue;
		}

		if (g_scatter_gather && job_num > 0) {
			ret = rte_dma_copy_sg(qdma_dev_id,
					g_vqid[lcore_id], src_sge, dst_sge,
					job_num, job_num,
					RTE_DMA_OP_FLAG_SUBMIT);
			if (unlikely(ret)) {
				RTE_LOG(ERR, qdma_demo,
					"SG DMA submit %d jobs error(%d)\n",
					job_num, ret);
				rte_exit(EXIT_FAILURE,
					"Job submit failed\n");
			}
		}
dequeue:
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
		if (g_latency) {
			calculate_latency(lcore_id, cycle1, dq_num);
			cycle1 = rte_get_timer_cycles();
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
	uint32_t lcore_id, uint32_t idx)
{
	int src_mem = 0, dst_mem = 0;
	char nm[RTE_MEMZONE_NAMESIZE];
	uint64_t total_size = TEST_PACKETS_NUM * TEST_PACKET_SIZE;
	uint32_t i;
	uint64_t src_iova, dst_iova;
	uint64_t src_va, dst_va;

	if (g_test_path == MEM_TO_MEM) {
		src_mem = 1;
		dst_mem = 1;
	} else if (g_test_path == MEM_TO_PCI) {
		src_mem = 1;
		dst_mem = 0;
	} else if (g_test_path == PCI_TO_MEM) {
		src_mem = 0;
		dst_mem = 1;
	} else if (g_test_path == PCI_TO_PCI) {
		src_mem = 0;
		dst_mem = 0;
	}

	if (src_mem) {
		sprintf(nm, "memz-src-%d", lcore_id);
		g_memz_src[lcore_id] = rte_memzone_reserve_aligned(nm,
			total_size, 0,
			RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!g_memz_src[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"src mem zone created failed on core%d\n",
				lcore_id);
			return -ENOMEM;
		}
		src_iova = g_memz_src[lcore_id]->iova;
		src_va = g_memz_src[lcore_id]->addr_64;
	} else {
		src_iova = g_pci_iova + idx * g_pci_size;
		src_va = (uint64_t)g_pci_vir + idx * g_pci_size;
	}

	if (dst_mem) {
		sprintf(nm, "memz-dst-%d", lcore_id);
		g_memz_dst[lcore_id] = rte_memzone_reserve_aligned(nm,
			total_size, 0,
			RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!g_memz_dst[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"src mem zone created failed on core%d\n",
				lcore_id);
			return -ENOMEM;
		}
		dst_iova = g_memz_dst[lcore_id]->iova;
		dst_va = g_memz_dst[lcore_id]->addr_64;
	} else {
		dst_iova = g_pci_iova + idx * g_pci_size;
		dst_va = (uint64_t)g_pci_vir + idx * g_pci_size;
	}

	for (i = 0; i < TEST_PACKETS_NUM; i++) {
		jobs[i].src = START_ADDR(src_iova, i);
		jobs[i].vsrc = START_ADDR(src_va, i);

		jobs[i].dest = START_ADDR(dst_iova, i);
		jobs[i].vdst = START_ADDR(dst_va, i);

		jobs[i].len = RTE_DPAA2_QDMA_IDX_LEN(i, TEST_PACKET_SIZE);
	}

	return 0;
}

static int
qdma_demo_job_ring_init(void)
{
	uint32_t lcore_id, cores = core_count, i, idx = 0;
	uint64_t total_size = TEST_PACKETS_NUM * TEST_PACKET_SIZE;
	char nm[RTE_MEMZONE_NAMESIZE];
	struct dma_job *job;
	int ret;

	if (g_pci_phy != RTE_BAD_IOVA) {
		g_pci_vir = pci_addr_mmap(NULL, g_pci_size,
			PROT_READ | PROT_WRITE, MAP_SHARED,
			g_pci_phy, NULL, NULL);
		if (!g_pci_vir) {
			RTE_LOG(ERR, qdma_demo,
				"Failed to mmap PCI addr %lx\n",
				g_pci_phy);
			return -ENOMEM;
		}
		if (rte_eal_iova_mode() == RTE_IOVA_PA)
			g_pci_iova = g_pci_phy;
		else
			g_pci_iova = (uint64_t)g_pci_vir;
		/* configure pci virtual address in SMMU via VFIO */
		rte_fslmc_vfio_mem_dmamap((uint64_t)g_pci_vir,
			g_pci_iova, g_pci_size);
	}

	if (g_test_path == PCI_TO_PCI)
		g_pci_size = g_pci_size / 2;
	g_pci_size = g_pci_size / (core_count - 1);
	if (g_test_path != MEM_TO_MEM) {
		while (g_pci_size < total_size)
			g_packet_num = g_packet_num / 2;

		if (g_packet_num < 32) {
			RTE_LOG(ERR, qdma_demo,
				"Too small pci size(%lx)\n",
				g_pci_size);
			return -EINVAL;
		}
	}
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (cores == 1)
			break;
		cores--;
		sprintf(nm, "job-ring-%d", lcore_id);
		g_job_ring[lcore_id] = rte_ring_create(nm,
			TEST_PACKETS_NUM * 2, 0, 0);
		if (!g_job_ring[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"job ring created failed on core%d\n",
				lcore_id);
			return -ENOMEM;
		}
		g_jobs[lcore_id] = rte_zmalloc("test qdma",
			TEST_PACKETS_NUM * sizeof(struct dma_job), 4096);
		if (!g_jobs[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"jobs created failed on core%d\n",
				lcore_id);
			return -ENOMEM;
		}

		ret = qdma_demo_jobs_init(g_jobs[lcore_id], lcore_id, idx);
		if (ret)
			return ret;

		job = g_jobs[lcore_id];
		for (i = 0; i < TEST_PACKETS_NUM; i++) {
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
	float ns_per_cyc = (1000 * rate) / freq;
	uint64_t cycle1 = 0, cycle2 = 0, cycle_diff;
	float speed;
	int ret, offset, log_len;
	uint32_t i;
	char perf_buf[1024];

	lcore_id = rte_lcore_id();

	/* wait synchro for slaves */
	if (!g_memcpy)
		test_dma_init();

	/* setup QDMA queues */
	for (i = 0; (!g_memcpy) && i < RTE_MAX_LCORE; i++) {
		if (!rte_lcore_is_enabled(i))
			continue;

		ret = rte_dma_info_get(qdma_dev_id, &info);
		if (ret)
			return ret;

		conf.direction = RTE_DMA_DIR_MEM_TO_MEM;
		conf.nb_desc = info.max_desc;
		conf.src_port.port_type = RTE_DMA_PORT_NONE;
		conf.dst_port.port_type = RTE_DMA_PORT_NONE;
		g_vqid[i] = i;
		ret = rte_dma_vchan_setup(qdma_dev_id, g_vqid[i], &conf);
		if (ret) {
			RTE_LOG(ERR, qdma_demo,
				"Vchan setup failed(%d)\n", ret);
			return ret;
		}
	}

	if (!g_memcpy) {
		ret = rte_dma_start(qdma_dev_id);
		if (ret) {
			RTE_LOG(ERR, qdma_demo, "Failed to start DMA[0](%d)\n",
				ret);
			return ret;
		}
	}

	ret = qdma_demo_job_ring_init();
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
		speed = (float)diff /
			(ns_per_cyc * cycle_diff / (1000 * 1000 * 1000));
		speed = speed * TEST_PACKET_SIZE;

		offset = 0;

		log_len = sprintf(&perf_buf[offset], "Statistics:\n");
		offset += log_len;

		log_len = sprintf(&perf_buf[offset],
			"Time Spend :%.3f ms rcvd cnt:%ld\n",
			(ns_per_cyc * cycle_diff) / (1000 * 1000),
			diff);
		offset += log_len;

		log_len = sprintf(&perf_buf[offset],
			"Rate: %.3f Mbps OR %.3f Kpps\n",
			8 * speed / (1000 * 1000),
			speed / (TEST_PACKET_SIZE * 1000));
		offset += log_len;

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
	char buf[2048];
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
	j = sprintf(&buf[pos], "	: --pci_addr <target_pci_addr>\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --packet_size <bytes>\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --test_case <test_case_name>\n");
	pos += j;
	for (i = 0; i < ARRAY_SIZE(test_case); i++) {
		j = sprintf(&buf[pos], "		%s - %s\n",
			test_case[i].name, test_case[i].help);
		pos += j;
	}
	j = sprintf(&buf[pos], "	: --latency_test\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --memcpy\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --scatter_gather\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --burst\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --packet_num\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --validate\n");

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
		if (ret == EOF) {
			RTE_LOG(ERR, qdma_demo, "Invalid PCI address\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "PCI addr %lx\n", g_pci_phy);
		break;
	case ARG_SIZE:
		ret = sscanf(optarg, "%ld", &g_packet_size);
		if (ret == EOF) {
			RTE_LOG(ERR, qdma_demo, "Invalid Packet size\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "Pkt size %ld\n", g_packet_size);
		break;
	case ARG_TEST_ID:
		for (i = 0; i < ARRAY_SIZE(test_case); i++) {
			ret = strncmp(test_case[i].name, optarg,
				TEST_CASE_NAME_SIZE);
			if (!ret) {
				g_test_path = test_case[i].id;
				break;
			}
		}
		if (i == ARRAY_SIZE(test_case)) {
			RTE_LOG(ERR, qdma_demo, "Invalid test case\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "test case %s\n", test_case[i].name);
		break;
	case ARG_LATENCY:
		g_latency = 1;
		break;
	case ARG_MEMCPY:
		g_memcpy = 1;
		break;
	case ARG_SCATTER_GATHER:
		g_scatter_gather = 1;
		break;
	case ARG_BURST:
		ret = sscanf(optarg, "%u", &g_burst);
		if (ret == EOF) {
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
		if (ret == EOF) {
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
	 {"packet_size", optional_argument, &flg, ARG_SIZE},
	 {"test_case", required_argument, &flg, ARG_TEST_ID},
	 {"latency_test", optional_argument, &flg, ARG_LATENCY},
	 {"memcpy", optional_argument, &flg, ARG_MEMCPY},
	 {"scatter_gather", optional_argument, &flg, ARG_SCATTER_GATHER},
	 {"burst", optional_argument, &flg, ARG_BURST},
	 {"packet_num", optional_argument, &flg, ARG_NUM},
	 {"validate", optional_argument, &flg, ARG_VALIDATE},
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

	if (g_test_path != MEM_TO_MEM)
		valid = !!(g_arg_mask & ARG_PCI_ADDR);

	if (!(g_arg_mask & ARG_SIZE)) {
		RTE_LOG(WARNING, qdma_demo,
			"Using Default packet size %ld bytes\n",
			g_packet_size);
	}

	core_count = rte_lcore_count();
	if (core_count < 2) {
		RTE_LOG(ERR, qdma_demo, "Insufficient cores %d < 2\n",
			core_count);
		valid = 0;
		goto out;
	}

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
	float ns_per_cyc;
	uint64_t start_cycles, end_cycles;
	uint64_t time_diff;

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
		g_pci_size = pci_find_bar_available_size(g_pci_phy);
		if (!g_pci_size) {
			RTE_LOG(ERR, qdma_demo,
				"PCI address 0x%lx not found for %s(%d)!\n",
				g_pci_phy,
				g_test_path == MEM_TO_PCI ? "mem2pci" :
				g_test_path == PCI_TO_MEM ? "pci2mem" :
				g_test_path == PCI_TO_PCI ? "pci2pci" :
				"invalid path", g_test_path);

			return 0;
		}
		if (g_pci_phy % PAGE_SIZE) {
			RTE_LOG(ERR, qdma_demo,
				"PCI addr(%lx) not multiple of page size\n",
				g_pci_phy);
			return 0;
		}
		if (g_pci_size % PAGE_SIZE) {
			RTE_LOG(ERR, qdma_demo,
				"PCI size(%lx) not multiple of page size\n",
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
	rate = (1000) / ((ns_per_cyc * time_diff) / (1000 * 1000));
	RTE_LOG(INFO, qdma_demo, "Rate:%.5f cpu freq:%ld MHz\n",
		rate, freq);

	start_cycles = rte_get_timer_cycles();
	rte_delay_ms(2000);
	end_cycles = rte_get_timer_cycles();
	time_diff = end_cycles - start_cycles;

	RTE_LOG(INFO, qdma_demo, "Spend :%.3f ms\n",
		(ns_per_cyc * time_diff * rate) / (1000 * 1000));

	ret = launch_cores(core_count);
	if (ret < 0)
		goto out;
	RTE_LOG(INFO, qdma_demo, "qdma_demo Finished.. bye!\n");
	return 0;
out:
	RTE_LOG(ERR, qdma_demo, "qdma_demo Failed!\n");
	return 0;
}
