/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/queue.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#ifdef IPC_USE_SBUF
#include <rte_eal_sbuf.h>
#endif
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_malloc.h>
#include <rte_common.h>
#include <rte_rawdev.h>
#include <rte_cycles.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <gul_pci_def.h>
#include <gul_host_if.h>
#include <geul_cpe_ipc.h>
#include <geul_cpe_ipc_api.h>
#include <rte_pmd_geul_ipc_rawdev.h>
#define UNUSED(x) void(x)

//#define ipc_debug(...) printf(__VA_ARGS__)
#define ipc_debug(...)

#define GEUL_DEVICE_ID "0"
#define GEUL_DEVICE_SEP "_"
/* Device name has to follow a certain naming pattern to be probed; this
 * includes having the driver name as the initial part; (or use device
 * alias - not implemented right now) - followed by ID
 */
#define GEUL_DEVICE_NAME (GEUL_IPC_RAWDEV_NAME_PREFIX GEUL_DEVICE_SEP GEUL_DEVICE_ID)

/* Only a single instance is supported */
#define GEUL_INSTANCE_ID 0
/* A prefix of pool name to create unique names */
#define POOL_NAME_PREFIX "geul_pool_"
/* Pool element counts */
#define POOL_2K_COUNT (152 * 1024)
#define POOL_4K_COUNT 15
#define POOL_128K_COUNT 256
#define SH_POOL_COUNT 150
/* Other pool values */
#define PRIVATE_DATA_SIZE 256
#define CACHE_SIZE	0
#define MSG_SIZE_4K	192/* QDMA compatible size */

#define CPU_FREQ_MHZ_2000 2000000
#define CPU_FREQ_MHZ_1400 1400000

/* L2 stack processing delay for geode. 34.5k Cycles */
#define GEODE_CPU_SPIN_CYCLES	34500

#define WARMUP_PKTS    2

enum run_mode {
	LATENCY_POLL = 0,
	LATENCY_L2_INT,
	LATENCY_L2_L1_INT,
	PERFORMANCE_1CC,
	PERFORMANCE_8CC,
	RUN_MODE_MAX
};

struct hugepage_info {
	void *vaddr;
	phys_addr_t paddr;
	size_t len;
};

typedef struct thread_info {
	ipc_t instance_handle;
	int ch_id;
	/* Epoll Fd */
	int32_t epoll_fd;
} thread_info_t;


/* TestApp Mode
 * Default = LATENCY;
 */
uint8_t test_mode = LATENCY_POLL;
uint64_t hz;

/* Driven by ipc_memelem_size, creating mempools which would be passed
 * as it it to the host_init call
 */
struct rte_mempool *pools[IPC_HOST_BUF_MAX_COUNT];
struct geulipc_channel *channels[CHANNELS_MAX];

/* mask of event (interrupt) enabled channels */
int32_t int_enabled_ch_mask;
int32_t ch_mask;
uint64_t hp_buf_ptr;

struct gul_stats *stats; /**< Stats for Host & modem (HIF) */

/* Signal control */
static uint8_t force_quit;

RTE_DEFINE_PER_LCORE(int, cpu_freq);

typedef struct latency_info {
	uint64_t timestamp;
	uint64_t modem_delta;
} latency_info_t;

float min_latency;
float avg_latency;
float max_latency;
__thread uint64_t pkt_count;

/* Duration to run the test
 * Default is 1 sec
 */
int duration = 1;
volatile int timer_running;
int num_pkts;
static struct rte_timer timer;

static int get_cpu_current_frequency(int processor_id);

/* timer callback */
#define TMR_2 0
#if TMR_2
static struct rte_timer timer2;
static void
tx_timer_cb(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) void *arg)
{
	/* Unblock the Sender */
	//pthread_mutex_unlock(&tx_lock);
	ipc_debug("%s: ------> Timer-2 expried on lcore %u\n", __func__, rte_lcore_id());
}
#endif

static void
main_timer_cb(struct rte_timer *tim, __attribute__((unused)) void *arg)
{
	unsigned int lcore_id = rte_lcore_id();

	printf("%s: ------> Timer expried on lcore %u\n", __func__, lcore_id);
	timer_running = 0;
#if TMR_2
	/* Unblock the Sender thread if waiting so that it can exit */
	tx_timer_cb(NULL, NULL);
#endif
	rte_timer_stop(tim);
}

/*
 * From a given mempool, fetch the information about the physical backing
 * hugepage info. This function assumes that all mempool (or at least
 * mempool passed) is spreading across ONLY A SINGLE HUGEPAGE.
 */
static void
iter_for_each_chunk(struct rte_mempool *mp,
		void *opaque __rte_unused,
		struct rte_mempool_memhdr *memhdr,
		unsigned mem_idx __rte_unused)
{
	struct hugepage_info *hp_info;
	struct rte_memseg *mseg;

	/* Just a safegaurd - in case this is called without opaque set
	 * to hugepage_info structure
	 */
	if (!opaque)
		return;

	hp_info = (struct hugepage_info *)opaque;
	mseg = rte_mem_virt2memseg(memhdr->addr, NULL);

	if (hp_info->vaddr && (memhdr->addr != hp_info->vaddr)) {
		printf("WARN: More than one memory segment observed."
		       " Not Supported (pool=%s)\n", mp->name);
	}

	/* Only update not already updated */
	if (!hp_info->vaddr) {
		hp_info->vaddr = mseg->addr;
		hp_info->paddr = rte_mem_virt2phy(mseg->addr);
		hp_info->len = mseg->len;
	}

	ipc_debug("hugepage info vaddr=%p, paddr=%lu, len=%lu\n",
	      hp_info->vaddr, hp_info->paddr, hp_info->len);

}

static struct hugepage_info *
get_hugepage_info(struct rte_mempool *mp)
{
	struct hugepage_info *hp_info;

	if (!mp)
		return NULL;

	hp_info = calloc(1, sizeof(struct hugepage_info));
	if (!hp_info) {
		printf("Unable to allocate on local heap\n");
		return NULL;
	}

	rte_mempool_mem_iter(mp, iter_for_each_chunk, hp_info);
	return hp_info;
}


static inline void
calc_latency(void *buffer)
{
	latency_info_t *latency_info;
	uint64_t now, latency;

	now = rte_rdtsc();
	latency_info = (latency_info_t *)buffer;
	/* TODO adjust Modem detla cycles */

	ipc_debug("%s: received pkt @ timestamp [%ld]\n",
			__func__, latency_info->timestamp);
	latency = (now - latency_info->timestamp) / 2;
	if (min_latency == 0)
		max_latency = min_latency = latency;
	else if (latency < min_latency)
		min_latency = latency;
	else if (latency > max_latency)
		max_latency = latency;

	avg_latency += latency;
}

static int
create_mempools(void)
{
	int i;
	char pool_name[32];
	uint32_t elem_size = 0, elem_count = 0;

	memset(pools, 0, IPC_HOST_BUF_MAX_COUNT * sizeof(struct rte_mempool *));
	memset(pool_name, 0, 32);

	/* For now skipping IPC_HOST_BUF_POOLSZ_R2 */
	for (i = 0; i < IPC_HOST_BUF_MAX_COUNT - 1; i++) {
		sprintf(pool_name, "%s%d", POOL_NAME_PREFIX, i);
		switch (i) {
		case IPC_HOST_BUF_POOLSZ_2K:
			elem_size = 2*1024;
			elem_count = POOL_2K_COUNT;
			break;
		case IPC_HOST_BUF_POOLSZ_4K:
			elem_size = MSG_SIZE_4K;
			elem_count = POOL_4K_COUNT;
			break;
		case IPC_HOST_BUF_POOLSZ_128K:
			elem_size = 128*1024;
			elem_count = POOL_128K_COUNT;
			break;
		case IPC_HOST_BUF_POOLSZ_SH_BUF:
			elem_size = sizeof(ipc_sh_buf_t);
			elem_count = SH_POOL_COUNT;
			break;
		default:
			printf("Invalid size of mempool specified:"
			       "(case %d)\n", i);
			goto cleanup;
		}

		/* Create a pool of (elem_count * elem_size), no contructor
		 * or destructor, no cache, no private_data and no flags
		 * and on socket_id = 0
		 */
		pools[i] = rte_mempool_create(pool_name, elem_count, elem_size,
					      CACHE_SIZE, PRIVATE_DATA_SIZE,
					      NULL, NULL, NULL, NULL,
					      rte_socket_id(), 0);
		if (!pools[i]) {
			printf("Unable to allocate pool "
			       "(%i:enum ipc_mempool_size)\n", i);
			goto cleanup;
		}
		ipc_debug("Created pool %s with (%ux%u) dimensions\n",
			  pools[i]->name, elem_count, elem_size);
	}

	return 0;

cleanup:
	ipc_debug("Error creating pools: Cleanup initiated\n");
	for (i = 0; i < IPC_HOST_BUF_MAX_COUNT; i++)
		rte_mempool_free(pools[i]);
	return -1;
}

static void
cleanup_mempools(void)
{
	int i;

	for (i = 0; i < IPC_HOST_BUF_MAX_COUNT; i++) {
		rte_mempool_free(pools[i]);
		pools[i] = NULL;
	}
}

static int
initialize_channels(ipc_t instance __rte_unused)
{
	int i, ret = 0;
	struct gul_hif *hif_start = NULL;
	geulipc_channel_t *ch = NULL;
	ipc_userspace_t *ipcu;
	uint8_t en_event = 0;

	if (!instance) {
		printf("Invalid instance handle\n");
		return -1;
	}

	ipcu = (ipc_userspace_t *)instance;
	hif_start = (struct gul_hif *)ipcu->mhif_start.host_vaddr;

	/* Point to the HIF stats */
	stats = &(hif_start->stats);
	memset(channels, 0, sizeof(struct geulipc_channel *) * CHANNELS_MAX);
	for (i = 0; i < CHANNELS_MAX; i++) {
		channels[i] = malloc(sizeof(geulipc_channel_t));
		if (!channels[i]) {
			printf("Unable to alloc channel mem (%d)\n", i);
			goto cleanup;
		}
		ch = channels[i];

		ipc_debug("Attempting initilaztion (%d)\n", i);

		switch (i) {
#define MSG_CHANNEL_DEPTH 64
		case L2_TO_L1_MSG_CH_1:
			/* 2K Channel */
			strcpy(ch->name, "L2_TO_L1_MSG_CH_1");
			ch->depth = MSG_CHANNEL_DEPTH;
			ch->type = IPC_CH_MSG;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_2K];
			ch->channel_id = i;
			if (test_mode == LATENCY_L2_L1_INT)
				ipc_channel_set_msi_valid(ch->channel_id, 1, instance);
			/* Configure channels is not called for MSG Consumer */
			continue;
		case L2_TO_L1_MSG_CH_2:
			/* 2K Channel */
			strcpy(ch->name, "L2_TO_L1_MSG_CH_2");
			ch->depth = MSG_CHANNEL_DEPTH;
			ch->type = IPC_CH_MSG;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_2K];
			ch->channel_id = i;
			if (test_mode == LATENCY_L2_L1_INT)
				ipc_channel_set_msi_valid(ch->channel_id, 1, instance);
			/* Configure channels is not called for MSG Consumer */
			continue;
		case L2_TO_L1_MSG_CH_3:
			/* 4K Channel */
			strcpy(ch->name, "L2_TO_L1_MSG_CH_3");
			ch->depth = MSG_CHANNEL_DEPTH;
			ch->type = IPC_CH_PTR;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_4K];
			ch->channel_id = i;
			if (test_mode == LATENCY_L2_L1_INT)
				ipc_channel_set_msi_valid(ch->channel_id, 1, instance);
			/* Configure channels is not called for MSG Consumer */
			continue;
		case L1_TO_L2_MSG_CH_4:
			/* 2K Channel */
			strcpy(ch->name, "L1_TO_L2_MSG_CH_4");
			ch->depth = MSG_CHANNEL_DEPTH;
			ch->type = IPC_CH_MSG;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_2K];
			ch->channel_id = i;
			ch->en_napi = 0;
			if (test_mode != LATENCY_POLL)
				en_event = 1 ;
			break;
		case L1_TO_L2_MSG_CH_5:
			/* 2K Channel */
			strcpy(ch->name, "L1_TO_L2_MSG_CH_5");
			ch->depth = MSG_CHANNEL_DEPTH;
			ch->type = IPC_CH_MSG;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_2K];
			ch->channel_id = i;
			ch->en_napi = 0;
			if (test_mode != LATENCY_POLL)
				en_event = 1 ;
			break;
		case L1_TO_L2_PRT_CH_1:
#define PRT_CHANNEL_DEPTH 64
			/* 128K Channel */
			strcpy(ch->name, "L1_TO_L2_PRT_CH_1");
			ch->depth = PRT_CHANNEL_DEPTH;
			ch->type = IPC_CH_PTR;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_128K];
			ch->channel_id = i;
			ch->en_napi = 0;
			if (test_mode == PERFORMANCE_8CC)
				en_event = 2;
			else if (test_mode != LATENCY_POLL)
				en_event = 1;
			break;
		case L1_TO_L2_PRT_CH_2:
			/* 128K Channel */
			strcpy(ch->name, "L1_TO_L2_PRT_CH_2");
			ch->depth = PRT_CHANNEL_DEPTH;
			ch->type = IPC_CH_PTR;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_128K];
			ch->channel_id = i;
			ch->en_napi = 0;
			if (test_mode == PERFORMANCE_8CC)
				en_event = 2;
			else if (test_mode != LATENCY_POLL)
				en_event = 1;
			break;
		default:
			printf("Invalid channel number/type (%d)\n", i);
			goto cleanup;
		}

		ipc_debug("Configuring channel (%d) with en_event %d\n",
						ch->channel_id, en_event);
		/* Call ipc_configure_channel */
		ret = ipc_configure_channel(ch->channel_id, ch->depth,
					    ch->type, ch->mp->elt_size,
					    en_event, instance);
		if (ret) {
			printf("Unable to configure channel (%d) (err=%d)\n",
			       i, ret);
			goto cleanup;
		}
		/* Store the Event FD if events are required */
		if (en_event)
			ch->eventfd = ipc_get_eventfd(ch->channel_id, instance);
		else
			ch->eventfd = -1;
	}
	return ret;

cleanup:
	for (; i > 0; i--) {
		if (channels[i]) {
			free(channels[i]);
			channels[i] = NULL;
		}
	}

	return -1;
}

static ipc_t
setup_ipc(uint16_t devid)
{
	int ret;
	struct rte_rawdev_info rdev_conf = {0};
	struct hugepage_info *hp;
	geulipc_rawdev_config_t config = {0};
	mem_range_t mr = {0};
	ipc_t handle = NULL;

	ret = create_mempools();
	if (ret) {
		printf("Unable to create mempools. Not conitnuing\n");
		return NULL;
	}
#ifdef IPC_USE_SBUF
	mr.size = dpaa_get_scratch_buf_size();
	if (mr.size) {
		mr.host_phys = dpaa_get_scratch_buf_paddr();
		mr.host_vaddr = dpaa_get_scratch_buf_vaddr();
	} else
#endif
	{
		/* Get the hugepage info against it */
		hp = get_hugepage_info(pools[0]);
		if (!hp) {
			printf("Unable to get hugepage info\n");
			goto err_out;
		}

		mr.host_phys = hp->paddr;
		mr.host_vaddr = hp->vaddr;
		mr.size = hp->len;
		free(hp);
	}
	ipc_debug("%lx %p %x\n", mr.host_phys, mr.host_vaddr, mr.size);

	/* Call IPC host init */
	handle = ipc_host_init(GEUL_INSTANCE_ID, pools, mr, &ret);
	if (ret != IPC_SUCCESS) {
		printf("--->Error from HOST initialization (%d)\n", ret);
		goto err_out;
	}

	/* Create the channels and get their IDs */
	ret = initialize_channels(handle);
	if (ret || !channels[0]) {
		printf("Unable to setup channels\n");
		goto err_out;
	}

	/* Send this info of handle to driver - just for future access */
	config.instance_handle = handle;
	config.device_id = GEUL_INSTANCE_ID;

	/* Wrap that into the rte_rawdev_info structure */
	rdev_conf.dev_private = &config;

	/* Configure the Geul device - includes host initialization */
	ret = rte_rawdev_configure(devid, &rdev_conf, sizeof(rdev_conf));
	if (ret < 0) {
		printf("Unable to configure device (%s): (%d)\n",
			   GEUL_DEVICE_NAME, ret);
		goto err_out;
	}

	return handle;

err_out:
	if (handle) {
		/* Ideally some host deinit should be done, but none exists */
		//ipc_host_deinit() //TODO in future, implement
		handle = NULL;
	}
	cleanup_mempools();

	return handle;
}

static int
parse_ch_mask(const char *ch_mask)
{
	char *end = NULL;
	unsigned long mask;

	/* parse hexadecimal string */
	mask = strtoul(ch_mask, &end, 16);
	if ((ch_mask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return mask;
}

static void
usage(char *prgname)
{
	fprintf(stderr, "\nUsage: %s [EAL args] -- [-t duration] "
					"[-m MODE]  [-e CH_MASK]\n"
			"-t duration: duration in seconds to run the benchmark\n"
			"          (default 1 sec)\n\n"
			"-e CH_MASK: Mask for channels to include in test\n"
			"          maximum of 2 channels are allowed\n\n"
			"	   In Latency Mode, use channel mask as: \n"
			"	-e 0xC  =  For L2_L1_MSG_3 <---> L1_L2_MSG_4 pair\n"
			"	-e 0x12 =  For L2_L1_MSG_2 <---> L1_L2_MSG_5 pair\n"
			"	-e 0x21 =  For L2_L1_MSG_1 <---> L1_L2_PTR_1 pair\n"
			"          In Performance Mode, channel mask is set by default.\n\n"
			"-m MODE : Mode of running:\n"
			"          0 - Letency_Poll (default)\n"
			"          1 - Latency_L2_Events\n"
			"          2 - Latency_L2_L1_Events\n"
			"          3 - Performance in 1-CC\n"
			"          4 - Performance in 8-CC\n\n"
			"-n num_pkts :  app will Send / Recv only num_pkts\n"
			"	   Mainly used in Latency mode\n"
			"\n------------ Sample configuration commands: -----------\n"
			" Latency Poll Mode:\n"
			"		geul_ipc_benchmark -c 0xF -- -e 0x12 -n 4\n"
			"\nPerformance 1-CC:\n"
			"		geul_ipc_benchmark -c 0xF -- -m 3 -t 30 \n\n",
			prgname);
}

static int
parse_args(int argc, char **argv)
{
	int opt;
	int mode;

	while ((opt = getopt(argc, argv, "t:e:m:n:h")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 't':
			if (!optarg) {
				printf("Arg parse error: Invalid duration value\n");
				return -1;
			}
			duration = atoi(optarg);
			if (duration < 0) {
				printf("Arg parse error: Invalid value for duration: (%d)\n", duration);
				printf("Assuming default = 5\n");
				duration = 5;
			}
			ipc_debug("Argument: Parsed duration = %d\n", duration);
			break;
		case 'n':
			if (!optarg) {
				printf("Arg parse error: Invalid num_pkts value\n");
				return -1;
			}
			num_pkts = atoi(optarg);
			break;
		case 'e':
			ch_mask = parse_ch_mask(optarg);
			if (ch_mask == -1) {
				printf("Invalid channel mask\n");
				return -1;
			}
			ipc_debug("Argument: ch_mask = 0x%X\n", ch_mask);
			break;
		case 'm':
			if (!optarg) {
				printf("Arg parse error: Invalid MODE value\n");
				return -1;
			}
			mode = atoi(optarg);
			if (mode < 0 || mode >= RUN_MODE_MAX) {
				printf("Arg parse error: Invalid MODE value (%d)\n", mode);
				return -1;
			}
			test_mode = mode;
			ipc_debug("Argument: Parsed Mode = %d\n", test_mode);

			if (test_mode >= PERFORMANCE_1CC)
				ch_mask = 0x64; /* In PerfMode */
			break;
		default:
			usage(argv[0]);
		}
	}

	return 0;
}

static int
is_modem_ready(ipc_t handle __rte_unused)
{
	ipc_debug("%d %s\n", __LINE__, __func__);
	usleep(5000);
	ipc_debug("\n\n\n");
	struct gul_hif *hif_start = NULL;
	ipc_userspace_t *ipcu;
	int ready = 1;

	if (!handle) {
		printf("Invalid handle for modem ready check\n");
		return -1;
	}

	ipcu = (ipc_userspace_t *)handle;
	ipc_debug("%d %s %p\n", __LINE__, __func__, handle);
	hif_start = (struct gul_hif *)ipcu->mhif_start.host_vaddr;
	ipc_debug("%d %s %p\n", __LINE__, __func__, hif_start);

	/* Set Host Read bit */
	SET_HIF_HOST_RDY(hif_start, HIF_HOST_READY_IPC_APP);

	/* Now wait for modem ready bit */
	while (ready && !force_quit)
		ready = !CHK_HIF_MOD_RDY(hif_start, HIF_MOD_READY_IPC_APP);

	if (force_quit)
		ready = 1;

	return ready;
}

static inline int
_recv(struct rte_mempool *mp, uint32_t channel_id, thread_info_t *th_args, int *warmup_pkt_count)
{
	int ret;
	uint32_t len;
	void *buffer;
	uint64_t timeout_ms = 1000 * 2; /* 2 Sec */
	struct epoll_event events[1];
	int  nfds;


	if (test_mode != LATENCY_POLL) {
		nfds = epoll_wait(th_args->epoll_fd, events, 1, timeout_ms);
		if (nfds <= 0)
			return IPC_CH_EMPTY;
	}
	ret = ipc_recv_msg_ptr(channel_id, &buffer, &len, th_args->instance_handle);
	if ((IPC_SUCCESS == ret) && len > 0 && len <= mp->elt_size) {
		/* Measure the latency */
		if (*warmup_pkt_count > 0)
			(*warmup_pkt_count)--;
		else
			calc_latency(buffer);
		ipc_set_consumed_status(channel_id, th_args->instance_handle);
		pkt_count++;

	} else if (ret == IPC_CH_EMPTY && !force_quit) {
		goto out;
	} else if (ret) {
		printf("Error from ipc_recv_msg_ptr %d\n", ret);
		goto out;
	} else if (len == 0)
		printf("Invalid length of received buffer. recvd:%u\n", len);
out:
	return ret;
}

#if defined(RTE_ARCH_ARM64)
static inline uint64_t mfatb(void)
{
	uint64_t ret, ret_new, timeout = 200;
	uint64_t cpu_cycles_per_generic_timer_tick = (uint64_t)RTE_PER_LCORE(cpu_freq) / (rte_get_timer_hz() / 1000);

	if (cpu_cycles_per_generic_timer_tick == 0)
		return 0;

	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret));
	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	while (ret != ret_new && timeout--) {
		ret = ret_new;
		asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	}
	if (!timeout && (ret != ret_new)) {
		printf("BUG: cannot spin\n");
		abort();
	}

	return (ret * cpu_cycles_per_generic_timer_tick);
}
#else
#define mfatb rte_rdtsc
#endif

/* Spin for a few cycles without bothering the bus */
static inline void cpu_spin(int cycles)
{

	if (RTE_PER_LCORE(cpu_freq) == CPU_FREQ_MHZ_1400) {
		/* For LS1043 based Geode */
		int j, count;

		/* On Geode, following instruction is taking ~ 2 cycles */
		count = cycles/2;
		for (j=0; j < count; j++)
			__asm__ __volatile__ ("" : "+g" (j) : :);

	} else { /* Redstone */
		uint64_t now = mfatb();

		if (now == 0) {
			printf("Error: Cannot empty spin CPU\n");
			exit(-1);
		}
		while (mfatb() < (now + cycles))
			;
	}
}

static inline int
_recv_ptr(struct rte_mempool *mp __rte_unused, uint32_t channel_id,
	  thread_info_t *th_args, int *warmup_pkt_count)
{
	int err;
	ipc_sh_buf_t sh_bd;
	uint64_t buffer = 0;
	uint64_t timeout_ms = 1000 * 2; /* 2 Sec */
	struct epoll_event events[1];
	int  nfds;

	if (test_mode == PERFORMANCE_1CC) {
		nfds = epoll_wait(th_args->epoll_fd, events, 1, timeout_ms);
		if (nfds <= 0)
			return IPC_CH_EMPTY;
	}

	if (test_mode <= PERFORMANCE_1CC) {
		/* 1-CC usecase */
		err = ipc_recv_ptr(channel_id, (void *)&sh_bd, th_args->instance_handle);
		if (err != IPC_SUCCESS)
			goto out;

		/* The Dummy Read thread (main) will keep on reading from here */
		buffer = sh_bd.host_virt_h;
		hp_buf_ptr = JOIN_VA32_64_APP(buffer, sh_bd.host_virt_l);

		if (test_mode <= LATENCY_L2_L1_INT) {
			if (*warmup_pkt_count > 0)
				(*warmup_pkt_count)--;
			else
				calc_latency((void *)hp_buf_ptr);
		}
		pkt_count++;
		ipc_put_buf(channel_id, &sh_bd, th_args->instance_handle);

	} else if (test_mode == PERFORMANCE_8CC) {
		int i;

		/* Receive 4 packets after each event in 8-CC usecase */
		//ipc_channel_set_msi_valid(channel_id, 0, th_args->instance_handle);
		for (i = 0; i < 4; i++) {
			err = ipc_recv_ptr(channel_id, (void *)&sh_bd, th_args->instance_handle);
			if (unlikely(err != IPC_SUCCESS))
				//continue;
				goto out;

			/* The Dummy Read thread (main) will keep on reading from here */
			buffer = sh_bd.host_virt_h;
			hp_buf_ptr = JOIN_VA32_64_APP(buffer, sh_bd.host_virt_l);
			/* L2 stack processing delay. */
			cpu_spin(GEODE_CPU_SPIN_CYCLES);
			pkt_count++;

			ipc_put_buf(channel_id, &sh_bd, th_args->instance_handle);
			if (i == 2)
				ipc_channel_set_msi_valid(channel_id, 2, th_args->instance_handle);
		}
		if (i != 4) /*  Handle break from loop */
			ipc_channel_set_msi_valid(channel_id, 2, th_args->instance_handle);
	}
	err = 0;
out:
	return err;
}

static int
rt_sender_latency(void *arg)
{
	int ret = 1;
	int  pkt_sent = 0;
	thread_info_t *th_args;
	pid_t tid;
#define COMMAND_LEN 256
	char command[COMMAND_LEN];
	ipc_sh_buf_t *sh_buf;
	int err;
	latency_info_t *latency_info;
	ipc_userspace_t *ipcu;

	if (!arg) {
		printf("Invalid call to RT thread without args\n");
		return -1;
	}
	th_args = (thread_info_t *)arg;
	ipcu = (ipc_userspace_t *)th_args->instance_handle;

	/* Call chrt */
	tid = syscall(SYS_gettid);
	snprintf(command, COMMAND_LEN, "chrt -p 90 %d", tid);
	ret = system(command);
	if (ret < 0)
		printf("Unable to set RT priority\n");
	else
		printf("RT Priority set for Send on Core %u\n", rte_lcore_id());

	/* Wait for Timer to start */
	while (!timer_running) {
		/* Do nothing .. Keep waiting */
	};

	printf(" --> Started RT Sender (lcore_id=%u)\n", rte_lcore_id());
	/* Now continue send pkts till timer ends */
	while (timer_running) {
		/* For the L2_TO_L1_MSG_CH_3 */
		/* Insert delay between packets to avoid Interrupt coalescing */
		usleep(1000);
		if (th_args->ch_id == L2_TO_L1_MSG_CH_3) {

			sh_buf = ipc_get_buf(channels[th_args->ch_id]->channel_id,
						th_args->instance_handle, &err);
			if (sh_buf == NULL) {
				ipc_debug("ipc_get_buf failed for L2_TO_L1_MSG_CH_3,(err=%d)!\n", err);
				continue;
			} else {
				sh_buf->data_size = MSG_SIZE_4K;
				latency_info = (latency_info_t *)MODEM_PHY2VIRT(sh_buf->mod_phys, ipcu);
				latency_info->timestamp = rte_rdtsc();
				ipc_debug("%s: Sending pkt @ timestamp [%ld]\n",
						__func__, latency_info->timestamp);

				ret = ipc_send_ptr(L2_TO_L1_MSG_CH_3, sh_buf, th_args->instance_handle);
				if (ret != IPC_SUCCESS)
					printf("Unable to send msg on L2_TO_L1_MSG_CH_%d (ret=%d)\n",
									(th_args->ch_id + 1), ret);
			}
		} else {
			/* For L2_TO_L1_MSG_CH_1 & L2_TO_L1_MSG_CH_2 */
repeat:
			ret = ipc_get_msg_ptr(th_args->ch_id, th_args->instance_handle,
								(void **)&latency_info);
			if (ret == IPC_SUCCESS) {
				latency_info->timestamp = rte_rdtsc();
				ret = ipc_send_msg_ptr(th_args->ch_id, 2048, th_args->instance_handle);
				if (ret != IPC_SUCCESS)
					printf("Unable to send msg on L2_TO_L1_MSG_CH_%d (ret=%d)\n",
									(th_args->ch_id + 1), ret);

			} else if (ret == IPC_CH_FULL && !force_quit) {
				/* Loop - right now infinitely */
				ipc_debug("send_msg returned = %d, repeating\n", ret);
				goto repeat;
			}
		}
		/* Check if user need to send only specific number
		 * of packets in given time frame
		 */
		if (num_pkts) {
			pkt_sent++;
			if (pkt_sent == num_pkts + WARMUP_PKTS)
				break;
		}
		if (force_quit)
			break;
	}

	printf("Quiting RT Sender thread\n");

	return ret;
}

static int
rt_sender_perf(void *arg)
{
	int ret = 1, retry = 0;
	thread_info_t *th_args;
	pid_t tx_tid;
#define COMMAND_LEN 256
	char command[COMMAND_LEN];
	uint32_t channel_id;
	ipc_t instance;
	ipc_sh_buf_t *sh_buf;
	int err;

	if (!arg) {
		printf("Invalid call to RT thread without args\n");
		return -1;
	}
	th_args = (thread_info_t *)arg;

	RTE_PER_LCORE(cpu_freq) = get_cpu_current_frequency((int)rte_lcore_id());

	/* Call chrt */
	tx_tid = syscall(SYS_gettid);
	snprintf(command, COMMAND_LEN, "chrt -p 90 %d", tx_tid);
	ret = system(command);
	if (ret < 0)
		printf("Unable to set RT priority\n");
	else
		printf("RT Priority set for Send on Core %u\n", rte_lcore_id());

	/* Now continue send pkts till timer ends */
	channel_id = channels[th_args->ch_id]->channel_id;
	instance = th_args->instance_handle;
	/* Wait for Timer to start */
	while (!timer_running) {
		/* Do nothing .. Keep waiting */
	};
	printf(" --> Started RT Sender Perf (lcore_id=%u)\n", rte_lcore_id());

	while (timer_running) {
		/* Sleep has been adjusted to have 8Kpps / 16Kpps rate @4K byte size */
		if (test_mode == PERFORMANCE_8CC) {
			if (RTE_PER_LCORE(cpu_freq) == CPU_FREQ_MHZ_2000)
				usleep(42);
			else if (RTE_PER_LCORE(cpu_freq) == CPU_FREQ_MHZ_1400)
				usleep(47);
			else
				usleep(50); /* 16 Kpps */
		} else if (test_mode == PERFORMANCE_1CC) {
			if (RTE_PER_LCORE(cpu_freq) == CPU_FREQ_MHZ_1400)
				usleep(92);
			else
				usleep(106); /* 8 Kpps */
		}
repeat:
		sh_buf = ipc_get_buf(channel_id, instance, &err);
		if (sh_buf == NULL) {
			ipc_debug("ipc_get_buf failed for L2_TO_L1_MSG_CH_3,(err=%d)!\n", err);
			goto repeat;
		} else {
			sh_buf->data_size = MSG_SIZE_4K;
			retry = 0; /* reset the counter */
			while (IPC_SUCCESS !=
				(ret = ipc_send_ptr(L2_TO_L1_MSG_CH_3, sh_buf, instance))) {
				if (++retry != 100000)
					continue;
				printf("Unable to send msg on L2_TO_L1_MSG_CH_3 (%d)\n", ret);
				break;
			}
		}
		pkt_count++;

		if (num_pkts) {
			if ((int)pkt_count == num_pkts)
				break;
		}
		if (force_quit)
			break;
	}

	printf("\n--> Quiting RT Sender Perf thread\n");
	printf("-------------------------------------------\n");
	printf("--- TX PERFORMANCE on %s ---\n", channels[th_args->ch_id]->name);
	printf("pkt %lu duration %ds Throughput = %ldpps\n", pkt_count,
			duration, (pkt_count/duration));
	printf("-------------------------------------------\n");

	return ret;
}

static inline float
ticks_to_usec(float ticks)
{
	ticks = (ticks/hz) * 1000000;
	return ticks;
}

static int
get_cpu_current_frequency(int processor_id)
{
	char cpu_freq_filename[1000], current_cpu_freq_str[30];
	FILE *cpu_freq_fp;

	sprintf(cpu_freq_filename, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", processor_id);

	cpu_freq_fp = fopen(cpu_freq_filename, "r");
	if (cpu_freq_fp == NULL) {
		printf("Error: Cannot open cpu current frequency file\n");
		return 0;
	}

	if (fgets(current_cpu_freq_str, 30, cpu_freq_fp) == NULL) {
		printf("Error: Cannot read cpu current frequency file\n");
		fclose(cpu_freq_fp);
		return 0;
	}

	fclose(cpu_freq_fp);

	return atoi(current_cpu_freq_str);
}

static int
receiver(void *arg)
{
	int ret = 1;
	geulipc_channel_t *ch = NULL;
	struct epoll_event epoll_ev;
	thread_info_t *th_args = (thread_info_t *)arg;
	int warmup_pkt_count = WARMUP_PKTS;

	if (!arg) {
		ipc_debug("Invalid call to Receive thread without args\n");
		return -1;
	}

	RTE_PER_LCORE(cpu_freq) = get_cpu_current_frequency((int)rte_lcore_id());

	ch = channels[th_args->ch_id];
	if (ch->eventfd != -1) {
		th_args->epoll_fd = epoll_create(1);
		if (th_args->epoll_fd < 0) {
			printf("--->Error in creating epoll fd\n");
			return -1;
		}
		/* Register the event */
		epoll_ev.events = EPOLLIN | EPOLLET;
		epoll_ev.data.ptr = (void *)ch;
		ret = epoll_ctl(th_args->epoll_fd, EPOLL_CTL_ADD, ch->eventfd, &epoll_ev);
		if (ret < 0) {
			printf("epoll_ctl ADD failed for Channel ID %d\n",
								ch->channel_id);
			return -1;
		}
		ipc_debug("Got Event fd (%d)\n", ch->eventfd);
	}
	printf("CPU spin factor: %d cycles\n", GEODE_CPU_SPIN_CYCLES);
	printf(" --> Starting Receiver (lcore_id=%u)\n", rte_lcore_id());
	/* Wait for Timer to start */
	while (!timer_running) {
		/* Do nothing .. Keep waiting */
	};

	printf("Receiver thread -- Timer Started\n");
	/* Now continue send pkts till timer ends */
	while (timer_running) {
		if (ch->channel_id < L1_TO_L2_PRT_CH_1)
			ret = _recv(ch->mp, ch->channel_id, th_args, &warmup_pkt_count);
		else
			ret = _recv_ptr(ch->mp, ch->channel_id, th_args, &warmup_pkt_count);

		if (ret) {
			ipc_debug("Unable to recv msg on channel Id %d ret %d\n", ch->channel_id, ret);
		}

		if (num_pkts) {
			if (num_pkts + WARMUP_PKTS == (int)pkt_count)
				break;
		}
		if (force_quit)
			break;
	}

	printf("\n--> Quiting Receiver thread\n");
	printf("-------------------------------------------\n");
	if (test_mode >= PERFORMANCE_1CC) {
		printf("---- PERFORMANCE on %s -----\n\n", ch->name);
		printf("pkt %lu duration %ds Throughput = %ldpps\n", pkt_count,
			duration, (pkt_count/duration));
	} else if (test_mode <= LATENCY_L2_L1_INT) {
		printf("---- LATENCY : Pkts=%lu : ", pkt_count - WARMUP_PKTS);
		if (ch->channel_id == L1_TO_L2_MSG_CH_4)
			printf("L2_TO_L1_MSG_CH_3 -> ");
		else if (ch->channel_id == L1_TO_L2_MSG_CH_5)
			printf("L2_TO_L1_MSG_CH_2 -> ");
		else
			printf("L2_TO_L1_MSG_CH_1 -> ");
		printf("%s ----\n", ch->name);
		printf("min_latency = %lf usec\n", ticks_to_usec(min_latency));
		printf("avg_latency  = %lf usec\n",
			ticks_to_usec(avg_latency/(pkt_count - WARMUP_PKTS)));
		printf("max_latency = %lf usec\n", ticks_to_usec(max_latency));
	}
	printf("-------------------------------------------\n\n\n");

	if (ch->eventfd != -1)
		close(th_args->epoll_fd);

	return ret;
}


static void
_dump_stats_per_channel(struct gul_ipc_ch_stats *stats)
{
	printf("recvd = %8u  sent = %8u\n",
	       stats->num_of_msg_recved,
	       stats->num_of_msg_sent);
	printf("total_message_len = %u\n",
	       stats->total_msg_length);
	printf("\tinput_invalid: %u\n", stats->err_input_invalid);
	printf("\tchannel_invalid: %u\n", stats->err_channel_invalid);
	printf("\tinvalid_memory: %u\n", stats->err_mem_invalid);
	printf("\tchannel_full: %u\n", stats->err_channel_full);
	printf("\tchannel_empty: %u\n", stats->err_channel_empty);
	printf("\tbuf_full: %u\n", stats->err_buf_list_full);
	printf("\tbuf_empty: %u\n", stats->err_buf_list_empty);
	printf("\tBuf_alloc_failed: %u\n", stats->err_host_buf_alloc_fail);
	printf("\tioctl_failed: %u\n", stats->err_ioctl_fail);
	printf("\teventfd_reg_failed: %u\n", stats->err_efd_reg_fail);
}

static void
dump_stats(void)
{
	int i;
	struct gul_ipc_stats *m_ipc_stats;
	struct gul_ipc_stats *h_ipc_stats;

	h_ipc_stats = &(stats->h_ipc_stats);
	m_ipc_stats = &(stats->m_ipc_stats);

	printf("##### Host Common Stats  ######\n");
	printf("MinInvalid IPC Instance = %u\n", h_ipc_stats->err_instance_invalid);
	printf("IPC Metadata Size mismatch = %u\n", h_ipc_stats->err_md_sz_mismatch);
	printf("##### MODEM Common stats  ######\n");
	printf("Invalid IPC Instance = %u\n", m_ipc_stats->err_instance_invalid);
	printf("IPC Metadata Size mismatch = %u\n", m_ipc_stats->err_md_sz_mismatch);

	printf("-------------------------------------------\n");
	printf("------- Per Channel Stats -----------------\n");
	printf("-------------------------------------------\n");
	for (i = 0; i < CHANNELS_MAX; i++) {
		/* Print Channel stats for Active channels only */
		int ch = ch_mask & (1 << i);
		int count = 0;

		if (ch && count < 2)
			count++;
		else
			continue;
		printf("---- For Channel %s ---\n", channels[i]->name);
		printf("##### HOST Stats ######\n");
		_dump_stats_per_channel(&h_ipc_stats->ipc_ch_stats[i]);
		printf("\n");
		printf("##### MODEM Stats ######\n");
		_dump_stats_per_channel(&m_ipc_stats->ipc_ch_stats[i]);
		printf("-------------------------\n");
	}
	printf("-------------------------------------------\n");
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\n Signal %d receieved. Preparing to exit\n", signum);
		force_quit = 1;
	}

	/* else, ignore */
}


int
main(int argc, char **argv)
{
	int ret, i, count = 0;
	uint16_t devid; /* Geul device ID */
	ipc_t instance_handle = NULL;
	thread_info_t th_arg[CHANNELS_MAX];
	uint32_t lcore_id;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("[%s] Cannot init EAL\n", argv[0]);

	printf("Version Info : %s\n", rte_version());
	if (rte_lcore_count() < 4)
		rte_panic("[%s] Cannot Run application as designed to run with minimium of 4 Cores\n", argv[0]);
	argc -= ret;
	argv += ret;

	force_quit = 0;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* No Event mode as default */
	int_enabled_ch_mask = 0x0;
	/* default to Send & Receive pkt on one channel each*/
	ch_mask = 0xC; /* In Latency Mode */

	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_panic("[%s] Unable to parse args.\n", argv[0]);

	/* Create a vdev device; Name of device contains Instance ID
	 * for the Geul IPC device instance
	 */
	ipc_debug("Creating VDEV with name=%s\n", GEUL_DEVICE_NAME);
	ret = rte_vdev_init(GEUL_DEVICE_NAME, "");
	if (ret) {
		printf("Unable to create Geul device (%s)\n", GEUL_DEVICE_NAME);
		goto err_cleanup;
	}

	ret = rte_rawdev_get_dev_id(GEUL_DEVICE_NAME);
	if (ret < 0) {
		printf("Unable to get Geul device ID\n");
		goto cleanup_vdev;
	}
	devid = ret;

	instance_handle = setup_ipc(devid);
	if (!instance_handle) {
		printf("IPC Setup failed\n");
		goto cleanup_vdev;
	}

	/* init RTE timer library */
	rte_timer_subsystem_init();
	/* init timer structures */
	rte_timer_init(&timer);

	/* Synchronize with Modem */
	ret = is_modem_ready(instance_handle);
	if (ret) {
		printf("Modem not ready in stripulated time\n");
		goto cleanup_vdev;
	}
	count = 3; /* Only 3 threads supported */
	/* If modem is ready, start the test cycle */
	for (i = 0; i < CHANNELS_MAX; i++) {
		int ch = ch_mask & (1 << i);

		if (ch) {
			if (count == 0) {
				printf("%s: Skipping more than 3 channels: ch_id(%d)\n", __func__, i);
				continue;
			}
			th_arg[i].instance_handle = instance_handle;
			th_arg[i].ch_id = i;
			/* Using count as CoreID too */
			if (i <= L2_TO_L1_MSG_CH_3) {
				if (test_mode >= PERFORMANCE_1CC)
					rte_eal_remote_launch(rt_sender_perf, &th_arg[i], count);
				else
					rte_eal_remote_launch(rt_sender_latency, &th_arg[i], count);
				printf("=-=-=-=-=--=-==-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-\n");
				printf(" \tPrint # : RT Sender is launched for channel %d\n", i);
				printf("=-=-=-=-=--=-==-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-\n");
			} else {
				rte_eal_remote_launch(receiver, &th_arg[i], count);
				printf("=-=-=-=-=--=-==-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-\n");
				printf(" \tPrint # : Receiver is launched for channel %d\n", i);
				printf("=-=-=-=-=--=-==-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-\n");
			}
			count--;
		}
	}
	/* load SINGLE type timer on master lcore */
	hz = rte_get_timer_hz();
	lcore_id = rte_lcore_id();
	printf("%s: Ticks/sec %lu duration %d\n", __func__, hz, duration);
	timer_running = 1;


#if TMR_2
	rte_timer_init(&timer2);
	/* Periodic Timer for sending pkts @ every 375 usec = 9375 ticks */
	if (test_mode >= PERFORMANCE_1CC)
		rte_timer_reset_sync(&timer2, 9375, PERIODICAL, lcore_id,
				tx_timer_cb, NULL);
#endif
	/* Total duration timer */
	rte_timer_reset_sync(&timer, (duration * hz), SINGLE, lcore_id,
				main_timer_cb, NULL);
	printf("%s: PENDING = %d\n", __func__, rte_timer_pending(&timer));
	while (timer_running) {
		uint64_t *ptr;
		int i;

		/* Dummy Read to Load DDR in performance mode */
		if (test_mode >= PERFORMANCE_1CC && hp_buf_ptr) {
			ptr = (uint64_t *)hp_buf_ptr;
			for (i = 0; i < 1000; i++, ptr++)
				*ptr = *ptr;
		}
		usleep(100);
		rte_timer_manage();
	}

	rte_eal_mp_wait_lcore();

	dump_stats();

	return 0;

cleanup_vdev:
	rte_vdev_uninit(GEUL_DEVICE_NAME);
	/* Ignoring any errors from rte_vdev_uninit*/

err_cleanup:
	return ret;
}
