/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
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
#include <gul_pci_def.h>
#include <gul_host_if.h>
#include <geul_cpe_ipc.h>
#include <geul_cpe_ipc_api.h>
#include <rte_pmd_geul_ipc_rawdev.h>
#include <rte_version.h>
#include <rte_bus_vdev.h>
#define UNUSED(x) void(x)

//#define ipc_debug(...) printf(__VA_ARGS__)
#define ipc_debug(...)

#define GEUL_DEVICE_SEP "_"
#define GEUL_DEVICE_ID_FILLER "%d"

/* Device name has to follow a certain naming pattern to be probed; this
 * includes having the driver name as the initial part; (or use device
 * alias - not implemented right now) - followed by ID
 */
#define GEUL_DEVICE_FILLER_NAME GEUL_IPC_RAWDEV_NAME_PREFIX GEUL_DEVICE_SEP GEUL_DEVICE_ID_FILLER
#define GEUL_DEVICE_NAME_MAX_LENGTH 50

/* A prefix of pool name to create unique names */
#define POOL_NAME_PREFIX "geul_pool_"
/* Pool element counts */
#define POOL_2K_COUNT (152 * 1024)
#define POOL_4K_COUNT 15
#define POOL_128K_COUNT 256
#define SH_POOL_COUNT 100

/* Other pool values */
#define PRIVATE_DATA_SIZE 256
#define CACHE_SIZE	0
#define MSG_SIZE_4K	192/* QDMA compatible size */

enum run_mode {
	VERIFICATION,
	L1_RECOVERY,
	SIX_CORE_MODE,
	RUN_MODE_MAX
};

struct hugepage_info {
	void *vaddr;
	phys_addr_t paddr;
	size_t len;
};

/* Cycle Times
 * Default = 1; Single buffer send/recv */
int cycle_times = 1;
/* TestApp Mode
 * Default = VALIDATION; Only
 * buffer validation performed.
 */
uint8_t test_mode = VERIFICATION;

/* Driven by ipc_memelem_size, creating mempools which would be passed
 * as it it to the host_init call
 */
struct rte_mempool *pools[IPC_HOST_BUF_MAX_COUNT];

/* mask of event (interrupt) enabled channels */
int32_t int_enabled_ch_mask;

int use_second_hugepage;

/** Napi related (valid only for event based channels) **/
/** Values can be tuned as per end use-case **/
/*
 * channel mask to indicate if napi is enabled
 * default value is 0x60 which enables napi for
 * L1_TO_L2 pointer channels (6th, 7th channel)
 * it can be changed via '-z' option at runtime
 */
int32_t en_napi_ch_mask = 0x60;

/* Mask of enabled geul(s) */
int32_t en_geul_mask = 0x1;

#define MAX_GEUL_DEVICES 2
#define GEUL_DEVICE_0_ID 0
#define GEUL_DEVICE_1_ID 1
#define GEUL_DEVICE_ALL_ID MAX_GEUL_DEVICES
int32_t max_events[MAX_GEUL_DEVICES] = {0};

/* Instance of Geul Id */
int geul_instance_id = GEUL_DEVICE_0_ID;

uint16_t devid[MAX_GEUL_DEVICES]; /* Geul device IDs */
ipc_t instance_handle[MAX_GEUL_DEVICES] = {NULL};
struct geulipc_channel *channels[MAX_GEUL_DEVICES][CHANNELS_MAX];
struct gul_stats *stats[MAX_GEUL_DEVICES]; /**< Stats for Host & modem (HIF) */

/* Epoll Fd */
int32_t epoll_fd[MAX_GEUL_DEVICES];

/* Geul device name */
char geul_device_name[MAX_GEUL_DEVICES][GEUL_DEVICE_NAME_MAX_LENGTH];

/*
 * Wait to compensate for delay in getting msi_valid value updates
 * propagated from host to modem side
 */
#define MSI_ENABLE_UDELAY 1
/*
 * To optimize performance in case a lot of time is wasted in context
 * switching between ISR and receive processing thread,
 * in case channel is empty, it is poll again 'RX_LOOP_COUNT' times
 */
#define RX_LOOP_COUNT 10000
/*
 * Limits number of packet read in context of one event interrupt
 */
#define NAPI_COUNT 100

/* Signal control */
static uint8_t force_quit;

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
	if (!opaque) {
		return;
	}

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

	return;
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

	/* XXX Rather than iterator, can be replaced with single step below
	 * which extracts the memhdr in mempool and does the work. test!*/
#if 0
	struct rte_mempool_memhdr *mhdr;
	mhdr = STAILQ_FIRST(mp->mem_list);
	if (mhdr) {
		hp_info->vaddr = mhdr->addr;
		hp_info->iova = rte_mem_virt2phy(mhdr->addr);
		hp_info->len = mhdr->len;
	} else {
		return NULL;
	}
#endif
	return hp_info;
}


static void
fill_buffer(void *buffer, size_t len)
{
	uint32_t i, count;
	uint32_t *val = NULL;

	/* memset(buffer, 0, len); */
	/* XXX Endianness is to be taken care of ? */
	val = (uint32_t *)buffer;
	count = len/sizeof(uint32_t);

	for (i = 0; i < count; i++) {
#ifdef INVS_SIM
	/* TODO: Temporary workaround to get buffer filled right on simulator.*/
		printf("#");
#endif
		*val = POISON;
		val++;
	}
}

/* Validate if POISON is correctly filled or not */

static int
validate_buffer(void *buffer, size_t len)
{
//	ipc_debug("\n %s %d>>>>>>>>>\n%s\n",__func__, __LINE__, (char *)buffer);
	int ret = 0;
	uint32_t i, count;
	int *val = NULL;

	/* XXX Endianness is to be taken care of ? */
	val = (int *)buffer;
	count = len/sizeof(int);
	/* XXX Whatif len is not word aligned */
	for (i = 0; i < count; i++)
		if (*val != POISON) {
			ret = 1; /* Failed */
			break;
		} else
			val++;

	if (ret) {
		ipc_debug("### Validate buffer FAILED\n");
	}

	return ret;
}

static int
create_mempools(void)
{
	int i;
	char pool_name[32];
	uint32_t elem_size = 0, elem_count = 0;

	for (i = 0; i < IPC_HOST_BUF_MAX_COUNT - 1; i++) {
		if (pools[i]) {
			ipc_debug("Mempool already created\n");
			return 0;
		}
	}

	memset(pool_name, 0, 32);

	/* For now skipping IPC_HOST_BUF_POOLSZ_R2 */
	for (i = 0; i < IPC_HOST_BUF_MAX_COUNT - 1; i++) {
		void *temp;

		sprintf(pool_name, "%s%d", POOL_NAME_PREFIX, i);
		switch(i) {
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
				if (use_second_hugepage) {
					temp = rte_malloc(NULL, 600 * 1024 * 1024, 0);
					if (!temp) {
						printf("Memory allocation failed\n");
						goto cleanup;
					}
				}
				RTE_SET_USED(temp);
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
	uint8_t en_napi = 0;
	struct epoll_event epoll_ev;

	if (!instance) {
		printf("Invalid instance handle\n");
		return -1;
	}

	ipcu = (ipc_userspace_t *)instance;
	hif_start = (struct gul_hif *)ipcu->mhif_start.host_vaddr;

	/* Point to the HIF stats */
	stats[ipcu->instance_id] = &(hif_start->stats);
	memset(channels[ipcu->instance_id], 0, sizeof(struct geulipc_channel *) * CHANNELS_MAX);
	for (i = 0; i < CHANNELS_MAX; i++) {
		channels[ipcu->instance_id][i] = malloc(sizeof(geulipc_channel_t));
		if (!channels[ipcu->instance_id][i]) {
			printf("Unable to alloc channel mem (%d)\n", i);
			goto cleanup;
		}
		ch = channels[ipcu->instance_id][i];

		ipc_debug("Attempting initilaztion (%d)\n", i);

		en_napi = (en_napi_ch_mask >> i) & 1;
		switch(i) {
#define MSG_CHANNEL_DEPTH 4
		case L2_TO_L1_MSG_CH_1:
			/* 2K Channel */
			strcpy(ch->name, "L2_TO_L1_MSG_CH_1");
			ch->depth = MSG_CHANNEL_DEPTH;
			ch->type = IPC_CH_MSG;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_2K];
			ch->channel_id = i;
			if ((int_enabled_ch_mask >> ch->channel_id) & 1)
				ipc_channel_set_msi_valid(ch->channel_id, 1,
							  instance);
			/* Configure channels is not called for MSG Consumer */
			continue;
		case L2_TO_L1_MSG_CH_2:
			/* 2K Channel */
			strcpy(ch->name, "L2_TO_L1_MSG_CH_2");
			ch->depth = MSG_CHANNEL_DEPTH;
			ch->type = IPC_CH_MSG;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_2K];
			ch->channel_id = i;
			if ((int_enabled_ch_mask >> ch->channel_id) & 1)
				ipc_channel_set_msi_valid(ch->channel_id, 1,
							  instance);
			/* Configure channels is not called for MSG Consumer */
			continue;
		case L2_TO_L1_MSG_CH_3:
			/* 4K Channel */
			strcpy(ch->name, "L2_TO_L1_MSG_CH_3");
			ch->depth = MSG_CHANNEL_DEPTH;
			ch->type = IPC_CH_PTR;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_4K];
			ch->channel_id = i;
			if ((int_enabled_ch_mask >> ch->channel_id) & 1)
				ipc_channel_set_msi_valid(ch->channel_id, 1,
							  instance);
			/* Configure channels is not called for MSG Consumer */
			continue;
		case L1_TO_L2_MSG_CH_4:
			/* 2K Channel */
			strcpy(ch->name, "L1_TO_L2_MSG_CH_4");
			ch->depth = MSG_CHANNEL_DEPTH;
			ch->type = IPC_CH_MSG;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_2K];
			ch->channel_id = i;
			ch->en_napi = en_napi;
			break;
		case L1_TO_L2_MSG_CH_5:
			/* 2K Channel */
			strcpy(ch->name, "L1_TO_L2_MSG_CH_5");
			ch->depth = MSG_CHANNEL_DEPTH;
			ch->type = IPC_CH_MSG;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_2K];
			ch->channel_id = i;
			ch->en_napi = en_napi;
			break;
		case L1_TO_L2_PRT_CH_1:
#define PTR_CHANNEL_DEPTH 16
			/* 128K Channel */
			strcpy(ch->name, "L1_TO_L2_PRT_CH_1");
			ch->depth = PTR_CHANNEL_DEPTH;
			ch->type = IPC_CH_PTR;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_128K];
			ch->channel_id = i;
			ch->en_napi = en_napi;
			break;
		case L1_TO_L2_PRT_CH_2:
			/* 128K Channel */
			if (test_mode == SIX_CORE_MODE)
				continue;
			strcpy(ch->name, "L1_TO_L2_PRT_CH_2");
			ch->depth = PTR_CHANNEL_DEPTH;
			ch->type = IPC_CH_PTR;
			ch->mp = pools[IPC_HOST_BUF_POOLSZ_128K];
			ch->channel_id = i;
			ch->en_napi = en_napi;
			break;
		default:
			printf("Invalid channel number/type (%d)\n", i);
			goto cleanup;
		}

		en_event = (int_enabled_ch_mask >> ch->channel_id) & 1;
		/*
		 * en_event variable is overloaded
		 * value 1 denotes en_event with napi disabled
		 * value 2 denotes en_event with napi enabled
		 */
		if (en_event)
			en_event += en_napi;

		ipc_debug("Configuring channel %d, en_event %d en_napi %d\n",
					ch->channel_id, en_event, en_napi);

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
		if (en_event) {
			ch->eventfd = ipc_get_eventfd(ch->channel_id, instance);
			/* Register the event */
			epoll_ev.events = EPOLLIN | EPOLLET;
			epoll_ev.data.ptr = (void *)ch;
			ret = epoll_ctl(epoll_fd[ipcu->instance_id], EPOLL_CTL_ADD, ch->eventfd, &epoll_ev);
			if (ret < 0) {
				printf("epoll_ctl ADD failed for Channel ID %d\n",
								ch->channel_id);
				goto cleanup;
			}
			max_events[ipcu->instance_id]++;
			ipc_debug("Got Event fd (%d)  max_events %d\n", ch->eventfd, max_events[ipcu->instance_id]);
		} else
			ch->eventfd = -1;
	}
	return ret;

cleanup:
	for (; i > 0; i--) {
		if (channels[ipcu->instance_id][i]) {
			free(channels[ipcu->instance_id][i]);
			channels[ipcu->instance_id][i] = NULL;
		}
	}

	return -1;
}

static void
reinitialize_channels(int modem_id)
{
	int i, ret;

	/* Add the same EventFDs again in Epoll */
	for (i = L1_TO_L2_MSG_CH_4; i < CHANNELS_MAX; i++) {
		if (i == L1_TO_L2_PRT_CH_2 && test_mode == SIX_CORE_MODE)
			continue;
		geulipc_channel_t *ch = NULL;
		struct epoll_event epoll_ev;

		ch = channels[modem_id][i];

		if (ch->eventfd != -1) {
			/* Register the event */
			epoll_ev.events = EPOLLIN | EPOLLET;
			epoll_ev.data.ptr = (void *)ch;
			ret = epoll_ctl(epoll_fd[modem_id], EPOLL_CTL_ADD, ch->eventfd, &epoll_ev);
			if (ret < 0)
				printf("epoll_ctl ADD failed for Channel ID %d\n", ch->channel_id);
			else {
				ipc_debug("epoll_ctl event %d added  for Channel ID %d\n", ch->eventfd, ch->channel_id);
			}
			max_events[modem_id]++;
		}
	}
}

static ipc_t
setup_ipc(uint16_t devid, int modem_id)
{
	int ret;
	struct rte_rawdev_info rdev_conf = {0};
	struct hugepage_info *hp;
	geulipc_rawdev_config_t config = {0};
	mem_range_t mr = {0};
	ipc_t handle = NULL;
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
#if 1
	handle = ipc_host_init(modem_id, pools, mr, &ret);
#else
	const char *a = "HANDLE";
	printf("Host vaddr=%p\n", mr.host_vaddr);
	handle = (ipc_t)&a;
#endif
	if (ret != IPC_SUCCESS) {
		printf("--->Error from HOST initialization (%d)\n", ret);
		goto err_out;
	}

	/* Create an epoll Fd */
	epoll_fd[modem_id] = epoll_create(1);
	if (epoll_fd[modem_id] < 0) {
		printf("--->Error in creating epoll fd\n");
		goto err_out;
	}
	/* Create the channels and get their IDs */
	ret = initialize_channels(handle);
	if (ret || !channels[modem_id][0]) {
		printf("Unable to setup channels\n");
		goto err_out;
	}

	/* Send this info of handle to driver - just for future access */
	config.instance_handle = handle;
	config.device_id = modem_id;

	/* Wrap that into the rte_rawdev_info structure */
	rdev_conf.dev_private = &config;

	/* Configure the Geul device - includes host initialization */
	ret = rte_rawdev_configure(devid, &rdev_conf, sizeof(config));
	if (ret < 0) {
		printf("Unable to configure device (%s): (%d)\n",
		       geul_device_name[modem_id], ret);
		goto err_out;
	}

	return handle;

err_out:
	if (handle) {
		/* Ideally some host deinit should be done, but none exists */
		//ipc_host_deinit() //TODO in future, implement
		handle = NULL;
	}

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
	fprintf(stderr, "Usage: %s [EAL args] -- [-t TIMES] [-e CH_MASK]"
			"          [-z en_napi_CH_MASK] [-m MODE]\n"
			"-t TIMES: number of a times the serialized test is"
			"          run (default 1)\n"
			"-e CH_MASK: Mask for Event enabled channels\n"
			"-z CH_MASK: Mask for Napi enabled channels\n"
			"-g GEUL_MASK: Mask for Enabled Geul(s)\n"
			"-m MODE : Mode of running:\n"
			"          0 - Verification (default)\n"
			"          1 - L1 Recovery test mode\n"
			"          2 - Six core test mode\n"
			" -d DOUBLE HUGEPAGES - Use two hugepages\n",
			prgname);
}

static int
parse_args(int argc, char **argv)
{
	int opt;
	int mode;

	while ((opt = getopt(argc, argv, "t:e:m:z:g:dh")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 't':
			if (!optarg) {
				printf("Arg parse error: Invalid TIMES count\n");
				return -1;
			}
			cycle_times = atoi(optarg);
			if (cycle_times < 0) {
				printf("Arg parse error: Invalid value for TIMES: (%d)\n", cycle_times);
				printf("Assuming default = 1\n");
				cycle_times = 1;
			}
			ipc_debug("Argument: Parsed TIMES = %d\n", cycle_times);
			break;
		case 'e':
			int_enabled_ch_mask = parse_ch_mask(optarg);
			if (int_enabled_ch_mask == -1) {
				printf("Invalid channel mask\n");
				return -1;
			}
			ipc_debug("Argument: int_enabled_ch_mask = 0x%X\n", int_enabled_ch_mask);
			break;
		case 'z':
			en_napi_ch_mask = parse_ch_mask(optarg);
			if (en_napi_ch_mask == -1) {
				printf("Invalid en_napi_ch_mask\n");
				return -1;
			}
			ipc_debug("Argument: en_napi_ch_mask = 0x%X\n",
				  en_napi_ch_mask);
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
			break;
		case 'd':
			use_second_hugepage = 1;
			break;
		case 'g':
			en_geul_mask  = parse_ch_mask(optarg);
			if (en_geul_mask == -1) {
				printf("Invalid geul mask\n");
				return -1;
			}
			if (en_geul_mask == 1) {
				geul_instance_id = GEUL_DEVICE_0_ID;
			} else if (en_geul_mask == 2) {
				geul_instance_id = GEUL_DEVICE_1_ID;
			} else if (en_geul_mask == 3) {
				geul_instance_id = GEUL_DEVICE_ALL_ID;
			} else {
				printf("Invalid geul mask\n");
				return -1;
			}
			ipc_debug("Argument: en_geul_mask = 0x%X\n",
				  en_geul_mask);
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
	ipc_debug("\n \n \n");
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
	ipc_debug("%d %s\n", __LINE__, __func__);
	SET_HIF_HOST_RDY(hif_start, HIF_HOST_READY_IPC_APP);
	ipc_debug("%d %s\n", __LINE__, __func__);

	/* Now wait for modem ready bit */
	while (ready && !force_quit) {
		ready = !CHK_HIF_MOD_RDY(hif_start, HIF_MOD_READY_IPC_APP);
	}

	if (force_quit)
		ready = 1;

	return ready;
}

static int
_send(struct rte_mempool *mp, uint32_t channel_id, ipc_t instance)
{
	int ret, jj=0;
	void *buffer;

/*
	ret = rte_mempool_get(mp, &buffer);
	if (ret) {
		printf("Unable to get pool\n");
		return -1;
	}
*/
repeat:
	ret = ipc_get_msg_ptr(channel_id, instance, &buffer);
	if (ret == IPC_SUCCESS) {
		fill_buffer(buffer, mp->elt_size);
		ret = ipc_send_msg_ptr(channel_id, mp->elt_size, instance);

	} else if (ret == IPC_CH_FULL && !force_quit) {
		/* Loop - right now infinitely */
		if ((++jj % 10000 ) == 0) {
			ipc_debug("#");
			jj = 0;
			fflush(stdout);
		}
		//ipc_debug("send_msg returned = %d, repeating\n", ret);
		goto repeat;
	}
	/*rte_mempool_put(mp, buffer);*/

	return ret;
}

static int
_recv(struct rte_mempool *mp, uint32_t channel_id, ipc_t instance)
{
	int ret, jj =0;
	uint32_t len;
	void *buffer;
/*
	ret = rte_mempool_get(mp, &buffer);
	if (ret) {
		printf("Unable to get pool\n");
		return -1;
	}
*/
repeat:
	ret = ipc_recv_msg_ptr(channel_id, &buffer, &len, instance);
	if (!ret && len > 0 && len <= mp->elt_size) {
		ret = validate_buffer(buffer, len);
		if (ret) {
			printf("Validation of buffer failed\n");
			goto out;
		}
		ipc_set_consumed_status(channel_id, instance);
	} else if (ret == IPC_CH_EMPTY && !force_quit) {
		if ((++jj % 10000) == 0) {
			ipc_debug(".");
			jj = 0;
			fflush(stdout);
		}
		goto repeat;
	} else if (ret) {
		printf("Error from ipc_recv_msg %d\n", ret);
		goto out;
	} else if (len == 0)
		printf("Invalid length of received buffer. recvd:%u\n", len);
out:
	/*rte_mempool_put(mp, buffer);*/
	return ret;
}

static int
_recv_ptr(struct rte_mempool *mp __rte_unused, uint32_t channel_id,
	  ipc_t instance)
{
	int ret, err, jj = 0;
	ipc_sh_buf_t buffer;
	uint64_t validate_buf = 0;

repeat:
	err = ipc_recv_ptr(channel_id, (void *)&buffer, instance);
	if (err == IPC_CH_EMPTY && !force_quit) {
		if ((++jj % 10000) == 0) {
			ipc_debug("*");
			fflush(stdout);
			jj = 0;
		}
		goto repeat;
	} else if (err != IPC_SUCCESS) {
		goto out;
	} else {
		validate_buf = buffer.host_virt_h;
		validate_buf = JOIN_VA32_64_APP(validate_buf, buffer.host_virt_l);
		if (!validate_buf || err) {
			printf("Invalid response from recv_ptr. (%lu)\n", validate_buf);
			goto out;
		}

		/* Buffer is valid, and no error */
		ret = validate_buffer((void *)validate_buf,
				      buffer.data_size);
		if (!buffer.data_size) {
			printf("WARN: %s : Received %d len buffer\n",
						__func__, buffer.data_size);
		}
		ipc_put_buf(channel_id, &buffer, instance);
		if (ret) {
			printf("Invalid buffer in recv_ptr (ret=%d)\n", ret);
			/* XXX Increase stats */
			err = ret;
			goto out;
		}
	}

	err = 0;
out:
	return err;
}

static inline int
_recv_napi_loop(struct rte_mempool *mp, uint32_t channel_id, int pkt_count,
		    ipc_t instance, void *buffer)
{
	int32_t loop_count = RX_LOOP_COUNT;
	int ret;
	uint32_t len;

	do {
		ret = ipc_recv_msg(channel_id, buffer, &len, instance);
		if (ret == IPC_CH_EMPTY && !force_quit) {
		/*
		 * To avid overhead of time spend in context switching
		 * between ISR and recv API, channel is polled again for valid
		 * packets RX_LOOP_COUNT times
		 */
			if (loop_count-- > 0) {
				ipc_debug(".");
				fflush(stdout);
				continue;
			} else {
				break;
			}

		} else if (ret != IPC_SUCCESS) {
			printf("ipc_recv_msg returned error %d\n", ret);
			break;
		} else if (len > 0 && len <= mp->elt_size) {
			ret = validate_buffer(buffer, len);
			if (ret)
				printf("Validation of buffer failed\n");

		} else if (len == 0)
			printf("Invalid length of received buffer:%u\n", len);

		ipc_debug("$");
		if (--pkt_count == 0)
			break;
		loop_count = RX_LOOP_COUNT;
	} while (!force_quit);

	return ret;
}
static int
_recv_napi(struct rte_mempool *mp, uint32_t channel_id, ipc_t instance)
{
	int ret;
	void *buffer;
	int pkt_count = NAPI_COUNT;
	uint32_t msi_valid_val = 0;

	ret = rte_mempool_get(mp, &buffer);
	if (ret) {
		printf("Unable to get pool\n");
		return -1;
	}

	/* Try to read again pkt_count equal to NAPI_COUNT */
	ret = _recv_napi_loop(mp, channel_id, pkt_count,
		    instance, (void *)buffer);

	/* Enable interrupt back at Modem side */
	msi_valid_val = MSI_VALID_NAPI;
	ipc_channel_set_msi_valid(channel_id, msi_valid_val, instance);

	/*
	 * Wait to compensate for delay in getting msi_valid value updates
	 * propagated from host to modem side
	 */
	rte_delay_us(MSI_ENABLE_UDELAY);

	/*
	 * Try to read again from channel for pkt_count equal to channel depth
	 * This is to avoid race condition if modem sends next packet just
	 * before it see changed msi_valid
	 */
	pkt_count = MSG_CHANNEL_DEPTH;
	ret = _recv_napi_loop(mp, channel_id, pkt_count,
		    instance, (void *)buffer);


	rte_mempool_put(mp, buffer);
	return ret;
}

static inline int
_recv_ptr_napi_loop(uint32_t channel_id, int pkt_count,
		    ipc_t instance)
{
	int32_t loop_count = RX_LOOP_COUNT;
	ipc_sh_buf_t buffer;
	uint64_t validate_buf = 0;
	int ret;

	do {
		ret = ipc_recv_ptr(channel_id, (void *)&buffer, instance);
		if (ret == IPC_CH_EMPTY && !force_quit) {
		/*
		 * To avid overhead of time spend in context switching
		 * between ISR and recv API, channel is polled again for valid
		 * packets RX_LOOP_COUNT times
		 */
			if (loop_count-- > 0) {
				ipc_debug(".");
				fflush(stdout);
				continue;
			} else {
				break;
			}

		} else if (ret != IPC_SUCCESS) {
			printf("ipc_recv_ptr returned error %d\n", ret);
			break;
		}

		validate_buf = buffer.host_virt_h;
		validate_buf = JOIN_VA32_64_APP(validate_buf,
						buffer.host_virt_l);
		if (!validate_buf) {
			printf("ipc_recv_ptr returned buf is NULL\n");
			continue;
		}

		/* Buffer is valid, and no error */
		ret = validate_buffer((void *)validate_buf,
				      buffer.data_size);
		if (!buffer.data_size)
			printf("WARN: %s : Received %d len buffer\n",
				__func__, buffer.data_size);

		ipc_put_buf(channel_id, &buffer, instance);
		if (ret)
			printf("ipc_recv_ptr Invalid buffer ret=%d\n",
			       ret);

		ipc_debug("$");
		if (--pkt_count == 0)
			break;
		loop_count = RX_LOOP_COUNT;
	} while (!force_quit);

	return ret;
}

static int
_recv_ptr_napi(struct rte_mempool *mp __rte_unused, uint32_t channel_id,
	       ipc_t instance)
{
	int ret;
	int pkt_count = NAPI_COUNT;
	uint32_t msi_valid_val = 0;

	/* Try to read again pkt_count equal to NAPI_COUNT */
	ret = _recv_ptr_napi_loop(channel_id, pkt_count, instance);

	/* Enable interrupt back at Modem side */
	msi_valid_val = MSI_VALID_NAPI;
	ipc_channel_set_msi_valid(channel_id, msi_valid_val, instance);

	/*
	 * Wait to compensate for delay in getting msi_valid value updates
	 * propagated from host to modem side
	 */
	rte_delay_us(MSI_ENABLE_UDELAY);

	/*
	 * Try to read again from channel for pkt_count equal to channel depth
	 * This is to avoid race condition if modem sends next packet just
	 * before it see changed msi_valid
	 */
	pkt_count = PTR_CHANNEL_DEPTH;

	ret = _recv_ptr_napi_loop(channel_id, pkt_count, instance);

	return ret;
}

/*
 * Create 3 Senders, each with Non-RT priority.
 * Sender 1: Send 2K;
 * Sender 2: Send 2K
 * Sender 3: Send 4K
 */
static int
non_rt_sender(void *arg)
{
	int ret = 1, i;
	uint8_t ch1_en_event, ch2_en_event;
	ipc_t instance;
	ipc_userspace_t *ipcu;

	if (!arg) {
		printf("Invalid call to NON RT thread without args\n");
		return -1;
	}
	instance  = (ipc_t)arg;
	ipcu = (ipc_userspace_t *)instance;

	printf(" --> Starting NON RT Sender (lcore_id=%u)\n", rte_lcore_id());

	for (i = 0; i < cycle_times; i++) {
		/* For the L2_TO_L1_MSG_CH_1 */
		ret = _send(channels[ipcu->instance_id][L2_TO_L1_MSG_CH_1]->mp,
			    channels[ipcu->instance_id][L2_TO_L1_MSG_CH_1]->channel_id,
			    instance);
		if (ret) {
			printf("Unable to send msg on L2_TO_L1_MSG_CH_1 (%d)\n", ret);
			/* XXX For performance, writing stats for each run is
			* bad but, if stats require error collection, it has
			* to be done per send/recv call*/
			return ret;
		}

		ch1_en_event = (int_enabled_ch_mask >> L2_TO_L1_MSG_CH_1) & 1;
		if (ch1_en_event)
			usleep(104);

		/* For the L2_TO_L1_MSG_CH_2 */
		ret = _send(channels[ipcu->instance_id][L2_TO_L1_MSG_CH_2]->mp,
			    channels[ipcu->instance_id][L2_TO_L1_MSG_CH_2]->channel_id,
			    instance);
		if (ret) {
			printf("Unable to send msg on L2_TO_L1_MSG_CH_2 (%d)\n", ret);
			return ret;
		}

		ch2_en_event = (int_enabled_ch_mask >> L2_TO_L1_MSG_CH_2) & 1;
		if (ch2_en_event)
			usleep(104);

		if (force_quit)
			break;
	}

	ipc_debug("Quiting NON RT Sender thread\n");

	return ret;
}

static int
rt_sender(void *arg)
{
	int ret = 1, i, retry = 0;
	uint8_t ch3_en_event;
	ipc_t instance;
	pid_t tid;
#define COMMAND_LEN 256
	char command[COMMAND_LEN];
	ipc_sh_buf_t *sh_buf;
	int err;
	ipc_userspace_t *ipcu;

	if (!arg) {
		printf("Invalid call to RT thread without args\n");
		return -1;
	}
	instance  = (ipc_t)arg;
	ipcu = (ipc_userspace_t *)instance;

	printf(" --> Starting RT Sender (lcore_id=%u)\n", rte_lcore_id());

	/* Call chrt */
	tid = syscall(SYS_gettid);
	snprintf(command, COMMAND_LEN, "chrt -p 90 %d", tid);
	ret = system(command);
	if (ret < 0)
		printf("Unable to set RT priority\n");
	else
		printf("RT Priority set for Send on Core %u\n", rte_lcore_id());

	/* XXX Loop on cycle_times */
	for (i = 0; i < cycle_times; i++) {
		sh_buf = ipc_get_buf(channels[ipcu->instance_id][L2_TO_L1_MSG_CH_3]->channel_id, instance, &err);
		if (sh_buf == NULL)
			ipc_debug("ipc_get_buf failed for L2_TO_L1_MSG_CH_3,(err=%d)!\n", err);
		else {
			void *buf_addr = (void *)MODEM_PHY2VIRT(sh_buf->mod_phys, ipcu);

			fill_buffer(buf_addr, MSG_SIZE_4K);
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

		ch3_en_event = (int_enabled_ch_mask >> L2_TO_L1_MSG_CH_3) & 1;
		if (ch3_en_event)
			usleep(104);

		if (force_quit)
			break;
	}

	ipc_debug("Quiting RT Sender thread\n");

	return ret;
}
static int
receiver_poll(void *arg __rte_unused)
{
	int ret = 1, i;
	ipc_t instance;
	ipc_userspace_t *ipcu;

	instance  = (ipc_t)arg;
	ipcu = (ipc_userspace_t *)instance;

	printf(" --> Starting Receiver (Poll Mode) (lcore_id=%u)\n", rte_lcore_id());

	/* XXX Loop on cycle_times */
	for (i = 0; i < cycle_times; i++) {
		/* For the L1_TO_L2_MSG_CH_4 */
		if (channels[ipcu->instance_id][L1_TO_L2_MSG_CH_4]->eventfd < 0) {
		ipc_debug("loop for _recv L1_TO_L2_MSG_CH_4\n");

		ret = _recv(channels[ipcu->instance_id][L1_TO_L2_MSG_CH_4]->mp,
			    channels[ipcu->instance_id][L1_TO_L2_MSG_CH_4]->channel_id,
			    instance);
		if (ret)
			printf("Unable to recv msg on L1_TO_L2_MSG_CH_4 (%d)\n", ret);
		}

		if (channels[ipcu->instance_id][L1_TO_L2_MSG_CH_5]->eventfd < 0) {
		ipc_debug("loop for _recv L1_TO_L2_MSG_CH_5\n");
		/* For the L1_TO_L2_MSG_CH_5 */
		ret = _recv(channels[ipcu->instance_id][L1_TO_L2_MSG_CH_5]->mp,
			    channels[ipcu->instance_id][L1_TO_L2_MSG_CH_5]->channel_id,
			    instance);
		if (ret)
			printf("Unable to recv msg on L1_TO_L2_MSG_CH_5 (%d)\n", ret);
		}

		if (channels[ipcu->instance_id][L1_TO_L2_PRT_CH_1]->eventfd < 0) {
		ipc_debug("loop for _recv L1_TO_L2_PRT_CH_1\n");
		/* For the L1_TO_L2_PRT_CH_1 */
		ret = _recv_ptr(channels[ipcu->instance_id][L1_TO_L2_PRT_CH_1]->mp,
				channels[ipcu->instance_id][L1_TO_L2_PRT_CH_1]->channel_id,
				instance);
		if (ret)
			printf("Unable to recv_ptr on L1_TO_L2_PRT_CH_1 (%d)\n", ret);
		}

		if (test_mode != SIX_CORE_MODE &&
				channels[ipcu->instance_id][L1_TO_L2_PRT_CH_2]->eventfd < 0) {
			ipc_debug("loop for _recv L1_TO_L2_PRT_CH_2\n");
			/* For the L1_TO_L2_PRT_CH_2 */
			ret = _recv_ptr(channels[ipcu->instance_id][L1_TO_L2_PRT_CH_2]->mp,
					channels[ipcu->instance_id][L1_TO_L2_PRT_CH_2]->channel_id,
					instance);
			if (ret)
				printf("Unable to recv msg on L1_TO_L2_PRT_CH_2 (%d)\n",
				       ret);
		}

		if (force_quit)
			break;
	}

	printf(" --------- Quiting receiver Poll Mode\n");

	return ret;
}


static int
receiver_event(void *arg __rte_unused)
{
	int ret = 0, i, nfds;
	ipc_t instance;
	ipc_userspace_t *ipcu;
	struct epoll_event events[CHANNELS_MAX];
	geulipc_channel_t *ch = NULL;
	uint64_t timeout_ms = 1000 * 2; /* 2 Sec */

	instance  = (ipc_t)arg;
	ipcu = (ipc_userspace_t *)instance;
	printf(" --> Starting Receiver (Event Mode) (lcore_id=%u)\n", rte_lcore_id());

	for (;;) {
		nfds = epoll_wait(epoll_fd[ipcu->instance_id], events,
				  max_events[ipcu->instance_id], timeout_ms);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			else if (errno == EINVAL) /* No FDs left */
				goto done;
			ipc_debug("epoll_wait return fail %d \n", errno);
			return -1;
		} else if (0 == nfds) {
			/*ipc_debug("epoll wait timeout...\n");*/
			if (force_quit) {
				ipc_debug("%s: Quiting.....\n",__func__);
				break;
			} else
				continue;
		}
		for (i = 0; i < nfds; i++) {
			ch = (geulipc_channel_t *) events[i].data.ptr;
			ipc_debug("Got event for Channel Id %d\n", ch->channel_id);

			if (ch->channel_id == L1_TO_L2_PRT_CH_2 &&
					test_mode == SIX_CORE_MODE)
				continue;

			if (ch->channel_id < L1_TO_L2_PRT_CH_1)
				if (ch->en_napi)
					ret = _recv_napi(ch->mp,
							 ch->channel_id,
							 instance);
				else
					ret = _recv(ch->mp, ch->channel_id,
						    instance);
			else
				if (ch->en_napi)
					ret = _recv_ptr_napi(ch->mp,
							     ch->channel_id,
							     instance);
				else
					ret = _recv_ptr(ch->mp,
							ch->channel_id,
							instance);
			if (ret) {
				ipc_debug("Unable to recv msg on channel Id %d ret %d\n", ch->channel_id, ret);
			}

			if (stats[ipcu->instance_id]->h_ipc_stats.ipc_ch_stats[ch->channel_id].num_of_msg_recved
					>= (uint32_t)cycle_times) {
				epoll_ctl(epoll_fd[ipcu->instance_id], EPOLL_CTL_DEL, ch->eventfd, NULL);
				max_events[ipcu->instance_id]--;
				if (0 == max_events[ipcu->instance_id])
					goto done;
			}
		}

		if (force_quit)
			break;
	}
done:
	printf(" -------- Quiting receiver Event Mode\n");

	return ret;
}
static int
receiver(void *arg __rte_unused)
{
	int ret = 1;

	if (!arg) {
		ipc_debug("Invalid call to Receive thread without args\n");
		return -1;
	}
	/* first Check if any channel/s need Polling then process them first */
	ret = receiver_poll (arg);
	if (ret  < 0)
		goto err;
	/* Now move to Event Mode */
	ret = receiver_event (arg);
	if (ret  < 0)
		goto err;

	return ret;

err:
	ipc_debug("Receiver thread Failed...Quiting\n");
	return -1;
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
dump_stats(int modem_id)
{
	int i;
	struct gul_ipc_stats *m_ipc_stats;
	struct gul_ipc_stats *h_ipc_stats;

	h_ipc_stats = &(stats[modem_id]->h_ipc_stats);
	m_ipc_stats = &(stats[modem_id]->m_ipc_stats);

	printf("##### Geul device %d HOST common stats  ######\n", modem_id);
	printf("Invalid IPC Instance = %u\n", h_ipc_stats->err_instance_invalid);
	printf("IPC Metadata Size mismatch = %u\n", h_ipc_stats->err_md_sz_mismatch);
	printf("##### Geul device %d MODEM common stats  ######\n", modem_id);
	printf("Invalid IPC Instance = %u\n", m_ipc_stats->err_instance_invalid);
	printf("IPC Metadata Size mismatch = %u\n", m_ipc_stats->err_md_sz_mismatch);

	printf("--------------------------------------------\n");
	printf("----- Geul device %d Per Channel Stats -----\n", modem_id);
	printf("--------------------------------------------\n");

	for (i = 0; i < CHANNELS_MAX; i++) {
		if (i == L1_TO_L2_PRT_CH_2 && test_mode == SIX_CORE_MODE)
			continue;
		printf("---- For Geul device %d Channel %s --- \n", modem_id,
		       channels[modem_id][i]->name);
		printf("##### HOST Stats ######\n");
		_dump_stats_per_channel(&h_ipc_stats->ipc_ch_stats[i]);
		printf("\n");
		printf("##### MODEM Stats ######\n");
		_dump_stats_per_channel(&m_ipc_stats->ipc_ch_stats[i]);
		printf("-------------------------\n");
	}

	return;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\n Signal %d recieved. Preparing to exit\n", signum);
		force_quit = 1;
	}

	/* else, ignore */
}

static void
close_modem(int modem_id)
{
	rte_vdev_uninit(geul_device_name[modem_id]);
	/* Ignoring any errors from rte_vdev_uninit*/

	if (epoll_fd[modem_id] >= 0)
		close(epoll_fd[modem_id]);
}

static int
setup_modem(int modem_id)
{
	int ret;

	snprintf(geul_device_name[modem_id],
		 GEUL_DEVICE_NAME_MAX_LENGTH, GEUL_DEVICE_FILLER_NAME,
		 modem_id);

	/* Create a vdev device; Name of device contains Instance ID
	 * for the Geul IPC device instance
	 */
	ipc_debug("Creating VDEV with name=%s\n",
		  geul_device_name[modem_id]);
	ret = rte_vdev_init(geul_device_name[modem_id], "");
	if (ret) {
		printf("Unable to create Geul device (%s)\n",
		       geul_device_name[modem_id]);
		geul_device_name[modem_id][0] = '\0';
		close_modem(modem_id);
		return -1;
	}

	ret = rte_rawdev_get_dev_id(geul_device_name[modem_id]);
	if (ret < 0) {
		printf("Unable to get Geul device ID\n");
		close_modem(modem_id);
		return -1;
	}
	devid[modem_id] = ret;

	instance_handle[modem_id] = setup_ipc(devid[modem_id], modem_id);
	if (!instance_handle[modem_id]) {
		printf("IPC Setup failed\n");
		close_modem(modem_id);
		return -1;
	}

	return 0;
}

#define GEUL_DEVICE_0_ID_CTRL_CORE	0
#define GEUL_DEVICE_1_ID_CTRL_CORE	1
#define GEUL_DEVICE_0_ID_IO_CORE	2
#define GEUL_DEVICE_1_ID_IO_CORE	3

static int
get_modem_io_lcore_id(int modem_id)
{
	if(modem_id == GEUL_DEVICE_0_ID)
		return GEUL_DEVICE_0_ID_IO_CORE;
	else
		return GEUL_DEVICE_1_ID_IO_CORE;
}

static int
test_modem(void *arg)
{
	uintptr_t m_id = (uintptr_t)arg;
	int ret, modem_recovered = 0, modem_id = (int)m_id;

	/* Setup modem */
	ret = setup_modem(modem_id);
	if (ret) {
		printf("Modem %d setup failed\n", modem_id);
		return -1;
	}

run_io_test:
	/* Synchronize with Modem */
	ret = is_modem_ready(instance_handle[modem_id]);
	if (ret) {
		printf("Modem %d not ready in stripulated time\n", modem_id);
		close_modem(modem_id);
		return -1;
	}

	/* Run Test Case
	 * 1. A Non-RT Sender - for sending on L2_TO_L1_MSG_CH_1,
	 *    L2_TO_L1_MSG_CH_2 and L2_TO_L1_MSG_CH_3
	 * 2. A RT Sender - for sending on L2_TO_L1_MSG_CH_3
	 * 3. A receiver - for receiving on L1_TO_L2_PRT_CH_1 and
	 *    L1_TO_L2_PRT_CH_2
	 */

	printf("=-=-=-=-=--=-==-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-\n");
	printf(" \tPrint # : Non-RT Sender is waiting\n");
	printf(" \tPrint . : RT Sender is waiting\n");
	printf(" \tPrint * : Receiver is waiting\n");
	printf("=-=-=-=-=--=-==-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-\n");

	rte_eal_remote_launch(non_rt_sender, instance_handle[modem_id],
			      get_modem_io_lcore_id(modem_id));
	rte_eal_wait_lcore(get_modem_io_lcore_id(modem_id));

	rte_eal_remote_launch(rt_sender, instance_handle[modem_id],
			      get_modem_io_lcore_id(modem_id));
	rte_eal_wait_lcore(get_modem_io_lcore_id(modem_id));

	rte_eal_remote_launch(receiver, instance_handle[modem_id],
			      get_modem_io_lcore_id(modem_id));
	rte_eal_wait_lcore(get_modem_io_lcore_id(modem_id));

	/* Print I/O stats */
	/* NOTE: This may cause both threads to print geul stats together, hence
	 * resulting in mixed up prints.
	 */
	dump_stats(modem_id);

	/* Continue only if test_mode is L1_RECOVERY */
	if (test_mode != L1_RECOVERY || modem_recovered == 1)
		goto done;

	ipc_prep_to_recover(instance_handle[modem_id]);

	printf("%s: Waiting for Modem %d reboot\n", __func__, modem_id);
	/* Just hit Enter manually once YAMI driver is reloaded */
	getc(stdin);

	ret = ipc_restore_cfg(instance_handle[modem_id]);
	if (ret) {
		printf("%s: IPC Recovery on geul %d failed\n", __func__,
		       modem_id);
	}

	reinitialize_channels(modem_id);

	/* Mark modem as recovered. */
	modem_recovered = 1;

	goto run_io_test;

done:
	close_modem(modem_id);
	return 0;
}

int
main(int argc, char **argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("[%s] Cannot init EAL\n", argv[0]);

	printf("Version Info : %s\n", rte_version());
	if (rte_lcore_count() < 4)
		rte_panic("[%s] Cannot Run application as designed to run with minimium of 4 Cores\n",
			  argv[0]);
	argc -= ret;
	argv += ret;

	force_quit = 0;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Set Event based rcv mode as default */
	int_enabled_ch_mask = 0x78;

	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_panic("[%s] Unable to parse args.\n", argv[0]);

	ret = create_mempools();
	if (ret)
		rte_panic("Error: Cannot create mempools(%d)\n", ret);

	if (geul_instance_id == GEUL_DEVICE_ALL_ID) {
		/* Run Modem 1 thread on core 1 */
		rte_eal_remote_launch(test_modem,
				      (void *)(uintptr_t)GEUL_DEVICE_1_ID,
				      GEUL_DEVICE_1_ID_CTRL_CORE);
		/* Run Modem 0 thread on core 0 */
		test_modem(GEUL_DEVICE_0_ID);

		/* Wait for Modem 1 test to finish */
		rte_eal_wait_lcore(GEUL_DEVICE_1_ID_CTRL_CORE);
	} else {
		test_modem((void *)(uintptr_t)geul_instance_id);
	}

	cleanup_mempools();

	return 0;

}
