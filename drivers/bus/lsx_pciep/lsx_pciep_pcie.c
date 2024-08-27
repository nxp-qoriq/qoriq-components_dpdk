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

#include <rte_eal.h>
#include <rte_log.h>
#include <rte_bus.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>

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
#include <dpaa_of.h>
#include <linux/pci_regs.h>
#include <rte_pci.h>
#include <linux/virtio_net.h>
#include <linux/virtio_blk.h>
#include <rte_lsx_pciep_bus.h>
#include <rte_spinlock.h>
#include <kpage_ncache_api.h>

#include <bus_fslmc_driver.h>
#include "lsx_pciep_dev.h"
#include "lsx_pciep_ctrl.h"

#define LSX_PCIE_PF_LS2_DBI_SIZE 0x20000
#define LSX_PCIE_PF_LX2_DBI_SIZE 0x8000

#define LSX_PCIE_REG_PHY_START 0x3400000
#define LSX_PCIE_REG_STRIDE 0x100000

#define LSX_PCIE_DT_REG_ADDR_IDX 0
#define LSX_PCIE_DT_OB_ADDR_IDX 1

#define SVR_MAJOR_VER_MASK	0x00F0

#ifndef SVR_MASK
#define SVR_MASK 0xffff0000
#endif

#define LSX_SIM_UIO_NM "sim_uio"

static struct lsx_pciep_ctl_hw *s_pctl_hw;

static rte_spinlock_t lsx_pciep_shared_data_lock =
	RTE_SPINLOCK_INITIALIZER;

static const struct rte_memzone *primary_shared_mz;

static const char *lsx_pciep_shared_data_nm =
	"lsx_pciep_shared_data";

#define LSX_PCIEP_CTL_HW_TOTAL_SIZE \
	(sizeof(struct lsx_pciep_ctl_hw) * LSX_MAX_PCIE_NB)

static uint32_t s_pciep_init_flag;

#define LSX_PCIEP_DEFAULT_POLICY RTE_DEV_ALLOWED
#define LSX_PCIEP_DEFAULT_OB_POLICY LSX_PCIEP_OB_FUN_IDX

#define LSX_PCIEP_DEFAULT_PF_ENABLE 1
#define LSX_PCIEP_DEFAULT_VF_ENABLE 0
#define LSX_PCIEP_DEFAULT_RBP_ENABLE 1
#define LSX_PCIEP_DEFAULT_SIM_ENABLE 0
#define LSX_PCIEP_DEFAULT_VIO_ENABLE 0
#define LSX_PCIEP_DEFAULT_NONSNOOP_ENABLE 0

#define LSX_PCIEP_DEFAULT_OB_FUN_SIZE CFG_8G_SIZE

struct lsx_pciep_env {
	enum rte_dev_policy policy;
	enum lsx_ob_policy ob_policy;
	uint64_t ob_fun_size;
	uint8_t rbp;
	uint8_t sim;
	uint8_t nonsnoop;

	uint8_t pf_enable[PF_MAX_NB];
	uint8_t vf_enable[PF_MAX_NB][PCIE_MAX_VF_NUM];

	uint8_t pf_virtio[PF_MAX_NB];
	uint8_t pf_dis_sriov[PF_MAX_NB];
	uint8_t pf_dis_ari[PF_MAX_NB];
	uint8_t pf_dis_ats[PF_MAX_NB];
	uint8_t vf_dis_ari[PF_MAX_NB][PCIE_MAX_VF_NUM];
	uint8_t vf_dis_ats[PF_MAX_NB][PCIE_MAX_VF_NUM];
};

static struct lsx_pciep_env s_pciep_env[LSX_MAX_PCIE_NB];

struct lsx_pciep_ib_mem_seg {
	struct rte_memseg *ib_seg[PCI_MAX_RESOURCE];
	uint64_t offset[PCI_MAX_RESOURCE];
	uint64_t used[PCI_MAX_RESOURCE];
	int cached[PCI_MAX_RESOURCE];
};

static struct lsx_pciep_ib_mem_seg s_ib_seg;

#define IB_HUGE_PAGE_DUMP_FORMAT(bar, iova, phy, vir, size) \
	"BAR[%d] new page iova(%lx), phy(%lx), vir(%p), size(%lx)", \
	bar, (uint64_t)iova, (uint64_t)phy, (void *)vir, \
	(uint64_t)size

static int
lsx_pciep_ctl_set_ops(void)
{
	enum PEX_TYPE type;
	int i;

	if (!s_pctl_hw)
		return -ENOTSUP;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		type = s_pctl_hw[i].type;
		if (type == PEX_LX2160_REV1) {
			s_pctl_hw[i].ops = lsx_pciep_get_mv_ops();
		} else if (type == PEX_LX2160_REV2) {
			s_pctl_hw[i].ops = lsx_pciep_get_dw_ops();
		} else if (type == PEX_LS208X) {
			s_pctl_hw[i].ops = lsx_pciep_get_dw_ops();
		} else {
			LSX_PCIEP_BUS_ERR("SoC type(%d) not supported",
				type);
			return -ENOTSUP;
		}
	}

	return 0;
}

static void lsx_pciep_ctl_process_sriov(void)
{
	int i, ret;
	struct lsx_pciep_ctl_hw *ctlhw;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		ctlhw = &s_pctl_hw[i];
		if (ctlhw->sim) {
			/* All the simulator controllers support SRIOV*/
			ctlhw->hw.is_sriov = 1;
			continue;
		}
		if (ctlhw->ep_enable && ctlhw->ops->pcie_is_sriov) {
			ret = ctlhw->ops->pcie_is_sriov(&ctlhw->hw);
			if (ret < 0) {
				LSX_PCIEP_BUS_ERR("PCIe%d is SRIOV?(%d)",
					ctlhw->hw.index, ret);
			}
		} else if (ctlhw->ep_enable) {
			/**SRIOV as default.*/
			ctlhw->hw.is_sriov = 1;
		}
	}
}

static int lsx_pciep_ctl_process_map(void)
{
	int i, ctl_nb = 0;
	struct lsx_pciep_ctl_hw *ctlhw;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		ctlhw = &s_pctl_hw[i];
		if (ctlhw->sim) {
			/*Simulator is supported only in primary process*/
			if (rte_eal_process_type() == RTE_PROC_PRIMARY)
				ctl_nb++;
			continue;
		}
		if (ctlhw->ep_enable) {
			ctlhw->hw.dbi_vir =
				lsx_pciep_map_region(ctlhw->hw.dbi_phy,
					ctlhw->hw.dbi_size);
			if (!ctlhw->hw.dbi_vir) {
				LSX_PCIEP_BUS_ERR("dbi_vir map failed\n");

				return -ENOMEM;
			}

			if (ctlhw->hw.ob_policy != LSX_PCIEP_OB_SHARE) {
				ctl_nb++;
				continue;
			}

			ctlhw->out_vir =
				lsx_pciep_map_region(ctlhw->hw.out_base,
					ctlhw->hw.out_size);
			if (!ctlhw->out_vir) {
				LSX_PCIEP_BUS_ERR("Failure of sharing OB");

				return -ENOMEM;
			}
			ctl_nb++;
		}
	}

	return ctl_nb;
}

int lsx_pciep_share_info_init(void)
{
	const struct rte_memzone *mz;
	int ret = 0;

	rte_spinlock_lock(&lsx_pciep_shared_data_lock);

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		mz = rte_memzone_reserve(lsx_pciep_shared_data_nm,
				sizeof(struct lsx_pciep_ctl_hw) *
				LSX_MAX_PCIE_NB,
				rte_socket_id(), 0);
		primary_shared_mz = mz;
	} else {
		mz = rte_memzone_lookup(lsx_pciep_shared_data_nm);
	}
	if (!mz) {
		LSX_PCIEP_BUS_ERR("Shared mz %s failed",
			rte_eal_process_type() == RTE_PROC_PRIMARY ?
			"reserve" : "lookup");
		ret = -ENOMEM;
		goto share_info_init_done;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		if (s_pctl_hw) {
			memcpy(mz->addr, s_pctl_hw,
				LSX_PCIEP_CTL_HW_TOTAL_SIZE);
		}
	} else {
		s_pctl_hw = malloc(LSX_PCIEP_CTL_HW_TOTAL_SIZE);
		if (!s_pctl_hw) {
			LSX_PCIEP_BUS_ERR("Secondary private mem alloc failed");
			ret = -ENOMEM;
			goto share_info_init_done;
		}
		memcpy(s_pctl_hw, mz->addr, LSX_PCIEP_CTL_HW_TOTAL_SIZE);
		ret = lsx_pciep_ctl_set_ops();
		if (ret)
			goto share_info_init_done;

		ret = lsx_pciep_ctl_process_map();
		if (ret > 0)
			ret = 0;
		else if (!ret)
			ret = -ENODEV;
	}
share_info_init_done:

	rte_spinlock_unlock(&lsx_pciep_shared_data_lock);

	return ret;
}

static void
lsx_pciep_general_env_default_set(void)
{
	int i;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		s_pciep_env[i].policy = LSX_PCIEP_DEFAULT_POLICY;
		s_pciep_env[i].ob_policy = LSX_PCIEP_DEFAULT_OB_POLICY;
		s_pciep_env[i].ob_fun_size = LSX_PCIEP_DEFAULT_OB_FUN_SIZE;
		s_pciep_env[i].sim = LSX_PCIEP_DEFAULT_SIM_ENABLE;
		s_pciep_env[i].rbp = LSX_PCIEP_DEFAULT_RBP_ENABLE;
		s_pciep_env[i].nonsnoop = LSX_PCIEP_DEFAULT_NONSNOOP_ENABLE;
	}
}

static void
lsx_pciep_sriov_env_default_set(void)
{
	int i, j, k;
	struct lsx_pciep_ctl_hw *ctlhw;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		ctlhw = &s_pctl_hw[i];
		for (j = 0; j < PF_MAX_NB; j++) {
			if (!ctlhw->hw.is_sriov && j > 0)
				continue;
			s_pciep_env[i].pf_enable[j] =
				LSX_PCIEP_DEFAULT_PF_ENABLE;
			s_pciep_env[i].pf_virtio[j] =
				LSX_PCIEP_DEFAULT_VIO_ENABLE;
			if (!ctlhw->hw.is_sriov)
				continue;
			for (k = 0; k < PCIE_MAX_VF_NUM; k++) {
				s_pciep_env[i].vf_enable[j][k] =
					LSX_PCIEP_DEFAULT_VF_ENABLE;
			}
		}
	}
}

static void
lsx_pciep_general_env_adjust(void)
{
	int i;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		if (s_pciep_env[i].sim)
			s_pciep_env[i].rbp = 0;
		if (s_pciep_env[i].rbp)
			s_pciep_env[i].ob_policy = LSX_PCIEP_OB_RBP;
	}
}

static void
lsx_pciep_sriov_env_adjust(void)
{
	int i, j;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		for (j = 0; j < PF_MAX_NB; j++) {
			if (!s_pciep_env[i].pf_enable[j]) {
				memset(&s_pciep_env[i].vf_enable[j],
					0, PCIE_MAX_VF_NUM);
			}
		}
	}
}

static void
lsx_pciep_fun_env_set(int pciep_idx,
	uint8_t pf_idx, int vf_idx, int enable)
{
	RTE_ASSERT(pciep_idx >= 0 && pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);
	RTE_ASSERT(vf_idx < PCIE_MAX_VF_NUM);

	if (vf_idx < 0) {
		s_pciep_env[pciep_idx].pf_enable[pf_idx] =
			enable;
	} else {
		s_pciep_env[pciep_idx].vf_enable[pf_idx][vf_idx] =
			enable;
	}
}

static void
lsx_pciep_fun_env_dis_sriov(int pciep_idx,
	uint8_t pf_idx, int dis)
{
	RTE_ASSERT(pciep_idx >= 0 && pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);

	s_pciep_env[pciep_idx].pf_dis_sriov[pf_idx] = dis;
}

static void
lsx_pciep_fun_env_dis_ari(int pciep_idx,
	uint8_t pf_idx, int vf_idx, int dis)
{
	RTE_ASSERT(pciep_idx >= 0 && pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB && vf_idx < PCIE_MAX_VF_NUM);

	if (vf_idx < 0)
		s_pciep_env[pciep_idx].pf_dis_ari[pf_idx] = dis;
	else
		s_pciep_env[pciep_idx].vf_dis_ari[pf_idx][vf_idx] = dis;
}

static void
lsx_pciep_fun_env_dis_ats(int pciep_idx,
	uint8_t pf_idx, int vf_idx, int dis)
{
	RTE_ASSERT(pciep_idx >= 0 && pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB && vf_idx < PCIE_MAX_VF_NUM);

	if (vf_idx < 0)
		s_pciep_env[pciep_idx].pf_dis_ats[pf_idx] = dis;
	else
		s_pciep_env[pciep_idx].vf_dis_ats[pf_idx][vf_idx] = dis;
}

static void
lsx_pciep_rbp_env_set(uint8_t pciep_idx,
	int enable)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].rbp = enable;
}

static void
lsx_pciep_sim_env_set(uint8_t pciep_idx,
	int enable)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].sim = enable;
}

static void
lsx_pciep_vio_env_set(uint8_t pciep_idx,
	uint8_t pf_idx, int enable)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);

	s_pciep_env[pciep_idx].pf_virtio[pf_idx] = enable;
}

static void
lsx_pciep_policy_env_set(uint8_t pciep_idx,
	enum rte_dev_policy policy)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].policy = policy;
}

static void
lsx_pciep_ob_policy_env_set(uint8_t pciep_idx,
	enum lsx_ob_policy policy)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].ob_policy = policy;
}

static void
lsx_pciep_ob_fun_size_env_set(uint8_t pciep_idx,
	uint64_t g_size)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].ob_fun_size = g_size * CFG_1G_SIZE;
}

static void
lsx_pciep_nonsnoop_env_set(uint8_t pciep_idx,
	int nonsnoop)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].nonsnoop = nonsnoop;
}

static int
lsx_pciep_fun_env_get(uint8_t pciep_idx,
	uint8_t pf_idx, int vf_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);
	RTE_ASSERT(vf_idx < PCIE_MAX_VF_NUM);

	if (vf_idx < 0)
		return s_pciep_env[pciep_idx].pf_enable[pf_idx];
	else
		return s_pciep_env[pciep_idx].vf_enable[pf_idx][vf_idx];
}

static int
lsx_pciep_rbp_env_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	return s_pciep_env[pciep_idx].rbp;
}

static int
lsx_pciep_sim_env_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	return s_pciep_env[pciep_idx].sim;
}

static int
lsx_pciep_vio_env_get(uint8_t pciep_idx,
	uint8_t pf_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);

	return s_pciep_env[pciep_idx].pf_virtio[pf_idx];
}

static enum lsx_ob_policy
lsx_pciep_ob_policy_env_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	return s_pciep_env[pciep_idx].ob_policy;
}

static uint64_t
lsx_pciep_ob_fun_size_env_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	return s_pciep_env[pciep_idx].ob_fun_size;
}

static int
lsx_pciep_nonsnoop_env_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	return s_pciep_env[pciep_idx].nonsnoop;
}

static void
lsx_pciep_parse_general_env(void)
{
	char *penv = NULL;
	int i;
	char env_name[64];

	lsx_pciep_general_env_default_set();

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		sprintf(env_name, "LSX_PCIE%d_BLACKLISTED", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_policy_env_set(i, atoi(penv));

		sprintf(env_name, "LSX_PCIE%d_NONSNOOP", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_nonsnoop_env_set(i, atoi(penv));

		sprintf(env_name, "LSX_PCIE%d_OB_POLICY", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_ob_policy_env_set(i, atoi(penv));

		sprintf(env_name, "LSX_PCIE%d_OB_FUN_GSIZE", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_ob_fun_size_env_set(i, atoi(penv));

		sprintf(env_name, "LSX_PCIE%d_RBP", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_rbp_env_set(i, atoi(penv));

		sprintf(env_name, "LSX_PCIE%d_SIM", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_sim_env_set(i, atoi(penv));
	}

	lsx_pciep_general_env_adjust();
}

static void
lsx_pciep_parse_sriov_env(void)
{
	char *penv = NULL;
	int i, j, k;
	struct lsx_pciep_ctl_hw *ctlhw;
	char env_name[64];

	lsx_pciep_sriov_env_default_set();

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		ctlhw = &s_pctl_hw[i];

		for (j = 0; j < PF_MAX_NB; j++) {
			if (!ctlhw->hw.is_sriov && j > 0)
				continue;
			sprintf(env_name, "LSX_PCIE%d_PF%d", i, j);
			penv = getenv(env_name);
			if (penv)
				lsx_pciep_fun_env_set(i, j, -1, atoi(penv));

			sprintf(env_name, "LSX_PCIE%d_PF%d_VIRTIO", i, j);
			penv = getenv(env_name);
			if (penv)
				lsx_pciep_vio_env_set(i, j, atoi(penv));

			if (!ctlhw->hw.is_sriov)
				continue;
			sprintf(env_name, "LSX_PCIE%d_PF%d_DIS_SRIOV",
					i, j);
			penv = getenv(env_name);
			if (penv) {
				lsx_pciep_fun_env_dis_sriov(i, j,
					atoi(penv));
			}
			sprintf(env_name, "LSX_PCIE%d_PF%d_DIS_ARI",
					i, j);
			penv = getenv(env_name);
			if (penv) {
				lsx_pciep_fun_env_dis_ari(i, j, -1,
					atoi(penv));
			}
			/** Disable ATS as default.*/
			lsx_pciep_fun_env_dis_ats(i, j, -1, 1);
			sprintf(env_name, "LSX_PCIE%d_PF%d_DIS_ATS",
					i, j);
			penv = getenv(env_name);
			if (penv) {
				lsx_pciep_fun_env_dis_ats(i, j, -1,
					atoi(penv));
			}
			for (k = 0; k < PCIE_MAX_VF_NUM; k++) {
				sprintf(env_name, "LSX_PCIE%d_PF%d_VF%d",
					i, j, k);
				penv = getenv(env_name);
				if (penv) {
					lsx_pciep_fun_env_set(i, j, k,
						atoi(penv));
				}
				sprintf(env_name,
					"LSX_PCIE%d_PF%d_VF%d_DIS_ARI",
					i, j, k);
				penv = getenv(env_name);
				if (penv) {
					lsx_pciep_fun_env_dis_ari(i, j, k,
						atoi(penv));
				}
				lsx_pciep_fun_env_dis_ats(i, j, k, 1);
				sprintf(env_name,
					"LSX_PCIE%d_PF%d_VF%d_DIS_ATS",
					i, j, k);
				penv = getenv(env_name);
				if (penv) {
					lsx_pciep_fun_env_dis_ats(i, j, k,
						atoi(penv));
				}
			}
		}
	}

	lsx_pciep_sriov_env_adjust();
}

static int lsx_pciep_ctl_filtered(int pcie_idx)
{
	if (s_pciep_env[pcie_idx].policy == RTE_DEV_BLOCKED)
		return true;
	return false;
}

static int lsx_pciep_find_all_sim(void)
{
	struct lsx_pciep_ctl_hw *ctlhw;
	int i, dev_nb = 0;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		if (s_pciep_env[i].policy == RTE_DEV_BLOCKED)
			continue;
		if (s_pciep_env[i].sim) {
			ctlhw = lsx_pciep_get_dev(i);
			ctlhw->hw.index = i;
			ctlhw->rbp = 0;
			ctlhw->sim = 1;
			ctlhw->ep_enable = 1;
			dev_nb++;
			LSX_PCIEP_BUS_INFO("Simulator PCIe%d added", i);
		}
	}

	return dev_nb;
}

int lsx_pciep_ctl_idx_validated(uint8_t pcie_idx)
{
	if (pcie_idx < LSX_MAX_PCIE_NB)
		return 1;

	return 0;
}

enum PEX_TYPE
rte_lsx_pciep_type_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	return s_pctl_hw[pciep_idx].type;
}

int
rte_lsx_pciep_hw_rbp_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	return s_pctl_hw[pciep_idx].rbp;
}

int
rte_lsx_pciep_hw_sim_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	return s_pctl_hw[pciep_idx].sim;
}

int
lsx_pciep_hw_vio_get(uint8_t pciep_idx,
	uint8_t pf_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);
	return s_pctl_hw[pciep_idx].vio_enable[pf_idx];
}

struct lsx_pciep_ctl_hw *
lsx_pciep_get_dev(uint8_t pcie_idx)
{
	if (pcie_idx >= LSX_MAX_PCIE_NB)
		return NULL;

	return &s_pctl_hw[pcie_idx];
}

static bool
lsx_pciep_ctl_is_ep(struct lsx_pciep_ctl_hw *ctlhw)
{
	if (ctlhw->type == PEX_LX2160_REV1 ||
		ctlhw->type == PEX_LX2160_REV2 ||
		ctlhw->type == PEX_LS208X)
		return true;

	return false;
}

static int
lsx_pciep_hw_set_type(void)
{
	FILE *svr_file = NULL;
	uint32_t svr_ver;
	enum PEX_TYPE type;
	int i;

	svr_file = fopen("/sys/devices/soc0/soc_id", "r");
	if (!svr_file) {
		LSX_PCIEP_BUS_ERR("Unable to open SoC device.");
		return -ENODEV;
	}
	if (fscanf(svr_file, "svr:%x", &svr_ver) < 0) {
		LSX_PCIEP_BUS_ERR("PCIe EP unable to read SoC device");
		return -ENODEV;
	}

	if ((svr_ver & SVR_MASK) == SVR_LX2160A) {
		if ((svr_ver & SVR_MAJOR_VER_MASK) == 0x10)
			type = PEX_LX2160_REV1;
		else
			type = PEX_LX2160_REV2;
	} else if ((svr_ver & SVR_MASK) == SVR_LS2088A) {
		type = PEX_LS208X;
	} else {
		LSX_PCIEP_BUS_DBG("SoC(0x%08x) not supported",
			(svr_ver & SVR_MASK));
		return -ENOTSUP;
	}

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		s_pctl_hw[i].type = type;
		if (type == PEX_LS208X)
			s_pctl_hw[i].hw.dbi_pf_size = LSX_PCIE_PF_LS2_DBI_SIZE;
		else if (type == PEX_LX2160_REV2)
			s_pctl_hw[i].hw.dbi_pf_size = LSX_PCIE_PF_LX2_DBI_SIZE;
	}

	return 0;
}

static int
lsx_pciep_hw_enable_clear_win(void)
{
	int i, clear_win;
	char *penv;
	char env[64];

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		sprintf(env, "LSX_PCIE%d_CLEAR_WINDOWS", i);
		penv = getenv(env);
		if (penv) {
			clear_win = atoi(penv);
		} else {
			/* Clear outbound/inbound windows configurations
			 * for EP starts up everytime as default.
			 * Notice: For the secondary standalone process,
			 * this flag must be DISABLED by setting this env to 0.
			 */
			clear_win = 1;
		}
		s_pctl_hw[i].clear_win = clear_win;
	}

	return 0;
}

uint16_t
rte_lsx_pciep_ctl_get_device_id(uint8_t pcie_idx,
	enum lsx_pcie_pf_idx pf_idx)
{
	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx == PF0_IDX || pf_idx == PF1_IDX);

	return s_pctl_hw[pcie_idx].pf_device_id[pf_idx];
}

static struct lsx_pciep_ctl_hw *
lsx_pciep_node2ctl(const struct device_node *pcie_node)
{
	const uint32_t *addr;
	uint64_t phys_addr, reg_off;
	uint64_t len;
	uint8_t pcie_idx;
	struct lsx_pciep_ctl_hw *ctlhw;

	addr = of_get_address(pcie_node, LSX_PCIE_DT_REG_ADDR_IDX,
			&len, NULL);
	if (!addr) {
		LSX_PCIEP_BUS_ERR("PCIe EP %s of_get_address failed",
			pcie_node->full_name);

		return NULL;
	}

	phys_addr = of_translate_address(pcie_node, addr);
	if (!phys_addr) {
		LSX_PCIEP_BUS_ERR("PCIe EP %s of_translate_address failed",
			pcie_node->full_name);

		return NULL;
	}
	RTE_ASSERT(!(phys_addr & (LSX_PCIE_REG_STRIDE - 1)));
	RTE_ASSERT(phys_addr >= LSX_PCIE_REG_PHY_START);
	RTE_ASSERT(phys_addr < (LSX_PCIE_REG_PHY_START +
			LSX_PCIE_REG_STRIDE * LSX_MAX_PCIE_NB));

	reg_off = phys_addr - LSX_PCIE_REG_PHY_START;

	pcie_idx = reg_off / LSX_PCIE_REG_STRIDE;
	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT((pcie_idx * (uint64_t)LSX_PCIE_REG_STRIDE) == reg_off);

	ctlhw = &s_pctl_hw[pcie_idx];

	ctlhw->hw.dbi_phy = phys_addr;
	ctlhw->hw.dbi_size = (uint32_t)len;
	ctlhw->hw.index = pcie_idx;

	return ctlhw;
}

static int
lsx_pciep_hw_out_base(struct lsx_pciep_ctl_hw *ctlhw,
	const struct device_node *pcie_node)
{
	uint64_t phys_addr;
	const uint32_t *addr;
	uint64_t len;

	addr = of_get_address(pcie_node, LSX_PCIE_DT_OB_ADDR_IDX,
			&len, NULL);
	if (!addr) {
		LSX_PCIEP_BUS_ERR("%s of_get_address failed",
			pcie_node->full_name);

		return -ENODEV;
	}

	phys_addr = of_translate_address(pcie_node, addr);
	if (!phys_addr) {
		LSX_PCIEP_BUS_ERR("%s of_translate_address failed",
			pcie_node->full_name);

		return -ENODEV;
	}

	ctlhw->hw.out_base = phys_addr;

	return 0;
}

static int
lsx_pciep_ctl_ob_win_scheme(struct lsx_pciep_ctl_hw *ctlhw)
{
	if (ctlhw->rbp)
		return 0;

	/** Hardware max window size.*/
	ctlhw->out_win_size = ctlhw->hw.out_win_max_size;
	if (ctlhw->hw.ob_policy == LSX_PCIEP_OB_SHARE) {
		/* All the PF/VFs share global outbound windows,
		 * in case PF/VFs devices are only mapped into
		 * same VM or host.
		 */
		ctlhw->out_size_per_fun = ctlhw->hw.out_size;
	}
	if (ctlhw->out_size_per_fun < ctlhw->out_win_size)
		ctlhw->out_size_per_fun = ctlhw->out_win_size;

	ctlhw->out_win_per_fun =
		ctlhw->out_size_per_fun / ctlhw->out_win_size;
	if (!ctlhw->out_win_per_fun) {
		LSX_PCIEP_BUS_ERR("Error out_win_per_fun");

		return -ENODEV;
	}

	return 0;
}

static int
lsx_pciep_ctl_hw_init(struct lsx_pciep_ctl_hw *ctlhw)
{
	int ret;

	if (ctlhw->ops->pcie_config)
		ctlhw->ops->pcie_config(&ctlhw->hw);
	ret = lsx_pciep_ctl_ob_win_scheme(ctlhw);
	if (ret)
		LSX_PCIEP_BUS_ERR("Invalid OB win");

	return ret;
}

static int
lsx_pciep_find_all_ctls(void)
{
	int ret, ctl_nb = 0, i = 0;
	const struct device_node *pcie_node;
	const char *compatible;
	struct lsx_pciep_ctl_hw *ctlhw;
	static const char * const compatible_strs[] = {
		LX2160A_REV1_PCIE_COMPATIBLE,
		LX2160A_REV2_PCIE_COMPATIBLE,
		LS2088A_PCIE_COMPATIBLE,
		LX2160A_REV2_PCIE_OLD_COMPATIBLE
	};
	int str_nb = sizeof(compatible_strs) / sizeof(const char *);

	if (lsx_pciep_ctl_set_ops())
		return -ENODEV;

	ret = of_init();
	if (ret) {
		LSX_PCIEP_BUS_ERR("of_init failed");

		return -ENODEV;
	}

	/* ctlhw is temporally pointed to the first
	 * PCIe dev to identify the PEX type.
	 */
	ctlhw = &s_pctl_hw[0];

	for (i = 0; i < str_nb; i++) {
		compatible = compatible_strs[i];
		for_each_compatible_node(pcie_node, NULL, compatible) {
			if (!of_device_is_available(pcie_node))
				continue;
			ctlhw = lsx_pciep_node2ctl(pcie_node);
			if (!ctlhw)
				continue;
			if (lsx_pciep_ctl_filtered(ctlhw->hw.index))
				continue;
			if (lsx_pciep_ctl_is_ep(ctlhw)) {
				ret = lsx_pciep_hw_out_base(ctlhw, pcie_node);
				if (!ret) {
					ret = lsx_pciep_ctl_hw_init(ctlhw);
					if (ret)
						return ret;
					ctlhw->ep_enable = 1;
					ctl_nb++;
				}
			}
		}
		if (ctl_nb)
			break;
	}

	if (ctl_nb)
		LSX_PCIEP_BUS_INFO("LX2 PCIe EP finds %d PCIe controller(s))", ctl_nb);
	else
		LSX_PCIEP_BUS_DBG("LX2 PCIe EP finds %d PCIe controller(s))", ctl_nb);

	return ctl_nb;
}

int lsx_pciep_ctl_init_win(uint8_t pcie_idx)
{
	struct lsx_pciep_ctl_hw *ctlhw;
	int ret = 0;

	if (pcie_idx >= LSX_MAX_PCIE_NB)
		return -EINVAL;

	ctlhw = &s_pctl_hw[pcie_idx];

	if (ctlhw->init || !ctlhw->ep_enable)
		goto end;

	if (rte_lsx_pciep_hw_sim_get(pcie_idx) ||
		rte_eal_process_type() != RTE_PROC_PRIMARY)
		goto init_end;

	if (!ctlhw->ops)
		return -EINVAL;

	if (ctlhw->clear_win &&
		ctlhw->ops->pcie_disable_ob_win) {
		ret = ctlhw->ops->pcie_disable_ob_win(&ctlhw->hw,
			PCIE_EP_DISABLE_ALL_WIN);
		if (ret)
			return ret;
	}
	if (ctlhw->clear_win &&
		ctlhw->ops->pcie_disable_ib_win) {
		ret = ctlhw->ops->pcie_disable_ib_win(&ctlhw->hw,
			PCIE_EP_DISABLE_ALL_WIN);
		if (ret)
			return ret;
	}

init_end:
	ctlhw->init = 1;
end:
	return ret;
}

#ifndef IORESOURCE_MEM
#define IORESOURCE_MEM        0x00000200
#endif

static int lsx_pciep_sim_rm_dir(const char *dir)
{
	char cur_dir[] = ".";
	char up_dir[] = "..";
	char dir_name[512];
	DIR *dirp;
	struct dirent *dp;
	struct stat dir_stat;
	int ret;

	ret = access(dir, F_OK);
	if (ret) {
		/** Force remove this file
		 */
		ret = remove(dir);
		if (ret) {
			LSX_PCIEP_BUS_ERR("line(%d) remove(%s) = %d failed",
				__LINE__, dir, ret);
		}
		return ret;
	}

	ret = stat(dir, &dir_stat);
	if (ret < 0) {
		/** Force remove this file
		 */
		ret = remove(dir);
		if (ret) {
			LSX_PCIEP_BUS_ERR("line(%d) remove(%s) = %d failed",
				__LINE__, dir, ret);
		}
		return ret;
	}

	if (S_ISREG(dir_stat.st_mode)) {
		ret = remove(dir);
		if (ret) {
			LSX_PCIEP_BUS_ERR("line(%d) remove(%s) = %d failed",
				__LINE__, dir, ret);
		}
	} else if (S_ISDIR(dir_stat.st_mode)) {
		dirp = opendir(dir);
		while ((dp = readdir(dirp)) != NULL) {
			if (strcmp(cur_dir, dp->d_name) == 0 ||
				strcmp(up_dir, dp->d_name) == 0) {
				continue;
			}

			sprintf(dir_name, "%s/%s", dir, dp->d_name);
			lsx_pciep_sim_rm_dir(dir_name);
		}
		closedir(dirp);

		ret = rmdir(dir);
		if (ret) {
			LSX_PCIEP_BUS_ERR("line(%d) rmdir(%s) = %d failed",
				__LINE__, dir, ret);
		}
	} else {
		LSX_PCIEP_BUS_ERR("unknown file(%s) type!",
				dir);
	}

	return 0;
}

int
rte_lsx_pciep_sim_dev_map_inbound(struct rte_lsx_pciep_device *ep_dev)
{
	char dir_name[64];
	char file_name[128];
	char file_link_name[128];
	char buf[1024];
	int status, fd, i, idx = 0, pf = ep_dev->pf;
	uint64_t flag = IORESOURCE_MEM, start, end;
	int ret;
	char *penv;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[ep_dev->pcie_id];
	uint16_t vendor_id, device_id, class_id;

	if (!rte_lsx_pciep_hw_sim_get(ep_dev->pcie_id))
		return 0;

	if (ep_dev->is_vf) {
		LSX_PCIEP_BUS_ERR("PCIe EP simulator does not support VF");

		return -ENODEV;
	}

	vendor_id = ctlhw->pf_vendor_id[pf];
	device_id = ctlhw->pf_device_id[pf];
	class_id = ctlhw->pf_class_id[pf];

	penv = getenv("PCIE_EP_SIM_DEV_PATH");
	if (!penv) {
		snprintf(dir_name, sizeof(dir_name),
			LSX_PCIEP_SIM_DEFAULT_PATH PCI_PRI_FMT,
			ep_dev->pcie_id, LSX_PCIEP_SIM_BUS,
			LSX_PCIEP_SIM_PF_DEV,
			pf);
	} else {
		strcpy(dir_name, penv);
		snprintf(dir_name + strlen(penv),
			sizeof(dir_name) - strlen(penv),
			PCI_PRI_FMT, ep_dev->pcie_id,
			LSX_PCIEP_SIM_BUS,
			LSX_PCIEP_SIM_PF_DEV, pf);
	}

	if (!access(dir_name, F_OK)) {
		status = lsx_pciep_sim_rm_dir(dir_name);
		if (status < 0) {
			LSX_PCIEP_BUS_ERR("Remove dir %s failed", dir_name);

			return -ENODEV;
		}
	}

	status = mkdir(dir_name, 0777);
	if (status < 0) {
		LSX_PCIEP_BUS_ERR("Create dir %s failed", dir_name);
		return -ENODEV;
	}

	snprintf(file_name, sizeof(file_name), "%s/vendor", dir_name);
	sprintf(buf, "0x%04x\n", vendor_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);

		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);

		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/device", dir_name);
	sprintf(buf, "0x%04x\n", device_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/subsystem_vendor", dir_name);
	sprintf(buf, "0x%04x\n", vendor_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/subsystem_device", dir_name);
	sprintf(buf, "0x%04x\n", device_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/class", dir_name);
	sprintf(buf, "0x%04x\n", class_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_link_name, sizeof(file_link_name),
		"%s/%s", dir_name, LSX_SIM_UIO_NM);
	sprintf(buf, "%s\n", LSX_SIM_UIO_NM);
	fd = open(file_link_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, strlen(buf));
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);
	snprintf(file_name, sizeof(file_name), "%s/driver", dir_name);
	ret = symlink(file_link_name, file_name);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Symlink file %s failed", file_name);
		return -ENODEV;
	}

	snprintf(file_name, sizeof(file_name), "%s/resource", dir_name);
	for (i = 0; i < PCI_MAX_RESOURCE; i++) {
		if (ep_dev->ib_size[i]) {
			start = ep_dev->iov_addr[i];
			end = start + ep_dev->ib_size[i] - 1;
			flag = IORESOURCE_MEM;
		} else {
			start = 0;
			end = 0;
			flag = 0;
		}
		idx += sprintf(&buf[idx], "0x%016lx ", start);
		idx += sprintf(&buf[idx], "0x%016lx ", end);
		idx += sprintf(&buf[idx], "0x%016lx\r\n", flag);
	}

	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, idx);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	LSX_PCIEP_BUS_INFO("PEX%d:pf%d bar info:\r\n%s",
		ep_dev->pcie_id, ep_dev->pf, buf);

	return 0;
}

int
rte_lsx_pciep_fun_config(uint16_t vendor_id,
	uint16_t device_id, uint16_t class_id,
	uint16_t sub_vendor_id, uint16_t sub_device_id,
	uint8_t pcie_id, int pf, int is_vf, int vf)
{
	struct lsx_pciep_ctl_hw *ctlhw;
	int ret = 0;

	if (pcie_id >= LSX_MAX_PCIE_NB || pf >= PF_MAX_NB) {
		LSX_PCIEP_BUS_ERR("%s Invalid PCIe ID or PF ID",
			__func__);

		return -EINVAL;
	}

	ctlhw = &s_pctl_hw[pcie_id];
	if (!ctlhw->ep_enable) {
		LSX_PCIEP_BUS_ERR("%s PCIe(%d) is not EP",
			__func__, pcie_id);

		return -ENODEV;
	}
	if (!ctlhw->pf_enable[pf]) {
		LSX_PCIEP_BUS_ERR("%s PCIe(%d) pf(%d) is not enabled",
			__func__, pcie_id, pf);

		return -ENODEV;
	}

	if (!rte_lsx_pciep_hw_sim_get(pcie_id)) {
		if (ctlhw->ops && ctlhw->ops->pcie_fun_init) {
			ret = ctlhw->ops->pcie_fun_init(&ctlhw->hw,
				pf, is_vf, vf,
				vendor_id, device_id, class_id);
			if (ret) {
				LSX_PCIEP_BUS_ERR("%s Fun init err(%d)",
					__func__, ret);
				return ret;
			}
		}
		ret = rte_lsx_pciep_fun_set_ext(sub_vendor_id,
			sub_device_id, pcie_id, pf, is_vf, vf);
		if (ret) {
			LSX_PCIEP_BUS_ERR("%s Fun set ext err(%d)",
				__func__, ret);
			return ret;
		}
	}

	if (is_vf) {
		ctlhw->vf_vendor_id[pf][vf] = vendor_id;
		ctlhw->vf_device_id[pf][vf] = device_id;
		ctlhw->vf_class_id[pf][vf] = class_id;

		ctlhw->vf_sub_vendor_id[pf][vf] = sub_vendor_id;
		ctlhw->vf_sub_device_id[pf][vf] = sub_device_id;
	} else {
		ctlhw->pf_vendor_id[pf] = vendor_id;
		ctlhw->pf_device_id[pf] = device_id;
		ctlhw->pf_class_id[pf] = class_id;

		ctlhw->pf_sub_vendor_id[pf] = sub_vendor_id;
		ctlhw->pf_sub_device_id[pf] = sub_device_id;
	}

	return ret;
}

int
rte_lsx_pciep_fun_set_ext(uint16_t sub_vendor_id,
	uint16_t sub_device_id, uint8_t pcie_id,
	int pf, int is_vf, int vf)
{
	struct lsx_pciep_ctl_hw *ctlhw;
	int ret = 0;
	uint8_t dis_sriov, dis_ari, dis_ats;

	if (pcie_id >= LSX_MAX_PCIE_NB || pf >= PF_MAX_NB) {
		LSX_PCIEP_BUS_ERR("%s Invalid PCIe ID or PF ID",
			__func__);

		return -EINVAL;
	}

	ctlhw = &s_pctl_hw[pcie_id];
	if (!ctlhw->ep_enable) {
		LSX_PCIEP_BUS_ERR("%s PCIe(%d) is not EP",
			__func__, pcie_id);

		return -ENODEV;
	}
	if (!ctlhw->pf_enable[pf]) {
		LSX_PCIEP_BUS_ERR("%s PCIe(%d) pf(%d) is not enabled",
			__func__, pcie_id, pf);

		return -ENODEV;
	}

	if (is_vf) {
		dis_sriov = 0;
		dis_ari = s_pciep_env[pcie_id].vf_dis_ari[pf][vf];
		dis_ats = s_pciep_env[pcie_id].vf_dis_ats[pf][vf];
	} else {
		dis_sriov = s_pciep_env[pcie_id].pf_dis_sriov[pf];
		dis_ari = s_pciep_env[pcie_id].pf_dis_ari[pf];
		dis_ats = s_pciep_env[pcie_id].pf_dis_ats[pf];
	}

	if (!rte_lsx_pciep_hw_sim_get(pcie_id)) {
		if (ctlhw->ops && ctlhw->ops->pcie_fun_init_ext) {
			ret = ctlhw->ops->pcie_fun_init_ext(&ctlhw->hw,
				pf, is_vf, vf, sub_vendor_id, sub_device_id,
				dis_sriov, dis_ari, dis_ats);
			if (ret)
				return ret;
		}
	}

	if (!is_vf) {
		ctlhw->pf_sub_vendor_id[pf] = sub_vendor_id;
		ctlhw->pf_sub_device_id[pf] = sub_device_id;
	} else {
		ctlhw->vf_sub_vendor_id[pf][vf] = sub_vendor_id;
		ctlhw->vf_sub_device_id[pf][vf] = sub_device_id;
	}

	return ret;
}

static void
lsx_pciep_hw_set_by_general_env(void)
{
	int i;
	struct lsx_pciep_ctl_hw *ctlhw;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		ctlhw = &s_pctl_hw[i];
		ctlhw->rbp = lsx_pciep_rbp_env_get(i);
		ctlhw->sim = lsx_pciep_sim_env_get(i);
		ctlhw->hw.ob_policy = lsx_pciep_ob_policy_env_get(i);
		ctlhw->out_size_per_fun = lsx_pciep_ob_fun_size_env_get(i);
	}
}

static void
lsx_pciep_hw_set_by_sriov_env(void)
{
	int i, j, k;
	struct lsx_pciep_ctl_hw *ctlhw;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		ctlhw = &s_pctl_hw[i];
		for (j = 0; j < PF_MAX_NB; j++) {
			ctlhw->pf_enable[j] =
				lsx_pciep_fun_env_get(i, j, -1);
			if (ctlhw->pf_enable[j])
				ctlhw->function_num++;
			ctlhw->vio_enable[j] =
				lsx_pciep_vio_env_get(i, j);
			for (k = 0; k < PCIE_MAX_VF_NUM; k++) {
				ctlhw->vf_enable[j][k] =
					lsx_pciep_fun_env_get(i, j, k);
				if (ctlhw->vf_enable[j][k])
					ctlhw->function_num++;
			}
		}
	}
}

int
lsx_pciep_primary_init(void)
{
	int ret = 0;

	if (s_pciep_init_flag) {
		LSX_PCIEP_BUS_INFO("%s has been executed!", __func__);

		return 0;
	}

	s_pctl_hw = malloc(LSX_PCIEP_CTL_HW_TOTAL_SIZE);
	if (!s_pctl_hw) {
		LSX_PCIEP_BUS_ERR("malloc (%ldBytes) for s_pctl_hw failed",
			LSX_PCIEP_CTL_HW_TOTAL_SIZE);

		ret = -ENOMEM;
		goto init_exit;
	}
	memset(s_pctl_hw, 0, LSX_PCIEP_CTL_HW_TOTAL_SIZE);

	lsx_pciep_parse_general_env();
	lsx_pciep_hw_set_by_general_env();
	ret = lsx_pciep_hw_set_type();
	if (ret)
		goto init_exit;

	lsx_pciep_hw_enable_clear_win();

	lsx_pciep_ctl_set_ops();

	ret = lsx_pciep_find_all_sim();
	if (!ret) {
		ret = lsx_pciep_find_all_ctls();
		if (ret <= 0) {
			ret = -ENODEV;
			goto init_exit;
		}
	} else if (ret < 0)
		goto init_exit;

	ret = lsx_pciep_ctl_process_map();
	if (ret <= 0) {
		if (!ret)
			ret = -ENODEV;
		goto init_exit;
	} else {
		ret = 0;
	}

	lsx_pciep_ctl_process_sriov();

	lsx_pciep_parse_sriov_env();
	lsx_pciep_hw_set_by_sriov_env();

init_exit:
	if (ret) {
		if (s_pctl_hw)
			free(s_pctl_hw);

		s_pctl_hw = NULL;
	}
	s_pciep_init_flag = 1;

	return ret;
}

int
lsx_pciep_uninit(void)
{
	int dev_idx;
	struct lsx_pciep_ctl_hw *ctlhw;

	if (!s_pctl_hw) {
		s_pciep_init_flag = 0;
		return 0;
	}

	for (dev_idx = 0; dev_idx < LSX_MAX_PCIE_NB; dev_idx++) {
		ctlhw = &s_pctl_hw[dev_idx];
		if (!ctlhw->ep_enable)
			continue;

		if (ctlhw->hw.dbi_vir)
			munmap(ctlhw->hw.dbi_vir, ctlhw->hw.dbi_size);

		if (ctlhw->out_vir)
			munmap((void *)ctlhw->out_vir, ctlhw->hw.out_size);

		if (ctlhw->ops->pcie_deconfig)
			ctlhw->ops->pcie_deconfig(&ctlhw->hw);
		ctlhw->ops = NULL;
	}

	if (s_pctl_hw)
		free(s_pctl_hw);
	s_pctl_hw = NULL;

	s_pciep_init_flag = 0;

	return 0;
}

void
lsx_pciep_free_shared_mem(void)
{
	if (primary_shared_mz) {
		rte_memzone_free(primary_shared_mz);
		primary_shared_mz = NULL;
	}
}

#include <rte_memory.h>

static uint64_t
lsx_get_hugepage_size(void)
{
	static const char sys_dir_path[] = "/sys/kernel/mm/hugepages";
	static const char dirent_start_text[] = "hugepages-";
	const size_t dirent_start_len = sizeof(dirent_start_text) - 1;
	uint64_t hugepage_sz, ret;
	DIR *dir;
	struct dirent *dirent;
	int fd, free_num;
	char free_huge_pages_nm[PATH_MAX];
	char buf[4096];

	dir = opendir(sys_dir_path);
	if (dir == NULL) {
		LSX_PCIEP_BUS_ERR("%s Open directory %s failed!",
			__func__, sys_dir_path);
		return 0;
	}

	for (dirent = readdir(dir); dirent != NULL; dirent = readdir(dir)) {
		if (strncmp(dirent->d_name, dirent_start_text,
			    dirent_start_len) != 0)
			continue;

		hugepage_sz =
			rte_str_to_size(&dirent->d_name[dirent_start_len]);
		sprintf(free_huge_pages_nm,
			"%s/%s/free_hugepages", sys_dir_path, dirent->d_name);
		fd = open(free_huge_pages_nm, O_RDONLY);
		ret = read(fd, buf, 1024);
		if (ret < 1) {
			LSX_PCIEP_BUS_WARN("%s Read %s failed!",
				__func__, free_huge_pages_nm);
			close(fd);
			continue;
		}
		free_num = atoi(buf);
		if (free_num > 0) {
			LSX_PCIEP_BUS_INFO("%s %s:%d",
				__func__, free_huge_pages_nm, free_num);
			close(fd);
			closedir(dir);
			return hugepage_sz;
		}
		close(fd);
	}
	closedir(dir);

	LSX_PCIEP_BUS_ERR("%s: No free pages found!",
		__func__);

	return 0;
}

int
rte_lsx_pciep_set_ib_win(struct rte_lsx_pciep_device *ep_dev,
	uint8_t bar_idx, uint64_t size)
{
	int pcie_id = ep_dev->pcie_id;
	int pf = ep_dev->pf;
	int vf = ep_dev->vf;
	int is_vf = ep_dev->is_vf, ret;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];
	char *penv, *ptr;
	char str[64];
	uint64_t min_size = LSX_PCIEP_INBOUND_MIN_BAR_SIZE;
	uint64_t iova = 0, phy = 0, vir = 0;
	uint64_t offset = 0, page_sz, adjust = 0;

	if (is_vf) {
		sprintf(str, "LSX_PCIE%d_PF%d_VF%d_BAR%d_MIN_SIZE",
			pcie_id, pf, vf, bar_idx);
	} else {
		sprintf(str, "LSX_PCIE%d_PF%d_BAR%d_MIN_SIZE",
			pcie_id, pf, bar_idx);
	}
	penv = getenv(str);
	if (penv) {
		if (strtol(penv, &ptr, 16) >= LSX_PCIEP_INBOUND_MIN_BAR_SIZE) {
			min_size = strtol(penv, &ptr, 16);
		} else if (atoi(penv) >= LSX_PCIEP_INBOUND_MIN_BAR_SIZE) {
			min_size = atoi(penv);
		} else {
			LSX_PCIEP_BUS_WARN("%s = 0x%08x/0x%lx too small?",
				str, atoi(penv), strtol(penv, &ptr, 16));
		}
	}

	if (size < min_size)
		size = min_size;
	if (!rte_is_power_of_2(size))
		size = rte_align64pow2(size);

	if (bar_idx >= PCI_MAX_RESOURCE) {
		LSX_PCIEP_BUS_ERR("%s too large bar number(%d)",
			__func__, bar_idx);

		return -EINVAL;
	}

	if (ep_dev->virt_addr[bar_idx] &&
		ep_dev->phy_addr[bar_idx] &&
		ep_dev->iov_addr[bar_idx]) {
		phy = ep_dev->phy_addr[bar_idx];
		goto configure_this_win;
	}

	if (lsx_pciep_nonsnoop_env_get(pcie_id))
		goto huge_page_ib_configure;

	if (is_vf) {
		sprintf(str, "PCIE%d_PF%d_VF%d_BAR%d_mz",
			pcie_id, pf, vf, bar_idx);
	} else {
		sprintf(str, "PCIE%d_PF%d_BAR%d_mz",
			pcie_id, pf, bar_idx);
	}

	ep_dev->ib_zone[bar_idx] = rte_memzone_reserve_aligned(str,
			size, 0, RTE_MEMZONE_IOVA_CONTIG, size);
	if (!ep_dev->ib_zone[bar_idx]) {
		LSX_PCIEP_BUS_ERR("%s: Reserve %s size(%ld) failed",
			__func__, str, size);
		return -ENOMEM;
	}
	vir = ep_dev->ib_zone[bar_idx]->addr_64;
	iova = ep_dev->ib_zone[bar_idx]->iova;
	phy = rte_mem_virt2phy((const void *)vir);
	goto configure_this_win;

huge_page_ib_configure:
	if (s_ib_seg.ib_seg[bar_idx])
		goto configure_this_bar;

	page_sz = lsx_get_hugepage_size();
	if (page_sz < size) {
		LSX_PCIEP_BUS_ERR("%s: Page size(%ld) < required(%ld)",
			__func__, page_sz, size);
		return -ENOMEM;
	}

	s_ib_seg.ib_seg[bar_idx] = rte_eal_memalloc_alloc_seg(page_sz, 0);
	LSX_PCIEP_BUS_INFO("%s: Alloc bar[%d]'s page(%p)(size=%lx)",
		__func__, bar_idx, s_ib_seg.ib_seg[bar_idx], page_sz);
	if (!s_ib_seg.ib_seg[bar_idx])
		return -ENOMEM;

	ret = rte_fslmc_vfio_mem_dmamap(s_ib_seg.ib_seg[bar_idx]->addr_64,
		s_ib_seg.ib_seg[bar_idx]->iova,
		s_ib_seg.ib_seg[bar_idx]->len);
	if (ret) {
		LSX_PCIEP_BUS_ERR("%s: VFIO MEM MAP failed(%d) for bar%d",
			__func__, ret, bar_idx);

		return ret;
	}

	LSX_PCIEP_BUS_INFO(IB_HUGE_PAGE_DUMP_FORMAT(bar_idx,
		s_ib_seg.ib_seg[bar_idx]->iova,
		rte_mem_virt2phy(s_ib_seg.ib_seg[bar_idx]->addr),
		s_ib_seg.ib_seg[bar_idx]->addr,
		s_ib_seg.ib_seg[bar_idx]->len));
	s_ib_seg.offset[bar_idx] = 0;
	s_ib_seg.used[bar_idx] = 0;
	s_ib_seg.cached[bar_idx] = 1;

configure_this_bar:
	offset = s_ib_seg.offset[bar_idx];
	iova = s_ib_seg.ib_seg[bar_idx]->iova + offset;

	while (iova & (size - 1)) {
		adjust++;
		iova++;
	}

	if ((offset + adjust + size) > s_ib_seg.ib_seg[bar_idx]->len) {
		LSX_PCIEP_BUS_ERR("%s: Page left(%ld) < required(%ld)",
			__func__,
			s_ib_seg.ib_seg[bar_idx]->len - offset - adjust,
			size);
		return -ENOMEM;
	}
	vir = s_ib_seg.ib_seg[bar_idx]->addr_64 + offset + adjust;
	phy = rte_mem_virt2phy((const void *)vir);

configure_this_win:
	if (!rte_lsx_pciep_hw_sim_get(ctlhw->hw.index)) {
		ret = ctlhw->ops->pcie_cfg_ib_win(&ctlhw->hw,
			pf, is_vf, vf,
			bar_idx, phy, size);
		if (ret)
			return ret;
	}

	if (vir) {
		/**Malloc from hugepage.*/
		if (!ep_dev->ib_zone[bar_idx]) {
			s_ib_seg.offset[bar_idx] = offset + adjust + size;
			s_ib_seg.used[bar_idx] += adjust + size;
		}

		ep_dev->virt_addr[bar_idx] = (void *)vir;
		ep_dev->phy_addr[bar_idx] = phy;
		ep_dev->iov_addr[bar_idx] = iova;
		ep_dev->ib_size[bar_idx] = size;
		if (!ep_dev->ib_zone[bar_idx])
			ep_dev->ib_seg_size[bar_idx] = size + adjust;
		else
			ep_dev->ib_seg_size[bar_idx] = 0;
	} else {
		ep_dev->ib_size[bar_idx] = size;
		ep_dev->ib_seg_size[bar_idx] = 0;
	}

	return 0;
}

int
rte_lsx_pciep_unset_ib_win(struct rte_lsx_pciep_device *ep_dev,
	uint8_t bar_idx)
{
	int ret;

	if (ep_dev->ib_zone[bar_idx]) {
		ret = rte_memzone_free(ep_dev->ib_zone[bar_idx]);
		if (ret) {
			LSX_PCIEP_BUS_ERR("Free BAR%d's memzone failed(%d)",
				bar_idx, ret);
		}
		ep_dev->ib_zone[bar_idx] = NULL;

		return ret;
	}

	s_ib_seg.used[bar_idx] -= ep_dev->ib_seg_size[bar_idx];
	if (!s_ib_seg.used[bar_idx] && s_ib_seg.ib_seg[bar_idx]) {
		ret = rte_eal_memalloc_free_seg(s_ib_seg.ib_seg[bar_idx]);
		if (ret) {
			LSX_PCIEP_BUS_ERR("Free BAR%d's segment failed(%d)",
				bar_idx, ret);
		}
		s_ib_seg.ib_seg[bar_idx] = NULL;
		s_ib_seg.offset[bar_idx] = 0;
		s_ib_seg.cached[bar_idx] = 0;
	}

	ep_dev->virt_addr[bar_idx] = NULL;
	ep_dev->phy_addr[bar_idx] = 0;
	ep_dev->iov_addr[bar_idx] = 0;
	ep_dev->ib_size[bar_idx] = 0;
	ep_dev->ib_seg_size[bar_idx] = 0;

	return 0;
}

void
rte_lsx_pciep_ib_cache_mark(struct rte_lsx_pciep_device *ep_dev,
	uint8_t bar_idx, int cached)
{
	RTE_SET_USED(ep_dev);
	if (!s_ib_seg.ib_seg[bar_idx])
		return;

	if ((cached && s_ib_seg.cached[bar_idx]) ||
		(!cached && !s_ib_seg.cached[bar_idx]))
		return;

	if (cached) {
		/**TBD*/
		return;
	}

	mark_kpage_ncache(s_ib_seg.ib_seg[bar_idx]->addr_64);
	s_ib_seg.cached[bar_idx] = 0;
}

#define OB_PF_INFO_DUMP_FORMAT(pci, pf, \
		vir, phy, bus, size) \
		"Outbound PEX%d PF%d:" \
		"  MEM VIRT:%p" \
		"  MEM:0x%lx" \
		"  PCI:0x%lx" \
		"  SIZE:0x%lx", \
		pci, pf, vir, \
		(unsigned long)phy, \
		(unsigned long)bus, \
		(unsigned long)size

#define OB_VF_INFO_DUMP_FORMAT(pci, pf, vf, \
		vir, phy, bus, size) \
		"Outbound PEX%d PF%d-VF%d:" \
		"  MEM VIRT:%p" \
		"  MEM:0x%lx" \
		"  PCI:0x%lx" \
		"  SIZE:0x%lx", \
		pci, pf, vf, vir, \
		(unsigned long)phy, \
		(unsigned long)bus, \
		(unsigned long)size

int
rte_lsx_pciep_rbp_ob_overlap(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_addr, uint64_t size)
{
	uint8_t i;
	struct lsx_pciep_outbound *ob_win;
	uint64_t win_size;

	for (i = 0; i < ep_dev->rbp_ob_win_nb; i++) {
		ob_win = &ep_dev->ob_win[i];
		win_size = ob_win->ob_win_size * ob_win->ob_win_nb;
		if (pci_addr >= (ob_win->ob_map_bus_base + win_size))
			continue;
		if ((pci_addr + size) <= ob_win->ob_map_bus_base)
			continue;
		return true;
	}

	return false;
}

static uint8_t *
lsx_pciep_set_ob_win_rbp(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_addr, uint64_t size, uint64_t *pphy)
{
	int pf = ep_dev->pf;
	int vf = ep_dev->vf;
	int is_vf = ep_dev->is_vf;
	int pcie_id = ep_dev->pcie_id;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];
	struct lsx_pciep_outbound *ob_win;

	if (ep_dev->rbp_ob_win_nb >= LSX_PCIEP_OB_MAX_NB) {
		LSX_PCIEP_BUS_ERR("Too many outbound windows");
		return NULL;
	}

	if (rte_lsx_pciep_rbp_ob_overlap(ep_dev, pci_addr, size)) {
		LSX_PCIEP_BUS_ERR("New outbound window overlaps");
		return NULL;
	}

	ob_win = &ep_dev->ob_win[ep_dev->rbp_ob_win_nb];

	ob_win->ob_map_bus_base = pci_addr;
	ob_win->ob_win_size = size;
	ob_win->ob_win_nb = 1;

	ob_win->ob_phy_base =
		ctlhw->ops->pcie_map_ob_win(&ctlhw->hw, pf,
				is_vf, vf,
				ob_win->ob_map_bus_base,
				size, 0);
	if (!ob_win->ob_phy_base) {
		LSX_PCIEP_BUS_ERR("%s: OB map failed", __func__);
		return NULL;
	}
	ob_win->ob_virt_base =
		lsx_pciep_map_region(ob_win->ob_phy_base,
				size);
	if (ob_win->ob_virt_base) {
		int ret;
		uint64_t va, iova;

		va = (uint64_t)ob_win->ob_virt_base;
		if (rte_eal_iova_mode() == RTE_IOVA_VA)
			iova = va;
		else
			iova = ob_win->ob_phy_base;
		ret = rte_fslmc_vfio_mem_dmamap(va, iova, size);
		if (ret) {
			LSX_PCIEP_BUS_ERR("MAP va(%lx):iova(%lx):size(%lx)",
				va, iova, size);

			return NULL;
		}
		if (pphy)
			*pphy = iova;
	} else {
		LSX_PCIEP_BUS_ERR("MAP pa(%lx):size(%lx)",
			ob_win->ob_phy_base, size);
		return NULL;
	}

	if (is_vf)
		LSX_PCIEP_BUS_INFO(OB_VF_INFO_DUMP_FORMAT(pcie_id,
			pf, vf,
			ob_win->ob_virt_base,
			ob_win->ob_phy_base,
			ob_win->ob_map_bus_base,
			ob_win->ob_win_size));
	else
		LSX_PCIEP_BUS_INFO(OB_PF_INFO_DUMP_FORMAT(pcie_id,
			pf,
			ob_win->ob_virt_base,
			ob_win->ob_phy_base,
			ob_win->ob_map_bus_base,
			ob_win->ob_win_size));

	ep_dev->rbp_ob_win_nb++;

	return ob_win->ob_virt_base;
}

static uint8_t *
lsx_pciep_set_ob_win_norbp(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_map, uint64_t size, uint64_t *pphy)
{
	int pf = ep_dev->pf;
	int is_vf = ep_dev->is_vf;
	int vf = ep_dev->vf;
	int pcie_id = ep_dev->pcie_id;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];
	uint32_t idx, out_win_nb;
	uint64_t pci_addr = 0, out_phy, iova, va;
	int shared, ret;
	struct lsx_pciep_outbound *ob_win = &ep_dev->ob_win[0];

	if (ob_win->ob_virt_base) {
		if ((pci_map + size) >=
			(ob_win->ob_win_size * ob_win->ob_win_nb)) {
			LSX_PCIEP_BUS_ERR("%s(0x%lx ~ 0x%lx) >= %s(0 ~ 0x%lx)",
				"New PCIe range",
				pci_map, pci_map + size,
				"Outbond Window",
				ob_win->ob_win_size * ob_win->ob_win_nb);
			return NULL;
		}
		goto return_pcie_map_vir;
	}

	out_win_nb = ctlhw->out_win_per_fun;

	ob_win->ob_map_bus_base = pci_addr;
	ob_win->ob_win_size = ctlhw->out_win_size;
	ob_win->ob_win_nb = out_win_nb;

	shared = ctlhw->hw.ob_policy == LSX_PCIEP_OB_SHARE ? 1 : 0;

	for (idx = 0; idx < out_win_nb; idx++) {
		out_phy = ctlhw->ops->pcie_map_ob_win(&ctlhw->hw,
					pf, is_vf, vf,
					pci_addr,
					ctlhw->out_win_size, shared);
		if (!out_phy) {
			LSX_PCIEP_BUS_ERR("%s: OB map failed",
				__func__);
			ob_win->ob_phy_base = 0;
			ob_win->ob_virt_base = 0;
			return NULL;
		}
		pci_addr += ctlhw->out_win_size;
		if (idx == 0)
			ob_win->ob_phy_base = out_phy;
	}
	if (!shared) {
		ob_win->ob_virt_base =
			lsx_pciep_map_region(ob_win->ob_phy_base,
				out_win_nb * ctlhw->out_win_size);
		va = (uint64_t)ob_win->ob_virt_base;
		if (rte_eal_iova_mode() == RTE_IOVA_VA)
			iova = va;
		else
			iova = ob_win->ob_phy_base;
		ret = rte_fslmc_vfio_mem_dmamap(va, iova,
				out_win_nb * ctlhw->out_win_size);
		if (ret) {
			LSX_PCIEP_BUS_ERR("MAP va(%lx):pa(%lx):iova(%lx)",
				va, ob_win->ob_phy_base, iova);
			ob_win->ob_iova_base = RTE_BAD_IOVA;

			return NULL;
		} else {
			ob_win->ob_iova_base = iova;
		}
	} else {
		ob_win->ob_virt_base = ctlhw->out_vir +
			ob_win->ob_phy_base - ctlhw->hw.out_base;
		if (!ctlhw->share_vfio_map) {
			va = (uint64_t)ctlhw->out_vir;
			if (rte_eal_iova_mode() == RTE_IOVA_VA)
				iova = va;
			else
				iova = ctlhw->hw.out_base;
			ret = rte_fslmc_vfio_mem_dmamap(va, iova,
					ctlhw->hw.out_size);
			if (ret) {
				LSX_PCIEP_BUS_ERR("MAP va(%lx):iova(%lx)",
					va, iova);
				ctlhw->out_iova = RTE_BAD_IOVA;

				return NULL;
			} else {
				ctlhw->out_iova = iova;
			}
		}
		ctlhw->share_vfio_map++;
	}

return_pcie_map_vir:
	if (pphy)
		*pphy = (ob_win->ob_phy_base + pci_map);
	return ob_win->ob_virt_base + pci_map;
}

void *
rte_lsx_pciep_alloc_pci_ob(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_addr, uint64_t size, uint64_t *phy_base)
{
	int pcie_id = ep_dev->pcie_id;
	int pf = ep_dev->pf;
	int vf = ep_dev->vf;
	int is_vf = ep_dev->is_vf;
	uint8_t *vaddr;
	uint64_t phy;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];

	phy = ctlhw->ops->pcie_map_ob_win(&ctlhw->hw, pf,
			is_vf, vf, pci_addr, size, 0);
	if (!phy) {
		LSX_PCIEP_BUS_ERR("%s: OB map failed", __func__);
		return NULL;
	}
	vaddr = lsx_pciep_map_region(phy, size);
	if (vaddr) {
		int ret;
		uint64_t va, iova;

		va = (uint64_t)vaddr;
		if (rte_eal_iova_mode() == RTE_IOVA_VA)
			iova = va;
		else
			iova = phy;
		ret = rte_fslmc_vfio_mem_dmamap(va, iova, size);
		if (ret) {
			LSX_PCIEP_BUS_ERR("MAP va(%lx):iova(%lx):size(%lx)",
				va, iova, size);

			return NULL;
		}
		*phy_base = iova;
	} else {
		LSX_PCIEP_BUS_ERR("MAP pa(%lx):size(%lx)",
			phy, size);
		return NULL;
	}

	if (is_vf)
		LSX_PCIEP_BUS_INFO(OB_VF_INFO_DUMP_FORMAT(pcie_id,
			pf, vf, vaddr, phy, pci_addr, size));
	else
		LSX_PCIEP_BUS_INFO(OB_PF_INFO_DUMP_FORMAT(pcie_id,
			pf, vaddr, phy, pci_addr, size));

	return vaddr;
}

void *
rte_lsx_pciep_set_ob_win(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_addr, uint64_t size, uint64_t *pphy)
{
	int pcie_id = ep_dev->pcie_id;
	uint8_t *vaddr;
	uint64_t phy;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];

	if (rte_lsx_pciep_hw_sim_get(ctlhw->hw.index)) {
		ep_dev->ob_win[0].ob_map_bus_base = pci_addr;
		ep_dev->ob_win[0].ob_iova_base = pci_addr;
		vaddr = rte_fslmc_mem_iova_to_vaddr(pci_addr);
		phy = rte_mem_virt2phy((const void *)vaddr);
		if (phy == RTE_BAD_IOVA)
			return NULL;
		ep_dev->ob_win[0].ob_phy_base = phy;
		ep_dev->ob_win[0].ob_virt_base = vaddr;
		if (pphy)
			*pphy = phy;
		return vaddr;
	}

	if (ctlhw->rbp) {
		vaddr = lsx_pciep_set_ob_win_rbp(ep_dev,
			pci_addr, size, pphy);
	} else {
		vaddr = lsx_pciep_set_ob_win_norbp(ep_dev,
			pci_addr, size, pphy);
	}

	return vaddr;
}

static int
lsx_pciep_unset_ob_win_rbp(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_addr)
{
	int ret;
	uint64_t min, max;
	struct lsx_pciep_outbound *ob_win;
	uint8_t i, j, k;

	for (i = 0; i < ep_dev->rbp_ob_win_nb; i++) {
		ob_win = &ep_dev->ob_win[i];
		min = ob_win->ob_map_bus_base;
		max = ob_win->ob_map_bus_base + ob_win->ob_win_size - 1;
		if (pci_addr >= min && pci_addr < max) {
			ret = lsx_pciep_unmap_region(ob_win->ob_virt_base,
				ob_win->ob_win_size);
			if (ret) {
				LSX_PCIEP_BUS_ERR("%s: OB%d unmap err(%d)",
					ep_dev->name, i, ret);
				return ret;
			}
			/*TO DO: Free this outbound window from PCIe bus.*/
			memset(ob_win, 0, sizeof(struct lsx_pciep_outbound));
			k = i;
			for (j = i + 1; j < ep_dev->rbp_ob_win_nb; j++) {
				memcpy(&ep_dev->ob_win[k],
					&ep_dev->ob_win[j],
					sizeof(struct lsx_pciep_outbound));
				k++;
			}
			if (ep_dev->rbp_ob_win_nb > 0)
				ep_dev->rbp_ob_win_nb--;

			return 0;
		}
	}

	LSX_PCIEP_BUS_ERR("%s: bus(0x%lx) not mapped in this device",
		ep_dev->name, pci_addr);

	return -ENOMEM;
}

static int
lsx_pciep_unset_ob_win_norbp(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_addr)
{
	int pcie_id = ep_dev->pcie_id;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];
	int shared, ret;
	struct lsx_pciep_outbound *ob_win = &ep_dev->ob_win[0];
	uint64_t min, max, size;

	shared = ctlhw->hw.ob_policy == LSX_PCIEP_OB_SHARE ? 1 : 0;
	size = ob_win->ob_win_size * ob_win->ob_win_nb;
	min = ob_win->ob_map_bus_base;
	max = min + size - 1;

	if (pci_addr < min || pci_addr > max) {
		LSX_PCIEP_BUS_ERR("%s: bus(0x%lx) not mapped in this device",
			ep_dev->name, pci_addr);
		return -ENOMEM;
	}
	if (!shared) {
		ret = lsx_pciep_unmap_region(ob_win->ob_virt_base, size);
		if (ret) {
			LSX_PCIEP_BUS_ERR("%s: unshared OB unmap err(%d)",
				ep_dev->name, ret);
			return ret;
		}
		ret = rte_fslmc_vfio_mem_dmaunmap(ob_win->ob_iova_base,
				size);
		if (ret) {
			LSX_PCIEP_BUS_ERR("%s: v(%p)/p(%lx)/s(%lx)",
				"VFIO unmap failed",
				ob_win->ob_virt_base,
				ob_win->ob_phy_base, size);

			return ret;
		}
	} else {
		if (!ctlhw->share_vfio_map) {
			LSX_PCIEP_BUS_ERR("PCIe%d shared ob has been unmapped.",
				pcie_id);

			return -EINVAL;
		}
		ctlhw->share_vfio_map--;
		if (!ctlhw->share_vfio_map) {
			ret = lsx_pciep_unmap_region(ctlhw->out_vir,
					ctlhw->hw.out_size);
			if (ret) {
				LSX_PCIEP_BUS_ERR("%s: shared OB unmap err(%d)",
					ep_dev->name, ret);
				return ret;
			}
			ret = rte_fslmc_vfio_mem_dmaunmap(ctlhw->out_iova,
					ctlhw->hw.out_size);
			if (ret) {
				LSX_PCIEP_BUS_ERR("%s: v(%p)/p(%lx)/s(%lx)",
					"VFIO unmap failed",
					ob_win->ob_virt_base,
					ob_win->ob_phy_base, size);

				return ret;
			}
			ctlhw->out_vir = NULL;
		}
	}

	ob_win->ob_virt_base = NULL;
	ob_win->ob_phy_base = 0;
	ob_win->ob_map_bus_base = 0;

	return 0;
}

int
rte_lsx_pciep_unset_ob_win(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_addr)
{
	int pcie_id = ep_dev->pcie_id;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];

	if (ctlhw->rbp)
		return lsx_pciep_unset_ob_win_rbp(ep_dev, pci_addr);
	else
		return lsx_pciep_unset_ob_win_norbp(ep_dev, pci_addr);
}

static int
lsx_pciep_misx_addr_start(uint64_t msix_addr[], int num)
{
	int i, min_idx = 0;
	uint64_t min = msix_addr[0], max = 0;

	for (i = 0; i < num; i++) {
		if (msix_addr[i] > max)
			max = msix_addr[i];
		if (msix_addr[i] < min) {
			min = msix_addr[i];
			min_idx = i;
		}
	}

	return min_idx;
}

int
rte_lsx_pciep_multi_msix_init(struct rte_lsx_pciep_device *ep_dev,
	int vector_total)
{
	int pcie_id = ep_dev->pcie_id, base_idx, ret = 0;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];
	uint64_t size = 0, phy_base, iova;
	void *vir_base;

	ctlhw->hw.msi_flag = ep_dev->mmsi_flag;
	if (ctlhw->hw.msi_flag == LSX_PCIEP_DONT_INT)
		return 0;

	size = sizeof(uint64_t) * vector_total;
	ep_dev->msix_phy = rte_malloc(NULL, size, RTE_CACHE_LINE_SIZE);
	size = sizeof(void *) * vector_total;
	ep_dev->msix_addr = rte_malloc(NULL, size, RTE_CACHE_LINE_SIZE);
	size = sizeof(uint32_t) * vector_total;
	ep_dev->msix_data = rte_malloc(NULL, size, RTE_CACHE_LINE_SIZE);

	size = 0;
	vector_total = ctlhw->ops->pcie_msix_cfg(&ctlhw->hw,
			ctlhw->out_vir,
			ep_dev->pf,
			ep_dev->is_vf, ep_dev->vf,
			ep_dev->msix_phy, ep_dev->msix_addr,
			ep_dev->msix_data, &size,
			vector_total);
	if (vector_total <= 0) {
		LSX_PCIEP_BUS_ERR("%s: msix cfg failed",
			ep_dev->name);
		if (vector_total < 0)
			ret = vector_total;
		else
			ret = -EIO;
		goto failed_init_msix;
	}

	base_idx = lsx_pciep_misx_addr_start(ep_dev->msix_phy,
				vector_total);
	vir_base = ep_dev->msix_addr[base_idx];
	phy_base = ep_dev->msix_phy[base_idx];
	if (rte_eal_iova_mode() == RTE_IOVA_VA)
		iova = (uint64_t)vir_base;
	else
		iova = phy_base;

	ep_dev->msix_phy_base = phy_base;
	ep_dev->msix_iova_base = iova;
	ep_dev->msix_addr_base = vir_base;
	ep_dev->msix_map_size = size;

	return 0;

failed_init_msix:
	if (ep_dev->msix_addr) {
		rte_free(ep_dev->msix_addr);
		ep_dev->msix_addr = NULL;
	}
	if (ep_dev->msix_data) {
		rte_free(ep_dev->msix_data);
		ep_dev->msix_data = NULL;
	}

	return ret;
}

int
rte_lsx_pciep_multi_msix_remove(struct rte_lsx_pciep_device *ep_dev)
{
	int pcie_id = ep_dev->pcie_id, ret = 0;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];

	if (ctlhw->hw.msi_flag == LSX_PCIEP_DONT_INT)
		return 0;

	/*To do: de-config msix from PCIe EP bus.*/

	if (ctlhw->ops->pcie_msix_decfg) {
		ret = ctlhw->ops->pcie_msix_decfg(&ctlhw->hw,
			ctlhw->out_vir,
			ep_dev->pf,
			ep_dev->is_vf, ep_dev->vf,
			&ep_dev->msix_phy_base,
			&ep_dev->msix_addr_base,
			&ep_dev->msix_map_size, 1);
	}

	ep_dev->msix_phy_base = 0;
	ep_dev->msix_iova_base = 0;
	ep_dev->msix_addr_base = NULL;
	ep_dev->msix_map_size = 0;

	if (ep_dev->msix_phy) {
		rte_free(ep_dev->msix_phy);
		ep_dev->msix_phy = NULL;
	}
	if (ep_dev->msix_addr) {
		rte_free(ep_dev->msix_addr);
		ep_dev->msix_addr = NULL;
	}
	if (ep_dev->msix_data) {
		rte_free(ep_dev->msix_data);
		ep_dev->msix_data = NULL;
	}

	return ret;
}

void
rte_lsx_pciep_start_msix(void *addr, uint32_t cmd)
{
	if (likely(addr))
		rte_write32(cmd, addr);
}

int
rte_lsx_pciep_bus_ob_mapped(struct rte_lsx_pciep_device *ep_dev,
	uint64_t bus_addr)
{
	uint64_t offset, range;
	struct lsx_pciep_outbound *ob_win;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[ep_dev->pcie_id];
	int i;

	if (rte_lsx_pciep_hw_sim_get(ep_dev->pcie_id))
		return true;

	if (!ctlhw->rbp) {
		ob_win = &ep_dev->ob_win[0];
		offset = bus_addr - ob_win->ob_map_bus_base;
		range = ob_win->ob_win_size * ob_win->ob_win_nb;

		if (offset > range)
			return false;

		return true;
	}

	for (i = 0; i < ep_dev->rbp_ob_win_nb; i++) {
		ob_win = &ep_dev->ob_win[i];
		offset = bus_addr - ob_win->ob_map_bus_base;
		range = ob_win->ob_win_size * ob_win->ob_win_nb;
		if (offset <= range)
			return true;
	}

	return false;
}

#define DMA_64BIT_MAX  0xffffffffffffffffULL
uint64_t
rte_lsx_pciep_bus_ob_dma_size(struct rte_lsx_pciep_device *ep_dev)
{
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[ep_dev->pcie_id];

	if (ctlhw->rbp || ctlhw->sim)
		return DMA_64BIT_MAX / 4;

	return ep_dev->ob_win[0].ob_win_size * ep_dev->ob_win[0].ob_win_nb;
}

uint64_t
rte_lsx_pciep_bus_win_mask(struct rte_lsx_pciep_device *ep_dev)
{
	struct lsx_pciep_ctl_hw *ctlhw;

	if (rte_lsx_pciep_hw_sim_get(ep_dev->pcie_id))
		return 0;

	ctlhw = &s_pctl_hw[ep_dev->pcie_id];

	return ctlhw->hw.win_mask;
}

static void __attribute__((destructor(102))) lsx_pciep_finish(void)
{
	lsx_pciep_uninit();

	/* rte_eal_memory_detach or rte_bus_close should be called
	 * by application to free this memory zone.
	 */
	if (primary_shared_mz) {
		LSX_PCIEP_BUS_LOG(DEBUG,
			"Bus is not closed, is memory detached?");
		primary_shared_mz = NULL;
	}
}
