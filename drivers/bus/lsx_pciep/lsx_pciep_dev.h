/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2024 NXP
 */

#ifndef _LSX_PCIEP_DEV_H_
#define _LSX_PCIEP_DEV_H_

#include <rte_lsx_pciep_bus.h>

/* common definition */
#ifndef SVR_LS1080A
#define SVR_LS1080A	0x87030000
#endif
#ifndef SVR_LS2080A
#define SVR_LS2080A	0x87010000
#endif
#ifndef SVR_LS2088A
#define SVR_LS2088A	0x87090000
#endif
#ifndef SVR_LX2160A
#define SVR_LX2160A	0x87360000
#endif

#define LSX_MAX_PCIE_NB 6

#define PCIE_OB_SHADOW_WIN_OFF	0
#define PCIE_OB_MSIX_WIN_OFF	1
#define PCIE_OB_RBP_WIN_OFF	2

#define LS2088A_PCIE_COMPATIBLE "fsl,ls2088a-pcie-ep"
#define LX2160A_REV1_PCIE_COMPATIBLE "fsl,lx2160a-pcie-ep"
#define LX2160A_REV2_PCIE_COMPATIBLE LS2088A_PCIE_COMPATIBLE
#define LX2160A_REV2_PCIE_OLD_COMPATIBLE "fsl,lx2160ar2-pcie-ep"

#define PCI_DMA_RBP_1T_BASE		(0x010000000000)
#define PCI_DMA_RBP_0_BASE		(0)

#define LSX_PCIEP_QDMA_RBP_SUPPORT 1

#define LSX_PCIE_SIM_IDX 0

/** Provide outbound space shared policy
 * for multiple functions of each PCIe controller.
 */
enum lsx_ob_policy {
	LSX_PCIEP_OB_RBP,
	LSX_PCIEP_OB_FUN_IDX,
	LSX_PCIEP_OB_SHARE
};

enum sriov_fun_idx {
	PF_IDX,
	VF_IDX,
	SRIOV_FUN_MAX
};

/**
 * Structure describing HW information of PCIe controller.
 * This structure is global information shared between multiple
 * processes.
 */
struct lsx_pciep_hw_low {
	uint8_t index;
	int is_sriov;

	uint64_t dbi_phy;
	uint8_t *dbi_vir;
	uint32_t dbi_size;
	uint64_t dbi_pf_size;

	uint64_t out_base;
	uint64_t out_size;
	uint64_t out_win_max_size;

	uint64_t win_mask;
	uint64_t win_max;

	int msi_flag;

	enum lsx_ob_policy ob_policy;
};

struct lsx_pciep_ctl_hw {
	uint8_t	init;
	int sim;
	int rbp;
	int ep_enable;
	int clear_win;
	struct lsx_pciep_ops *ops;
	int vio_enable[PF_MAX_NB];
	uint16_t function_num;
	int pf_enable[PF_MAX_NB];
	int vf_enable[PF_MAX_NB][PCIE_MAX_VF_NUM];

	uint16_t pf_vendor_id[PF_MAX_NB];
	uint16_t pf_device_id[PF_MAX_NB];
	uint16_t pf_class_id[PF_MAX_NB];
	uint16_t pf_sub_vendor_id[PF_MAX_NB];
	uint16_t pf_sub_device_id[PF_MAX_NB];

	uint16_t vf_vendor_id[PF_MAX_NB][PCIE_MAX_VF_NUM];
	uint16_t vf_device_id[PF_MAX_NB][PCIE_MAX_VF_NUM];
	uint16_t vf_class_id[PF_MAX_NB][PCIE_MAX_VF_NUM];
	uint16_t vf_sub_vendor_id[PF_MAX_NB][PCIE_MAX_VF_NUM];
	uint16_t vf_sub_device_id[PF_MAX_NB][PCIE_MAX_VF_NUM];

	enum PEX_TYPE type;
	struct lsx_pciep_hw_low hw;

	uint8_t *out_vir;
	uint64_t out_iova;
	uint64_t out_win_size;
	uint64_t out_size_per_fun;
	uint32_t out_win_per_fun;
	int share_vfio_map;
};

int
lsx_pciep_ctl_idx_validated(uint8_t pcie_idx);
int
lsx_pciep_hw_vio_get(uint8_t pciep_idx,
	uint8_t pf_idx);
struct lsx_pciep_ctl_hw *
lsx_pciep_get_dev(uint8_t pcie_idx);

int
lsx_pciep_primary_init(void);
int
lsx_pciep_uninit(void);
void
lsx_pciep_free_shared_mem(void);
int
lsx_pciep_ctl_init_win(uint8_t pcie_idx);

void *
lsx_pciep_map_region(uint64_t addr, size_t len);
int
lsx_pciep_unmap_region(void *vaddr, size_t len);
int
lsx_pciep_share_info_init(void);

#endif
