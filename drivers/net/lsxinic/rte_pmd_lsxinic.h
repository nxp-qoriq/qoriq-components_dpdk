/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2024 NXP
 */

#ifndef _RTE_PMD_LSXINIC_H
#define _RTE_PMD_LSXINIC_H

/**
 * @file rte_pmd_lsxinic.h
 *
 * NXP lsxinic PMD specific functions.
 */

#include <rte_compat.h>

__rte_experimental
int
rte_lsinic_dev_start_poll_rc(void *_dev);

__rte_experimental
int
rte_lsinic_dev_get_rc_dma(void *_dev,
	void **pci_vir, uint64_t *pci_phy,
	uint64_t *pci_bus, uint64_t *pci_size,
	int *pci_id, int *pf_id, int *is_vf, int *vf_id);

#endif /* _RTE_PMD_LSXINIC_H */
