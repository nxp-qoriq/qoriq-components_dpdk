/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023-2024 NXP
 */

#ifndef _ENETQOS_LOGS_H_
#define _ENETQOS_LOGS_H_

#include <rte_log.h>

extern int enetqos_logtype_pmd;

/* PMD related logs */
#define ENETQOS_PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, enetqos_logtype_pmd, "\nqos_net: %s()" \
		fmt "\n", __func__, ##args)

#define ENETQOS_PMD_DEBUG(fmt, args...) \
	ENETQOS_PMD_LOG(DEBUG, fmt, ## args)
#define ENETQOS_PMD_ERR(fmt, args...) \
	ENETQOS_PMD_LOG(ERR, fmt, ## args)
#define ENETQOS_PMD_INFO(fmt, args...) \
	ENETQOS_PMD_LOG(INFO, fmt, ## args)

#define ENETQOS_PMD_WARN(fmt, args...) \
	ENETQOS_PMD_LOG(WARNING, fmt, ## args)

#define PMD_INIT_FUNC_TRACE() ENETQOS_PMD_DEBUG(">>")

/* DP Logs, toggled out at compile time if level lower than current level */
#define ENETQOS_DP_LOG(level, fmt, args...) \
	RTE_LOG_DP(level, PMD, fmt, ## args)

#endif /* _ENETQOS_LOGS_H_ */
