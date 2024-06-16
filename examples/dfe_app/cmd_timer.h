/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#ifndef __CMD_TIMER_H
#define __CMD_TIMER_H

#include <time.h>

/* how long to wait for a response from LA9310 */
#define DFE_CMD_TIMEOUT_SEC		6

int create_cmd_timer(void);
void delete_cmd_timer(void);
void set_cmd_timer(uint64_t timeout_sec);
void arm_cmd_timer(void);
void disarm_cmd_timer(void);

#endif
