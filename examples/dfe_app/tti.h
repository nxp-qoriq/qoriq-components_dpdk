/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright 2024 NXP
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <string.h>
#include <sched.h>
#include <la9310_tti_ioctl.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <fcntl.h>

#include "dfe_app.h"

#define	APP_SCHED_PRIORITY   99
#define MAX_EVENTS           2

int tti_init(void);
int tti_wait(void);
int signal_close(void);
int tti_close(void);
