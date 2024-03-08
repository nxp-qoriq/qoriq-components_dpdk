/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/queue.h>
#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdbool.h>
#include <ftw.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>

#include "logging.h"
#include "cmd_timer.h"

timer_t cmd_timer;

void cmd_timer_thread(union sigval si);

int create_cmd_timer(void)
{
	struct sigevent se = {0};
	int ret;

	se.sigev_notify = SIGEV_THREAD;
	se.sigev_value.sival_ptr = &cmd_timer;
	se.sigev_notify_function = cmd_timer_thread;
	se.sigev_notify_attributes = NULL;

	ret = timer_create(CLOCK_REALTIME, &se, &cmd_timer);
	if (ret < 0) {
		app_print_err("Error creating cmd timer\n");
		return ret;
	}

	return 0;
}

void delete_cmd_timer(void)
{
	timer_delete(cmd_timer);
}

void set_cmd_timer(uint64_t timeout_sec)
{
	struct itimerspec ts = {0};
	int ret;

	ts.it_value.tv_sec = timeout_sec;
	ts.it_value.tv_nsec = 0;
	/* One shot timer */
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;

	ret = timer_settime(cmd_timer, 0, &ts, 0);
	if (ret < 0)
		app_print_err("Error setting cmd timer\n");

	app_print_dbg("timer set to %ldsec\n", timeout_sec);
}

void arm_cmd_timer(void)
{
	set_cmd_timer(DFE_CMD_TIMEOUT_SEC);
}

void disarm_cmd_timer(void)
{
	set_cmd_timer(0);
}

void cmd_timer_thread(__attribute__((unused)) union sigval si)
{
	/* If we got here, modem card is unresponsive. */
	app_print_err("modem card hang detected!\n");

	/* TODO: implement recovery here */
}
