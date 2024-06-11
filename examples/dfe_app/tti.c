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

#include "dfe_host_if.h"
#include "dfe_app.h"
#include "logging.h"
#include "cmd_timer.h"
#include "ipc.h"
#include "tti.h"

struct epoll_event ev, events[MAX_EVENTS];
struct tti tti_t;
ssize_t bytes_read;
struct timeval tv;
uint64_t eftd_ctr;
int epollfd, epollstopfd[2], epollstoppipe, nfds;
int ret = 0;
static int is_inited = 0;

int tti_init(void)
{
	app_print_dbg("%s: TTI init, core %u\n", __func__, rte_lcore_id());

	/* Register Modem & TTI */
	tti_t.tti_eventfd = -1;
	ret = modem_tti_register(&tti_t, 0, 1 /* wait event flag */);
	if (ret < 0) {
		printf("%s failed...\n", __func__);
		goto _error;
	}

	if ((epollstoppipe = pipe(epollstopfd)) < 0)
		goto _error;

	epollfd = epoll_create1(0);
	if (epollfd < 0) {
		printf("epoll create failed !\n");
		goto _bailout;
	}

	ev.events = EPOLLIN;
	ev.data.fd = tti_t.tti_eventfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, tti_t.tti_eventfd, &ev) == -1) {
		printf("Failed to create tti_eventfd\n");
		close(epollfd);
		goto _bailout;
	}

	ev.events = EPOLLIN;
	ev.data.fd = epollstopfd[0];
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, epollstopfd[0], &ev) == -1) {
		printf("Failed to create eventstopfd\n");
		close(epollfd);
		goto _bailout;
	}

	is_inited = 1;
	return 0;

_bailout:
	modem_tti_deregister(&tti_t);
_error:
	return -1;
}

int tti_wait(void)
{
	int n;

	if (!is_inited)
		return -1;

	nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
	for (n = 0; n < nfds; n++) {
		if (events[n].data.fd == epollstopfd[0])
		{
			uint32_t buf[2];
			if (read(epollstopfd[0], buf, sizeof(uint64_t)) == sizeof(uint64_t)) {
				ev.events = EPOLLIN;
				ev.data.fd = tti_t.tti_eventfd;
				if (epoll_ctl(epollfd, EPOLL_CTL_DEL, tti_t.tti_eventfd, &ev) == -1)
					printf("Failed to delete tti_eventfd\n");

				return 0;
			}
		}
		else  {
			bytes_read = read(tti_t.tti_eventfd, &eftd_ctr, sizeof(uint64_t));
			if (bytes_read != sizeof(uint64_t)) {
				printf("Error in reset counter : %ld\n", bytes_read);
			}
			return 0;
		}
	}

	return -1;
}

int signal_close(void)
{
	uint32_t buf[2];

	/* stop epoll_wait */
	return write(epollstopfd[1], buf, sizeof(uint64_t));
}

int tti_close(void)
{
	if (!is_inited)
		return -1;

	is_inited = 0;

	/* stop epoll_wait */
	signal_close();

	close(epollfd);
	epollfd = -1;
	close(epollstopfd[0]);
	close(epollstopfd[1]);

	sleep(1);

	/* Deregister TTI */
	modem_tti_deregister(&tti_t);

	return 0;
}
