/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#ifndef __LOGGING_H
#define __LOGGING_H

/* logging */
enum app_dbg_log_level {
	APP_DBG_LOG_ERROR,
	APP_DBG_LOG_WARN,
	APP_DBG_LOG_DEBUG,
	APP_DBG_LOG_INFO,
};

#define app_print(level, fmt, ...)				\
	do {							\
		if (level <= log_level) {		\
			printf("dfe_app: %s: ", __func__);	\
			printf(fmt, ##__VA_ARGS__);		\
		}						\
	} while (0)

#define app_print_err(fmt, ...)					\
	app_print(APP_DBG_LOG_ERROR, fmt, ##__VA_ARGS__);
#define app_print_warn(fmt, ...)				\
	app_print(APP_DBG_LOG_WARN, fmt, ##__VA_ARGS__);
#define app_print_info(fmt, ...)				\
	app_print(APP_DBG_LOG_INFO, fmt, ##__VA_ARGS__);
#define app_print_dbg(fmt, ...)					\
	app_print(APP_DBG_LOG_DEBUG, fmt, ##__VA_ARGS__);

static inline void _hexdump(char *buf, uint32_t len)
{
	unsigned int i;

	printf("Dump @%p[%d]:", buf, len);
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("\n%08x: ", i);
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

#define hexdump(buf, len)					\
	do {							\
		if (log_level >= APP_DBG_LOG_DEBUG)		\
			_hexdump(buf, len);			\
	} while (0)


extern int log_level;

#endif
