# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019-2024 NXP

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

include $(RTE_SDK)/mk/rte.vars.mk

ifneq ($(CONFIG_RTE_EXEC_ENV),"linuxapp")
$(error This application can only operate in a linuxapp environment, \
please change the definition of the RTE_TARGET environment variable)
endif

ifeq ($(COMMON_HEADERS_DIR),)
$(error "Please define COMMON_HEADERS_DIR environment variable \
	to include Geul common header files")
endif
#
# library name
#
LIB = librte_pmd_geul_ipc_rawdev.a

GEUL_DIR=$(RTE_SDK)/drivers/raw/geul_ipc_rawdev/

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(GEUL_DIR)/
CFLAGS += -I$(COMMON_HEADERS_DIR)/
CFLAGS += -DDEBUG
CFLAGS += -DHOST=1 -DMODEM=0 #-DABERDEEN=1
LDLIBS += -lrte_eal
LDLIBS += -lrte_rawdev
LDLIBS += -lrte_bus_vdev
LDLIBS += -lrte_kvargs
LDLIBS += -lrte_mempool

EXPORT_MAP := rte_pmd_geul_ipc_rawdev_version.map

LIBABIVER := 1

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_PMD_GEUL_IPC_RAWDEV) += geul_ipc_dev.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_GEUL_IPC_RAWDEV) += geul_ipc_api.c

SYMLINK-$(CONFIG_RTE_LIBRTE_PMD_GEUL_IPC_RAWDEV)-include += rte_pmd_geul_ipc_rawdev.h

# create symbolic links for geul common headers required by application
COMMON_HDRS := $(shell find $(COMMON_HEADERS_DIR) -name '*.h')
SYMLINK-$(CONFIG_RTE_LIBRTE_PMD_GEUL_IPC_RAWDEV)-include += $(COMMON_HDRS)

include $(RTE_SDK)/mk/rte.lib.mk
