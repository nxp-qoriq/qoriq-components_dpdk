# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019-2024 NXP

# binary name
APP = geul_ipc_testapp

# all source are stored in SRCS-y
SRCS-y := main.c

ifeq ($(COMMON_HEADERS_DIR),)
$(error "Please define COMMON_HEADERS_DIR environment variable \
        to include Geul common header files")
endif

# Build using pkg-config variables if possible
$(shell pkg-config --exists libdpdk)
ifeq ($(.SHELLSTATUS),0)

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PC_FILE := $(shell pkg-config --path libdpdk)
CFLAGS += -O3 $(shell pkg-config --cflags libdpdk)
LDFLAGS_SHARED = $(shell pkg-config --libs libdpdk)
LDFLAGS_STATIC = -Wl,-Bstatic $(shell pkg-config --static --libs libdpdk)

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	rmdir --ignore-fail-on-non-empty build

else

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += -I$(SRCDIR)
CFLAGS += -O3
CFLAGS += -DHOST=1 -DMODEM=0 #-DABERDEEN=1 -DINVS_SIM=1
CFLAGS += $(WERROR_FLAGS)
LDFLAGS += -lrte_pmd_geul_ipc_rawdev

include $(RTE_SDK)/mk/rte.extapp.mk

endif
