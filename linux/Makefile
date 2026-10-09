# SPDX-License-Identifier: GPL-2.0-only
ifneq ($(KERNELRELEASE),)
include $(src)/Kbuild
else
KDIR ?= /lib/modules/$(shell uname -r)/build
KMI_SRC ?= $(KDIR)
KMI_OUT ?=
ARCH ?= $(shell uname -m)
ifeq ($(ARCH),aarch64)
override ARCH := arm64
endif
JOBS ?= 4
KERNEL_CONFIG := $(if $(KMI_OUT),$(KMI_OUT),$(KMI_SRC))/include/config/auto.conf
LLVM ?= $(if $(findstring CONFIG_CC_IS_CLANG=y,$(file <$(KERNEL_CONFIG))),1,)
.PHONY: all clean
all:
	$(MAKE) -C "$(KMI_SRC)" $(if $(KMI_OUT),O="$(KMI_OUT)") M="$(CURDIR)" ARCH="$(ARCH)" LLVM="$(LLVM)" KBUILD_GENDWARFKSYMS_STABLE=1 -j$(JOBS) modules
clean:
	$(MAKE) -C "$(KMI_SRC)" $(if $(KMI_OUT),O="$(KMI_OUT)") M="$(CURDIR)" clean
endif
