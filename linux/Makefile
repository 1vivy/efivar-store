# SPDX-License-Identifier: GPL-2.0-only
ifneq ($(KERNELRELEASE),)
obj-m := efivar_store.o
else
KMI_SRC ?=
KMI_OUT ?=
JOBS ?= 4
LLVM ?= 1
.PHONY: all clean
all:
	@test -n "$(KMI_SRC)" && test -n "$(KMI_OUT)"
	$(MAKE) -C "$(KMI_SRC)" O="$(KMI_OUT)" M="$(CURDIR)" ARCH=arm64 LLVM="$(LLVM)" KBUILD_GENDWARFKSYMS_STABLE=1 KBUILD_MODPOST_WARN=1 -j$(JOBS) modules
clean:
	@test -n "$(KMI_SRC)" && test -n "$(KMI_OUT)"
	$(MAKE) -C "$(KMI_SRC)" O="$(KMI_OUT)" M="$(CURDIR)" clean
endif
