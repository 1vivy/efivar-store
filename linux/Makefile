# SPDX-License-Identifier: GPL-2.0-only
CARGO ?= $(HOME)/.cargo/bin/cargo
RUST_TOOLCHAIN ?= nightly-2026-08-08
RUST_TARGET := aarch64-unknown-none-softfloat
RUST_FLAGS := -Z unstable-options -C relocation-model=static -C panic=immediate-abort -C force-unwind-tables=no -C embed-bitcode=no
ifneq ($(KERNELRELEASE),)
obj-m := efivar_store.o
efivar_store-objs := efivar_store_glue.o efvs_engine.o
$(obj)/efivar_store_glue.o: $(src)/efivar_store.c FORCE
	$(call if_changed_dep,cc_o_c)
# Cargo tracks source dependencies; this also works when the caller invokes
# ACK kbuild directly (as kernelesp's pinned-source receipt builder does).
$(src)/../target/$(RUST_TARGET)/release/libefivar_store_ffi.a: FORCE
	cd "$(src)/.." && RUSTFLAGS="$(RUST_FLAGS)" $(CARGO) +$(RUST_TOOLCHAIN) build --locked --offline -Z build-std=core,compiler_builtins --release --target $(RUST_TARGET) -p efivar-store-ffi --no-default-features
quiet_cmd_efvs = LD      $@
      cmd_efvs = $(LD) -r --gc-sections $(addprefix -u ,efvs_ctx_size efvs_scratch_size efvs_load efvs_get efvs_next efvs_set efvs_query) --whole-archive $< --no-whole-archive -o $@
$(obj)/efvs_engine.o: $(src)/../target/$(RUST_TARGET)/release/libefivar_store_ffi.a FORCE
	$(call if_changed,efvs)
targets += efvs_engine.o efivar_store_glue.o
else
KMI_SRC ?=
KMI_OUT ?=
JOBS ?= 4
LLVM ?= /usr/bin/
.PHONY: all clean
all:
	@test -n "$(KMI_SRC)" && test -n "$(KMI_OUT)"
	$(MAKE) -C "$(KMI_SRC)" O="$(KMI_OUT)" M="$(CURDIR)" ARCH=arm64 LLVM="$(LLVM)" KBUILD_GENDWARFKSYMS_STABLE=1 KBUILD_MODPOST_WARN=1 -j$(JOBS) modules
clean:
	@test -n "$(KMI_SRC)" && test -n "$(KMI_OUT)"
	$(MAKE) -C "$(KMI_SRC)" O="$(KMI_OUT)" M="$(CURDIR)" clean
endif
