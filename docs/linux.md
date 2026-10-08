# Linux Rust efivars backend

`linux/efivar_store.rs` is an out-of-tree Rust-for-Linux module, not a filesystem or C ABI crate. It includes the allocation-free engine directly from `crates/efivar-store/src/lib.rs`. An internal `StoreBackend` boundary owns load/list/get/query/set; the current implementation persists edk2 changes with `persist::apply` and serves an owned in-kernel list. The EFVS format and firmware-table discovery are not implemented by this module; select the backing device explicitly with `dev=major:minor`.

The module replaces only generic firmware runtime operations, using the `tee_stmm_efi` unregister/register/restore pattern. Another registered backend causes registration to fail rather than being evicted. Unload restores generic runtime operations. Do not unload while efivarfs is mounted. Firmware runtime reads may represent Surfacer's frozen post-ExitBootServices view; Linux's live writes are served by this backend. Nonblocking SetVariable is NULL; boot-services-only writes return EFI_WRITE_PROTECTED. EFI attributes zero or empty data delete a variable. Crypto/authenticated updates are not implemented here.

## Feasibility evidence

Paths below are relative to `/home/vivy/Projects/efisp-projects` unless stated otherwise. No phone commands were issued for this work.

| Fact | Observed value | Evidence |
| --- | --- | --- |
| Phone kernel | 6.12.58-android16-6-g925a103d123c-ab15898589-4k | `gobbl-lab/records/20261006T040000Z-phone-recovery-reads/evidence/02-uname--a.stdout` |
| Matching ACK source | android16-6.12, 925a103d123c30a84577f29e1573376aacbde94b, KMI generation 6 | `.work/thinpool-proof/.work/phone-common` |
| Captured configuration | CONFIG_RUST=y; CONFIG_ANDROID_BINDER_IPC_RUST=m; CONFIG_EFI=y; CONFIG_EFIVAR_FS unset; CONFIG_MODVERSIONS=y | `.work/thinpool-proof/.work/phone-live.config` (saved capture, not the lab's config.gz-presence listing) |
| Phone Rust compiler | rustc 1.82.0-dev f6e511eec, Android linux-15123656 | same saved configuration, CONFIG_RUSTC_VERSION_TEXT |
| Phone bindgen | 0.69.5 | same saved configuration, CONFIG_BINDGEN_VERSION_TEXT |
| Tested build output | Rust=y, Binder Rust=m, EFI=y, EFIVAR_FS unset, MODVERSIONS=y, TRIM_UNUSED_KSYMS=y | `.work/thinpool-proof/.work/gki-out/.config` |
| Tested Rust metadata | libkernel/libcore/libbindings/libuapi/libffi/libcompiler_builtins/libbuild_error .rmeta, libmacros.so, generated bindings present | `gki-out/rust/` |
| Tested metadata compiler | upstream rustc 1.82.0, LLVM 19.1.1 | gki-out configuration; installed rustup 1.82.0 compiler |
| Exact Android compiler available | 1.82.0.p1, linux-15123656 | `.work/thinpool-proof/.work/cf-super/prebuilts/rust/linux-x86/1.82.0.p1/bin/rustc` |
| AOSP manifest | GBL mainline, not the phone ACK kernel; its Rust prebuilts are newer | `gobbl-aosp/.repo/manifests/default.xml` |
| Host bindgen | 0.73.2; exact 0.69.5 not located | installed bindgen; external build consumes existing generated bindings |
| Module code generation that passed QEMU | upstream rustc 1.82.0 plus LLVM 23.1.1 tools | explicit RUSTC and LLVM arguments below |

**Important toolchain finding:** Android clang/llvm-link 19.0.1 from clang-r536225 produced a linkable but invalid module when consuming upstream rustc's LLVM 19.1.1 bitcode. Prelink IR retained correct pointers; linked IR introduced `ptr undef`, and QEMU crashed in module initialization. LLVM 23.1.1 linking/code generation passed the runtime test. Do not treat a successful .ko link as proof that mixed LLVM minor releases are compatible. The exact Android compiler/output combination has not been runtime-tested.

## Build and loading

Supply a fully built matching kernel output, including Rust metadata, generated bindings, Module.symvers and System.map. `modules_prepare` alone does not supply these artifacts. Bindgen regeneration is unnecessary for this external module.

```sh
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTC_BOOTSTRAP=1
make -C linux KMI_SRC=/path/to/phone-common KMI_OUT=/path/to/gki-out \
  RUSTC="$HOME/.rustup/toolchains/1.82.0-x86_64-unknown-linux-gnu/bin/rustc" \
  LLVM=/usr/bin/
modinfo linux/efivar_store.ko
```

The tested vermagic is `6.12.58-4k-g925a103d123c SMP preempt mod_unload modversions aarch64`. This is the scratch rebuilt ACK release, not the captured production phone's complete release string.

Generic kernels with appropriate exported symbols can use ordinary insmod/modprobe. This Android GKI output trims some exports and protects others: ordinary insmod failed with protected-symbol errors (-13) for kernel_read/kernel_write and Rust support functions, and unknown-symbol errors (-2) for trimmed helpers. Exact console evidence: `/var/tmp/efivar-rust-qemu-target/write.log`. Android integration therefore uses kernelesp's existing relocating loader, not plain insmod. This is not a generally KMI-export-only module.

The LLVM-23-built module's trimmed imports reported by modpost are efivars_register, efivars_unregister, efivars_generic_ops_register/unregister, Rust kernel INFO format strings, and Rust core formatting/slice failure helpers. They are required registration or Rust runtime functions and are resolved by the existing esu loader against live kallsyms. An earlier LLVM-19 artifact passed kernelesp's CRC/System.map admission check, but was invalid at runtime; rerun admission for the final artifact before packaging.

The phone has CONFIG_EFIVAR_FS unset, so kernelesp builds the matching upstream fs/efivarfs as a separate efivarfs.ko. Keep upstream source pristine plus exactly one named patch adding esu's project GUID (`7a5e4b1c-0d3f-4e62-9b8a-1c2d3e4f5a6b`) to the removable allowlist. Without it, unknown-GUID variables are immutable and the boot HAL cannot write them without CAP_LINUX_IMMUTABLE. The Rust backend is a second module, efivar_store.ko, loaded before mounting efivarfs.

## Exercised round-trip

`linux/test_qemu.py` creates a file-backed CLI-formatted image, uses static busybox and matching virtio modules, and boots the ACK Image twice. With `--loader`, both EFI modules are loaded by a standalone executable calling the production `esuinit::load_module` implementation; there is no test-only relocation engine.

```sh
python3 linux/test_qemu.py --kernel-out /path/to/gki-out \
  --backend linux/efivar_store.ko --frontend /path/to/efivarfs.ko \
  --busybox /path/to/static-arm64-busybox --cli target/debug/efivar-store \
  --loader /path/to/relocating-insmod --work /var/tmp/efivar-rust-qemu-roundtrip
```

Observed PASS: load both modules, mount efivarfs read-write, create/read/update a project-GUID variable, create/delete another, power down, boot a second VM on the same image, read the updated value and verify the deleted variable is absent. Logs: `/var/tmp/efivar-rust-qemu-roundtrip/{write,read}.log`; image: `store.img`. This exercises list/get/set/delete and ordered persistence through the actual kernel frontend and esu loader. QueryVariableInfo, backend replacement on EFI-present boots, unloading/restoration, fault-injection durability and physical phone behavior remain unproven.
