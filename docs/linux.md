# Linux Rust efivars backend

`linux/efivar_store.rs` is an out-of-tree Rust-for-Linux module, not a filesystem or C ABI crate. It embeds the allocation-free engine directly. `StoreBackend` loads EFVS v1, replays read-only into an owned in-kernel list and never compacts: compaction belongs exclusively to firmware. Writes pass the shared structural, boot-services-only-name, attribute, policy and authentication/timestamp checks, append exactly one checked record, flush, then publish the new list entry. Log exhaustion returns EFI_OUT_OF_RESOURCES. I/O failure reloads the durable view, disabling operations if reload fails.

The shipped verifier is **PolicyNone**: authenticated attributes and secure-boot enrollment return EFI_SECURITY_VIOLATION, not successful deferred enrollment. The shared timestamp rule applies before a verifier could accept an authenticated write; no cryptographic verifier is shipped. Boot-services-only names/variables and firmware policy variables return EFI_WRITE_PROTECTED. Nonblocking SetVariable is NULL. QueryVariableInfo reports log capacity/free bytes and the checkpoint-bound maximum variable size.

Discovery accepts mutually exclusive `dev=major:minor` or `partuuid=<unique-GPT-UUID>` parameters. UUID lookup iterates live block-class partitions and matches `bd_meta_info.uuid`, never calling discarded `__init` lookup functions. Without parameters it reads the string `/chosen/efivar-store,partuuid` from the device tree. Android/GBL has no EFI system table, so esu supplies `dev`. Native binding on the EFVS EFI configuration-table GUID is the **in-tree upstreaming route**, not available to this external module: ACK's boot-only parser discards unknown GUIDs and releases the original table arrays. It requires adding the GUID to `efi_config_parse_tables`' recognized table list and retaining the decoded descriptor; scanning reclaimable firmware boot memory at module load is unsound.

Registration follows `tee_stmm_efi`: unregister generic runtime operations, register ours, restore generic operations on failure/remove. Other backends are not evicted. `Mutex<Option<State>>` owns all state; unload excludes callbacks before dropping it. Do not unload with efivarfs mounted.

Blank/unformatted partitions are refused at probe with a clear error and **no writes**. Firmware initializes blank partitions on first boot; the Linux module never formats, imports or compacts storage.

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

The final non-KMI imports and admission evidence are recorded below. CRC/System.map admission alone cannot detect the mixed-LLVM invalid-IR failure; the loader VM gate is required.

The phone has CONFIG_EFIVAR_FS unset, so kernelesp builds the matching upstream fs/efivarfs as a separate efivarfs.ko. Keep upstream source pristine plus exactly one named patch adding esu's project GUID (`7a5e4b1c-0d3f-4e62-9b8a-1c2d3e4f5a6b`) to the removable allowlist. Without it, unknown-GUID variables are immutable and the boot HAL cannot write them without CAP_LINUX_IMMUTABLE. The Rust backend is a second module, efivar_store.ko, loaded before mounting efivarfs.

## Exercised round-trip

`linux/test_qemu.py` initializes an EFVS image with `efivar-store init --efvs`, uses static busybox and matching virtio modules, and boots the ACK Image for write, reboot-read, offline firmware-equivalent CLI compaction/read, and truncated-record-tail/read. With `--loader`, both EFI modules use an executable calling production `esuinit::load_module`, not a test relocation engine. The frontend loads before the backend; both load before mounting.

```sh
python3 linux/test_qemu.py --kernel-out /path/to/gki-out \
  --backend linux/efivar_store.ko --frontend /path/to/efivarfs.ko \
  --busybox /path/to/static-arm64-busybox --cli target/debug/efivar-store \
  --loader /path/to/relocating-insmod --work /var/tmp/efvs-geometry-final
```

Observed PASS through the production loader: OS create/immediate read/update/delete, reboot reread, offline CLI `compact` followed by reread, a final CLI-created record with its last 16 bytes truncated/zeroed followed by reread of the earlier checkpoint, and blank-store refusal with host-confirmed byte-identical zero storage. Logs: `/var/tmp/efvs-geometry-final/{write,read,compact,torn,blank}.log`; retained image: `store.img`. A 16-KiB EFVS image with 512-byte blocks and two 4-KiB checkpoints also passed set/update/delete and reboot reread (`small-write.log`, `small-read.log`); probe reads bounded candidate headers rather than assuming a minimum 64-KiB partition. No physical phone commands were issued. UUID/DT discovery, QueryVariableInfo, EFI-present replacement, unload/restoration and injected I/O failure remain unproven at runtime.

Final `scripts/kmi_modules.py::verify_module` admission: **38 versioned imports, 11 kallsyms-resolved imports, no CRC mismatches**. Final `modinfo`: name `efivar_store`, GPL, no dependencies, vermagic `6.12.58-4k-g925a103d123c SMP preempt mod_unload modversions aarch64`, parameters `dev` and `partuuid`.

Exact non-KMI symbol list:

```text
_RNvNtCshBBT4i9RzFA_4core3fmt5write
_RNvNtNtCshBBT4i9RzFA_4core5slice5index22slice_index_order_fail
_RNvNtNtCshBBT4i9RzFA_4core5slice5index26slice_start_index_len_fail
_RNvNtNtCshBBT4i9RzFA_4core9panicking11panic_const24panic_const_shl_overflow
_RNvNtNtCskPkSD4WGMmy_6kernel5print14format_strings4INFO
_RNvNvMNtCshBBT4i9RzFA_4core5sliceSp15copy_from_slice17len_mismatch_fail
block_class
efivars_generic_ops_register
efivars_generic_ops_unregister
efivars_register
efivars_unregister
```
