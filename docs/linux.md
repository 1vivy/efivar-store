# Linux C-glue efivars backend

`linux/efivar_store.c` is an out-of-tree C module linked with the audited,
allocation-free Rust EFVS engine through `crates/efivar-store-ffi`. It is not a
filesystem: it supplies the kernel's own efivarfs backend. No kernel Rust crate,
Rust metadata, bindgen, or `CONFIG_RUST` is required. The engine's public API and
EFVS on-disk format are unchanged.

## State and durability

C allocates the image (1 MiB for the phone profile, bounded at 16 MiB), checkpoint
scratch, and aligned opaque context. The FFI context borrows these buffers;
`efvs_ctx_size()` describes its size. The callbacks allocate nothing and share
one kernel mutex. Names cross the boundary as UTF-16LE bytes without a terminator,
and GUIDs as 16 EFI wire-order bytes. Borrowed get/next views remain valid only
until the next set or load; C consumes them while holding the mutex.

`efvs_load` replays read-only under **PolicyNone**, including filtering imported
checkpoint variables. `efvs_set` validates and appends exactly one record to the
memory image/state, returning its changed byte range. While still holding the
mutex, C performs `kernel_write`, `vfs_fsync`, then chunked readback verification
of exactly that range. Only then can another reader observe the new state. I/O
failure rereads the durable image and replays it; failed reload disables all
callbacks. Linux never formats, imports or compacts. Firmware alone initializes
blank partitions and compacts exhausted or torn logs.

Blank/unusable storage is refused with:

```text
efivar_store: no usable EFVS store; firmware must initialize blank partitions (no bytes written)
```

Probe reads bounded header candidates at zero and powers of two from 512 to
65536, so recovery works with a torn A header and smaller-than-phone geometry.
No probe failure writes any storage bytes.

EFI status behavior is retained: exhaustion is EFI_OUT_OF_RESOURCES;
boot-services-only variables/names and firmware policy variables are
EFI_WRITE_PROTECTED; authenticated attributes and Secure Boot enrollment are
EFI_SECURITY_VIOLATION. No cryptographic verifier is shipped. Nonblocking
SetVariable and query-store are NULL. QueryVariableInfo accepts attributes 7 and
reports log capacity/free bytes and the checkpoint-bound maximum variable size.

## Discovery and registration

Accept mutually exclusive `dev=major:minor` or `partuuid=<unique-GPT-UUID>`.
Without parameters, read `/chosen/efivar-store,partuuid` from DT. UUID lookup
iterates live `block_class` partitions and matches `bd_meta_info.uuid`
case-insensitively, after checking canonical 36-character UUID syntax. It never
calls discarded boot-only lookup functions. Open with
`bdev_file_open_by_dev(dev, BLK_OPEN_READ | BLK_OPEN_WRITE, NULL, NULL)`.

Registration follows `tee_stmm_efi`: unregister generic runtime operations,
register ours, restore generic operations on registration failure or removal.
Other registered backends are not evicted. Unregister excludes callbacks before
freeing buffers. Do not unload with efivarfs mounted.

Android/GBL has no EFI system table, so esu supplies `dev`. Native discovery via
the EFVS EFI configuration-table GUID remains the **in-tree upstreaming route**:
ACK's boot-only parser discards unknown GUIDs and releases the table arrays. It
would need a recognized GUID entry in `efi_config_parse_tables` and retained
decoded descriptor, not scanning reclaimable boot memory from an external LKM.

## Freestanding build

A fully built matching ACK output is required: generated C headers,
Module.symvers, and System.map. `modules_prepare` alone is insufficient.

```sh
make -C linux KMI_SRC=/path/to/phone-common KMI_OUT=/path/to/gki-out \
  LLVM=/usr/bin/
```

The Makefile works both through its outer target and direct ACK kbuild (including
kernelesp's pinned-source builder). It builds the staticlib offline with pinned
`nightly-2026-08-08`, `-Z build-std=core,compiler_builtins`, and installed `rust-src`;
no downloaded softfloat target is needed. Override `CARGO` and `RUST_TOOLCHAIN`
only with an equivalently supported toolchain. The target is
`aarch64-unknown-none-softfloat`, forbidding FP/NEON. Rust code generation uses
static relocations, one codegen unit, no embedded LLVM bitcode, and no forced
unwind tables. Kbuild links the C object and a garbage-collected `ld -r
--whole-archive` Rust object into one `efivar_store.ko`, retaining only the FFI
roots and their dependencies.

**Panic strategy:** the freestanding build deliberately uses
`-Z unstable-options -C panic=immediate-abort`. Ordinary `panic=abort` still
retains core formatting code through bounds-check/assertion message construction,
even when the panic handler ignores its argument. Immediate abort removes that
reachable formatting machinery. The crate has its own tiny panic handler calling
a nonreturning C hook, but compiler-generated panics under this strategy fault
immediately instead. An invariant failure is a kernel oops; the phone crash
capture profile (`androidboot.init_fatal_panic=true` plus `oops=panic`) turns it
into a panic and readable KCONSOLE dump. Host tests use the normal host panic
strategy. No reachable Debug derivations or formatting operations are introduced
by the FFI. The final tested module contains **zero core::fmt symbols**.

C compilation and native object linking used **LLVM 23.1.1 at `/usr/bin/`**.
ACK was built with Android clang 19.0.1, so its compiler-difference warning is
expected. Do not use Android LLVM 19 to consume the Rust object's bitcode:
previous mixed-minor LLVM linking produced invalid IR despite a successful link.
This build supplies native Rust object code, not kernel Rust metadata/IR.

Generic kernels with suitable exports can use insmod/modprobe. Trimmed Android
GKI protects or omits some C exports, so kernelesp's production relocating loader
resolves undefined symbols against kallsyms before invoking init_module. It does
not itself apply AArch64 relocations: ACK's `arch/arm64/kernel/module.c` does.
Successful CRC/System.map admission alone is not a runtime proof.

The phone has efivarfs disabled in its kernel. Kernelesp ships matching upstream
`fs/efivarfs` as `efivarfs.ko`, with its named patch adding project GUID
`7a5e4b1c-0d3f-4e62-9b8a-1c2d3e4f5a6b` to the removable allowlist. Load the backend
before mounting it; unknown GUIDs otherwise need CAP_LINUX_IMMUTABLE for deletion.

## Compatibility evidence (2026-10-08)

The old Rust-for-Linux implementation failed the real phone relocating loader
because its core/kernel crate hashes differed from the phone's exports and
`core::fmt::Formatter::pad` was absent altogether. The C-glue cutover fixes the
ABI cause, rather than renaming imports to guessed crate hashes.

Saved evidence, relative to `/home/vivy/Projects/efisp-projects`:

- Failure: `gobbl-lab/records/20261008T055846Z-phone-efvs-lkm-test/efvs.json`.
- Phone symbols: `gobbl-lab/records/20261008T055912Z-phone-efvs-kallsyms/evidence/01-kallsyms.stdout`.
- ACK source: `.work/thinpool-proof/.work/phone-common`, android16-6.12,
  `925a103d123c30a84577f29e1573376aacbde94b`, KMI generation 6.
- Kernel output: `.work/thinpool-proof/.work/gki-out`.

`readelf -Ws` and `llvm-nm --undefined-only` show no undefined `_RN` symbol.
Every undefined symbol exists in the saved phone kallsyms: **missing set empty**.
The Rust object has no unwind section and disassembly of the final module shows
no FP/NEON instructions. KMI admission reports **24 versioned entries** (including
module_layout) and **five kallsyms-resolved imports**, with no CRC mismatch:

```text
block_class
efivars_generic_ops_register
efivars_generic_ops_unregister
efivars_register
efivars_unregister
```

The receipt was generated using the unmodified kernelesp verifier's
`verify_module`, `kmi_identity`, and `provenance` functions, then admitted by:

```sh
python3 /path/to/kernelesp/scripts/kmi_modules.py verify \
  --kmi-out /path/to/gki-out --module linux/efivar_store.ko
```

The existing kernelesp tracked SOURCE_REVISION pins the earlier implementation,
and EFIVAR_STORE_REPO only changes the clone origin, not that revision. The
packaged make flow therefore cannot select this branch without a pin update;
no kernelesp tracked files were changed here.

## Exercised round-trip

```sh
cargo test --locked --offline
cargo clippy --all-targets --locked --offline -- -D warnings
python3 linux/test_qemu.py --kernel-out /path/to/gki-out \
  --backend linux/efivar_store.ko --frontend /path/to/efivarfs.ko \
  --busybox /path/to/static-arm64-busybox --cli target/debug/efivar-store \
  --loader /path/to/relocating-insmod --work /var/tmp/efvs-c-glue-accepted
```

All **76 existing tests plus three new FFI ABI tests** pass. FFI tests exercise
changed-range preservation, create/update/append/delete/replay/iteration, policy
precedence, query sizing, exhaustion without writes, torn-tail recovery and
blank refusal. Clippy with warnings denied passes.

`linux/test_qemu.py` uses the production `esuinit::load_module` executable, not a
test relocation engine. Final observed output:

```text
PASS: immediate read, update, delete, reboot, firmware compaction, torn-tail reread and blank refusal without writes
```

Logs are `/var/tmp/efvs-c-glue-accepted/{write,read,compact,torn,blank}.log`.
The blank image is host-confirmed byte-identical to its initial 1 MiB of zeroes.
UUID/DT discovery, EFI-present generic-backend replacement and physical-device
power cuts were not exercised. **No device commands were issued.**
