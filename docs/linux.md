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

## Device I/O credentials

The first real-phone ROM1 boot with SELinux enforcing exposed a failure absent
from the permissive recovery test: a boot-control HAL callback inherited
`hal_bootctl_default` credentials, while the module's backing file had been
opened with the kernel SID. SELinux denied `fd:use` during device I/O. The write
failed, then reload failed for the same reason and correctly disabled callbacks,
making later efivarfs reads return EIO. The physical log remained untouched.

The backend brackets each `kernel_read`, `kernel_write`, `vfs_fsync` and final
`fput` with `override_creds(store_file->f_cred)` / `revert_creds`. The file's
opener credentials are retained by the file and the override API; no private
credential symbols, provider ABI, `symbol_get` or product/root-runtime dependency
is involved. Pure in-memory get/next/query/replay need no credential override.
Initial backing-file open uses the module loader's credentials. Load during
rdinit before policy, then permit that opener domain access to the backing block
device through module-owned policy. UID 0 is not a SELinux authorization.

Kernel read/write short counts, fsync errors, verification mismatches and reload
failures retain their logged operation/result and disable callbacks on failed
reload. There is no fallback to caller credentials.

The backend discovers the native boot-lifetime EFI object through exported
sysfs/kobject APIs, or creates its own `efi` object under `firmware_kobj`. It creates `efivars` only when absent,
records mountpoint ownership, and removes only the mountpoint it created. A
native EFI tree is never removed. Mount filesystem type `efivarfs` at
`/sys/firmware/efi/efivars`; directory presence alone is not readiness. The
read-only `ready` parameter becomes true only after validated store load and
successful callback registration. Unmount efivarfs before unload.

The QEMU gate has **no SELinux policy** and cannot prove that an enforcing
Android HAL no longer triggers `fd:use` denial. An enforcing real-phone boot
and boot-control write are the acceptance proof for that security-context fix.
The VM still checks registration, durability and failure/refusal behavior.

## Discovery and registration

Accept mutually exclusive `dev=major:minor` or `partuuid=<unique-GPT-UUID>`.
Without parameters, read `/chosen/efivar-store,partuuid` from DT. Mount sysfs at
`/sys` before loading the module when using either UUID discovery path. Lookup
reads canonical `/sys/class/block/<name>/uevent` entries, matching the exact
36-character PARTUUID case-insensitively and validating decimal MAJOR/MINOR.
It requires one match: missing UUID is `ENODEV`, ambiguity is `EEXIST`, malformed
fields are `EINVAL`; I/O errors propagate. No udev by-partuuid link, `block_class`
private import, boot-only lookup, or root helper is required. Each uevent is read
after readdir releases its locks, using its opener credentials. Open with
`bdev_file_open_by_dev(dev, BLK_OPEN_READ | BLK_OPEN_WRITE, THIS_MODULE, NULL)`
to hold an exclusive block-device claim for the callback lifetime. Competing
claimants are refused; the existing final `fput` releases the claim after
callback removal. This also identifies the live backing as an owned consumer
to partition-protection code, rather than an unclaimed raw partition.
Recheck the opened partition's UUID before loading bytes, rejecting hotplug
device-number reuse. Explicit `dev=major:minor` remains independent of sysfs
UUID enumeration.

Registration follows `tee_stmm_efi`: unregister generic runtime operations,
register ours, restore generic operations on registration failure or removal.
Other registered backends are not evicted. Unregister excludes callbacks before
freeing buffers. Do not unload with efivarfs mounted.

Android/GBL has no EFI system table, so boot configuration supplies an explicit
UUID or device selector. Native discovery via the EFVS EFI configuration-table
GUID remains the **in-tree upstreaming route**:
ACK's boot-only parser discards unknown GUIDs and releases the table arrays. It
would need a recognized GUID entry in `efi_config_parse_tables` and retained
decoded descriptor, not scanning reclaimable boot memory from an external LKM.

## Host build

The root `rust-toolchain.toml` selects `stable` for the host crates: the storage
engine, the UEFI service, the FFI crate and the CLI. `.cargo/config.toml` sets
`target-dir`, so Cargo writes host output to the ignored `out/cargo/` directory.
`CARGO_TARGET_DIR` overrides it.

```sh
cargo build --locked
cargo build --locked --release -p efivar-store-cli
```

The UEFI crate is a `no_std` library. The host build also compiles it, and no
separate toolchain is needed for it.

## Freestanding build

A fully built matching ACK output is required: generated C headers,
Module.symvers, and System.map. `modules_prepare` alone is insufficient.

```sh
make -C linux KMI_SRC=/path/to/phone-common KMI_OUT=/path/to/gki-out \
  ARCH=arm64 LLVM=/usr/bin/
```

The outer Makefile writes the module and generated files to `out/linux`.
`EFVS_OUTPUT_DIR` selects another module output directory.
It passes that directory to Kbuild as `MO`, so no build product goes into the
source tree. `EFVS_ROOT` names the repository root of the source. A consumer
sets `EFVS_ROOT` and includes `$(EFVS_ROOT)/linux/Kbuild` from its own Kbuild.
The consumer supplies `MO` and `EFVS_CARGO_TARGET_DIR`. It must not copy the
rules or the C glue.

Kbuild compiles the engine archive into `out/linux-cargo`, separate from host
Cargo output. `EFVS_CARGO_TARGET_DIR` selects another directory. The archive
path is
`$(EFVS_CARGO_TARGET_DIR)/<Rust target>/release/libefivar_store_ffi.a`, where
`<Rust target>` is `aarch64-unknown-none-softfloat` or `efvs-x86_64`.

To build the engine archive alone, run the same Cargo command without Kbuild:

```sh
CARGO_TARGET_DIR=out/linux-cargo \
RUSTFLAGS="-Z unstable-options -C relocation-model=static -C panic=immediate-abort -C force-unwind-tables=no -C embed-bitcode=no" \
  cargo +nightly-2026-08-08 build --locked --offline -Zjson-target-spec \
  -Z build-std=core,compiler_builtins --release \
  --target aarch64-unknown-none-softfloat -p efivar-store-ffi --no-default-features
```

The result is `out/linux-cargo/aarch64-unknown-none-softfloat/release/libefivar_store_ffi.a`.
This archive build needs no kernel source. For an x86 kernel, first generate the
JSON target with `linux/rust-target.py`, then pass its path to `--target`.

Two toolchains stay separate. The root `rust-toolchain.toml` keeps `stable` for
host and firmware crates. Only the Linux build selects `nightly-2026-08-08`, and
it also needs the `rust-src` component. The `kernel-ffi` CI job explicitly selects
this nightly with `cargo +nightly-2026-08-08`, because installing it as rustup's
default does not override the root's stable toolchain file.

The Makefile works both through its outer target and direct ACK kbuild (including
the egysk pinned-source builder). It builds the staticlib offline with pinned
`nightly-2026-08-08`, `-Z build-std=core,compiler_builtins`, and installed `rust-src`;
no downloaded softfloat target is needed. Override `CARGO`, `EFVS_RUSTC` and
`RUST_TOOLCHAIN` only with an equivalently supported toolchain. Cargo explicitly
uses `EFVS_RUSTC` rather than an unrelated kernel-exported `RUSTC` found on PATH.
`ARCH=arm64` selects `aarch64-unknown-none-softfloat`, forbidding FP/NEON.
`ARCH=x86` or `ARCH=x86_64` derives `efvs-x86_64.json` from the pinned compiler's
`x86_64-unknown-none` softfloat target and actual kernel
`include/config/auto.conf`, not from the host.
`make -C linux KDIR=/lib/modules/$(uname -r)/build` supports standalone/DKMS
packaging with a configured kernel output. Unless explicitly overridden, `LLVM`
follows that kernel's `CONFIG_CC_IS_CLANG`: Clang for a Clang kernel, GCC
otherwise. Ordinary modpost errors remain fatal; DKMS installs no relocating
loader.

The DKMS entry quotes its leading `'make'` so DKMS does not inject
`KERNELRELEASE` into the outer wrapper. Only the recursive kernel build sets
that variable; setting it on the wrapper selects Kbuild without its `src`
context. `BUILT_MODULE_LOCATION` names `out/linux`, the directory that the outer
Makefile passes as `MO`. `KMI_SRC=${kernel_source_dir}` selects the requested kernel rather
than the running host. `AUTOINSTALL=no` excludes this package from DKMS autoinstall.

Rust code generation uses static relocations, one codegen unit, no embedded LLVM bitcode, and no forced
unwind tables. Kbuild links the C object and a garbage-collected `ld -r
--whole-archive` Rust object into one `efivar_store.ko`, retaining only the FFI
roots and their dependencies.
The freestanding invocation explicitly disables shared generic instantiations
(`-Zshare-generics=n`) and LTO, and rebuilds core/compiler-builtins with one
codegen unit and v0 symbol mangling. Cargo's workspace `profile.release.lto=true`
is overridden only for this kernel build; host and firmware profiles remain
unchanged. Custom target builds retain Cargo's required `-Zjson-target-spec`.

`linux/rustc-wrapper.py` selects `linux/compiler-builtins.rs` as the designated
compiler-runtime crate. It changes only that crate's source operand: every
sanitizer, metadata, target and codegen argument remains identical to the other
freestanding crates. The descriptor defines no functions. LLVM-lowered helper
calls therefore resolve to genuine kernel implementations, never panicking or
no-op substitutes. Kbuild garbage-collects unused core code before ordinary
module import/CRC admission; any required helper absent from the target kernel
fails admission. Nothing ignores unresolved symbols or exempts runtime imports
from that check. The previous accepted ARM ELF required only memory runtime
helpers (`bcmp`, `memcmp`, `memcpy`, `memmove`, `memset`); the configured x86
kernel exports all five with genuine version CRCs. Newly produced ELF imports
and objtool diagnostics, not this historic inventory, determine acceptance.
The kernel likewise supplies its own designated compiler runtime, but this
descriptor intentionally does not copy the kernel's panicking arithmetic stubs.

The generated x86 target follows the kernel's `scripts/generate_rust_target.rs`:
external retpoline thunks plus indirect-call/branch retpolines when configured,
SLS indirect-jump/return hardening when configured, kernel code model, no red
zone and no user-space stack probes. Kbuild separately follows `arch/x86/Makefile`
for external return thunks, IBT landing pads with jump tables disabled, and
configured call padding. Enabled frame-pointer and CFI/normalized-integer settings
are honored even without CONFIG_RUST; the freestanding engine must obey the
kernel's codegen/security ABI. The pinned Rust 1.99 nightly supports these
unstable codegen switches. Changing target configuration or flags rebuilds all
engine/core/compiler-builtins objects; no mitigation is disabled globally.

The x86 target also sets `plt-by-default=true`. The bare-metal base defaults to
no PLT and made LLVM-lowered memory calls emit `R_X86_64_GOTPCREL`, even with
static relocation and kernel code model. ACK rejects that userspace-GOT form
at module load. Direct PLT32 calls retain the configured mitigations and resolve
to the kernel's genuine helpers. Product admission checks relocation types in
allocated sections as well as symbols/CRCs; debug-only relocations are not loaded.

An objtool mitigation/IBT warning is a failed build/admission, even if make returns
zero. The product KMI builder preserves the full `.build.log`, rejects objtool
diagnostics, and does not emit an admitted receipt. The Android generalized gate
may explicitly permit modpost warnings only before validating every real
System.map/CRC import. Ordinary standalone/DKMS builds leave undefined-symbol
errors fatal. Native EFI and UUID discovery use exported APIs rather than
`efi_kobj`/`block_class` globals. The exercised targets are recorded below; other
kernel configurations still require their own build and load proof.

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

ACK C compilation and native-object linking use Android LLVM 19.0.1; the tested
native kernels use their configured Clang 23.1.1 or GCC 16.2.1 family. The ACK ARM
output and supplied compiler have different Android build IDs of the same
r536225 revision; that warning remains visible. Rust supplies native object code,
not LLVM bitcode or kernel Rust metadata: do not pass mixed-version bitcode
between Rust and the kernel linker.

Generic kernels with suitable exports can use insmod/modprobe. Trimmed Android
GKI protects or omits some C exports, so the egysk `lkm-loader` production
relocating loader resolves undefined symbols against kallsyms before invoking
init_module. It does not itself apply AArch64 relocations: ACK's
`arch/arm64/kernel/module.c` does.
Successful CRC/System.map admission alone is not a runtime proof.

The phone has efivarfs disabled in its kernel. The independent LKM product ships
`fs/efivarfs` as `efivarfs.ko`, with its named patch adding project GUID
`7a5e4b1c-0d3f-4e62-9b8a-1c2d3e4f5a6b` to the removable allowlist. Load the backend
before mounting it; unknown GUIDs otherwise need CAP_LINUX_IMMUTABLE for deletion.

## Exercised build targets (2026-10-09)

The final C-glue backend was built and admitted against ACK
`android16-6.12`, generation 6, on both architectures:

| Architecture | CRC-versioned imports | Admitted private imports |
| --- | ---: | ---: |
| aarch64 | 46 | 8 |
| x86_64 | 56 | 0 |

ARM private imports are `efivars_generic_ops_register`,
`efivars_generic_ops_unregister`, `efivars_register`, `efivars_unregister`,
`filp_open`, `kobject_get_unless_zero`, `sysfs_create_mount_point` and
`sysfs_remove_mount_point`. The actual target's System.map/CRC checks admit them;
this list is not an exception to artifact admission.

Standalone builds against `7.2.8-2-cachyos` (Clang) and
`6.18.52-1-cachyos-lts` (GCC) passed with `ARCH=x86`, native compiler selection,
fatal modpost and no objtool diagnostics. These are build results, not claims of
loading either module into the workstation kernel.

An actual DKMS 3.4.3 `add`/`build` for `6.18.52-1-cachyos-lts`, `ARCH=x86_64`,
also passed through the quoted wrapper, produced the matching vermagic and signed
`efivar_store.ko` with an ephemeral test certificate. Source, DKMS state, module
output, temporary files and signing material stayed in isolated unprivileged
trees. No system install, key enrollment or host module load was performed.

The original x86 artifact passed CRC admission but failed its first Cuttlefish
load with `Unknown rela relocation: 9`. After the target correction, ELF
inspection found zero GOTPCREL references (previously 23), and the stricter
admission gate rejected the old artifact while accepting the corrected module.

## Exercised round-trip

```sh
cargo test --workspace --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
python3 -m unittest discover -s linux -p 'test_rust*.py'
python3 linux/test_qemu.py --kernel-out /path/to/gki-out \
  --backend /path/to/arm64/efivar_store.ko --frontend /path/to/efivarfs.ko \
  --busybox /path/to/static-arm64-busybox --cli out/cargo/debug/efivar-store \
  --loader /path/to/lkm-loader \
  --partuuid f5a3bc0f-4dea-56c6-aeed-cb638157a125 \
  --work /var/tmp/efvs-uuid-proof
```

The explicit UUID above names a **new disposable GPT fixture**, not a physical
device or product default. `--partuuid` requires `sfdisk`, wraps the initialized
EFVS image in a real GPT partition, and boots it through the kernel partition
parser. Omit it to exercise the explicit `dev=major:minor` path.

For x86_64 use `--arch x86_64` and matching x86 inputs. The test kernel needs
SysRq support: the guest syncs and requests reboot through `/proc/sysrq-trigger`;
QEMU's `-no-reboot` exits the VM. This does not require a BusyBox poweroff applet.
Guest output goes through `/dev/kmsg` and the configured early console. A timeout
or nonzero QEMU exit fails the gate even if an earlier phase marker was printed.

The shipped loader and final ARM backend passed seven VM phases: missing UUID,
duplicate UUID, write/update/delete, reboot/read, firmware compaction, torn-tail
reread, and blank refusal. Missing and duplicate selectors returned ENODEV and
EEXIST respectively. Host comparisons confirmed no writes to rejected disks and
no writes outside the selected GPT partition. Logs:
`/var/tmp/efvs-final-uuid-proof-20261009/{missing,duplicate,write,read,compact,torn,blank}.log`.

The corrected x86_64 backend and production loader also passed all seven phases
against the stock Cuttlefish kernel, including byte-for-byte rejected-disk and
partition-boundary comparisons. Evidence:
`/var/tmp/efvs-x64-final-proof-20261009/{missing,duplicate,write,read,compact,torn,blank}.log`.

The host suite covers FFI changed-range preservation, create/update/append/
delete/replay/iteration, policy precedence, query sizing, exhaustion without
writes, torn-tail recovery and blank refusal.

The VM has no SELinux policy. It does not prove enforcing HAL-domain access,
DT selection, native EFI backend replacement, or physical-device power-cut
behavior. Enforcing Android credential and boot-control acceptance remain
separate gates. No physical-device commands were issued for these checks.

