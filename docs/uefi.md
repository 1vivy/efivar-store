# UEFI variable service

**Status (2026-10-07)** — `efivar-store-uefi` owns the UEFI variable-service mechanism formerly
in Surfacer. It is a `no_std` library with boot-time `alloc`, linked into the consumer application;
it is **not a standalone runtime DXE image**. The storage engine remains dependency-free and
allocation-free. The sole UEFI ABI dependency is `r-efi = 6.0.0`, resolved offline from gobbl's lock set.

## Lifecycle: manifest → install → EBS → runtime

1. **Manifest (consumer).** Discover and validate the partition. Supply `backend::Manifest`
   (size, initial checkpoint capacity, physical write unit, unique GPT GUID), a
   `service::BlockBackend` implementing `backend::Storage` (primary `Read`/`Write`/`Flush`
   plus independently flushed migration-journal I/O), a namespace `Policy`, a verifier and
   anchor. Journal pathname/lifecycle, project/BLI GUIDs, size, logging and trail marks are
   consumer policy. Absent journal reads are zero; create/extend happens only on journal writes.
2. **Install at application start, before any variable consumers or children.** Call
   `VariableService::install(table, backend, manifest, policy, verifier, anchor, report)`.
   Only one installation is permitted. A blank/unrecognized partition is initialized as
   EFVS; an edk2 image is imported once through the transaction below. An EFVS image loads
   its highest valid generation and replays its log under the caller's `efvs::Verifier`.
   The official caller supplies `PolicyNone` and `NoneAnchor`: no key enrollment, setup mode,
   no cryptographic authenticity or protected rollback guarantee.
   Replay checks the anchor, durably compacts the accepted state and torn/rejected tail,
   independently reads it back, then bumps/locks the anchor **before publication and EBS**.
   The library captures bounded original-firmware RT variables, prepares the runtime index,
   copies/seals the runtime readers, installs a private gRT and refreshes CRCs. It publishes
   `EFI_RT_PROPERTIES_TABLE` and a runtime-owned EFVS configuration table under
   `930e89ed-540e-4af0-9b41-c2c559939d50` (unique partition GUID, tier 0, capabilities,
   committed anchor value), and corrects copied-code execute attributes.
3. **Boot-services operation.** Every downstream consumer uses ordinary gRT
   GetVariable/GetNextVariableName/SetVariable/QueryVariableInfo, not raw image access.
   Managed NV|BS|RT updates append checked EFVS SET/APPEND/DELETE records, flush and read
   back before publication. Authorized firmware-only NV|BS variables use A/B checkpoint
   compaction, never bypass runtime log admission rules. Volatile values remain in RAM.
   Other namespaces forward to saved firmware callbacks; enumeration suppresses shadowed
   namespaces. Every successful mutation rebuilds the runtime index. BS-only variables
   are excluded from that index. `inspect()` reports generation/log usage/posture without
   handing consumers the backing bytes. There is no private application get/set shortcut.
4. **ExitBootServices (library notification).** Installation arms an EBS-group notification. It
   swaps the four variable entries to the copied runtime thunks and refreshes the private table CRC.
   The index is already prepared: no allocation, filesystem access or block I/O occurs in this
   transition. Consumers need no second commit or independent snapshot implementation.
5. **Runtime (library thunks).** AArch64 and x86-64 EFI-ABI readers access only the frozen validated
   index. GetVariable, GetNextVariableName and QueryVariableInfo work; SetVariable returns
   `EFI_UNSUPPORTED` without dereferencing its arguments. No allocator, Rust application code,
   policy callback, backend, or boot-services pointer is used by these readers. Direct OS writes to
   the persistent image do not refresh this snapshot; they become visible on the next boot.

If a child returns while boot services are still live, `restore` reverses publication and releases
owned state; dropping the owner also attempts restoration. Never restore or drop it after a
successful EBS. Retain/leak the owner across that handoff. The application must not unload itself
while its pre-EBS callbacks or EBS event remain installed.

## First-boot migration and recovery

The primary is never overwritten until the independent journal contains a complete,
flushed, byte-verified EFVS image plus a committed marker (size, image SHA-256 and marker
SHA-256). The journal has a 4096-byte marker page followed by the full image. Both initial
checkpoint slots contain the imported live state: a damaged header must not fall back to
an empty store. Import failure (including insufficient checkpoint space) leaves the
original image untouched.

The service writes/verifies the complete body, then each whole physical header block,
with a flush after every write. A committed journal resumes an interrupted conversion,
including completing the second pair after the first header was published. Before any
EFI callbacks or subsequent mutations are exposed, the marker is zeroed, flushed and
read back. Thus a retained journal body is inert and cannot later roll back an EFVS
store. A normal EFVS boot needs no full-image ESP mirror: its A/B checkpoints and append
log own recovery. A stale legacy spare is never treated as an authoritative migration
source.

Host tests interrupt every journal/primary write and flush, including partial marker
prefixes and representative body/header tears, then restart the actual service. They
also cover OS log replay on the next boot, torn-tail compaction, anchor lock and
firmware-only BS variables. These are logical storage-order tests, not proof that a
particular firmware filesystem or BlockIo flush is honest.

## OS discovery

The EFVS table describes the store to EFI consumers. An out-of-tree Linux module cannot
depend on an unknown EFI configuration table surviving kernel initialization. Consumers
such as Surfacer additionally publish `/chosen/efivar-store,partuuid` as a NUL-terminated
canonical lowercase unique GPT GUID through their DT fixup path. This is consumer
publishing policy; both the GBL Android DT and native EFI_DT_FIXUP path need it. The Linux
backend uses the kernel's efivars/efivarfs machinery; it does not modify the frozen EFI
runtime index.

## Physical runtime, not virtual relocation

`SetVirtualAddressMap` and `ConvertPointer` are **unsupported**, as in the source implementation.
The properties mask preserves unrelated firmware capability bits, enables the three read services,
and clears SetVariable, SetVirtualAddressMap and ConvertPointer. The consumer/OS must honor that
contract. This extraction does not add a virtual-address-change event or advertise conversion.

The runtime readers are copied relocatable assembly blobs, not a PE/COFF runtime driver. Their
internal references are PC-relative, but installation patches one **physical index pointer** before
sealing the code read-only. The original application is not registered as a runtime DXE image;
firmware does not relocate its Rust callbacks, globals or heap. Nobody converts the copied index
pointer or the private table to virtual addresses: this is deliberately a physical-only service.
Calling SetVirtualAddressMap despite the advertised mask is outside the supported contract.

Linux's EFI stub honors this distinction: its runtime-properties processing sets `efi_novamap`
when `EFI_RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP` is absent; the memory-map path then uses physical
runtime addresses. See Linux [`drivers/firmware/efi/libstub/efi-stub.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/firmware/efi/libstub/efi-stub.c)
and [`drivers/firmware/efi/libstub/arm64-stub.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/firmware/efi/libstub/arm64-stub.c).
This does not manufacture an EFI handoff where a bootloader provides none: gobbl's current Android
GBL path does not hand the system table to the kernel. Device proof is outside this extraction.

## Scope and limits

- Namespace routing is caller policy; a forwarded namespace is captured into the frozen runtime
  view rather than called through to firmware after EBS. Capture truncation is explicit in the index.
- Current bounds are 256 UTF-16 name units (including termination), 64 KiB values, 64 KiB volatile
  overlay, 512 runtime variables and a 2 MiB index. Firmware capture is separately bounded at 256
  variables / 512 KiB. An arbitrary backend size does not imply unlimited runtime snapshot capacity.
- Append writes are supported for persistent runtime-visible variables. Policy None rejects
  authenticated updates; caller-supplied verification/anchor interfaces are real admission
  boundaries, while production crypto/secure-storage primitives remain explicitly unsupported.
  The current once-per-boot anchor is locked at installation; later unauthenticated boot writes
  do not claim freshness, and authenticated state is reconciled at the next boot.
- The `lab` feature exposes placement/proof wiring used by consumers' boot instruments. The library
  owns the mechanism; diagnostic markers, synthetic proof variables and persistence policy remain
  consumer code.
- Host tests retain the moved routing, durability, visibility, bounds, capture and x86-64 EFI-ABI
  differential assertions. An AArch64 compile is not proof of execution on a device.

## Build

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --locked -p efivar-store-uefi --target aarch64-unknown-uefi
```

If the selected toolchain does not distribute this UEFI target, use the pinned consumer nightly
with `rust-src` and build only core/alloc:

```sh
rustup run nightly-2026-08-08 cargo build --locked -p efivar-store-uefi \
  --target aarch64-unknown-uefi -Zbuild-std=core,alloc \
  -Zbuild-std-features=compiler-builtins-mem
```
