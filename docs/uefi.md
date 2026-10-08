# UEFI variable service

**Status (2026-10-07)** — `efivar-store-uefi` owns the UEFI variable-service mechanism formerly
in Surfacer. It is a `no_std` library with boot-time `alloc`, linked into the consumer application;
it is **not a standalone runtime DXE image**. The storage engine remains dependency-free and
allocation-free. The sole UEFI ABI dependency is `r-efi = 6.0.0`, resolved offline from gobbl's lock set.

## Lifecycle: manifest → install → EBS → runtime

1. **Manifest (consumer).** Discover and validate the selected device/partition. Supply its byte
   size and an implementation of `service::BlockBackend` (the engine's `Read`, `Write`, `Flush`
   traits with `r_efi::efi::Status` errors). Flush must durably order earlier writes. Choose a
   `Policy` function mapping vendor GUIDs to `Route::Firmware` or `Route::Store { volatile }`.
   The latter boolean grants volatile-overlay writes in that namespace. Names, project/BLI GUIDs,
   partition size, spare-file lifecycle, provisioning, logging and trail records are not library policy.
2. **Install at application start, before children (consumer publishing call).** Call
   `VariableService::install(table, backend, size, policy, report)`. Only one installation is permitted.
   The caller supplies a live initialized EFI system table and serializes boot-services use. The
   library validates the image, captures bounded firmware RT variables, allocates the runtime index,
   copies and seals position-independent readers into `EfiRuntimeServicesCode`, installs a private
   `EfiRuntimeServicesData` table at `SystemTable.RuntimeServices`, and updates table CRCs. It
   publishes `EFI_RT_PROPERTIES_TABLE`, and corrects the copied-code range's execute attribute in
   the firmware Memory Attributes Table. The report callback receives boot-time publication events;
   it is never called by the runtime readers. Installation fails before use if preparation is invalid.
3. **Boot-services operation (library).** Managed NV updates use `persist::apply`; success includes
   ordered flushes and readback. Managed volatile values stay in RAM. Forwarded get/set operations
   use the original firmware function pointers. Enumeration suppresses shadowed firmware namespaces.
   Every accepted mutation rebuilds the prepared runtime index, including forwarded firmware updates.
   BS-only values remain available before EBS but are excluded from the runtime index. Application
   helpers `get`, `set` and `delete_durable` operate on managed namespaces; the last independently
   reloads the backend after deletion to verify absence.
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

## EFVS lifecycle integration boundary

The owner's deferred-verification EFVS container is a subsequent format/backend integration,
not implemented by this behavior-preserving extraction. Today `BlockBackend` abstracts byte I/O
while `variables::Service` uses the edk2 engine; adopting EFVS also requires replacing that
boot-time store adapter, not merely pointing this parser at an EFVS partition.

Boot-time load/replay/verification/compaction belongs before preparing and publishing the runtime
index, while storage and verification primitives are available. A future EFVS configuration table
belongs alongside runtime-properties publication during installation, using runtime-owned data
and the same reverse-restore lifecycle. Freshness-anchor bump/lock belongs after successful durable
compaction and **before EBS** (or before publication when required by the platform's milestone).
It must not add storage/crypto/anchor work to the allocation-free EBS notification or runtime thunks.
The current crate does not publish a pretend EFVS table or claim an anchor was locked.

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
- Authenticated and append writes remain rejected. This component neither enrolls Secure Boot keys
  nor supplies a crypto verifier or anti-rollback service.
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
