# Consumer guide: putting a variable store under UEFI

**Status (2026-10-07)** — lifecycle rules for consumers of the storage engine and the
[`efivar-store-uefi` service library](uefi.md). The service implements publication, routing,
boot-time persistence and the frozen EBS view; the consumer still owns policy, storage selection
and installation timing. Each rule below cites its primary source.

## 1. Install the provider before the images that use it

A UEFI image receives the system table when it is loaded (`EFI_LOADED_IMAGE_PROTOCOL.SystemTable`,
UEFI 2.11 §9 Protocols — EFI Loaded Image,
<https://uefi.org/specs/UEFI/2.11/09_Protocols_EFI_Loaded_Image.html>),
and most images cache `gST`/`gRT` at entry. If you replace `SystemTable->RuntimeServices` after an
image has already been started, that image keeps calling the table it captured, and one boot ends up
with two inconsistent views of the same variables.

Rules:

- Publish your variable service **before** `LoadImage`/`StartImage` of any image that reads or writes
  variables — a bootloader, a kernel EFI stub, a provisioning app.
- Keep one owner of the runtime-services table and one variable store per boot. Restore the previous
  table in reverse order if you must remove the service.
- An image that reads variables lazily (re-reading `gRT` at each call) is unaffected by later
  installation, but nothing in the spec requires that; do not rely on it.

## 2. Volatile and non-volatile are different promises

- `EFI_VARIABLE_NON_VOLATILE` (`0x1`) variables are retained across power cycles; a variable without
  it "is not maintained across a power cycle" (UEFI 2.11 §8.2 Variable Services,
  <https://uefi.org/specs/UEFI/2.11/08_Services_Runtime_Services.html>). Volatile variables are for
  passing information between components within one boot.
- `EFI_VARIABLE_BOOTSERVICE_ACCESS` (`0x2`) makes a variable visible to boot services, and
  `EFI_VARIABLE_RUNTIME_ACCESS` (`0x4`) makes it visible to the OS after `ExitBootServices`. The OS
  only ever sees variables that carry runtime access: an NV variable without `RT` is invisible to
  efivarfs, and a `BS`-only variable is invisible at runtime.
- After `ExitBootServices` only variables that have **both** `RT` and `NV` can still be set;
  runtime-access variables that are not non-volatile become read-only (UEFI 2.11 §8.2).
- Deletion is `SetVariable` with a data size of zero, and the space of the deleted variable "may not
  be available until the next power cycle" (UEFI 2.11 §8.2) — which is exactly the append-then-reclaim
  model of this crate: a delete only marks records, and reclaim is separate offline work.
- Not every well-known variable is persistent. systemd-boot publishes the entry it booted as a
  **volatile** variable — "Always export the selected boot entry to the system in a volatile var."
  (`LoaderEntrySelected`, <https://github.com/systemd/systemd/blob/main/src/boot/boot.c>) — so an OS
  that looks for it in the NV store finds nothing, and one that writes it expects it to disappear at
  the next power cycle. `LoaderInfo` and `LoaderFeatures` are published the same way. Conversely
  `LoaderEntryOneShot` and `LoaderEntryDefault` are ordinary persistent variables; the CLI's
  `oneshot` subcommand writes the former with the `NV|BS|RT` attribute word the Boot Loader Interface
  specifies (<https://github.com/systemd/systemd/blob/main/docs/BOOT_LOADER_INTERFACE.md>).

## 3. A successful non-volatile write is already persistent

The specification defines no flush step for variables: the firmware must have saved the value to
non-volatile storage before `SetVariable` returns `EFI_SUCCESS`, and it must not perform a partial
save. If power fails mid-call, the variable holds either its previous or its new value — nothing else
(UEFI 2.11 §8.2, quoted in [durability.md](durability.md#2-what-a-crash-may-leave-behind)).

Consequences for a consumer:

- Do not add a second "commit" call, a sync, or a redundant rewrite "to be safe" — there is nothing
  to sync, and the extra write costs the append region.
- A write that returned an error tells you nothing about what the medium now holds; re-read the
  variable instead of assuming the old value.
- For a store that lives on a **block device** rather than in firmware NVRAM (this crate's case), the
  same promise is only as good as the device's flush semantics — see
  [durability.md](durability.md#4-limits--what-is-not-modelled) and Linux
  `Documentation/block/writeback_cache_control.rst`
  (<https://docs.kernel.org/block/writeback_cache_control.html>).

## 4. After `ExitBootServices`: no boot services at all

`ExitBootServices` is the point after which boot services "are no longer available"
(UEFI 2.11 §7, `EFI_BOOT_SERVICES.ExitBootServices`,
<https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html>). A post-`EBS` variable service may
therefore not:

- allocate (`AllocatePool`/`AllocatePages`/`FreePool`) or free memory;
- use handles or protocols (`HandleProtocol`, `OpenProtocol`, `SimpleFileSystem`, `BlockIo`,
  `LoadImage`/`StartImage`) — including reading the store from the disk it lives on;
- create, signal or close events or timers.

Everything the runtime path touches must be in memory that the OS keeps mapped: `RuntimeServicesData`
/ `RuntimeServicesCode`, described by the Memory Attributes Table (`EFI_MEMORY_ATTRIBUTES_TABLE`,
UEFI 2.11 §4, <https://uefi.org/specs/UEFI/2.11/04_EFI_System_Table.html>) so the OS can apply `RO`/`XP`
correctly. A practical shape, and the one this crate's tests assume:

- before `EBS`: the store is read through whatever device abstraction the consumer owns, and writes go
  through `persist::apply` (or the Unix adapter off-firmware);
- at `EBS` (notification): freeze a validated in-memory view — an index built from `Store::parse` —
  and swap the runtime entry points;
- after `EBS`: serve reads from the frozen view, refuse writes, or forward non-volatile writes to the
  firmware's own runtime service if one exists.

If you take part in `SetVirtualAddressMap`, the frozen view and the runtime code must be convertible;
if you do not, the OS must boot with physical addressing.

## 5. The Linux side

- efivarfs is a filesystem view over the firmware's variables; creating, modifying and deleting
  variables goes through `efivar_operations` to the firmware's `SetVariable`
  (<https://docs.kernel.org/filesystems/efivarfs.html>). The first four bytes of each efivarfs file
  are the attribute word in little-endian, followed by the data.
- **The kernel has exactly one variable backend.** `efivars_register()` fails with `-EBUSY`
  ("efivars already registered") if one is already registered, and the private `__efivars` pointer is
  what every efivarfs operation uses
  (<https://github.com/torvalds/linux/blob/master/drivers/firmware/efi/vars.c>). A Linux-side provider
  therefore *replaces* the backend — it does not add a second one, and it must be unregistered
  cleanly on module unload.
- efivarfs is mounted read-only when the firmware does not advertise runtime `SetVariable` support:
  `efivar_supports_writes()` is false when no backend supplies `set_variable`, and the platform
  leaves that hook unset when the `EFI_RT_PROPERTIES_TABLE` does not list `SetVariable`. That is why a
  firmware whose variable service refuses runtime writes shows up as `EROFS` in the OS.
- libefivar (and tools built on it) honours the `EFIVARFS_PATH` environment variable, which lets a
  test harness point it at a synthetic efivarfs instead of the real firmware
  (<https://github.com/rhboot/efivar/blob/main/src/efivarfs.c>).
- A file-backed store is not efivarfs: writes to it are plain block writes whose durability depends on
  flush semantics, and the OS's efivarfs view stays stale until the next boot if firmware is the only
  thing that re-reads the store. A store partition that *does* want to be efivarfs reaches it by
  registering that one backend over the partition's own bytes — the
  [SM8850 case study](case-studies/qcom-sm8850-phone.md) documents a production instance of exactly
  that, including what the firmware side must do to be consistent with it.

## 6. Using this crate as the storage engine

- Implement `persist::Read`/`Write`/`Flush` for your device (firmware: `BlockIo` with
  `FlushBlocks`; host: `persist::unix::Device`), and let `persist::apply` own the phase order. Copying
  a whole rebuilt image to the device is *not* a crash-safe transaction.
- Take your own single-writer discipline on firmware — `flock` is a host concept. edk2's recovery
  covers an interrupted single commit; it does not cover two interleaved writers.
- Keep `reclaim` (and `format`) offline or at boot, with a spare copy if you have one
  (`mirror::decide`), and never in a live update path.
- Read `capacity()`/`free_space()` and plan for append-only growth: a full store fails writes until a
  reclaim, and there is no implicit reclaim anywhere in this crate.
- Layout support is not authorization: authenticated variables can be read and preserved, but the engine
  still refuses to write one, and no signature is verified. The `auth` module
  ([format.md](format.md#9-authenticated-variables-parsing-and-policy)) parses the authentication
  descriptors, rebuilds the digest input a signature covers and applies the specification's own rules
  (time-stamp monotonicity, `APPEND_WRITE`, attribute changes), but it ships no cryptographic verifier —
  `Pkcs7Verifier` is an owner-directed stub — and its official policy, `SecureBootPolicy::None`, refuses
  every authenticated write. Verification and freshness belong to the consumer; the
  [SM8850 case study](case-studies/qcom-sm8850-phone.md) documents the deferred-verification model this
  project is moving to, where the firmware keeps the submitted payload and verifies it at boot.
