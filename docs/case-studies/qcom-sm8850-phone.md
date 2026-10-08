# Case study: runtime variables on a production Qualcomm phone (OnePlus 15, SM8850)

**Status (2026-10-07)** — what the lab and the source say about the UEFI variable posture of the
Qualcomm SM8850 phone this project runs on (OnePlus 15, `infiniti`, OOS 16 / Android 16), why the
operating system has no writable variables, and how a block-backed store on an appended GPT
partition is presented to both firmware and kernel as *the* variable service.

Everything below is either quoted from a source in the workspace, taken from a lab record, or marked
`[INFERENCE]` where it is reasoning over those facts. Sections 1–6 describe the UEFI-runtime mechanism as
this repo's consumption path; section 7 describes the OS-side path; section 8 lists what each layer
actually guarantees; section 9 is the residual risk and open-fact list, including the forward pointer to
the deferred-verification store that replaces the on-disk format.

The names in play, so the rest reads unambiguously:

| Name | What it is | Where it lives |
| --- | --- | --- |
| `uefivarstore` | Qualcomm firmware's own variable store, `sde93` | OEM GPT, LU 0 |
| `bdsvars` | this project's store: appended 1 MiB GPT partition, edk2 NV image | LU 0, entry 16 |
| `VariableDxe` | Qualcomm DXE driver producing `gEfiVariableServicesProtocolGuid` | firmware |
| `uefisecapp` | TrustZone app `qcom.tz.uefisecapp`, the SCM-backed variable owner | TZ, `uefisecapp_a`/`_b` |
| efisp / Surfacer | our UEFI payload; owns the runtime-variable hijack | ESP / critical |
| `kernelesp` | our kernel modules; `efivarfs.ko` registers the block-backed backend | Android kernel |
| EFVS | planned successor format: checkpoint + hash-chained log, verification at boot | not shipped |

## 1. Platform posture as found

**The firmware's variable services are real, storage-backed and boot-services-only.** The device census
shows `gEfiVariableServicesProtocolGuid` (F9085B9D) with one handle, and "only `VariableDxe.inf`
produces it, not `EmuVariableRuntimeDxe`" (`gobbl-lab/legacy/docs-history/goal-1-bringup.md:172`). The
shipping producer is not byte-for-byte the reference BSP driver: the census does not show
`gEdkiiVariablePolicyProtocol` (81D1675C), which the BSP's `VariableDxe.inf` also produces
(`legacy/docs-history/open-qualifiers.md:205`). The reference BSP FDF that ships `SocPkg` for
Bonito/Eliza/Pakala "would have told you the opposite — it enables Emu and comments out VariableDxe
under `--PRESIL--`. **Census beats BSP.**" (`goal-1-bringup.md:172`).

**Every runtime entry point refuses service after `ExitBootServices`.** Qualcomm's `Variable.c` gates its
four variable entry points on `EfiAtRuntime()` and returns `EFI_UNSUPPORTED`
(`legacy/docs-history/research-gaps.md:52`, citing `Variable.c:231-236`, `:334-339`, `:464-469`,
`:570-575`, from `BOOT.MXF.2.5.3-00131-KAANAPALI`). Two consequences are load-bearing:

- Boot-services-time writes are **not** refused, which is why every pre-`EBS` component in this stack
  (BDS, GBL, our own images, systemd-boot) can use variables normally.
- At runtime the store is unreachable through the firmware, on all four operations.

**Measured on the phone, before any of our runtime code is published**
(`gobbl-lab/records/20260929T204501Z-phone-loop`, read-only probe; `docs/device-results.md:142`):

```
rt_properties absent
query_variable_info nv_bs_rt status=0x0 maximum=64512 remaining=63980 largest=63960
get_variable address=0xbeaf3940 type=5 runtime=true
get_next_variable_name address=0xbeaf3a80 type=5 runtime=true
set_variable address=0xbeaf3b70 type=5 runtime=true
query_variable_info address=0xbeaf3cc0 type=5 runtime=true
variables count=34
```

(`evidence/iteration-01/logfs/gbl-bds-rtvars.txt`.) So: no `EFI_RT_PROPERTIES_TABLE`, four entry points
that are advertised as runtime-capable, a 63 KiB NV `BS|RT` budget, and 34 variable names enumerable
before `EBS`. The runtime entry points existing is exactly what makes the naive path look viable — and
exactly what returns `EFI_UNSUPPORTED` later.

**The storage behind those variables is TrustZone-owned.** The store is a UFS GPT soft partition that the
TrustZone app writes; the non-secure side reaches it through a GPT listener
(`GPTListener.c`, listener `0x2001`) whose buffer is freed at `EBS`
(`gobbl/docs/storage/variables.md:137-146`). Writing variables at boot-services time therefore has a
side effect the lab refuses to take casually: `gRT->SetVariable` is "a durable change to a TZ-backed
varstore partition", failures are lossily re-encoded (`ScmCmdVar.c:107-108`) so "a refusal cannot be
distinguished from a bad argument", and `RuntimeFlushVariableNV` calls
`ScmCmdSyncVarTables(TABLE_ID_RESERVED)` — "all tables are synced" — so a durability test would "commit
every other pending variable in every table as a side effect" (`legacy/docs-history/device-probe-plan.md:231`).
A pre-`EBS` reset silently loses the write: it sets `VariableSyncEnabled = FALSE`
(`device-probe-plan.md:250`, citing `Variable.c:640-649`). `[INFERENCE]` The same flush ordering is why
the OEM store cannot be treated as a durable scratchpad from an outside writer.

**A partially nulled service table is a legitimate firmware state.** On the `Fail` path `VariableDxe`
NULLs all four runtime variable services, so a probe must guard on `gRT != NULL && gRT->GetVariable != NULL`
and treat absence as an outcome, not a crash (`device-probe-plan.md:201`).

**The TrustZone variable path exists but is not available to this phone from mainline Linux.** Mainline
has a client driver, `drivers/firmware/qcom/qcom_qseecom_uefisecapp.c` (865 lines, upstream by Maximilian
Luz, 2023): it forwards the four variable operations over SCM to the TEE app. It registers a **single**
`efivar_operations` instance:

```c
static const struct efivar_operations qcom_efivar_ops = {
	.get_variable = qcuefi_get_variable,
	.set_variable = qcuefi_set_variable,
	.get_next_variable = qcuefi_get_next_variable,
	.query_variable_info = qcuefi_query_variable_info,
};
...
	status = efivars_register(&qcuefi->efivars, &qcom_efivar_ops);
```

(`qcom_qseecom_uefisecapp.c:794-799`, `:831`; the TEE sub-commands are `0x8000|{0,1,2,3}` at `:30-34`,
the app is `qcom.tz.uefisecapp` at `qcom_qseecom.c:86-88`.) Two gates stand in the way on a phone:

- The SCM transport refuses to create the `qseecom` platform device unless the DT machine compatible is
  in a static allowlist: "We do not yet support re-entrant calls via the qseecom interface. To prevent
  any potential issues with this, only allow validated machines for now"
  (`drivers/firmware/qcom/qcom_scm.c:2285-2288`, list at `:2289-2323`). `oneplus,infiniti` is not in
  the upstream list; the lab probe carries a one-line local patch adding it
  (`linux-on-sm8850/uefisecapp-probe/0001-allowlist-oneplus-infiniti.patch`, applied at `qcom_scm.c:2312`).
- Even patched, the lab could not get a mainline kernel booted through GBL's fastboot path to exercise
  it: two `fastboot boot` runs of a mainline kernel (allowlist-patched) went to the `05c6:900e` crash
  dump ~17 s after the upload, with the minidump shadows all zero
  (`records/20260930T024939Z-phone-chainboot`, `records/20260930T025220Z-phone-chainboot`,
  `docs/device-results.md:151`). Packaging an EFI-stub kernel as an Android boot image "contradicts the
  native-Linux design and is not pursued".

`[INFERENCE]` The TrustZone path is the *right* long-term owner of the OEM store (it is how Arm laptops
work), but on this phone it needs either an allowlisted machine compatible — a policy decision, not a
technical one — or the HLOS path the OEM uses, at which point our store is still the one the OS tools
must reach. That is the gap sections 3–7 fill.

## 2. Why the OS has no variables

Three independent walls, in the order an OS meets them:

1. **No EFI handoff at all on the Android boot path.** "Android is entered by GBL's raw arm64 jump
   rather than the EFI stub, so its kernel has no EFI boot context and cannot use efivarfs to reach our
   state" (`gobbl/docs/storage/variables.md:18-20`). `sys.boot_completed=1` arrives with no
   `/sys/firmware/efi`. A stock Android kernel therefore has no variable filesystem, no matter what
   firmware does — and the lab's own EFI-stub probes never reached a kernel at all
   (`docs/device-results.md:150`: three runs rejected at GBL's Android boot-image boundary with
   `AvbSlotVerifyError(InvalidMetadata)` and finally `AvbIoError(Io)`).
2. **If an OS does boot through EFI, the firmware's runtime services refuse.** The four entry points
   return `EFI_UNSUPPORTED` after `EBS` (section 1), so "mainline's generic efivars backend
   self-disables" (`docs/storage/variables.md:137-139`). The lab's own survey states the Linux-side
   rule: "Linux registers its generic efivars backend only when `EFI_RT_PROPERTIES_TABLE` advertises
   GetVariable/GetNextVariableName, and enables writes only with SetVariable"
   (`surfacer/app/src/lab/runtime_survey.rs:1-10`).
3. **The one backend the kernel has is a single slot.** `efivars_register()` fails with `-EBUSY`
   ("efivars already registered") if a backend is registered
   (`drivers/firmware/efi/vars.c:68-74`), and the driver must have a full implementation of all four
   operations to be useful. A file- or partition-backed store cannot be added next to a firmware
   backend; it can only replace it.

`[INFERENCE]` On the measured device the absence of an `EFI_RT_PROPERTIES_TABLE` means an EFI-booted
mainline kernel assumes every runtime service is supported and registers the generic backend and its
`set_variable`; the writes then fail at the firmware boundary rather than at mount time. Our own service
publishes the opposite advertisement (section 5), which is the honest one.

## 3. The store: an appended GPT partition, not the ESP, not the OEM store

`bdsvars` is "an appended GPT partition on LU0, 1 MiB, carrying an edk2/OVMF-format variable-store
image; its partition type GUID is `4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709`. It is initialized by
`provision bdsvars` and is not part of the LVM pool. OEM `uefivarstore` (`sde93`) is the firmware's own
store and is **not** our state store" (`gobbl/docs/storage/variables.md:12-16`; measured mapping
`docs/storage/layout.md:36`, `records/20260929T065938Z-phone-baseline/evidence/12-by-name-list.stdout:142-144`:
`uefivarstore -> /dev/block/sde93`, `uefisecapp_a -> sde17`, `uefisecapp_b -> sde61`).

Why a GPT partition rather than a file on the ESP, in the lab's own words: "This is what
`OVMF_VARS.fd` is. Advantages over a file in FAT: no FAT driver on the write path, fewer torn-write
states, offline-editable over MSD with existing tooling (`virt-fw-vars`, UEFITool), and available in the
critical tier when the ESP is absent or reformatted" (`legacy/docs-history/gpt-esp-varstore-investigation.md:154-162`).
The store is found "via GPT `BlockIo` by name because `LoadedImage->DeviceHandle` is NULL"
(`gpt-esp-varstore-investigation.md:176-178`) — the same reason the kernel-side module is handed a
`major:minor` instead of scanning GPT itself.

The on-disk format is the one this repository implements: `EFI_FIRMWARE_VOLUME_HEADER` →
`VARIABLE_STORE_HEADER` → `VARIABLE_HEADER` records with edk2's state byte, append-then-reclaim
(`docs/format.md`; `gpt-esp-varstore-investigation.md:154-162`). Provisioning appends the entry after
`userdata`, 1 MiB aligned, as entry 16 with the private type GUID
(`gobbl/crates/provision-core/src/gpt.rs:42-54`, `:1076-1111`), and the same layout was reproduced
end-to-end on a 4Kn loop replica and read back offline
(`records/20261004T034826Z-provision-replica`, `records/20261007T175802Z-provision-replica`).

## 4. The hijack: install over `gRT` before any child image runs

`EBS` is the ownership wall — "Surfacer owns everything below it and nothing above it"
(`legacy/docs-history/gpt-esp-varstore-investigation.md:93-94`). The design intervenes on the *UEFI side
of that wall*, in the following order.

**a. Read the store.** The store image is read and validated (`Store::parse`) through the consumer's own
block access before any variable call is served.

**b. Publish a private runtime-services table and point the system table at it.** When managed storage
is discovered, "composition installs a private RuntimeServices table
(`surfacer/app/src/variables.rs`, logic in `surfacer/core/src/variables.rs`) and leaves the firmware's
table untouched; restore runs in reverse cleanup, and a restore failure cold-resets"
(`docs/storage/variables.md:104-108`). The mechanism is a pointer swap with CRC maintenance, not a new
configuration table:

```rust
system.runtime_services = private_runtime.as_ptr();
if let Err(error) = refresh_header_crc(...) {
    system.runtime_services = original_runtime.as_ptr();
    ...
```

(`surfacer/app/src/variables/mechanism.rs:377-386`; restore at `:516-519`.) The four entry points are
also assigned in place on the private table (`surfacer/app/src/variables.rs:164-168`). The table is
allocated as `EfiRuntimeServicesData` so the OS keeps it mapped; the callbacks themselves are copied
into `EfiRuntimeServicesCode` (`variables/mechanism.rs:1-9`).

**c. Install before any image that caches `gRT`.** "Install once, before launching children; restore
only while boot services are live. The index is physical-address-only: SetVirtualAddressMap is not
supported. Direct-partition OS writes leave the already-frozen runtime view stale until reboot"
(`surfacer/app/src/variables.rs:1-5`). This is the rule `docs/consumer-guide.md` §1 states from the
spec side: an image that already captured `gST`/`gRT` keeps calling the table it captured.

**d. Split by attribute, and forward everything not owned.** NV variables in the BLI and project vendor
namespaces persist to `bdsvars` "edk2 phase order, flush per phase, whole store read back"; a failed
commit reloads the image before the next call, `Full` maps to `EFI_OUT_OF_RESOURCES` and I/O to
`EFI_DEVICE_ERROR`, and live writes never reclaim. Volatile BLI information variables (`BS|RT` without
`NV`) live in a bounded RAM overlay and are never forced persistent — they vanish at power loss by
design. Authenticated and `APPEND_WRITE` requests return `EFI_UNSUPPORTED`. Other vendor GUIDs "forward
to the firmware unchanged", `GetNextVariableName` lists the managed view and then firmware variables
outside the managed GUIDs, and `QueryVariableInfo` reports the managed capacity per attribute class
(`docs/storage/variables.md:109-121`). The forward-and-filter shape is the shim's original design:
"overwrite `GetVariable`/`SetVariable`/`GetNextVariableName`/`QueryVariableInfo` in the live table,
recompute `Hdr.CRC32`, intercept **only** the systemd loader namespace
`4a67b082-0a4c-41cf-b6c7-5b8a4b9a1a4f`, pass everything else through (Qualcomm DXE consumers, GBL's
`gbl_fw_api_level`)" (`gpt-esp-varstore-investigation.md:113-119`). GBL's own consumption of a vendor
runtime variable is real and must keep working (`docs/platform/gbl-protocols.md:71`).

`[INFERENCE]` The `EFI_UNSUPPORTED` for authenticated and `APPEND_WRITE` requests is exactly the refusal
this repository's engine already implements for the authenticated attribute bits (`0x10`/`0x20`/`0x80`)
and for `APPEND_WRITE`; the `auth` module added alongside this document is the parsing and policy half
of lifting that restriction later (section 9).

**e. At `EBS`, freeze the view and swap entry points.** "Every successful pre-EBS write rebuilds a
bounded immutable index in `RUNTIME_SERVICES_DATA` … The EBS notification only swaps entry points to
position-independent aarch64/x86_64 code: after EBS `GetVariable`/`GetNextVariableName`/
`QueryVariableInfo` serve that frozen view and `SetVariable` returns `EFI_UNSUPPORTED`"
(`docs/storage/variables.md:123-127`; the swap itself is
`runtime.set_variable = context.set_variable; ... runtime.query_variable_info = context.query_variable_info;`
at `surfacer/app/src/variables/mechanism.rs:580-583`). The original design said the same thing before it
was code: "At EBS: snapshot owned variables into `EfiRuntimeServicesData`; keep the read side
runtime-resident … owned-namespace `SetVariable` after EBS returns `EFI_UNSUPPORTED` because no storage
exists post-EBS" (`gpt-esp-varstore-investigation.md:121-128`).

**f. Advertise honestly in `EFI_RT_PROPERTIES_TABLE`.** The table is published through
`gBS->InstallConfigurationTable` under GUID `eb66918a-7eef-402a-842e-931d21c38ae9`
(`surfacer/app/src/variables/properties.rs:3-8`, `:71-78`) with the word
`(supported | 0x2030) & !0x01c0`, where `supported` starts at `0x3fff` and is replaced by the firmware's
own table when one exists. That sets `GetVariable`/`GetNextVariableName`/`ConvertPointer` and clears
`SetVariable`, `QueryVariableInfo` and `GetNextHighMonotonicCount`. The design prose states the intent
as "advertises no SetVariable, SetVirtualAddressMap or ConvertPointer, so Linux mounts efivarfs read-only
and the EFI stub takes the physical (`efi_novamap`) path" (`docs/storage/variables.md:127-129`).

> **Discrepancy, open.** The expression above clears `SetVariable` (0x40), `QueryVariableInfo` (0x80) and
> `GetNextHighMonotonicCount` (0x100), and in the measured no-firmware-table case leaves
> `SetVirtualAddressMap` (0x1000) and `ConvertPointer` (0x2000) set — the opposite of the prose for
> those two bits, and it also un-advertises `QueryVariableInfo` while the same document says that
> operation serves the frozen view. Either the published word or the prose is wrong; this case study
> records both rather than choosing. `[INFERENCE]` a host-side re-check of one phone boot's table would
> settle it in one reading.

**g. The frozen view is a snapshot, and that is visible to userspace.** "The runtime view is a
boot-time snapshot: a later direct write is **stale** in efivarfs until the next boot"
(`docs/storage/variables.md:131-133`). The same sentence is in the module doc: "Direct-partition OS
writes leave the already-frozen runtime view stale until reboot" (`surfacer/app/src/variables.rs:1-5`).

### 4.1 What the phone actually proved, and what it did not

The mechanism was driven on hardware over one evening; the record ids matter because the failures are
as informative as the pass:

| When | What | Result | Record |
| --- | --- | --- | --- |
| 2026-09-29T20:45Z | read-only runtime-variable survey | PASS: no RT-properties table, four entry points type 5/runtime, 34 names, NV budget 64512/63980/63960 | `20260929T204501Z-phone-loop` |
| 2026-09-29T21:17Z | runtime-variable override, mutating the firmware's table | FAIL into `05c6:900e` after GBL `handoff-saved`; mutation of Qualcomm's original table the leading, unproven cause | `20260929T211744Z-phone-loop` |
| 2026-09-29T21:41–21:44Z | EBS callback trace, with and without a BootServices interposer | all four variable pointers and the runtime-table CRC were written successfully; the fault was after the callback | `20260929T214114Z-phone-loop`, `20260929T214408Z-phone-loop` |
| 2026-09-29T21:47Z | private `EfiRuntimeServicesData` table, patched only from the EBS event | PASS: Android reached `sys.boot_completed=1` on slot `_b`; the firmware handoff accepts a replacement table | `20260929T214718Z-phone-loop` |
| 2026-09-29T22:02Z | identity virtual map | FAIL into `05c6:900e` inside Qualcomm `SetVirtualAddressMap`; explicitly "not efivarfs proof" | `20260929T220236Z-phone-loop` |
| 2026-09-29T22:09–22:15Z | runtime-code permissions | post-EBS call stopped at trace stage 11 in three variants; the copied `EfiRuntimeServicesCode` allocation was not executable while writable | `20260929T220919Z-…`, `20260929T221149Z-…`, `20260929T221442Z-…` |
| 2026-09-29T22:17Z | physical runtime-variable proof | PASS after `SetMemoryAttributes(..., EFI_MEMORY_RO)`: post-EBS `GetNextVariableName` enumerated `SurfacerEbsProbe`, `GetVariable` returned attributes `0x6` and `EBSRTOK\0`, `RTVAR-OK` reached `/proc/bootloader_log`, Android booted | `20260929T221712Z-phone-loop` |
| 2026-09-29T22:41Z – 2026-09-30T01:41Z | EFI-stub efivarfs probe via GBL | INCONCLUSIVE: never reached kernel entry (`AvbSlotVerifyError(InvalidMetadata)` twice, then `AvbIoError(Io)`); no efivarfs mount ran | `…phone-efivarfs-probe`, `…phone-efivarfs-final` |
| 2026-09-30T02:49–03:01Z | TrustZone `uefisecapp` probe via `fastboot boot` | STOPPED by owner: two runs ended in `05c6:900e`, minidump shadows zero | `20260930T024939Z-phone-chainboot`, `20260930T025220Z-phone-chainboot` |

So: the **read** side of a runtime variable service is proven on the phone, under a private table, with
the page made read-only executable. The **write** side through firmware was not proven, and no efivarfs
mount has ever run on the phone from firmware-provided variables. The lab's device-results table states
the same boundary in one line: the pass "proves the physical-runtime/EFI-stub `efi_novamap` firmware
path, not an efivarfs mount in stock Android, whose raw-Image path receives no EFI handoff"
(`gobbl-lab/docs/device-results.md:149`).

## 5. What the UEFI layer guarantees, precisely

- **Identity**: reads of the managed namespaces return the store's records; every other vendor GUID is
  the firmware's own, forwarded unchanged.
- **Boot-service writes**: NV writes in the managed namespaces are durable through the same ordered
  edk2 commit the crate implements, with a flush boundary per phase and a whole-image readback; a full
  store fails the write instead of reclaiming live.
- **Volatility**: `BS|RT`-without-`NV` variables live in RAM and are gone after power loss — by
  specification, not by accident (`docs/consumer-guide.md` §2).
- **Post-`EBS` reads**: served from an immutable snapshot built before `EBS`, from
  `EfiRuntimeServicesData`, callable from `EfiRuntimeServicesCode`.
- **Post-`EBS` writes**: refused (`EFI_UNSUPPORTED`). There is no runtime storage path, and the
  advertisement says so.
- **Isolation**: the firmware's original table is left intact; restore happens in reverse cleanup, and a
  failed restore cold-resets rather than continuing with two inconsistent views.

## 6. The Linux side: the same bytes, through the kernel's own efivarfs

The kernel has one variable backend, so the OS-side answer is not "a second variable service" but "the
backend the kernel already has, over our partition". Two implementations exist in this workspace and
they agree on the mechanism:

- **`kernelesp/modules/efivarfs`** — the bundled ACK `efivarfs` sources (android16-6.12, KMI generation
  6, `PROVENANCE.md:1-6`) plus a 310-line C engine `bdsvars.c`: "Block-backed edk2 authenticated
  variable store. No runtime firmware calls." (`bdsvars.c:1-2`).
- **The Rust kernel module** being built in this repository's sibling worktree, which registers the same
  operation set through Rust-for-Linux.

The C engine is worth reading as the reference for what "as intended" means here:

- The engine is handed a resolved `major:minor` (`module_param(dev, …)`, "required bdsvars block device
  major:minor", `bdsvars.c:16-20`); partition discovery is the init's job (`bdsvars` by PARTNAME,
  `userspace/esuinit/src/init.rs:221-235`). The kernel side never scans GPT, which keeps it under the
  vendor-module constraints.
- It validates the image exactly as this crate does — `_FVH`, `gEfiSystemNvDataFvGuid`, the declared
  length, the authenticated store GUID, `0x5a`/`0xfe` (`bdsvars.c:73-100`) — and serves `get_variable`,
  `get_next_variable`, `set_variable` and `query_variable_info` from one RAM image under a mutex
  (`bdsvars.c:139-177`, `:258-270`), installing them with
  `efivars_register(&esu_efivars, &esu_ops)` (`bdsvars.c:287`). The filesystem is upstream `efivarfs`
  (`super.c`, `inode.c`, `file.c`, `vars.c`), driven through the kernel's exported
  `efivar_get_next_variable`/`efivar_set_variable_locked` (`vars.c:402-404`, `:660-661`).
- Writes follow the same edk2 FTW order as `persist::apply`: retire the predecessor with `0xfe`, write
  the header with its state byte erased, `0x7f`, payload, `0x3f`, retire the predecessor with `0xfd`,
  then verify the whole image (`bdsvars.c:239-252`), with a per-phase `fsync` and read-back compare
  (`bdsvars.c:178-200`). New writes must carry exactly `NV|BS|RT` (`attr != 7` is refused) and a live
  record with authenticated or append bits refuses the write (`bdsvars.c:220-223`).
- The store is a plain partition the OS may write: the engine has no `EBS` event, no
  `SetVirtualAddressMap`, no memory-type change, and its teardown is module exit plus `kvfree`
  (`bdsvars.c:295-310`). `[INFERENCE]` That is precisely why the *firmware's* frozen view is stale
  after an OS write, and why the firmware must re-read the partition at boot (the EFVS design) or be
  re-entered through `SetVariable` before `EBS`.

One deviation from verbatim upstream is deliberate and load-bearing: `vars.c` adds
`{ ESU_PROJECT_GUID, "*", NULL }` to the removable-variable table (`PROVENANCE.md:16-21`,
`vars.c:184-185`, `esu-guid.h:5`), without which upstream `inode.c:33` marks the files and they are
immutable. A second, documented consequence is left unpatched: "Stock `super.c` gates statfs on EFI
runtime-service support, so its statfs capacity reporting may remain zero on a non-EFI Android kernel
even though the backend's query operation reports the actual store geometry" (`PROVENANCE.md:130-133`).

**Proven so far, on the phone**: the block-backed backend loads from userspace and efivarfs serves the
real partition. `espinitd insmod efivarfs.ko dev=259:93` resolved 22 non-KMI imports, dmesg logged
`efivars: Registered efivars operations`, there was no `/sys/firmware/efi` on that boot so no competing
backend, and `mount -t efivarfs -o ro` listed exactly the two live records whose bytes matched the
offline image read by the host `bdsvars` CLI (`records/20261006T073500Z-phone-efivarfs-userspace`,
`record.md:22-26`). A set/read/delete probe ran on a **loop-backed copy** and matched the host CLI byte
for byte; **no physical `bdsvars` write was performed** in that record.

`[INFERENCE]` That the whole chain works end to end (firmware sees an OS write at the next boot, the OS
sees a firmware write immediately) is the part that still depends on the boot-time re-read in section 9.

## 7. What each layer guarantees

| Layer | Owns | Does not own |
| --- | --- | --- |
| Qualcomm firmware (`VariableDxe`, TZ app) | the OEM store, `BS`-time service, the SCM/GPT-listener path | any runtime variable service; returning `EFI_UNSUPPORTED` is its documented runtime behaviour |
| efisp / Surfacer (UEFI) | partition choice, the store's byte-format use, the private runtime table, the pre/post-`EBS` split, the honest RT advertisement | the OS's view after handoff; reclaim timing; anything above `EBS` |
| this crate (byte-image engine) | the edk2 image format, record-state recovery, the ordered per-phase commit, reclaim as offline work | where the bytes live, who may write them, firmware calls, verification |
| the store partition itself | nothing | it is not a security boundary: any writer with block access can rewrite it |
| kernel `efivarfs` + registered backend | the OS-facing file view (`<name>-<GUID>`, four LE attribute bytes then the payload), immediate visibility of OS writes in the list it serves | firmware's view, which is a boot-time snapshot; nothing about authorization |
| the OS's tools (`efibootmgr`, `bootctl`, `fwupd`, `mokutil`) | their own expectations of UEFI semantics | nothing; they see whatever the backend reports |

The layering is why two consumers can disagree about the same variable without either being wrong: the
firmware serves its frozen view, the kernel serves the partition's current bytes.

## 8. Residual risks and open facts

**Proven gaps (evidence is missing, not negative):**

1. No lab record shows the `bdsvars`-backed **gRT shim running on the phone**; `plans/cutover.md:126`
   describes it as "Phase B source-only", and the 2026-09-29 records prove a runtime-table override and
   post-`EBS` variable calls, while 2026-10-06 proves the backend through userspace efivarfs. The join
   between them is unproven.
2. No physical `bdsvars` write from userspace has been performed; the write proof used a loop copy.
3. No **efivarfs mount from firmware-provided variables** has ever run on this phone (section 4.1).
4. The TrustZone variable path has never been observed working on this phone: the probe ended in crash
   dumps, and the one measured attempt to read a TrustZone-owned name returned
   `GetVariable(UefiSecAppId)` = `EFI_NOT_FOUND` (0x8000000000000005) at boot-services time
   (`records/20260929T204501Z-phone-loop/evidence/24-m6-proc-bootloader_log.stdout:974`), which
   contradicts the probe plan's expectation (`legacy/docs-history/device-probe-plan.md:103-105`).
   `[INFERENCE]` either the name moved, or the SCM path is not populated on this ROM.
5. `GPTListener`/`0x2001` is a single prose paragraph (`docs/storage/variables.md:144`) with no
   address, size or lab hit anywhere else — `grep -i 'gpt.?listener'` over `gobbl-lab` finds nothing.
   Treat it as the project's statement of the OEM mechanism, not as measurement.
6. The `EFI_RT_PROPERTIES_TABLE` word and the prose about it disagree (section 4.f).

**Design risks, stated rather than hidden:**

- **Freshness.** The partition is a plain block device: an attacker with disk access can restore an
  older, perfectly valid image — un-revoking a key, or dropping the system into setup mode. Signatures
  give integrity, not freshness; otherwise nothing here needs a secret, and a rewindable store is the
  central weakness of every file/partition-backed UEFI store shipping today.
- **No authorization.** Authenticated variables are refused rather than verified (this repository claims
  no verification), and Secure Boot is officially off: setup mode, `SecureBoot == 0`, no keys enrolled by
  us, with Qualcomm's UEFI setup menu reachable. That is a posture, not an oversight.
- **Staleness on both sides.** Direct OS writes are invisible to firmware's frozen view until the next
  boot; firmware writes after `EBS` are impossible. The split is inherent to "the OS owns the storage
  after `EBS`".
- **Runtime code permissions.** Copying callbacks into `EfiRuntimeServicesCode` is not enough on this
  firmware: the page had to be transitioned with `EFI_CPU_ARCH_PROTOCOL.SetMemoryAttributes` before it
  would execute. Any successor implementation must do the same, and `SetVirtualAddressMap` is not
  supported (`[INFERENCE]` the identity/physical path is the only one exercised).
- **Reset semantics.** A reset before the firmware's variable flush sets `VariableSyncEnabled = FALSE`
  (`device-probe-plan.md:250`); the OS-side writer cannot observe or prevent that.

**Forward pointer — the planned persistence and integrity model.** The successor to the on-disk format
is the *block-backed EFI variables with deferred verification* (EFVS) design: a firmware-written
checkpoint plus a hash-chained, append-only log; authenticated variables are stored as the submitted
`EFI_VARIABLE_AUTHENTICATION_2` payload and verified at boot-time replay against the key state at that
point in the chain; freshness moves to a platform anchor (a monotonic 64-bit value the OS cannot write,
e.g. a TrustZone-backed devinfo `rollback_index` slot on Qualcomm); and the posture — how strong the
anchor is — is reported in a configuration table so the OS and the user can see it. In that design the
log's security contribution is zero and the signatures plus the anchor do the work. Today's shipped
store is the edk2 image these sections describe; `efivar_store::auth` (see
[docs/format.md](../format.md#9-authenticated-variables-parsing-and-policy)) is the parsing and policy
half of that transition and is already pure and allocation-free for a boot-time replay to call.

## Sources

Primary specification:

- UEFI Specification 2.10 §8.2 Variable Services (attribute words; after `ExitBootServices` only `RT|NV`
  variables can still be set; zero-size delete), §8.2.3 `SetVariable` (descriptor definitions),
  §8.2.6 (using `EFI_VARIABLE_AUTHENTICATION_2`), §8.2.5 (using `EFI_VARIABLE_AUTHENTICATION_3`),
  §32.3 (secure boot modes and key roles):
  <https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html>.
- edk2 `MdeModulePkg/Universal/Variable/RuntimeDxe/Variable.c` (`UpdateVariable` phase order) and
  `SecurityPkg/Library/AuthVariableLib/AuthService.c` (`VerifyTimeBasedPayload`: `EfiAtRuntime` gate
  mirrors, GMT time-stamp check, its `:2126` time-stamp rule, `:2219-2265` signed-buffer construction).

This repository:

- `docs/format.md` — the byte layouts of the image the store uses, and the authenticated-layout rules.
- `docs/durability.md` — what a commit guarantees and what it does not.
- `docs/consumer-guide.md` — the lifecycle rules a variable-service consumer must follow.

Workspace evidence (paths are relative to `~/Projects/efisp-projects`):

- `gobbl/docs/storage/variables.md` (12-20, 104-135, 137-146, 167-179), `docs/storage/layout.md:36`,
  `docs/boot/selection.md:78-79`, `docs/architecture.md:26-28`.
- `gobbl/surfacer/app/src/variables.rs` (1-5, 164-168), `variables/mechanism.rs` (1-9, 377-386, 516-519,
  580-583), `variables/properties.rs` (3-8, 71-78), `lab/runtime_survey.rs` (1-10, 20-27).
- `gobbl/crates/provision-core/src/gpt.rs` (42-54, 969-980, 1076-1111).
- `gobbl-lab/legacy/docs-history/gpt-esp-varstore-investigation.md` (93-94, 113-134, 154-162, 176-178),
  `goal-1-bringup.md:172`, `open-qualifiers.md` (205, 207), `research-gaps.md` (52, 126),
  `implementation-notes.md:291`, `plan-breakers.md:247,323`, `device-probe-plan.md` (68-71, 97-105, 201,
  231, 250), `lu0-storage-plan.md` (29, 73-75), `multi-rom-investigation.md:28`.
- `gobbl-lab/docs/device-results.md` (142-151, 182) and the records named in section 4.1, plus
  `20260929T065938Z-phone-baseline`, `20261004T013922Z-phone-layout`,
  `20261004T034826Z-provision-replica`, `20261007T175802Z-provision-replica`.
- `kernelesp/modules/efivarfs/` (`bdsvars.c`, `PROVENANCE.md`, `esu-guid.h`, `vars.c`, `super.c`,
  `inode.c`, `file.c`, `test/`), `kernelesp/README.md` (11, 13, 130),
  `kernelesp/userspace/esuinit/src/init.rs` (221-235, 289-300),
  `kernelesp/userspace/esu-platform/src/efivars.rs` (2-3, 10-13, 62-69, 117-159),
  `kernelesp/payloads/boot-hal/src/backend.rs`, `kernelesp/esu/modules/boot-hal/sepolicy.rule`.
- Linux: `linux-on-sm8850/uefisecapp-probe/linux/drivers/firmware/qcom/qcom_qseecom_uefisecapp.c`
  (1-8, 30-34, 794-799, 831), `qcom_scm.c` (90-121, 2155-2167, 2207-2228, 2261-2270, 2285-2323,
  2333-2360), `qcom_qseecom.c:86-88`, `drivers/firmware/qcom/Kconfig:61-73`,
  `drivers/firmware/efi/vars.c` (26-41, 68-95), `fs/efivarfs/super.c` (361-362, 505-506),
  `include/linux/efi.h:1050-1062`, and the probe's `out/config` /
  `0001-allowlist-oneplus-infiniti.patch`.
- `gobbl-lab/records/20260930T025853Z-phone-harvest` for the harvested console of the TrustZone probe.
