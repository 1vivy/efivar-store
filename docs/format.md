# Byte formats

**Status (2026-10-07)** — the layouts `crates/efivar-store` parses and writes today, with the offsets
its implementation uses. Everything here is byte-exact against `src/format.rs` and `src/lib.rs`;
where the image is one edk2 also produces, the edk2 source is cited. Section 9 covers the `auth`
module: the authentication descriptors, the digest input a signature covers, and the rules that apply
without key material.

All multi-byte integers are little-endian. GUIDs are written in EFI on-disk order (mixed-endian:
`Data1`/`Data2`/`Data3` little-endian, `Data4` in order), **not** in UUID text order. Erased media is
`0xff`.

## 1. Image overview

An image this crate accepts begins at byte zero with an `EFI_FIRMWARE_VOLUME_HEADER` whose
`FileSystemGuid` is `gEfiSystemNvDataFvGuid`. Everything is measured from the start of that volume.
A bare `VARIABLE_STORE_HEADER` with no firmware volume around it is **not** a valid image here
(`Error::FvSignature`/`Error::FvGuid`).

Inside the volume sits one variable store; the store declares its own size, and the bytes of the
volume after that size are not variable space (they may be an event log, FTW areas or padding).

## 2. `EFI_FIRMWARE_VOLUME_HEADER` — 72 bytes as written by the formatter

| Offset | Size | Field | Value |
| --- | --- | --- | --- |
| 0 | 16 | `ZeroVector` | zero |
| 16 | 16 | `FileSystemGuid` | `fff12b8d-7696-4c8b-a985-2747075b4f50` (`gEfiSystemNvDataFvGuid`), wire bytes `8d 2b f1 ff 96 76 8b 4c a9 85 27 47 07 5b 4f 50` |
| 32 | 8 | `FvLength` | the whole image length |
| 40 | 4 | `Signature` | `_FVH` |
| 44 | 4 | `Attributes` | `0x00000e36` (read/write enabled and status, sticky write, memory mapped, erase polarity 1) |
| 48 | 2 | `HeaderLength` | 72 |
| 50 | 2 | `HeaderChecksum` | 16-bit sum of the header words == 0 |
| 52 | 2 | `ExtHeaderOffset` | 0 |
| 54 | 1 | `Reserved` | 0 |
| 55 | 1 | `Revision` | 2 |
| 56 | 8 | `BlockMap[0]` | `NumBlocks` (u32), `Length` (u32) — the image length divided by the block size |
| 64 | 8 | `BlockMap[1]` | terminator `{0, 0}` |

Parse rules (all of them fail closed with `Error::Fv*`/`Error::BlockMap`):

- `HeaderLength >= 72`, a multiple of 4, and not larger than `FvLength`.
- `Reserved == 0` and `Revision == 2`, and `EFI_FVB2_ERASE_POLARITY` (`0x800`) set in `Attributes`.
- The header checksum (sum of its 16-bit words) is zero.
- The block map's `NumBlocks * Length` entries sum to exactly `FvLength`; an entry with only one of
  the two fields zero is rejected.
- If `ExtHeaderOffset` is non-zero it must point at or after the end of the block map, and the
  extension's length field (offset 16 of the extension) must be at least 20 and inside the header.

The formatter writes `HeaderLength = 72` (one block-map entry plus its terminator), so the store
begins at offset 72. OVMF's `VarStore.fdf.inc` uses the same header length and the same
`gEfiSystemNvDataFvGuid`.

## 3. `VARIABLE_STORE_HEADER` — 28 bytes

| Offset | Size | Field | Value |
| --- | --- | --- | --- |
| 0 | 16 | `Signature` | `ddcf3616-3275-4164-98b6-fe85707ffe7d` (normal layout, `gEfiVariableGuid`) or `aaf32c78-947b-439a-a180-2e144ec37792` (authenticated layout, `gEfiAuthenticatedVariableGuid`) |
| 16 | 4 | `Size` | bytes of the store **including** this header |
| 20 | 1 | `Format` | `0x5a` |
| 21 | 1 | `State` | `0xfe` |
| 22 | 6 | `Reserved` | zero |

Parse rules: the signature selects the layout, `Size >= 28`, `Size` a multiple of 4, `Size` not
larger than the bytes of the volume after the FV header, and `Format`/`State` exactly `0x5a`/`0xfe`.
Records start at `HeaderLength + 28` (offset 100 in a standalone FV).

## 4. Records

The record header differs between layouts, but in both the size/GUID block sits at
`record_header_size - 24`:

`VARIABLE_HEADER`, normal layout — 32 bytes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | `StartId` = `0x55aa` |
| 2 | 1 | `State` |
| 3 | 1 | `Reserved` = 0 |
| 4 | 4 | `Attributes` |
| 8 | 4 | `NameSize` (bytes, **including** the terminating NUL) |
| 12 | 4 | `DataSize` |
| 16 | 16 | `VendorGuid` |

`AUTHENTICATED_VARIABLE_HEADER`, authenticated layout — 60 bytes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | `StartId` = `0x55aa` |
| 2 | 1 | `State` |
| 3 | 1 | `Reserved` = 0 |
| 4 | 4 | `Attributes` |
| 8 | 8 | `MonotonicCount` |
| 16 | 16 | `TimeStamp` (`EFI_TIME`) |
| 32 | 4 | `PubKeyIndex` |
| 36 | 4 | `NameSize` |
| 40 | 4 | `DataSize` |
| 44 | 16 | `VendorGuid` |

After the header: `Name` (`NameSize` bytes, UTF-16LE code units with a terminating NUL),
`Data` (`DataSize` bytes), then zero padding to the next 4-byte boundary. The record's aligned length
is what the append cursor advances by.

Parse rules (`Error::Record*`/`Error::Name`/`Error::Bounds`):

- `StartId == 0x55aa`; the state byte is one of `0x7f`, `0x3f`, `0x3e`, `0x3d`, `0x3c` or `0xff`.
- `NameSize >= 4` (at least one character plus its NUL) and even.
- The name decodes as UTF-16 with no embedded NUL and ends with a NUL — except for header-only
  records (`State == 0x7f`) and erased slots, whose names may not have been written yet: those still
  reserve their full, bounded slot and are never visible.
- The whole aligned record fits inside the store.
- A run of erased bytes ends the record list; a hole followed by programmed bytes is corruption, not
  free space, and is rejected.

## 5. Record states, resolution and the update sequence

State byte values used by edk2 and by this crate:

| Value | Meaning |
| --- | --- |
| `0x3f` | `VAR_ADDED` — live |
| `0x3e` | `VAR_IN_DELETED_TRANSITION` — still live; a replacement is being written |
| `0x7f` | `VAR_HEADER_VALID_ONLY` — header written, not live |
| `0x3d` | deleted (`0x3f & ~0x02`) |
| `0x3c` | deleted and in transition (`0x3f & ~0x03`) |
| `0xff` | erased |

Every write only clears bits, so the transition from `0x3f` to `0x3e`/`0x3d`/`0x3c` is a single byte
write that cannot create an invalid state.

Resolution matches edk2's `FindVariableEx`: among the live records for a `(name, GUID)` an `ADDED`
record always wins; if only transitions exist, the last one is the value. A header-only record never
shadows a live predecessor.

`persist::apply` writes a `Set` in six flushed phases:

1. every live predecessor `ADDED` → `IN_DELETED_TRANSITION` (still readable);
2. the replacement header, written as one unit with its state byte left erased so a torn header
   cannot be parsed;
3. the state byte → `VAR_HEADER_VALID_ONLY`;
4. name, data and padding;
5. the state byte → `VAR_ADDED` (the new value is live);
6. the predecessors → deleted.

`Delete` is a single phase: clear bit 1 of every live version. After the last phase the whole store
range is read back and compared byte for byte.

## 6. Free space, capacity and reclaim

- `capacity()` = store end − first record offset (`Size - 28` in a standalone FV).
- `free_space()` = store end − append cursor. Deleted records are **not** free until an explicit
  reclaim, and a full append region fails a `set` with `Error::Full` without changing a byte.
- `reclaim(scratch)` copies only the live records (promoting a recovered transition to `ADDED`),
  erases the rest of the store, and moves the append cursor back. It needs caller-owned scratch of
  `reclaim_scratch_size()` bytes and is an **erase-and-rewrite** operation, never part of a live
  update.

## 7. A full OVMF `VARS` image

`OvmfPkg/VarStore.fdf.inc` builds one FV that contains the variable store, an event log and the two
FTW (fault-tolerant write) areas:

| Region | `FD_SIZE_IN_KB` 1024/2048 | `FD_SIZE_IN_KB` 4096 | Contents |
| --- | --- | --- | --- |
| `NV_VARIABLE_STORE` | `0x00000000` + `0x0000e000` | `0x00000000` + `0x00040000` | FV header (`0x48`) + `VARIABLE_STORE_HEADER` + records |
| `NV_EVENT_LOG` | `0x0000e000` + `0x00001000` | `0x00040000` + `0x00001000` | event log |
| `NV_FTW_WORKING` | `0x0000f000` + `0x00001000` | `0x00041000` + `0x00001000` | `EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER`, signature `gEdkiiWorkingBlockSignatureGuid` `9e58292b-7c68-497d-a0ce-6500fd9f1b95` |
| `NV_FTW_SPARE` | `0x00010000` + `0x00010000` | `0x00042000` + `0x00042000` | FTW spare block |

The volume's `FvLength` covers all of it (`0x20000` or `0x84000`), the store `Size` is
`FvLength - 0x48` (`0xdfb8` or `0x3ffb8`), and the store signature is the authenticated one (OVMF
notes it is "compatible with `SECURE_BOOT_ENABLE == FALSE` as well").

What this crate does with such an image:

- parses it and edits it; every byte outside the declared store `Size` (event log, FTW working, FTW
  spare) is preserved byte for byte;
- does **not** write, replay or validate the FTW log. Crash recovery for a commit is edk2's
  record-state recovery, not FTW replay. Because of that, `reclaim` on an OVMF image leaves the FTW
  log describing a store that was rewritten, and an OVMF that later replays it would be replaying a
  stale log; treat reclaim on a live OVMF image as offline-only work.

## 8. Authenticated layout: readable, not authorized

- `MonotonicCount`, `TimeStamp` and `PubKeyIndex` are parsed as part of the record header and
  preserved byte for byte by `reclaim` (which copies live records). They are not exposed by the
  public API — `Variable` carries the name, GUID, attributes and data only.
- There is **no** signature verification and no Secure Boot authorization: layout support is not
  authorization.
- A `set`/`delete` of a key that already has an authenticated attribute (`Attributes & 0xb0`) fails
  with `Error::AuthenticatedWrite`, so authenticated variables cannot be replaced or removed by
  accident.
- `APPEND_WRITE`, unknown attribute bits and attribute words that are not `NV|BS` with optional
  `RT`/`HARDWARE_ERROR_RECORD` (`Attributes & !0x0f != 0` or `Attributes & 3 != 3`) fail with
  `Error::UnsupportedAttributes` instead of being silently treated as a replacement.

## 9. Authenticated variables: parsing and policy

The `auth` module (`crates/efivar-store/src/auth.rs`) is the specification half of authenticated
variables: it parses the authentication descriptors, rebuilds the exact digest input a signature covers,
and applies every rule that does not depend on key material. It is pure — no I/O, no allocation, no
dependencies, callable from firmware, a boot loader, a kernel module or a host tool. It performs **no
cryptography and no verification of its own**; the only verifier it ships is an explicit stub.

### 9.1 Descriptors

- `Authentication2::parse(payload)` — `EFI_VARIABLE_AUTHENTICATION_2`, the descriptor
  `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS` payloads begin with (UEFI 2.10 §8.2.3, §8.2.6).
  Layout: `EFI_TIME` (16 bytes, GMT), then a `WIN_CERTIFICATE_UEFI_GUID` whose `dwLength` counts itself.
  `Authentication2::HEADER` is 40 bytes, `len()` is `16 + dwLength`, and `value(payload)` is every byte
  after the descriptor (the new variable content; the descriptor itself is never variable data).
  Refused, before a caller sees any of it: a payload shorter than `dwLength` claims; `dwLength` below the
  certificate header; a revision other than `0x0200`; `wCertificateType` other than
  `WIN_CERT_TYPE_EFI_GUID` (`0x0ef1`); `CertType` other than `EFI_CERT_TYPE_PKCS7_GUID`
  (`4aafd29d-68df-49ee-8aa9-347d375665a7`); an empty `CertData`; and a time stamp whose `Pad1`,
  `Nanosecond`, `TimeZone`, `Daylight` or `Pad2` is not zero or whose date components are out of range.
  These are the gates edk2's `VerifyTimeBasedPayload` applies before it touches a payload.
- `Authentication3::parse(payload)` — `EFI_VARIABLE_AUTHENTICATION_3`, which
  `EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS` selects (UEFI 2.10 §8.2.5): a 10-byte primary descriptor
  (`Version`, `Type`, `MetadataSize`, `Flags`), a type-specific secondary descriptor (`EFI_TIME`, or
  `EFI_VARIABLE_AUTHENTICATION_3_NONCE`), an optional `NewCert` when
  `EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT` is set, then the signing certificate. `len()` is
  `MetadataSize` and `value(payload)` is everything after it. An unknown version or type, a reserved
  `Flags` bit, a `MetadataSize` that does not bound the structures exactly, a zero-length nonce and a
  certificate that is not PKCS#7 are refused. No consumer in this workspace uses `_3` yet; it is parsed
  because the format is part of the specification this crate implements.

### 9.2 The digest input

`Request::signing_input()` yields the byte-exact input of UEFI 2.10 §8.2.6 step 2,
`digest = hash (VariableName, VendorGuid, Attributes, TimeStamp, DataNew_variable_content)` — "The NULL
character terminating the VariableName value shall not be included in the hash computation". The name is
serialized as UTF-16LE, from either `VariableName::Units(&[u16])` or `VariableName::Bytes(&[u8])`
(wire order, exactly what `Name::as_bytes` yields), so no caller has to allocate or copy to reach it. For
`EFI_VARIABLE_AUTHENTICATION_3` the input follows §8.2.5 step 3: name, vendor GUID, attributes and the
secondary descriptor, then the value, then — for a nonce update — the variable's *current* nonce, then a
`NewCert`. `SigningInput::feed(&mut impl DigestInput)` streams the input (the name arrives two bytes at a
time), so a boot-time verifier can hash it without a buffer; `copy_into(&mut [u8])` materializes it for
tests and host tools and writes nothing at all when the buffer is too small.

### 9.3 Rules

`auth::check(&Request)` is the part of the specification that does not need a key: it reads nothing,
writes nothing, and returns the `Plan` the caller must execute.

| Situation | Result |
| --- | --- |
| neither, both, or the deprecated counter-based `EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS` | `Error::Descriptor` |
| attribute bits above the defined `0xff` | `Error::Attributes` |
| payload descriptor ≠ the descriptor the attributes select | `Error::Descriptor` |
| `APPEND_WRITE` with the enhanced descriptor | `Error::AppendWrite` |
| stored attribute word ≠ submitted attributes without `APPEND_WRITE` | `Error::AttributeChange` |
| time stamp not strictly later than the stored one, without `APPEND_WRITE` | `Error::Stale` |
| the all-zero time stamp without `APPEND_WRITE` | `Error::TimeStamp` |
| stored authenticated variable with no recorded time stamp | `Error::MissingTimeStamp` |
| empty value, no `APPEND_WRITE` | `Plan::Delete` |
| `APPEND_WRITE` with a stored value | `Plan::Append` (an empty value refreshes only the time stamp) |
| otherwise | `Plan::Replace` |

### 9.4 Authorization, and what is deliberately absent

`Verifier` checks the signature over the digest input; `Policy` decides whether an update may happen at
all; `KeyStore` supplies the key state; `Role::of(name, guid)` maps the names and GUIDs of UEFI 2.10
§32.3 (`PK`, `KEK`, `db`, `dbx`, `dbt`, `dbr`, `OsRecoveryOrder`, and everything else as the
specification's "Private Authenticated Variable"); `Mode::of` maps `SetupMode`/`AuditMode`/`DeployedMode`.
The policy this repository ships is `SecureBootPolicy::None`: setup mode, `SecureBoot == 0`, no keys
enrolled, and `Error::Refused` for every authenticated write — the same refusal the byte-image engine
already reports as `Error::AuthenticatedWrite` for an attribute word carrying `0x10`/`0x20`/`0x80`. The
verifier it ships, `Pkcs7Verifier`, is an owner-directed stub returning
`Error::Unsupported(Unsupported::Crypto)`, so a caller that forgets to supply a real verifier fails closed
instead of accepting an unchecked write.

**No verification is claimed while those primitives are stubs.** Layout support is not authorization: the
engine still refuses to write an authenticated variable, and the `auth` module is a parser and a rule
set, not a security boundary. Persistence, freshness (a monotonic value the OS cannot write) and the
write path belong to the consumer. In this project they belong to the deferred-verification store — a
firmware-written checkpoint plus a hash-chained, append-only log, with authenticated payloads kept as
submitted and verified at boot-time replay — not to the edk2 image written in place. The
[SM8850 case study](case-studies/qcom-sm8850-phone.md) describes the platform this applies to.

## References

- edk2 `MdeModulePkg/Include/Guid/VariableFormat.h` — record states and header structures:
  <https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Include/Guid/VariableFormat.h>
- edk2 `MdeModulePkg/Universal/Variable/RuntimeDxe/Variable.c` — `UpdateVariable`, the phase order
  reproduced by `persist::apply`:
  <https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Universal/Variable/RuntimeDxe/Variable.c>
- edk2 `MdeModulePkg/Universal/Variable/RuntimeDxe/VariableParsing.c` — `FindVariableEx` resolution:
  <https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Universal/Variable/RuntimeDxe/VariableParsing.c>
- edk2 `MdeModulePkg/Universal/Variable/RuntimeDxe/Reclaim.c` — reclaim:
  <https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Universal/Variable/RuntimeDxe/Reclaim.c>
- edk2 `OvmfPkg/VarStore.fdf.inc` — the OVMF `VARS` layout:
  <https://github.com/tianocore/edk2/blob/master/OvmfPkg/VarStore.fdf.inc>
- UEFI Specification 2.11, §8.2 Variable Services — attribute words, zero-size delete, non-volatile
  semantics: <https://uefi.org/specs/UEFI/2.11/08_Services_Runtime_Services.html>
- `virt-firmware` (`virt-fw-vars`), an independent reader/writer of these images used as a host
  cross-check: <https://gitlab.com/kraxel/virt-firmware>
- UEFI Specification 2.10 §8.2.3 `SetVariable()` and §8.2.6 "Using the
  `EFI_VARIABLE_AUTHENTICATION_2` descriptor" — the descriptor layout, the signed digest input and the
  `APPEND_WRITE` rules `auth` implements: <https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html>
- UEFI Specification 2.10 §8.2.5 "Using the `EFI_VARIABLE_AUTHENTICATION_3` descriptor" — the
  extensible descriptor's sequencing and its own digest serialization:
  <https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html>
- edk2 `SecurityPkg/Library/AuthVariableLib/AuthService.c` — `VerifyTimeBasedPayload` (the GMT
  time-stamp check, the time-stamp rule at `:2126`, and the `(VariableName, VendorGuid, Attributes,
  TimeStamp, Data)` buffer at `:2219-2265`):
  <https://github.com/tianocore/edk2/blob/master/SecurityPkg/Library/AuthVariableLib/AuthService.c>
