# efivar-store

**Status (2026-10-07)** — EFVS v1 is the live block-backed EFI variable container:
A/B checkpoints plus a hash-chained append log, with shared allocation-free `no_std`
serializers and replay for firmware and Linux. The existing edk2 FV engine remains
unchanged for import/export, inspection and migration of existing stores.
Compaction writes the inactive checkpoint and its generation/CRC header, with
flush barriers before clearing the log. Header copies occupy distinct physical
write units (4096 bytes by default), so a torn sector cannot destroy both.
The 1 MiB phone profile reserves two 128 KiB checkpoint slots and a 778240-byte log.

The official Secure Boot policy is **None**: no root keys, SecureBoot=0, tier 0.
Authenticated writes are refused, not silently accepted by a crypto stub.
See [the byte-exact EFVS specification](docs/efvs-v1.md), including its
[checkpoint provenance correction](docs/efvs-v1.md#spec-correction-checkpoint-provenance).

| Primitive | Status |
| --- | --- |
| SHA-256, CRC32, checkpoint/record codecs, replay, compaction | Implemented, dependency-free |
| AUTH_2 structure and timestamp rules | Shared pure authentication parser/rules |
| Signature verification | Authorised unsupported stub; no production verifier |
| `NoneAnchor` | Implemented, boot-local only, no rollback protection |
| TPM2 NV / OP-TEE RPMB / Qualcomm devinfo slot 31 | Authorised unsupported platform stubs |
| Protected checkpoint provenance | Not implemented; all posture reporting capped at 0 |

Nominal tiers are 0 (no protected freshness), 1 (boot-time monotonic freshness),
2 (runtime freshness). None is advertised above 0 today: an unkeyed checkpoint
digest cannot bind authenticated state or its counter on attacker-writable media.
Tier 0 under Policy None does **not** claim authenticated integrity.

## What this repository owns

- **Live format**: EFVS v1 header/checkpoint/log, SET/APPEND/DELETE replay,
  torn-tail recovery, explicit boot-time compaction, config table and anchor interfaces.
- **Interoperability**: the edk2 operations below remain available unchanged.

- **Identity**: the `(name, vendor GUID)` key — UTF-16LE names with their on-disk NUL, 16-byte EFI
  wire-order GUIDs (not UUID text order).
- **Attributes**: the UEFI attribute word as stored, including the refusal of authenticated,
  time-based, enhanced-authenticated and `APPEND_WRITE` updates.
- **Authenticated variables, parsed**: the `EFI_VARIABLE_AUTHENTICATION_2` and `_3` descriptors, the
  exact digest input a signature covers, and the rules that hold without key material — time-stamp
  monotonicity, `APPEND_WRITE`, attribute changes, and the key roles and modes of secure boot (`auth`).
  Parsing and policy only: the verifier is a stub, no signature is checked, and the official policy
  refuses every authenticated write ([docs/format.md §9](docs/format.md#9-authenticated-variables-parsing-and-policy)).
- **Formats**: edk2's normal and authenticated variable record layouts, the `VARIABLE_STORE_HEADER`,
  the `EFI_FIRMWARE_VOLUME_HEADER` around it, and record-state recovery
  (`ADDED` / `IN_DELETED_TRANSITION` / `HEADER_VALID_ONLY`) exactly as edk2 resolves them.
- **Operations**: image init (`StoreMut::format`), inspection (`Store::parse`/`get`/`list`/
  `free_space`), durable set and delete (`persist::apply`), reclamation (`StoreMut::reclaim`), and an
  offline primary/spare decision (`mirror`).
- **Durability**: the ordered edk2 commit sequence with a flush boundary per phase, over a
  caller-supplied byte device (`persist::{Read, Write, Flush}`), plus a Unix file/block-device adapter
  (`persist::unix`, the `std` feature) with `flock` and `fsync`. See [docs/durability.md](docs/durability.md).

## What this repository does not own

- **Boot policy**: which variable means what, boot order, slot/merge semantics, Boot Loader Interface
  selection precedence (`OneShot` > `Default` > `Selected`). Consumers own all of it.
- **Partitioning**: partition names, sizes, GPT or LVM layout, block-device discovery, provisioning of
  the medium. The store is GUID- and size-agnostic: the caller chooses the bytes and the geometry.
- **UEFI runtime services**: installing a `gRT` `SetVariable`/`GetVariable` implementation, the
  `ExitBootServices` view, `EFI_RT_PROPERTIES_TABLE` reporting and the firmware side of variable
  access are consumer work. This repository is the storage engine underneath; it never talks to
  firmware. [docs/consumer-guide.md](docs/consumer-guide.md) collects the lifecycle rules such a
  consumer must follow.

## Three representations

| Representation | Layout | Supported today |
| --- | --- | --- |
| Raw store | `VARIABLE_STORE_HEADER` + records, with no firmware volume around it | **No.** `Store::parse` requires the NV-data FV at byte zero; a bare store header is not a valid image for this crate. |
| Standalone NV FV | `EFI_FIRMWARE_VOLUME_HEADER` (72 bytes) + `VARIABLE_STORE_HEADER` + records | **Yes**, and it is what the formatter writes: `StoreMut::format` / `efivar-store init`. No FTW working/spare area and no event log are reserved, so the whole image beyond the headers is variable space. |
| Full OVMF `VARS` image | Variable store + event log + FTW working + FTW spare inside one FV | **Read/edit yes, FTW no.** The image parses, `get`/`list`/`set`/`delete` work and every byte outside the declared store size (event log, FTW working, FTW spare) is preserved untouched. The FTW log itself is neither written nor replayed, so a `reclaim` (an erase-and-rewrite of the store region) invalidates it. |

The byte layouts of all three, with offsets, are in [docs/format.md](docs/format.md).

## Usage

### Library

```toml
[dependencies]
efivar-store = { git = "https://github.com/1vivy/efivar-store" }
# or, in a checkout:
# efivar-store = { path = "../efivar-store/crates/efivar-store" }
```

The crate is `#![no_std]` and has no dependencies. The optional `std` feature adds only
`persist::unix` (file and block-device I/O, `flock`, `fsync`); firmware never enables it.

```rust
use efivar_store::{Layout, Store, StoreMut};

let mut image = vec![0u8; 1 << 20];
StoreMut::format(&mut image, Layout::Authenticated, 4096)?;
let store = Store::parse(&image)?;
assert_eq!(store.free_space(), store.capacity());

// Durable update over a caller-supplied device (`persist::apply`) or the Unix adapter:
// the partition name, size and GUID are the consumer's choice, not this crate's.
let mut device = efivar_store::persist::unix::Device::open(std::path::Path::new("/dev/disk/by-partlabel/efivars"))?;
let name: Vec<u16> = "LoaderEntryDefault".encode_utf16().collect();
let guid = [0x82, 0xb0, 0x67, 0x4a, 0x4c, 0x0a, 0xcf, 0x41, 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f];
let outcome = device.transaction(|tx| tx.set(&name, &guid, 0x7, b"linux\0".as_slice()))?;
```

### CLI

The `efivar-store` binary (package `efivar-store-cli`) works on a partition, a block device or an
image file:

```sh
cargo run --locked -p efivar-store-cli -- init --efvs --image store.img --size 1048576
cargo run --locked -p efivar-store-cli -- --image store.img inspect
echo -n linux > value.bin
cargo run --locked -p efivar-store-cli -- --image store.img set \
    --name LoaderEntryDefault --guid 4a67b082-0a4c-41cf-b6c7-440b29bb8c4f --attributes 0x7 --data-file value.bin
cargo run --locked -p efivar-store-cli -- --image store.img get \
    --name LoaderEntryDefault --guid 4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
cargo run --locked -p efivar-store-cli -- --image store.img list
cargo run --locked -p efivar-store-cli -- --image store.img oneshot linux.conf
cargo run --locked -p efivar-store-cli -- --image store.img delete \
    --name LoaderEntryDefault --guid 4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
```

`--efvs` selects the live container; omit it for an edk2 interoperability FV.
`compact --image store.img` is an explicit offline firmware-equivalent operation.
`import-edk2 --from old.fd --image new.img --size 1048576` preserves live edk2
variables in a fresh EFVS checkpoint (boot policy still drops authenticated keys).
EFVS set/delete/oneshot append only one record and fsync; they never rewrite the
whole image or reclaim on exhaustion. The shared serializer supplies these bytes.

`inspect`, `list` and `get` open the store read-only and take no lock. Mutations
take an exclusive `flock`, reload, flush and verify readback. EFVS flushes the appended
record; edk2 retains its ordered phase sequence. `oneshot` writes the standard
Boot Loader Interface `LoaderEntryOneShot` variable (NV|BS|RT, UTF-16LE with a NUL).

The crate also ships a host example with the same operations in wire-order GUID hex:

```sh
cargo run --locked -p efivar-store --example store-image -- init out.img 1048576 4096 auth
cargo run --locked -p efivar-store --example store-image -- inspect out.img
```

## Case studies

- [Runtime variables on a Qualcomm SM8850 phone](docs/case-studies/qcom-sm8850-phone.md) — what a
  production phone's UEFI variable posture actually is (Qualcomm `VariableDxe`, the TrustZone
  `uefisecapp` the mainline allowlist excludes, the GPT listener), why the operating system therefore
  has no variables, and how a block-backed store on an appended GPT partition is presented to both
  firmware and kernel as *the* variable service. Written from lab record ids and source, with what is
  proven, what is not, and the deferred-verification design that supersedes the on-disk format.

## Layout

```
crates/efivar-store/   no_std core: format parsing/writing, ordered durable commit, auth descriptors, Unix adapter
cli/                   the `efivar-store` binary
docs/format.md         byte layouts (FV, store, records, OVMF VARS, FTW) and the authenticated-variable API
docs/durability.md     what persist::apply and the Unix adapter guarantee, and what they do not
docs/consumer-guide.md lifecycle rules for a UEFI variable-service consumer
docs/case-studies/     field evidence: platforms this store is deployed on
```

## License

Apache-2.0. The code was imported from the gobbl boot stack, which is licensed the same way; see
[LICENSE](LICENSE).
