# efivar-store

**Status (2026-10-07)** — extracted from the gobbl boot stack (`gobbl@ec63674`, where it was
`crates/varstore` + `tools/bdsvars`). The core engine and the Unix adapter are host-tested; the
formatter creates a standalone NV FV, and FTW (fault-tolerant write) maintenance is not implemented.

edk2-compatible EFI variable storage on a block device or partition: a `no_std`, allocation-free,
dependency-free Rust core that validates, formats and updates edk2 NV variable images byte for byte,
plus a CLI that inspects and edits them. The canonical use is an OVMF-style variable store on its own
partition, written and read by firmware, a bootloader or an operating system that owns the bytes.

## What this repository owns

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
cargo run --locked -p efivar-store-cli -- init --image store.img --size 1048576 --layout auth
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

`inspect`, `list` and `get` open the store read-only and take no lock. `set`, `delete` and `oneshot`
take an exclusive `flock`, reload under it, flush every edk2 phase and verify the readback, so
cooperative writers cannot interleave. `oneshot` writes the standard Boot Loader Interface
`LoaderEntryOneShot` variable (NV|BS|RT, UTF-16LE with a NUL).

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
