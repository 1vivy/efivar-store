# Changelog

## Unreleased

- Home the UEFI variable-service mechanism in `crates/efivar-store-uefi`, extracted from
  Surfacer with its host tests and AArch64/x86-64 runtime readers. Namespace routing and
  volatile permission are caller policy; storage geometry and block I/O are caller supplied.
- Document application-linked publication, the EBS freeze, and physical-only runtime.
  SetVirtualAddressMap/ConvertPointer and runtime writes remain unsupported.

## 0.1.0 — 2026-10-07

First release. Imported from the gobbl boot stack at `gobbl@ec63674`, where this code lived as
`crates/varstore` and `tools/bdsvars`; behaviour is unchanged.

- `efivar-store` (crate `crates/efivar-store`) — `no_std`, dependency-free edk2 NV variable image
  engine: `Store` (`parse`/`get`/`list`/`free_space`/`capacity`), `StoreMut`
  (`format`/`set`/`delete`/`reclaim`), `persist::apply` (edk2's ordered, per-phase-flushed commit
  with whole-range readback), `persist::unix` (the `std` feature: `flock` + `fsync` file and
  block-device adapter) and `mirror` (`decide`/`needs_reclaim`).
- `efivar-store-cli` (binary `efivar-store`) — `init`, `inspect`, `list`, `get`, `set`, `delete` and
  `oneshot`. `init` is new: gobbl initialised the store from its own provisioning tool instead.
- Docs — `docs/format.md` (byte layouts), `docs/durability.md` (commit guarantees and limits),
  `docs/consumer-guide.md` (UEFI lifecycle rules for consumers).
- CI — formatting, clippy with `-D warnings`, tests, and a `no_std` build of the core for a bare
  target.
