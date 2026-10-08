# Changelog

## Unreleased

- `efivar-store` (crate `crates/efivar-store`) — new `auth` module: parses
  `EFI_VARIABLE_AUTHENTICATION_2` and `_3` descriptors and rebuilds the byte-exact digest input a
  signature covers (UEFI 2.10 §8.2.6 and §8.2.5); applies the rules that need no key material —
  descriptor selection, time-stamp monotonicity, `APPEND_WRITE`, attribute changes, delete/append/replace
  planning — through `auth::check`, and defines `Verifier`, `Policy`, `KeyStore`, `Role` and `Mode`. The
  shipped policy is `SecureBootPolicy::None` (setup mode, `SecureBoot == 0`, authenticated writes
  refused), the shipped verifier is the owner-directed `Pkcs7Verifier` stub
  (`Unsupported::Crypto`), and nothing in the module performs I/O, allocation or cryptography. Purely
  additive: no existing type, trait or function changed.
- Docs — `docs/case-studies/qcom-sm8850-phone.md`: the Qualcomm SM8850 (OnePlus 15) runtime-variable
  posture as found, why the OS has no variables, how a block-backed store on an appended GPT partition
  is presented to firmware and kernel, what each layer guarantees, and the residual risks and open facts
  — with lab record ids, source citations and `[INFERENCE]` marks. `docs/format.md` gains §9 (the
  authenticated-variable API) and the primary references for it; `docs/consumer-guide.md` and `README.md`
  link both and state that no verification is claimed while the crypto primitive is a stub.

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
