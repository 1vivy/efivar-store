# Changelog

## Unreleased

- Switch the UEFI service's live backend to EFVS: first-boot initialization/import,
  highest-valid-generation replay, durable compaction, anchor bump/lock before publication,
  checked boot-time append updates and EFVS runtime configuration-table publication.
- Make first-boot conversion restartable through an independently durable migration journal;
  populate both imported checkpoint pairs and retire the journal before exposing callbacks.
  Add write/flush/torn-marker fault tests, next-boot OS-log replay and anchor lifecycle tests.
- Expose a read-only service inspection API; application variable users call gRT rather than
  private get/set shortcuts. Keep read-only physical runtime and explicit tier-0 Policy None.
- Home the UEFI variable-service mechanism in `crates/efivar-store-uefi`, extracted from
  Surfacer with its host tests and AArch64/x86-64 runtime readers. Namespace routing and
  volatile permission are caller policy; storage geometry and block I/O are caller supplied.
- Document application-linked publication, the EBS freeze, and physical-only runtime.
  SetVirtualAddressMap/ConvertPointer and runtime writes remain unsupported.
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
- Add EFVS v1 as the live container, leaving edk2 APIs unchanged for interoperability.
  Shared no_std, allocation-free codecs, SHA-256, ordered replay, torn-tail recovery,
  explicit compaction, edk2 migration, configuration table and anchor interfaces.
- Make EFVS compaction crash-atomic with two block-aligned checkpoint slots and
  generation/CRC header copies in distinct physical write units. Add the shared
  ordered compaction I/O interface, highest-valid-generation recovery, and
  exhaustive torn-checkpoint/header plus write/flush and 4Kn-sector fault tests.
- Add EFVS CLI init/inspect/list/get/set/delete/oneshot, offline compact and import-edk2.
- Official Policy None rejects authenticated updates; anchor/crypto primitives remain
  explicit unsupported stubs except the real no-persistence NoneAnchor.
- Freeze GUIDs and byte layouts in docs/efvs-v1.md. Document the source design's
  checkpoint-provenance gap; cap all advertised posture at tier 0 until resolved.

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
