# Durability

EFVS and edk2 have different persistence contracts. Nothing here claims unconditional
power-loss safety or authentication from an unkeyed digest.

## EFVS: append durability

EFVS updates are complete, 8-byte-aligned hash-chained records, not whole-image
rewrites. `efvs::append` validates and returns the exact absolute byte range to
persist. Write that range, flush it, then publish the tentative working set.
The CLI locks and reloads first, writes only that range, fsyncs and checks readback.
On I/O failure reload: the tentative in-memory state is not a durable commitment.

Replay stops at the first truncated, malformed, wrongly sequenced or hash-broken
record. A torn final record loses at most that append; all valid earlier records
remain usable. Replay never hunts for a later magic. A torn tail requires explicit
boot/offline compaction before appending; full capacity returns `Full`, never reclaim.
These guarantees assume writes do not damage earlier already-durable bytes.
The hash chain detects damage/order, not hostile rewriting or boundary truncation.

EFVS compaction is crash-atomic using A/B checkpoint slots and two headers in
**different physical write units**, each with generation and CRC. The phone
profile uses 4096-byte blocks (headers at 0/4096), two 128 KiB checkpoint slots
and a shared 778240-byte log in the 1 MiB image.
`compact_durable` writes the inactive checkpoint and flushes, writes the inactive
header's complete physical block and flushes, then zeroes the log and flushes.
Only after this sequence succeeds may the caller bump (if greater) and lock its anchor.

Load selects the highest-generation header with a valid CRC and referenced
checkpoint SHA-256, falling back to the other pair. Before header commitment the
old checkpoint plus log recover the pre-compaction state; afterwards the new
checkpoint recovers the post-compaction state. Stale log records cannot replay
against a different checkpoint hash/sequence. Interrupted clearing is finished
before further append. Header discovery still finds B when A's entire block is lost.

Tests inject failure at every write/flush call, both outcomes of failed flushes,
every byte offset of a torn checkpoint/header write in both directions, and
damage to an entire 4 KiB target sector. These guarantees assume flush ordering
is honored and torn writes cannot corrupt unrelated physical write units;
consumers must select a block size at least their medium's physical write unit.
An arbitrary subsequent corruption may fall back to an older checkpoint, not
reconstruct an already-cleared historical log. `compact` only stages bytes;
writing its whole result at once would violate the ordered contract.
The host compact command uses `compact_durable` and remains offline image-only.
SHA-256 and redundant headers do not establish checkpoint provenance; see the
[spec correction](efvs-v1.md#spec-correction-checkpoint-provenance).

## edk2: ordered phase durability

The remaining sections describe exactly what `efivar_store::persist::apply` and
`persist::unix` guarantee for edk2 images. Their whole-write/phase limitations and
non-atomic reclaim remain unchanged; the EFVS torn-record recovery does not apply
to an edk2 image.

## 1. The commit contract

`apply(io, image, scratch, change)` performs one `(name, GUID)` change in edk2's
`UpdateVariable` phase order over a caller-supplied device. Its contract:

- **Success**: `image` equals the new device contents byte for byte, and every phase was flushed in
  order. `Outcome` says which of `Written`, `Deleted`, `Unchanged` or `Absent` happened.
- **Any error** (I/O, readback mismatch, a rejected change): `image` is **invalid**; the caller must
  reload it from the device before the next mutation. There is no rollback — the device may already
  hold a partially applied change.
- **Flush boundary**: every phase is one or more `write_at` calls followed by exactly one
  `Flush::flush`. The adapter must make the flushed prefix durable before `flush` returns. A
  whole-image rewrite, a reclaim or a reformat is never part of a live update.
- **Whole-range readback**: after the final phase the entire store range is read back in 4 KiB chunks
  and compared with the planned image; the first differing byte is reported as
  `Error::Readback { offset }`.
- **No allocation**: both buffers are caller-owned; `scratch` must be at least `image.len()` bytes.

Rejections happen before any write, so a failed change leaves the device untouched: a full store
(`Error::Format(Full)`), an authenticated write, an unsupported attribute word, an invalid name, a
change whose planned bytes would not be a legal edk2 transition (`Error::Unexpected`), and an append
slot that is not erased (`Error::NotErased`). A `Set` with identical attributes and data returns
`Outcome::Unchanged` and a `Delete` of a missing key returns `Outcome::Absent`, both with zero writes.

## 2. What a crash may leave behind

A power loss between phases leaves a store that still parses and reports **either the complete old
value or the complete new value** — never a torn value, never a half-visible record:

- between phase 1 and 5 the old value is live (its record is in transition, which still resolves as
  live) and the new record is not `ADDED` yet;
- from phase 5 the new value is live, and the old records are still `IN_DELETED_TRANSITION`, which
  resolution prefers only when no `ADDED` record exists;
- phase 6 only makes the retirement of the old records durable.

This mirrors the model the UEFI specification requires of a non-volatile write:

> The only rules the firmware must implement when saving a nonvolatile variable is that it has
> actually been saved to nonvolatile storage before returning `EFI_SUCCESS`, and that a partial save
> is not performed. If power fails during a call to `SetVariable()` the variable may contain its
> previous value, or its new value.

— UEFI Specification 2.11, §8.2 Variable Services
(<https://uefi.org/specs/UEFI/2.11/08_Services_Runtime_Services.html>).

## 3. The Unix adapter

`persist::unix::Device` is the `std`-only host adapter (firmware must not enable the `std` feature):

- `Device::transaction(f)` takes a **blocking `flock(LOCK_EX)`** on the open descriptor, reloads the
  whole store from the backing store under that lock, parses it, runs `f` (which may call
  `Transaction::apply`/`set`/`delete` at most once), and releases the lock on every exit path,
  including an error from `f` or from the unlock itself.
- Every read comes from the backing store — never from an `efivarfs` snapshot or a cache.
- Every `flush` is `fsync` on the descriptor (`sync_all`), and every write is positional
  (`pwrite`/`pread`), so phases do not depend on a shared file offset.
- Cooperative writers that use this adapter cannot interleave phases; a writer that does not take the
  lock can.
- Sizing: a regular file by its length, a block device (whose metadata length is 0) by seeking to the
  end.

Two `flock`-using writers that both land are covered by `tests/cli.rs::concurrent_writers_both_land`
and `tests/persist.rs::two_cooperative_writers_both_land`.

## 4. Limits — what is *not* modelled

1. **Only whole-write/whole-call failure is modelled.** The fault-injection tests fail a complete
   `read_at`/`write_at`/`flush` call; the device is assumed to apply each call either fully or not at
   all. A torn sector, a partially programmed block, a write that is reordered with a later flush, or
   a device that reports success for a write it never performed are **not** modelled, and the
   readback does not catch them: it runs after the write returned, so it verifies the device's
   read-back view, not the medium.
2. **A flush that lies voids every guarantee.** The whole contract is relative to `Flush::flush`
   meaning "the preceding writes are on the medium". On a device with a volatile write-back cache
   that does not honour flush/FUA, a successful `fsync` is not durability; see Linux
   `Documentation/block/writeback_cache_control.rst`
   (<https://docs.kernel.org/block/writeback_cache_control.html>). `fsync` on a block device issues a
   cache flush, which is only meaningful if the device implements it.
3. **`reclaim` and `format` are erase-and-rewrite**, not flash bit-clearing operations. They are not
   part of a live update; the caller owns their durability policy (and should run them at boot or
   offline, with a spare copy — see `efivar_store::mirror::decide`).
4. **The store is not a journal.** There is no checksum or sequence number beyond the edk2 record
   states. A device that corrupts bytes arbitrarily can produce an image the parser refuses (it fails
   closed) but not one the crate repairs.
5. **One commit at a time.** `apply` performs a single `(name, GUID)` change. A multi-variable
   transaction is not atomic; each variable is its own commit.
6. **Not implemented today**: FTW working/spare maintenance (an OVMF FTW log is neither written nor
   replayed — tracked as an issue), torn-write/torn-sector fault model (issue), and any host-side
   detection of a device that silently discards flushes.

## 5. Test coverage for these claims

`crates/efivar-store/tests/persist.rs` injects a failure at **every** write and flush step of both
commit shapes and asserts after each that the device image still parses and still reports a complete
old or complete new value; it also covers readback mismatch, the zero-write outcomes, a full store
rejected before any write, authenticated/unsupported attributes rejected before any write, and two
cooperative writers. `tests/contracts.rs` covers the parser and writer contracts, including the
interruption cuts, reclaim promotion and the fail-closed bounds.

Run them with:

```sh
cargo test --locked -p efivar-store
```
