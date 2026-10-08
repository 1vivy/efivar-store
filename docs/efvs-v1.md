# EFVS v1: block-backed EFI variables

EFVS is the live container: redundant firmware checkpoints and an append-only runtime log.
The existing edk2 FV engine is unchanged and remains the import/export/inspection
and migration interoperability engine. An edk2 FV is not an EFVS checkpoint.
All serializers live in `efivar_store::efvs`; firmware and Linux compile the same
allocation-free, dependency-free Rust source (Rust 1.82 / edition 2021 compatible).
`sha256` is the shared SHA-256 implementation; `auth` supplies AUTH_2 parsing.

## Identity and geometry

Generated with `uuidgen` for this format freeze:

- Configuration-table GUID: **930e89ed-540e-4af0-9b41-c2c559939d50**.
- Recommended new partition type: **517663b2-3fb3-4a78-9abe-c45594848dd5**.

Format identity is `EFVS` magic plus version, **not** a GPT type. Existing bdsvars
partitions retain their type and require no GPT change. The configuration table
contains the partition's **unique instance GUID**, not its type GUID. GUID fields
use EFI mixed-endian wire order: first u32/u16/u16 little endian, last eight bytes
in displayed order. Integers below are unsigned little endian unless stated.
Offsets are bytes. No native-structure casts, pointers, compiler padding, or host
endianness are used. All regions and records are 8-byte aligned. All unused bytes,
reserved fields and padding are zero. Unknown versions/flags are refused, never
silently ignored. Length arithmetic is checked before indexing caller buffers.

Phone profile: 1,048,576-byte image, 4096-byte physical write units, header A at
0 and header B at 4096 (each a 64-byte structure in its own zero-padded block).
Checkpoint A is at 8192, checkpoint B at 139264, each with 131072-byte capacity
(256 KiB total checkpoint reservation, 128 KiB usable slot budget including its
96-byte header). The shared log begins at 270336 and has 778240 bytes capacity.
Header blocks, checkpoint starts/capacities and log start are physical-block aligned.
Sizes are caller-selected, not inferred from partition type.

Block size is a power of two from 512 through 65536, defaults to 4096, and must
be at least the device's actual physical write unit. Consumers must reject a
geometry smaller than their device write unit. Two structures at offsets 0/64
would share a physical sector and are explicitly **not** this format. Header B
is always one recorded block from zero. To recover when header A is destroyed,
decoders try the bounded supported block-size positions for B and validate its
recorded geometry, CRC and checkpoint. Image size and each slot capacity must
be multiples of block size; each slot occupies at least one block.

### Image headers A/B (64 bytes each, in separate physical blocks)

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | ASCII `EFVS` |
| 4 | 2 | version = 1 |
| 6 | 2 | header size = 64 |
| 8 | 8 | exact image size |
| 16 | 8 | referenced checkpoint offset: `2*block_size` for A, plus one capacity for B |
| 24 | 8 | capacity of **each** checkpoint slot, block-aligned |
| 32 | 8 | shared log offset = `2*block_size + 2*checkpoint_capacity` |
| 40 | 8 | log capacity; log end must equal image size |
| 48 | 4 | CRC32 |
| 52 | 4 | physical block size |
| 56 | 8 | monotonically increasing compaction generation |

CRC32 is reflected IEEE CRC-32: polynomial 0xedb88320, initial/final XOR
0xffffffff, over **all 64 header bytes with bytes 48..52 zeroed**. It is only
corruption detection. Image length must match, not merely contain, header geometry.
The remainder of each physical header block is zero. Initialization creates both
valid pairs at generation zero; ties prefer header A. Load chooses the highest
generation with both a valid header CRC/geometry and a valid referenced checkpoint
SHA-256/structure, falling back to the other pair. Generation overflow is refused.
Neither the CRC nor the generation authenticates data against a malicious writer.

### Checkpoint slots A/B (equal fixed reserved capacity)

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | ASCII `EFVC` |
| 4 | 2 | version = 1 |
| 6 | 2 | header size = 96 |
| 8 | 4 | used length, including header, multiple of 8 |
| 12 | 4 | variable count |
| 16 | 8 | next physical log sequence (`0` initially) |
| 24 | 8 | cumulative accepted authenticated-write count |
| 32 | 32 | SHA-256 |
| 64 | 4 | reserved provenance flags = 0 |
| 68 | 28 | reserved provenance/extension metadata = 0 |
| 96 | variable | packed variable entries |
| used | remaining capacity | zero-filled free space |

SHA-256 covers **the entire checkpoint capacity**, including its metadata,
entries and zero-filled free space, with bytes 32..64 replaced by zeros. This
stored digest is also the first log record's `prev_hash` after every compaction.
The next sequence is one beyond the last structurally valid, hash-chained record,
including policy-rejected records. It does not count only successful operations.
This resolves the source spec's `seq 0` ambiguity: only a freshly initialized
store starts at zero; after compaction the checkpoint's next sequence continues.
An empty-log compaction does not advance it, so repeated compaction is byte-identical.
Sequence/counter overflow is refused rather than wrapped.

Each variable entry:

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | total aligned entry length |
| 4 | 4 | stored attributes, APPEND_WRITE cleared |
| 8 | 2 | name byte length |
| 10 | 2 | reserved entry flags = 0 |
| 12 | 4 | data byte length |
| 16 | 16 | vendor GUID |
| 32 | 16 | EFI_TIME of last accepted auth write; zeros for unauthenticated values |
| 48 | name length | UTF-16LE name, **no NUL** |
| following | data length | value (not the AUTH_2 wrapper) |
| following | 0..7 | zero padding to 8-byte boundary |

Names are nonempty, even-length, valid UTF-16 with no embedded NUL, and at most
65534 bytes. Duplicate (name, GUID) keys invalidate a checkpoint. Replacing a key
preserves its enumeration position; insertion appends and deletion closes the gap.
Migration preserves every live edk2 variable, attributes, value, name/GUID and
EFI_TIME, including authenticated and BS-only entries. This is byte-data migration,
not enrollment or signature verification. Boot policy filters imported values.

### Log record (`efvs_record`)

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | ASCII `EFVR` |
| 4 | 4 | whole record length, multiple of 8 |
| 8 | 8 | physical sequence |
| 16 | 32 | previous record hash, or checkpoint hash for first record |
| 48 | 2 | name byte length |
| 50 | 2 | operation: SET=1, APPEND=2, DELETE=3 |
| 52 | 4 | attributes **as submitted**, including APPEND_WRITE |
| 56 | 16 | vendor GUID |
| 72 | 4 | data byte length |
| 76 | name length | UTF-16LE name without NUL |
| following | data length | submitted payload, AUTH_2 descriptor untouched for auth writes |
| following | 0..7 | zero padding |
| length - 32 | 32 | SHA-256 of every preceding byte of this record |

`length = align8(76 + name_len + data_len + 32)`. Padding precedes the final hash
and **is covered by it**. This fixes the source's otherwise unspecified alignment
placement. The previous hash is the previous record's stored SHA-256, not a digest
of its digest. Each record is self-delimiting, canonical and minimum 112 bytes.

A wrong hash, link, sequence, malformed/truncated record or nonzero malformed tail
**ends** the log. Replay never scans ahead for another magic. All complete prior
records remain intact. An all-zero remainder is a clean end. A clean truncate at
a record boundary is indistinguishable from an older log; hash chaining is not
freshness protection. Append refuses a torn tail until firmware/offline compaction.
Capacity exhaustion returns `Full` without changing image or working set. It never
reclaims implicitly and never writes a partial record intentionally.

## Runtime and replay policy

The shared `State::apply` is the only mutation rule path used by checked append
and replay. SET replaces, APPEND concatenates (creates if absent, empty append is
a no-op), DELETE removes (absent returns `NotFound`). Non-append empty writes are
represented as DELETE, not SET. Attributes must retain the existing stored bits;
APPEND_WRITE is an operation bit, not a stored bit. Non-delete writes require
NV|BS|RT; obsolete/enhanced authentication is unsupported by EFVS v1. Delete can
submit zero attributes for an unauthenticated existing variable.

Unauthenticated records are accepted as-is subject to structure, attributes,
capacity and write-protection, not signature verification. Boot-services-only
variables can exist in checkpoints but never be mutated by the log: an existing
BS-only variable or submitted attributes without RT are rejected. Independently
of attributes, shim GUID 605dab50-e046-4300-abb6-3dd810dd8b23 names MokList,
MokListX, MokSBState, MokDBState, MokIgnoreDB and MokListTrusted are write-protected.
Global SecureBoot, SetupMode, AuditMode and DeployedMode are firmware-derived,
write-protected names, not caller-controlled runtime policy.

AUTH_2 records retain their complete descriptor until replay. Structural parsing
requires the PKCS#7 certificate GUID, correct WIN_CERTIFICATE revision/type/length,
and valid EFI_TIME representation. The firmware verifier hook sees the state
**at that record**, so KEK then db uses the new KEK. Non-append timestamps must
strictly increase; APPEND follows UEFI's exception (zero/equal/earlier timestamp
permitted, stored timestamp remains the maximum). Attribute changes are refused.
Only successfully applied authenticated operations increment the cumulative count.
Rejected records consume sequence numbers but do not mutate variables or count.
The replay result reports accepted/rejected operations, accepted auth writes and
torn-tail position. A working-set capacity failure refuses replay rather than
silently losing a valid write.

Kernel pre-check decision: always enforce structure, name protection, attribute
and timestamp rules. Signature pre-check runs **only when a verifier is supplied**.
A future deferred-verification deployment may supply a transport verifier that
explicitly defers crypto; it must never be presented as firmware verification.
The shipped policy supplies no such success stub: crypto is unsupported, and
Policy None refuses authenticated writes synchronously. Firmware verification
remains authoritative, regardless of an optional kernel pre-check.

### Official Secure Boot policy: None

There is **no compiled-in root set**, no PK/KEK/db/dbx trust and SecureBoot=0.
The EFI mode is Setup (SetupMode=1), unlike the source document's production
"never Setup Mode" claim. Missing/unreadable/malformed/rollback-refused stores
fall back to an empty policy-controlled store with SecureBoot=0, never fabricated
root keys. The caller owns provisioning that fallback and policy variables.
PolicyNone also drops checkpoint copies of SecureBoot, SetupMode, AuditMode and
DeployedMode (`WriteProtected`): offline bytes cannot override these derived values.

At append, PolicyNone returns `SecurityViolation` (EFI_SECURITY_VIOLATION) for
PK and KEK in the EFI global namespace, db/dbx/dbt/dbr in the image-security
namespace, and **all** time-based/other authenticated variables, regardless of
name. An unauthenticated attempt to disguise a protected key also fails.
At replay, the same entries in a checkpoint are dropped and those log writes are
rejected and counted; processing continues. BS-only log writes return
`WriteProtected` (EFI_WRITE_PROTECTED). Other mappings: `NotFound` = EFI_NOT_FOUND,
`Full` = EFI_OUT_OF_RESOURCES, `InvalidParameter` = EFI_INVALID_PARAMETER,
`Unsupported` = EFI_UNSUPPORTED. Codec errors invalidate the region or terminate
the log, never become a successful variable write.

## Freshness, compaction and posture

Compare checkpoint cumulative count + newly accepted auth writes with the anchor:
count < anchor returns `Rollback`, refusing the store. A restored older image with
a newly instantiated NoneAnchor (read=0) is accepted, explicitly tier 0. NoneAnchor
is a real no-persistence implementation; its value and lock are boot-local. Its
`bump` still enforces strictly increasing values and refuses after `lock`. Equal
count compactions skip bump. Real backend implementations must enforce these
rules internally, not trust their callers.

`AnchorOps` exposes read/bump/lock/capabilities. Capability bits are NONE=0,
MONOTONIC=1, RUNTIME_BUMP=2 (the latter requires MONOTONIC).
TPM2 NV, OP-TEE RPMB and Qualcomm devinfo are **authorised primitive stubs**,
returning typed `Unsupported` for every operation and advertising no capability.
Qualcomm's reserved rollback index is 31; no device I/O or milestone is implemented.
`commit_anchor` only bumps after durable data writes and then locks before EBS.

Compaction first replays into caller scratch and rejects rollback. `compact_durable`
then implements the only supported persistence order:

1. Encode the resulting state, next sequence and cumulative authenticated count into
   the **inactive** checkpoint slot. Write that complete aligned slot and flush.
2. Encode the inactive header with generation `active + 1`, referring to that slot.
   Write its **entire physical header block** (64 bytes plus zero padding), then flush.
   The old active header/checkpoint pair has not been touched.
3. Zero the shared log and flush it. Only then bump (if greater) and lock the anchor.

Before the new header is durable, the old pair and original log recover the
pre-compaction state. Afterwards the new checkpoint recovers the post-compaction
state. A stale or partly erased old log has the old checkpoint's link/sequence and
terminates immediately; it cannot be applied on top of the new checkpoint.
Interrupted log clearing is finished by the next boot compaction before appending.
No scan past a bad first record is permitted. If the working checkpoint is already
identical, compaction preserves the generation and only clears a dirty log; a clean
no-op writes nothing and remains byte-identical.

`compact` stages the final image without I/O; callers must not persist it as a
whole-image write. `CompactionIo` and `compact_durable` share the above write/flush
order between firmware and host. The returned u64 is the cumulative new anchor
value, **not** old anchor plus that already cumulative count. A failed I/O invalidates
the tentative staging image; reload before reuse. The guarantees require honest
flush barriers and a torn write that damages only its addressed physical write units.
An arbitrary later corruption can recover an older checkpoint but does not promise
that its already-cleared historical log is still available. This is crash atomicity,
not indefinite redundant history or checkpoint authentication.
No verified runtime write is published until its record has been appended and flushed.

Nominal source tiers are 0=no protected freshness, 1=boot-time monotonic freshness,
2=runtime monotonic freshness. **All current code reports tier 0**, even if supplied
MONOTONIC capability bits, because production verification and checkpoint
provenance do not exist. Tier 0 under Policy None is *not authenticated integrity*;
SHA-256 only detects accidental damage, not hostile changes. No equivalence to
SMM, StMM or RPMB is claimed by this implementation.

### Spec correction: checkpoint provenance

The source assumes firmware is the checkpoint writer but puts its bytes on an
untrusted partition. An attacker can rewrite values **and auth_count**, recompute
SHA-256, and satisfy a 64-bit counter check. Thus signed log entries and an anchor
alone do not authenticate the checkpoint, nor the serialized cumulative count.
A production design must bind state/history and counter together. Candidate fixes:

1. Retain accepted AUTH_2 descriptors for authenticated variables in checkpoints
   and re-verify on load; preserve sufficient authority/history for key rotation,
   authenticated deletes and the cumulative count, not just each last value.
2. Bind checkpoint digest plus count into an authenticated freshness primitive with
   at least 32 bytes of protected digest storage (TPM NV or RPMB). Qualcomm's
   64-bit rollback slot alone cannot hold that binding.
3. MAC the checkpoint with a platform-held secret, e.g. a TEE service, with replay
   protection tied to the anchor.

No crypto for these candidates is implemented. Checkpoint provenance flags at
64, 28 extension bytes at 68, and per-entry flags at 10 reserve representation
space: a future descriptor/history trailer can be delimited by these fields;
an external protected digest binding needs only a provenance flag. This permits
an additive v1 profile without changing the base geometry. Present decoders reject
all nonzero reserved fields: support must be explicitly negotiated/implemented,
not silently enabled. No untrusted provenance flag can raise the posture tier.

## Configuration table (48 bytes)

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | ASCII `EFVT` |
| 4 | 2 | format version = 1 |
| 6 | 2 | table length = 48 |
| 8 | 16 | partition unique GUID |
| 24 | 1 | posture tier = 0 in this implementation |
| 25 | 3 | zero |
| 28 | 4 | capability bits |
| 32 | 8 | current anchor value |
| 40 | 8 | reserved zero |

Publish in firmware-owned memory under CONFIG_TABLE_GUID. It contains no pointers;
byte codecs avoid ABI packing assumptions. Format GUID and partition type GUID
are different from the per-device partition GUID in this table.

## Host tools

```
efivar-store init --efvs --image vars.img --size 1048576
efivar-store --image vars.img inspect
efivar-store --image vars.img set --name BootOrder --guid 8be4df61-93ca-11d2-aa0d-00e098032b8c --attributes 7 --data-file order.bin
efivar-store --image vars.img compact
efivar-store import-edk2 --from old.fd --image vars.img --size 1048576 --force
```

`inspect/list/get/set/delete/oneshot` detect EFVS by header magic; edk2 commands
remain compatible. EFVS writes lock, reload, append **only the record range**,
fsync and verify readback. Compaction/import are offline image operations, not
runtime garbage collection; compact refuses `--device`. Policy None is used by
the host, so authenticated values imported for preservation disappear from its
replayed live view. Inspect still reports raw checkpoint count/digest and rejects.

Source: owner's “Block-Backed EFI Variables with Deferred Verification”, 2026-10-07;
AUTH_2 signing input is UEFI 2.10 §8.2.6 (not §8.2.2, which is enumeration).
Unresolved platform evidence: Qualcomm VBRwDeviceState success before milestone
must be proven on the target; this repository performs no device commands.
