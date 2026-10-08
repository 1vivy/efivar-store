//! Allocation-free Linux ABI. All buffers belong to the C backend and remain
//! live until it destroys the context, with calls serialized by its mutex.
#![cfg_attr(not(feature = "host"), no_std)]

use core::slice;
use efivar_store::{
    Guid,
    efvs::{self, Verifier},
};

#[cfg(not(feature = "host"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe extern "C" {
        fn efvs_panic() -> !;
    }
    // SAFETY: The C glue provides a nonreturning panic hook.
    unsafe { efvs_panic() }
}

const fn error(n: usize) -> usize {
    (1usize << (usize::BITS - 1)) | n
}
pub const INVALID: usize = error(2);
pub const DEVICE: usize = error(7);
pub const NOT_FOUND: usize = error(14);
fn map(e: efvs::Error) -> usize {
    match e {
        efvs::Error::Full => error(9),
        efvs::Error::WriteProtected => error(8),
        efvs::Error::SecurityViolation => error(26),
        efvs::Error::Unsupported => error(3),
        efvs::Error::Name | efvs::Error::InvalidParameter => INVALID,
        efvs::Error::NotFound => NOT_FOUND,
        _ => DEVICE,
    }
}
struct Context {
    image: &'static mut [u8],
    state: efvs::State<'static>,
}
#[unsafe(no_mangle)]
pub extern "C" fn efvs_ctx_size() -> usize {
    core::mem::size_of::<Context>()
}

/// # Safety
/// Image points to len readable bytes; output points to writable size_t.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn efvs_scratch_size(
    image: *const u8,
    len: usize,
    output: *mut usize,
) -> usize {
    // SAFETY: Required by the ABI contract.
    let image = unsafe { slice::from_raw_parts(image, len) };
    match efvs::Header::decode(image) {
        Ok(h) => {
            // SAFETY: Caller supplies writable output.
            unsafe { output.write(h.checkpoint_capacity) };
            0
        }
        Err(e) => map(e),
    }
}
/// # Safety
/// ctx is aligned caller storage of efvs_ctx_size bytes. Image and scratch are
/// disjoint writable buffers, live for the context's lifetime. No call may use
/// a previous context or its returned pointers while loading/reloading it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn efvs_load(
    ctx: *mut u8,
    image: *mut u8,
    len: usize,
    scratch: *mut u8,
    scratch_len: usize,
) -> usize {
    // SAFETY: The caller owns disjoint buffers for the context's lifetime.
    let image = unsafe { slice::from_raw_parts_mut(image, len) };
    // SAFETY: See above; replay's state borrows only scratch, not image.
    let scratch = unsafe { slice::from_raw_parts_mut(scratch, scratch_len) };
    match efvs::replay(image, scratch, &mut efvs::PolicyNone, 0) {
        Ok(replay) => {
            // SAFETY: Storage is aligned and large enough; Context needs no drop.
            unsafe {
                ctx.cast::<Context>().write(Context {
                    image,
                    state: replay.state,
                })
            };
            0
        }
        Err(e) => map(e),
    }
}
/// # Safety
/// ctx is loaded; name is len UTF-16LE bytes (without terminator), guid is 16
/// readable bytes. Outputs are writable. Returned data lives until set/load.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn efvs_get(
    ctx: *const u8,
    name: *const u8,
    len: usize,
    guid: *const Guid,
    attr: *mut u32,
    data: *mut *const u8,
    data_len: *mut usize,
) -> usize {
    // SAFETY: All pointers meet the ABI contract.
    let (ctx, name, guid) = unsafe {
        (
            &*ctx.cast::<Context>(),
            slice::from_raw_parts(name, len),
            &*guid,
        )
    };
    let Some(v) = ctx.state.get(name, guid) else {
        return NOT_FOUND;
    };
    // SAFETY: Outputs are writable; the mutex protects the returned view.
    unsafe {
        attr.write(v.attributes);
        data.write(v.data.as_ptr());
        data_len.write(v.data.len());
    }
    0
}
/// # Safety
/// Same input contract as get. Outputs name/data_len/guid point to writable
/// storage; the returned name is a borrowed UTF-16LE byte view until set/load.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn efvs_next(
    ctx: *const u8,
    name: *const u8,
    len: usize,
    guid: *const Guid,
    next_name: *mut *const u8,
    next_len: *mut usize,
    next_guid: *mut Guid,
) -> usize {
    // SAFETY: Required by the ABI contract.
    let (ctx, name, guid) = unsafe {
        (
            &*ctx.cast::<Context>(),
            slice::from_raw_parts(name, len),
            &*guid,
        )
    };
    let mut found = name.is_empty();
    for v in ctx.state.variables() {
        if found {
            // SAFETY: Outputs are writable.
            unsafe {
                next_name.write(v.name.as_ptr());
                next_len.write(v.name.len());
                next_guid.write(v.guid);
            }
            return 0;
        }
        found = v.name == name && v.guid == *guid;
    }
    NOT_FOUND
}
/// # Safety
/// ctx is loaded and exclusively held. Name/guid follow get's contract, data
/// points to data_len readable bytes (non-null even for zero length). Outputs
/// are writable. Persist the returned image range, flush and readback before
/// allowing another call. On failure reread the image and efvs_load it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn efvs_set(
    ctx: *mut u8,
    name: *const u8,
    len: usize,
    guid: *const Guid,
    attr: u32,
    data: *const u8,
    data_len: usize,
    start: *mut usize,
    end: *mut usize,
) -> usize {
    // SAFETY: Required by the ABI contract.
    let (ctx, name, guid, data) = unsafe {
        (
            &mut *ctx.cast::<Context>(),
            slice::from_raw_parts(name, len),
            &*guid,
            slice::from_raw_parts(data, data_len),
        )
    };
    let input = efvs::RecordInput {
        name,
        guid: *guid,
        attributes: attr,
        operation: if attr & efvs::ATTR_APPEND != 0 {
            efvs::Operation::Append
        } else if attr == 0 || data.is_empty() {
            efvs::Operation::Delete
        } else {
            efvs::Operation::Set
        },
        data: if attr == 0 { &[] } else { data },
    };
    // Preserve policy/structure precedence over log exhaustion.
    if let Err(e) = input.encoded_len() {
        return map(e);
    }
    let old = ctx.state.get(name, guid);
    if efvs::boot_services_only(name, guid)
        || old.is_some_and(|v| v.attributes & 4 == 0)
        || (attr != 0 && attr & 4 == 0)
    {
        return error(8);
    }
    if let Err(e) = efvs::PolicyNone.authorize(name, guid, attr) {
        return map(e);
    }
    if let Some(v) = old
        && let Err(e) = efvs::PolicyNone.authorize(v.name, guid, v.attributes)
    {
        return map(e);
    }
    match efvs::append(ctx.image, input, &mut ctx.state, &mut efvs::PolicyNone) {
        Ok(range) => {
            // SAFETY: Outputs are writable.
            unsafe {
                start.write(range.start);
                end.write(range.end);
            }
            0
        }
        Err(e) => map(e),
    }
}
/// # Safety
/// ctx is loaded; all outputs are writable u64 pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn efvs_query(
    ctx: *const u8,
    attr: u32,
    cap: *mut u64,
    remaining: *mut u64,
    largest: *mut u64,
) -> usize {
    if attr != 7 {
        return if attr & !7 != 0 { error(3) } else { INVALID };
    }
    // SAFETY: ctx is loaded and held under the mutex.
    let ctx = unsafe { &*ctx.cast::<Context>() };
    let h = match efvs::Header::decode(ctx.image) {
        Ok(h) => h,
        Err(e) => return map(e),
    };
    let cp = match efvs::Checkpoint::decode(&ctx.image[h.checkpoint_range()]) {
        Ok(cp) => cp,
        Err(e) => return map(e),
    };
    let mut log = efvs::Log::new(&ctx.image[h.log_offset..], cp.hash, cp.next_sequence);
    for _ in log.by_ref() {}
    // SAFETY: Outputs are writable.
    unsafe {
        cap.write(h.log_capacity as u64);
        remaining.write((h.log_capacity - log.consumed) as u64);
        largest.write(
            h.checkpoint_capacity
                .saturating_sub(efvs::CHECKPOINT_HEADER_SIZE + 48 + 2) as u64,
        );
    }
    0
}
