//! Lab-only AArch64 cache maintenance shared by the boot instruments.
//!
//! The minidump shadow publishes SMEM metadata and the runtime-variable
//! override publishes copied callback code, both of which firmware or later
//! runtime code reads without going through Rust. Each sequence names the
//! architectural maintenance operation its caller needs, so they stay separate.

#[cfg(target_arch = "aarch64")]
use core::arch::asm;

/// Read `CTR_EL0`, which reports the data and instruction cache line sizes.
#[cfg(target_arch = "aarch64")]
#[inline]
fn ctr_el0() -> usize {
    let ctr: usize;
    // SAFETY: CTR_EL0 is readable in the AArch64 UEFI environment.
    unsafe {
        asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr, options(nomem, nostack, preserves_flags));
    }
    ctr
}

/// Make `size` bytes of freshly written instructions visible to instruction fetch.
///
/// # Safety
///
/// `start..start + size` must be a mapped, written code range owned by the caller.
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn sync_instruction_cache(start: *mut u8, size: usize) {
    let ctr = ctr_el0();
    let data_line = 4_usize << ((ctr >> 16) & 0xf);
    let instruction_line = 4_usize << (ctr & 0xf);
    let end = start.addr().saturating_add(size);
    let mut current = start.addr() & !(data_line - 1);
    while current < end {
        // SAFETY: cache maintenance accepts every virtual address in the copied range.
        unsafe {
            asm!("dc cvau, {address}", address = in(reg) current, options(nostack, preserves_flags));
        }
        current = current.saturating_add(data_line);
    }
    // SAFETY: order data-cache clean before instruction-cache invalidation.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };
    current = start.addr() & !(instruction_line - 1);
    while current < end {
        // SAFETY: same mapped range, rounded to the architecture line size.
        unsafe {
            asm!("ic ivau, {address}", address = in(reg) current, options(nostack, preserves_flags));
        }
        current = current.saturating_add(instruction_line);
    }
    // SAFETY: complete cache maintenance before publishing function pointers.
    unsafe { asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
}

#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn sync_instruction_cache(_: *mut u8, _: usize) {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}
