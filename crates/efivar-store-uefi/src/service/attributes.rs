//! Correct the firmware Memory Attributes Table entry for our copied runtime
//! code so it agrees with the firmware page tables.
//!
//! edk2 marks a runtime-code region that is not part of a loaded image with
//! `EFI_MEMORY_XP` when the DXE NX policy covers `EfiRuntimeServicesCode`
//! (image code sections are exempted by PE section splitting). Firmware that
//! honours the table — Linux `efi_runtime_update_mappings` — then maps the
//! region non-executable and the first runtime call faults. Our own seal call
//! clears `IA32_PG_NX` in the firmware page tables, so the table is the only
//! remaining source of the stale attribute. This does not widen permissions:
//! the entry keeps `EFI_MEMORY_RO` and only clears the execute-disable bit that
//! contradicts the sealed executable page, and no other entry is touched.

use core::{ffi::c_void, ptr, ptr::NonNull};
use r_efi::efi::{self, Status};

const ATTRIBUTES_GUID: efi::Guid = efi::Guid::from_fields(
    0xdcfa_911d,
    0x26eb,
    0x469f,
    0xa2,
    0x20,
    &[0x38, 0xb7, 0xdc, 0x46, 0x12, 0x20],
);
const HEADER: usize = 16;
const DESCRIPTOR: usize = 40;
const XP: u64 = 0x0000_0000_0000_4000;
const MAX_ENTRIES: u32 = 64 * 1024;
const PAGE: u64 = 4096;

pub(super) struct Correction {
    boot: NonNull<efi::BootServices>,
    original: *mut c_void,
    address: u64,
    pages: usize,
}

/// Copy the validated descriptor at `index`, overriding address, page count and
/// attributes only when `rewrite` is set. Returns the destination index used.
fn emit(
    output: *mut u8,
    index: usize,
    source: *const u8,
    descriptor: usize,
    rewrite: Option<(u64, u64, u64)>,
) -> usize {
    // SAFETY: `index` and `source` are validated against the copied table and
    // the allocated replacement spans `index + 1` descriptors.
    unsafe {
        let destination = output.add(HEADER + index * descriptor);
        ptr::copy_nonoverlapping(source, destination, descriptor);
        if let Some((start, pages, attributes)) = rewrite {
            ptr::write_unaligned(destination.add(8).cast::<u64>(), start);
            ptr::write_unaligned(destination.add(24).cast::<u64>(), pages);
            ptr::write_unaligned(destination.add(32).cast::<u64>(), attributes);
        }
    }
    index + 1
}

impl Correction {
    /// Correct exactly `code = (start, pages)`; a no-op while the firmware
    /// publishes no Memory Attributes Table.
    pub(super) fn install(
        table: NonNull<efi::SystemTable>,
        code: (u64, usize),
    ) -> Result<Self, Status> {
        // SAFETY: install receives the live system table before EBS.
        let system = unsafe { table.as_ref() };
        let boot = NonNull::new(system.boot_services).ok_or(Status::NOT_READY)?;
        let mut correction = Self {
            boot,
            original: ptr::null_mut(),
            address: 0,
            pages: 0,
        };
        if system.number_of_table_entries == 0 || system.configuration_table.is_null() {
            return Ok(correction);
        }
        // SAFETY: the system table advertises this initialized entry array.
        let entries = unsafe {
            core::slice::from_raw_parts(system.configuration_table, system.number_of_table_entries)
        };
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.vendor_guid == ATTRIBUTES_GUID)
        else {
            return Ok(correction);
        };
        if entry.vendor_table.is_null() {
            return Err(Status::COMPROMISED_DATA);
        }
        let source = entry.vendor_table.cast::<u8>();
        // SAFETY: the GUID names a live table header of four u32 fields.
        let (version, count, descriptor) = unsafe {
            (
                ptr::read_unaligned(source.cast::<u32>()),
                ptr::read_unaligned(source.add(4).cast::<u32>()),
                ptr::read_unaligned(source.add(8).cast::<u32>()) as usize,
            )
        };
        if version > 2 || descriptor < DESCRIPTOR || count > MAX_ENTRIES {
            return Err(Status::COMPROMISED_DATA);
        }
        let Some(size) = (descriptor as u64)
            .checked_mul(u64::from(count))
            .and_then(|bytes| bytes.checked_add(HEADER as u64))
            .and_then(|bytes| usize::try_from(bytes).ok())
        else {
            return Err(Status::COMPROMISED_DATA);
        };
        let pages = size.div_ceil(4096);
        let mut address = 0_u64;
        // SAFETY: live boot services and a writable allocation output.
        let status = unsafe {
            (boot.as_ref().allocate_pages)(
                efi::ALLOCATE_ANY_PAGES,
                efi::RUNTIME_SERVICES_DATA,
                pages,
                &mut address,
            )
        };
        if status.is_error() {
            return Err(status);
        }
        let output = address as usize as *mut u8;
        let (start, length) = (code.0, (code.1 as u64) * PAGE);
        let Some(end) = start.checked_add(length) else {
            // SAFETY: the allocation is unpublished and owned by this call.
            let _ = unsafe { (boot.as_ref().free_pages)(address, pages) };
            return Err(Status::COMPROMISED_DATA);
        };
        let mut written = 0_usize;
        for index in 0..count as usize {
            let record = source.wrapping_add(HEADER + index * descriptor);
            // SAFETY: index is within the validated descriptor array.
            let (physical, count_pages, attributes) = unsafe {
                (
                    ptr::read_unaligned(record.add(8).cast::<u64>()),
                    ptr::read_unaligned(record.add(24).cast::<u64>()),
                    ptr::read_unaligned(record.add(32).cast::<u64>()),
                )
            };
            let region_end = physical.saturating_add(count_pages.saturating_mul(PAGE));
            // Only a record that is marked non-executable and contains the whole
            // code range is corrected; everything else is copied verbatim.
            if attributes & XP == 0 || physical > start || region_end < end {
                written = emit(output, written, record, descriptor, None);
                continue;
            }
            if physical < start {
                written = emit(
                    output,
                    written,
                    record,
                    descriptor,
                    Some((physical, (start - physical) / PAGE, attributes)),
                );
            }
            written = emit(
                output,
                written,
                record,
                descriptor,
                Some((start, length / PAGE, attributes & !XP)),
            );
            if region_end > end {
                written = emit(
                    output,
                    written,
                    record,
                    descriptor,
                    Some((end, (region_end - end) / PAGE, attributes)),
                );
            }
        }
        if written > count as usize + 2 {
            // SAFETY: unpublished allocation owned by this call.
            let _ = unsafe { (boot.as_ref().free_pages)(address, pages) };
            return Err(Status::COMPROMISED_DATA);
        }
        // SAFETY: the replacement header precedes the copied descriptor array.
        unsafe {
            ptr::copy_nonoverlapping(source, output, HEADER);
            ptr::write_unaligned(output.add(4).cast::<u32>(), written as u32);
        }
        correction.original = entry.vendor_table;
        correction.address = address;
        correction.pages = pages;
        let mut guid = ATTRIBUTES_GUID;
        // SAFETY: the replacement lives in runtime memory and retains every
        // firmware entry except the corrected code page.
        let status =
            unsafe { (boot.as_ref().install_configuration_table)(&mut guid, output.cast()) };
        if status.is_error() {
            // SAFETY: failed publication retains no reference to this allocation.
            let _ = unsafe { (boot.as_ref().free_pages)(address, pages) };
            return Err(status);
        }
        Ok(correction)
    }

    pub(super) fn restore(&mut self) -> Result<(), Status> {
        if self.address == 0 {
            return Ok(());
        }
        let mut guid = ATTRIBUTES_GUID;
        // SAFETY: live boot services revert the table to the firmware's own.
        let status =
            unsafe { (self.boot.as_ref().install_configuration_table)(&mut guid, self.original) };
        let address = self.address;
        let pages = self.pages;
        self.address = 0;
        if status.is_error() {
            return Err(status);
        }
        // SAFETY: the configuration table no longer references this allocation.
        let freed = unsafe { (self.boot.as_ref().free_pages)(address, pages) };
        if freed.is_error() { Err(freed) } else { Ok(()) }
    }
}
