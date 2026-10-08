//! Shared snapshot of the live firmware memory map for the lab instruments.
//!
//! The minidump shadow validates whole reserved ranges before it publishes
//! them; the runtime-variable override and the runtime survey look up the one
//! descriptor holding a single address. Both needs read the same captured copy.

use alloc::vec;
use core::{mem::size_of, ptr};
use r_efi::efi::{self, Status};

use crate::service::PAGE_SIZE;

/// A copy of the firmware memory map taken while boot services are live.
pub struct MemoryMap {
    bytes: vec::Vec<u64>,
    size: usize,
    descriptor_size: usize,
}

impl MemoryMap {
    pub fn capture(boot: &efi::BootServices) -> Result<Self, Status> {
        let mut size = 0_usize;
        let mut key = 0_usize;
        let mut descriptor_size = 0_usize;
        let mut version = 0_u32;
        // SAFETY: null/zero is the documented size query.
        let status = unsafe {
            (boot.get_memory_map)(
                &mut size,
                ptr::null_mut(),
                &mut key,
                &mut descriptor_size,
                &mut version,
            )
        };
        if status != Status::BUFFER_TOO_SMALL {
            return Err(status);
        }
        let capacity = size
            .checked_add(PAGE_SIZE)
            .ok_or(Status::OUT_OF_RESOURCES)?;
        let mut bytes = vec![0_u64; capacity.div_ceil(size_of::<u64>())];
        size = bytes.len() * size_of::<u64>();
        // SAFETY: bytes is writable for the supplied size.
        check(unsafe {
            (boot.get_memory_map)(
                &mut size,
                bytes.as_mut_ptr().cast(),
                &mut key,
                &mut descriptor_size,
                &mut version,
            )
        })?;
        if descriptor_size < size_of::<efi::MemoryDescriptor>() {
            return Err(Status::COMPROMISED_DATA);
        }
        Ok(Self {
            bytes,
            size,
            descriptor_size,
        })
    }

    /// The descriptor that contains all of `[address, address + size)`.
    pub fn containing(&self, address: u64, size: usize) -> Result<efi::MemoryDescriptor, Status> {
        if size == 0 {
            return Err(Status::BAD_BUFFER_SIZE);
        }
        let end = address
            .checked_add(u64::try_from(size).map_err(|_| Status::BAD_BUFFER_SIZE)?)
            .ok_or(Status::BAD_BUFFER_SIZE)?;
        let bytes = self.bytes.as_ptr().cast::<u8>();
        for offset in
            (0..self.size / self.descriptor_size).map(|index| index * self.descriptor_size)
        {
            // SAFETY: the firmware stride was validated against the descriptor size.
            let descriptor =
                unsafe { ptr::read_unaligned(bytes.add(offset).cast::<efi::MemoryDescriptor>()) };
            let descriptor_end = descriptor.physical_start.checked_add(
                descriptor
                    .number_of_pages
                    .checked_mul(PAGE_SIZE as u64)
                    .ok_or(Status::COMPROMISED_DATA)?,
            );
            if descriptor.physical_start <= address
                && descriptor_end.is_some_and(|value| end <= value)
            {
                return Ok(descriptor);
            }
        }
        Err(Status::NOT_FOUND)
    }

    /// Require `[address, address + size)` to be writable reserved memory.
    #[cfg(feature = "lab")]
    pub fn require_writable_reserved(&self, address: u64, size: usize) -> Result<(), Status> {
        let descriptor = self.containing(address, size)?;
        if descriptor.r#type != efi::RESERVED_MEMORY_TYPE
            || descriptor.attribute & (efi::MEMORY_RO | efi::MEMORY_WP) != 0
        {
            return Err(Status::ACCESS_DENIED);
        }
        Ok(())
    }

    /// Require `[address, address + size)` to be readable reserved memory.
    #[cfg(feature = "lab")]
    pub fn require_readable_reserved(&self, address: u64, size: usize) -> Result<(), Status> {
        let descriptor = self.containing(address, size)?;
        if descriptor.r#type != efi::RESERVED_MEMORY_TYPE {
            return Err(Status::ACCESS_DENIED);
        }
        Ok(())
    }

    /// The descriptor containing `address`, with saturating end arithmetic.
    pub fn descriptor_at(&self, address: u64) -> Option<efi::MemoryDescriptor> {
        let bytes = self.bytes.as_ptr().cast::<u8>();
        for offset in
            (0..self.size / self.descriptor_size).map(|index| index * self.descriptor_size)
        {
            // SAFETY: the firmware stride was validated against the descriptor size.
            let descriptor =
                unsafe { ptr::read_unaligned(bytes.add(offset).cast::<efi::MemoryDescriptor>()) };
            let end = descriptor
                .physical_start
                .saturating_add(descriptor.number_of_pages.saturating_mul(PAGE_SIZE as u64));
            if (descriptor.physical_start..end).contains(&address) {
                return Some(descriptor);
            }
        }
        None
    }
}

fn check(status: Status) -> Result<(), Status> {
    if status.is_error() {
        Err(status)
    } else {
        Ok(())
    }
}
