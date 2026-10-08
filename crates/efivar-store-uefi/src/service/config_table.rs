//! Runtime-owned EFVS discovery data with reverse boot-time restoration.
use core::{ffi::c_void, ptr, ptr::NonNull};
use efivar_store::efvs;
use r_efi::efi::{self, Status};
const GUID: efi::Guid = efi::Guid::from_fields(
    0x930e89ed,
    0x540e,
    0x4af0,
    0x9b,
    0x41,
    &[0xc2, 0xc5, 0x59, 0x93, 0x9d, 0x50],
);
pub(super) struct Publication {
    boot: NonNull<efi::BootServices>,
    original: *mut c_void,
    address: u64,
}
impl Publication {
    pub(super) fn install(
        table: NonNull<efi::SystemTable>,
        config: efvs::ConfigTable,
    ) -> Result<Self, Status> {
        let mut bytes = [0; efvs::CONFIG_TABLE_SIZE];
        config
            .encode(&mut bytes)
            .map_err(|_| Status::INVALID_PARAMETER)?;
        // SAFETY: caller supplies the initialized system table before EBS.
        let system = unsafe { table.as_ref() };
        let boot = NonNull::new(system.boot_services).ok_or(Status::NOT_READY)?;
        let mut original = ptr::null_mut();
        if system.number_of_table_entries != 0 {
            if system.configuration_table.is_null() {
                return Err(Status::COMPROMISED_DATA);
            }
            // SAFETY: firmware owns the advertised configuration array.
            let entries = unsafe {
                core::slice::from_raw_parts(
                    system.configuration_table,
                    system.number_of_table_entries,
                )
            };
            if let Some(entry) = entries.iter().find(|entry| entry.vendor_guid == GUID) {
                original = entry.vendor_table;
            }
        }
        let mut address = 0;
        // SAFETY: live boot services and writable allocation output.
        let status = unsafe {
            (boot.as_ref().allocate_pages)(
                efi::ALLOCATE_ANY_PAGES,
                efi::RUNTIME_SERVICES_DATA,
                1,
                &mut address,
            )
        };
        if status.is_error() {
            return Err(status);
        }
        let output = address as usize as *mut u8;
        // SAFETY: one owned runtime page covers the encoded table and all padding.
        unsafe {
            ptr::write_bytes(output, 0, 4096);
            ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
        }
        let mut guid = GUID;
        // SAFETY: allocation survives publication until restoration or runtime handoff.
        let status =
            unsafe { (boot.as_ref().install_configuration_table)(&mut guid, output.cast()) };
        if status.is_error() {
            // SAFETY: failed publication retains no reference to the owned page.
            let _ = unsafe { (boot.as_ref().free_pages)(address, 1) };
            return Err(status);
        }
        Ok(Self {
            boot,
            original,
            address,
        })
    }
    pub(super) fn restore(&mut self) -> Result<(), Status> {
        if self.address == 0 {
            return Ok(());
        }
        let mut guid = GUID;
        // SAFETY: restore is only called while boot services are live.
        let status =
            unsafe { (self.boot.as_ref().install_configuration_table)(&mut guid, self.original) };
        if status.is_error() {
            return Err(status);
        }
        // SAFETY: no configuration entry references the owned page now.
        let status = unsafe { (self.boot.as_ref().free_pages)(self.address, 1) };
        self.address = 0;
        if status.is_error() {
            Err(status)
        } else {
            Ok(())
        }
    }
}
