use core::{ffi::c_void, ptr, ptr::NonNull};
use r_efi::efi::{self, Status};
const GUID: efi::Guid = efi::Guid::from_fields(
    0xeb66_918a,
    0x7eef,
    0x402a,
    0x84,
    0x2e,
    &[0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9],
);
#[repr(C)]
struct Properties {
    version: u16,
    length: u16,
    supported: u32,
}
pub(super) struct Publication {
    boot: NonNull<efi::BootServices>,
    original: *mut c_void,
    address: u64,
}
impl Publication {
    pub(super) fn install(table: NonNull<efi::SystemTable>) -> Result<Self, Status> {
        // SAFETY: install receives the live initialized system table before EBS.
        let system = unsafe { table.as_ref() };
        let boot = NonNull::new(system.boot_services).ok_or(Status::NOT_READY)?;
        let mut original = ptr::null_mut();
        let mut supported = 0x3fff;
        if system.number_of_table_entries != 0 {
            if system.configuration_table.is_null() {
                return Err(Status::COMPROMISED_DATA);
            }
            // SAFETY: EFI system table advertises this initialized configuration array.
            let entries = unsafe {
                core::slice::from_raw_parts(
                    system.configuration_table,
                    system.number_of_table_entries,
                )
            };
            if let Some(entry) = entries.iter().find(|e| e.vendor_guid == GUID) {
                original = entry.vendor_table;
                if original.is_null() {
                    return Err(Status::COMPROMISED_DATA);
                }
                // SAFETY: GUID identifies an eight-byte runtime properties header.
                let p = unsafe { ptr::read_unaligned(original.cast::<Properties>()) };
                if p.version != 1 || p.length < 8 {
                    return Err(Status::COMPROMISED_DATA);
                }
                supported = p.supported;
            }
        }
        let mut address = 0;
        // SAFETY: live boot services and writable page allocation output.
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
        let properties = address as usize as *mut Properties;
        // SAFETY: allocated runtime page is writable and aligned for Properties.
        unsafe {
            properties.write(Properties {
                version: 1,
                length: 8,
                supported: (supported | 0x2030) & !0x01c0,
            })
        };
        let mut guid = GUID;
        // SAFETY: pointer remains owned through rollback or successful EBS.
        let status =
            unsafe { (boot.as_ref().install_configuration_table)(&mut guid, properties.cast()) };
        if status.is_error() {
            // SAFETY: failed publication retains no reference to this owned page.
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
        // SAFETY: before EBS restore the original firmware entry (null removes ours).
        let status =
            unsafe { (self.boot.as_ref().install_configuration_table)(&mut guid, self.original) };
        if status.is_error() {
            return Err(status);
        }
        // SAFETY: configuration table no longer references our owned page.
        let status = unsafe { (self.boot.as_ref().free_pages)(self.address, 1) };
        self.address = 0;
        if status.is_error() {
            Err(status)
        } else {
            Ok(())
        }
    }
}
