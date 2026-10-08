//! Shared private-runtime-table placement, sealing and reverse cleanup.
//!
//! This is deliberately not a variable-store implementation. It places four
//! position-independent callbacks in `EfiRuntimeServicesCode`, publishes a
//! private `EfiRuntimeServicesData` table before handoff, and swaps that
//! table's variable-service entries from an ExitBootServices notification.
//! The callbacks, their pre-EBS self-test, the ExitBootServices interposer and
//! the post-EBS proof belong to `proof`; this module owns placement, sealing,
//! publication, CRC maintenance, rollback and the pending/ready/failed state.

use alloc::boxed::Box;
#[cfg(feature = "lab")]
use alloc::{vec, vec::Vec};
use core::{
    ffi::c_void,
    mem::size_of,
    ptr::{self, NonNull, addr_of, addr_of_mut},
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};
use r_efi::efi::{self, Status};

use crate::service::{PAGE_SIZE, cache, memory_map::MemoryMap};

const PATCH_PENDING: usize = 1;
const PATCH_READY: usize = 2;
const PATCH_FAILED: usize = 3;
#[cfg(feature = "lab")]
const MAP_BYTES: usize = 64 * 1024;

const CPU_ARCH_PROTOCOL_GUID: efi::Guid = efi::Guid::from_fields(
    0x26ba_ccb1,
    0x6f42,
    0x11d4,
    0xbc,
    0xe7,
    &[0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
);

type CpuSetMemoryAttributes = unsafe extern "efiapi" fn(
    this: *mut CpuArchProtocol,
    base: efi::PhysicalAddress,
    length: u64,
    attributes: u64,
) -> Status;

#[repr(C)]
struct CpuArchProtocol {
    preceding_methods: [*mut c_void; 7],
    set_memory_attributes: Option<CpuSetMemoryAttributes>,
}

static PATCH_STATE: AtomicUsize = AtomicUsize::new(0);
static PUBLISHED_CONTEXT: AtomicPtr<EventContext> = AtomicPtr::new(ptr::null_mut());

/// The four position-independent callbacks and the linker-delimited blob that
/// carries them and their constants, as delimited by the proof's assembly.
pub enum Report {
    SelfTest,
    Armed { code: u64, table: u64 },
}

pub struct CallbackBlob {
    pub start: usize,
    pub size: usize,
    pub get_variable: usize,
    pub get_next_variable_name: usize,
    pub set_variable: usize,
    pub query_variable_info: usize,
    pub index: Option<(usize, usize)>,
}

/// Proof-supplied wiring this mechanism cannot implement itself.
pub struct ProofWiring {
    /// Entry installed in `BootServices.ExitBootServices` before publication.
    pub report: fn(Report),
    pub interposer: Option<efi::BootExitBootServices>,
    /// Verifies the copied callbacks before the private table is published.
    pub self_test: fn(
        efi::RuntimeGetVariable,
        efi::RuntimeGetNextVariableName,
        efi::RuntimeSetVariable,
        efi::RuntimeQueryVariableInfo,
    ) -> Result<(), Status>,
    /// Snapshots the proof diagnostics before the runtime-table entry swap.
    pub snapshot: fn() -> bool,
    /// Allocation-free optional event diagnostics; product uses no diagnostics.
    pub mark: fn(u64, u64) -> bool,
}

#[repr(C)]
pub struct EventContext {
    #[cfg(feature = "lab")]
    pub boot: NonNull<efi::BootServices>,
    pub runtime: NonNull<efi::RuntimeServices>,
    pub original_exit_boot_services: efi::BootExitBootServices,
    pub calculate_crc32: efi::BootCalculateCrc32,
    get_variable: efi::RuntimeGetVariable,
    get_next_variable_name: efi::RuntimeGetNextVariableName,
    set_variable: efi::RuntimeSetVariable,
    query_variable_info: efi::RuntimeQueryVariableInfo,
    #[cfg(feature = "lab")]
    interposer: Option<efi::BootExitBootServices>,
    snapshot: fn() -> bool,
    mark: fn(u64, u64) -> bool,
    #[cfg(feature = "lab")]
    pub map: Vec<u64>,
}

pub struct Override {
    table: NonNull<efi::SystemTable>,
    original_services: NonNull<efi::BootServices>,
    original_runtime: NonNull<efi::RuntimeServices>,
    runtime_address: efi::PhysicalAddress,
    runtime_pages: usize,
    event: efi::Event,
    context: NonNull<EventContext>,
    code_address: efi::PhysicalAddress,
    code_pages: usize,
    armed: bool,
}

impl Override {
    /// Place the proof's callbacks in runtime code, publish a private runtime
    /// table and arm the EBS-group entry swap.
    pub fn install(
        table: NonNull<efi::SystemTable>,
        callbacks: CallbackBlob,
        wiring: ProofWiring,
    ) -> Result<Self, Status> {
        if PATCH_STATE
            .compare_exchange(0, PATCH_PENDING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Status::ALREADY_STARTED);
        }
        match Self::install_inner(table, callbacks, wiring) {
            Ok(value) => Ok(value),
            Err(error) => {
                PATCH_STATE.store(0, Ordering::Release);
                Err(error)
            }
        }
    }

    fn install_inner(
        mut table: NonNull<efi::SystemTable>,
        callbacks: CallbackBlob,
        wiring: ProofWiring,
    ) -> Result<Self, Status> {
        let ProofWiring {
            interposer,
            report,
            self_test,
            snapshot,
            mark,
        } = wiring;
        // SAFETY: std initialized the live writable system table before main.
        let system = unsafe { table.as_mut() };
        let original_services = NonNull::new(system.boot_services).ok_or(Status::NOT_READY)?;
        let original_runtime = NonNull::new(system.runtime_services).ok_or(Status::NOT_READY)?;
        // SAFETY: both tables belong to the live firmware environment.
        let services = unsafe { original_services.as_ref() };

        let blob_start = callbacks.start;
        let blob_size = callbacks.size;
        let get_variable_offset =
            blob_offset(callbacks.get_variable as *const u8, blob_start, blob_size)?;
        let get_next_variable_name_offset = blob_offset(
            callbacks.get_next_variable_name as *const u8,
            blob_start,
            blob_size,
        )?;
        let set_variable_offset =
            blob_offset(callbacks.set_variable as *const u8, blob_start, blob_size)?;
        let query_variable_info_offset = blob_offset(
            callbacks.query_variable_info as *const u8,
            blob_start,
            blob_size,
        )?;
        let code_pages = blob_size.div_ceil(PAGE_SIZE);
        let mut code_address = 0_u64;
        // SAFETY: the output address is writable and the requested runtime-code
        // pages remain owned by this object until EBS or rollback.
        let status = unsafe {
            (services.allocate_pages)(
                efi::ALLOCATE_ANY_PAGES,
                efi::RUNTIME_SERVICES_CODE,
                code_pages,
                &mut code_address,
            )
        };
        check(status)?;
        let code = usize::try_from(code_address).map_err(|_| Status::UNSUPPORTED)? as *mut u8;
        // SAFETY: firmware allocated `code_pages * PAGE_SIZE` writable bytes and
        // the linker-delimited blob is readable for exactly `blob_size` bytes.
        unsafe { ptr::copy_nonoverlapping(blob_start as *const u8, code, blob_size) };
        if let Some((offset, address)) = callbacks.index {
            if offset
                .checked_add(size_of::<usize>())
                .is_none_or(|end| end > blob_size)
            {
                // SAFETY: the allocation is unpublished and owned by install.
                let _ = unsafe { (services.free_pages)(code_address, code_pages) };
                return Err(Status::COMPROMISED_DATA);
            }
            // SAFETY: checked linker slot lies within this writable copied blob.
            unsafe { code.add(offset).cast::<usize>().write_unaligned(address) };
        }
        // SAFETY: the copied bytes are AArch64 instructions plus position-relative
        // constants; make the write visible to instruction fetch before publication.
        unsafe { cache::sync_instruction_cache(code, blob_size) };
        if let Err(error) = seal_runtime_code(services, code_address, code_pages) {
            // SAFETY: no callback pointer has been published.

            let _ = unsafe { (services.free_pages)(code_address, code_pages) };
            return Err(error);
        }
        let mapping = match locate_mapping(services, code_address) {
            Ok(mapping) => mapping,
            Err(error) => {
                // SAFETY: no callback pointer or event has been published yet.
                let _ = unsafe { (services.free_pages)(code_address, code_pages) };
                return Err(error);
            }
        };
        if mapping != (efi::RUNTIME_SERVICES_CODE, true) {
            // SAFETY: no callback pointer or event has been published yet.
            let _ = unsafe { (services.free_pages)(code_address, code_pages) };
            return Err(Status::COMPROMISED_DATA);
        }

        // SAFETY: each copied address names the matching `efiapi` assembly entry
        // in executable runtime code and carries no Rust unwind path.
        let get_variable = unsafe {
            core::mem::transmute::<usize, efi::RuntimeGetVariable>(
                code.wrapping_add(get_variable_offset).addr(),
            )
        };
        // SAFETY: same invariant for GetNextVariableName.
        let get_next_variable_name = unsafe {
            core::mem::transmute::<usize, efi::RuntimeGetNextVariableName>(
                code.wrapping_add(get_next_variable_name_offset).addr(),
            )
        };
        // SAFETY: same invariant for SetVariable.
        let set_variable = unsafe {
            core::mem::transmute::<usize, efi::RuntimeSetVariable>(
                code.wrapping_add(set_variable_offset).addr(),
            )
        };
        // SAFETY: same invariant for QueryVariableInfo.
        let query_variable_info = unsafe {
            core::mem::transmute::<usize, efi::RuntimeQueryVariableInfo>(
                code.wrapping_add(query_variable_info_offset).addr(),
            )
        };

        if let Err(error) = self_test(
            get_variable,
            get_next_variable_name,
            set_variable,
            query_variable_info,
        ) {
            // SAFETY: no callback pointer has been published.
            let _ = unsafe { (services.free_pages)(code_address, code_pages) };
            return Err(error);
        }
        report(Report::SelfTest);
        let runtime_pages = size_of::<efi::RuntimeServices>().div_ceil(PAGE_SIZE);
        let mut runtime_address = 0_u64;
        // SAFETY: the private table must survive EBS and virtual-address conversion.
        let status = unsafe {
            (services.allocate_pages)(
                efi::ALLOCATE_ANY_PAGES,
                efi::RUNTIME_SERVICES_DATA,
                runtime_pages,
                &mut runtime_address,
            )
        };
        if status.is_error() {
            // SAFETY: no code pointer has been published.
            let _ = unsafe { (services.free_pages)(code_address, code_pages) };
            return Err(status);
        }
        let private_runtime = match usize::try_from(runtime_address)
            .ok()
            .and_then(|address| NonNull::new(address as *mut efi::RuntimeServices))
        {
            Some(runtime) => runtime,
            None => {
                release_pages(
                    services,
                    code_address,
                    code_pages,
                    runtime_address,
                    runtime_pages,
                );
                return Err(Status::UNSUPPORTED);
            }
        };
        // SAFETY: the source is the initialized live runtime table and the
        // destination is a disjoint allocation large enough for one table.
        unsafe { ptr::copy_nonoverlapping(original_runtime.as_ptr(), private_runtime.as_ptr(), 1) };
        let runtime_mapping = match locate_mapping(services, runtime_address) {
            Ok(mapping) => mapping,
            Err(error) => {
                release_pages(
                    services,
                    code_address,
                    code_pages,
                    runtime_address,
                    runtime_pages,
                );
                return Err(error);
            }
        };
        if runtime_mapping != (efi::RUNTIME_SERVICES_DATA, true) {
            release_pages(
                services,
                code_address,
                code_pages,
                runtime_address,
                runtime_pages,
            );
            return Err(Status::COMPROMISED_DATA);
        }
        // SAFETY: the copied table is private and writable before publication.
        let private = unsafe { &mut *private_runtime.as_ptr() };
        if let Err(error) = refresh_header_crc(
            addr_of_mut!(private.hdr),
            private_runtime.as_ptr().cast(),
            services.calculate_crc32,
        ) {
            release_pages(
                services,
                code_address,
                code_pages,
                runtime_address,
                runtime_pages,
            );
            return Err(error);
        }

        let context = Box::new(EventContext {
            #[cfg(feature = "lab")]
            boot: original_services,
            runtime: private_runtime,
            original_exit_boot_services: services.exit_boot_services,
            calculate_crc32: services.calculate_crc32,
            get_variable,
            get_next_variable_name,
            set_variable,
            query_variable_info,
            #[cfg(feature = "lab")]
            interposer,
            snapshot,
            mark,
            #[cfg(feature = "lab")]
            map: if interposer.is_some() {
                vec![0_u64; MAP_BYTES / size_of::<u64>()]
            } else {
                Vec::new()
            },
        });
        let context = NonNull::new(Box::into_raw(context)).ok_or(Status::OUT_OF_RESOURCES)?;
        let mut event = ptr::null_mut();
        // SAFETY: context stays pinned through event close or successful EBS.
        let status = unsafe {
            (services.create_event_ex)(
                efi::EVT_NOTIFY_SIGNAL,
                efi::TPL_CALLBACK,
                Some(on_exit_boot_services),
                context.as_ptr().cast(),
                &efi::EVENT_GROUP_EXIT_BOOT_SERVICES,
                &mut event,
            )
        };
        if status.is_error() {
            // SAFETY: event publication failed, so this allocation has no observer.
            unsafe { drop(Box::from_raw(context.as_ptr())) };
            release_pages(
                services,
                code_address,
                code_pages,
                runtime_address,
                runtime_pages,
            );
            return Err(status);
        }

        system.runtime_services = private_runtime.as_ptr();
        if let Err(error) = refresh_header_crc(
            addr_of_mut!(system.hdr),
            table.as_ptr().cast(),
            services.calculate_crc32,
        ) {
            system.runtime_services = original_runtime.as_ptr();
            let _ = refresh_header_crc(
                addr_of_mut!(system.hdr),
                table.as_ptr().cast(),
                services.calculate_crc32,
            );
            // SAFETY: publication was rolled back and the event is still live.
            let _ = unsafe { (services.close_event)(event) };
            // SAFETY: event close completed synchronously.
            unsafe { drop(Box::from_raw(context.as_ptr())) };
            release_pages(
                services,
                code_address,
                code_pages,
                runtime_address,
                runtime_pages,
            );
            return Err(error);
        }

        if PUBLISHED_CONTEXT
            .compare_exchange(
                ptr::null_mut(),
                context.as_ptr(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            rollback_published_runtime(
                services,
                system,
                table,
                original_runtime,
                event,
                context,
                code_address,
                code_pages,
                runtime_address,
                runtime_pages,
            );
            return Err(Status::ALREADY_STARTED);
        }
        if let Err(error) = interposer.map_or(Ok(()), |entry| {
            patch_exit_boot_services(original_services, entry, services.calculate_crc32)
        }) {
            PUBLISHED_CONTEXT.store(ptr::null_mut(), Ordering::Release);
            let _ = patch_exit_boot_services(
                original_services,
                services.exit_boot_services,
                services.calculate_crc32,
            );
            rollback_published_runtime(
                services,
                system,
                table,
                original_runtime,
                event,
                context,
                code_address,
                code_pages,
                runtime_address,
                runtime_pages,
            );
            return Err(error);
        }

        report(Report::Armed {
            code: code_address,
            table: runtime_address,
        });

        Ok(Self {
            table,
            original_services,
            original_runtime,
            runtime_address,
            runtime_pages,
            event,
            context,
            code_address,
            code_pages,
            armed: true,
        })
    }

    /// Physical start and page count of the copied runtime code.
    pub const fn code_range(&self) -> (u64, usize) {
        (self.code_address, self.code_pages)
    }

    pub fn restore(&mut self) -> Result<(), Status> {
        if !self.armed {
            return Ok(());
        }
        // SAFETY: restoration occurs only if the child returned without
        // successful EBS; original boot services and allocations remain live.
        let services = unsafe { self.original_services.as_ref() };
        // SAFETY: the pinned event context remains live until CloseEvent below.
        let context = unsafe { self.context.as_ref() };
        let mut error = None;
        // Product mode never modifies BootServices; only undo an actual interposer.
        if services.exit_boot_services as usize != context.original_exit_boot_services as usize
            && let Err(status) = patch_exit_boot_services(
                self.original_services,
                context.original_exit_boot_services,
                context.calculate_crc32,
            )
        {
            error = Some(status);
        }
        let _ = PUBLISHED_CONTEXT.compare_exchange(
            self.context.as_ptr(),
            ptr::null_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        // SAFETY: this is the live system table patched by install.
        let system = unsafe { self.table.as_mut() };
        system.runtime_services = self.original_runtime.as_ptr();
        if let Err(status) = refresh_header_crc(
            addr_of_mut!(system.hdr),
            self.table.as_ptr().cast(),
            services.calculate_crc32,
        ) {
            error.get_or_insert(status);
        }
        // SAFETY: this is the live event created by install and no callback is active.
        let close = unsafe { (services.close_event)(self.event) };
        if close.is_error() {
            // The event still owns its context/table/code. Retain those pages
            // rather than free memory a later notification can dereference.
            return Err(error.unwrap_or(close));
        }
        // SAFETY: the event is closed synchronously and cannot retain context.
        unsafe { drop(Box::from_raw(self.context.as_ptr())) };
        for (address, pages) in [
            (self.runtime_address, self.runtime_pages),
            (self.code_address, self.code_pages),
        ] {
            // SAFETY: closed event and restored system table retain no references.
            let status = unsafe { (services.free_pages)(address, pages) };
            if status.is_error() {
                error.get_or_insert(status);
            }
        }
        PATCH_STATE.store(0, Ordering::Release);
        self.armed = false;
        error.map_or(Ok(()), Err)
    }
}

impl Drop for Override {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

unsafe extern "efiapi" fn on_exit_boot_services(_: efi::Event, raw: *mut c_void) {
    let Some(mut context) = NonNull::new(raw.cast::<EventContext>()) else {
        PATCH_STATE.store(PATCH_FAILED, Ordering::Release);
        return;
    };
    // SAFETY: install pinned this context through the EBS event lifetime and no
    // concurrent callback exists at TPL_CALLBACK.
    let context = unsafe { context.as_mut() };
    let mark_exit_boot_services = context.mark;
    // SAFETY: the lab shadow owns its trace and snapshot buffers through EBS.
    let runtime_address = context.runtime.as_ptr().addr() as u64;
    if !mark_exit_boot_services(1, runtime_address) || !(context.snapshot)() {
        PATCH_STATE.store(PATCH_FAILED, Ordering::Release);
        return;
    }
    // SAFETY: the same retained trace buffer records callback progress without
    // allocation or boot-service calls.
    let _ = mark_exit_boot_services(2, runtime_address);
    // SAFETY: the firmware runtime table is still writable during the EBS-group
    // callback; memory services are frozen but the table and copied code are live.
    let runtime = unsafe { context.runtime.as_mut() };
    let _ = mark_exit_boot_services(3, runtime_address);
    runtime.get_variable = context.get_variable;
    let _ = mark_exit_boot_services(4, runtime_address);
    runtime.get_next_variable_name = context.get_next_variable_name;
    let _ = mark_exit_boot_services(5, runtime_address);
    runtime.set_variable = context.set_variable;
    let _ = mark_exit_boot_services(6, runtime_address);
    runtime.query_variable_info = context.query_variable_info;
    let _ = mark_exit_boot_services(7, runtime_address);
    let table = runtime as *mut efi::RuntimeServices;
    let _ = mark_exit_boot_services(8, runtime_address);
    let result = refresh_header_crc(
        addr_of_mut!(runtime.hdr),
        table.cast(),
        context.calculate_crc32,
    );
    let _ = mark_exit_boot_services(9, result.err().map_or(0, |status| status.as_usize()) as u64);
    PATCH_STATE.store(
        if result.is_ok() {
            PATCH_READY
        } else {
            PATCH_FAILED
        },
        Ordering::Release,
    );
}

/// Reinstall the proof's interposer after a failed exit.
#[cfg(feature = "lab")]
pub fn rearm_exit_boot_services(context: &EventContext) -> Result<(), Status> {
    context.interposer.map_or(Ok(()), |entry| {
        patch_exit_boot_services(context.boot, entry, context.calculate_crc32)
    })
}

/// Swap one `BootServices` entry and refresh the table checksum.
pub fn patch_exit_boot_services(
    boot: NonNull<efi::BootServices>,
    entry: efi::BootExitBootServices,
    calculate_crc32: efi::BootCalculateCrc32,
) -> Result<(), Status> {
    // SAFETY: callers use the live firmware BootServices table before
    // successful EBS and serialize publication/restoration.
    unsafe { addr_of_mut!((*boot.as_ptr()).exit_boot_services).write(entry) };
    // SAFETY: the same live table has its header at offset zero.
    refresh_header_crc(
        unsafe { addr_of_mut!((*boot.as_ptr()).hdr) },
        boot.as_ptr().cast(),
        calculate_crc32,
    )
}

#[allow(clippy::too_many_arguments)]
fn rollback_published_runtime(
    services: &efi::BootServices,
    system: &mut efi::SystemTable,
    table: NonNull<efi::SystemTable>,
    original_runtime: NonNull<efi::RuntimeServices>,
    event: efi::Event,
    context: NonNull<EventContext>,
    code_address: efi::PhysicalAddress,
    code_pages: usize,
    runtime_address: efi::PhysicalAddress,
    runtime_pages: usize,
) {
    system.runtime_services = original_runtime.as_ptr();
    let _ = refresh_header_crc(
        addr_of_mut!(system.hdr),
        table.as_ptr().cast(),
        services.calculate_crc32,
    );
    // SAFETY: this is the live event created by install and no callback is active.
    let _ = unsafe { (services.close_event)(event) };
    // SAFETY: event close completed synchronously.
    unsafe { drop(Box::from_raw(context.as_ptr())) };
    release_pages(
        services,
        code_address,
        code_pages,
        runtime_address,
        runtime_pages,
    );
}

fn seal_runtime_code(
    services: &efi::BootServices,
    address: efi::PhysicalAddress,
    pages: usize,
) -> Result<(), Status> {
    let mut guid = CPU_ARCH_PROTOCOL_GUID;
    let mut interface = ptr::null_mut::<c_void>();
    // SAFETY: live BootServices and writable protocol output.
    check(unsafe { (services.locate_protocol)(&mut guid, ptr::null_mut(), &mut interface) })?;
    let protocol = NonNull::new(interface.cast::<CpuArchProtocol>()).ok_or(Status::NOT_FOUND)?;
    // SAFETY: the GUID-selected live interface has the PI CPU architecture ABI.
    let set_attributes =
        unsafe { protocol.as_ref().set_memory_attributes }.ok_or(Status::UNSUPPORTED)?;
    let length = u64::try_from(
        pages
            .checked_mul(PAGE_SIZE)
            .ok_or(Status::OUT_OF_RESOURCES)?,
    )
    .map_err(|_| Status::OUT_OF_RESOURCES)?;
    // SAFETY: the caller owns this exact page-aligned runtime-code allocation.
    check(unsafe { set_attributes(protocol.as_ptr(), address, length, efi::MEMORY_RO) })
}

fn blob_offset(symbol: *const u8, start: usize, size: usize) -> Result<usize, Status> {
    symbol
        .addr()
        .checked_sub(start)
        .filter(|offset| *offset < size)
        .ok_or(Status::COMPROMISED_DATA)
}

fn release_pages(
    services: &efi::BootServices,
    code_address: efi::PhysicalAddress,
    code_pages: usize,
    runtime_address: efi::PhysicalAddress,
    runtime_pages: usize,
) {
    // SAFETY: callers own both exact, unpublished firmware allocations.
    let _ = unsafe { (services.free_pages)(runtime_address, runtime_pages) };
    // SAFETY: same ownership invariant for the runtime-code allocation.
    let _ = unsafe { (services.free_pages)(code_address, code_pages) };
}

pub(crate) fn refresh_header_crc(
    header: *mut efi::TableHeader,
    table: *mut c_void,
    calculate_crc32: efi::BootCalculateCrc32,
) -> Result<(), Status> {
    let Some(header) = NonNull::new(header) else {
        return Err(Status::INVALID_PARAMETER);
    };
    // SAFETY: the caller supplies the live header at offset zero in `table`;
    // raw accesses avoid creating an exclusive reference while firmware reads
    // the complete table to calculate its checksum.
    unsafe { addr_of_mut!((*header.as_ptr()).crc32).write(0) };
    // SAFETY: the same initialized header keeps a valid UEFI header size.
    let size = usize::try_from(unsafe { addr_of!((*header.as_ptr()).header_size).read() })
        .map_err(|_| Status::UNSUPPORTED)?;
    let mut crc = 0_u32;
    // SAFETY: caller supplies the complete table named by this live header.
    let status = unsafe { calculate_crc32(table, size, &mut crc) };
    check(status)?;
    // SAFETY: this is the checksum field zeroed above and the firmware call completed.
    unsafe { addr_of_mut!((*header.as_ptr()).crc32).write(crc) };
    Ok(())
}

fn locate_mapping(
    services: &efi::BootServices,
    address: efi::PhysicalAddress,
) -> Result<(u32, bool), Status> {
    let map = MemoryMap::capture(services)?;
    let descriptor = map.descriptor_at(address).ok_or(Status::NOT_FOUND)?;
    Ok((
        descriptor.r#type,
        descriptor.attribute & efi::MEMORY_RUNTIME != 0,
    ))
}

fn check(status: Status) -> Result<(), Status> {
    if status.is_error() {
        Err(status)
    } else {
        Ok(())
    }
}

/// Whether the EBS-group notification completed the runtime-table entry swap.
#[cfg(feature = "lab")]
pub fn swap_ready() -> bool {
    PATCH_STATE.load(Ordering::Acquire) == PATCH_READY
}

/// The context published by the installed override, for the proof's
/// ExitBootServices interposer.
#[cfg(feature = "lab")]
pub fn published_context() -> Option<&'static mut EventContext> {
    let mut context = NonNull::new(PUBLISHED_CONTEXT.load(Ordering::Acquire))?;
    // SAFETY: install pins this context until child return or successful EBS, and
    // clears it only after the event is closed and no callback is active.
    Some(unsafe { context.as_mut() })
}
