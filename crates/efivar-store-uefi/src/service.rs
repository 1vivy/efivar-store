//! EFVS-backed variables before EBS and a frozen read-only EFI runtime view.
//!
//! Install once, before launching children; restore only while boot services are
//! live. The index is physical-address-only: SetVirtualAddressMap is not supported.
//! Direct-partition OS writes leave the already-frozen runtime view stale until reboot.
use crate::backend::Manifest;
use crate::variables::{self as logic, Service, index, runtime};
use alloc::{boxed::Box, vec};
use core::{
    ffi::c_void,
    ptr::{self, NonNull, addr_of, addr_of_mut},
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};
use efivar_store::efvs;
use efivar_store::persist::{Flush, Read, Write};
use r_efi::efi::{self, Status};
mod attributes;
mod cache;
mod config_table;
mod firmware;
pub mod mechanism;
pub mod memory_map;
mod properties;
/// Persistent store and consumer-owned first-boot migration journal.
pub trait BlockBackend: crate::backend::Storage<Error = Status> {}
impl<T: crate::backend::Storage<Error = Status>> BlockBackend for T {}
struct Backend(Box<dyn BlockBackend>);
impl Read for Backend {
    type Error = Status;
    fn read_at(&mut self, offset: usize, output: &mut [u8]) -> Result<(), Status> {
        self.0.read_at(offset, output)
    }
}
impl Write for Backend {
    fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), Status> {
        self.0.write_at(offset, data)
    }
}
impl Flush for Backend {
    fn flush(&mut self) -> Result<(), Status> {
        self.0.flush()
    }
}
impl crate::backend::Storage for Backend {
    fn backup_read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Status> {
        self.0.backup_read(offset, bytes)
    }
    fn backup_write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Status> {
        self.0.backup_write(offset, bytes)
    }
    fn backup_flush(&mut self) -> Result<(), Status> {
        self.0.backup_flush()
    }
}

struct Verifier(Box<dyn efvs::Verifier>);
impl efvs::Verifier for Verifier {
    fn authorize(
        &self,
        name: &[u8],
        guid: &efvs::Guid,
        attributes: u32,
    ) -> Result<(), efvs::Error> {
        self.0.authorize(name, guid, attributes)
    }
    fn verify(
        &mut self,
        request: efvs::RecordInput<'_>,
        authentication: efivar_store::auth::Authentication2<'_>,
        state: &efvs::State<'_>,
    ) -> Result<(), efvs::Error> {
        self.0.verify(request, authentication, state)
    }
}

const PAGE_SIZE: usize = 4096;
static CONTEXT: AtomicPtr<Context> = AtomicPtr::new(ptr::null_mut());
static BUSY: AtomicBool = AtomicBool::new(false);
struct Context {
    service: Service<Backend, firmware::Original, Verifier>,
    snapshot: NonNull<u8>,
}
impl Context {
    fn rebuild(&mut self) -> Result<(), Status> {
        // SAFETY: VariableService owns CAPACITY writable runtime-data bytes until restore/EBS.
        let output =
            unsafe { core::slice::from_raw_parts_mut(self.snapshot.as_ptr(), index::CAPACITY) };
        self.service.snapshot(output).map_err(firmware::status)?;
        index::Reader::parse(output).map_err(firmware::status)?;
        Ok(())
    }
}

pub struct VariableService {
    table: NonNull<efi::SystemTable>,
    original: NonNull<efi::RuntimeServices>,
    context: NonNull<Context>,
    snapshot_address: u64,
    mechanism: Option<mechanism::Override>,
    properties: properties::Publication,
    config_table: Option<config_table::Publication>,
    attributes: Option<attributes::Correction>,
}
impl VariableService {
    /// Install over a live system table with caller-selected backend, size and policy.
    /// Serialize boot-services use and retain the owner until restoration before
    /// EBS, or leak it across successful EBS. The allocator and application code
    /// need not survive EBS.
    pub fn install(
        table: NonNull<efi::SystemTable>,
        backend: impl BlockBackend + 'static,
        manifest: Manifest,
        policy: logic::Policy,
        verifier: impl efvs::Verifier + 'static,
        anchor: &mut impl efvs::AnchorOps,
        report: fn(mechanism::Report),
    ) -> Result<Self, Status> {
        if !CONTEXT.load(Ordering::Acquire).is_null() {
            return Err(Status::ALREADY_STARTED);
        }
        // SAFETY: caller supplies the initialized system table before EBS.
        let system = unsafe { table.as_ref() };
        let boot = NonNull::new(system.boot_services).ok_or(Status::NOT_READY)?;
        let original = NonNull::new(system.runtime_services).ok_or(Status::NOT_READY)?;
        let service = Service::open(
            Backend(Box::new(backend)),
            firmware::Original {
                table: original,
                truncated: false,
                policy,
            },
            manifest,
            policy,
            Verifier(Box::new(verifier)),
            anchor,
        )
        .map_err(firmware::status)?;
        let mut snapshot_address = 0;
        // SAFETY: live boot services and writable allocation output.
        let status = unsafe {
            (boot.as_ref().allocate_pages)(
                efi::ALLOCATE_ANY_PAGES,
                efi::RUNTIME_SERVICES_DATA,
                index::CAPACITY / PAGE_SIZE,
                &mut snapshot_address,
            )
        };
        if status.is_error() {
            return Err(status);
        }
        let snapshot =
            NonNull::new(snapshot_address as usize as *mut u8).ok_or(Status::OUT_OF_RESOURCES)?;
        let mut context = Box::new(Context { service, snapshot });
        // SAFETY: live firmware boot services provide the allocation's memory map.
        let prepared = memory_map::MemoryMap::capture(unsafe { boot.as_ref() })
            .and_then(|map| map.containing(snapshot_address, index::CAPACITY))
            .and_then(|mapping| {
                if mapping.r#type != efi::RUNTIME_SERVICES_DATA
                    || mapping.attribute & efi::MEMORY_RUNTIME == 0
                {
                    return Err(Status::COMPROMISED_DATA);
                }
                context.rebuild()
            });
        if let Err(e) = prepared {
            // SAFETY: no publication references the owned snapshot allocation.
            let _ = unsafe {
                (boot.as_ref().free_pages)(snapshot_address, index::CAPACITY / PAGE_SIZE)
            };
            return Err(e);
        }
        let properties = match properties::Publication::install(table) {
            Ok(p) => p,
            Err(e) => {
                // SAFETY: snapshot remains unpublished and owned.
                let _ = unsafe {
                    (boot.as_ref().free_pages)(snapshot_address, index::CAPACITY / PAGE_SIZE)
                };
                return Err(e);
            }
        };
        // Explicit FFI owner: cleanup reconstructs this Box after unpublication.
        let context = NonNull::new(Box::into_raw(context)).ok_or(Status::OUT_OF_RESOURCES)?;
        CONTEXT.store(context.as_ptr(), Ordering::Release);
        let mut value = Self {
            table,
            original,
            context,
            snapshot_address,
            mechanism: None,
            properties,
            config_table: None,
            attributes: None,
        };
        // All boot replay/compaction and anchor operations completed before publication.
        // SAFETY: this pinned context is exclusively owned during installation.
        let config = unsafe { value.context.as_ref() }.service.store.config();
        value.config_table = Some(config_table::Publication::install(table, config)?);
        let start = addr_of!(runtime::efivar_store_blob_start).addr();
        let end = addr_of!(runtime::efivar_store_blob_end).addr();
        let mechanism = mechanism::Override::install(
            table,
            mechanism::CallbackBlob {
                start,
                size: end.checked_sub(start).ok_or(Status::COMPROMISED_DATA)?,
                get_variable: addr_of!(runtime::efivar_store_get).addr(),
                get_next_variable_name: addr_of!(runtime::efivar_store_next).addr(),
                set_variable: addr_of!(runtime::efivar_store_set).addr(),
                query_variable_info: addr_of!(runtime::efivar_store_query).addr(),
                index: Some((
                    addr_of!(runtime::efivar_store_index).addr() - start,
                    snapshot.as_ptr().addr(),
                )),
            },
            mechanism::ProofWiring {
                interposer: None,
                report,
                self_test,
                snapshot: || true,
                mark: |_, _| true,
            },
        )?;
        value.mechanism = Some(mechanism);
        value.attributes = Some(attributes::Correction::install(
            table,
            value
                .mechanism
                .as_ref()
                .map_or((0, 0), mechanism::Override::code_range),
        )?);
        // SAFETY: mechanism just published our writable private runtime table.
        let private = unsafe { &mut *(*table.as_ptr()).runtime_services };
        private.get_variable = get_variable;
        private.get_next_variable_name = get_next_variable_name;
        private.set_variable = set_variable;
        private.query_variable_info = query_variable_info;
        mechanism::refresh_header_crc(
            addr_of_mut!(private.hdr),
            ptr::from_mut(private).cast(),
            // SAFETY: live boot services retain the CRC implementation.
            unsafe { boot.as_ref().calculate_crc32 },
        )?;
        Ok(value)
    }
    pub fn original_runtime(&self) -> &'static efi::RuntimeServices {
        // SAFETY: saved firmware table remains firmware-owned throughout runtime.
        unsafe { self.original.as_ref() }
    }
    pub fn restore(mut self) -> Result<(), Status> {
        self.cleanup()
    }
    fn cleanup(&mut self) -> Result<(), Status> {
        if self.snapshot_address == 0 {
            return Ok(());
        }
        if let Some(mut correction) = self.attributes.take() {
            self.attributes = None;
            correction.restore()?;
        }
        if let Some(owner) = self.mechanism.as_mut() {
            owner.restore()?;
        }
        drop(self.mechanism.take());
        CONTEXT.store(ptr::null_mut(), Ordering::Release);
        if let Some(publication) = self.config_table.as_mut() {
            publication.restore()?;
        }
        self.config_table = None;
        self.properties.restore()?;
        // SAFETY: callback table and event were restored before dropping boot state.
        unsafe { drop(Box::from_raw(self.context.as_ptr())) };

        // SAFETY: caller only restores before successful EBS.
        let boot = unsafe { &*self.table.as_ref().boot_services };
        // SAFETY: no published callback refers to these exact owned pages.
        let status =
            unsafe { (boot.free_pages)(self.snapshot_address, index::CAPACITY / PAGE_SIZE) };
        self.snapshot_address = 0;
        if status.is_error() {
            Err(status)
        } else {
            Ok(())
        }
    }
}
impl Drop for VariableService {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}
fn context() -> Result<(&'static mut Context, Guard), Status> {
    if BUSY
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Status::NOT_READY);
    }
    let guard = Guard;
    let Some(mut context) = NonNull::new(CONTEXT.load(Ordering::Acquire)) else {
        return Err(Status::NOT_READY);
    };
    // SAFETY: install pins this object; the atomic guard serializes every access.
    Ok((unsafe { context.as_mut() }, guard))
}

pub fn installed() -> bool {
    !CONTEXT.load(Ordering::Acquire).is_null()
}

/// Inspect the live service without opening or parsing its backing partition.
pub fn inspect() -> Result<crate::backend::Inspection, Status> {
    let (context, _guard) = context()?;
    context.service.store.inspect().map_err(firmware::status)
}

unsafe fn name<'a>(raw: *const u16, limit: usize) -> Result<&'a [u16], Status> {
    if raw.is_null() {
        return Err(Status::INVALID_PARAMETER);
    }
    for i in 0..limit.min(32 * 1024) {
        // SAFETY: EFI caller supplies a readable terminated name, or for enumeration its advertised buffer.
        if unsafe { raw.add(i).read() } == 0 {
            // SAFETY: scanned initialized units before the terminator.
            return Ok(unsafe { core::slice::from_raw_parts(raw, i) });
        }
    }
    Err(Status::INVALID_PARAMETER)
}

unsafe extern "efiapi" fn get_variable(
    raw: *mut u16,
    guid: *mut efi::Guid,
    attributes: *mut u32,
    size: *mut usize,
    data: *mut c_void,
) -> Status {
    if guid.is_null() || size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let (context, _guard) = match context() {
        Ok(c) => c,
        Err(e) => return e,
    };
    // SAFETY: EFI caller supplies readable GUID and writable size.
    let key = firmware::guid_bytes(unsafe { &*guid });
    if !matches!((context.service.policy)(&key), logic::Route::Store { .. }) {
        // SAFETY: forward exactly the caller's original EFI argument contract.
        return unsafe {
            (context.service.firmware.services().get_variable)(raw, guid, attributes, size, data)
        };
    }
    // SAFETY: caller supplies a terminated UTF-16 name.
    let name = match unsafe { name(raw, logic::MAX_NAME) } {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (value_attributes, value) = match context.service.managed_value(name, &key) {
        Ok(v) => v,
        Err(e) => return firmware::status(e),
    };
    // SAFETY: required EFI size pointer is writable.
    let capacity = unsafe { size.read() };
    // SAFETY: size and optional attributes outputs were supplied by the EFI caller.
    unsafe {
        size.write(value.len());
        if !attributes.is_null() {
            attributes.write(value_attributes);
        }
    }
    if capacity < value.len() {
        return Status::BUFFER_TOO_SMALL;
    }
    if !value.is_empty() && data.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if !value.is_empty() {
        // SAFETY: caller advertises enough writable data capacity; buffers are disjoint.
        unsafe { ptr::copy_nonoverlapping(value.as_ptr(), data.cast(), value.len()) };
    }
    Status::SUCCESS
}

unsafe extern "efiapi" fn set_variable(
    raw: *mut u16,
    guid: *mut efi::Guid,
    attributes: u32,
    size: usize,
    data: *mut c_void,
) -> Status {
    if guid.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let (context, _guard) = match context() {
        Ok(c) => c,
        Err(e) => return e,
    };
    // SAFETY: EFI caller supplies a readable GUID.
    let key = firmware::guid_bytes(unsafe { &*guid });
    if !matches!((context.service.policy)(&key), logic::Route::Store { .. }) {
        // SAFETY: forward the original EFI argument contract unchanged.
        let result = unsafe {
            (context.service.firmware.services().set_variable)(raw, guid, attributes, size, data)
        };
        if !result.is_error() {
            // SAFETY: a successful original firmware call accepted its terminated name.
            match unsafe { name(raw, logic::MAX_NAME) } {
                Ok(name) => context.service.refresh_capture(name, &key),
                Err(_) => context.service.capture_truncated = true,
            }
            if let Err(e) = context.rebuild() {
                return e;
            }
        }
        return result;
    }
    // SAFETY: EFI caller supplies a terminated UTF-16 variable name.
    let name = match unsafe { name(raw, logic::MAX_NAME) } {
        Ok(n) => n,
        Err(e) => return e,
    };
    if attributes != 0 && size > logic::MAX_VALUE {
        return Status::OUT_OF_RESOURCES;
    }
    if size != 0 && data.is_null() && attributes != 0 {
        return Status::INVALID_PARAMETER;
    }
    let bytes = if size == 0 || attributes == 0 {
        &[]
    } else {
        // SAFETY: EFI caller supplies size readable bytes for a nondelete operation.
        unsafe { core::slice::from_raw_parts(data.cast::<u8>(), size) }
    };
    match context
        .service
        .set(name, &key, attributes, bytes)
        .map_err(firmware::status)
        .and_then(|()| context.rebuild())
    {
        Ok(()) => Status::SUCCESS,
        Err(e) => e,
    }
}

unsafe extern "efiapi" fn get_next_variable_name(
    size: *mut usize,
    raw: *mut u16,
    guid: *mut efi::Guid,
) -> Status {
    if size.is_null() || guid.is_null() || raw.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let (context, _guard) = match context() {
        Ok(c) => c,
        Err(e) => return e,
    };
    // SAFETY: EFI caller provides writable size and GUID.
    let capacity = unsafe { size.read() };
    if capacity < 2 {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: bounded by the caller's advertised UTF-16 name allocation.
    let previous = match unsafe { name(raw, capacity / 2) } {
        Ok(n) => n,
        Err(e) => return e,
    };
    // SAFETY: caller supplies readable GUID even for the initial empty-name query.
    let key = firmware::guid_bytes(unsafe { &*guid });
    let values = match context.service.list() {
        Ok(v) => v,
        Err(e) => return firmware::status(e),
    };
    let value = match logic::next(&values, previous, &key) {
        Ok(v) => v,
        Err(e) => return firmware::status(e),
    };
    let required = (value.name.len() + 1) * 2;
    // SAFETY: EFI size output is writable even for BUFFER_TOO_SMALL.
    unsafe { size.write(required) };
    if capacity < required {
        return Status::BUFFER_TOO_SMALL;
    }
    // SAFETY: outputs cover the required name and GUID sizes.
    unsafe {
        ptr::copy_nonoverlapping(value.name.as_ptr(), raw, value.name.len());
        raw.add(value.name.len()).write(0);
        ptr::copy_nonoverlapping(value.guid.as_ptr(), guid.cast::<u8>(), 16);
    }
    Status::SUCCESS
}

unsafe extern "efiapi" fn query_variable_info(
    attributes: u32,
    maximum: *mut u64,
    remaining: *mut u64,
    value: *mut u64,
) -> Status {
    if maximum.is_null() || remaining.is_null() || value.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let (context, _guard) = match context() {
        Ok(c) => c,
        Err(e) => return e,
    };
    match context.service.capacity(attributes) {
        Ok((m, r, v)) => {
            // SAFETY: EFI caller provides three writable u64 outputs.
            unsafe {
                maximum.write(m);
                remaining.write(r);
                value.write(v);
            }
            Status::SUCCESS
        }
        Err(e) => firmware::status(e),
    }
}

fn self_test(
    get: efi::RuntimeGetVariable,
    next: efi::RuntimeGetNextVariableName,
    set: efi::RuntimeSetVariable,
    query: efi::RuntimeQueryVariableInfo,
) -> Result<(), Status> {
    let (context, _guard) = context()?;
    exercise_index(context, get, next, set, query)?;
    // Also test successful reads on an empty store. This temporary prepared
    // index is never published; rebuild the real view before install returns.
    // SAFETY: exclusive boot-services guard owns these preallocated runtime pages.
    let output =
        unsafe { core::slice::from_raw_parts_mut(context.snapshot.as_ptr(), index::CAPACITY) };
    let mut builder = index::Builder::new(output, false).map_err(firmware::status)?;
    builder.capacity((1000, 900, 128), (512, 256, 64));
    builder
        .push(&[0x41, 0x03b1], &[0xa5; 16], 6, b"volatile")
        .map_err(firmware::status)?;
    builder
        .push(&[0x42], &[0x5a; 16], 7, b"persistent")
        .map_err(firmware::status)?;
    builder.finish();
    exercise_index(context, get, next, set, query)?;
    context.rebuild()
}

fn exercise_index(
    context: &Context,
    get: efi::RuntimeGetVariable,
    next: efi::RuntimeGetNextVariableName,
    set: efi::RuntimeSetVariable,
    query: efi::RuntimeQueryVariableInfo,
) -> Result<(), Status> {
    // SAFETY: prepared snapshot is owned and initialized for CAPACITY bytes.
    let bytes = unsafe { core::slice::from_raw_parts(context.snapshot.as_ptr(), index::CAPACITY) };
    let reference = index::Reader::parse(bytes).map_err(firmware::status)?;
    let values = reference.list();
    let mut name = [0_u16; logic::MAX_NAME];
    let mut guid = efi::Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]);
    for value in &values {
        let mut size = core::mem::size_of_val(&name);
        // SAFETY: copied runtime entry uses the prepared index; outputs cover capacity.
        let result = unsafe { next(&mut size, name.as_mut_ptr(), &mut guid) };
        if result != Status::SUCCESS
            || size != (value.name.len() + 1) * 2
            || name[..value.name.len()] != value.name
            || firmware::guid_bytes(&guid) != value.guid
        {
            return Err(Status::COMPROMISED_DATA);
        }
        let mut data = vec![0; value.data.len()];
        let mut data_size = data.len();
        let mut attributes = 0;
        // SAFETY: outputs span the exact reference value lengths.
        let result = unsafe {
            get(
                name.as_mut_ptr(),
                &mut guid,
                &mut attributes,
                &mut data_size,
                data.as_mut_ptr().cast(),
            )
        };
        if result != Status::SUCCESS
            || data != value.data
            || data_size != value.data.len()
            || attributes != value.attributes
        {
            return Err(Status::COMPROMISED_DATA);
        }
        if !value.data.is_empty() {
            data_size = 0;
            // SAFETY: EFI null-data sizing query with writable size output.
            let result = unsafe {
                get(
                    name.as_mut_ptr(),
                    &mut guid,
                    ptr::null_mut(),
                    &mut data_size,
                    ptr::null_mut(),
                )
            };
            if result != Status::BUFFER_TOO_SMALL || data_size != value.data.len() {
                return Err(Status::COMPROMISED_DATA);
            }
        }
    }
    let mut size = core::mem::size_of_val(&name);
    // SAFETY: copied runtime enumeration uses writable bounded outputs.
    if unsafe { next(&mut size, name.as_mut_ptr(), &mut guid) } != Status::NOT_FOUND {
        return Err(Status::COMPROMISED_DATA);
    }
    for attributes in [logic::BS | logic::RT, logic::NV | logic::BS | logic::RT] {
        let (mut maximum, mut remaining, mut value) = (0, 0, 0);
        // SAFETY: copied runtime query receives three writable capacity outputs.
        let result = unsafe { query(attributes, &mut maximum, &mut remaining, &mut value) };
        if result != Status::SUCCESS
            || (maximum, remaining, value)
                != reference.capacity(attributes).map_err(firmware::status)?
        {
            return Err(Status::COMPROMISED_DATA);
        }
    }
    for mut invalid in [[0, 0], [0xd800, 0], [0xdc00, 0]] {
        let mut size = 0;
        // SAFETY: each test name is terminated; size is a live EFI sizing output.
        let result = unsafe {
            get(
                invalid.as_mut_ptr(),
                &mut guid,
                ptr::null_mut(),
                &mut size,
                ptr::null_mut(),
            )
        };
        if result != Status::INVALID_PARAMETER {
            return Err(Status::COMPROMISED_DATA);
        }
    }
    if let Some(first) = values.first() {
        name.fill(0);
        let mut size = 2;
        // SAFETY: valid empty previous name and writable enumeration outputs.
        let result = unsafe { next(&mut size, name.as_mut_ptr(), &mut guid) };
        if result != Status::BUFFER_TOO_SMALL || size != (first.name.len() + 1) * 2 || name[0] != 0
        {
            return Err(Status::COMPROMISED_DATA);
        }
    }
    // SAFETY: copied runtime setter refuses writes without reading arguments.
    if unsafe { set(ptr::null_mut(), ptr::null_mut(), 0, 0, ptr::null_mut()) }
        != Status::UNSUPPORTED
    {
        return Err(Status::COMPROMISED_DATA);
    }
    Ok(())
}
