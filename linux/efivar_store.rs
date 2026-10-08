// SPDX-License-Identifier: GPL-2.0-only
//! Block-backed efivars backend for ACK android16-6.12.
//!
//! The filesystem is upstream efivarfs, not implemented by this module.

use core::{cell::UnsafeCell, ffi::c_void, ptr, slice};
use kernel::{alloc::KVVec, bindings, prelude::*};

#[allow(unused_attributes, missing_docs, unreachable_pub)]
#[path = "../crates/efivar-store/src/lib.rs"]
pub mod engine;
use engine::{Guid, efvs, persist};

module! {
    type: EfivarStore,
    name: "efivar_store",
    author: "efivar-store contributors",
    description: "Block-backed EFI variable service using the efivar-store Rust engine",
    license: "GPL",
}

// ACK 6.12 has no Rust module-parameter abstraction. These are the kernel's
// own parameter ABI and parser, with perm=0: the device cannot change at runtime.
struct DeviceParameter(UnsafeCell<*mut core::ffi::c_char>);
// SAFETY: The kernel sets this only before module init; perm=0 prevents later writes.
unsafe impl Sync for DeviceParameter {}
static DEVICE: DeviceParameter = DeviceParameter(UnsafeCell::new(ptr::null_mut()));
#[repr(transparent)]
struct Parameter {
    _descriptor: bindings::kernel_param,
}
// SAFETY: The descriptor is immutable; only its separately guarded argument is mutable.
unsafe impl Sync for Parameter {}
// Linker address only: never read as u8; bindings::module contains opaque
// bindgen marker types that cannot appear in an extern-static declaration.
extern "C" {
    static __this_module: u8;
}
#[used]
#[link_section = "__param"]
static DEV_PARAM: Parameter = Parameter {
    _descriptor: bindings::kernel_param {
        name: b"dev\0".as_ptr().cast(),
        mod_: ptr::addr_of!(__this_module) as *mut bindings::module,
        ops: ptr::addr_of!(bindings::param_ops_charp),
        perm: 0,
        level: -1,
        flags: 0,
        __bindgen_anon_1: bindings::kernel_param__bindgen_ty_1 {
            arg: DEVICE.0.get().cast(),
        },
    },
};
#[used]
#[link_section = ".modinfo"]
static DEV_DESCRIPTION: [u8; 45] = *b"parm=dev:Backing block device as major:minor\0";
static PARTUUID: DeviceParameter = DeviceParameter(UnsafeCell::new(ptr::null_mut()));
#[used]
#[link_section = "__param"]
static UUID_PARAM: Parameter = Parameter {
    _descriptor: bindings::kernel_param {
        name: b"partuuid\0".as_ptr().cast(),
        mod_: ptr::addr_of!(__this_module) as *mut bindings::module,
        ops: ptr::addr_of!(bindings::param_ops_charp),
        perm: 0,
        level: -1,
        flags: 0,
        __bindgen_anon_1: bindings::kernel_param__bindgen_ty_1 {
            arg: PARTUUID.0.get().cast(),
        },
    },
};
#[used]
#[link_section = ".modinfo"]
static UUID_DESCRIPTION: [u8; b"parm=partuuid:Backing partition unique GUID\0".len()] =
    *b"parm=partuuid:Backing partition unique GUID\0";

extern "C" {
    fn of_find_node_opts_by_path(
        path: *const core::ffi::c_char,
        opts: *mut *const core::ffi::c_char,
    ) -> *mut c_void;
    fn of_property_read_string(
        node: *const c_void,
        property: *const core::ffi::c_char,
        value: *mut *const core::ffi::c_char,
    ) -> i32;
    #[cfg(CONFIG_OF_DYNAMIC)]
    fn of_node_put(node: *mut c_void);
}

unsafe extern "C" fn match_partition(device: *mut bindings::device, value: *const c_void) -> i32 {
    // SAFETY: block_class devices embed bd_device; class traversal holds their references.
    let block = unsafe {
        device
            .cast::<u8>()
            .sub(core::mem::offset_of!(bindings::block_device, bd_device))
            .cast::<bindings::block_device>()
    };
    let metadata = unsafe { (*block).bd_meta_info };
    if metadata.is_null() {
        return 0;
    }
    // SAFETY: Both UUID buffers contain at least 36 characters.
    let expected = unsafe { slice::from_raw_parts(value.cast::<u8>(), 36) };
    let actual = unsafe { slice::from_raw_parts((*metadata).uuid.as_ptr().cast::<u8>(), 36) };
    i32::from(actual.eq_ignore_ascii_case(expected))
}

fn uuid_device(uuid: &[u8]) -> Result<u32> {
    if uuid.len() != 36
        || !uuid.iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(EINVAL);
    }
    // SAFETY: Callback borrows uuid only during synchronous class iteration.
    let device = unsafe {
        bindings::class_find_device(
            ptr::addr_of!(bindings::block_class),
            ptr::null(),
            uuid.as_ptr().cast(),
            Some(match_partition),
        )
    };
    if device.is_null() {
        return Err(ENODEV);
    }
    // SAFETY: The returned referenced device is in block_class.
    let block = unsafe {
        device
            .cast::<u8>()
            .sub(core::mem::offset_of!(bindings::block_device, bd_device))
            .cast::<bindings::block_device>()
    };
    let dev = unsafe { (*block).bd_dev };
    unsafe { bindings::put_device(device) };
    Ok(dev)
}

fn discover_device() -> Result<u32> {
    // SAFETY: Parameters are immutable after the parser completes.
    let (dev, uuid) = unsafe { (*DEVICE.0.get(), *PARTUUID.0.get()) };
    if !dev.is_null() && !uuid.is_null() {
        return Err(EINVAL);
    }
    if !dev.is_null() {
        let text = unsafe { kernel::str::CStr::from_char_ptr(dev.cast()) }.as_bytes();
        let separator = text.iter().position(|b| *b == b':').ok_or(EINVAL)?;
        fn number(bytes: &[u8]) -> Result<u32> {
            if bytes.is_empty() {
                return Err(EINVAL);
            }
            bytes.iter().try_fold(0u32, |n, b| {
                if !b.is_ascii_digit() {
                    return Err(EINVAL);
                }
                n.checked_mul(10)
                    .and_then(|v| v.checked_add((b - b'0') as u32))
                    .ok_or(EINVAL)
            })
        }
        let major = number(&text[..separator])?;
        let minor = number(&text[separator + 1..])?;
        if major == 0 || major > 0xfff || minor > 0xfffff {
            return Err(EINVAL);
        }
        return Ok((major << 20) | minor);
    }
    if !uuid.is_null() {
        return uuid_device(unsafe { kernel::str::CStr::from_char_ptr(uuid.cast()) }.as_bytes());
    }
    // SAFETY: OF API returns a referenced node and immutable property storage.
    let chosen = unsafe { of_find_node_opts_by_path(c"/chosen".as_ptr(), ptr::null_mut()) };
    if chosen.is_null() {
        return Err(ENODEV);
    }
    let mut value = ptr::null();
    let rc =
        unsafe { of_property_read_string(chosen, c"efivar-store,partuuid".as_ptr(), &mut value) };
    let result = if rc == 0 && !value.is_null() {
        uuid_device(unsafe { kernel::str::CStr::from_char_ptr(value.cast()) }.as_bytes())
    } else {
        Err(ENODEV)
    };
    // With !OF_DYNAMIC, of_node_put is an empty inline in include/linux/of.h.
    #[cfg(CONFIG_OF_DYNAMIC)]
    unsafe {
        of_node_put(chosen)
    };
    result
}

// Missing from kernel's generated bindings: include/linux/efi.h on the pinned
// ACK revision. EFI status is unsigned long; GUID and names are caller-owned.
type Get = unsafe extern "C" fn(
    *mut u16,
    *mut bindings::guid_t,
    *mut u32,
    *mut usize,
    *mut c_void,
) -> usize;
type Next = unsafe extern "C" fn(*mut usize, *mut u16, *mut bindings::guid_t) -> usize;
type Set = unsafe extern "C" fn(*mut u16, *mut bindings::guid_t, u32, usize, *mut c_void) -> usize;
type Query = unsafe extern "C" fn(u32, *mut u64, *mut u64, *mut u64) -> usize;
#[repr(C)]
struct Operations {
    get: Option<Get>,
    next: Option<Next>,
    set: Option<Set>,
    nonblocking: Option<Set>,
    query_store: Option<unsafe extern "C" fn(u32, usize, bool) -> usize>,
    query: Option<Query>,
}
#[repr(C)]
struct Efivars {
    kset: *mut c_void,
    ops: *const Operations,
}
extern "C" {
    fn efivars_register(vars: *mut Efivars, ops: *const Operations) -> i32;
    fn efivars_unregister(vars: *mut Efivars) -> i32;
    fn efivars_generic_ops_unregister();
    fn efivars_generic_ops_register();
}
const SUCCESS: usize = 0;
const fn status(code: usize) -> usize {
    (1usize << (usize::BITS - 1)) | code
}
const INVALID: usize = status(2);
const UNSUPPORTED: usize = status(3);
const TOO_SMALL: usize = status(5);
const DEVICE_ERROR: usize = status(7);
const OUT_OF_RESOURCES: usize = status(9);
const NOT_FOUND: usize = status(14);
const MAX_IMAGE: usize = 16 * 1024 * 1024;
const MAX_NAME: usize = 512; // efivarfs uses EFI_VAR_NAME_LEN (1024 bytes).
static OPS: Operations = Operations {
    get: Some(get_variable),
    next: Some(next_variable),
    set: Some(set_variable),
    nonblocking: None,
    query_store: None,
    query: Some(query_info),
};

struct BlockFile(*mut bindings::file);
// SAFETY: The owned file reference is only used under STATE's mutex, except during init.
unsafe impl Send for BlockFile {}
impl Drop for BlockFile {
    fn drop(&mut self) {
        // SAFETY: Owns one successful bdev_file_open_by_dev reference.
        unsafe { bindings::fput(self.0) };
    }
}
impl persist::Read for BlockFile {
    type Error = i32;
    fn read_at(&mut self, offset: usize, buf: &mut [u8]) -> core::result::Result<(), i32> {
        let mut pos = offset as i64;
        // SAFETY: File is live, buffer is exclusively borrowed and pos is a valid loff_t.
        let n =
            unsafe { bindings::kernel_read(self.0, buf.as_mut_ptr().cast(), buf.len(), &mut pos) };
        if n == buf.len() as isize {
            Ok(())
        } else {
            Err(if n < 0 { n as i32 } else { -5 })
        }
    }
}
impl persist::Write for BlockFile {
    fn write_at(&mut self, offset: usize, data: &[u8]) -> core::result::Result<(), i32> {
        let mut pos = offset as i64;
        // SAFETY: File is live, data is readable throughout the synchronous call.
        let n =
            unsafe { bindings::kernel_write(self.0, data.as_ptr().cast(), data.len(), &mut pos) };
        if n == data.len() as isize {
            Ok(())
        } else {
            Err(if n < 0 { n as i32 } else { -5 })
        }
    }
}
impl persist::Flush for BlockFile {
    fn flush(&mut self) -> core::result::Result<(), i32> {
        // SAFETY: File is live; block fsync flushes dirty pages and the device cache.
        let rc = unsafe { bindings::vfs_fsync(self.0, 0) };
        if rc == 0 { Ok(()) } else { Err(rc) }
    }
}
struct Entry {
    name: KVVec<u16>,
    guid: Guid,
    attributes: u32,
    data: KVVec<u8>,
}
impl Entry {
    fn new(name: &[u16], guid: &Guid, attributes: u32, data: &[u8]) -> Result<Self> {
        let mut key = KVVec::new();
        key.extend_from_slice(name, GFP_KERNEL)?;
        let mut value = KVVec::new();
        value.extend_from_slice(data, GFP_KERNEL)?;
        Ok(Self {
            name: key,
            guid: *guid,
            attributes,
            data: value,
        })
    }
}
// Internal cutover boundary: no callback or block-I/O ABI depends on edk2.
trait StoreBackend: Sized {
    fn load(file: BlockFile, anchor: u64) -> Result<Self>;
    fn list(&self) -> &[Entry];
    fn get(&self, name: &[u16], guid: &Guid) -> Option<&Entry> {
        self.list()
            .iter()
            .find(|v| &*v.name == name && &v.guid == guid)
    }
    fn query(&self) -> core::result::Result<(u64, u64, u64), usize>;
    fn set(&mut self, name: &[u16], guid: &Guid, attr: u32, data: &[u8]) -> usize;
}
struct State {
    file: BlockFile,
    image: KVVec<u8>,
    scratch: KVVec<u8>,
    working: KVVec<u8>,
    entries: KVVec<Entry>,
    ready: bool,
}
impl State {
    fn entries(state: &efvs::State<'_>) -> Result<KVVec<Entry>> {
        let mut entries = KVVec::new();
        for variable in state.variables() {
            let mut name = KVVec::new();
            for unit in variable.name.chunks_exact(2) {
                name.push(u16::from_le_bytes([unit[0], unit[1]]), GFP_KERNEL)?;
            }
            entries.push(
                Entry::new(&name, &variable.guid, variable.attributes, variable.data)?,
                GFP_KERNEL,
            )?;
        }
        Ok(entries)
    }
    fn reload(&mut self) -> Result<()> {
        use persist::Read;
        self.ready = false;
        self.file.read_at(0, &mut self.image).map_err(|_| EIO)?;
        let replay = efvs::replay(&self.image, &mut self.scratch, &mut efvs::PolicyNone, 0)
            .map_err(|_| EINVAL)?;
        self.entries = Self::entries(&replay.state)?;
        replay
            .state
            .encode_checkpoint(&mut self.working)
            .map_err(|_| EINVAL)?;
        self.ready = true;
        Ok(())
    }
}
impl StoreBackend for State {
    fn load(mut file: BlockFile, anchor: u64) -> Result<Self> {
        use persist::Read;
        // Obtain geometry from either valid header, including recovery when A is torn.
        let mut b = [0u8; efvs::HEADER_SIZE];
        let mut length = None;
        for offset in Iterator::chain(core::iter::once(0), (9..=16).map(|shift| 1usize << shift)) {
            if file.read_at(offset, &mut b).is_err() {
                continue;
            }
            if &b[..4] == b"EFVS" {
                let n = u64::from_le_bytes(b[8..16].try_into().map_err(|_| EINVAL)?);
                if n >= (offset + efvs::HEADER_SIZE) as u64 && n <= MAX_IMAGE as u64 {
                    length = Some(length.map_or(n, |old: u64| old.max(n)));
                }
            }
        }
        let mut image = KVVec::new();
        image.resize(length.ok_or(EINVAL)? as usize, 0, GFP_KERNEL)?;
        file.read_at(0, &mut image).map_err(|_| EIO)?;
        let header = efvs::Header::decode(&image).map_err(|_| EINVAL)?;
        let mut scratch = KVVec::new();
        scratch.resize(header.checkpoint_capacity, 0, GFP_KERNEL)?;
        let mut working = KVVec::new();
        working.resize(header.checkpoint_capacity, 0, GFP_KERNEL)?;
        let replay = efvs::replay(&image, &mut scratch, &mut efvs::PolicyNone, anchor)
            .map_err(|_| EINVAL)?;
        let entries = Self::entries(&replay.state)?;
        replay
            .state
            .encode_checkpoint(&mut working)
            .map_err(|_| EINVAL)?;
        Ok(Self {
            file,
            image,
            scratch,
            working,
            entries,
            ready: true,
        })
    }
    fn list(&self) -> &[Entry] {
        &self.entries
    }
    fn query(&self) -> core::result::Result<(u64, u64, u64), usize> {
        let header = efvs::Header::decode(&self.image).map_err(map_format)?;
        let checkpoint =
            efvs::Checkpoint::decode(&self.image[header.checkpoint_range()]).map_err(map_format)?;
        let mut log = efvs::Log::new(
            &self.image[header.log_offset..],
            checkpoint.hash,
            checkpoint.next_sequence,
        );
        for _ in log.by_ref() {}
        Ok((
            header.log_capacity as u64,
            (header.log_capacity - log.consumed) as u64,
            header
                .checkpoint_capacity
                .saturating_sub(efvs::CHECKPOINT_HEADER_SIZE + 48 + 2) as u64,
        ))
    }
    fn set(&mut self, name: &[u16], guid: &Guid, attr: u32, data: &[u8]) -> usize {
        use persist::{Flush, Write};
        let mut encoded = [0u8; MAX_NAME * 2];
        for (unit, bytes) in name.iter().zip(encoded.chunks_exact_mut(2)) {
            bytes.copy_from_slice(&unit.to_le_bytes());
        }
        let input = efvs::RecordInput {
            name: &encoded[..name.len() * 2],
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
        let mut state = match efvs::State::from_checkpoint(&self.working, &mut self.scratch) {
            Ok(state) => state,
            Err(error) => return map_format(error),
        };
        // Reject policy/structure failures before considering log exhaustion.
        if let Err(error) = input.encoded_len() {
            return map_format(error);
        }
        let old = state.get(input.name, guid);
        if efvs::boot_services_only(input.name, guid)
            || old.is_some_and(|v| v.attributes & 4 == 0)
            || (attr != 0 && attr & 4 == 0)
        {
            return status(8);
        }
        use efvs::Verifier;
        if let Err(error) = efvs::PolicyNone.authorize(input.name, guid, attr) {
            return map_format(error);
        }
        if let Some(old) = old {
            if let Err(error) = efvs::PolicyNone.authorize(old.name, guid, old.attributes) {
                return map_format(error);
            }
        }
        let range = match efvs::append(&mut self.image, input, &mut state, &mut efvs::PolicyNone) {
            Ok(range) => range,
            Err(error) => return map_format(error),
        };
        let position = self
            .entries
            .iter()
            .position(|v| &*v.name == name && &v.guid == guid);
        let replacement = match state.get(input.name, guid) {
            Some(v) => match Entry::new(name, guid, v.attributes, v.data) {
                Ok(entry) => Some(entry),
                Err(_) => {
                    let _ = self.reload();
                    return OUT_OF_RESOURCES;
                }
            },
            None => None,
        };
        if replacement.is_some()
            && position.is_none()
            && self.entries.reserve(1, GFP_KERNEL).is_err()
        {
            let _ = self.reload();
            return OUT_OF_RESOURCES;
        }
        if self
            .file
            .write_at(range.start, &self.image[range])
            .and_then(|_| self.file.flush())
            .is_err()
        {
            let _ = self.reload();
            return DEVICE_ERROR;
        }
        if state.encode_checkpoint(&mut self.working).is_err() {
            self.ready = false;
            return DEVICE_ERROR;
        }
        match (position, replacement) {
            (Some(i), Some(entry)) => self.entries[i] = entry,
            (None, Some(entry)) => {
                // Capacity was reserved before the durable write.
                if self.entries.push(entry, GFP_KERNEL).is_err() {
                    self.ready = false;
                    return DEVICE_ERROR;
                }
            }
            (Some(i), None) => {
                let _ = self.entries.remove(i);
            }
            (None, None) => {}
        }
        SUCCESS
    }
}
kernel::global_lock! { unsafe(uninit) static STATE: Mutex<Option<State>> = None; }
struct EfivarStore {
    registration: KBox<Registration>,
}
struct Registration(UnsafeCell<Efivars>);
// SAFETY: Access is serialized by the kernel efivars semaphore; allocation stays pinned.
unsafe impl Send for Registration {}
// SAFETY: No Rust reader accesses the registration concurrently with kernel updates.
unsafe impl Sync for Registration {}

impl kernel::Module for EfivarStore {
    fn init(_: &'static ThisModule) -> Result<Self> {
        // StoreBackend::load owns the validated image and immediate-read list.
        // SAFETY: Module init runs exactly once, before publishing any callbacks.
        unsafe { STATE.init() };
        let dev = discover_device()?;
        let major = dev >> 20;
        let minor = dev & 0xfffff;
        // BLK_OPEN_READ | BLK_OPEN_WRITE; no C wrapper or duplicate format engine.
        // SAFETY: Valid dev_t; no holder callbacks are installed. This owns one file reference.
        let raw = unsafe { bindings::bdev_file_open_by_dev(dev, 3, ptr::null_mut(), ptr::null()) };
        if raw as usize >= usize::MAX - 4094 {
            return Err(kernel::error::Error::from_errno(raw as isize as i32));
        }
        let backend = State::load(BlockFile(raw), 0).map_err(|error| {
            pr_err!("efivar_store: no usable EFVS store; firmware must initialize blank partitions (no bytes written)\n");
            error
        })?;
        let registration = KBox::new(
            Registration(UnsafeCell::new(Efivars {
                kset: ptr::null_mut(),
                ops: ptr::null(),
            })),
            GFP_KERNEL,
        )?;
        *STATE.lock() = Some(backend);
        // SAFETY: Like tee_stmm_efi, replace only the kernel's generic RT backend.
        // A different registered backend remains registered and makes ours fail EBUSY.
        unsafe { efivars_generic_ops_unregister() };
        // SAFETY: Registration is heap-stable until unregister, OPS is static; state is ready.
        let rc = unsafe { efivars_register(registration.0.get(), &OPS) };
        if rc != 0 {
            *STATE.lock() = None;
            // SAFETY: Restore generic RT services after a failed replacement.
            unsafe { efivars_generic_ops_register() };
            return Err(kernel::error::Error::from_errno(rc));
        }
        pr_info!(
            "efivar_store: registered block-backed efivars (dev={}:{})\n",
            major,
            minor
        );
        Ok(Self { registration })
    }
}
impl Drop for EfivarStore {
    fn drop(&mut self) {
        // SAFETY: This instance owns the active registration; unregister excludes callbacks.
        unsafe { efivars_unregister(self.registration.0.get()) };
        // SAFETY: Our callbacks are gone; restore the firmware's generic frozen view.
        unsafe { efivars_generic_ops_register() };
        *STATE.lock() = None;
    }
}

// Kernel efivars supplies valid, terminated EFI_VAR_NAME_LEN buffers. Copy only
// name units to a bounded stack buffer; callbacks allocate nothing.
unsafe fn name_units<'a>(
    name: *const u16,
    buffer: &'a mut [u16; MAX_NAME],
) -> core::result::Result<&'a [u16], usize> {
    if name.is_null() {
        return Err(INVALID);
    }
    for (i, slot) in buffer.iter_mut().enumerate() {
        // SAFETY: Caller promises a valid bounded EFI name buffer.
        let unit = unsafe { name.add(i).read() };
        if unit == 0 {
            return Ok(&buffer[..i]);
        }
        *slot = unit;
    }
    Err(INVALID)
}
fn map_format(error: efvs::Error) -> usize {
    match error {
        efvs::Error::Full => OUT_OF_RESOURCES,
        efvs::Error::WriteProtected => status(8),
        efvs::Error::SecurityViolation => status(26),
        efvs::Error::Unsupported => UNSUPPORTED,
        efvs::Error::Name | efvs::Error::InvalidParameter => INVALID,
        efvs::Error::NotFound => NOT_FOUND,
        _ => DEVICE_ERROR,
    }
}
unsafe extern "C" fn get_variable(
    name: *mut u16,
    guid: *mut bindings::guid_t,
    attr: *mut u32,
    size: *mut usize,
    data: *mut c_void,
) -> usize {
    if guid.is_null() || size.is_null() {
        return INVALID;
    }
    let mut buffer = [0u16; MAX_NAME];
    // SAFETY: The efivars caller supplies a bounded terminated name.
    let name = match unsafe { name_units(name, &mut buffer) } {
        Ok(n) if !n.is_empty() => n,
        _ => return INVALID,
    };
    let guard = STATE.lock();
    let state = match guard.as_ref() {
        Some(s) if s.ready => s,
        _ => return DEVICE_ERROR,
    };
    // SAFETY: The caller supplies a valid EFI GUID.
    let variable = match state.get(name, unsafe { &(*guid).b }) {
        Some(v) => v,
        None => return NOT_FOUND,
    };
    // SAFETY: Caller-owned output pointers are valid; only write data when capacity suffices.
    unsafe {
        let available = *size;
        *size = variable.data.len();
        if !attr.is_null() {
            *attr = variable.attributes;
        }
        if available < variable.data.len() {
            return TOO_SMALL;
        }
        if data.is_null() && !variable.data.is_empty() {
            return INVALID;
        }
        if !variable.data.is_empty() {
            ptr::copy_nonoverlapping(variable.data.as_ptr(), data.cast(), variable.data.len());
        }
    }
    SUCCESS
}
unsafe extern "C" fn next_variable(
    size: *mut usize,
    name: *mut u16,
    guid: *mut bindings::guid_t,
) -> usize {
    if size.is_null() || name.is_null() || guid.is_null() {
        return INVALID;
    }
    // SAFETY: Caller supplies valid size and name buffers, bounded by EFI_VAR_NAME_LEN.
    let capacity = unsafe { *size };
    if capacity < 2 || capacity % 2 != 0 {
        return INVALID;
    }
    let mut buffer = [0u16; MAX_NAME];
    let bound = (capacity / 2).min(MAX_NAME);
    let mut length = None;
    for (i, slot) in buffer[..bound].iter_mut().enumerate() {
        // SAFETY: Reads only within the declared caller buffer.
        *slot = unsafe { name.add(i).read() };
        if *slot == 0 {
            length = Some(i);
            break;
        }
    }
    let length = match length {
        Some(n) => n,
        None => return INVALID,
    };
    let guard = STATE.lock();
    let state = match guard.as_ref() {
        Some(s) if s.ready => s,
        _ => return DEVICE_ERROR,
    };
    let mut found = length == 0;
    for variable in state.list() {
        if found {
            let needed = variable.name.len() * 2 + 2;
            // SAFETY: size is writable; names/guid are written only with sufficient capacity.
            unsafe {
                *size = needed;
                if capacity < needed {
                    return TOO_SMALL;
                }
                for (i, unit) in variable.name.iter().copied().enumerate() {
                    name.add(i).write(unit);
                }
                name.add(needed / 2 - 1).write(0);
                (*guid).b = variable.guid;
            }
            return SUCCESS;
        }
        // SAFETY: guid points to a readable caller GUID.
        found = variable.guid == unsafe { (*guid).b } && &*variable.name == &buffer[..length];
    }
    NOT_FOUND
}
unsafe extern "C" fn set_variable(
    name: *mut u16,
    guid: *mut bindings::guid_t,
    attr: u32,
    size: usize,
    data: *mut c_void,
) -> usize {
    if guid.is_null() || (size != 0 && data.is_null()) || size > MAX_IMAGE {
        return INVALID;
    }
    let mut buffer = [0u16; MAX_NAME];
    // SAFETY: Kernel supplies a bounded, terminated name.
    let name = match unsafe { name_units(name, &mut buffer) } {
        Ok(n) if !n.is_empty() => n,
        _ => return INVALID,
    };
    // SAFETY: Kernel supplies `size` readable bytes, or deletion uses an empty slice.
    let bytes = if size == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data.cast::<u8>(), size) }
    };
    let mut guard = STATE.lock();
    let state = match guard.as_mut() {
        Some(s) if s.ready => s,
        _ => return DEVICE_ERROR,
    };
    // SAFETY: guid points to a readable caller GUID.
    state.set(name, unsafe { &(*guid).b }, attr, bytes)
}
unsafe extern "C" fn query_info(
    attr: u32,
    capacity: *mut u64,
    remaining: *mut u64,
    maximum: *mut u64,
) -> usize {
    if capacity.is_null() || remaining.is_null() || maximum.is_null() {
        return INVALID;
    }
    if attr != 7 {
        return if attr & !7 != 0 { UNSUPPORTED } else { INVALID };
    }
    let guard = STATE.lock();
    let state = match guard.as_ref() {
        Some(s) if s.ready => s,
        _ => return DEVICE_ERROR,
    };
    let (total, free, max) = match state.query() {
        Ok(values) => values,
        Err(e) => return e,
    };
    // SAFETY: Kernel supplies three writable u64 output pointers.
    unsafe {
        *capacity = total;
        *remaining = free;
        *maximum = max;
    }
    SUCCESS
}
