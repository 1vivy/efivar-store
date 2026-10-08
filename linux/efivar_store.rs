// SPDX-License-Identifier: GPL-2.0-only
//! Block-backed efivars backend for ACK android16-6.12.
//!
//! The filesystem is upstream efivarfs, not implemented by this module.

use core::{cell::UnsafeCell, ffi::c_void, ptr, slice};
use kernel::{alloc::KVVec, bindings, prelude::*};

#[allow(unused_attributes, missing_docs, unreachable_pub)]
#[path = "../crates/efivar-store/src/lib.rs"]
pub mod engine;
use engine::{Error as StoreError, Guid, Store, persist};

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
    fn load(file: BlockFile) -> Result<Self>;
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
    entries: KVVec<Entry>,
    ready: bool,
}
impl State {
    fn entries(image: &[u8]) -> Result<KVVec<Entry>> {
        let store = Store::parse(image).map_err(|_| EINVAL)?;
        let mut entries = KVVec::new();
        for variable in store.list() {
            let mut name = KVVec::new();
            for unit in variable.name.units() {
                name.push(unit, GFP_KERNEL)?;
            }
            let mut data = KVVec::new();
            data.extend_from_slice(variable.data, GFP_KERNEL)?;
            entries.push(
                Entry {
                    name,
                    guid: variable.guid,
                    attributes: variable.attributes,
                    data,
                },
                GFP_KERNEL,
            )?;
        }
        Ok(entries)
    }
    fn reload(&mut self) {
        use persist::Read;
        self.ready = false;
        if self.file.read_at(0, &mut self.image).is_ok() {
            if let Ok(entries) = Self::entries(&self.image) {
                self.entries = entries;
                self.ready = true;
            }
        }
    }
}
impl StoreBackend for State {
    fn load(mut file: BlockFile) -> Result<Self> {
        use persist::Read;
        let mut header = [0u8; 72];
        file.read_at(0, &mut header).map_err(|_| EIO)?;
        let length = u64::from_le_bytes(header[32..40].try_into().map_err(|_| EINVAL)?);
        if !(100..=MAX_IMAGE as u64).contains(&length) {
            return Err(EINVAL);
        }
        let length = length as usize;
        let mut image = KVVec::new();
        image.resize(length, 0, GFP_KERNEL)?;
        file.read_at(0, &mut image).map_err(|_| EIO)?;
        let entries = Self::entries(&image)?;
        let mut scratch = KVVec::new();
        scratch.resize(length, 0, GFP_KERNEL)?;
        Ok(Self {
            file,
            image,
            scratch,
            entries,
            ready: true,
        })
    }
    fn list(&self) -> &[Entry] {
        &self.entries
    }
    fn query(&self) -> core::result::Result<(u64, u64, u64), usize> {
        let store = Store::parse(&self.image).map_err(|_| DEVICE_ERROR)?;
        let header = match store.layout() {
            engine::Layout::Normal => 32,
            engine::Layout::Authenticated => 60,
        };
        Ok((
            store.capacity() as u64,
            store.free_space() as u64,
            store.capacity().saturating_sub(header + 4) as u64,
        ))
    }
    fn set(&mut self, name: &[u16], guid: &Guid, attr: u32, data: &[u8]) -> usize {
        let data = if attr == 0 { &[][..] } else { data };
        let position = self
            .entries
            .iter()
            .position(|v| &*v.name == name && &v.guid == guid);
        let old = position.map(|i| &self.entries[i]);
        if (attr != 0 && attr & 4 == 0) || old.is_some_and(|v| v.attributes & 4 == 0) {
            return status(8);
        }
        if !data.is_empty() && old.is_some_and(|v| v.attributes != attr) {
            return INVALID;
        }
        if !data.is_empty() && old.is_some_and(|v| v.attributes == attr && &*v.data == data) {
            return SUCCESS;
        }
        // Allocate the prospective list entry before touching durable bytes.
        let replacement = if data.is_empty() {
            None
        } else {
            if self.entries.reserve(1, GFP_KERNEL).is_err() {
                return OUT_OF_RESOURCES;
            }
            match Entry::new(name, guid, attr, data) {
                Ok(v) => Some(v),
                Err(_) => return OUT_OF_RESOURCES,
            }
        };
        let change = if data.is_empty() || attr == 0 {
            persist::Change::Delete { name, guid }
        } else {
            persist::Change::Set {
                name,
                guid,
                attributes: attr,
                data,
            }
        };
        match persist::apply(&mut self.file, &mut self.image, &mut self.scratch, change) {
            Ok(persist::Outcome::Absent) => NOT_FOUND,
            Ok(_) => {
                match (position, replacement) {
                    (Some(i), Some(v)) => self.entries[i] = v,
                    (None, Some(v)) => {
                        if self.entries.push(v, GFP_KERNEL).is_err() {
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
            Err(error) => {
                let result = match error {
                    persist::Error::Format(e) => map_format(e),
                    _ => DEVICE_ERROR,
                };
                self.reload();
                result
            }
        }
    }
}
kernel::global_lock! { unsafe(uninit) static STATE: Mutex<()> = (); }
struct BackendCell(
    UnsafeCell<core::mem::MaybeUninit<kernel::sync::GlobalLockedBy<Option<State>, STATE>>>,
);
// SAFETY: Initialized before callbacks; all accesses require the globally unique STATE guard.
unsafe impl Sync for BackendCell {}
static BACKEND: BackendCell = BackendCell(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
impl BackendCell {
    fn as_ref<'a>(&'a self, guard: &'a kernel::sync::GlobalGuard<STATE>) -> &'a Option<State> {
        // SAFETY: Module init initializes the cell before any call to this method.
        unsafe { (&*self.0.get()).assume_init_ref() }.as_ref(guard)
    }
    fn as_mut<'a>(
        &'a self,
        guard: &'a mut kernel::sync::GlobalGuard<STATE>,
    ) -> &'a mut Option<State> {
        // SAFETY: Module init initializes the cell before any call to this method.
        unsafe { (&*self.0.get()).assume_init_ref() }.as_mut(guard)
    }
}
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
        // SAFETY: Sole module initializer, before publishing callbacks.
        unsafe { (*BACKEND.0.get()).write(kernel::sync::GlobalLockedBy::new(None)) };
        // SAFETY: The module parameter parser finished; perm=0 makes this immutable.
        let dev = unsafe { *DEVICE.0.get() };
        if dev.is_null() {
            return Err(EINVAL);
        }
        // SAFETY: param_ops_charp provides a valid NUL-terminated string until unload.
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
        // BLK_OPEN_READ | BLK_OPEN_WRITE; no C wrapper or duplicate format engine.
        // SAFETY: Valid dev_t; no holder callbacks are installed. This owns one file reference.
        let raw = unsafe {
            bindings::bdev_file_open_by_dev((major << 20) | minor, 3, ptr::null_mut(), ptr::null())
        };
        if raw as usize >= usize::MAX - 4094 {
            return Err(kernel::error::Error::from_errno(raw as isize as i32));
        }
        let backend = State::load(BlockFile(raw))?;
        let registration = KBox::new(
            Registration(UnsafeCell::new(Efivars {
                kset: ptr::null_mut(),
                ops: ptr::null(),
            })),
            GFP_KERNEL,
        )?;
        *BACKEND.as_mut(&mut STATE.lock()) = Some(backend);
        // SAFETY: Like tee_stmm_efi, replace only the kernel's generic RT backend.
        // A different registered backend remains registered and makes ours fail EBUSY.
        unsafe { efivars_generic_ops_unregister() };
        // SAFETY: Registration is heap-stable until unregister, OPS is static; state is ready.
        let rc = unsafe { efivars_register(registration.0.get(), &OPS) };
        if rc != 0 {
            *BACKEND.as_mut(&mut STATE.lock()) = None;
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
        *BACKEND.as_mut(&mut STATE.lock()) = None;
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
fn map_format(error: StoreError) -> usize {
    match error {
        StoreError::Full | StoreError::ScratchTooSmall => OUT_OF_RESOURCES,
        StoreError::AuthenticatedWrite | StoreError::UnsupportedAttributes => UNSUPPORTED,
        StoreError::Name => INVALID,
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
    let state = match BACKEND.as_ref(&guard).as_ref() {
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
    let state = match BACKEND.as_ref(&guard).as_ref() {
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
    let state = match BACKEND.as_mut(&mut guard).as_mut() {
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
    let state = match BACKEND.as_ref(&guard).as_ref() {
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
