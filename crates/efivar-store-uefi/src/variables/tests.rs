use super::*;
use alloc::vec;
pub const BLI: Guid = [
    0x82, 0xb0, 0x67, 0x4a, 0x4c, 0x0a, 0xcf, 0x41, 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f,
];
pub const PROJECT: Guid = [
    0x1c, 0x4b, 0x5e, 0x7a, 0x3f, 0x0d, 0x62, 0x4e, 0x9b, 0x8a, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b,
];
fn policy(guid: &Guid) -> Route {
    if *guid == BLI {
        Route::Store { volatile: true }
    } else if *guid == PROJECT {
        Route::Store { volatile: false }
    } else {
        Route::Firmware
    }
}

use efivar_store::{
    efvs,
    persist::{Flush, Read, Write},
};
#[path = "snapshot_tests.rs"]
mod snapshot_tests;
struct Memory {
    bytes: Vec<u8>,
    journal: Vec<u8>,
    writes: usize,
    fail: bool,
}
impl Read for Memory {
    type Error = ();
    fn read_at(&mut self, offset: usize, data: &mut [u8]) -> Result<(), ()> {
        data.copy_from_slice(self.bytes.get(offset..offset + data.len()).ok_or(())?);
        Ok(())
    }
}
impl Write for Memory {
    fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), ()> {
        if self.fail {
            self.fail = false;
            return Err(());
        }
        self.writes += 1;
        self.bytes
            .get_mut(offset..offset + data.len())
            .ok_or(())?
            .copy_from_slice(data);
        Ok(())
    }
}
impl Storage for Memory {
    fn backup_read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), ()> {
        bytes.copy_from_slice(&self.journal[offset..offset + bytes.len()]);
        Ok(())
    }
    fn backup_write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), ()> {
        self.journal[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn backup_flush(&mut self) -> Result<(), ()> {
        Ok(())
    }
}
impl Flush for Memory {
    fn flush(&mut self) -> Result<(), ()> {
        Ok(())
    }
}
#[derive(Default)]
struct Fake {
    values: Vec<Variable>,
}
impl Firmware for Fake {
    fn get(&mut self, name: &[u16], guid: &Guid) -> Result<Variable, Error> {
        self.values
            .iter()
            .find(|v| v.name == name && v.guid == *guid)
            .cloned()
            .ok_or(Error::NotFound)
    }
    fn set(
        &mut self,
        name: &[u16],
        guid: &Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        self.values.retain(|v| v.name != name || v.guid != *guid);
        if attributes != 0 && !data.is_empty() {
            self.values.push(Variable {
                name: name.to_vec(),
                guid: *guid,
                attributes,
                data: data.to_vec(),
            });
        }
        Ok(())
    }
    fn list(&mut self) -> Result<Vec<Variable>, Error> {
        Ok(self.values.clone())
    }
}
fn service() -> Service<Memory, Fake> {
    let mut bytes = vec![0; 64 * 1024];
    efvs::initialize(&mut bytes, 16 * 1024).unwrap();
    Service::open(
        Memory {
            bytes,
            writes: 0,
            fail: false,
            journal: vec![0; crate::migration::journal_size(64 * 1024)],
        },
        Fake::default(),
        Manifest {
            size: 64 * 1024,
            checkpoint_capacity: 16 * 1024,
            write_unit: 4096,
            partition_guid: PROJECT,
        },
        policy,
        efvs::PolicyNone,
        &mut efvs::NoneAnchor::new(),
    )
    .unwrap()
}
fn name(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn disk_value(bytes: &[u8], name: &[u16], guid: &Guid) -> Option<Vec<u8>> {
    let mut scratch = vec![0; 16 * 1024];
    let replay = efvs::replay(bytes, &mut scratch, &mut efvs::PolicyNone, 0).unwrap();
    let name: Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    replay.state.get(&name, guid).map(|v| v.data.to_vec())
}

fn os_write(bytes: &mut [u8], name: &[u16], guid: Guid, data: &[u8]) {
    let mut scratch = vec![0; 16 * 1024];
    let mut replay = efvs::replay(bytes, &mut scratch, &mut efvs::PolicyNone, 0).unwrap();
    let name: Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    efvs::append(
        bytes,
        efvs::RecordInput {
            name: &name,
            guid,
            attributes: 7,
            data,
            operation: efvs::Operation::Set,
        },
        &mut replay.state,
        &mut efvs::PolicyNone,
    )
    .unwrap();
}

#[test]
fn bli_attributes_sizing_and_durable_deletion() {
    let mut service = service();
    let key = name("LoaderEntryOneShot");
    assert_eq!(
        service.set(&key, &BLI, RT, b"bad"),
        Err(Error::InvalidParameter)
    );
    assert_eq!(
        service.set(&key, &BLI, 0x27, b"bad"),
        Err(Error::SecurityViolation)
    );
    service.set(&key, &BLI, NV | BS | RT, b"entry\0").unwrap();
    assert!(service.store.io.writes > 0);
    assert_eq!(
        service.set(&key, &BLI, RT, &[]),
        Err(Error::InvalidParameter)
    );
    assert_eq!(
        service.set(&key, &BLI, 0x107, b"unsupported"),
        Err(Error::Unsupported)
    );
    let value = service.get(&key, &BLI).unwrap();
    assert_eq!(
        read_value(&value, &mut [0; 2]),
        Err(Error::BufferTooSmall(6))
    );
    assert_eq!(
        service.set(&key, &BLI, BS | RT, b"volatile"),
        Err(Error::InvalidParameter)
    );
    assert_eq!(
        disk_value(&service.store.io.bytes, &key, &BLI).unwrap(),
        b"entry\0"
    );
    service.set(&key, &BLI, 0, &[]).unwrap();
    assert!(disk_value(&service.store.io.bytes, &key, &BLI).is_none());
    assert_eq!(service.set(&key, &BLI, 0, &[]), Err(Error::NotFound));
}
#[test]
fn volatile_overlay_never_persists_and_enumeration_suppresses_firmware_managed_keys() {
    let mut service = service();
    let key = name("LoaderInfo");
    service
        .firmware
        .set(&key, &BLI, BS | RT, b"firmware")
        .unwrap();
    service.set(&key, &BLI, BS | RT, b"Surfacer").unwrap();
    assert_eq!(service.store.io.writes, 0);
    assert!(disk_value(&service.store.io.bytes, &key, &BLI).is_none());
    let other = [0x99; 16];
    service
        .firmware
        .set(&key, &other, BS | RT, b"other")
        .unwrap();
    let list = service.list().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(next(&list, &[], &[0; 16]).unwrap().guid, BLI);
    assert_eq!(next(&list, &key, &BLI).unwrap().guid, other);
    assert_eq!(next(&list, &key, &other), Err(Error::NotFound));
    assert_eq!(
        next(&list, &name("unknown"), &other),
        Err(Error::InvalidParameter)
    );
    service.set(&key, &BLI, 0, &[]).unwrap();
    assert_eq!(service.get(&key, &BLI), Err(Error::NotFound));
}
#[test]
fn snapshot_tracks_pre_ebs_updates_and_is_stale_after_direct_write() {
    let mut service = service();
    let key = name("Slot-rom1");
    let mut snapshot = vec![0; index::CAPACITY];
    service.set(&key, &PROJECT, 7, b"a").unwrap();
    service.snapshot(&mut snapshot).unwrap();
    assert_eq!(
        index::Reader::parse(&snapshot)
            .unwrap()
            .get(&key, &PROJECT)
            .unwrap()
            .data,
        b"a"
    );
    service.set(&key, &PROJECT, 7, b"b").unwrap();
    service.snapshot(&mut snapshot).unwrap();
    os_write(&mut service.store.io.bytes, &key, PROJECT, b"c");
    assert_eq!(
        index::Reader::parse(&snapshot)
            .unwrap()
            .get(&key, &PROJECT)
            .unwrap()
            .data,
        b"b"
    );
}
#[test]
fn persistence_error_reloads_before_the_next_operation() {
    let mut service = service();
    let key = name("LoaderEntryDefault");
    service.store.io.fail = true;
    assert_eq!(service.set(&key, &BLI, 7, b"entry"), Err(Error::Device));
    assert_eq!(service.get(&key, &BLI), Err(Error::NotFound));
    service.set(&key, &BLI, 7, b"entry").unwrap();
    assert_eq!(service.get(&key, &BLI).unwrap().data, b"entry");
}
#[test]
fn index_bounds_and_duplicate_keys_fail_closed() {
    let mut bytes = vec![0; index::HEADER + 32];
    let mut builder = index::Builder::new(&mut bytes, false).unwrap();
    assert_eq!(
        builder.push(&name("A"), &BLI, 6, b"payload"),
        Err(Error::OutOfResources)
    );
    builder.finish();
    bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(index::Reader::parse(&bytes), Err(Error::Corrupt)));
    let mut bytes = vec![0; 1024];
    let mut builder = index::Builder::new(&mut bytes, false).unwrap();
    builder.push(&name("A"), &BLI, 6, b"1").unwrap();
    builder.push(&name("A"), &BLI, 6, b"2").unwrap();
    builder.finish();
    assert!(matches!(index::Reader::parse(&bytes), Err(Error::Corrupt)));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn x86_runtime_efiapi_differential_reader_and_write_refusal() {
    use core::{ffi::c_void, ptr};
    type Get =
        unsafe extern "efiapi" fn(*mut u16, *mut Guid, *mut u32, *mut usize, *mut c_void) -> usize;
    type Next = unsafe extern "efiapi" fn(*mut usize, *mut u16, *mut Guid) -> usize;
    type Query = unsafe extern "efiapi" fn(u32, *mut u64, *mut u64, *mut u64) -> usize;
    type Set = unsafe extern "efiapi" fn(*mut u16, *mut Guid, u32, usize, *mut c_void) -> usize;
    const ERROR: usize = 1 << 63;
    let mut service = service();
    for (key, guid, attrs, data) in [
        ("LoaderInfo", BLI, 6, b"info".as_slice()),
        ("Slot-rom1", PROJECT, 7, b"slot".as_slice()),
    ] {
        service.set(&name(key), &guid, attrs, data).unwrap();
    }
    service
        .firmware
        .set(&name("Original"), &[0x99; 16], 7, b"OEM")
        .unwrap();
    service.refresh_capture(&name("Original"), &[0x99; 16]);
    let mut snapshot = vec![0; index::CAPACITY];
    service.snapshot(&mut snapshot).unwrap();
    let reference = index::Reader::parse(&snapshot).unwrap();
    // Copy the exact production blob to an executable anonymous mapping, patch
    // only its index slot, then run the same ABI the firmware will invoke.
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            length: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: isize,
        ) -> *mut c_void;
        fn munmap(address: *mut c_void, length: usize) -> i32;
    }
    let start = ptr::addr_of!(runtime::efivar_store_blob_start).addr();
    let end = ptr::addr_of!(runtime::efivar_store_blob_end).addr();
    let size = end - start;
    // SAFETY: anonymous private mapping, no file offset, sufficient writable/executable bytes.
    let code = unsafe { mmap(ptr::null_mut(), size, 7, 0x22, -1, 0) }.cast::<u8>();
    assert_ne!(code.addr(), usize::MAX);
    // SAFETY: copied linker blob and validated slot are inside the owned mapping.
    unsafe {
        ptr::copy_nonoverlapping(start as *const u8, code, size);
        code.add(ptr::addr_of!(runtime::efivar_store_index).addr() - start)
            .cast::<usize>()
            .write_unaligned(snapshot.as_ptr().addr());
    }
    // SAFETY: matching EFI ABI symbols in the copied executable mapping.
    let get: Get = unsafe {
        core::mem::transmute(code.add(ptr::addr_of!(runtime::efivar_store_get).addr() - start))
    };
    // SAFETY: matching EFI ABI symbol in the copied executable mapping.
    let next: Next = unsafe {
        core::mem::transmute(code.add(ptr::addr_of!(runtime::efivar_store_next).addr() - start))
    };
    // SAFETY: matching EFI ABI symbol in the copied executable mapping.
    let query: Query = unsafe {
        core::mem::transmute(code.add(ptr::addr_of!(runtime::efivar_store_query).addr() - start))
    };
    // SAFETY: matching EFI ABI symbol in the copied executable mapping.
    let set: Set = unsafe {
        core::mem::transmute(code.add(ptr::addr_of!(runtime::efivar_store_set).addr() - start))
    };
    let mut units = [0; MAX_NAME];
    let mut guid = [0; 16];
    for value in reference.list() {
        let mut name_size = core::mem::size_of_val(&units);
        // SAFETY: bounded writable EFI enumeration outputs and initialized previous name.
        assert_eq!(
            // SAFETY: bounded writable EFI enumeration outputs and initialized previous name.
            unsafe { next(&mut name_size, units.as_mut_ptr(), &mut guid) },
            0
        );
        assert_eq!(units[..value.name.len()], value.name);
        assert_eq!(guid, value.guid);
        let mut size = 0;
        // SAFETY: EFI sizing query with null optional output.
        assert_eq!(
            // SAFETY: EFI sizing query with null optional output.
            unsafe {
                get(
                    units.as_mut_ptr(),
                    &mut guid,
                    ptr::null_mut(),
                    &mut size,
                    ptr::null_mut(),
                )
            },
            ERROR | 5
        );
        assert_eq!(size, value.data.len());
        let mut data = vec![0; size];
        let mut attrs = 0;
        // SAFETY: all outputs cover their advertised capacity.
        assert_eq!(
            // SAFETY: all outputs cover their advertised capacity.
            unsafe {
                get(
                    units.as_mut_ptr(),
                    &mut guid,
                    &mut attrs,
                    &mut size,
                    data.as_mut_ptr().cast(),
                )
            },
            0
        );
        assert_eq!(data, value.data);
        assert_eq!(attrs, value.attributes);
    }
    let mut name_size = core::mem::size_of_val(&units);
    // SAFETY: initialized last name and writable EFI outputs.
    assert_eq!(
        // SAFETY: initialized last name and writable EFI outputs.
        unsafe { next(&mut name_size, units.as_mut_ptr(), &mut guid) },
        ERROR | 14
    );
    for attrs in [6, 7] {
        let (mut max, mut remaining, mut value) = (0, 0, 0);
        // SAFETY: three writable capacity outputs.
        assert_eq!(
            // SAFETY: three writable capacity outputs.
            unsafe { query(attrs, &mut max, &mut remaining, &mut value) },
            0
        );
        assert_eq!((max, remaining, value), reference.capacity(attrs).unwrap());
    }
    // SAFETY: runtime setter refuses all writes before dereferencing arguments.
    assert_eq!(
        // SAFETY: runtime setter refuses all writes before dereferencing arguments.
        unsafe { set(ptr::null_mut(), ptr::null_mut(), 7, 0, ptr::null_mut()) },
        ERROR | 3
    );
    for invalid in [
        vec![0],
        vec![0xd800, 0],
        vec![0xdc00, 0],
        vec![65; MAX_NAME + 1],
    ] {
        let mut invalid = invalid;
        let mut size = 0;
        // SAFETY: names span the runtime bound, outputs are live sizing-query storage.
        let result = unsafe {
            get(
                invalid.as_mut_ptr(),
                &mut guid,
                ptr::null_mut(),
                &mut size,
                ptr::null_mut(),
            )
        };
        assert_eq!(result, ERROR | 2);
    }
    units.fill(0);
    guid.fill(0);
    name_size = 2;
    // SAFETY: empty previous name with the advertised two writable bytes.
    let result = unsafe { next(&mut name_size, units.as_mut_ptr(), &mut guid) };
    assert_eq!(result, ERROR | 5);
    assert_eq!(name_size, (reference.list()[0].name.len() + 1) * 2);
    assert_eq!(units[0], 0);
    assert_eq!(guid, [0; 16]);
    units[0] = 0x7f;
    name_size = core::mem::size_of_val(&units);
    // SAFETY: unknown, terminated previous name and complete writable outputs.
    let result = unsafe { next(&mut name_size, units.as_mut_ptr(), &mut guid) };

    assert_eq!(result, ERROR | 2);
    // SAFETY: exact mapping created above, all callback use has completed.
    assert_eq!(unsafe { munmap(code.cast(), size) }, 0);
}

#[test]
fn next_boot_replays_os_log_and_compacts_torn_tail_before_append() {
    let mut first = service();
    let key = name("Slot-rom1");
    first.set(&key, &PROJECT, 7, b"firmware").unwrap();
    os_write(&mut first.store.io.bytes, &key, PROJECT, b"os");
    let h = efvs::Header::decode(&first.store.io.bytes).unwrap();
    let cp = efvs::Checkpoint::decode(&first.store.io.bytes[h.checkpoint_range()]).unwrap();
    let mut log = efvs::Log::new(
        &first.store.io.bytes[h.log_offset..],
        cp.hash,
        cp.next_sequence,
    );
    for _ in log.by_ref() {}
    let end = h.log_offset + log.consumed;
    first.store.io.bytes[end..end + 4].copy_from_slice(b"EFVR");
    let mut anchor = efvs::NoneAnchor::new();
    let mut next = Service::open(
        first.store.io,
        Fake::default(),
        Manifest {
            size: 64 * 1024,
            checkpoint_capacity: 16 * 1024,
            write_unit: 4096,
            partition_guid: PROJECT,
        },
        policy,
        efvs::PolicyNone,
        &mut anchor,
    )
    .unwrap();
    assert_eq!(next.get(&key, &PROJECT).unwrap().data, b"os");
    assert!(next.store.io.bytes[h.log_offset..].iter().all(|b| *b == 0));
    let config = next.store.config();
    assert_eq!(config.partition_guid, PROJECT);
    assert_eq!(config.posture_tier, 0);
    assert_eq!(config.anchor_value, 0);
    assert_eq!(
        efvs::AnchorOps::bump(&mut anchor, 1),
        Err(efvs::Error::Locked)
    );
    next.set(&key, &PROJECT, 7 | efvs::ATTR_APPEND, b"+new")
        .unwrap();
    assert_eq!(
        disk_value(&next.store.io.bytes, &key, &PROJECT).unwrap(),
        b"os+new"
    );
}

#[test]
fn boot_only_mutations_are_checkpointed_not_runtime_log_records() {
    let mut service = service();
    let key = name("HandoffOrigin");
    service.set(&key, &PROJECT, NV | BS, b"intent").unwrap();
    let h = efvs::Header::decode(&service.store.io.bytes).unwrap();
    assert!(
        service.store.io.bytes[h.log_offset..]
            .iter()
            .all(|b| *b == 0)
    );
    assert_eq!(
        disk_value(&service.store.io.bytes, &key, &PROJECT).unwrap(),
        b"intent"
    );
    service.set(&key, &PROJECT, 0, &[]).unwrap();
    service.store.verify_absent(&key, &PROJECT).unwrap();
    assert!(disk_value(&service.store.io.bytes, &key, &PROJECT).is_none());
}

#[test]
fn failed_boot_compaction_does_not_lock_or_publish_an_anchor() {
    struct Anchor {
        locked: bool,
    }
    impl efvs::AnchorOps for Anchor {
        fn read(&mut self) -> Result<u64, efvs::Error> {
            Ok(0)
        }
        fn bump(&mut self, _: u64) -> Result<(), efvs::Error> {
            panic!("unauthenticated write must not bump")
        }
        fn lock(&mut self) -> Result<(), efvs::Error> {
            self.locked = true;
            Ok(())
        }
        fn capabilities(&self) -> u32 {
            0
        }
    }
    let mut first = service();
    os_write(
        &mut first.store.io.bytes,
        &name("BootedRom"),
        PROJECT,
        b"rom2",
    );
    first.store.io.fail = true;
    let mut anchor = Anchor { locked: false };
    let result = Efvs::open(
        first.store.io,
        Manifest {
            size: 64 * 1024,
            checkpoint_capacity: 16 * 1024,
            write_unit: 4096,
            partition_guid: PROJECT,
        },
        efvs::PolicyNone,
        &mut anchor,
    );
    assert!(matches!(result, Err(Error::Device)));
    assert!(!anchor.locked);
}
