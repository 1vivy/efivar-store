//! Durable-writer contracts: the ordered commit sequence must leave a store
//! that always parses and always reports a complete value, and a rejected
//! change must not touch the device at all.

use std::io;

use efivar_store::persist::{Change, Error as PersistError, Flush, Outcome, Read, Write, apply};
use efivar_store::{Error, Layout, Store, StoreMut};

const GUID: [u8; 16] = [0x12; 16];

fn name(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn image(layout: Layout, size: usize) -> Vec<u8> {
    let mut image = vec![0; size];
    StoreMut::format(&mut image, layout, 4096).unwrap();
    image
}

fn header_size(layout: Layout) -> usize {
    match layout {
        Layout::Normal => 32,
        Layout::Authenticated => 60,
    }
}

/// Byte span of the live record holding `key`, parsed straight from the image
/// the way the on-disk format defines it.
fn span(image: &[u8], key: &[u16]) -> Option<(usize, usize)> {
    let store = usize::from(u16::from_le_bytes(image[48..50].try_into().unwrap()));
    let authenticated = image[store] == 0x78;
    let size = u32::from_le_bytes(image[store + 16..store + 20].try_into().unwrap()) as usize;
    let end = store + size;
    let header = if authenticated { 60 } else { 32 };
    let sizes = if authenticated { 36 } else { 8 };
    let mut pos = store + 28;
    while pos + header <= end && image[pos..pos + 2] == [0xaa, 0x55] {
        let state = image[pos + 2];
        let name_size =
            u32::from_le_bytes(image[pos + sizes..pos + sizes + 4].try_into().unwrap()) as usize;
        let data_size =
            u32::from_le_bytes(image[pos + sizes + 4..pos + sizes + 8].try_into().unwrap())
                as usize;
        let length = (header + name_size + data_size + 3) & !3;
        if matches!(state, 0x3f | 0x3e) {
            let units: Vec<u16> = image[pos + header..pos + header + name_size - 2]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            if units == key {
                return Some((pos, pos + length));
            }
        }
        pos += length;
    }
    None
}

/// An in-memory device that can fail one write or flush, or corrupt one read.
struct Memory {
    bytes: Vec<u8>,
    steps: usize,
    fail_at: Option<usize>,
    corrupt_at: Option<usize>,
}

impl Memory {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            steps: 0,
            fail_at: None,
            corrupt_at: None,
        }
    }

    fn failing_at(bytes: Vec<u8>, fail_at: usize) -> Self {
        Self {
            fail_at: Some(fail_at),
            ..Self::new(bytes)
        }
    }

    fn step(&mut self) -> Result<(), io::Error> {
        let index = self.steps;
        self.steps += 1;
        if self.fail_at == Some(index) {
            return Err(io::Error::other("injected write/flush fault"));
        }
        Ok(())
    }
}

impl Read for Memory {
    type Error = io::Error;

    fn read_at(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), io::Error> {
        buf.copy_from_slice(&self.bytes[offset..offset + buf.len()]);
        if self.corrupt_at == Some(offset) {
            buf[0] ^= 0xff;
        }
        Ok(())
    }
}

impl Write for Memory {
    fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), io::Error> {
        self.step()?;
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }
}

impl Flush for Memory {
    fn flush(&mut self) -> Result<(), io::Error> {
        self.step()
    }
}

/// Runs one change against a fresh copy of `bytes`, returning the device.
fn run(
    bytes: &[u8],
    change: Change<'_>,
) -> (Result<Outcome, PersistError<io::Error>>, Memory, Vec<u8>) {
    let mut device = bytes.to_vec();
    let mut scratch = vec![0; bytes.len()];
    let mut io = Memory::new(bytes.to_vec());
    let result = apply(&mut io, &mut device, &mut scratch, change);
    (result, io, device)
}

fn set<'a>(key: &'a [u16], value: &'a [u8]) -> Change<'a> {
    Change::Set {
        name: key,
        guid: &GUID,
        attributes: 7,
        data: value,
    }
}

#[test]
fn update_and_delete_preserve_unrelated_records_byte_for_byte() {
    for layout in [Layout::Normal, Layout::Authenticated] {
        let alpha = name("Alpha");
        let beta = name("Beta");
        let gamma = name("Gamma");
        let (result, io, device) = run(&image(layout, 4096), set(&alpha, b"one"));
        assert_eq!(result.unwrap(), Outcome::Written);
        assert_eq!(io.bytes, device);
        let (_, _, device) = run(&io.bytes, set(&beta, b"two"));
        let (_, _, device) = run(&device, set(&gamma, b"three"));

        // A replacement appends, so only the superseded record may change.
        let before = device.clone();
        let gamma_span = span(&before, &gamma).expect("gamma record");
        let (result, io, device) = run(&before, set(&alpha, b"one-longer"));
        assert_eq!(result.unwrap(), Outcome::Written);
        assert_eq!(
            &io.bytes[gamma_span.0..gamma_span.1],
            &before[gamma_span.0..gamma_span.1]
        );
        assert_eq!(
            &device[gamma_span.0..gamma_span.1],
            &before[gamma_span.0..gamma_span.1]
        );
        let store = Store::parse(&io.bytes).unwrap();
        assert_eq!(store.get(&alpha, &GUID).unwrap().data, b"one-longer");
        assert_eq!(store.get(&gamma, &GUID).unwrap().data, b"three");

        // Deleting a neighbour leaves the untouched record intact too.
        let before = io.bytes.clone();
        let gamma_span = span(&before, &gamma).expect("gamma record");
        let (result, io, _) = run(
            &before,
            Change::Delete {
                name: &beta,
                guid: &GUID,
            },
        );
        assert_eq!(result.unwrap(), Outcome::Deleted);
        assert_eq!(
            &io.bytes[gamma_span.0..gamma_span.1],
            &before[gamma_span.0..gamma_span.1]
        );
        let store = Store::parse(&io.bytes).unwrap();
        assert!(store.get(&beta, &GUID).is_none());
        assert_eq!(store.get(&gamma, &GUID).unwrap().data, b"three");
        assert_eq!(store.list().count(), 2);
    }
}

#[test]
fn interrupted_commit_never_tears_a_value() {
    for layout in [Layout::Normal, Layout::Authenticated] {
        let alpha = name("Alpha");
        let beta = name("Beta");
        let (_, _, seeded) = run(&image(layout, 4096), set(&alpha, b"old"));
        let (_, _, seeded) = run(&seeded, set(&beta, b"keep"));

        // One successful commit, to learn the phase count of this change.
        let mut device = seeded.clone();
        let mut scratch = vec![0; seeded.len()];
        let mut io = Memory::new(seeded.clone());
        assert_eq!(
            apply(&mut io, &mut device, &mut scratch, set(&alpha, b"new")).unwrap(),
            Outcome::Written
        );
        assert_eq!(
            Store::parse(&io.bytes)
                .unwrap()
                .get(&alpha, &GUID)
                .unwrap()
                .data,
            b"new"
        );
        let total = io.steps;
        assert!(total > 0);

        // Failing any single write or flush must still leave every prefix valid.
        for fail_at in 0..total {
            let mut device = seeded.clone();
            let mut scratch = vec![0; seeded.len()];
            let mut faulting = Memory::failing_at(seeded.clone(), fail_at);
            let result = apply(
                &mut faulting,
                &mut device,
                &mut scratch,
                set(&alpha, b"new"),
            );
            assert!(result.is_err(), "fault {fail_at} was not reported");
            let store = Store::parse(&faulting.bytes).unwrap_or_else(|error| {
                panic!("fault {fail_at} left an unparsable store: {error}")
            });
            let value = store
                .get(&alpha, &GUID)
                .unwrap_or_else(|| panic!("fault {fail_at} lost the value"))
                .data
                .to_vec();
            assert!(
                value == b"old" || value == b"new",
                "fault {fail_at} produced a torn value {value:?}"
            );
            assert_eq!(store.get(&beta, &GUID).unwrap().data, b"keep");
            assert_eq!(
                store.list().count(),
                2,
                "fault {fail_at} changed the record count"
            );
        }
    }
}

#[test]
fn flush_error_and_readback_mismatch_surface() {
    let alpha = name("Alpha");
    let bytes = image(Layout::Authenticated, 4096);

    // The first phase of a replacement on an empty store is a flush.
    let (result, _, _) = {
        let mut device = bytes.clone();
        let mut scratch = vec![0; bytes.len()];
        let mut io = Memory::failing_at(bytes.clone(), 0);
        let result = apply(&mut io, &mut device, &mut scratch, set(&alpha, b"value"));
        (result, io, device)
    };
    assert!(matches!(result, Err(PersistError::Io(_))), "{result:?}");

    let mut device = bytes.clone();
    let mut scratch = vec![0; bytes.len()];
    let mut io = Memory {
        corrupt_at: Some(0),
        ..Memory::new(bytes)
    };
    let result = apply(&mut io, &mut device, &mut scratch, set(&alpha, b"value"));
    assert!(
        matches!(result, Err(PersistError::Readback { offset: 0 })),
        "{result:?}"
    );
}

#[test]
fn full_store_is_rejected_before_any_write() {
    for layout in [Layout::Normal, Layout::Authenticated] {
        let mut bytes = image(layout, 4096);
        let empty = Store::parse(&bytes).unwrap();
        let usable = empty.free_space();
        // An empty store's free space is exactly its validated capacity: the
        // FV and store headers are not part of the variable area.
        assert_eq!(empty.capacity(), usable);
        let filler = name("filler");
        let overhead = header_size(layout) + filler.len() * 2 + 2;
        let mut seeded = StoreMut::parse(&mut bytes).unwrap();
        seeded
            .set(&filler, &GUID, 7, &vec![0x5a; usable - overhead])
            .unwrap();
        let bytes = seeded.image().to_vec();
        assert_eq!(Store::parse(&bytes).unwrap().free_space(), 0);

        let (result, io, device) = run(&bytes, set(&name("other"), b"x"));
        assert!(
            matches!(result, Err(PersistError::Format(Error::Full))),
            "{result:?}"
        );
        assert_eq!(io.steps, 0, "a full store must not be written");
        assert_eq!(io.bytes, bytes);
        assert_eq!(device, bytes);
    }
}

#[test]
fn deleting_a_missing_key_is_absent_with_zero_writes() {
    let (result, io, device) = run(
        &image(Layout::Authenticated, 4096),
        Change::Delete {
            name: &name("Nothing"),
            guid: &GUID,
        },
    );
    assert_eq!(result.unwrap(), Outcome::Absent);
    assert_eq!(io.steps, 0);
    assert_eq!(device, io.bytes);
}

#[test]
fn identical_value_is_unchanged_with_zero_writes() {
    let alpha = name("Alpha");
    let (_, _, seeded) = run(&image(Layout::Normal, 4096), set(&alpha, b"value"));
    let gamma = name("Gamma");
    let (_, _, seeded) = run(&seeded, set(&gamma, b"other"));
    let before = seeded.clone();
    let (result, io, device) = run(&before, set(&alpha, b"value"));
    assert_eq!(result.unwrap(), Outcome::Unchanged);
    assert_eq!(io.steps, 0);
    assert_eq!(io.bytes, before);
    assert_eq!(device, before);

    // A different attribute word is a different value, not an unchanged one.
    let (result, _, _) = run(
        &before,
        Change::Set {
            name: &alpha,
            guid: &GUID,
            attributes: 0xb,
            data: b"value",
        },
    );
    assert_eq!(result.unwrap(), Outcome::Written);
}

#[test]
fn authenticated_and_unsupported_attributes_are_rejected_with_zero_writes() {
    let bytes = image(Layout::Authenticated, 4096);
    for attributes in [0x27, 0x87, 0x1, 0x1f] {
        let (result, io, device) = run(
            &bytes,
            Change::Set {
                name: &name("Alpha"),
                guid: &GUID,
                attributes,
                data: b"value",
            },
        );
        assert!(result.is_err(), "attributes {attributes:#x} were accepted");
        assert_eq!(io.steps, 0, "attributes {attributes:#x} were written");
        assert_eq!(io.bytes, bytes);
        assert_eq!(device, bytes);
    }
}

/// Two cooperative writers on one backing store must serialise on the lock and
/// both land; the second must reload the first writer's change, not overwrite it.
#[cfg(feature = "std")]
#[test]
fn two_cooperative_writers_both_land() {
    use efivar_store::persist::unix::Device;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let path = std::env::temp_dir().join(format!(
        "efivar-store-persist-{}-{}.img",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, image(Layout::Authenticated, 1 << 20)).unwrap();

    let writers: Vec<_> = [("KeyA", b"a-value".as_slice()), ("KeyB", b"b-value")]
        .into_iter()
        .map(|(key, value)| {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut device = Device::open(&path).unwrap();
                let key = name(key);
                device
                    .transaction(|tx| tx.set(&key, &GUID, 7, value).map(|_| ()))
                    .unwrap();
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }

    let mut device = Device::open(&path).unwrap();
    device.load().unwrap();
    let store = Store::parse(device.image()).unwrap();
    assert_eq!(store.get(&name("KeyA"), &GUID).unwrap().data, b"a-value");
    assert_eq!(store.get(&name("KeyB"), &GUID).unwrap().data, b"b-value");
    let _ = std::fs::remove_file(&path);
}
