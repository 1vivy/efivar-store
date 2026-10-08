use super::super::*;
use super::{BLI, PROJECT, name, service};
use alloc::vec;

#[test]
fn runtime_view_excludes_boot_only_and_refreshes_forwarded_firmware_updates() {
    let mut service = service();
    let guid = [0x99; 16];
    service.set(&name("BootOnly"), &BLI, BS, b"boot").unwrap();
    service
        .set(&name("NVBootOnly"), &PROJECT, NV | BS, b"boot")
        .unwrap();
    service.set(&name("Original"), &guid, 7, b"first").unwrap();
    let mut bytes = vec![0; index::CAPACITY];
    service.snapshot(&mut bytes).unwrap();
    let index = index::Reader::parse(&bytes).unwrap();
    assert_eq!(index.get(&name("BootOnly"), &BLI), Err(Error::NotFound));
    assert_eq!(
        index.get(&name("NVBootOnly"), &PROJECT),
        Err(Error::NotFound)
    );
    assert_eq!(index.get(&name("Original"), &guid).unwrap().data, b"first");
    service.set(&name("Original"), &guid, 7, b"second").unwrap();
    service.snapshot(&mut bytes).unwrap();
    assert_eq!(
        index::Reader::parse(&bytes)
            .unwrap()
            .get(&name("Original"), &guid)
            .unwrap()
            .data,
        b"second"
    );
    service.set(&name("Original"), &guid, 0, &[]).unwrap();
    service.snapshot(&mut bytes).unwrap();
    assert_eq!(
        index::Reader::parse(&bytes)
            .unwrap()
            .get(&name("Original"), &guid),
        Err(Error::NotFound)
    );
}

#[test]
fn firmware_capture_truncation_is_explicit_without_forcing_persistence() {
    let mut service = service();
    let guid = [0x99; 16];
    service
        .set(&name("TooLarge"), &guid, 7, &vec![0; MAX_VALUE + 1])
        .unwrap();
    let mut bytes = vec![0; index::CAPACITY];
    service.snapshot(&mut bytes).unwrap();
    let reader = index::Reader::parse(&bytes).unwrap();
    assert!(reader.truncated());
    assert_eq!(reader.get(&name("TooLarge"), &guid), Err(Error::NotFound));
    assert_eq!(service.store.io.writes, 0);
}
