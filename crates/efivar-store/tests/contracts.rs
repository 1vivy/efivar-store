use efivar_store::{Error, Layout, Store, StoreMut};

const GUID: [u8; 16] = [0x12; 16];
fn name(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn image(layout: Layout, size: usize) -> Vec<u8> {
    let mut image = vec![0; size];
    StoreMut::format(&mut image, layout, size as u32).unwrap();
    image
}

fn record_offsets(image: &[u8]) -> Vec<usize> {
    let header = usize::from(u16::from_le_bytes(image[48..50].try_into().unwrap()));
    let end =
        header + u32::from_le_bytes(image[header + 16..header + 20].try_into().unwrap()) as usize;
    let auth = image[header] == 0x78;
    let mut pos = header + 28;
    let mut result = Vec::new();
    while pos + 2 < end && image[pos..pos + 2] == [0xaa, 0x55] {
        result.push(pos);
        let sizes = pos + if auth { 36 } else { 8 };
        let n = u32::from_le_bytes(image[sizes..sizes + 4].try_into().unwrap()) as usize;
        let d = u32::from_le_bytes(image[sizes + 4..sizes + 8].try_into().unwrap()) as usize;
        pos = (pos + if auth { 60 } else { 32 } + n + d + 3) & !3;
    }
    result
}

#[test]
fn interrupted_update_uses_old_until_added_then_prefers_new_and_reclaims() {
    for layout in [Layout::Normal, Layout::Authenticated] {
        let mut bytes = image(layout, 512);
        let key = name("LoaderEntryDefault");
        let mut writer = StoreMut::parse(&mut bytes).unwrap();
        writer.set(&key, &GUID, 7, b"old").unwrap();
        writer.set(&key, &GUID, 7, b"new").unwrap();
        let offsets = record_offsets(&bytes);
        let old = offsets[0];
        let new = offsets[1];
        // Durable cuts of edk2 UpdateVariable: old transitioned, replacement
        // header only (including a torn name), and then replacement added.
        bytes[old + 2] = 0x3e;
        for state in [0xff, 0x7f, 0x3f] {
            let mut cut = bytes.clone();
            cut[new + 2] = state;
            if state != 0x3f {
                let header_size = if layout == Layout::Normal { 32 } else { 60 };
                cut[new + header_size..].fill(0xff);
            }
            let expected: &[u8] = if state == 0x3f { b"new" } else { b"old" };
            let reader = Store::parse(&cut).unwrap();
            assert_eq!(reader.get(&key, &GUID).unwrap().data, expected);
            assert_eq!(
                reader.list().map(|v| v.data).collect::<Vec<_>>(),
                vec![expected]
            );
            let mut writer = StoreMut::parse(&mut cut).unwrap();
            let mut scratch = vec![0; writer.reclaim_scratch_size()];
            writer.reclaim(&mut scratch).unwrap();
            assert_eq!(
                Store::parse(writer.image())
                    .unwrap()
                    .get(&key, &GUID)
                    .unwrap()
                    .data,
                expected
            );
            // A recovered record can be replaced/deleted without resurrecting
            // either predecessor, including when the new ADDED cut had both.
            writer.set(&key, &GUID, 7, b"third").unwrap();
            writer.delete(&key, &GUID).unwrap();
            assert!(writer.as_store().get(&key, &GUID).is_none());
        }
        let mut writer = StoreMut::parse(&mut bytes).unwrap();
        writer.delete(&key, &GUID).unwrap();
        assert!(
            Store::parse(writer.image())
                .unwrap()
                .get(&key, &GUID)
                .is_none()
        );
    }
}

#[test]
fn updates_clear_bits_and_preserve_other_guid_and_unicode_names() {
    for layout in [Layout::Normal, Layout::Authenticated] {
        let mut bytes = image(layout, 1024);
        let key = name("選択𝄞");
        let other = [0x34; 16];
        let mut writer = StoreMut::parse(&mut bytes).unwrap();
        writer.set(&key, &GUID, 7, b"first").unwrap();
        writer.set(&key, &other, 3, b"other namespace").unwrap();
        let before = writer.image().to_vec();
        writer
            .set(&key, &GUID, 7, b"replacement of odd length")
            .unwrap();
        assert!(
            before
                .iter()
                .zip(writer.image())
                .all(|(old, new)| old & new == *new)
        );
        let before = writer.image().to_vec();
        writer.delete(&key, &GUID).unwrap();
        assert!(
            before
                .iter()
                .zip(writer.image())
                .all(|(old, new)| old & new == *new)
        );
        assert!(writer.as_store().get(&key, &GUID).is_none());
        let value = writer.as_store().get(&key, &other).unwrap();
        assert_eq!(value.name.units().collect::<Vec<_>>(), key);
        assert_eq!(value.attributes, 3);
        assert_eq!(value.data, b"other namespace");
        let free = writer.as_store().free_space();
        let mut scratch = vec![0; writer.reclaim_scratch_size()];
        let recovered = writer.reclaim(&mut scratch).unwrap();
        assert_eq!(writer.as_store().free_space(), free + recovered);
        assert_eq!(
            writer.as_store().list().map(|v| v.data).collect::<Vec<_>>(),
            vec![b"other namespace".as_slice()]
        );
    }
}

#[test]
fn full_store_and_failed_reclaim_leave_every_byte_unchanged() {
    for layout in [Layout::Normal, Layout::Authenticated] {
        let mut bytes = image(layout, 256);
        let key = name("x");
        let mut writer = StoreMut::parse(&mut bytes).unwrap();
        writer.set(&key, &GUID, 7, b"old").unwrap();
        let before = writer.image().to_vec();
        assert_eq!(writer.set(&key, &GUID, 7, &[9; 256]), Err(Error::Full));
        assert_eq!(writer.image(), before);
        assert_eq!(writer.reclaim(&mut []), Err(Error::ScratchTooSmall));
        assert_eq!(writer.image(), before);
        let free = writer.as_store().free_space();
        writer.delete(&key, &GUID).unwrap();
        assert_eq!(writer.as_store().free_space(), free);
        writer.reclaim(&mut []).unwrap();
        let capacity = writer.as_store().free_space();
        let header = if layout == Layout::Normal { 32 } else { 60 };
        let data = vec![0xa5; capacity - header - 4];
        writer.set(&key, &GUID, 7, &data).unwrap();
        assert_eq!(writer.as_store().free_space(), 0);
        assert_eq!(
            Store::parse(writer.image())
                .unwrap()
                .get(&key, &GUID)
                .unwrap()
                .data,
            data
        );
        let before = writer.image().to_vec();
        assert_eq!(writer.set(&key, &GUID, 7, b"new"), Err(Error::Full));
        assert_eq!(writer.image(), before);
    }
}

fn repair_checksum(image: &mut [u8]) {
    let length = u16::from_le_bytes(image[48..50].try_into().unwrap()) as usize;
    image[50..52].fill(0);
    let sum = image[..length]
        .as_chunks::<2>()
        .0
        .iter()
        .fold(0u16, |sum, b| sum.wrapping_add(u16::from_le_bytes(*b)));
    image[50..52].copy_from_slice(&sum.wrapping_neg().to_le_bytes());
}

#[test]
fn invalid_headers_bounds_and_names_fail_closed() {
    for layout in [Layout::Normal, Layout::Authenticated] {
        let mut base = image(layout, 512);
        StoreMut::parse(&mut base)
            .unwrap()
            .set(&name("good"), &GUID, 7, b"data")
            .unwrap();
        let record = record_offsets(&base)[0];
        let header = if layout == Layout::Normal { 32 } else { 60 };
        let sizes = record + header - 24;
        let mutations: Vec<(usize, Vec<u8>, Option<Error>, bool)> = vec![
            (40, b"BAD!".to_vec(), Some(Error::FvSignature), false),
            (50, vec![0, 0], Some(Error::FvChecksum), false),
            (60, 0u32.to_le_bytes().to_vec(), Some(Error::BlockMap), true),
            (
                56,
                u32::MAX.to_le_bytes().to_vec(),
                Some(Error::BlockMap),
                true,
            ),
            (64, 1u32.to_le_bytes().to_vec(), None, true),
            (52, 60u16.to_le_bytes().to_vec(), None, true),
            (72, vec![0; 16], Some(Error::StoreGuid), false),
            (
                88,
                u32::MAX.to_le_bytes().to_vec(),
                Some(Error::StoreSize),
                false,
            ),
            (92, vec![0], Some(Error::StoreState), false),
            (record, vec![0, 0], Some(Error::RecordSignature), false),
            (record + 2, vec![0], Some(Error::RecordState), false),
            (sizes, 3u32.to_le_bytes().to_vec(), Some(Error::Name), false),
            (
                sizes + 4,
                u32::MAX.to_le_bytes().to_vec(),
                Some(Error::Bounds),
                false,
            ),
            (record + header + 8, vec![1, 0], Some(Error::Name), false),
            (record + header, vec![0, 0], Some(Error::Name), false),
            (record + header, vec![0, 0xd8], Some(Error::Name), false),
        ];
        for (offset, value, expected, fix_checksum) in mutations {
            let mut broken = base.clone();
            broken[offset..offset + value.len()].copy_from_slice(&value);
            if fix_checksum {
                repair_checksum(&mut broken);
            }
            let error = Store::parse(&broken).unwrap_err();
            if let Some(expected) = expected {
                assert_eq!(error, expected, "offset {offset}");
            }
            assert!(StoreMut::parse(&mut broken).is_err());
        }
        // Bounds are against the store, not a following FTW/spare area. Shrink
        // only VARIABLE_STORE.Size so that an otherwise valid record straddles it.
        let mut broken = base.clone();
        broken[88..92].copy_from_slice(&32u32.to_le_bytes());
        assert_eq!(Store::parse(&broken).unwrap_err(), Error::Bounds);
        // An erased hole is not permission to overwrite later programmed data.
        let mut broken = base.clone();
        broken[500] = 0;
        assert!(Store::parse(&broken).is_err());
        for end in 0..base.len() {
            assert!(Store::parse(&base[..end]).is_err(), "truncation {end}");
        }
        // Deterministic malformed-input smoke: every single-byte mutation is
        // either a valid bounded image or an error, never a panic.
        for offset in 0..base.len() {
            let mut candidate = base.clone();
            candidate[offset] ^= 0xff;
            if let Ok(store) = Store::parse(&candidate) {
                for variable in store.list() {
                    assert!(variable.data.len() <= candidate.len());
                }
            }
        }
    }
}

#[test]
fn authenticated_attributes_cannot_bypass_signature_checks() {
    let mut bytes = image(Layout::Authenticated, 512);
    let key = name("protected");
    let mut writer = StoreMut::parse(&mut bytes).unwrap();
    for attributes in [0x27, 0x17, 0x87] {
        let before = writer.image().to_vec();
        assert_eq!(
            writer.set(&key, &GUID, attributes, b"data"),
            Err(Error::AuthenticatedWrite)
        );
        assert_eq!(writer.image(), before);
    }
    assert_eq!(
        writer.set(&key, &GUID, 0x47, b"append"),
        Err(Error::UnsupportedAttributes)
    );
    for invalid in [vec![], vec![0], vec![0xd800], vec![b'x' as u16, 0]] {
        assert_eq!(writer.set(&invalid, &GUID, 7, b"data"), Err(Error::Name));
    }
    writer.set(&key, &GUID, 7, b"signed elsewhere").unwrap();
    let record = record_offsets(&bytes)[0];
    bytes[record + 4] = 0x27;
    let mut writer = StoreMut::parse(&mut bytes).unwrap();
    let before = writer.image().to_vec();
    assert_eq!(
        writer.set(&key, &GUID, 7, b"unsigned"),
        Err(Error::AuthenticatedWrite)
    );
    assert_eq!(writer.delete(&key, &GUID), Err(Error::AuthenticatedWrite));
    assert_eq!(writer.image(), before);
    let mut scratch = vec![0; writer.reclaim_scratch_size()];
    writer.reclaim(&mut scratch).unwrap();
    let variable = writer.as_store().get(&key, &GUID).unwrap();
    assert_eq!(variable.attributes, 0x27);
    assert_eq!(variable.data, b"signed elsewhere");
}
