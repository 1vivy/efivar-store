use efivar_store::{Layout, Store, StoreMut, auth, efvs::*, migrate};
fn name(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}
fn image() -> Vec<u8> {
    let mut v = vec![0; 4096];
    initialize_with_block(&mut v, 1024, 512).unwrap();
    v
}
fn input<'a>(n: &'a [u8], data: &'a [u8], operation: Operation) -> RecordInput<'a> {
    RecordInput {
        name: n,
        guid: [1; 16],
        attributes: 7 | if operation == Operation::Append {
            ATTR_APPEND
        } else {
            0
        },
        operation,
        data,
    }
}
fn raw_append(image: &mut [u8], input: RecordInput<'_>) -> core::ops::Range<usize> {
    let h = Header::decode(image).unwrap();
    let cp = Checkpoint::decode(&image[h.checkpoint_range()]).unwrap();
    let mut log = Log::new(&image[h.log_offset..], cp.hash, cp.next_sequence);
    for _ in log.by_ref() {}
    let start = h.log_offset + log.consumed;
    let sequence = log.next_sequence;
    let previous_hash = log.previous_hash;
    let n = Record::encode(&mut image[start..], input, sequence, previous_hash).unwrap();
    start..start + n
}
#[test]
fn codecs_and_phone_geometry() {
    let mut image = vec![0; PHONE_SIZE];
    initialize(&mut image, PHONE_CHECKPOINT_CAPACITY).unwrap();
    let h = Header::decode(&image).unwrap();
    assert_eq!(h.block_size, 4096);
    assert_eq!(h.checkpoint_offset, 8192);
    assert_eq!(h.checkpoint_capacity, 131072);
    assert_eq!(h.log_offset, 270336);
    assert_eq!(h.log_capacity, 778240);
    assert_eq!(
        Checkpoint::decode(&image[h.checkpoint_range()])
            .unwrap()
            .count,
        0
    );
    let mut header = [0; 64];
    h.encode(&mut header).unwrap();
    assert_eq!(&image[..64], &header);
    let table = ConfigTable {
        partition_guid: [9; 16],
        posture_tier: 0,
        anchor_value: 42,
        capabilities: CAP_NONE,
    };
    let mut b = [0; CONFIG_TABLE_SIZE];
    table.encode(&mut b).unwrap();
    assert_eq!(ConfigTable::decode(&b).unwrap(), table);
    let n = name("選択𝄞");
    let r = input(&n, b"data", Operation::Set);
    let mut bytes = [0; 256];
    let size = Record::encode(&mut bytes, r, 4, [3; 32]).unwrap();
    let parsed = Record::decode(&bytes[..size]).unwrap();
    assert_eq!(parsed.sequence, 4);
    assert_eq!(parsed.input.name, n);
    assert_eq!(parsed.input.data, b"data");
    assert_eq!(size % 8, 0);
    for end in 0..size {
        assert!(Record::decode(&bytes[..end]).is_err());
    }
}
#[test]
fn torn_last_record_at_every_byte_and_chain_break() {
    let mut full = image();
    let a = name("A");
    let b = name("B");
    let c = name("C");
    let first = raw_append(&mut full, input(&a, b"first", Operation::Set));
    let last = raw_append(&mut full, input(&b, b"second", Operation::Set));
    for cut in 0..last.len() {
        let mut torn = full.clone();
        torn[last.start + cut..].fill(0);
        let mut scratch = [0; 1024];
        let r = replay(&torn, &mut scratch, &mut PolicyNone, 0).unwrap();
        assert_eq!(r.accepted, 1, "cut {cut}");
        assert_eq!(r.state.get(&a, &[1; 16]).unwrap().data, b"first");
        assert!(r.state.get(&b, &[1; 16]).is_none());
        assert_eq!(r.log_bytes, first.len());
    }
    raw_append(&mut full, input(&c, b"third", Operation::Set));
    full[last.start + 16] ^= 1;
    let mut scratch = [0; 1024];
    let r = replay(&full, &mut scratch, &mut PolicyNone, 0).unwrap();
    assert_eq!(r.accepted, 1);
    assert_eq!(r.end, LogEnd::Torn);
    assert!(r.state.get(&c, &[1; 16]).is_none());
}
#[test]
fn ordered_set_append_delete_and_compaction_idempotence() {
    let mut image = image();
    let n = name("key");
    let mut scratch = [0; 1024];
    let mut r = replay(&image, &mut scratch, &mut PolicyNone, 0).unwrap();
    for (op, data) in [
        (Operation::Set, b"one".as_slice()),
        (Operation::Append, b"two"),
        (Operation::Set, b"three"),
        (Operation::Delete, b""),
        (Operation::Append, b"four"),
    ] {
        append(
            &mut image,
            input(&n, data, op),
            &mut r.state,
            &mut PolicyNone,
        )
        .unwrap();
    }
    assert_eq!(r.state.get(&n, &[1; 16]).unwrap().data, b"four");
    let mut other = [0; 1024];
    let r = replay(&image, &mut other, &mut PolicyNone, 0).unwrap();
    assert_eq!(r.accepted, 5);
    assert_eq!(r.state.get(&n, &[1; 16]).unwrap().data, b"four");
    compact(&mut image, &r.state).unwrap();
    let once = image.clone();
    let mut scratch = [0; 1024];
    let r = replay(&image, &mut scratch, &mut PolicyNone, 0).unwrap();
    assert_eq!(r.accepted, 0);
    assert_eq!(r.state.next_sequence, 5);
    compact(&mut image, &r.state).unwrap();
    assert_eq!(once, image);
}
#[test]
fn boot_only_names_and_policy_none_are_refused_and_dropped() {
    let mut image = image();
    let mok = name("MokList");
    let pk = name("PK");
    let auth = name("private");
    let mut scratch = [0; 1024];
    let mut r = replay(&image, &mut scratch, &mut PolicyNone, 0).unwrap();
    let mut record = input(&mok, b"offline", Operation::Set);
    record.guid = SHIM_GUID;
    assert_eq!(
        r.state.apply(record, &mut PolicyNone),
        Err(Error::WriteProtected)
    );
    raw_append(&mut image, record);
    record = input(&pk, b"key", Operation::Set);
    record.guid = GLOBAL_GUID;
    assert_eq!(
        r.state.apply(record, &mut PolicyNone),
        Err(Error::SecurityViolation)
    );
    raw_append(&mut image, record);
    record = input(&auth, b"auth", Operation::Set);
    record.attributes |= ATTR_TIME_AUTH;
    assert_eq!(
        r.state.apply(record, &mut PolicyNone),
        Err(Error::SecurityViolation)
    );
    raw_append(&mut image, record);
    let mut other = [0; 1024];
    let r = replay(&image, &mut other, &mut PolicyNone, 0).unwrap();
    assert_eq!(r.rejected, 3);
    assert_eq!(r.state.variables().count(), 0);
    let mut source = [0; 1024];
    let mut state = State::empty(&mut source).unwrap();
    state
        .insert_checkpoint(Variable {
            name: &pk,
            guid: GLOBAL_GUID,
            attributes: 7,
            timestamp: [0; 16],
            data: b"bad",
        })
        .unwrap();
    state
        .insert_checkpoint(Variable {
            name: &mok,
            guid: SHIM_GUID,
            attributes: 3,
            timestamp: [0; 16],
            data: b"firmware",
        })
        .unwrap();
    compact(&mut image, &state).unwrap();
    let mut scratch = [0; 1024];
    let r = replay(&image, &mut scratch, &mut PolicyNone, 0).unwrap();
    assert_eq!(r.rejected, 1);
    assert!(r.state.get(&pk, &GLOBAL_GUID).is_none());
    assert_eq!(r.state.get(&mok, &SHIM_GUID).unwrap().data, b"firmware");
}
fn authenticated(day: u8, value: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 41];
    b[..2].copy_from_slice(&2026u16.to_le_bytes());
    b[2] = 10;
    b[3] = day;
    b[16..20].copy_from_slice(&25u32.to_le_bytes());
    b[20..22].copy_from_slice(&0x200u16.to_le_bytes());
    b[22..24].copy_from_slice(&0xef1u16.to_le_bytes());
    b[24..40].copy_from_slice(&auth::PKCS7_CERT_TYPE);
    b[40] = 0x30;
    b.extend_from_slice(value);
    b
}
struct TestVerifier;
impl Verifier for TestVerifier {
    fn authorize(&self, _: &[u8], _: &Guid, _: u32) -> Result<(), Error> {
        Ok(())
    }
    fn verify(
        &mut self,
        r: RecordInput<'_>,
        _: auth::Authentication2<'_>,
        state: &State<'_>,
    ) -> Result<(), Error> {
        if r.name == name("db")
            && state.get(&name("KEK"), &GLOBAL_GUID).map(|v| v.data) != Some(b"new-key".as_slice())
        {
            return Err(Error::SecurityViolation);
        }
        Ok(())
    }
}
#[test]
fn auth_replay_uses_updated_kek_rejects_stale_and_enforces_anchor() {
    let mut image = image();
    let kek = name("KEK");
    let db = name("db");
    let first = authenticated(7, b"new-key");
    let second = authenticated(8, b"allow");
    let stale = authenticated(8, b"stale");
    let mut r = input(&kek, &first, Operation::Set);
    r.guid = GLOBAL_GUID;
    r.attributes = 0x27;
    raw_append(&mut image, r);
    r = input(&db, &second, Operation::Set);
    r.guid = IMAGE_SECURITY_GUID;
    r.attributes = 0x27;
    raw_append(&mut image, r);
    r.data = &stale;
    raw_append(&mut image, r);
    let mut scratch = [0; 1024];
    let result = replay(&image, &mut scratch, &mut TestVerifier, 2).unwrap();
    assert_eq!(result.accepted, 2);
    assert_eq!(result.rejected, 1);
    assert_eq!(result.authenticated_writes, 2);
    assert_eq!(
        result.state.get(&db, &IMAGE_SECURITY_GUID).unwrap().data,
        b"allow"
    );
    let mut scratch = [0; 1024];
    assert!(matches!(
        replay(&image, &mut scratch, &mut TestVerifier, 3),
        Err(Error::Rollback)
    ));
    let result = replay(&image, &mut scratch, &mut TestVerifier, 2).unwrap();
    compact(&mut image, &result.state).unwrap();
    let mut scratch = [0; 1024];
    let result = replay(&image, &mut scratch, &mut TestVerifier, 2).unwrap();
    assert_eq!(result.state.authenticated_count, 2);
    assert_eq!(result.authenticated_writes, 0);
}
#[test]
fn auth_append_timestamp_exception_and_empty_append() {
    let n = name("private");
    let mut bytes = [0; 1024];
    let mut state = State::empty(&mut bytes).unwrap();
    let data = authenticated(8, b"first");
    let mut r = input(&n, &data, Operation::Set);
    r.attributes = 0x27;
    state.apply(r, &mut TestVerifier).unwrap();
    let mut older = authenticated(7, b"second");
    r = input(&n, &older, Operation::Append);
    r.attributes = 0x67;
    state.apply(r, &mut TestVerifier).unwrap();
    assert_eq!(state.get(&n, &[1; 16]).unwrap().data, b"firstsecond");
    assert_eq!(state.get(&n, &[1; 16]).unwrap().timestamp[3], 8);
    older[..16].fill(0);
    r = input(&n, &older, Operation::Append);
    r.attributes = 0x67;
    state.apply(r, &mut TestVerifier).unwrap();
    let zero = authenticated(0, b"not valid");
    r = input(&n, &zero, Operation::Set);
    r.attributes = 0x27;
    assert_eq!(
        state.apply(r, &mut TestVerifier),
        Err(Error::SecurityViolation)
    );
}
#[test]
fn anchors_stubs_none_and_posture() {
    let older = image();
    let mut anchor = NoneAnchor::new();
    assert_eq!(anchor.read(), Ok(0));
    anchor.bump(2).unwrap();
    assert_eq!(anchor.bump(2), Err(Error::NonMonotonic));
    anchor.lock().unwrap();
    assert_eq!(anchor.bump(3), Err(Error::Locked));
    let mut reboot = NoneAnchor::new();
    let mut scratch = [0; 1024];
    assert!(
        replay(
            &older,
            &mut scratch,
            &mut PolicyNone,
            reboot.read().unwrap()
        )
        .is_ok()
    );
    for cap in [CAP_NONE, CAP_MONOTONIC, CAP_MONOTONIC | CAP_RUNTIME_BUMP] {
        assert_eq!(posture_tier(cap), 0);
    }
    assert_eq!(Tpm2NvAnchor.read(), Err(Error::Unsupported));
    assert_eq!(OpteeRpmbAnchor.bump(1), Err(Error::Unsupported));
    assert_eq!(QcomDevinfoAnchor.lock(), Err(Error::Unsupported));
    assert_eq!(DEVINFO_RB_EFVS_ANCHOR, 31);
}
#[test]
fn capacity_failure_preserves_image_and_state() {
    let mut image = vec![0; 4096];
    initialize_with_block(&mut image, 512, 512).unwrap();
    let mut scratch = [0; 512];
    let mut r = replay(&image, &mut scratch, &mut PolicyNone, 0).unwrap();
    let before = image.clone();
    let n = name("key");
    assert_eq!(
        append(
            &mut image,
            input(&n, &[1; 500], Operation::Set),
            &mut r.state,
            &mut PolicyNone
        ),
        Err(Error::Full)
    );
    assert_eq!(image, before);
    assert_eq!(r.state.variables().count(), 0);
    let mut image = vec![0; 3072];
    initialize_with_block(&mut image, 1024, 512).unwrap();
    let before = image.clone();
    let mut scratch = [0; 1024];
    let mut r = replay(&image, &mut scratch, &mut PolicyNone, 0).unwrap();
    assert_eq!(
        append(
            &mut image,
            input(&n, b"too much data", Operation::Set),
            &mut r.state,
            &mut PolicyNone
        ),
        Err(Error::Full)
    );
    assert_eq!(image, before);
}
#[test]
fn edk2_fixture_import_parity_both_layouts() {
    for layout in [Layout::Normal, Layout::Authenticated] {
        let mut source = vec![0; 4096];
        let mut writer = StoreMut::format(&mut source, layout, 4096).unwrap();
        for (n, attrs, data) in [
            ("選択𝄞", 7, b"value".as_slice()),
            ("boot-only", 3, b"firmware"),
            ("replace", 7, b"old"),
        ] {
            writer
                .set(&n.encode_utf16().collect::<Vec<_>>(), &[2; 16], attrs, data)
                .unwrap();
        }
        writer
            .set(
                &"replace".encode_utf16().collect::<Vec<_>>(),
                &[2; 16],
                7,
                b"new",
            )
            .unwrap();
        let mut image = vec![0; 32768];
        let mut scratch = [0; 4096];
        let count = migrate::import_edk2(&source, &mut image, 4096, &mut scratch).unwrap();
        let h = Header::decode(&image).unwrap();
        let cp = Checkpoint::decode(&image[h.checkpoint_range()]).unwrap();
        assert_eq!(count, Store::parse(&source).unwrap().list().count());
        for old in Store::parse(&source).unwrap().list() {
            let new = cp
                .variables()
                .find(|v| v.name == old.name.as_bytes() && v.guid == old.guid)
                .unwrap();
            assert_eq!(new.attributes, old.attributes);
            assert_eq!(new.data, old.data);
        }
    }
}

#[test]
fn valid_hash_wrong_chain_and_existing_bs_only_are_rejected() {
    let mut image = image();
    let a = name("A");
    let b = name("B");
    raw_append(&mut image, input(&a, b"first", Operation::Set));
    let second = raw_append(&mut image, input(&b, b"second", Operation::Set));
    Record::encode(
        &mut image[second.start..],
        input(&b, b"second", Operation::Set),
        1,
        [0; 32],
    )
    .unwrap();
    let mut scratch = [0; 1024];
    let result = replay(&image, &mut scratch, &mut PolicyNone, 0).unwrap();
    assert_eq!(result.accepted, 1);
    assert_eq!(result.end, LogEnd::Torn);
    let mut bytes = [0; 1024];
    let mut state = State::empty(&mut bytes).unwrap();
    state
        .insert_checkpoint(Variable {
            name: &a,
            guid: [1; 16],
            attributes: 3,
            timestamp: [0; 16],
            data: b"firmware",
        })
        .unwrap();
    assert_eq!(
        state.apply(input(&a, b"offline", Operation::Set), &mut PolicyNone),
        Err(Error::WriteProtected)
    );
}

#[test]
fn malformed_headers_checkpoints_and_zero_auth_time_fail_closed() {
    let mut image = image();
    image[48] ^= 1;
    assert_eq!(Header::decode(&image).unwrap().header_offset, 512);
    image[512 + 48] ^= 1;
    assert_eq!(Header::decode(&image), Err(Error::Header));
    image[512 + 48] ^= 1;
    image[48] ^= 1;
    let h = Header::decode(&image).unwrap();
    image[h.checkpoint_offset + 40] ^= 1;
    assert!(Checkpoint::decode(&image[h.checkpoint_range()]).is_err());
    assert_eq!(Header::decode(&image).unwrap().header_offset, 512);
    let n = name("private");
    let mut bytes = [0; 1024];
    let mut state = State::empty(&mut bytes).unwrap();
    let mut data = authenticated(7, b"value");
    data[..16].fill(0);
    let mut request = input(&n, &data, Operation::Set);
    request.attributes = 0x27;
    assert_eq!(
        state.apply(request, &mut TestVerifier),
        Err(Error::SecurityViolation)
    );
    request.operation = Operation::Append;
    request.attributes = 0x67;
    state.apply(request, &mut TestVerifier).unwrap();
    assert_eq!(state.get(&n, &[1; 16]).unwrap().data, b"value");
}

#[test]
fn policy_none_drops_offline_secure_boot_state() {
    let mut image = image();
    let mut bytes = [0; 1024];
    let mut state = State::empty(&mut bytes).unwrap();
    let secure_boot = name("SecureBoot");
    state
        .insert_checkpoint(Variable {
            name: &secure_boot,
            guid: GLOBAL_GUID,
            attributes: 6,
            timestamp: [0; 16],
            data: &[1],
        })
        .unwrap();
    compact(&mut image, &state).unwrap();
    let mut scratch = [0; 1024];
    let result = replay(&image, &mut scratch, &mut PolicyNone, 0).unwrap();
    assert_eq!(result.rejected, 1);
    assert!(result.state.get(&secure_boot, &GLOBAL_GUID).is_none());
}
