use efivar_store::efvs::*;
fn name(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}
fn set<'a>(name: &'a [u8], data: &'a [u8]) -> RecordInput<'a> {
    RecordInput {
        name,
        guid: [1; 16],
        attributes: 7,
        operation: Operation::Set,
        data,
    }
}
fn fixture(block: usize, cycles: usize) -> Vec<u8> {
    let mut image = vec![0; block * 8];
    initialize_with_block(&mut image, block, block).unwrap();
    let mut scratch = vec![0; block];
    let mut state = State::empty(&mut scratch).unwrap();
    let key = name("key");
    let stable = name("stable");
    let gone = name("gone");
    for (n, data) in [
        (&key, b"old".as_slice()),
        (&stable, b"keep"),
        (&gone, b"remove"),
    ] {
        state
            .insert_checkpoint(Variable {
                name: n,
                guid: [1; 16],
                attributes: 7,
                timestamp: [0; 16],
                data,
            })
            .unwrap();
    }
    compact(&mut image, &state).unwrap();
    if cycles == 2 {
        state
            .insert_checkpoint(Variable {
                name: &stable,
                guid: [1; 16],
                attributes: 7,
                timestamp: [0; 16],
                data: b"keep-two",
            })
            .unwrap();
        compact(&mut image, &state).unwrap();
    }
    let mut other = vec![0; block];
    let mut replay = replay(&image, &mut other, &mut PolicyNone, 0).unwrap();
    append(
        &mut image,
        set(&key, b"new"),
        &mut replay.state,
        &mut PolicyNone,
    )
    .unwrap();
    let mut request = set(&key, b"-tail");
    request.operation = Operation::Append;
    request.attributes |= ATTR_APPEND;
    append(&mut image, request, &mut replay.state, &mut PolicyNone).unwrap();
    let mut request = set(&gone, b"");
    request.operation = Operation::Delete;
    append(&mut image, request, &mut replay.state, &mut PolicyNone).unwrap();
    let added = name("added");
    append(
        &mut image,
        set(&added, b"fresh"),
        &mut replay.state,
        &mut PolicyNone,
    )
    .unwrap();
    image
}
type Snapshot = Vec<(Vec<u8>, Guid, u32, Vec<u8>)>;
fn snapshot(image: &[u8]) -> Snapshot {
    let h = Header::decode(image).unwrap();
    let mut scratch = vec![0; h.checkpoint_capacity];
    let replay = replay(image, &mut scratch, &mut PolicyNone, 0).unwrap();
    replay
        .state
        .variables()
        .map(|v| (v.name.to_vec(), v.guid, v.attributes, v.data.to_vec()))
        .collect()
}
#[derive(Clone)]
struct FaultIo {
    durable: Vec<u8>,
    pending: Vec<u8>,
    fail_call: usize,
    call: usize,
    tear: Option<usize>,
    persist_flush: bool,
    writes: Vec<(usize, usize)>,
}
impl FaultIo {
    fn new(image: &[u8], fail_call: usize) -> Self {
        Self {
            durable: image.to_vec(),
            pending: image.to_vec(),
            fail_call,
            call: 0,
            tear: None,
            persist_flush: false,
            writes: Vec::new(),
        }
    }
}
impl CompactionIo for FaultIo {
    type Error = ();
    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<(), ()> {
        let call = self.call;
        self.call += 1;
        self.writes.push((offset, bytes.len()));
        if call == self.fail_call {
            if let Some(cut) = self.tear {
                self.durable[offset..offset + cut].copy_from_slice(&bytes[..cut]);
            }
            return Err(());
        }
        self.pending[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        let call = self.call;
        self.call += 1;
        if call == self.fail_call {
            if self.persist_flush {
                self.durable.copy_from_slice(&self.pending);
            }
            return Err(());
        }
        self.durable.copy_from_slice(&self.pending);
        Ok(())
    }
}
fn interrupt(source: &[u8], fault: &mut FaultIo) {
    let h = Header::decode(source).unwrap();
    let mut scratch = vec![0; h.checkpoint_capacity];
    let replay = replay(source, &mut scratch, &mut PolicyNone, 0).unwrap();
    let mut staged = source.to_vec();
    assert!(matches!(
        compact_durable(&mut staged, &replay.state, fault),
        Err(CompactionError::Io(()))
    ));
}
#[test]
fn every_compaction_write_and_flush_cut_recovers_complete_state() {
    for cycles in [1, 2] {
        let source = fixture(4096, cycles);
        let expected = snapshot(&source);
        let old = Header::decode(&source).unwrap();
        for call in 0..6 {
            for persisted in [false, true] {
                let mut fault = FaultIo::new(&source, call);
                fault.persist_flush = persisted;
                interrupt(&source, &mut fault);
                assert_eq!(
                    snapshot(&fault.durable),
                    expected,
                    "call {call}, persisted {persisted}, cycle {cycles}"
                );
            }
        }
        let mut io = FaultIo::new(&source, usize::MAX);
        let mut staged = source.clone();
        let mut scratch = vec![0; old.checkpoint_capacity];
        let replay = replay(&source, &mut scratch, &mut PolicyNone, 0).unwrap();
        compact_durable(&mut staged, &replay.state, &mut io).unwrap();
        let new = Header::decode(&io.durable).unwrap();
        assert_eq!(new.generation, old.generation + 1);
        assert_ne!(new.header_offset, old.header_offset);
        assert_ne!(new.checkpoint_offset, old.checkpoint_offset);
        assert_eq!(io.call, 6);
        assert_eq!(
            io.writes,
            vec![
                (new.checkpoint_offset, new.checkpoint_capacity),
                (new.header_offset, new.block_size),
                (new.log_offset, new.log_capacity)
            ]
        );
        assert_eq!(snapshot(&io.durable), expected);
        assert_eq!(staged, io.durable);
        let mut clean = io.durable.clone();
        let replay =
            efivar_store::efvs::replay(&io.durable, &mut scratch, &mut PolicyNone, 0).unwrap();
        let mut noop = FaultIo::new(&io.durable, 0);
        compact_durable(&mut clean, &replay.state, &mut noop).unwrap();
        assert_eq!(noop.call, 0);
        assert_eq!(clean, io.durable);
    }
}
#[test]
fn every_byte_torn_checkpoint_and_header_recovers_complete_state() {
    // 4Kn geometry: whole header blocks are disjoint physical write units.
    for cycles in [1, 2] {
        let source = fixture(4096, cycles);
        let expected = snapshot(&source);
        let h = Header::decode(&source).unwrap();
        for (call, length) in [(0, h.checkpoint_capacity), (2, h.block_size)] {
            for cut in 0..=length {
                let mut fault = FaultIo::new(&source, call);
                fault.tear = Some(cut);
                interrupt(&source, &mut fault);
                assert_eq!(
                    snapshot(&fault.durable),
                    expected,
                    "call {call}, cut {cut}, cycle {cycles}"
                );
            }
        }
        // A interrupted log erasure cannot replay the old generation's records.
        for cut in [0, 1, 64, 127, 4095, 4096, h.log_capacity] {
            let mut fault = FaultIo::new(&source, 4);
            fault.tear = Some(cut);
            interrupt(&source, &mut fault);
            assert_eq!(snapshot(&fault.durable), expected);
        }
    }
}
#[test]
fn damaged_physical_sector_does_not_destroy_both_headers() {
    for cycles in [1, 2] {
        let source = fixture(4096, cycles);
        let expected = snapshot(&source);
        let old = Header::decode(&source).unwrap();
        let target_header = if old.header_offset == 0 { 4096 } else { 0 };
        let target_checkpoint = 8192 + if target_header == 0 { 0 } else { 4096 };
        for (call, offset) in [(0, target_checkpoint), (2, target_header)] {
            let mut fault = FaultIo::new(&source, call);
            interrupt(&source, &mut fault);
            fault.durable[offset..offset + 4096].fill(0xa5);
            assert_eq!(snapshot(&fault.durable), expected);
            assert_eq!(
                Header::decode(&fault.durable).unwrap().header_offset,
                old.header_offset
            );
        }
    }
}
#[test]
fn newest_bad_checkpoint_falls_back_and_geometry_is_block_aligned() {
    let mut image = fixture(4096, 2);
    let h = Header::decode(&image).unwrap();
    assert_eq!(h.generation, 2);
    image[h.checkpoint_offset + 100] ^= 1;
    let fallback = Header::decode(&image).unwrap();
    assert_eq!(fallback.generation, 1);
    assert_ne!(fallback.header_offset, h.header_offset);
    for bad in [0, 64, 256, 513, 3072, 131072] {
        assert!(Header::new_with_block(32768, 4096, bad).is_err());
    }
    for block in [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
        let mut image = vec![0; block * 8];
        initialize_with_block(&mut image, block, block).unwrap();
        let h = Header::decode(&image).unwrap();
        assert_eq!(h.checkpoint_offset % block, 0);
        assert_eq!(h.log_offset % block, 0);
        image[..block].fill(0xff);
        let fallback = Header::decode(&image).unwrap();
        assert_eq!(fallback.header_offset, block);
    }
}
