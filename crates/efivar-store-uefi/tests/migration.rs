use efivar_store::{Layout, StoreMut, efvs, persist};
use efivar_store_uefi::{
    backend::{Efvs, Manifest, Storage},
    migration::journal_size,
    variables::Error,
};
const SIZE: usize = efvs::PHONE_SIZE;
const GUID: [u8; 16] = [0x51; 16];
fn manifest() -> Manifest {
    Manifest {
        size: SIZE,
        checkpoint_capacity: efvs::PHONE_CHECKPOINT_CAPACITY,
        write_unit: 4096,
        partition_guid: GUID,
    }
}
#[derive(Clone)]
struct Disk {
    primary: Vec<u8>,
    pending: Vec<u8>,
    journal: Vec<u8>,
    journal_pending: Vec<u8>,
    fail: Option<usize>,
    call: usize,
    tear: usize,
    commit_failed_flush: bool,
}
impl Disk {
    fn new(primary: Vec<u8>) -> Self {
        Self {
            pending: primary.clone(),
            primary,
            journal: vec![0; journal_size(SIZE)],
            journal_pending: vec![0; journal_size(SIZE)],
            fail: None,
            call: 0,
            tear: 0,
            commit_failed_flush: false,
        }
    }
    fn interrupt(&mut self) -> bool {
        let hit = self.fail == Some(self.call);
        self.call += 1;
        hit
    }
    fn restart(&mut self) {
        self.pending.clone_from(&self.primary);
        self.journal_pending.clone_from(&self.journal);
        self.fail = None;
        self.call = 0;
    }
}
struct Device<'a>(&'a mut Disk);
impl persist::Read for Device<'_> {
    type Error = ();
    fn read_at(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), ()> {
        bytes.copy_from_slice(&self.0.pending[offset..offset + bytes.len()]);
        Ok(())
    }
}
impl persist::Write for Device<'_> {
    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<(), ()> {
        if self.0.interrupt() {
            let n = self.0.tear.min(bytes.len());
            self.0.primary[offset..offset + n].copy_from_slice(&bytes[..n]);
            return Err(());
        }
        self.0.pending[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}
impl persist::Flush for Device<'_> {
    fn flush(&mut self) -> Result<(), ()> {
        let fail = self.0.interrupt();
        if !fail || self.0.commit_failed_flush {
            self.0.primary.clone_from(&self.0.pending);
        }
        if fail { Err(()) } else { Ok(()) }
    }
}
impl Storage for Device<'_> {
    fn backup_read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), ()> {
        bytes.copy_from_slice(&self.0.journal_pending[offset..offset + bytes.len()]);
        Ok(())
    }
    fn backup_write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), ()> {
        if self.0.interrupt() {
            let n = self.0.tear.min(bytes.len());
            self.0.journal[offset..offset + n].copy_from_slice(&bytes[..n]);
            return Err(());
        }
        self.0.journal_pending[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn backup_flush(&mut self) -> Result<(), ()> {
        let fail = self.0.interrupt();
        if !fail || self.0.commit_failed_flush {
            self.0.journal.clone_from(&self.0.journal_pending);
        }
        if fail { Err(()) } else { Ok(()) }
    }
}
fn legacy() -> Vec<u8> {
    let mut bytes = vec![0; SIZE];
    let mut store = StoreMut::format(&mut bytes, Layout::Authenticated, 4096).unwrap();
    store.set(&[65], &GUID, 7, b"runtime").unwrap();
    store.set(&[66], &GUID, 3, b"boot-only").unwrap();
    bytes
}
fn open(disk: &mut Disk) -> Result<(), Error> {
    let store = Efvs::open(
        Device(disk),
        manifest(),
        efvs::PolicyNone,
        &mut efvs::NoneAnchor::new(),
    )?;
    assert_eq!(store.get(&[65], &GUID)?, (7, b"runtime".as_slice()));
    assert_eq!(store.get(&[66], &GUID)?, (3, b"boot-only".as_slice()));
    Ok(())
}
#[test]
fn every_migration_write_and_flush_cut_preserves_the_complete_store() {
    let initial = Disk::new(legacy());
    let mut complete = initial.clone();
    open(&mut complete).unwrap();
    assert_eq!(
        complete.call, 12,
        "journal body/marker, primary body/A/B, marker retirement: each write then flush"
    );
    for call in 0..complete.call {
        for tear in [0, 1, 4095, 4096, SIZE / 2, SIZE - 1, SIZE] {
            for commit_failed_flush in [false, true] {
                let mut disk = initial.clone();
                disk.fail = Some(call);
                disk.tear = tear;
                disk.commit_failed_flush = commit_failed_flush;
                assert!(open(&mut disk).is_err(), "failure call {call}");
                disk.restart();
                open(&mut disk).unwrap_or_else(|error| {
                    panic!(
                        "recovery call={call} tear={tear} flush={commit_failed_flush}: {error:?}"
                    )
                });
                assert!(disk.journal[..4096].iter().all(|b| *b == 0));
                // Either initial header can be lost without falling back to an empty checkpoint.
                for offset in [0, 4096] {
                    let mut damaged = disk.primary.clone();
                    damaged[offset..offset + 4096].fill(0xa5);
                    let mut scratch = vec![0; efvs::PHONE_CHECKPOINT_CAPACITY];
                    let replay =
                        efvs::replay(&damaged, &mut scratch, &mut efvs::PolicyNone, 0).unwrap();
                    assert_eq!(replay.state.get(&[65, 0], &GUID).unwrap().data, b"runtime");
                    assert_eq!(
                        replay.state.get(&[66, 0], &GUID).unwrap().data,
                        b"boot-only"
                    );
                }
            }
        }
    }
}
#[test]
fn blank_and_unrecognized_partitions_are_initialized_by_the_service() {
    for byte in [0, 0xff, 0x5a] {
        let mut disk = Disk::new(vec![byte; SIZE]);
        let store = Efvs::open(
            Device(&mut disk),
            manifest(),
            efvs::PolicyNone,
            &mut efvs::NoneAnchor::new(),
        )
        .unwrap();
        assert_eq!(store.variables().unwrap().count(), 0);
        assert_eq!(store.config().posture_tier, 0);
        drop(store);
        assert!(efvs::Header::decode(&disk.primary).is_ok());
        assert!(disk.journal[..4096].iter().all(|b| *b == 0));
    }
}

#[test]
fn every_marker_prefix_cut_is_uncommitted_or_recoverable() {
    for tear in 0..=80 {
        let mut disk = Disk::new(legacy());
        disk.fail = Some(2);
        disk.tear = tear;
        assert!(open(&mut disk).is_err());
        disk.restart();
        open(&mut disk).unwrap_or_else(|e| panic!("marker prefix {tear}: {e:?}"));
    }
}

#[test]
fn boot_commits_and_locks_the_replayed_count_before_exposing_configuration() {
    let mut disk = Disk::new(vec![0; SIZE]);
    efvs::initialize(&mut disk.primary, efvs::PHONE_CHECKPOINT_CAPACITY).unwrap();
    let mut scratch = vec![0; efvs::PHONE_CHECKPOINT_CAPACITY];
    let mut state = efvs::State::empty(&mut scratch).unwrap();
    state.authenticated_count = 3;
    efvs::compact(&mut disk.primary, &state).unwrap();
    disk.restart();
    let mut anchor = efvs::NoneAnchor::new();
    let store = Efvs::open(Device(&mut disk), manifest(), efvs::PolicyNone, &mut anchor).unwrap();
    assert_eq!(store.config().anchor_value, 3);
    assert_eq!(
        efvs::AnchorOps::bump(&mut anchor, 4),
        Err(efvs::Error::Locked)
    );
    assert_eq!(
        store.config().posture_tier,
        0,
        "a boot-local counter confers no protected freshness"
    );
}
