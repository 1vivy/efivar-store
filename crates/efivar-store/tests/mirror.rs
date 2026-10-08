use efivar_store::{
    Layout, Store, StoreMut,
    mirror::{Decision, decide, needs_reclaim},
};
const SIZE: usize = 1024 * 1024;
fn image() -> Vec<u8> {
    let mut image = vec![0; SIZE];
    StoreMut::format(&mut image, Layout::Authenticated, 4096).unwrap();
    image
}

/// Primary authority: a stale but valid spare must never roll back a valid
/// primary. Missing, malformed and wrong-sized copies are not restore sources.
#[test]
fn primary_wins_and_only_a_valid_exact_size_spare_restores() {
    let old = image();
    let mut primary = old.clone();
    StoreMut::parse(&mut primary)
        .unwrap()
        .set(&[65], &[1; 16], 7, b"new")
        .unwrap();
    let invalid = vec![0; SIZE];
    assert_eq!(
        decide(Some(&primary), Some(&primary), SIZE),
        Decision::Unchanged
    );
    for spare in [
        None,
        Some(old.as_slice()),
        Some(invalid.as_slice()),
        Some(&old[..SIZE - 1]),
    ] {
        assert_eq!(decide(Some(&primary), spare, SIZE), Decision::Mirror);
    }
    for primary in [None, Some(invalid.as_slice()), Some(&old[..SIZE - 1])] {
        assert_eq!(decide(primary, Some(&old), SIZE), Decision::Restore);
        for spare in [None, Some(invalid.as_slice()), Some(&old[..SIZE - 1])] {
            assert_eq!(decide(primary, spare, SIZE), Decision::Invalid);
        }
    }
}

/// Reclaim is strictly below 25% of variable capacity, not 25% of the image;
/// compaction preserves live values while recovering superseded records.
#[test]
fn reclaim_threshold_and_live_values() {
    let mut image = image();
    let mut store = StoreMut::parse(&mut image).unwrap();
    assert!(!needs_reclaim(store.as_store()));
    let value = vec![42; 16384];
    while !needs_reclaim(store.as_store()) {
        let before = store.as_store();
        assert!(before.free_space() * 4 >= before.capacity());
        store.set(&[65], &[1; 16], 7, &value).unwrap();
    }
    let before = store.as_store();
    assert!(before.free_space() * 4 < before.capacity());
    let mut scratch = vec![0; SIZE];
    assert!(store.reclaim(&mut scratch).unwrap() > 0);
    let after = Store::parse(store.image()).unwrap();
    assert!(!needs_reclaim(after));
    assert_eq!(after.get(&[65], &[1; 16]).unwrap().data, value);
    assert_eq!(after.list().count(), 1);
}
