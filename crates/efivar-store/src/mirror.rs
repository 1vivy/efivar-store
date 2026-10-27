//! Offline primary/spare selection. A valid primary always wins, even when the
//! spare is also valid: the spare is a previous pre-boot snapshot, not a journal.
use super::Store;

/// What an offline primary/spare comparison requires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Both copies are valid and identical.
    Unchanged,
    /// The primary is valid and differs: copy it over the spare.
    Mirror,
    /// The primary is invalid and the spare is valid: copy the spare back.
    Restore,
    /// Neither copy is a valid store at this size.
    Invalid,
}

/// Missing, unreadable and wrong-sized copies are invalid. No I/O or allocation.
pub fn decide(primary: Option<&[u8]>, spare: Option<&[u8]>, size: usize) -> Decision {
    let valid = |image: Option<&[u8]>| {
        image.is_some_and(|bytes| bytes.len() == size && Store::parse(bytes).is_ok())
    };
    if valid(primary) {
        if primary == spare {
            Decision::Unchanged
        } else {
            Decision::Mirror
        }
    } else if valid(spare) {
        Decision::Restore
    } else {
        Decision::Invalid
    }
}

/// Strictly below one quarter of the variable area, excluding FV/store headers.
pub fn needs_reclaim(store: Store<'_>) -> bool {
    store.free_space() < store.capacity().div_ceil(4)
}
