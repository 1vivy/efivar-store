//! Offline edk2 interoperability. Import preserves every live variable, including
//! authentication metadata; policy filtering happens when EFVS is replayed.
use crate::{Layout, Store, efvs};
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    Edk2(crate::Error),
    Efvs(efvs::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for Error {}
pub fn import_edk2(
    source: &[u8],
    destination: &mut [u8],
    checkpoint_capacity: usize,
    scratch: &mut [u8],
) -> Result<usize, Error> {
    let store = Store::parse(source).map_err(Error::Edk2)?;
    // Build the entire checkpoint before touching the destination.
    let header = efvs::Header::new(destination.len(), checkpoint_capacity).map_err(Error::Efvs)?;
    let scratch = scratch
        .get_mut(..checkpoint_capacity)
        .ok_or(Error::Efvs(efvs::Error::Full))?;
    let mut state = efvs::State::empty(scratch).map_err(Error::Efvs)?;
    let mut count = 0;
    for record in store.live_records() {
        let timestamp = if store.layout() == Layout::Authenticated {
            source[record.offset + 16..record.offset + 32]
                .try_into()
                .unwrap()
        } else {
            [0; 16]
        };
        state
            .insert_checkpoint(efvs::Variable {
                name: record.name.as_bytes(),
                guid: record.guid,
                attributes: record.attributes,
                timestamp,
                data: record.data,
            })
            .map_err(Error::Efvs)?;
        count += 1;
    }
    efvs::initialize(destination, checkpoint_capacity).map_err(Error::Efvs)?;
    // Both initial generations must contain the imported state. Publishing an
    // empty fallback pair would lose every variable after one damaged header.
    for offset in [
        header.checkpoint_offset,
        header.checkpoint_offset + checkpoint_capacity,
    ] {
        state
            .encode_checkpoint(&mut destination[offset..offset + checkpoint_capacity])
            .map_err(Error::Efvs)?;
    }
    Ok(count)
}
