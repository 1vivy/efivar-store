//! EFVS v1 shared, allocation-free wire format and replay. See `docs/efvs-v1.md`.
mod anchor;
mod checkpoint;
mod config_table;
mod header;
mod log;
mod replay;
pub use anchor::*;
pub use checkpoint::*;
pub use config_table::*;
pub use header::*;
pub use log::*;
pub use replay::*;

pub type Guid = [u8; 16];
pub type Timestamp = [u8; 16];
pub const VERSION: u16 = 1;
pub const PHONE_SIZE: usize = 1024 * 1024;
pub const PHONE_CHECKPOINT_CAPACITY: usize = 256 * 1024;
pub const ATTR_TIME_AUTH: u32 = 0x20;
pub const ATTR_APPEND: u32 = 0x40;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Header,
    Checksum,
    Checkpoint,
    Record,
    Name,
    Full,
    WriteProtected,
    SecurityViolation,
    InvalidParameter,
    NotFound,
    Rollback,
    Unsupported,
    Locked,
    NonMonotonic,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for Error {}
pub(crate) fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
pub(crate) fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
pub(crate) fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
pub(crate) fn align(n: usize) -> Result<usize, Error> {
    n.checked_add(7).map(|n| n & !7).ok_or(Error::Bounds)
}
pub(crate) fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() % 2 == 0
        && name.len() <= u16::MAX as usize
        && core::char::decode_utf16(
            name.chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]])),
        )
        .all(|c| matches!(c,Ok(c) if c!='\0'))
}
pub(crate) fn name_is(name: &[u8], text: &str) -> bool {
    name.chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .eq(text.encode_utf16())
}
