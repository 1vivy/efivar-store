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

/// EFI_GUID bytes in their on-disk (mixed-endian) representation.
pub type Guid = [u8; 16];
/// An `EFI_TIME` in its 16-byte on-disk form.
pub type Timestamp = [u8; 16];
/// The EFVS wire-format version this crate writes and accepts.
pub const VERSION: u16 = 1;
/// The 1 MiB phone partition layout this format was designed for.
pub const PHONE_SIZE: usize = 1024 * 1024;
/// Capacity of each of the two checkpoints in the phone layout.
pub const PHONE_CHECKPOINT_CAPACITY: usize = 128 * 1024;
/// `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS`.
pub const ATTR_TIME_AUTH: u32 = 0x20;
/// `EFI_VARIABLE_APPEND_WRITE`.
pub const ATTR_APPEND: u32 = 0x40;
/// Why an EFVS image, record or update was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A buffer is shorter than the structure it must hold, or size arithmetic
    /// overflowed.
    Bounds,
    /// The header is not an EFVS header of this version and size.
    Header,
    /// A CRC-32, SHA-256 or checkpoint hash does not match the bytes it covers.
    Checksum,
    /// The checkpoint is malformed, duplicates a key or disagrees with its count.
    Checkpoint,
    /// A log record is malformed, truncated or out of sequence.
    Record,
    /// A variable name is empty, not UTF-16 or too long.
    Name,
    /// The checkpoint or log has no room for the update.
    Full,
    /// The variable or prefix is write-protected for this operation.
    WriteProtected,
    /// The update is not authorized: a secure-boot key, an invalid signature or a
    /// policy refusal.
    SecurityViolation,
    /// The request is inconsistent with the variable's stored state.
    InvalidParameter,
    /// The variable does not exist.
    NotFound,
    /// The authenticated counter in the store is below the freshness anchor.
    Rollback,
    /// The feature or descriptor is not implemented by this format version.
    Unsupported,
    /// The anchor is locked and cannot be bumped again.
    Locked,
    /// The anchor bump would not increase the protected value.
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
        && name.len().is_multiple_of(2)
        && name.len() <= u16::MAX as usize
        && core::char::decode_utf16(
            name.as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]])),
        )
        .all(|c| matches!(c,Ok(c) if c!='\0'))
}
pub(crate) fn name_is(name: &[u8], text: &str) -> bool {
    name.as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .eq(text.encode_utf16())
}
