//! Explicit, versioned selection of the storage that holds an EFVS image.
//!
//! A descriptor is external configuration (normally `EFI/EFVS/store.cfg` on the
//! selected ESP), not part of the EFVS on-disk format. It names one partition or
//! one file below the ESP that contains a fixed-size EFVS image. Selection is
//! authoritative: an invalid descriptor or missing target is an error, never a
//! reason to fall back to partition discovery.
use super::*;
/// Bytes of one encoded backing descriptor.
pub const BACKING_DESCRIPTOR_SIZE: usize = 320;
/// Largest store image a descriptor may name, so consumers can bound their
/// whole-image read before validating a file or partition target.
pub const BACKING_MAX_STORE_SIZE: u64 = 16 * 1024 * 1024;
/// Largest canonical volume-relative path a descriptor accepts.
pub const BACKING_PATH_CAPACITY: usize = 256;
/// ESP-relative path of the selection descriptor.
pub const BACKING_CONFIG_PATH: &str = "EFI/EFVS/store.cfg";
/// The same selection path for UEFI file protocols.
pub const BACKING_CONFIG_UEFI_PATH: &str = "\\EFI\\EFVS\\store.cfg";
/// The wire version this crate writes and accepts.
pub const BACKING_VERSION: u16 = 1;
/// Which object holds the EFVS image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BackingKind {
    /// A GPT partition, named by its unique partition GUID.
    Partition = 1,
    /// A fixed-size regular file below the selected ESP.
    File = 2,
}
/// A validated selection of one EFVS backing object.
///
/// The store identity is independent of the locator. A partition-backed store
/// normally uses its partition UUID as the store UUID; a file-backed store needs
/// its own stable UUID because the containing ESP is already the partition UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackingDescriptor {
    /// Partition or file backing.
    pub kind: BackingKind,
    /// Stable identity of the EFVS store, independent of where it lives.
    pub store_uuid: Guid,
    /// Partition holding the store, or the containing ESP for a file.
    pub partition_uuid: Guid,
    /// Exact image size in bytes.
    pub store_size: u64,
    /// At least the physical write unit of the backing device.
    pub write_unit: u32,
    path: [u8; BACKING_PATH_CAPACITY],
    path_len: u16,
}
impl BackingDescriptor {
    /// Select a whole partition. Its UUID is also the store UUID by convention.
    pub fn partition(
        store_uuid: Guid,
        partition_uuid: Guid,
        store_size: u64,
        write_unit: u32,
    ) -> Result<Self, Error> {
        Self::new(
            BackingKind::Partition,
            store_uuid,
            partition_uuid,
            store_size,
            write_unit,
            "",
        )
    }
    /// Select a fixed-size file below the ESP that holds the store.
    pub fn file(
        store_uuid: Guid,
        esp_uuid: Guid,
        store_size: u64,
        write_unit: u32,
        path: &str,
    ) -> Result<Self, Error> {
        Self::new(
            BackingKind::File,
            store_uuid,
            esp_uuid,
            store_size,
            write_unit,
            path,
        )
    }
    fn new(
        kind: BackingKind,
        store_uuid: Guid,
        partition_uuid: Guid,
        store_size: u64,
        write_unit: u32,
        path: &str,
    ) -> Result<Self, Error> {
        let bytes = path.as_bytes();
        if bytes.len() > BACKING_PATH_CAPACITY {
            return Err(Error::InvalidParameter);
        }
        let mut stored = [0; BACKING_PATH_CAPACITY];
        stored[..bytes.len()].copy_from_slice(bytes);
        let descriptor = Self {
            kind,
            store_uuid,
            partition_uuid,
            store_size,
            write_unit,
            path: stored,
            path_len: bytes.len() as u16,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
    /// The canonical, volume-relative path; empty for a partition backing.
    pub fn path(&self) -> &str {
        // The constructor and decoder admit ASCII only.
        core::str::from_utf8(&self.path[..self.path_len as usize]).unwrap_or("")
    }
    /// Re-check every invariant that a decoded descriptor must satisfy.
    pub fn validate(&self) -> Result<(), Error> {
        if self.store_uuid == [0; 16]
            || self.partition_uuid == [0; 16]
            || self.write_unit < MIN_BLOCK_SIZE as u32
            || self.write_unit > MAX_BLOCK_SIZE as u32
            || !self.write_unit.is_power_of_two()
            || self.store_size < 2 * u64::from(self.write_unit)
            || self.store_size > BACKING_MAX_STORE_SIZE
            || !self.store_size.is_multiple_of(u64::from(self.write_unit))
        {
            return Err(Error::InvalidParameter);
        }
        let len = self.path_len as usize;
        if len > BACKING_PATH_CAPACITY
            || self.path[len..].iter().any(|byte| *byte != 0)
            || self.kind == BackingKind::Partition && len != 0
            || self.kind == BackingKind::File
                && (!valid_path(&self.path[..len])
                    || self.path[..len].eq_ignore_ascii_case(BACKING_CONFIG_PATH.as_bytes()))
        {
            return Err(Error::InvalidParameter);
        }
        Ok(())
    }
    /// Encode the fixed-width descriptor into `dst`.
    pub fn encode(self, dst: &mut [u8]) -> Result<(), Error> {
        self.validate()?;
        let out = dst
            .get_mut(..BACKING_DESCRIPTOR_SIZE)
            .ok_or(Error::Bounds)?;
        out.fill(0);
        out[..4].copy_from_slice(b"EFVB");
        out[4..6].copy_from_slice(&BACKING_VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&(BACKING_DESCRIPTOR_SIZE as u16).to_le_bytes());
        out[8] = self.kind as u8;
        out[16..32].copy_from_slice(&self.store_uuid);
        out[32..48].copy_from_slice(&self.partition_uuid);
        out[48..56].copy_from_slice(&self.store_size.to_le_bytes());
        out[56..60].copy_from_slice(&self.write_unit.to_le_bytes());
        out[60..62].copy_from_slice(&self.path_len.to_le_bytes());
        out[64..64 + self.path_len as usize].copy_from_slice(&self.path[..self.path_len as usize]);
        Ok(())
    }
    /// Decode and strictly validate one descriptor.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let b = bytes.get(..BACKING_DESCRIPTOR_SIZE).ok_or(Error::Bounds)?;
        if &b[..4] != b"EFVB"
            || u16_at(b, 4) != BACKING_VERSION
            || u16_at(b, 6) != BACKING_DESCRIPTOR_SIZE as u16
            || b[9..16].iter().chain(b[62..64].iter()).any(|b| *b != 0)
        {
            return Err(Error::Header);
        }
        let kind = match b[8] {
            1 => BackingKind::Partition,
            2 => BackingKind::File,
            _ => return Err(Error::Header),
        };
        let path_len = u16_at(b, 60) as usize;
        if path_len > BACKING_PATH_CAPACITY || b[64 + path_len..].iter().any(|byte| *byte != 0) {
            return Err(Error::Header);
        }
        let mut path = [0; BACKING_PATH_CAPACITY];
        path[..path_len].copy_from_slice(&b[64..64 + path_len]);
        let descriptor = Self {
            kind,
            store_uuid: b[16..32].try_into().unwrap(),
            partition_uuid: b[32..48].try_into().unwrap(),
            store_size: u64_at(b, 48),
            write_unit: u32_at(b, 56),
            path,
            path_len: path_len as u16,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
}
/// Canonical relative path rules: ASCII, slash-separated, no empty, dot or
/// trailing-dot components, no leading or trailing separator, no alternate
/// separator. The selector path itself is refused separately.
fn valid_path(path: &[u8]) -> bool {
    if path.is_empty() || path[0] == b'/' || path[path.len() - 1] == b'/' {
        return false;
    }
    path.split(|byte| *byte == b'/').all(|component| {
        !component.is_empty()
            && component != b"."
            && component != b".."
            && component[component.len() - 1] != b'.'
            && component.len() <= 255
            && component
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.'))
    })
}
