use super::*;
/// 930e89ed-540e-4af0-9b41-c2c559939d50 in EFI GUID wire order.
pub const CONFIG_TABLE_GUID: Guid = [
    0xed, 0x89, 0x0e, 0x93, 0x0e, 0x54, 0xf0, 0x4a, 0x9b, 0x41, 0xc2, 0xc5, 0x59, 0x93, 0x9d, 0x50,
];
/// Recommended fresh-deployment type, not required for discovery/format identity.
pub const PARTITION_TYPE_GUID: Guid = [
    0xb2, 0x63, 0x76, 0x51, 0xb3, 0x3f, 0x78, 0x4a, 0x9a, 0xbe, 0xc4, 0x55, 0x94, 0x84, 0x8d, 0xd5,
];
/// Wire version of the published configuration table.
pub const CONFIG_TABLE_VERSION: u16 = 2;
/// Bytes of one encoded EFVS configuration table.
pub const CONFIG_TABLE_SIZE: usize = 32 + BACKING_DESCRIPTOR_SIZE;
/// The EFVS configuration table published in `EFI_CONFIGURATION_TABLE`.
///
/// The descriptor binds a running image to the exact backing it opened; the
/// store identity is the descriptor's `store_uuid`, never a misleading
/// partition GUID for a file-backed store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigTable {
    /// Store identity, backing kind, locator and geometry.
    pub backing: BackingDescriptor,
    /// Provenance posture tier the platform can claim.
    pub posture_tier: u8,
    /// Freshness-anchor value the store was opened with.
    pub anchor_value: u64,
    /// Anchor capabilities the platform declares.
    pub capabilities: u32,
}
impl ConfigTable {
    fn validate(self) -> Result<(), Error> {
        if self.posture_tier != posture_tier(self.capabilities)
            || self.capabilities & !(CAP_MONOTONIC | CAP_RUNTIME_BUMP) != 0
            || self.capabilities & CAP_RUNTIME_BUMP != 0 && self.capabilities & CAP_MONOTONIC == 0
        {
            return Err(Error::Unsupported);
        }
        self.backing.validate()?;
        Ok(())
    }
    /// Encode the table into `dst`.
    pub fn encode(self, dst: &mut [u8]) -> Result<(), Error> {
        self.validate()?;
        let b = dst.get_mut(..CONFIG_TABLE_SIZE).ok_or(Error::Bounds)?;
        b.fill(0);
        b[..4].copy_from_slice(b"EFVT");
        b[4..6].copy_from_slice(&CONFIG_TABLE_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(CONFIG_TABLE_SIZE as u16).to_le_bytes());
        b[8] = self.posture_tier;
        b[12..16].copy_from_slice(&self.capabilities.to_le_bytes());
        b[16..24].copy_from_slice(&self.anchor_value.to_le_bytes());
        self.backing.encode(&mut b[32..])?;
        Ok(())
    }
    /// Decode and validate a configuration table. Version 1 is rejected rather
    /// than interpreted with the version 2 layout.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let b = bytes.get(..CONFIG_TABLE_SIZE).ok_or(Error::Bounds)?;
        if &b[..4] != b"EFVT"
            || u16_at(b, 4) != CONFIG_TABLE_VERSION
            || u16_at(b, 6) != CONFIG_TABLE_SIZE as u16
            || b[9..12].iter().chain(b[24..32].iter()).any(|b| *b != 0)
        {
            return Err(Error::Header);
        }
        let t = Self {
            backing: BackingDescriptor::decode(&b[32..])?,
            posture_tier: b[8],
            capabilities: u32_at(b, 12),
            anchor_value: u64_at(b, 16),
        };
        t.validate()?;
        Ok(t)
    }
}
