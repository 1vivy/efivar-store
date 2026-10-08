use super::*;
/// 930e89ed-540e-4af0-9b41-c2c559939d50 in EFI GUID wire order.
pub const CONFIG_TABLE_GUID: Guid = [
    0xed, 0x89, 0x0e, 0x93, 0x0e, 0x54, 0xf0, 0x4a, 0x9b, 0x41, 0xc2, 0xc5, 0x59, 0x93, 0x9d, 0x50,
];
/// Recommended fresh-deployment type, not required for discovery/format identity.
pub const PARTITION_TYPE_GUID: Guid = [
    0xb2, 0x63, 0x76, 0x51, 0xb3, 0x3f, 0x78, 0x4a, 0x9a, 0xbe, 0xc4, 0x55, 0x94, 0x84, 0x8d, 0xd5,
];
pub const CONFIG_TABLE_SIZE: usize = 48;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigTable {
    pub partition_guid: Guid,
    pub posture_tier: u8,
    pub anchor_value: u64,
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
        Ok(())
    }
    pub fn encode(self, dst: &mut [u8]) -> Result<(), Error> {
        self.validate()?;
        let b = dst.get_mut(..CONFIG_TABLE_SIZE).ok_or(Error::Bounds)?;
        b.fill(0);
        b[..4].copy_from_slice(b"EFVT");
        b[4..6].copy_from_slice(&VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(CONFIG_TABLE_SIZE as u16).to_le_bytes());
        b[8..24].copy_from_slice(&self.partition_guid);
        b[24] = self.posture_tier;
        b[28..32].copy_from_slice(&self.capabilities.to_le_bytes());
        b[32..40].copy_from_slice(&self.anchor_value.to_le_bytes());
        Ok(())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let b = bytes.get(..CONFIG_TABLE_SIZE).ok_or(Error::Bounds)?;
        if &b[..4] != b"EFVT"
            || u16_at(b, 4) != VERSION
            || u16_at(b, 6) != CONFIG_TABLE_SIZE as u16
            || b[25..28].iter().chain(b[40..48].iter()).any(|b| *b != 0)
        {
            return Err(Error::Header);
        }
        let t = Self {
            partition_guid: b[8..24].try_into().unwrap(),
            posture_tier: b[24],
            capabilities: u32_at(b, 28),
            anchor_value: u64_at(b, 32),
        };
        t.validate()?;
        Ok(t)
    }
}
