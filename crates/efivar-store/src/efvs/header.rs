use super::*;
pub const HEADER_SIZE: usize = 64;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub image_size: usize,
    pub checkpoint_offset: usize,
    pub checkpoint_capacity: usize,
    pub log_offset: usize,
    pub log_capacity: usize,
}
impl Header {
    pub fn new(image_size: usize, checkpoint_capacity: usize) -> Result<Self, Error> {
        let log_offset = HEADER_SIZE
            .checked_add(checkpoint_capacity)
            .ok_or(Error::Bounds)?;
        let h = Self {
            image_size,
            checkpoint_offset: HEADER_SIZE,
            checkpoint_capacity,
            log_offset,
            log_capacity: image_size.checked_sub(log_offset).ok_or(Error::Bounds)?,
        };
        h.validate()?;
        Ok(h)
    }
    fn validate(self) -> Result<(), Error> {
        if self.checkpoint_offset != HEADER_SIZE
            || self.checkpoint_capacity < CHECKPOINT_HEADER_SIZE
            || self.checkpoint_capacity % 8 != 0
            || self.log_offset
                != self
                    .checkpoint_offset
                    .checked_add(self.checkpoint_capacity)
                    .ok_or(Error::Bounds)?
            || self.log_capacity % 8 != 0
            || self.log_offset.checked_add(self.log_capacity) != Some(self.image_size)
        {
            return Err(Error::Header);
        }
        Ok(())
    }
    pub fn decode(image: &[u8]) -> Result<Self, Error> {
        let b = image.get(..HEADER_SIZE).ok_or(Error::Bounds)?;
        if &b[..4] != b"EFVS"
            || u16_at(b, 4) != VERSION
            || u16_at(b, 6) != HEADER_SIZE as u16
            || b[52..].iter().any(|b| *b != 0)
        {
            return Err(Error::Header);
        }
        let mut header = [0; HEADER_SIZE];
        header.copy_from_slice(b);
        header[48..52].fill(0);
        if crc32(&header) != u32_at(b, 48) {
            return Err(Error::Checksum);
        }
        let size = |o| usize::try_from(u64_at(b, o)).map_err(|_| Error::Bounds);
        let h = Self {
            image_size: size(8)?,
            checkpoint_offset: size(16)?,
            checkpoint_capacity: size(24)?,
            log_offset: size(32)?,
            log_capacity: size(40)?,
        };
        h.validate()?;
        if h.image_size != image.len() {
            return Err(Error::Bounds);
        }
        Ok(h)
    }
    pub fn encode(self, dst: &mut [u8]) -> Result<(), Error> {
        self.validate()?;
        let b = dst.get_mut(..HEADER_SIZE).ok_or(Error::Bounds)?;
        b.fill(0);
        b[..4].copy_from_slice(b"EFVS");
        b[4..6].copy_from_slice(&VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        for (o, n) in [
            (8, self.image_size),
            (16, self.checkpoint_offset),
            (24, self.checkpoint_capacity),
            (32, self.log_offset),
            (40, self.log_capacity),
        ] {
            b[o..o + 8].copy_from_slice(&(n as u64).to_le_bytes());
        }
        let crc = crc32(b);
        b[48..52].copy_from_slice(&crc.to_le_bytes());
        Ok(())
    }
}
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in bytes {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320u32.wrapping_mul(crc & 1));
        }
    }
    !crc
}
pub fn initialize(image: &mut [u8], checkpoint_capacity: usize) -> Result<(), Error> {
    let h = Header::new(image.len(), checkpoint_capacity)?;
    image.fill(0);
    h.encode(image)?;
    initialize_checkpoint(&mut image[h.checkpoint_offset..h.log_offset])?;
    Ok(())
}
