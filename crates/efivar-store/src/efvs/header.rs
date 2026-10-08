use super::*;
pub const HEADER_SIZE: usize = 64;
pub const DEFAULT_BLOCK_SIZE: usize = 4096;
pub const MIN_BLOCK_SIZE: usize = 512;
pub const MAX_BLOCK_SIZE: usize = 65536;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub image_size: usize,
    pub checkpoint_offset: usize,
    /// Capacity of each of the two checkpoint slots.
    pub checkpoint_capacity: usize,
    pub log_offset: usize,
    pub log_capacity: usize,
    pub block_size: usize,
    /// Header A is at zero; header B is at block_size.
    pub header_offset: usize,
    pub generation: u64,
}
impl Header {
    pub fn new(image_size: usize, checkpoint_capacity: usize) -> Result<Self, Error> {
        Self::new_with_block(image_size, checkpoint_capacity, DEFAULT_BLOCK_SIZE)
    }
    pub fn new_with_block(
        image_size: usize,
        checkpoint_capacity: usize,
        block_size: usize,
    ) -> Result<Self, Error> {
        let checkpoint_offset = block_size.checked_mul(2).ok_or(Error::Bounds)?;
        let log_offset = checkpoint_capacity
            .checked_mul(2)
            .and_then(|n| n.checked_add(checkpoint_offset))
            .ok_or(Error::Bounds)?;
        let h = Self {
            image_size,
            checkpoint_offset,
            checkpoint_capacity,
            log_offset,
            log_capacity: image_size.checked_sub(log_offset).ok_or(Error::Bounds)?,
            block_size,
            header_offset: 0,
            generation: 0,
        };
        h.validate()?;
        Ok(h)
    }
    fn validate(self) -> Result<(), Error> {
        if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&self.block_size)
            || !self.block_size.is_power_of_two()
            || self.checkpoint_capacity < self.block_size
            || self.checkpoint_capacity > u32::MAX as usize
            || self.checkpoint_capacity % self.block_size != 0
            || self.image_size % self.block_size != 0
            || (self.header_offset != 0 && self.header_offset != self.block_size)
        {
            return Err(Error::Header);
        }
        let start = self.block_size * 2;
        let expected = start
            .checked_add(if self.header_offset == 0 {
                0
            } else {
                self.checkpoint_capacity
            })
            .ok_or(Error::Bounds)?;
        if self.checkpoint_offset != expected
            || self.log_offset
                != self
                    .checkpoint_capacity
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(start))
                    .ok_or(Error::Bounds)?
            || self.log_offset.checked_add(self.log_capacity) != Some(self.image_size)
        {
            return Err(Error::Header);
        }
        Ok(())
    }
    pub fn checkpoint_range(self) -> core::ops::Range<usize> {
        self.checkpoint_offset..self.checkpoint_offset + self.checkpoint_capacity
    }
    pub fn header_range(self) -> core::ops::Range<usize> {
        self.header_offset..self.header_offset + self.block_size
    }
    pub(crate) fn inactive(self) -> Self {
        let header_offset = if self.header_offset == 0 {
            self.block_size
        } else {
            0
        };
        Self {
            header_offset,
            checkpoint_offset: self.block_size * 2
                + if header_offset == 0 {
                    0
                } else {
                    self.checkpoint_capacity
                },
            ..self
        }
    }
    /// Select the highest-generation CRC-valid header whose referenced checkpoint
    /// also validates. Scan supported block-size positions so a destroyed header A
    /// cannot hide header B's geometry. Equal generations prefer header A.
    pub fn decode(image: &[u8]) -> Result<Self, Error> {
        let mut selected = Self::decode_at(image, 0).ok();
        let mut block = MIN_BLOCK_SIZE;
        while block <= MAX_BLOCK_SIZE {
            if let Ok(candidate) = Self::decode_at(image, block) {
                if selected.is_none_or(|old| candidate.generation > old.generation) {
                    selected = Some(candidate);
                }
            }
            block *= 2;
        }
        selected.ok_or(Error::Header)
    }
    fn decode_at(image: &[u8], offset: usize) -> Result<Self, Error> {
        let b = image
            .get(offset..)
            .and_then(|b| b.get(..HEADER_SIZE))
            .ok_or(Error::Bounds)?;
        if &b[..4] != b"EFVS" || u16_at(b, 4) != VERSION || u16_at(b, 6) != HEADER_SIZE as u16 {
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
            block_size: u32_at(b, 52) as usize,
            header_offset: offset,
            generation: u64_at(b, 56),
        };
        h.validate()?;
        if h.image_size != image.len() {
            return Err(Error::Bounds);
        }
        if image[h.header_offset + HEADER_SIZE..h.header_offset + h.block_size]
            .iter()
            .any(|b| *b != 0)
        {
            return Err(Error::Header);
        }
        Checkpoint::decode(&image[h.checkpoint_range()])?;
        Ok(h)
    }
    /// Encode the 64-byte structure. Its remaining physical header block is zero.
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
        b[52..56].copy_from_slice(&(self.block_size as u32).to_le_bytes());
        b[56..64].copy_from_slice(&self.generation.to_le_bytes());
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
    initialize_with_block(image, checkpoint_capacity, DEFAULT_BLOCK_SIZE)
}
pub fn initialize_with_block(
    image: &mut [u8],
    checkpoint_capacity: usize,
    block_size: usize,
) -> Result<(), Error> {
    let first = Header::new_with_block(image.len(), checkpoint_capacity, block_size)?;
    image.fill(0);
    for h in [first, first.inactive()] {
        initialize_checkpoint(&mut image[h.checkpoint_range()])?;
        h.encode(&mut image[h.header_range()])?;
    }
    Ok(())
}
