use super::*;
use crate::sha256::Sha256;
pub const CHECKPOINT_HEADER_SIZE: usize = 96;
pub const VARIABLE_HEADER_SIZE: usize = 48;
#[derive(Clone, Copy, Debug)]
pub struct Variable<'a> {
    pub name: &'a [u8],
    pub guid: Guid,
    pub attributes: u32,
    pub timestamp: Timestamp,
    pub data: &'a [u8],
}
fn checkpoint_hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&bytes[..32]);
    h.update(&[0; 32]);
    h.update(&bytes[64..]);
    h.finalize()
}
#[derive(Clone, Copy)]
pub struct Checkpoint<'a> {
    bytes: &'a [u8],
    pub used: usize,
    pub count: u32,
    pub next_sequence: u64,
    pub authenticated_count: u64,
    pub hash: [u8; 32],
}
impl<'a> Checkpoint<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < CHECKPOINT_HEADER_SIZE
            || bytes.len() % 8 != 0
            || &bytes[..4] != b"EFVC"
            || u16_at(bytes, 4) != VERSION
            || u16_at(bytes, 6) != CHECKPOINT_HEADER_SIZE as u16
            || bytes[64..96].iter().any(|b| *b != 0)
        {
            return Err(Error::Checkpoint);
        }
        let used = u32_at(bytes, 8) as usize;
        if used < CHECKPOINT_HEADER_SIZE
            || used > bytes.len()
            || used % 8 != 0
            || bytes[used..].iter().any(|b| *b != 0)
        {
            return Err(Error::Checkpoint);
        }
        let hash = bytes[32..64].try_into().unwrap();
        if checkpoint_hash(bytes) != hash {
            return Err(Error::Checksum);
        }
        let cp = Self {
            bytes,
            used,
            count: u32_at(bytes, 12),
            next_sequence: u64_at(bytes, 16),
            authenticated_count: u64_at(bytes, 24),
            hash,
        };
        let mut pos = CHECKPOINT_HEADER_SIZE;
        let mut count = 0u32;
        while pos < used {
            let (v, n) = decode_variable(&bytes[pos..used])?;
            // Duplicate keys make replay ambiguous; reject instead of choosing one.
            if (Variables {
                bytes: &bytes[CHECKPOINT_HEADER_SIZE..pos],
            })
            .any(|old| old.guid == v.guid && old.name == v.name)
            {
                return Err(Error::Checkpoint);
            }
            pos += n;
            count = count.checked_add(1).ok_or(Error::Bounds)?;
        }
        if count != cp.count {
            return Err(Error::Checkpoint);
        }
        Ok(cp)
    }
    pub fn variables(self) -> Variables<'a> {
        Variables {
            bytes: &self.bytes[CHECKPOINT_HEADER_SIZE..self.used],
        }
    }
}
fn decode_variable(bytes: &[u8]) -> Result<(Variable<'_>, usize), Error> {
    if bytes.len() < VARIABLE_HEADER_SIZE {
        return Err(Error::Bounds);
    }
    let n = u32_at(bytes, 0) as usize;
    let name_end = 48 + u16_at(bytes, 8) as usize;
    let end = name_end
        .checked_add(u32_at(bytes, 12) as usize)
        .ok_or(Error::Bounds)?;
    if n < 48
        || n > bytes.len()
        || align(end)? != n
        || u16_at(bytes, 10) != 0
        || bytes[end..n].iter().any(|b| *b != 0)
    {
        return Err(Error::Checkpoint);
    }
    let name = &bytes[48..name_end];
    if !valid_name(name) {
        return Err(Error::Name);
    }
    Ok((
        Variable {
            name,
            guid: bytes[16..32].try_into().unwrap(),
            attributes: u32_at(bytes, 4),
            timestamp: bytes[32..48].try_into().unwrap(),
            data: &bytes[name_end..end],
        },
        n,
    ))
}
pub struct Variables<'a> {
    bytes: &'a [u8],
}
impl<'a> Iterator for Variables<'a> {
    type Item = Variable<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let (v, n) = decode_variable(self.bytes).ok()?;
        self.bytes = &self.bytes[n..];
        Some(v)
    }
}
pub fn initialize_checkpoint(bytes: &mut [u8]) -> Result<(), Error> {
    if bytes.len() < CHECKPOINT_HEADER_SIZE
        || bytes.len() > u32::MAX as usize
        || bytes.len() % 8 != 0
    {
        return Err(Error::Bounds);
    }
    bytes.fill(0);
    bytes[..4].copy_from_slice(b"EFVC");
    bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
    bytes[6..8].copy_from_slice(&(CHECKPOINT_HEADER_SIZE as u16).to_le_bytes());
    bytes[8..12].copy_from_slice(&(CHECKPOINT_HEADER_SIZE as u32).to_le_bytes());
    let hash = checkpoint_hash(bytes);
    bytes[32..64].copy_from_slice(&hash);
    Ok(())
}
/// Caller-owned packed working set. Mutation is allocation-free; errors do not alter it.
pub struct State<'a> {
    pub(crate) bytes: &'a mut [u8],
    pub(crate) used: usize,
    pub next_sequence: u64,
    pub authenticated_count: u64,
}
impl<'a> State<'a> {
    pub fn from_checkpoint(checkpoint: &[u8], scratch: &'a mut [u8]) -> Result<Self, Error> {
        let cp = Checkpoint::decode(checkpoint)?;
        if scratch.len() < checkpoint.len() {
            return Err(Error::Full);
        }
        let bytes = &mut scratch[..checkpoint.len()];
        bytes.copy_from_slice(checkpoint);
        Ok(Self {
            bytes,
            used: cp.used,
            next_sequence: cp.next_sequence,
            authenticated_count: cp.authenticated_count,
        })
    }
    pub fn empty(scratch: &'a mut [u8]) -> Result<Self, Error> {
        initialize_checkpoint(scratch)?;
        Ok(Self {
            bytes: scratch,
            used: CHECKPOINT_HEADER_SIZE,
            next_sequence: 0,
            authenticated_count: 0,
        })
    }
    pub fn variables(&self) -> Variables<'_> {
        Variables {
            bytes: &self.bytes[CHECKPOINT_HEADER_SIZE..self.used],
        }
    }
    pub fn get(&self, name: &[u8], guid: &Guid) -> Option<Variable<'_>> {
        self.variables().find(|v| v.name == name && v.guid == *guid)
    }
    pub fn capacity(&self) -> usize {
        self.bytes.len() - CHECKPOINT_HEADER_SIZE
    }
    pub fn used(&self) -> usize {
        self.used - CHECKPOINT_HEADER_SIZE
    }
    fn locate(&self, name: &[u8], guid: &Guid) -> Option<(usize, usize)> {
        let mut pos = CHECKPOINT_HEADER_SIZE;
        while pos < self.used {
            let (v, n) = decode_variable(&self.bytes[pos..self.used]).ok()?;
            if v.name == name && v.guid == *guid {
                return Some((pos, n));
            }
            pos += n;
        }
        None
    }
    /// Firmware/import path, not a policy bypass for runtime clients.
    pub fn insert_checkpoint(&mut self, v: Variable<'_>) -> Result<(), Error> {
        self.update(v, Operation::Set)
    }
    pub(crate) fn update(&mut self, v: Variable<'_>, op: Operation) -> Result<(), Error> {
        if !valid_name(v.name) || v.data.len() > u32::MAX as usize {
            return Err(Error::Name);
        }
        let existing = self.locate(v.name, &v.guid);
        if op == Operation::Delete {
            let (pos, n) = existing.ok_or(Error::NotFound)?;
            self.bytes.copy_within(pos + n..self.used, pos);
            self.used -= n;
            self.bytes[self.used..].fill(0);
            return Ok(());
        }
        if op == Operation::Append && v.data.is_empty() {
            return Ok(());
        }
        let old_data = if op == Operation::Append {
            self.get(v.name, &v.guid).map_or(0, |v| v.data.len())
        } else {
            0
        };
        let data_len = old_data.checked_add(v.data.len()).ok_or(Error::Bounds)?;
        let n = align(
            48usize
                .checked_add(v.name.len())
                .and_then(|n| n.checked_add(data_len))
                .ok_or(Error::Bounds)?,
        )?;
        let (pos, old_n) = existing.unwrap_or((self.used, 0));
        let new_used = self
            .used
            .checked_sub(old_n)
            .and_then(|u| u.checked_add(n))
            .ok_or(Error::Bounds)?;
        if new_used > self.bytes.len() || data_len > u32::MAX as usize {
            return Err(Error::Full);
        }
        self.bytes.copy_within(pos + old_n..self.used, pos + n);
        let b = &mut self.bytes[pos..pos + n];
        b[..48].fill(0);
        b[..4].copy_from_slice(&(n as u32).to_le_bytes());
        b[4..8].copy_from_slice(&(v.attributes & !ATTR_APPEND).to_le_bytes());
        b[8..10].copy_from_slice(&(v.name.len() as u16).to_le_bytes());
        b[12..16].copy_from_slice(&(data_len as u32).to_le_bytes());
        b[16..32].copy_from_slice(&v.guid);
        b[32..48].copy_from_slice(&v.timestamp);
        b[48..48 + v.name.len()].copy_from_slice(v.name);
        let data_start = 48 + v.name.len();
        b[data_start + old_data..data_start + data_len].copy_from_slice(v.data);
        b[data_start + data_len..].fill(0);
        self.used = new_used;
        self.bytes[self.used..].fill(0);
        Ok(())
    }
    pub fn encode_checkpoint(&self, dst: &mut [u8]) -> Result<(), Error> {
        if dst.len() != self.bytes.len() {
            return Err(Error::Bounds);
        }
        dst.copy_from_slice(self.bytes);
        dst[8..12].copy_from_slice(&(self.used as u32).to_le_bytes());
        dst[12..16].copy_from_slice(&(self.variables().count() as u32).to_le_bytes());
        dst[16..24].copy_from_slice(&self.next_sequence.to_le_bytes());
        dst[24..32].copy_from_slice(&self.authenticated_count.to_le_bytes());
        let hash = checkpoint_hash(dst);
        dst[32..64].copy_from_slice(&hash);
        Ok(())
    }
}
/// Pure image compaction. Caller must persist checkpoint, clear log, then bump/lock anchor.
pub fn compact(image: &mut [u8], state: &State<'_>) -> Result<u64, Error> {
    let h = Header::decode(image)?;
    if state.bytes.len() != h.checkpoint_capacity {
        return Err(Error::Bounds);
    }
    state.encode_checkpoint(&mut image[h.checkpoint_offset..h.log_offset])?;
    image[h.log_offset..].fill(0);
    Ok(state.authenticated_count)
}
