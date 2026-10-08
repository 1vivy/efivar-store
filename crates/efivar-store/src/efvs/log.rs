use super::*;
use crate::sha256::digest;
pub const RECORD_HEADER_SIZE: usize = 76;
pub const RECORD_MIN_SIZE: usize = 112;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Operation {
    Set = 1,
    Append = 2,
    Delete = 3,
}
#[derive(Clone, Copy, Debug)]
pub struct RecordInput<'a> {
    pub name: &'a [u8],
    pub guid: Guid,
    pub attributes: u32,
    pub operation: Operation,
    pub data: &'a [u8],
}
impl RecordInput<'_> {
    pub fn encoded_len(self) -> Result<usize, Error> {
        if !valid_name(self.name) || self.data.len() > u32::MAX as usize {
            return Err(Error::Name);
        }
        let length = align(
            RECORD_HEADER_SIZE
                .checked_add(self.name.len())
                .and_then(|n| n.checked_add(self.data.len()))
                .and_then(|n| n.checked_add(32))
                .ok_or(Error::Bounds)?,
        )?;
        u32::try_from(length).map_err(|_| Error::Bounds)?;
        Ok(length)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    pub input: RecordInput<'a>,
    pub sequence: u64,
    pub previous_hash: [u8; 32],
    pub hash: [u8; 32],
    pub length: usize,
}
impl<'a> Record<'a> {
    pub fn encode(
        dst: &mut [u8],
        input: RecordInput<'_>,
        sequence: u64,
        previous_hash: [u8; 32],
    ) -> Result<usize, Error> {
        let n = input.encoded_len()?;
        let b = dst.get_mut(..n).ok_or(Error::Full)?;
        b.fill(0);
        b[..4].copy_from_slice(b"EFVR");
        let length = u32::try_from(n).map_err(|_| Error::Bounds)?;
        b[4..8].copy_from_slice(&length.to_le_bytes());
        b[8..16].copy_from_slice(&sequence.to_le_bytes());
        b[16..48].copy_from_slice(&previous_hash);
        b[48..50].copy_from_slice(&(input.name.len() as u16).to_le_bytes());
        b[50..52].copy_from_slice(&(input.operation as u16).to_le_bytes());
        b[52..56].copy_from_slice(&input.attributes.to_le_bytes());
        b[56..72].copy_from_slice(&input.guid);
        b[72..76].copy_from_slice(&(input.data.len() as u32).to_le_bytes());
        let end = 76 + input.name.len();
        b[76..end].copy_from_slice(input.name);
        b[end..end + input.data.len()].copy_from_slice(input.data);
        let hash = digest(&b[..n - 32]);
        b[n - 32..].copy_from_slice(&hash);
        Ok(n)
    }
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < RECORD_MIN_SIZE || &bytes[..4] != b"EFVR" {
            return Err(Error::Record);
        }
        let n = u32_at(bytes, 4) as usize;
        if n < RECORD_MIN_SIZE || n % 8 != 0 {
            return Err(Error::Record);
        }
        let b = bytes.get(..n).ok_or(Error::Bounds)?;
        let name_end = 76usize
            .checked_add(u16_at(b, 48) as usize)
            .ok_or(Error::Bounds)?;
        let end = name_end
            .checked_add(u32_at(b, 72) as usize)
            .ok_or(Error::Bounds)?;
        if end > n - 32 || align(end + 32)? != n || b[end..n - 32].iter().any(|b| *b != 0) {
            return Err(Error::Record);
        }
        let name = &b[76..name_end];
        if !valid_name(name) {
            return Err(Error::Name);
        }
        let operation = match u16_at(b, 50) {
            1 => Operation::Set,
            2 => Operation::Append,
            3 => Operation::Delete,
            _ => return Err(Error::Record),
        };
        let hash: [u8; 32] = b[n - 32..].try_into().unwrap();
        if digest(&b[..n - 32]) != hash {
            return Err(Error::Checksum);
        }
        Ok(Self {
            input: RecordInput {
                name,
                guid: b[56..72].try_into().unwrap(),
                attributes: u32_at(b, 52),
                operation,
                data: &b[name_end..end],
            },
            sequence: u64_at(b, 8),
            previous_hash: b[16..48].try_into().unwrap(),
            hash,
            length: n,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogEnd {
    Clean,
    Torn,
}
pub struct Log<'a> {
    bytes: &'a [u8],
    pub consumed: usize,
    pub next_sequence: u64,
    pub previous_hash: [u8; 32],
    pub end: LogEnd,
    stopped: bool,
}
impl<'a> Log<'a> {
    pub fn new(bytes: &'a [u8], checkpoint_hash: [u8; 32], next_sequence: u64) -> Self {
        Self {
            bytes,
            consumed: 0,
            next_sequence,
            previous_hash: checkpoint_hash,
            end: LogEnd::Clean,
            stopped: false,
        }
    }
}
impl<'a> Iterator for Log<'a> {
    type Item = Record<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped {
            return None;
        }
        let remaining = &self.bytes[self.consumed..];
        if remaining.iter().all(|b| *b == 0) {
            self.stopped = true;
            return None;
        }
        let record = match Record::decode(remaining) {
            Ok(r) if r.sequence == self.next_sequence && r.previous_hash == self.previous_hash => r,
            _ => {
                self.end = LogEnd::Torn;
                self.stopped = true;
                return None;
            }
        };
        let Some(next) = self.next_sequence.checked_add(1) else {
            self.end = LogEnd::Torn;
            self.stopped = true;
            return None;
        };
        self.next_sequence = next;
        self.previous_hash = record.hash;
        self.consumed += record.length;
        Some(record)
    }
}
