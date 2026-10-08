//! Little-endian physical-runtime index (not an FV parser).
//! Header: magic u64, used u32, count u32, truncation u32, reserved u32,
//! NV maximum/remaining/maximum-value u64, volatile equivalents u64 (72 bytes).
//! Records: GUID[16], attributes u32, name bytes u32 (including NUL),
//! data bytes u32, record bytes u32; UTF-16LE name, value, padding to 8.
use super::{Error, Guid, MAX_VARIABLES, NV, RT, Variable, valid_name};
use alloc::vec::Vec;
pub const HEADER: usize = 72;
pub const RECORD: usize = 32;
pub const MAGIC: u64 = 0x3158_4449_5652_4653;
pub const CAPACITY: usize = 2 * 1024 * 1024;

fn u32_at(bytes: &[u8], offset: usize) -> Result<usize, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Corrupt)?
            .try_into()
            .map_err(|_| Error::Corrupt)?,
    ) as usize)
}

pub struct Builder<'a> {
    output: &'a mut [u8],
    used: usize,
    count: usize,
}
impl<'a> Builder<'a> {
    pub fn new(output: &'a mut [u8], truncated: bool) -> Result<Self, Error> {
        if output.len() < HEADER {
            return Err(Error::OutOfResources);
        }
        let limit = output.len().min(CAPACITY);
        let output = &mut output[..limit];
        output.fill(0);
        output[..8].copy_from_slice(&MAGIC.to_le_bytes());
        output[16..20].copy_from_slice(&u32::from(truncated).to_le_bytes());
        Ok(Self {
            output,
            used: HEADER,
            count: 0,
        })
    }
    pub fn push(
        &mut self,
        name: &[u16],
        guid: &Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        if !valid_name(name) || attributes & RT == 0 {
            return Err(Error::InvalidParameter);
        }
        if data.len() > super::MAX_VALUE {
            return Err(Error::OutOfResources);
        }
        let name_bytes = (name.len() + 1) * 2;
        let size = (RECORD + name_bytes + data.len())
            .checked_add(7)
            .ok_or(Error::OutOfResources)?
            & !7;
        let end = self
            .used
            .checked_add(size)
            .filter(|end| *end <= self.output.len())
            .ok_or(Error::OutOfResources)?;
        if self.count == MAX_VARIABLES || end > u32::MAX as usize {
            return Err(Error::OutOfResources);
        }
        let r = &mut self.output[self.used..end];
        r[..16].copy_from_slice(guid);
        for (offset, value) in [
            (16, attributes as usize),
            (20, name_bytes),
            (24, data.len()),
            (28, size),
        ] {
            r[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
        for (i, unit) in name.iter().enumerate() {
            r[RECORD + i * 2..RECORD + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
        r[RECORD + name_bytes..RECORD + name_bytes + data.len()].copy_from_slice(data);
        self.used = end;
        self.count += 1;
        Ok(())
    }
    pub fn capacity(&mut self, nv: (u64, u64, u64), volatile: (u64, u64, u64)) {
        for (i, value) in [nv.0, nv.1, nv.2, volatile.0, volatile.1, volatile.2]
            .iter()
            .enumerate()
        {
            self.output[24 + i * 8..32 + i * 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    pub fn finish(self) {
        self.output[8..12].copy_from_slice(&(self.used as u32).to_le_bytes());
        self.output[12..16].copy_from_slice(&(self.count as u32).to_le_bytes());
    }
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    count: usize,
}
impl<'a> Reader<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER || bytes[..8] != MAGIC.to_le_bytes() {
            return Err(Error::Corrupt);
        }
        let used = u32_at(bytes, 8)?;
        let count = u32_at(bytes, 12)?;
        if used < HEADER || used > bytes.len() || used > CAPACITY || count > MAX_VARIABLES {
            return Err(Error::Corrupt);
        }
        let bytes = &bytes[..used];
        let mut offset = HEADER;
        let mut keys = Vec::new();
        for _ in 0..count {
            let size = u32_at(bytes, offset + 28)?;
            let name = u32_at(bytes, offset + 20)?;
            let data = u32_at(bytes, offset + 24)?;
            if size < RECORD
                || size % 8 != 0
                || name < 4
                || name % 2 != 0
                || name > super::MAX_NAME * 2
                || data > super::MAX_VALUE
                || RECORD + name + data > size
            {
                return Err(Error::Corrupt);
            }
            let end = offset
                .checked_add(size)
                .filter(|e| *e <= used)
                .ok_or(Error::Corrupt)?;
            let record = &bytes[offset..end];
            if record[RECORD + name - 2..RECORD + name] != [0, 0]
                || u32_at(record, 16)? & RT as usize == 0
            {
                return Err(Error::Corrupt);
            }
            let units: Vec<_> = record[RECORD..RECORD + name - 2]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            let guid: Guid = record[..16].try_into().map_err(|_| Error::Corrupt)?;
            if !valid_name(&units) || keys.contains(&(guid, units.clone())) {
                return Err(Error::Corrupt);
            }
            keys.push((guid, units));
            offset = end;
        }
        if offset != used {
            return Err(Error::Corrupt);
        }
        Ok(Self { bytes, count })
    }
    pub fn list(&self) -> Vec<Variable> {
        let mut result = Vec::with_capacity(self.count);
        let mut offset = HEADER;
        for _ in 0..self.count {
            let record = &self.bytes[offset..];
            let name = u32_at(record, 20).expect("validated index");
            let size = u32_at(record, 24).expect("validated index");
            result.push(Variable {
                guid: record[..16].try_into().expect("validated GUID"),
                attributes: u32_at(record, 16).expect("validated attributes") as u32,
                name: record[RECORD..RECORD + name - 2]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect(),
                data: record[RECORD + name..RECORD + name + size].to_vec(),
            });
            offset += u32_at(record, 28).expect("validated index");
        }
        result
    }
    pub fn get(&self, name: &[u16], guid: &Guid) -> Result<Variable, Error> {
        if !valid_name(name) {
            return Err(Error::InvalidParameter);
        }
        self.list()
            .into_iter()
            .find(|v| v.name == name && v.guid == *guid)
            .ok_or(Error::NotFound)
    }
    pub fn capacity(&self, attributes: u32) -> Result<(u64, u64, u64), Error> {
        super::validate_attributes(attributes)?;
        let offset = if attributes & NV != 0 { 24 } else { 48 };
        let read =
            |o| u64::from_le_bytes(self.bytes[o..o + 8].try_into().expect("validated header"));
        Ok((read(offset), read(offset + 8), read(offset + 16)))
    }
    pub fn truncated(&self) -> bool {
        self.bytes[16..20] != [0; 4]
    }
}
