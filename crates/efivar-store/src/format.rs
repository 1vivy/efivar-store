use crate::{Error, Guid, Layout, Name};

pub(crate) const FV_HEADER: usize = 72;
pub(crate) const STORE_HEADER: usize = 28;
pub(crate) const NV_DATA: Guid = [
    0x8d, 0x2b, 0xf1, 0xff, 0x96, 0x76, 0x8b, 0x4c, 0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50,
];
const NORMAL: Guid = [
    0x16, 0x36, 0xcf, 0xdd, 0x75, 0x32, 0x64, 0x41, 0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d,
];
const AUTH: Guid = [
    0x78, 0x2c, 0xf3, 0xaa, 0x7b, 0x94, 0x9a, 0x43, 0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92,
];
pub(crate) const ADDED: u8 = 0x3f;
pub(crate) const TRANSITION: u8 = 0x3e;
pub(crate) const HEADER_VALID: u8 = 0x7f;

impl Layout {
    pub(crate) fn signature(self) -> Guid {
        match self {
            Self::Normal => NORMAL,
            Self::Authenticated => AUTH,
        }
    }

    pub(crate) fn header_size(self) -> usize {
        match self {
            Self::Normal => 32,
            Self::Authenticated => 60,
        }
    }

    pub(crate) fn sizes_offset(self) -> usize {
        self.header_size() - 24
    }
}

pub(crate) fn align(value: usize) -> Result<usize, Error> {
    value.checked_add(3).map(|n| n & !3).ok_or(Error::Bounds)
}

pub(crate) fn bytes<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], Error> {
    data.get(offset..)
        .and_then(|tail| tail.get(..N))
        .and_then(|span| span.try_into().ok())
        .ok_or(Error::Bounds)
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(bytes(data, offset)?))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(bytes(data, offset)?))
}

pub(crate) fn checksum(header: &[u8]) -> u16 {
    header.as_chunks::<2>().0.iter().fold(0u16, |sum, word| {
        sum.wrapping_add(u16::from_le_bytes(*word))
    })
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Geometry {
    pub(crate) layout: Layout,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) append: usize,
}

impl Geometry {
    pub(crate) fn parse(image: &[u8]) -> Result<Self, Error> {
        if bytes::<4>(image, 40)? != *b"_FVH" {
            return Err(Error::FvSignature);
        }
        if bytes::<16>(image, 16)? != NV_DATA {
            return Err(Error::FvGuid);
        }
        let length =
            usize::try_from(u64::from_le_bytes(bytes(image, 32)?)).map_err(|_| Error::Bounds)?;
        let header_len = usize::from(u16_at(image, 48)?);
        if header_len < FV_HEADER || header_len % 4 != 0 || header_len > length {
            return Err(Error::FvHeader);
        }
        let volume = image.get(..length).ok_or(Error::Bounds)?;
        let header = volume.get(..header_len).ok_or(Error::Bounds)?;
        if header[54] != 0 || header[55] != 2 || u32_at(header, 44)? & 0x800 == 0 {
            return Err(Error::FvHeader);
        }
        if checksum(header) != 0 {
            return Err(Error::FvChecksum);
        }
        let ext = usize::from(u16_at(header, 52)?);
        let map_end = if ext == 0 { header_len } else { ext };
        let map = header.get(..map_end).ok_or(Error::FvHeader)?;
        let mut pos = 56;
        let mut total = 0u64;
        loop {
            let blocks = u32_at(map, pos)?;
            let size = u32_at(map, pos + 4)?;
            pos += 8;
            if blocks == 0 && size == 0 {
                break;
            }
            if blocks == 0 || size == 0 {
                return Err(Error::BlockMap);
            }
            total = total
                .checked_add(u64::from(blocks) * u64::from(size))
                .ok_or(Error::BlockMap)?;
        }
        if total != length as u64 {
            return Err(Error::BlockMap);
        }
        if ext != 0 {
            if ext < pos {
                return Err(Error::FvHeader);
            }
            let extension = header.get(ext..).ok_or(Error::FvHeader)?;
            let size = usize::try_from(u32_at(extension, 16)?).map_err(|_| Error::Bounds)?;
            if size < 20 || size > extension.len() {
                return Err(Error::FvHeader);
            }
        }
        let store = volume.get(header_len..).ok_or(Error::Bounds)?;
        let layout = match bytes(store, 0)? {
            NORMAL => Layout::Normal,
            AUTH => Layout::Authenticated,
            _ => return Err(Error::StoreGuid),
        };
        let size = usize::try_from(u32_at(store, 16)?).map_err(|_| Error::Bounds)?;
        if size < STORE_HEADER || size % 4 != 0 || size > store.len() {
            return Err(Error::StoreSize);
        }
        if store[20] != 0x5a || store[21] != 0xfe {
            return Err(Error::StoreState);
        }
        let start = header_len + STORE_HEADER;
        let end = header_len + size;
        let mut append = start;
        while append < end {
            if volume[append..end].iter().all(|b| *b == 0xff) {
                break;
            }
            // A hole followed by programmed bytes is corruption, not free space.
            let record = Record::parse(volume, append, end, layout)?;
            append = record.end;
        }
        Ok(Self {
            layout,
            start,
            end,
            append,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Record<'a> {
    pub(crate) offset: usize,
    pub(crate) end: usize,
    pub(crate) state: u8,
    pub(crate) attributes: u32,
    pub(crate) guid: Guid,
    pub(crate) name: Name<'a>,
    pub(crate) data: &'a [u8],
}

impl<'a> Record<'a> {
    fn parse(image: &'a [u8], offset: usize, end: usize, layout: Layout) -> Result<Self, Error> {
        let tail = image.get(offset..end).ok_or(Error::Bounds)?;
        let header = tail.get(..layout.header_size()).ok_or(Error::Bounds)?;
        if u16_at(header, 0)? != 0x55aa {
            return Err(Error::RecordSignature);
        }
        let state = header[2];
        if !matches!(
            state,
            0xff | HEADER_VALID | ADDED | TRANSITION | 0x3d | 0x3c
        ) {
            return Err(Error::RecordState);
        }
        let sizes = layout.sizes_offset();
        let name_size = usize::try_from(u32_at(header, sizes)?).map_err(|_| Error::Bounds)?;
        let data_size = usize::try_from(u32_at(header, sizes + 4)?).map_err(|_| Error::Bounds)?;
        if name_size < 4 || name_size % 2 != 0 {
            return Err(Error::Name);
        }
        let name_end = layout
            .header_size()
            .checked_add(name_size)
            .ok_or(Error::Bounds)?;
        let data_end = name_end.checked_add(data_size).ok_or(Error::Bounds)?;
        let length = align(data_end)?;
        if length > tail.len() {
            return Err(Error::Bounds);
        }
        let name_bytes = &tail[layout.header_size()..name_end];
        let name = Name(&name_bytes[..name_size - 2]);
        // Header-only records may have interrupted (unwritten) names/data. Their
        // bounded length still reserves the entire slot; they are never visible.
        if state != HEADER_VALID
            && state != 0xff
            && (name_bytes[name_size - 2..] != [0, 0] || !valid_name(name.units()))
        {
            return Err(Error::Name);
        }
        Ok(Self {
            offset,
            end: offset + length,
            state,
            attributes: u32_at(header, 4)?,
            guid: bytes(header, sizes + 8)?,
            name,
            data: &tail[name_end..data_end],
        })
    }

    pub(crate) fn live(self) -> bool {
        self.state == ADDED || self.state == TRANSITION
    }
}

pub(crate) fn valid_name(units: impl Iterator<Item = u16>) -> bool {
    core::char::decode_utf16(units).all(|c| matches!(c, Ok(c) if c != '\0'))
}

pub(crate) struct Records<'a> {
    pub(crate) image: &'a [u8],
    pub(crate) geometry: Geometry,
    pub(crate) pos: usize,
}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.geometry.append {
            return None;
        }
        // Construction validates every record. The immutable borrow prevents
        // changes beneath this iterator; no unsafe casts or alignment assumptions.
        let record = Record::parse(
            self.image,
            self.pos,
            self.geometry.append,
            self.geometry.layout,
        )
        .ok()?;
        self.pos = record.end;
        Some(record)
    }
}
