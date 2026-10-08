//! edk2 NV variable-store byte images, independent of partition GUID and size.
//!
//! `Store` validates an FV at byte zero and borrows its records. `StoreMut`
//! appends updates without reclaiming implicitly. Neither type performs I/O.
//! Persistence adapters must preserve edk2's write/flush ordering; copying the
//! final image to a device is not a crash-safe transaction. Reclaim/format are
//! erase-and-rewrite operations, not flash bit-clearing operations. The
//! `persist` module owns that ordered commit sequence over a caller-supplied
//! byte device; the optional `std` feature adds a Unix file/block-device
//! adapter.
#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod auth;
#[clippy::msrv = "1.82.0"]
pub mod efvs;
mod format;
pub mod migrate;
pub mod mirror;
pub mod persist;
#[clippy::msrv = "1.82.0"]
pub mod sha256;

use format::{ADDED, Geometry, HEADER_VALID, Record, Records, TRANSITION};

/// EFI_GUID bytes in their on-disk (mixed-endian) representation, not UUID text order.
pub type Guid = [u8; 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layout {
    Normal,
    Authenticated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    FvSignature,
    FvGuid,
    FvHeader,
    FvChecksum,
    BlockMap,
    StoreGuid,
    StoreSize,
    StoreState,
    RecordSignature,
    RecordState,
    Name,
    AuthenticatedWrite,
    UnsupportedAttributes,
    Full,
    ScratchTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for Error {}

/// Validated UTF-16LE name, excluding the on-disk NUL terminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Name<'a>(&'a [u8]);

impl<'a> Name<'a> {
    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    pub fn units(self) -> impl Iterator<Item = u16> + 'a {
        self.0
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_le_bytes)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Variable<'a> {
    pub name: Name<'a>,
    pub guid: Guid,
    pub attributes: u32,
    pub data: &'a [u8],
}

impl<'a> From<Record<'a>> for Variable<'a> {
    fn from(record: Record<'a>) -> Self {
        Self {
            name: record.name,
            guid: record.guid,
            attributes: record.attributes,
            data: record.data,
        }
    }
}

/// Fully validated read-only image. Trailing FV/FTW bytes are not variable space.
#[derive(Clone, Copy, Debug)]
pub struct Store<'a> {
    image: &'a [u8],
    geometry: Geometry,
}

impl<'a> Store<'a> {
    pub fn parse(image: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            image,
            geometry: Geometry::parse(image)?,
        })
    }

    pub fn layout(self) -> Layout {
        self.geometry.layout
    }

    /// Erased append space in bytes, including future record headers/alignment.
    /// Deleted records are not free until an explicit reclaim.
    pub fn free_space(self) -> usize {
        self.geometry.end - self.geometry.append
    }

    /// Total bytes of validated variable area: from the end of the firmware
    /// volume and store headers to the end of the store. This is the capacity
    /// `free_space` counts against, so `capacity() - free_space()` is the bytes
    /// occupied by records. Unlike `image.len()`, it excludes the FV and store
    /// headers and any bytes past the declared store size.
    pub fn capacity(self) -> usize {
        self.geometry.end - self.geometry.start
    }

    fn records(self) -> Records<'a> {
        Records {
            image: self.image,
            geometry: self.geometry,
            pos: self.geometry.start,
        }
    }

    /// `(first record offset, append cursor)` from the validated FV geometry.
    /// Persistence adapters use these instead of recomputing record offsets.
    pub(crate) fn record_bounds(self) -> (usize, usize) {
        (self.geometry.start, self.geometry.append)
    }

    fn resolve(self, mut matches: impl FnMut(&Record<'a>) -> bool) -> Option<Record<'a>> {
        let mut transition = None;
        for record in self.records().filter(|r| r.live()).filter(|r| matches(r)) {
            if record.state == ADDED {
                return Some(record);
            }
            // FindVariableEx returns the last transition only when no ADDED
            // record exists; a header-only replacement cannot shadow it.
            transition = Some(record);
        }
        transition
    }

    /// Names are UTF-16 code units without a terminating NUL.
    pub fn get(self, name: &[u16], guid: &Guid) -> Option<Variable<'a>> {
        self.resolve(|r| r.guid == *guid && r.name.units().eq(name.iter().copied()))
            .map(Into::into)
    }

    fn live_records(self) -> impl Iterator<Item = Record<'a>> {
        self.records().filter(move |r| {
            r.live()
                && self
                    .resolve(|other| other.guid == r.guid && other.name == r.name)
                    .is_some_and(|selected| selected.offset == r.offset)
        })
    }

    /// Enumerate each live (name, GUID) once, using the same recovery as `get`.
    pub fn list(self) -> impl Iterator<Item = Variable<'a>> {
        self.live_records().map(Into::into)
    }
}

/// Exclusive in-memory writer. No allocation, I/O, implicit reclaim or journal.
pub struct StoreMut<'a> {
    image: &'a mut [u8],
    geometry: Geometry,
}

impl<'a> StoreMut<'a> {
    pub fn parse(image: &'a mut [u8]) -> Result<Self, Error> {
        let geometry = Geometry::parse(image)?;
        Ok(Self { image, geometry })
    }

    /// Initialize a standalone FV using the caller's entire image and block size.
    /// This erases the image. It does not create an FTW area or choose GPT identity.
    pub fn format(image: &'a mut [u8], layout: Layout, block_size: u32) -> Result<Self, Error> {
        let minimum = format::FV_HEADER + format::STORE_HEADER;
        let block_size_usize = usize::try_from(block_size).map_err(|_| Error::Bounds)?;
        if image.len() < minimum
            || !image.len().is_multiple_of(4)
            || block_size == 0
            || !image.len().is_multiple_of(block_size_usize)
        {
            return Err(Error::StoreSize);
        }
        let blocks = u32::try_from(image.len() / block_size_usize).map_err(|_| Error::Bounds)?;
        let store_size =
            u32::try_from(image.len() - format::FV_HEADER).map_err(|_| Error::Bounds)?;
        let length = image.len() as u64;
        image.fill(0xff);
        let header = &mut image[..format::FV_HEADER];
        header.fill(0);
        header[16..32].copy_from_slice(&format::NV_DATA);
        header[32..40].copy_from_slice(&length.to_le_bytes());
        header[40..44].copy_from_slice(b"_FVH");
        // Read/write enabled, erase polarity 1; no architecture-specific mapping.
        header[44..48].copy_from_slice(&0x0000_0e36u32.to_le_bytes());
        header[48..50].copy_from_slice(&(format::FV_HEADER as u16).to_le_bytes());
        header[55] = 2;
        header[56..60].copy_from_slice(&blocks.to_le_bytes());
        header[60..64].copy_from_slice(&block_size.to_le_bytes());
        let checksum = format::checksum(header).wrapping_neg();
        header[50..52].copy_from_slice(&checksum.to_le_bytes());
        let store = &mut image[format::FV_HEADER..minimum];
        store.fill(0);
        store[..16].copy_from_slice(&layout.signature());
        store[16..20].copy_from_slice(&store_size.to_le_bytes());
        store[20] = 0x5a;
        store[21] = 0xfe;
        Self::parse(image)
    }

    pub fn as_store(&self) -> Store<'_> {
        Store {
            image: self.image,
            geometry: self.geometry,
        }
    }

    pub fn image(&self) -> &[u8] {
        self.image
    }

    /// Append cursor after the last mutation: the end of the newest record.
    /// A `set` with non-empty data moves it forward by the record's aligned
    /// length, which is exactly the byte range the adapter must program.
    pub(crate) fn append_cursor(&self) -> usize {
        self.geometry.append
    }

    fn validate_name(name: &[u16]) -> Result<(), Error> {
        if name.is_empty() || !format::valid_name(name.iter().copied()) {
            Err(Error::Name)
        } else {
            Ok(())
        }
    }

    fn check_existing(&self, name: &[u16], guid: &Guid) -> Result<(), Error> {
        if self.as_store().records().any(|r| {
            r.live()
                && r.guid == *guid
                && r.name.units().eq(name.iter().copied())
                && r.attributes & 0xb0 != 0
        }) {
            return Err(Error::AuthenticatedWrite);
        }
        Ok(())
    }

    fn mark_old(&mut self, name: &[u16], guid: &Guid, limit: usize, mask: u8) {
        let mut pos = self.geometry.start;
        while pos < limit {
            let mut records = self.as_store().records();
            records.pos = pos;
            let Some(record) = records.next() else { break };
            let matches = record.live()
                && record.guid == *guid
                && record.name.units().eq(name.iter().copied());
            let offset = record.offset;
            pos = record.end;
            if matches {
                self.image[offset + 2] &= mask;
            }
        }
    }

    /// Append a replacement, then retire the old records. An empty payload deletes.
    /// Attributes must be NV + BS, optionally RT/HARDWARE_ERROR_RECORD. Authenticated
    /// writes (including changes/deletion of an authenticated variable) are rejected;
    /// APPEND_WRITE and unknown attributes are not silently treated as replacement.
    /// All errors leave the image unchanged, including `Full`; reclaim is explicit.
    pub fn set(
        &mut self,
        name: &[u16],
        guid: &Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        Self::validate_name(name)?;
        if attributes & 0xb0 != 0 {
            return Err(Error::AuthenticatedWrite);
        }
        if attributes & !0x0f != 0 || attributes & 3 != 3 {
            return Err(Error::UnsupportedAttributes);
        }
        self.check_existing(name, guid)?;
        if data.is_empty() {
            self.delete(name, guid)?;
            return Ok(());
        }
        let name_size = name
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_mul(2))
            .ok_or(Error::Bounds)?;
        let name_size_u32 = u32::try_from(name_size).map_err(|_| Error::Bounds)?;
        let data_size_u32 = u32::try_from(data.len()).map_err(|_| Error::Bounds)?;
        let layout = self.geometry.layout;
        let length = layout
            .header_size()
            .checked_add(name_size)
            .and_then(|n| n.checked_add(data.len()))
            .ok_or(Error::Bounds)?;
        let length = format::align(length)?;
        if length > self.as_store().free_space() {
            return Err(Error::Full);
        }
        let offset = self.geometry.append;
        // Match UpdateVariable: old -> transition, write new header, header-valid,
        // payload, added, old -> deleted. Every programmed byte only clears bits.
        self.mark_old(name, guid, offset, 0xfe);
        let header = &mut self.image[offset..offset + layout.header_size()];
        header[..2].copy_from_slice(&0x55aau16.to_le_bytes());
        header[3] = 0;
        if layout == Layout::Authenticated {
            header[8..36].fill(0);
        }
        header[4..8].copy_from_slice(&attributes.to_le_bytes());
        let sizes = layout.sizes_offset();
        header[sizes..sizes + 4].copy_from_slice(&name_size_u32.to_le_bytes());
        header[sizes + 4..sizes + 8].copy_from_slice(&data_size_u32.to_le_bytes());
        header[sizes + 8..].copy_from_slice(guid);
        header[2] &= HEADER_VALID;
        let name_offset = offset + layout.header_size();
        for (i, unit) in name.iter().chain(core::iter::once(&0)).enumerate() {
            self.image[name_offset + i * 2..name_offset + i * 2 + 2]
                .copy_from_slice(&unit.to_le_bytes());
        }
        let data_offset = name_offset + name_size;
        self.image[data_offset..data_offset + data.len()].copy_from_slice(data);
        self.image[offset + 2] &= ADDED;
        self.geometry.append += length;
        self.mark_old(name, guid, offset, 0xfd);
        Ok(())
    }

    /// Clear deletion bits in all live versions; return whether the key existed.
    pub fn delete(&mut self, name: &[u16], guid: &Guid) -> Result<bool, Error> {
        Self::validate_name(name)?;
        self.check_existing(name, guid)?;
        let existed = self.as_store().get(name, guid).is_some();
        self.mark_old(name, guid, self.geometry.append, 0xfd);
        Ok(existed)
    }

    /// Bytes of caller-owned scratch required by reclaim (only live records).
    pub fn reclaim_scratch_size(&self) -> usize {
        self.as_store()
            .live_records()
            .map(|r| r.end - r.offset)
            .sum()
    }

    /// Compact live records, preserving authentication metadata without verifying it.
    /// A recovered transition is promoted in the erased replacement, never in place.
    /// Returns bytes recovered. Scratch shortage leaves the image unchanged.
    /// The caller owns the erase/rewrite durability policy: a reclaim is never
    /// part of a live update, so it belongs to an offline/boot-time writer.
    pub fn reclaim(&mut self, scratch: &mut [u8]) -> Result<usize, Error> {
        let needed = self.reclaim_scratch_size();
        if scratch.len() < needed {
            return Err(Error::ScratchTooSmall);
        }
        let mut used = 0;
        for record in self.as_store().live_records() {
            let length = record.end - record.offset;
            scratch[used..used + length].copy_from_slice(&self.image[record.offset..record.end]);
            if record.state == TRANSITION {
                scratch[used + 2] = ADDED;
            }
            used += length;
        }
        let start = self.geometry.start;
        let old_append = self.geometry.append;
        self.image[start..start + used].copy_from_slice(&scratch[..used]);
        self.image[start + used..self.geometry.end].fill(0xff);
        self.geometry.append = start + used;
        Ok(old_append - self.geometry.append)
    }
}
