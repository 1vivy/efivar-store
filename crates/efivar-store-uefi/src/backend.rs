//! Boot-time EFVS owner. Runtime readers never retain this object or its I/O.
use crate::variables::{Error, MAX_NAME};
use alloc::{vec, vec::Vec};
use efivar_store::{efvs, persist};

#[derive(Clone, Copy)]
pub struct Manifest {
    pub size: usize,
    pub checkpoint_capacity: usize,
    /// At least the device's physical write unit, not merely its logical sector.
    pub write_unit: usize,
    pub partition_guid: efvs::Guid,
}

/// Boot-time diagnostic snapshot; this exposes no mutable bytes or alternate I/O path.
#[derive(Clone, Copy, Debug)]
pub struct Inspection {
    pub generation: u64,
    pub log_bytes: usize,
    pub log_capacity: usize,
    pub variables: usize,
    pub posture_tier: u8,
    pub anchor_value: u64,
}

/// The primary store plus an independently flushed first-boot journal.
/// An absent journal reads as zeroes; writes create/extend it. Its pathname and
/// file lifecycle belong to the consumer, never the engine or EFI mechanism.
pub trait Storage: persist::Flush {
    fn backup_read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Self::Error>;
    fn backup_write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Self::Error>;
    fn backup_flush(&mut self) -> Result<(), Self::Error>;
}

pub struct Efvs<I, V> {
    pub io: I,
    verifier: V,
    image: Vec<u8>,
    working: Vec<u8>,
    scratch: Vec<u8>,
    valid: bool,
    anchor_value: u64,
    config: efvs::ConfigTable,
}

struct Sink<'a, I>(&'a mut I);
impl<I: persist::Flush> efvs::CompactionIo for Sink<'_, I> {
    type Error = I::Error;
    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.write_at(offset, bytes)
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.flush()
    }
}
fn compact_error<E>(error: efvs::CompactionError<E>) -> Error {
    match error {
        efvs::CompactionError::Format(e) => format_error(e),
        efvs::CompactionError::Io(_) => Error::Device,
    }
}
pub(crate) fn format_error(error: efvs::Error) -> Error {
    match error {
        efvs::Error::Full => Error::OutOfResources,
        efvs::Error::NotFound => Error::NotFound,
        efvs::Error::InvalidParameter | efvs::Error::Name => Error::InvalidParameter,
        efvs::Error::Unsupported => Error::Unsupported,
        efvs::Error::SecurityViolation | efvs::Error::Rollback => Error::SecurityViolation,
        efvs::Error::WriteProtected | efvs::Error::Locked => Error::WriteProtected,
        _ => Error::Corrupt,
    }
}

impl<I: Storage, V: efvs::Verifier> Efvs<I, V> {
    /// Load the highest valid generation, replay under the supplied verifier,
    /// compact durably, then bump/lock the anchor before any EFI publication.
    pub fn open(
        mut io: I,
        manifest: Manifest,
        mut verifier: V,
        anchor: &mut impl efvs::AnchorOps,
    ) -> Result<Self, Error> {
        let mut image = vec![0; manifest.size];
        io.read_at(0, &mut image).map_err(|_| Error::Device)?;
        if manifest.write_unit == 0 || !manifest.write_unit.is_power_of_two() {
            return Err(Error::InvalidParameter);
        }
        crate::migration::prepare(&mut io, &mut image, manifest)?;
        let header = efvs::Header::decode(&image).map_err(format_error)?;
        if manifest.write_unit == 0
            || !manifest.write_unit.is_power_of_two()
            || header.block_size < manifest.write_unit
        {
            return Err(Error::InvalidParameter);
        }
        let mut scratch = vec![0; header.checkpoint_capacity];
        let mut working = vec![0; header.checkpoint_capacity];
        let anchor_value = anchor.read().map_err(format_error)?;
        let replay = efvs::replay(&image, &mut scratch, &mut verifier, anchor_value)
            .map_err(format_error)?;
        let count = efvs::compact_durable(&mut image, &replay.state, &mut Sink(&mut io))
            .map_err(compact_error)?;
        verify_bytes(&mut io, 0, &image)?;
        replay
            .state
            .encode_checkpoint(&mut working)
            .map_err(format_error)?;
        efvs::commit_anchor(anchor, count).map_err(format_error)?;
        let anchor_value = anchor.read().map_err(format_error)?;
        let config = efvs::ConfigTable {
            partition_guid: manifest.partition_guid,
            posture_tier: efvs::posture_tier(anchor.capabilities()),
            anchor_value,
            capabilities: anchor.capabilities(),
        };
        Ok(Self {
            io,
            verifier,
            image,
            working,
            scratch,
            valid: true,
            anchor_value,
            config,
        })
    }
    pub fn config(&self) -> efvs::ConfigTable {
        self.config
    }
    pub fn image_size(&self) -> usize {
        self.image.len()
    }
    pub fn inspect(&mut self) -> Result<Inspection, Error> {
        self.reload()?;
        let header = efvs::Header::decode(&self.image).map_err(format_error)?;
        let checkpoint = efvs::Checkpoint::decode(&self.image[header.checkpoint_range()])
            .map_err(format_error)?;
        let mut log = efvs::Log::new(
            &self.image[header.log_offset..],
            checkpoint.hash,
            checkpoint.next_sequence,
        );
        for _ in log.by_ref() {}
        Ok(Inspection {
            generation: header.generation,
            log_bytes: log.consumed,
            log_capacity: header.log_capacity,
            variables: self.variables()?.count(),
            posture_tier: self.config.posture_tier,
            anchor_value: self.config.anchor_value,
        })
    }
    pub fn reload(&mut self) -> Result<(), Error> {
        if !self.valid {
            self.io
                .read_at(0, &mut self.image)
                .map_err(|_| Error::Device)?;
            let replay = efvs::replay(
                &self.image,
                &mut self.scratch,
                &mut self.verifier,
                self.anchor_value,
            )
            .map_err(format_error)?;
            replay
                .state
                .encode_checkpoint(&mut self.working)
                .map_err(format_error)?;
            self.valid = true;
        }
        Ok(())
    }
    pub fn variables(&self) -> Result<efvs::Variables<'_>, Error> {
        Ok(efvs::Checkpoint::decode(&self.working)
            .map_err(format_error)?
            .variables())
    }
    pub fn get(&self, name: &[u16], guid: &efvs::Guid) -> Result<(u32, &[u8]), Error> {
        self.variables()?
            .find(|v| v.guid == *guid && units(v.name).eq(name.iter().copied()))
            .map(|v| (v.attributes, v.data))
            .ok_or(Error::NotFound)
    }
    pub fn capacity(&self) -> Result<(usize, usize), Error> {
        let cp = efvs::Checkpoint::decode(&self.working).map_err(format_error)?;
        let capacity = self.working.len() - efvs::CHECKPOINT_HEADER_SIZE;
        let h = efvs::Header::decode(&self.image).map_err(format_error)?;
        let disk_cp =
            efvs::Checkpoint::decode(&self.image[h.checkpoint_range()]).map_err(format_error)?;
        let mut log = efvs::Log::new(
            &self.image[h.log_offset..],
            disk_cp.hash,
            disk_cp.next_sequence,
        );
        for _ in log.by_ref() {}
        let remaining = (self.working.len() - cp.used).min(h.log_capacity - log.consumed);
        Ok((capacity, remaining))
    }
    /// NV|BS|RT mutations append checked records. Firmware-only NV|BS values
    /// bypass the runtime log only through authorized A/B checkpoint compaction.
    pub fn set(
        &mut self,
        name: &[u16],
        guid: &efvs::Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        self.reload()?;
        let mut encoded = [0; MAX_NAME * 2];
        if name.is_empty() || name.len() >= MAX_NAME {
            return Err(Error::InvalidParameter);
        }
        for (unit, bytes) in name.iter().zip(encoded.as_chunks_mut::<2>().0) {
            bytes.copy_from_slice(&unit.to_le_bytes());
        }
        let name = &encoded[..name.len() * 2];
        let mut state =
            efvs::State::from_checkpoint(&self.working, &mut self.scratch).map_err(format_error)?;
        let old = state.get(name, guid);
        let deleting = deleting(attributes, data)?;
        let boot_only =
            old.is_some_and(|v| v.attributes & 4 == 0) || (attributes != 0 && attributes & 4 == 0);
        let result = if boot_only {
            self.verifier
                .authorize(name, guid, attributes)
                .map_err(format_error)?;
            if let Some(old) = old {
                self.verifier
                    .authorize(old.name, &old.guid, old.attributes)
                    .map_err(format_error)?;
                if !deleting && old.attributes != attributes {
                    return Err(Error::InvalidParameter);
                }
            }
            if attributes & !7 != 0 {
                return Err(Error::Unsupported);
            }
            if !deleting && attributes & 3 != 3 {
                return Err(Error::InvalidParameter);
            }
            if deleting {
                state.delete_checkpoint(name, guid).map_err(format_error)?;
            } else {
                state
                    .insert_checkpoint(efvs::Variable {
                        name,
                        guid: *guid,
                        attributes,
                        timestamp: [0; 16],
                        data,
                    })
                    .map_err(format_error)?;
            }
            efvs::compact_durable(&mut self.image, &state, &mut Sink(&mut self.io))
                .map_err(compact_error)
                .and_then(|_| verify_bytes(&mut self.io, 0, &self.image))
        } else {
            let operation = if deleting {
                efvs::Operation::Delete
            } else if attributes & efvs::ATTR_APPEND != 0 {
                efvs::Operation::Append
            } else {
                efvs::Operation::Set
            };
            let range = efvs::append(
                &mut self.image,
                efvs::RecordInput {
                    name,
                    guid: *guid,
                    attributes,
                    data: if deleting && attributes & efvs::ATTR_TIME_AUTH == 0 {
                        &[]
                    } else {
                        data
                    },
                    operation,
                },
                &mut state,
                &mut self.verifier,
            )
            .map_err(format_error)?;
            self.io
                .write_at(range.start, &self.image[range.clone()])
                .map_err(|_| Error::Device)
                .and_then(|()| self.io.flush().map_err(|_| Error::Device))
                .and_then(|()| verify_bytes(&mut self.io, range.start, &self.image[range]))
        };
        if let Err(error) = result {
            self.valid = false;
            return Err(error);
        }
        state
            .encode_checkpoint(&mut self.working)
            .map_err(format_error)
    }
    pub fn verify_absent(&mut self, name: &[u16], guid: &efvs::Guid) -> Result<(), Error> {
        self.valid = false;
        self.reload()?;
        match self.get(name, guid) {
            Err(Error::NotFound) => Ok(()),
            Ok(_) => Err(Error::Device),
            Err(e) => Err(e),
        }
    }
}

pub(crate) fn deleting(attributes: u32, data: &[u8]) -> Result<bool, Error> {
    let value = if attributes & efvs::ATTR_TIME_AUTH != 0 {
        let auth = efivar_store::auth::Authentication2::parse(data)
            .map_err(|_| Error::SecurityViolation)?;
        &data[auth.len()..]
    } else {
        data
    };
    Ok(attributes == 0 || (value.is_empty() && attributes & efvs::ATTR_APPEND == 0))
}
pub fn units(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}
pub(crate) fn verify_bytes<I: persist::Read>(
    io: &mut I,
    offset: usize,
    expected: &[u8],
) -> Result<(), Error> {
    let mut buffer = [0; 4096];
    for (i, chunk) in expected.chunks(buffer.len()).enumerate() {
        io.read_at(offset + i * 4096, &mut buffer[..chunk.len()])
            .map_err(|_| Error::Device)?;
        if buffer[..chunk.len()] != *chunk {
            return Err(Error::Device);
        }
    }
    Ok(())
}
