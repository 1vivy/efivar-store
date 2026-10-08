//! One crash-tolerant commit of a store change to a caller-supplied byte device.
//!
//! [`apply`] reproduces edk2's `UpdateVariable` programming order, so that a
//! power loss at any phase leaves a store that still parses and reports either
//! the complete old value or the complete new value — never a torn record. The
//! module owns no buffers and performs no allocation: the caller supplies the
//! current device image and a second buffer of at least the same length in
//! which the updated image is built.
//!
//! Every phase is one or more byte writes followed by [`Flush::flush`]. A
//! device adapter must make the flushed prefix durable before returning; a
//! whole-image rewrite, a reclaim or a reformat is never part of a live update.
//!
//! # Failure contract
//!
//! On success `image` equals the new device contents byte for byte. On **any**
//! error — I/O, readback mismatch, a rejected change — `image` is invalid and
//! the caller must reload it from the device before the next mutation. There is
//! no rollback: the device may already hold a partially applied change, and the
//! remaining recovery is exactly the edk2 record-state recovery that
//! [`crate::Store`] and [`crate::StoreMut`] already implement.

use crate::format::{ADDED, HEADER_VALID, TRANSITION};
use crate::{Error as FormatError, Guid, Store, StoreMut};

/// Blocking byte reader over the backing store image.
pub trait Read {
    /// Backing-store failure, e.g. an I/O error.
    type Error;

    /// Fills `buf` from `offset`, measured from the start of the store image.
    fn read_at(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), Self::Error>;
}

/// Blocking byte writer over the backing store image.
pub trait Write: Read {
    /// Programs `data` at `offset`, measured from the start of the store image.
    fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), Self::Error>;
}

/// Durability boundary: every earlier write is on the medium when this returns.
pub trait Flush: Write {
    /// Flushes all preceding writes to the backing store.
    fn flush(&mut self) -> Result<(), Self::Error>;
}

/// One requested change to a (name, GUID) key.
#[derive(Clone, Copy, Debug)]
pub enum Change<'a> {
    /// Replace the value. An empty `data` is an EFI delete, exactly like
    /// [`Change::Delete`]; the `attributes` are still validated.
    Set {
        name: &'a [u16],
        guid: &'a Guid,
        attributes: u32,
        data: &'a [u8],
    },
    /// Delete every live version of the key.
    Delete { name: &'a [u16], guid: &'a Guid },
}

/// Observable result of [`apply`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The live record already had these attributes and data; nothing was written.
    Unchanged,
    /// A new record was appended and the previous ones retired.
    Written,
    /// Every live version of the key was retired.
    Deleted,
    /// The key had no live record; the caller maps this to `EFI_NOT_FOUND`.
    Absent,
}

/// Why [`apply`] did not commit, or what it observed afterwards.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error<E> {
    /// The caller's image, the change itself, or the append slot is invalid.
    Format(FormatError),
    /// The backing store failed a read, write or flush.
    Io(E),
    /// The device did not return the byte the commit programmed.
    Readback { offset: usize },
    /// The append slot already holds non-erased bytes.
    NotErased { offset: usize },
    /// A pre-append byte changed in a way that is not a legal record-state
    /// transition, so the planned commit is not an edk2 update.
    Unexpected { offset: usize },
}

impl<E: core::fmt::Display> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Format(FormatError::Full) => {
                write!(f, "the store is full; reclaim needs an explicit erase")
            }
            Self::Format(error) => write!(f, "invalid store change: {error}"),
            Self::Io(error) => write!(f, "backing store I/O failed: {error}"),
            Self::Readback { offset } => write!(f, "readback mismatch at byte {offset}"),
            Self::NotErased { offset } => write!(f, "append slot is not erased at byte {offset}"),
            Self::Unexpected { offset } => {
                write!(f, "unexpected store byte change at offset {offset}")
            }
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display> core::error::Error for Error<E> {}

/// Which of the two edk2 commit shapes is being performed.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    /// Append a replacement, then retire the records it supersedes.
    Set,
    /// Retire every live version in one phase.
    Delete,
}

/// Bytes read back per stack chunk while verifying the commit: one 4 KiB
/// block, so a firmware adapter over block storage reads each block once.
const READBACK_CHUNK: usize = 4096;

/// Applies one change to `image` and to the backing store, in edk2's order.
///
/// `image` is the caller's current copy of the device bytes and `scratch` is a
/// caller-owned buffer of at least `image.len()` bytes used to build the updated
/// image. Every phase is flushed; after the last phase the whole image range is
/// read back and compared. See the module documentation for the failure
/// contract and for the meaning of an empty [`Change::Set`] payload.
pub fn apply<I: Flush>(
    io: &mut I,
    image: &mut [u8],
    scratch: &mut [u8],
    change: Change<'_>,
) -> Result<Outcome, Error<I::Error>> {
    let len = image.len();
    if scratch.len() < len {
        return Err(Error::Format(FormatError::ScratchTooSmall));
    }
    let (name, guid) = match change {
        Change::Set { name, guid, .. } | Change::Delete { name, guid } => (name, guid),
    };

    // Plan against the caller's image before programming anything: an invalid
    // change (unsupported attributes, authenticated variable, Full, bad name)
    // is rejected here with zero writes.
    let (layout, records_start, old_append, existed) = {
        let store = Store::parse(&*image).map_err(Error::Format)?;
        let (records_start, append) = store.record_bounds();
        let existing = store.get(name, guid);
        if let Change::Set {
            attributes, data, ..
        } = change
            && !data.is_empty()
            && let Some(existing) = existing
            && existing.attributes == attributes
            && existing.data == data
        {
            return Ok(Outcome::Unchanged);
        }
        (store.layout(), records_start, append, existing.is_some())
    };
    let mode = match change {
        Change::Set { data, .. } if !data.is_empty() => Mode::Set,
        _ => Mode::Delete,
    };
    if mode == Mode::Delete && !existed {
        return Ok(Outcome::Absent);
    }

    scratch[..len].copy_from_slice(image);
    let mut writer = StoreMut::parse(&mut scratch[..len]).map_err(Error::Format)?;
    match change {
        Change::Set {
            name,
            guid,
            attributes,
            data,
        } => writer
            .set(name, guid, attributes, data)
            .map_err(Error::Format)?,
        Change::Delete { name, guid } => {
            writer.delete(name, guid).map_err(Error::Format)?;
        }
    }
    let new_append = writer.append_cursor();
    if new_append < old_append
        || new_append > len
        || (mode == Mode::Set && new_append == old_append)
    {
        return Err(Error::Unexpected { offset: new_append });
    }

    // Validate the whole plan before programming a single byte. Below the
    // append cursor only live record-state bytes may change, and each change
    // must be the edk2 retirement of that record.
    let mut offset = records_start;
    while offset < old_append {
        let old = image[offset];
        let new = scratch[offset];
        if old != new {
            let expected = match mode {
                Mode::Set => old & 0xfc,
                Mode::Delete => old & 0xfd,
            };
            if !matches!(old, ADDED | TRANSITION) || new != expected {
                return Err(Error::Unexpected { offset });
            }
        }
        offset += 1;
    }
    let mut offset = old_append;
    while offset < new_append {
        if image[offset] != 0xff {
            return Err(Error::NotErased { offset });
        }
        offset += 1;
    }

    if mode == Mode::Set {
        // (1) Retire the superseded records into transition, but keep them
        // visible: until the new record is added the store still reports the
        // old value.
        let mut offset = records_start;
        while offset < old_append {
            if image[offset] != scratch[offset] {
                io.write_at(offset, &[image[offset] & 0xfe])
                    .map_err(Error::Io)?;
            }
            offset += 1;
        }
        io.flush().map_err(Error::Io)?;

        // (2) Write the replacement header as one unit with its state byte left
        // erased, so no torn header can be parsed as a record.
        let header = layout.header_size();
        let state = scratch[old_append + 2];
        scratch[old_append + 2] = 0xff;
        let written = io.write_at(old_append, &scratch[old_append..old_append + header]);
        scratch[old_append + 2] = state;
        written.map_err(Error::Io)?;
        io.flush().map_err(Error::Io)?;

        // (3) Header valid: the record becomes parseable but not yet live.
        io.write_at(old_append + 2, &[HEADER_VALID])
            .map_err(Error::Io)?;
        io.flush().map_err(Error::Io)?;

        // (4) Name, data and trailing alignment padding.
        io.write_at(
            old_append + header,
            &scratch[old_append + header..new_append],
        )
        .map_err(Error::Io)?;
        io.flush().map_err(Error::Io)?;

        // (5) Added: the replacement becomes the live value.
        io.write_at(old_append + 2, &[ADDED]).map_err(Error::Io)?;
        io.flush().map_err(Error::Io)?;

        // (6) Finally make the retirement of the old records durable.
        let mut offset = records_start;
        while offset < old_append {
            if image[offset] != scratch[offset] {
                io.write_at(offset, &scratch[offset..offset + 1])
                    .map_err(Error::Io)?;
            }
            offset += 1;
        }
        io.flush().map_err(Error::Io)?;
    } else {
        // Delete is a single phase: apply the deletion mask to every live
        // version, clearing only bits, and never a transition bit in between.
        let mut offset = records_start;
        while offset < old_append {
            if image[offset] != scratch[offset] {
                io.write_at(offset, &scratch[offset..offset + 1])
                    .map_err(Error::Io)?;
            }
            offset += 1;
        }
        io.flush().map_err(Error::Io)?;
    }

    // Verify every byte of the store range, not just the bytes written.
    let expected = &scratch[..len];
    let mut buffer = [0u8; READBACK_CHUNK];
    let mut offset = 0;
    while offset < len {
        let end = core::cmp::min(offset + READBACK_CHUNK, len);
        let chunk = &expected[offset..end];
        let bytes = &mut buffer[..chunk.len()];
        io.read_at(offset, bytes).map_err(Error::Io)?;
        if let Some(index) = bytes
            .iter()
            .zip(chunk)
            .position(|(read, expected)| read != expected)
        {
            return Err(Error::Readback {
                offset: offset + index,
            });
        }
        offset = end;
    }
    image.copy_from_slice(expected);
    Ok(match mode {
        Mode::Set => Outcome::Written,
        Mode::Delete => Outcome::Deleted,
    })
}

#[cfg(all(feature = "std", unix))]
pub mod unix;
