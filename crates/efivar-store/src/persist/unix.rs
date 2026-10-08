//! Unix file and block-device adapter for [`apply`](super::apply).
//!
//! [`Device`] owns the opened descriptor and the two image buffers; a
//! [`Device::transaction`] takes a blocking `flock(LOCK_EX)`, reloads the whole
//! store from the backing store under that lock, parses it, runs the caller's
//! closure (which may call [`Transaction::apply`]) and releases the lock. Every
//! read comes from the backing store — never from an `efivarfs` snapshot — and
//! every write is followed by `fsync`, so cooperative writers that use this
//! adapter serialise on the same lock and cannot interleave phases.

use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::path::Path;
use std::vec::Vec;

use crate::persist::{self, Change, Error, Flush, Outcome, Read, Write};
use crate::{Error as FormatError, Guid, Store, Variable};

/// `flock(2)` exclusive lock; blocking.
const LOCK_EX: core::ffi::c_int = 2;
/// `flock(2)` unlock.
const LOCK_UN: core::ffi::c_int = 8;

// SAFETY: `flock` is the standard Unix advisory lock; it takes a live
// descriptor and a flag word, holds no pointers and cannot be called with
// invalid memory through these arguments.
unsafe extern "C" {
    fn flock(fd: core::ffi::c_int, operation: core::ffi::c_int) -> core::ffi::c_int;
}

/// One opened backing store plus its reusable image buffers.
pub struct Device {
    file: File,
    /// Current device contents, as of the last load. Invalid after a failed
    /// mutation; [`Device::transaction`] reloads before every closure.
    image: Vec<u8>,
    /// Build buffer for the updated image, never written to until a phase runs.
    scratch: Vec<u8>,
}

impl Device {
    /// Opens a file or block device read-write. Nothing is locked or read yet.
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self::wrap(
            OpenOptions::new().read(true).write(true).open(path)?,
        ))
    }

    /// Opens a file or block device read-only, for `inspect`/`list`/`get`.
    pub fn open_read_only(path: &Path) -> io::Result<Self> {
        Ok(Self::wrap(OpenOptions::new().read(true).open(path)?))
    }

    fn wrap(file: File) -> Self {
        Self {
            file,
            image: Vec::new(),
            scratch: Vec::new(),
        }
    }

    /// Size of the backing store: the file length, or, for block devices (whose
    /// metadata length is zero), the size reached by seeking to the end.
    fn size(&self) -> io::Result<u64> {
        let metadata = self.file.metadata()?;
        if metadata.file_type().is_block_device() || metadata.len() == 0 {
            let mut file = &self.file;
            return file.seek(SeekFrom::End(0));
        }
        Ok(metadata.len())
    }

    /// Reads the whole store into the reusable image buffer. The contents are
    /// exactly what the backing store holds; no cache is consulted.
    pub fn load(&mut self) -> Result<(), Error<io::Error>> {
        let len = self.size().map_err(Error::Io)?;
        let len = usize::try_from(len).map_err(|_| Error::Format(FormatError::Bounds))?;
        self.image.resize(len, 0);
        self.scratch.resize(len, 0);
        self.file
            .read_exact_at(&mut self.image, 0)
            .map_err(Error::Io)
    }

    /// The bytes read by the last [`Device::load`] or transaction.
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    /// Runs `f` inside one exclusive, reloaded transaction.
    ///
    /// The closure sees the store exactly as the device holds it and may call
    /// [`Transaction::apply`] at most once; the lock is released on every exit
    /// path, including an error returned by the closure.
    pub fn transaction<T>(
        &mut self,
        f: impl FnOnce(&mut Transaction<'_>) -> Result<T, Error<io::Error>>,
    ) -> Result<T, Error<io::Error>> {
        let fd = self.file.as_raw_fd();
        lock(fd, LOCK_EX).map_err(Error::Io)?;
        let result = (|| {
            self.load()?;
            Store::parse(&self.image).map_err(Error::Format)?;
            let mut transaction = Transaction {
                io: FileIo(&self.file),
                image: &mut self.image,
                scratch: &mut self.scratch,
            };
            f(&mut transaction)
        })();
        let unlocked = lock(fd, LOCK_UN).map_err(Error::Io);
        match (result, unlocked) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
}

/// The store view and mutation entry point handed to a transaction closure.
pub struct Transaction<'a> {
    io: FileIo<'a>,
    image: &'a mut Vec<u8>,
    scratch: &'a mut Vec<u8>,
}

impl Transaction<'_> {
    /// The reloaded device image, validated by the transaction start.
    pub fn store(&self) -> Result<Store<'_>, Error<io::Error>> {
        Store::parse(self.image.as_slice()).map_err(Error::Format)
    }

    /// Raw bytes of the reloaded device image.
    pub fn image(&self) -> &[u8] {
        self.image.as_slice()
    }

    /// Live value of a key, resolved exactly as `FindVariableEx` would.
    pub fn get(&self, name: &[u16], guid: &Guid) -> Result<Option<Variable<'_>>, Error<io::Error>> {
        Ok(self.store()?.get(name, guid))
    }

    /// Every live variable, each (name, GUID) once.
    pub fn list(&self) -> Result<impl Iterator<Item = Variable<'_>>, Error<io::Error>> {
        Ok(self.store()?.list())
    }

    /// Applies one change to the device with the ordered, flushed phases of
    /// [`persist::apply`].
    pub fn apply(&mut self, change: Change<'_>) -> Result<Outcome, Error<io::Error>> {
        persist::apply(
            &mut self.io,
            self.image.as_mut_slice(),
            self.scratch.as_mut_slice(),
            change,
        )
    }

    /// [`Change::Set`] convenience.
    pub fn set(
        &mut self,
        name: &[u16],
        guid: &Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<Outcome, Error<io::Error>> {
        self.apply(Change::Set {
            name,
            guid,
            attributes,
            data,
        })
    }

    /// [`Change::Delete`] convenience.
    pub fn delete(&mut self, name: &[u16], guid: &Guid) -> Result<Outcome, Error<io::Error>> {
        self.apply(Change::Delete { name, guid })
    }
}

/// Blocking `flock(2)` on a descriptor that stays open across the call.
fn lock(fd: RawFd, operation: core::ffi::c_int) -> io::Result<()> {
    // SAFETY: `fd` is an open descriptor owned by the caller for the duration
    // of the call; `flock` dereferences no pointer arguments.
    if unsafe { flock(fd, operation) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Positional I/O over the backing store: one `fsync` per flush.
struct FileIo<'a>(&'a File);

impl Read for FileIo<'_> {
    type Error = io::Error;

    fn read_at(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read_exact_at(buf, offset as u64)
    }
}

impl Write for FileIo<'_> {
    fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), Self::Error> {
        self.0.write_all_at(data, offset as u64)
    }
}

impl Flush for FileIo<'_> {
    fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.sync_all()
    }
}
