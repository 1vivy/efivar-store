//! First-boot conversion transaction. The consumer owns the journal file's path;
//! only this module interprets its bytes. No primary write precedes a durable,
//! independently verified complete EFVS journal image.
use crate::{
    backend::{Manifest, Storage, format_error, verify_bytes},
    variables::Error,
};
use alloc::vec;
use efivar_store::{Store, efvs, migrate, sha256};
const MARKER: usize = 4096;
const MAGIC: &[u8; 8] = b"EFVMIG01";
/// Required journal bytes: marker in its own page followed by the complete image.
pub const fn journal_size(image_size: usize) -> usize {
    MARKER + image_size
}

pub(crate) fn prepare<I: Storage>(
    io: &mut I,
    image: &mut [u8],
    manifest: Manifest,
) -> Result<(), Error> {
    let mut marker = [0; MARKER];
    io.backup_read(0, &mut marker).map_err(|_| Error::Device)?;
    let valid_marker = marker[..8] == *MAGIC
        && u64::from_le_bytes(marker[8..16].try_into().unwrap()) == image.len() as u64
        && sha256::digest(&marker[..48]) == marker[48..80];
    if efvs::Header::decode(image).is_ok() && !valid_marker {
        return retire(io, &marker);
    }
    let mut staged = vec![0; image.len()];
    let recovered = if valid_marker {
        io.backup_read(MARKER, &mut staged)
            .map_err(|_| Error::Device)?;
        if sha256::digest(&staged) != marker[16..48] || efvs::Header::decode(&staged).is_err() {
            // A committed marker must never authorize a damaged backup.
            return Err(Error::Corrupt);
        }
        true
    } else {
        false
    };
    if !recovered {
        if Store::parse(image).is_ok() {
            if manifest.write_unit > efvs::DEFAULT_BLOCK_SIZE {
                return Err(Error::Unsupported);
            }
            let mut scratch = vec![0; manifest.checkpoint_capacity];
            migrate::import_edk2(
                image,
                &mut staged,
                manifest.checkpoint_capacity,
                &mut scratch,
            )
            .map_err(|e| match e {
                migrate::Error::Edk2(_) => Error::Corrupt,
                migrate::Error::Efvs(e) => format_error(e),
            })?;
        } else {
            efvs::initialize_with_block(
                &mut staged,
                manifest.checkpoint_capacity,
                manifest.write_unit.max(efvs::DEFAULT_BLOCK_SIZE),
            )
            .map_err(format_error)?;
        }
        // Invalidate a previous incomplete journal before overwriting its body.
        retire(io, &marker)?;
        io.backup_write(MARKER, &staged)
            .map_err(|_| Error::Device)?;
        io.backup_flush().map_err(|_| Error::Device)?;
        verify_backup(io, MARKER, &staged)?;
        marker.fill(0);
        marker[..8].copy_from_slice(MAGIC);
        marker[8..16].copy_from_slice(&(image.len() as u64).to_le_bytes());
        marker[16..48].copy_from_slice(&sha256::digest(&staged));
        let marker_hash = sha256::digest(&marker[..48]);
        marker[48..80].copy_from_slice(&marker_hash);
        io.backup_write(0, &marker).map_err(|_| Error::Device)?;
        io.backup_flush().map_err(|_| Error::Device)?;
        verify_backup(io, 0, &marker)?;
    }
    let h = efvs::Header::decode(&staged).map_err(format_error)?;
    // Publish only after both complete checkpoints and the zero log are durable.
    // Each initial checkpoint contains the entire imported state, never an empty fallback.
    for range in [
        2 * h.block_size..staged.len(),
        0..h.block_size,
        h.block_size..2 * h.block_size,
    ] {
        io.write_at(range.start, &staged[range.clone()])
            .map_err(|_| Error::Device)?;
        io.flush().map_err(|_| Error::Device)?;
        verify_bytes(io, range.start, &staged[range]).map_err(|_| Error::Device)?;
    }
    image.copy_from_slice(&staged);
    // No callbacks or subsequent mutations are allowed until retirement is durable.
    retire(io, &marker)
}
fn retire<I: Storage>(io: &mut I, marker: &[u8]) -> Result<(), Error> {
    if marker.iter().all(|b| *b == 0) {
        return Ok(());
    }
    let zero = [0; MARKER];
    io.backup_write(0, &zero).map_err(|_| Error::Device)?;
    io.backup_flush().map_err(|_| Error::Device)?;
    verify_backup(io, 0, &zero)
}
fn verify_backup<I: Storage>(io: &mut I, offset: usize, expected: &[u8]) -> Result<(), Error> {
    let mut buffer = [0; 4096];
    for (i, chunk) in expected.chunks(buffer.len()).enumerate() {
        io.backup_read(offset + i * 4096, &mut buffer[..chunk.len()])
            .map_err(|_| Error::Device)?;
        if buffer[..chunk.len()] != *chunk {
            return Err(Error::Device);
        }
    }
    Ok(())
}
