//! Blank-partition initialisation. The consumer owns the primary image; this
//! module only decides whether the bytes it read are already EFVS, blank, or
//! foreign. There is no migration path: a non-blank image that is not EFVS is
//! refused, never converted.
use crate::{
    backend::{Manifest, Storage, format_error, verify_bytes},
    variables::Error,
};
use efivar_store::efvs;

pub(crate) fn prepare<I: Storage>(
    io: &mut I,
    image: &mut [u8],
    manifest: Manifest,
) -> Result<(), Error> {
    if efvs::Header::decode(image).is_ok() {
        return Ok(());
    }
    if image.iter().any(|byte| *byte != 0) {
        return Err(Error::Corrupt);
    }
    efvs::initialize_with_block(
        image,
        manifest.checkpoint_capacity,
        manifest.write_unit.max(efvs::DEFAULT_BLOCK_SIZE),
    )
    .map_err(format_error)?;
    let header = efvs::Header::decode(image).map_err(format_error)?;
    // Durable publication order: the tail (both checkpoints and the zero log),
    // then header A, then header B. Each whole write unit is flushed and read
    // back, so a torn write is reported rather than left as a store that only
    // looks initialized.
    for range in [
        2 * header.block_size..image.len(),
        0..header.block_size,
        header.block_size..2 * header.block_size,
    ] {
        io.write_at(range.start, &image[range.clone()])
            .map_err(|_| Error::Device)?;
        io.flush().map_err(|_| Error::Device)?;
        verify_bytes(io, range.start, &image[range]).map_err(|_| Error::Device)?;
    }
    Ok(())
}
