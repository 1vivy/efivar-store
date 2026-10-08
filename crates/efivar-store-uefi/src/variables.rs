//! EFI variable routing and immutable physical-runtime index.
//!
//! Authenticated and append writes are unsupported. QueryVariableInfo describes
//! our managed capacity by attribute class, not a GUID-specific firmware promise.
use alloc::{vec, vec::Vec};
use efivar_store::{Guid, Store, persist};

pub mod index;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod runtime;

pub const NV: u32 = 1;
pub const BS: u32 = 2;
pub const RT: u32 = 4;
pub const MAX_NAME: usize = 256;
pub const MAX_VALUE: usize = 64 * 1024;
pub const OVERLAY_BYTES: usize = 64 * 1024;
pub const MAX_VARIABLES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidParameter,
    Unsupported,
    NotFound,
    BufferTooSmall(usize),
    OutOfResources,
    Device,
    Corrupt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Variable {
    pub name: Vec<u16>,
    pub guid: Guid,
    pub attributes: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key {
    pub name: Vec<u16>,
    pub guid: Guid,
}

/// Caller-owned namespace decision; evaluated only before ExitBootServices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Firmware,
    Store { volatile: bool },
}
pub type Policy = fn(&Guid) -> Route;
fn managed(policy: Policy, guid: &Guid) -> bool {
    matches!(policy(guid), Route::Store { .. })
}

pub fn valid_name(name: &[u16]) -> bool {
    !name.is_empty()
        && name.len() < MAX_NAME
        && !name.contains(&0)
        && char::decode_utf16(name.iter().copied()).all(|c| c.is_ok())
}

pub fn validate_attributes(attributes: u32) -> Result<(), Error> {
    if attributes & !7 != 0 {
        return Err(Error::Unsupported);
    }
    if attributes & BS == 0 {
        return Err(Error::InvalidParameter);
    }
    Ok(())
}

/// Firmware adapter supplies owned values only in boot-services context.
pub trait Firmware {
    fn get(&mut self, name: &[u16], guid: &Guid) -> Result<Variable, Error>;
    fn set(&mut self, name: &[u16], guid: &Guid, attributes: u32, data: &[u8])
    -> Result<(), Error>;
    fn list(&mut self) -> Result<Vec<Variable>, Error>;
    fn enumerate(&mut self) -> Result<Vec<Variable>, Error> {
        self.list()
    }
    fn truncated(&self) -> bool {
        false
    }
}

pub struct Service<I, F> {
    pub io: I,
    pub policy: Policy,
    pub firmware: F,
    image: Vec<u8>,
    scratch: Vec<u8>,
    overlay: Vec<Variable>,
    captured: Vec<Variable>,
    valid: bool,
    pub capture_truncated: bool,
}

impl<I: persist::Flush, F: Firmware> Service<I, F> {
    pub fn open(mut io: I, mut firmware: F, size: usize, policy: Policy) -> Result<Self, Error> {
        let mut image = vec![0; size];
        io.read_at(0, &mut image).map_err(|_| Error::Device)?;
        Store::parse(&image).map_err(|_| Error::Corrupt)?;
        let mut capture_truncated = false;
        let mut captured = Vec::new();
        let mut bytes = 0;
        for v in firmware
            .list()?
            .into_iter()
            .filter(|v| !managed(policy, &v.guid) && v.attributes & RT != 0)
        {
            let size = index::RECORD + (v.name.len() + 1) * 2 + v.data.len() + 7;
            if !valid_name(&v.name)
                || v.data.len() > MAX_VALUE
                || captured.len() == 256
                || bytes + size > 512 * 1024
            {
                capture_truncated = true;
            } else {
                bytes += size;
                captured.push(v);
            }
        }
        capture_truncated |= firmware.truncated();
        Ok(Self {
            io,
            policy,
            firmware,
            image,
            scratch: vec![0; size],
            overlay: Vec::new(),
            captured,
            valid: true,
            capture_truncated,
        })
    }

    pub fn image_size(&self) -> usize {
        self.image.len()
    }

    fn reload(&mut self) -> Result<(), Error> {
        if !self.valid {
            self.io
                .read_at(0, &mut self.image)
                .map_err(|_| Error::Device)?;
            Store::parse(&self.image).map_err(|_| Error::Corrupt)?;
            self.valid = true;
        }
        Ok(())
    }

    pub fn get(&mut self, name: &[u16], guid: &Guid) -> Result<Variable, Error> {
        if !managed(self.policy, guid) {
            return self.firmware.get(name, guid);
        }
        let (attributes, data) = self.managed_value(name, guid)?;
        Ok(Variable {
            name: name.to_vec(),
            guid: *guid,
            attributes,
            data: data.to_vec(),
        })
    }

    /// Borrow a managed value directly from the cache/overlay. EFI GetVariable
    /// can copy into the caller's output without allocating a temporary value.
    pub fn managed_value(&mut self, name: &[u16], guid: &Guid) -> Result<(u32, &[u8]), Error> {
        if !managed(self.policy, guid) {
            return Err(Error::Unsupported);
        }
        if !valid_name(name) {
            return Err(Error::InvalidParameter);
        }
        self.reload()?;
        if let Some(v) = self
            .overlay
            .iter()
            .find(|v| v.guid == *guid && v.name == name)
        {
            return Ok((v.attributes, &v.data));
        }
        Store::parse(&self.image)
            .map_err(|_| Error::Corrupt)?
            .get(name, guid)
            .map(|v| (v.attributes, v.data))
            .ok_or(Error::NotFound)
    }

    pub fn set(
        &mut self,
        name: &[u16],
        guid: &Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        if !managed(self.policy, guid) {
            self.firmware.set(name, guid, attributes, data)?;
            self.refresh_capture(name, guid);
            return Ok(());
        }
        if !valid_name(name) {
            return Err(Error::InvalidParameter);
        }
        if attributes & !7 != 0 {
            return Err(Error::Unsupported);
        }
        if attributes & RT != 0 && attributes & BS == 0 {
            return Err(Error::InvalidParameter);
        }
        self.reload()?;
        let deleting = attributes == 0 || data.is_empty();
        let previous = match self.managed_value(name, guid) {
            Ok((attributes, data)) => Some((attributes, data.len())),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        if deleting && previous.is_none() {
            return Err(Error::NotFound);
        }
        if !deleting {
            validate_attributes(attributes)?;
            if data.len() > MAX_VALUE {
                return Err(Error::OutOfResources);
            }
            if previous.as_ref().is_some_and(|v| v.0 != attributes) {
                return Err(Error::InvalidParameter);
            }
            if previous.is_none()
                && attributes & RT != 0
                && Store::parse(&self.image)
                    .map_err(|_| Error::Corrupt)?
                    .list()
                    .filter(|v| managed(self.policy, &v.guid) && v.attributes & RT != 0)
                    .count()
                    + self
                        .overlay
                        .iter()
                        .filter(|v| v.attributes & RT != 0)
                        .count()
                    + self.captured.len()
                    >= MAX_VARIABLES
            {
                return Err(Error::OutOfResources);
            }
        }
        let volatile = previous
            .as_ref()
            .map_or(attributes & NV == 0, |v| v.0 & NV == 0);
        if volatile {
            if !matches!((self.policy)(guid), Route::Store { volatile: true }) {
                return Err(Error::Unsupported);
            }
            let old = previous.as_ref().map_or(0, |v| (name.len() + 1) * 2 + v.1);
            let used: usize = self
                .overlay
                .iter()
                .map(|v| (v.name.len() + 1) * 2 + v.data.len())
                .sum();
            if !deleting
                && (used - old + (name.len() + 1) * 2 + data.len() > OVERLAY_BYTES
                    || (previous.is_none() && self.overlay.len() == MAX_VARIABLES))
            {
                return Err(Error::OutOfResources);
            }
            self.overlay.retain(|v| v.guid != *guid || v.name != name);
            if !deleting {
                self.overlay.push(Variable {
                    name: name.to_vec(),
                    guid: *guid,
                    attributes,
                    data: data.to_vec(),
                });
            }
            return Ok(());
        }
        let change = if deleting {
            persist::Change::Delete { name, guid }
        } else {
            persist::Change::Set {
                name,
                guid,
                attributes,
                data,
            }
        };
        if let Err(e) = persist::apply(&mut self.io, &mut self.image, &mut self.scratch, change) {
            self.valid = false;
            return Err(match e {
                persist::Error::Format(
                    efivar_store::Error::Full | efivar_store::Error::ScratchTooSmall,
                ) => Error::OutOfResources,
                persist::Error::Format(
                    efivar_store::Error::AuthenticatedWrite
                    | efivar_store::Error::UnsupportedAttributes,
                ) => Error::Unsupported,
                persist::Error::Format(efivar_store::Error::Name) => Error::InvalidParameter,
                persist::Error::Format(_) => Error::Corrupt,
                _ => Error::Device,
            });
        }
        Ok(())
    }

    pub fn refresh_capture(&mut self, name: &[u16], guid: &Guid) {
        self.captured.retain(|v| v.guid != *guid || v.name != name);
        match self.firmware.get(name, guid) {
            Ok(v) if v.attributes & RT != 0 => {
                let used: usize = self
                    .captured
                    .iter()
                    .map(|v| index::RECORD + (v.name.len() + 1) * 2 + v.data.len() + 7)
                    .sum();
                let managed_count = Store::parse(&self.image).map_or(MAX_VARIABLES, |store| {
                    store
                        .list()
                        .filter(|v| managed(self.policy, &v.guid) && v.attributes & RT != 0)
                        .count()
                });
                if valid_name(&v.name)
                    && v.data.len() <= MAX_VALUE
                    && self.captured.len() < 256
                    && managed_count
                        + self
                            .overlay
                            .iter()
                            .filter(|v| v.attributes & RT != 0)
                            .count()
                        + self.captured.len()
                        < MAX_VARIABLES
                    && used + index::RECORD + (v.name.len() + 1) * 2 + v.data.len() + 7
                        <= 512 * 1024
                {
                    self.captured.push(v);
                } else {
                    self.capture_truncated = true;
                }
            }
            Err(Error::NotFound) | Ok(_) => {}
            Err(_) => {
                self.capture_truncated = true;
            }
        }
    }

    /// Managed keys first, then non-managed firmware keys; neither phase copies values.
    pub fn list(&mut self) -> Result<Vec<Key>, Error> {
        self.reload()?;
        let mut values: Vec<_> = Store::parse(&self.image)
            .map_err(|_| Error::Corrupt)?
            .list()
            .filter(|v| managed(self.policy, &v.guid))
            .map(|v| Key {
                name: v.name.units().collect(),
                guid: v.guid,
            })
            .collect();
        values.extend(self.overlay.iter().map(|v| Key {
            name: v.name.clone(),
            guid: v.guid,
        }));
        values.sort_by(|a, b| (&a.guid, &a.name).cmp(&(&b.guid, &b.name)));
        let mut firmware: Vec<_> = self
            .firmware
            .enumerate()?
            .into_iter()
            .map(|v| Key {
                name: v.name,
                guid: v.guid,
            })
            .collect();
        firmware.retain(|v| !managed(self.policy, &v.guid));
        firmware.sort_by(|a, b| (&a.guid, &a.name).cmp(&(&b.guid, &b.name)));
        firmware.dedup_by(|a, b| a.guid == b.guid && a.name == b.name);
        values.extend(firmware);
        Ok(values)
    }

    pub fn snapshot(&mut self, output: &mut [u8]) -> Result<(), Error> {
        self.reload()?;
        let store = Store::parse(&self.image).map_err(|_| Error::Corrupt)?;
        let nv = (
            store.capacity() as u64,
            store.free_space() as u64,
            MAX_VALUE as u64,
        );
        let used: usize = self
            .overlay
            .iter()
            .map(|v| (v.name.len() + 1) * 2 + v.data.len())
            .sum();
        let volatile = (
            OVERLAY_BYTES as u64,
            (OVERLAY_BYTES - used) as u64,
            MAX_VALUE as u64,
        );
        let mut builder = index::Builder::new(output, self.capture_truncated)?;
        builder.capacity(nv, volatile);
        let mut values: Vec<_> = store
            .list()
            .filter(|v| managed(self.policy, &v.guid) && v.attributes & RT != 0)
            .map(|v| {
                (
                    v.guid,
                    v.name.units().collect::<Vec<_>>(),
                    v.attributes,
                    v.data,
                )
            })
            .collect();
        values.extend(
            self.overlay
                .iter()
                .filter(|v| v.attributes & RT != 0)
                .map(|v| (v.guid, v.name.clone(), v.attributes, v.data.as_slice())),
        );
        values.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        for (guid, name, attributes, data) in values {
            builder.push(&name, &guid, attributes, data)?;
        }
        let mut captured: Vec<_> = self.captured.iter().collect();
        captured.sort_by(|a, b| (&a.guid, &a.name).cmp(&(&b.guid, &b.name)));
        for v in captured {
            builder.push(&v.name, &v.guid, v.attributes, &v.data)?;
        }
        builder.finish();
        Ok(())
    }

    pub fn capacity(&mut self, attributes: u32) -> Result<(u64, u64, u64), Error> {
        validate_attributes(attributes)?;
        self.reload()?;
        let (maximum, remaining) = if attributes & NV != 0 {
            let store = Store::parse(&self.image).map_err(|_| Error::Corrupt)?;
            (store.capacity(), store.free_space())
        } else {
            (
                OVERLAY_BYTES,
                OVERLAY_BYTES
                    - self
                        .overlay
                        .iter()
                        .map(|v| (v.name.len() + 1) * 2 + v.data.len())
                        .sum::<usize>(),
            )
        };
        Ok((maximum as u64, remaining as u64, MAX_VALUE as u64))
    }
}

pub fn next<'a>(values: &'a [Key], previous: &[u16], guid: &Guid) -> Result<&'a Key, Error> {
    let position = if previous.is_empty() {
        0
    } else {
        values
            .iter()
            .position(|v| v.name == previous && v.guid == *guid)
            .ok_or(Error::InvalidParameter)?
            + 1
    };
    values.get(position).ok_or(Error::NotFound)
}

pub fn read_value(value: &Variable, output: &mut [u8]) -> Result<(u32, usize), Error> {
    if output.len() < value.data.len() {
        return Err(Error::BufferTooSmall(value.data.len()));
    }
    output[..value.data.len()].copy_from_slice(&value.data);
    Ok((value.attributes, value.data.len()))
}

#[cfg(test)]
mod tests;
