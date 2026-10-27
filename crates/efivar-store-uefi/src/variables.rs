//! EFI variable routing and immutable physical-runtime index.
//!
//! The caller's verifier governs persistent updates. QueryVariableInfo describes
//! our managed capacity by attribute class, not a GUID-specific firmware promise.
use crate::backend::{Efvs, Manifest, Storage, units};
use alloc::vec::Vec;
use efivar_store::{Guid, efvs};

pub mod index;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod runtime;

/// `EFI_VARIABLE_NON_VOLATILE`.
pub const NV: u32 = 1;
/// `EFI_VARIABLE_BOOTSERVICE_ACCESS`.
pub const BS: u32 = 2;
/// `EFI_VARIABLE_RUNTIME_ACCESS`.
pub const RT: u32 = 4;
/// Longest accepted variable name, in code units, terminator included.
pub const MAX_NAME: usize = 256;
/// Largest accepted variable value in bytes.
pub const MAX_VALUE: usize = 64 * 1024;
/// Bytes the volatile overlay may hold.
pub const OVERLAY_BYTES: usize = 64 * 1024;
/// Most variables the managed store and the snapshot index accept together.
pub const MAX_VARIABLES: usize = 512;

/// Why a variable operation failed, in the shape a UEFI status maps from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The name, attribute word or request is inconsistent.
    InvalidParameter,
    /// The feature or route is not offered by this configuration.
    Unsupported,
    /// The variable does not exist.
    NotFound,
    /// The verifier refused the write.
    SecurityViolation,
    /// The variable is firmware-only or otherwise write-protected.
    WriteProtected,
    /// The caller's output buffer is smaller than the value.
    BufferTooSmall(usize),
    /// The store or overlay has no room.
    OutOfResources,
    /// The backing device failed an operation or returned unexpected bytes.
    Device,
    /// The stored bytes do not parse.
    Corrupt,
}

/// One variable value, owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Variable {
    /// The name, in UTF-16 code units without the terminator.
    pub name: Vec<u16>,
    /// The vendor GUID in EFI on-disk byte order.
    pub guid: Guid,
    /// The attribute word.
    pub attributes: u32,
    /// The value.
    pub data: Vec<u8>,
}

/// One `(name, GUID)` key, owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key {
    /// The name, in UTF-16 code units without the terminator.
    pub name: Vec<u16>,
    /// The vendor GUID in EFI on-disk byte order.
    pub guid: Guid,
}

/// Caller-owned namespace decision; evaluated only before ExitBootServices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Serve the GUID from the firmware's own variable services.
    Firmware,
    /// Serve the GUID from the managed store; `volatile` keeps the value in
    /// the boot-local overlay instead of the partition.
    Store {
        /// Keep the value in the boot-local overlay only.
        volatile: bool,
    },
}
/// The consumer's `GUID -> Route` decision function.
pub type Policy = fn(&Guid) -> Route;
fn managed(policy: Policy, guid: &Guid) -> bool {
    matches!(policy(guid), Route::Store { .. })
}

/// Whether `name` is a legal UEFI variable name.
pub fn valid_name(name: &[u16]) -> bool {
    !name.is_empty()
        && name.len() < MAX_NAME
        && !name.contains(&0)
        && char::decode_utf16(name.iter().copied()).all(|c| c.is_ok())
}

/// Check an attribute word the volatile overlay accepts.
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
    /// Read one firmware-owned variable.
    fn get(&mut self, name: &[u16], guid: &Guid) -> Result<Variable, Error>;
    /// Write one firmware-owned variable.
    fn set(&mut self, name: &[u16], guid: &Guid, attributes: u32, data: &[u8])
    -> Result<(), Error>;
    /// List the firmware-owned variables whose GUIDs the policy keeps on firmware.
    fn list(&mut self) -> Result<Vec<Variable>, Error>;
    /// Enumerate keys without copying values, when the firmware can.
    fn enumerate(&mut self) -> Result<Vec<Variable>, Error> {
        self.list()
    }
    /// Whether `list` stopped short of the full namespace.
    fn truncated(&self) -> bool {
        false
    }
}

/// The routed variable service: a managed store, the firmware adapter, and the
/// boot-local volatile overlay.
pub struct Service<I, F, V = efvs::PolicyNone> {
    /// The managed persistent store.
    pub store: Efvs<I, V>,
    /// The GUID routing decision.
    pub policy: Policy,
    /// The firmware namespace the policy keeps on firmware.
    pub firmware: F,
    overlay: Vec<Variable>,
    captured: Vec<Variable>,
    /// Whether capturing firmware runtime variables overflowed a limit.
    pub capture_truncated: bool,
}

impl<I: Storage, F: Firmware, V: efvs::Verifier> Service<I, F, V> {
    /// Open the managed store and capture the firmware runtime variables the
    /// policy keeps on firmware.
    pub fn open(
        io: I,
        mut firmware: F,
        manifest: Manifest,
        policy: Policy,
        verifier: V,
        anchor: &mut impl efvs::AnchorOps,
    ) -> Result<Self, Error> {
        let store = Efvs::open(io, manifest, verifier, anchor)?;
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
            store,
            policy,
            firmware,
            overlay: Vec::new(),
            captured,
            capture_truncated,
        })
    }

    /// Size of the managed store image in bytes.
    pub fn image_size(&self) -> usize {
        self.store.image_size()
    }

    fn reload(&mut self) -> Result<(), Error> {
        self.store.reload()
    }

    /// Read one variable through the route its GUID selects.
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
        self.store.get(name, guid)
    }

    /// Write one variable through the route its GUID selects.
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
        if attributes & !0x6f != 0 {
            return Err(Error::Unsupported);
        }
        if attributes & RT != 0 && attributes & BS == 0 {
            return Err(Error::InvalidParameter);
        }
        self.reload()?;
        let deleting = crate::backend::deleting(attributes, data)?;
        let previous = match self.managed_value(name, guid) {
            Ok((attributes, data)) => Some((attributes, data.len())),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        if deleting && previous.is_none() {
            return Err(Error::NotFound);
        }
        if !deleting {
            if attributes & BS == 0 {
                return Err(Error::InvalidParameter);
            }
            if data.len() > MAX_VALUE {
                return Err(Error::OutOfResources);
            }
            if previous
                .as_ref()
                .is_some_and(|v| v.0 != attributes & !efvs::ATTR_APPEND)
            {
                return Err(Error::InvalidParameter);
            }
            if previous.is_none()
                && attributes & RT != 0
                && self
                    .store
                    .variables()?
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
            if !deleting {
                validate_attributes(attributes)?;
            }
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
        self.store.set(name, guid, attributes, data)
    }

    /// Refresh the captured firmware copy of one key after a firmware write.
    pub fn refresh_capture(&mut self, name: &[u16], guid: &Guid) {
        self.captured.retain(|v| v.guid != *guid || v.name != name);
        match self.firmware.get(name, guid) {
            Ok(v) if v.attributes & RT != 0 => {
                let used: usize = self
                    .captured
                    .iter()
                    .map(|v| index::RECORD + (v.name.len() + 1) * 2 + v.data.len() + 7)
                    .sum();
                let managed_count = self.store.variables().map_or(MAX_VARIABLES, |variables| {
                    variables
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
    /// Both phases are ordered by GUID then name.
    pub fn list(&mut self) -> Result<Vec<Key>, Error> {
        self.reload()?;
        let mut values: Vec<_> = self
            .store
            .variables()?
            .filter(|v| managed(self.policy, &v.guid))
            .map(|v| Key {
                name: units(v.name).collect(),
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

    /// Build the immutable physical-runtime index into `output`.
    pub fn snapshot(&mut self, output: &mut [u8]) -> Result<(), Error> {
        self.reload()?;
        let (maximum, remaining) = self.store.capacity()?;
        let nv = (maximum as u64, remaining as u64, MAX_VALUE as u64);
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
        let mut values: Vec<_> = self
            .store
            .variables()?
            .filter(|v| managed(self.policy, &v.guid) && v.attributes & RT != 0)
            .map(|v| {
                (
                    v.guid,
                    units(v.name).collect::<Vec<_>>(),
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

    /// `QueryVariableInfo` values for one attribute class: maximum, remaining, and
    /// largest single value.
    pub fn capacity(&mut self, attributes: u32) -> Result<(u64, u64, u64), Error> {
        validate_attributes(attributes)?;
        self.reload()?;
        let (maximum, remaining) = if attributes & NV != 0 {
            self.store.capacity()?
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

/// The key after `(previous, guid)` in a sorted key list.
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

/// Copy a variable value into `output`, returning its attributes and length.
pub fn read_value(value: &Variable, output: &mut [u8]) -> Result<(u32, usize), Error> {
    if output.len() < value.data.len() {
        return Err(Error::BufferTooSmall(value.data.len()));
    }
    output[..value.data.len()].copy_from_slice(&value.data);
    Ok((value.attributes, value.data.len()))
}

#[cfg(test)]
mod tests;
