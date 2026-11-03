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
///
/// The service applies it to every key that a [`NamePolicy`] leaves undecided.
/// Evaluate it only before ExitBootServices.
pub type Policy = fn(&Guid) -> Route;
/// The consumer's `(GUID, name) -> Route` decision function.
///
/// The service consults it before the [`Policy`] for every key. `Some(route)`
/// decides that key; `None` defers to the GUID decision. A consumer selects this
/// policy when one GUID must route by name, such as the EFI global namespace
/// whose boot names belong to the store while `BootCurrent` stays with the
/// firmware. Evaluate it only before ExitBootServices.
pub type NamePolicy = fn(&Guid, &[u16]) -> Option<Route>;
/// The route one key takes: the name decision first, then the GUID decision.
fn route(policy: Policy, names: Option<NamePolicy>, name: &[u16], guid: &Guid) -> Route {
    names
        .and_then(|names| names(guid, name))
        .unwrap_or_else(|| policy(guid))
}
/// Whether `(name, guid)` routes to the managed store.
fn routed(policy: Policy, names: Option<NamePolicy>, name: &[u16], guid: &Guid) -> bool {
    is_store(route(policy, names, name, guid))
}
/// Whether `route` serves the value from the managed store.
fn is_store(route: Route) -> bool {
    matches!(route, Route::Store { .. })
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
    /// The name-aware routing decision, consulted before [`Service::policy`].
    names: Option<NamePolicy>,
    /// The firmware namespace the policy keeps on firmware.
    pub firmware: F,
    overlay: Vec<Variable>,
    captured: Vec<Variable>,
    /// Whether capturing firmware runtime variables overflowed a limit.
    pub capture_truncated: bool,
}

impl<I: Storage, F: Firmware, V: efvs::Verifier> Service<I, F, V> {
    /// Open the managed store and capture the firmware runtime variables the
    /// GUID policy keeps on firmware.
    ///
    /// Use [`Service::open_uncaptured`], [`Service::select_names`] and
    /// [`Service::capture`] instead when a value in the store decides the
    /// routing.
    pub fn open(
        io: I,
        firmware: F,
        manifest: Manifest,
        policy: Policy,
        verifier: V,
        anchor: &mut impl efvs::AnchorOps,
    ) -> Result<Self, Error> {
        let mut service = Self::open_uncaptured(io, firmware, manifest, policy, verifier, anchor)?;
        service.capture()?;
        Ok(service)
    }

    /// Open the managed store without capturing the firmware namespace.
    ///
    /// The caller reads any routing selection from `service.store`, calls
    /// [`Service::select_names`], then calls [`Service::capture`]. Capture reads
    /// the firmware namespace, so it runs after the selection: the selection
    /// decides which firmware names stay visible.
    pub fn open_uncaptured(
        io: I,
        firmware: F,
        manifest: Manifest,
        policy: Policy,
        verifier: V,
        anchor: &mut impl efvs::AnchorOps,
    ) -> Result<Self, Error> {
        Ok(Self {
            store: Efvs::open(io, manifest, verifier, anchor)?,
            policy,
            names: None,
            firmware,
            overlay: Vec::new(),
            captured: Vec::new(),
            capture_truncated: false,
        })
    }

    /// Select the name-aware routing decision, replacing any earlier one.
    ///
    /// Select before [`Service::capture`], which copies the firmware names the
    /// routing keeps on firmware. Every later read, write, enumeration and
    /// snapshot decides each key again through the same routing.
    pub fn select_names(&mut self, names: Option<NamePolicy>) {
        self.names = names;
    }

    /// Capture the firmware runtime variables the current routing keeps on
    /// firmware, replacing the captured set.
    ///
    /// [`Service::open`] calls it once. A second call reflects the current
    /// selection, so a consumer that reselects the routing recaptures.
    pub fn capture(&mut self) -> Result<(), Error> {
        let policy = self.policy;
        let names = self.names;
        let listed = self.firmware.list()?;
        let mut captured = Vec::new();
        let mut bytes = 0;
        let mut truncated = false;
        for v in listed
            .into_iter()
            .filter(|v| !routed(policy, names, &v.name, &v.guid) && v.attributes & RT != 0)
        {
            let size = index::RECORD + (v.name.len() + 1) * 2 + v.data.len() + 7;
            if !valid_name(&v.name)
                || v.data.len() > MAX_VALUE
                || captured.len() == 256
                || bytes + size > 512 * 1024
            {
                truncated = true;
            } else {
                bytes += size;
                captured.push(v);
            }
        }
        truncated |= self.firmware.truncated();
        self.captured = captured;
        self.capture_truncated |= truncated;
        Ok(())
    }

    /// The route one key takes.
    pub fn route(&self, name: &[u16], guid: &Guid) -> Route {
        route(self.policy, self.names, name, guid)
    }

    /// Whether one key routes to the managed store.
    fn managed(&self, name: &[u16], guid: &Guid) -> bool {
        routed(self.policy, self.names, name, guid)
    }

    /// Whether one stored key routes to the managed store.
    fn managed_stored(&self, name: &[u8], guid: &Guid) -> bool {
        match self.names {
            Some(names) => names(guid, &units(name).collect::<Vec<_>>()).is_some_and(is_store),
            None => is_store((self.policy)(guid)),
        }
    }

    /// Size of the managed store image in bytes.
    pub fn image_size(&self) -> usize {
        self.store.image_size()
    }

    fn reload(&mut self) -> Result<(), Error> {
        self.store.reload()
    }

    /// Read one variable through the route its GUID and name select.
    pub fn get(&mut self, name: &[u16], guid: &Guid) -> Result<Variable, Error> {
        if !self.managed(name, guid) {
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
        if !self.managed(name, guid) {
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

    /// Write one variable through the route its GUID and name select.
    pub fn set(
        &mut self,
        name: &[u16],
        guid: &Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        if !self.managed(name, guid) {
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
                    .filter(|v| self.managed_stored(v.name, &v.guid) && v.attributes & RT != 0)
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
            if !matches!(self.route(name, guid), Route::Store { volatile: true }) {
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
                        .filter(|v| self.managed_stored(v.name, &v.guid) && v.attributes & RT != 0)
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
            .filter(|v| self.managed_stored(v.name, &v.guid))
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
        firmware.retain(|v| !self.managed(&v.name, &v.guid));
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
        let policy = self.policy;
        let names = self.names;
        let mut values: Vec<_> = Vec::new();
        for v in self.store.variables()? {
            let name: Vec<u16> = units(v.name).collect();
            if v.attributes & RT != 0 && routed(policy, names, &name, &v.guid) {
                values.push((v.guid, name, v.attributes, v.data));
            }
        }
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
