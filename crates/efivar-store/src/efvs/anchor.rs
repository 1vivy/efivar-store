use super::Error;
/// The anchor exposes no capability: it is boot-local state only.
pub const CAP_NONE: u32 = 0;
/// The anchor can report a value that survives power loss.
pub const CAP_MONOTONIC: u32 = 1;
/// The runtime can bump the anchor without boot services.
pub const CAP_RUNTIME_BUMP: u32 = 2;
/// Offset of the EFVS freshness anchor in the Qualcomm DeviceInfo record.
pub const DEVINFO_RB_EFVS_ANCHOR: u32 = 31;
/// Implementations, not callers, must enforce new_value > current and boot lock.
pub trait AnchorOps {
    /// Read the current protected value.
    fn read(&mut self) -> Result<u64, Error>;
    /// Raise the protected value to `new_value`.
    fn bump(&mut self, new_value: u64) -> Result<(), Error>;
    /// Refuse every later bump until the next boot.
    fn lock(&mut self) -> Result<(), Error>;
    /// Report the anchor's capabilities as `CAP_*` bits.
    fn capabilities(&self) -> u32;
}
/// Real no-persistence backend. Its boot-local value is NOT rollback protection.
#[derive(Default)]
pub struct NoneAnchor {
    value: u64,
    locked: bool,
}
impl NoneAnchor {
    /// A boot-local anchor at value zero, unlocked.
    pub const fn new() -> Self {
        Self {
            value: 0,
            locked: false,
        }
    }
}
impl AnchorOps for NoneAnchor {
    fn read(&mut self) -> Result<u64, Error> {
        Ok(self.value)
    }
    fn bump(&mut self, new_value: u64) -> Result<(), Error> {
        if self.locked {
            return Err(Error::Locked);
        }
        if new_value <= self.value {
            return Err(Error::NonMonotonic);
        }
        self.value = new_value;
        Ok(())
    }
    fn lock(&mut self) -> Result<(), Error> {
        self.locked = true;
        Ok(())
    }
    fn capabilities(&self) -> u32 {
        CAP_NONE
    }
}
macro_rules! unsupported_anchor {
    ($name:ident) => {
        /// Authorised platform primitive STUB: no hardware I/O, no security capability.
        pub struct $name;
        impl AnchorOps for $name {
            fn read(&mut self) -> Result<u64, Error> {
                Err(Error::Unsupported)
            }
            fn bump(&mut self, _: u64) -> Result<(), Error> {
                Err(Error::Unsupported)
            }
            fn lock(&mut self) -> Result<(), Error> {
                Err(Error::Unsupported)
            }
            fn capabilities(&self) -> u32 {
                CAP_NONE
            }
        }
    };
}
unsupported_anchor!(Tpm2NvAnchor);
unsupported_anchor!(OpteeRpmbAnchor);
unsupported_anchor!(QcomDevinfoAnchor);
/// Counter capabilities alone cannot establish checkpoint provenance. V1 currently
/// has no provenance implementation and therefore never advertises tier 1 or 2.
pub const fn posture_tier(_capabilities: u32) -> u8 {
    0
}
/// Call only after checkpoint and zeroed log have been durably persisted.
pub fn commit_anchor(anchor: &mut impl AnchorOps, new_value: u64) -> Result<(), Error> {
    let old = anchor.read()?;
    if new_value < old {
        return Err(Error::Rollback);
    }
    if new_value > old {
        anchor.bump(new_value)?;
    }
    anchor.lock()
}
