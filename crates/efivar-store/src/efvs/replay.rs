use super::*;
use crate::auth::{self, Authentication2, Time};
pub const GLOBAL_GUID: Guid = [
    0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
];
pub const IMAGE_SECURITY_GUID: Guid = [
    0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f,
];
pub const SHIM_GUID: Guid = [
    0x50, 0xab, 0x5d, 0x60, 0x46, 0xe0, 0x00, 0x43, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23,
];
/// Firmware-only names, independent of submitted attribute bits.
pub fn boot_services_only(name: &[u8], guid: &Guid) -> bool {
    *guid == SHIM_GUID
        && [
            "MokList",
            "MokListX",
            "MokSBState",
            "MokDBState",
            "MokIgnoreDB",
            "MokListTrusted",
        ]
        .iter()
        .any(|s| name_is(name, s))
}
pub fn secure_boot_key(name: &[u8], guid: &Guid) -> bool {
    (*guid == GLOBAL_GUID && ["PK", "KEK"].iter().any(|s| name_is(name, s)))
        || (*guid == IMAGE_SECURITY_GUID
            && ["db", "dbx", "dbt", "dbr"].iter().any(|s| name_is(name, s)))
}
/// Signature hook. The current working set includes earlier accepted key updates.
/// No production cryptographic verifier is supplied by this crate.
pub trait Verifier {
    fn authorize(&self, name: &[u8], guid: &Guid, attributes: u32) -> Result<(), Error>;
    fn verify(
        &mut self,
        request: RecordInput<'_>,
        authentication: Authentication2<'_>,
        state: &State<'_>,
    ) -> Result<(), Error>;
}
fn policy_variable(name: &[u8], guid: &Guid) -> bool {
    *guid == GLOBAL_GUID
        && ["SecureBoot", "SetupMode", "AuditMode", "DeployedMode"]
            .iter()
            .any(|s| name_is(name, s))
}
/// Official policy: no root keys, SecureBoot=0, no authenticated enrollment.
pub struct PolicyNone;
impl Verifier for PolicyNone {
    fn authorize(&self, name: &[u8], guid: &Guid, attributes: u32) -> Result<(), Error> {
        if policy_variable(name, guid) {
            return Err(Error::WriteProtected);
        }
        if attributes & 0xb0 != 0 || secure_boot_key(name, guid) {
            Err(Error::SecurityViolation)
        } else {
            Ok(())
        }
    }
    fn verify(
        &mut self,
        _: RecordInput<'_>,
        _: Authentication2<'_>,
        _: &State<'_>,
    ) -> Result<(), Error> {
        Err(Error::SecurityViolation)
    }
}
impl State<'_> {
    /// Runtime-equivalent checked operation; does not change sequence numbers.
    pub fn apply(
        &mut self,
        input: RecordInput<'_>,
        verifier: &mut impl Verifier,
    ) -> Result<(), Error> {
        input.encoded_len()?;
        let old = self.get(input.name, &input.guid);
        if boot_services_only(input.name, &input.guid)
            || old.is_some_and(|v| v.attributes & 4 == 0)
            || (input.attributes != 0 && input.attributes & 4 == 0)
            || policy_variable(input.name, &input.guid)
        {
            return Err(Error::WriteProtected);
        }
        verifier.authorize(input.name, &input.guid, input.attributes)?;
        if let Some(v) = old {
            verifier.authorize(v.name, &v.guid, v.attributes)?;
        }
        if input.attributes & !0x6f != 0 {
            return Err(Error::Unsupported);
        }
        let attrs = input.attributes & !ATTR_APPEND;
        if input.operation != Operation::Delete && attrs & 7 != 7 {
            return Err(Error::InvalidParameter);
        }
        if (input.operation == Operation::Append) != (input.attributes & ATTR_APPEND != 0) {
            return Err(Error::InvalidParameter);
        }
        if let Some(v) = old {
            if (input.operation != Operation::Delete || attrs != 0) && v.attributes != attrs {
                return Err(Error::InvalidParameter);
            }
            if v.attributes & ATTR_TIME_AUTH != 0 && attrs & ATTR_TIME_AUTH == 0 {
                return Err(Error::SecurityViolation);
            }
        }
        let mut data = input.data;
        let mut timestamp = [0; 16];
        let authenticated = attrs & ATTR_TIME_AUTH != 0;
        if authenticated {
            let old_time = old
                .map(|v| Time::parse(&v.timestamp).map_err(|_| Error::SecurityViolation))
                .transpose()?;
            let stored = old.map(|v| auth::Stored {
                attributes: v.attributes,
                data: v.data,
                time_stamp: old_time,
            });
            let request = auth::Request::parse(
                auth::VariableName::Bytes(input.name),
                &input.guid,
                input.attributes,
                stored,
                input.data,
            )
            .map_err(|_| Error::SecurityViolation)?;
            auth::check(&request).map_err(|_| Error::SecurityViolation)?;
            let auth::Descriptor::Authentication2(authentication) = request.descriptor else {
                return Err(Error::Unsupported);
            };
            let time = authentication.time_stamp();
            verifier.verify(input, authentication, self)?;
            data = &input.data[authentication.len()..];
            timestamp = if input.operation == Operation::Append {
                old_time
                    .map_or(time, |old| core::cmp::max(old, time))
                    .to_bytes()
            } else {
                time.to_bytes()
            };
        }
        if (input.operation == Operation::Delete && !data.is_empty())
            || (input.operation == Operation::Set && data.is_empty())
        {
            return Err(Error::InvalidParameter);
        }
        let count = if authenticated {
            self.authenticated_count
                .checked_add(1)
                .ok_or(Error::Bounds)?
        } else {
            self.authenticated_count
        };
        self.update(
            Variable {
                name: input.name,
                guid: input.guid,
                attributes: attrs,
                timestamp,
                data,
            },
            input.operation,
        )?;
        self.authenticated_count = count;
        Ok(())
    }
}
pub struct Replay<'a> {
    pub state: State<'a>,
    pub accepted: u64,
    pub rejected: u64,
    pub authenticated_writes: u64,
    pub log_bytes: usize,
    pub end: LogEnd,
}
pub fn replay<'a>(
    image: &[u8],
    scratch: &'a mut [u8],
    verifier: &mut impl Verifier,
    anchor: u64,
) -> Result<Replay<'a>, Error> {
    let h = Header::decode(image)?;
    let region = &image[h.checkpoint_range()];
    let cp = Checkpoint::decode(region)?;
    let mut state = State::from_checkpoint(region, scratch)?;
    // Policy filtering applies to imported/offline-created checkpoints too.
    let mut rejected = 0;
    for variable in cp.variables() {
        if verifier
            .authorize(variable.name, &variable.guid, variable.attributes)
            .is_err()
        {
            state.update(variable, Operation::Delete)?;
            rejected += 1;
        }
    }
    let mut log = Log::new(&image[h.log_offset..], cp.hash, cp.next_sequence);
    let mut accepted = 0;
    let mut authenticated_writes = 0;
    for record in log.by_ref() {
        let before = state.authenticated_count;
        match state.apply(record.input, verifier) {
            Ok(()) => {
                accepted += 1;
                authenticated_writes += state.authenticated_count - before;
            }
            Err(Error::Full) => return Err(Error::Full),
            Err(_) => rejected += 1,
        }
    }
    state.next_sequence = log.next_sequence;
    if state.authenticated_count < anchor {
        return Err(Error::Rollback);
    }
    Ok(Replay {
        state,
        accepted,
        rejected,
        authenticated_writes,
        log_bytes: log.consumed,
        end: log.end,
    })
}
/// Serialize exactly one checked append. Persist only the returned absolute range,
/// then flush before publishing the working set to readers. On I/O failure reload.
pub fn append(
    image: &mut [u8],
    input: RecordInput<'_>,
    state: &mut State<'_>,
    verifier: &mut impl Verifier,
) -> Result<core::ops::Range<usize>, Error> {
    let h = Header::decode(image)?;
    let cp = Checkpoint::decode(&image[h.checkpoint_range()])?;
    let mut log = Log::new(&image[h.log_offset..], cp.hash, cp.next_sequence);
    for _ in log.by_ref() {}
    if log.end == LogEnd::Torn {
        return Err(Error::Record);
    }
    if log.next_sequence != state.next_sequence {
        return Err(Error::Record);
    }
    let next = log.next_sequence.checked_add(1).ok_or(Error::Bounds)?;
    let size = input.encoded_len()?;
    if size > h.log_capacity - log.consumed {
        return Err(Error::Full);
    }
    let start = h.log_offset + log.consumed;
    let prev = log.previous_hash;
    state.apply(input, verifier)?;
    Record::encode(&mut image[start..], input, state.next_sequence, prev)?;
    state.next_sequence = next;
    Ok(start..start + size)
}
