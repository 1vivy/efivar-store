//! Descriptor parsing, digest-input construction and the rule set of `efivar_store::auth`.
//!
//! The module is pure, so every test here checks one of three things: the bytes a
//! descriptor exposes, the exact digest input a signature would cover, or the refusal a
//! rule produces. "Nothing is written" is enforced by the type system — the parsers and
//! [`auth::check`] take shared references — and is additionally asserted for the two
//! functions that do take a caller buffer, which must leave it untouched when they fail.

use efivar_store::auth::{
    self, Authentication2, Authentication3, Descriptor, DigestInput, Error, KeyStore, Kind3, Mode,
    Pkcs7Verifier, Plan, Policy, Request, Role, SecureBootPolicy, Stored, Time, Unsupported,
    VariableName, Verifier,
};

const GUID: [u8; 16] = [
    0x82, 0xb0, 0x67, 0x4a, 0x4c, 0x0a, 0xcf, 0x41, 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f,
];

/// The attribute word of a time-based authenticated, non-volatile runtime variable.
const AUTH_ATTRIBUTES: u32 = auth::NON_VOLATILE
    | auth::BOOTSERVICE_ACCESS
    | auth::RUNTIME_ACCESS
    | auth::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

/// The attribute word of an enhanced-authenticated runtime variable.
const ENHANCED_ATTRIBUTES: u32 =
    auth::NON_VOLATILE | auth::BOOTSERVICE_ACCESS | auth::ENHANCED_AUTHENTICATED_ACCESS;

/// A time stamp as an authentication descriptor must carry it: GMT, offset fields zero.
fn stamp(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> [u8; 16] {
    Time {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanosecond: 0,
        time_zone: 0,
        daylight: 0,
    }
    .to_bytes()
}

/// The `CertData` every descriptor test uses unless it is the thing under test. The
/// `EFI_CERT_TYPE_PKCS7_GUID` `CertData` is a DER-encoded PKCS#7 `SignedData`; this crate
/// never parses it, so the bytes only have to exist.
fn certificate() -> Vec<u8> {
    vec![0x30, 0x82, 0x01, 0x00]
}

/// Assembles `EFI_VARIABLE_AUTHENTICATION_2 || value` the way `SetVariable` receives it.
fn auth2_payload(time_stamp: &[u8; 16], cert: &[u8], value: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(time_stamp);
    payload.extend_from_slice(&(24u32 + cert.len() as u32).to_le_bytes());
    payload.extend_from_slice(&0x0200u16.to_le_bytes());
    payload.extend_from_slice(&0x0ef1u16.to_le_bytes());
    payload.extend_from_slice(&auth::PKCS7_CERT_TYPE);
    payload.extend_from_slice(cert);
    payload.extend_from_slice(value);
    payload
}

/// Assembles `EFI_VARIABLE_AUTHENTICATION_3 || value`: a 10-byte primary descriptor, the
/// secondary descriptor, an optional `NewCert`, the signing certificate, then the value.
fn auth3_payload(
    kind: Kind3,
    secondary: &[u8],
    cert: &[u8],
    new_cert: &[u8],
    value: &[u8],
) -> Vec<u8> {
    let type_byte = match kind {
        Kind3::TimeStamp => auth::AUTHENTICATION_3_TIMESTAMP_TYPE,
        Kind3::Nonce => auth::AUTHENTICATION_3_NONCE_TYPE,
    };
    let flags = if new_cert.is_empty() {
        0
    } else {
        auth::ENHANCED_AUTH_FLAG_UPDATE_CERT
    };
    let mut certificates = Vec::new();
    for block in [new_cert, cert] {
        if block.is_empty() {
            continue;
        }
        certificates.extend_from_slice(&(24u32 + block.len() as u32).to_le_bytes());
        certificates.extend_from_slice(&0x0200u16.to_le_bytes());
        certificates.extend_from_slice(&0x0ef1u16.to_le_bytes());
        certificates.extend_from_slice(&auth::PKCS7_CERT_TYPE);
        certificates.extend_from_slice(block);
    }

    let mut payload = Vec::new();
    payload.push(1);
    payload.push(type_byte);
    payload.extend_from_slice(&((10 + secondary.len() + certificates.len()) as u32).to_le_bytes());
    payload.extend_from_slice(&flags.to_le_bytes());
    payload.extend_from_slice(secondary);
    payload.extend_from_slice(&certificates);
    payload.extend_from_slice(value);
    payload
}

fn name_units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn wire(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn req<'a>(
    name: &'a [u16],
    stored: Option<Stored<'a>>,
    attributes: u32,
    payload: &'a [u8],
) -> Result<Request<'a>, Error> {
    Request::parse(
        VariableName::Units(name),
        &GUID,
        attributes,
        stored,
        payload,
    )
}

/// The rule outcome of a request that must parse, as an `Option` so `assert_eq!` needs no
/// `PartialEq` on the descriptor types.
fn plan<'a>(
    name: &'a [u16],
    stored: Option<Stored<'a>>,
    attributes: u32,
    payload: &'a [u8],
) -> Option<Plan> {
    req(name, stored, attributes, payload)
        .map(|request| auth::check(&request))
        .ok()
        .and_then(Result::ok)
}

/// The refusal of a request that must parse, or `None` if it was accepted.
fn refusal<'a>(
    name: &'a [u16],
    stored: Option<Stored<'a>>,
    attributes: u32,
    payload: &'a [u8],
) -> Option<Error> {
    req(name, stored, attributes, payload)
        .map(|request| auth::check(&request))
        .err()
        .or_else(|| {
            req(name, stored, attributes, payload)
                .ok()
                .and_then(|request| auth::check(&request).err())
        })
}

fn stored<'a>(attributes: u32, data: &'a [u8], year: u16) -> Stored<'a> {
    Stored {
        attributes,
        data,
        time_stamp: Some(Time::parse(&stamp(year, 1, 1, 0, 0, 0)).unwrap()),
    }
}

/// A sink that records the digest input exactly as a hash would consume it.
#[derive(Default)]
struct Concat {
    bytes: Vec<u8>,
    updates: usize,
}

impl DigestInput for Concat {
    fn update(&mut self, chunk: &[u8]) {
        self.bytes.extend_from_slice(chunk);
        self.updates += 1;
    }
}

/// A test-only verifier: it has no cryptography, and says so by only ever accepting a
/// payload whose certificate is the marker it was built with.
struct TestVerifier {
    marker: Vec<u8>,
}

impl Verifier for TestVerifier {
    fn verify(&self, request: &Request<'_>) -> Result<(), Error> {
        // A real verifier hashes `signing_input` and checks the PKCS#7 signature against
        // the key store. This stand-in checks that the digest input is well formed and
        // that the certificate is the marker it holds.
        let mut digest = vec![0u8; request.signing_input().len()];
        request.signing_input().copy_into(&mut digest)?;
        let certificate = match request.descriptor {
            Descriptor::Authentication2(descriptor) => descriptor.certificate(),
            Descriptor::Authentication3(descriptor) => descriptor.certificate(),
        };
        if certificate == self.marker.as_slice() {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}

/// The policy a consumer that really verifies signatures would write: the key role, then
/// the verifier.
struct TestPolicy {
    verifier: TestVerifier,
}

impl Policy for TestPolicy {
    fn authorize(&self, request: &Request<'_>) -> Result<(), Error> {
        let role = Role::of(request.name, request.guid);
        assert_eq!(role, Role::Private, "the test variable is a private one");
        self.verifier.verify(request)
    }
}

#[test]
fn authentication2_exposes_the_descriptor_and_the_value() {
    let cert = certificate();
    let time_stamp = stamp(2026, 10, 7, 12, 34, 56);
    let payload = auth2_payload(&time_stamp, &cert, b"new value");
    let descriptor = Authentication2::parse(&payload).unwrap();

    assert_eq!(descriptor.time_stamp().year, 2026);
    assert_eq!(descriptor.time_stamp().second, 56);
    assert_eq!(descriptor.time_stamp_bytes(), &time_stamp);
    assert_eq!(descriptor.certificate_type(), auth::PKCS7_CERT_TYPE);
    assert_eq!(descriptor.certificate(), cert.as_slice());
    assert_eq!(
        descriptor.len(),
        44,
        "16 + dwLength, the CertData being 4 bytes"
    );
    assert!(!descriptor.is_empty());
    assert_eq!(descriptor.value(&payload), b"new value");
    assert_eq!(Authentication2::HEADER, 40);

    // A descriptor with no value is the authenticated delete form.
    let empty = auth2_payload(&time_stamp, &cert, b"");
    assert_eq!(Authentication2::parse(&empty).unwrap().value(&empty), b"");
}

#[test]
fn authentication2_refuses_malformed_descriptors_before_the_value() {
    let cert = certificate();
    let good = auth2_payload(&stamp(2026, 10, 7, 0, 0, 0), &cert, b"value");

    // Truncated payloads: shorter than the time stamp, and shorter than dwLength claims.
    assert_eq!(
        Authentication2::parse(&good[..15]).err(),
        Some(Error::Truncated)
    );
    assert_eq!(
        Authentication2::parse(&good[..30]).err(),
        Some(Error::Truncated),
        "dwLength must be bounded by the slice"
    );

    // dwLength smaller than the certificate header, and one that cannot be a length.
    let mut short = good.clone();
    short[16..20].copy_from_slice(&23u32.to_le_bytes());
    assert_eq!(Authentication2::parse(&short).err(), Some(Error::Length));
    let mut huge = good.clone();
    huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        Authentication2::parse(&huge),
        Err(Error::Truncated) | Err(Error::Length)
    ));

    // An empty CertData is not a signature.
    let mut empty_cert = good.clone();
    empty_cert[16..20].copy_from_slice(&24u32.to_le_bytes());
    empty_cert.truncate(40);
    assert_eq!(
        Authentication2::parse(&empty_cert).err(),
        Some(Error::Length)
    );

    // Revision, certificate type and CertType.
    let mut revision = good.clone();
    revision[20..22].copy_from_slice(&0x0100u16.to_le_bytes());
    assert_eq!(
        Authentication2::parse(&revision).err(),
        Some(Error::Invalid)
    );
    let mut win_type = good.clone();
    win_type[22..24].copy_from_slice(&0x0ef0u16.to_le_bytes());
    assert_eq!(
        Authentication2::parse(&win_type).err(),
        Some(Error::CertificateType)
    );
    let mut cert_type = good.clone();
    cert_type[24..40].copy_from_slice(&[0x11; 16]);
    assert_eq!(
        Authentication2::parse(&cert_type).err(),
        Some(Error::CertificateType)
    );
}

#[test]
fn authentication2_refuses_a_time_stamp_that_is_not_gmt() {
    let cert = certificate();
    for (offset, byte) in [
        (7u8, 1u8), // Pad1
        (9, 1),     // Nanosecond
        (12, 1),    // TimeZone
        (14, 1),    // Daylight
        (15, 1),    // Pad2
        (2, 13),    // Month 13
        (3, 32),    // Day 32
        (4, 24),    // Hour 24
        (5, 60),    // Minute 60
        (6, 60),    // Second 60
    ] {
        let mut time_stamp = stamp(2026, 10, 7, 12, 0, 0);
        time_stamp[usize::from(offset)] = byte;
        let payload = auth2_payload(&time_stamp, &cert, b"value");
        assert_eq!(
            Authentication2::parse(&payload).err(),
            Some(Error::TimeStamp),
            "byte {offset} should be refused"
        );
    }

    // Year 1899 is below the EFI_TIME range.
    let payload = auth2_payload(&stamp(1899, 10, 7, 12, 0, 0), &cert, b"value");
    assert_eq!(
        Authentication2::parse(&payload).err(),
        Some(Error::TimeStamp)
    );

    // The all-zero time is a legal EFI_TIME; only the rule set rejects it, and only
    // without APPEND_WRITE.
    let zero = auth2_payload(&[0u8; 16], &cert, b"value");
    assert!(Authentication2::parse(&zero).is_ok());
}

#[test]
fn signing_input_is_name_guid_attributes_timestamp_value() {
    let units = name_units("LoaderEntryDefault");
    let cert = certificate();
    let time_stamp = stamp(2026, 10, 7, 12, 34, 56);
    let payload = auth2_payload(&time_stamp, &cert, b"linux.conf");
    let request = req(&units, None, AUTH_ATTRIBUTES, &payload).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(&wire(&units));
    expected.extend_from_slice(&GUID);
    expected.extend_from_slice(&AUTH_ATTRIBUTES.to_le_bytes());
    expected.extend_from_slice(&time_stamp);
    expected.extend_from_slice(b"linux.conf");

    let input = request.signing_input();
    assert_eq!(input.len(), expected.len());
    assert_eq!(input.len(), units.len() * 2 + 16 + 4 + 16 + 10);
    assert!(!input.is_empty());
    assert_eq!(input.name(), VariableName::Units(&units));
    assert_eq!(input.guid(), &GUID);
    assert_eq!(input.attributes(), AUTH_ATTRIBUTES);
    assert_eq!(input.value(), b"linux.conf");

    let mut buffer = vec![0u8; input.len()];
    let written = input.copy_into(&mut buffer).unwrap();
    assert_eq!(written, buffer.len());
    assert_eq!(buffer, expected);

    // The streaming form must produce the same bytes, chunk for chunk.
    let mut sink = Concat::default();
    input.feed(&mut sink);
    assert_eq!(sink.bytes, expected);
    assert_eq!(sink.updates, units.len() + 5);

    // The wire form of the name is the same digest input.
    let wire_name = wire(&units);
    let from_bytes = Request::parse(
        VariableName::Bytes(&wire_name),
        &GUID,
        AUTH_ATTRIBUTES,
        None,
        &payload,
    )
    .unwrap();
    let mut other = vec![0u8; from_bytes.signing_input().len()];
    from_bytes.signing_input().copy_into(&mut other).unwrap();
    assert_eq!(other, expected);
}

#[test]
fn signing_input_excludes_the_name_nul_and_bounds_the_caller_buffer() {
    let units = name_units("OneShot");
    let cert = certificate();
    let payload = auth2_payload(&stamp(2026, 1, 1, 0, 0, 0), &cert, b"v");
    let request = req(&units, None, AUTH_ATTRIBUTES, &payload).unwrap();
    let input = request.signing_input();

    // "OneShot" is seven UTF-16 code units: 14 bytes, with no terminator anywhere.
    assert_eq!(input.len(), 14 + 16 + 4 + 16 + 1);
    let mut expected = Vec::new();
    expected.extend_from_slice(&wire(&units));
    expected.extend_from_slice(&GUID);
    expected.extend_from_slice(&AUTH_ATTRIBUTES.to_le_bytes());
    expected.extend_from_slice(&stamp(2026, 1, 1, 0, 0, 0));
    expected.push(b'v');
    assert_eq!(
        &expected[..14],
        &[
            b'O', 0, b'n', 0, b'e', 0, b'S', 0, b'h', 0, b'o', 0, b't', 0
        ]
    );

    let mut buffer = vec![0u8; input.len()];
    input.copy_into(&mut buffer).unwrap();
    assert_eq!(buffer, expected);

    // A short buffer is refused and left untouched.
    let mut small = [0x5au8; 8];
    assert_eq!(input.copy_into(&mut small).err(), Some(Error::Truncated));
    assert_eq!(small, [0x5au8; 8]);
}

#[test]
fn variable_name_forms_agree() {
    let units = name_units("dbx");
    let bytes = wire(&units);
    let from_units = VariableName::Units(&units);
    let from_bytes = VariableName::Bytes(&bytes);

    assert_eq!(from_units, from_bytes);
    assert_eq!(from_units.units_len(), 3);
    assert_eq!(from_units.len(), 6);
    assert!(!from_units.is_empty());
    assert!(from_units.ascii_eq("dbx"));
    assert!(!from_units.ascii_eq("DBX"), "names are case-sensitive");
    assert!(!from_units.ascii_eq("db"), "names compare in full");
    assert_eq!(from_bytes.units().collect::<Vec<_>>(), units);

    let mut out = [0u8; 6];
    assert_eq!(from_units.write_bytes(&mut out).unwrap(), 6);
    assert_eq!(out, bytes.as_slice());
    let mut small = [0u8; 5];
    assert_eq!(
        from_units.write_bytes(&mut small).err(),
        Some(Error::Truncated)
    );
    assert_eq!(small, [0u8; 5]);

    // An odd trailing byte is not a code unit.
    assert_eq!(VariableName::Bytes(&bytes[..5]).units_len(), 2);
    assert!(VariableName::Units(&[]).is_empty());
    assert_eq!(VariableName::from(units.as_slice()), from_units);
}

#[test]
fn check_enforces_time_stamp_monotonicity() {
    let units = name_units("MyOwnVariable");
    let cert = certificate();
    let previous = stored(AUTH_ATTRIBUTES, b"stored", 2026);

    // Strictly later: accepted.
    let later = auth2_payload(&stamp(2026, 10, 8, 0, 0, 0), &cert, b"next");
    assert_eq!(
        plan(&units, Some(previous), AUTH_ATTRIBUTES, &later),
        Some(Plan::Replace)
    );

    // Equal and earlier: a replay, or a signer whose clock went backwards.
    for year in [2026, 2025] {
        let payload = auth2_payload(&stamp(year, 1, 1, 0, 0, 0), &cert, b"next");
        assert_eq!(
            refusal(&units, Some(previous), AUTH_ATTRIBUTES, &payload),
            Some(Error::Stale),
            "year {year}"
        );
    }

    // APPEND_WRITE turns time-stamp verification off, exactly as §8.2.6 step 2 says.
    let older = auth2_payload(&stamp(2025, 1, 1, 0, 0, 0), &cert, b"tail");
    assert_eq!(
        plan(
            &units,
            Some(previous),
            AUTH_ATTRIBUTES | auth::APPEND_WRITE,
            &older
        ),
        Some(Plan::Append)
    );

    // A new variable has nothing to compare against.
    let create = auth2_payload(&stamp(1990, 1, 1, 0, 0, 0), &cert, b"first");
    assert_eq!(
        plan(&units, None, AUTH_ATTRIBUTES, &create),
        Some(Plan::Replace)
    );
}

#[test]
fn check_fails_closed_when_the_stored_time_stamp_is_missing() {
    let units = name_units("MyOwnVariable");
    let cert = certificate();
    let payload = auth2_payload(&stamp(2026, 10, 8, 0, 0, 0), &cert, b"next");
    let without = Stored {
        attributes: AUTH_ATTRIBUTES,
        data: b"stored",
        time_stamp: None,
    };
    assert_eq!(
        refusal(&units, Some(without), AUTH_ATTRIBUTES, &payload),
        Some(Error::MissingTimeStamp)
    );

    // Without a stored variable there is nothing to establish monotonicity against, and
    // the update is a create.
    assert_eq!(
        plan(&units, None, AUTH_ATTRIBUTES, &payload),
        Some(Plan::Replace)
    );
}

#[test]
fn check_applies_the_append_write_and_delete_rules() {
    let units = name_units("MyOwnVariable");
    let cert = certificate();
    let payload = auth2_payload(&stamp(2026, 10, 7, 12, 0, 0), &cert, b"tail");
    let previous = stored(AUTH_ATTRIBUTES, b"head", 2020);

    // APPEND_WRITE with a stored value appends, and skips the time stamp.
    assert_eq!(
        plan(
            &units,
            Some(previous),
            AUTH_ATTRIBUTES | auth::APPEND_WRITE,
            &payload
        ),
        Some(Plan::Append)
    );

    // APPEND_WRITE without a stored value creates.
    assert_eq!(
        plan(&units, None, AUTH_ATTRIBUTES | auth::APPEND_WRITE, &payload),
        Some(Plan::Replace)
    );

    // The append plan composes the stored and submitted data through caller scratch.
    let append = req(
        &units,
        Some(previous),
        AUTH_ATTRIBUTES | auth::APPEND_WRITE,
        &payload,
    )
    .unwrap();
    assert_eq!(append.plan(), Plan::Append);
    let mut out = [0u8; 8];
    assert_eq!(append.stored_with_appended(&mut out).unwrap(), b"headtail");
    let mut tiny = [0u8; 3];
    assert_eq!(
        append.stored_with_appended(&mut tiny).err(),
        Some(Error::Truncated)
    );
    assert_eq!(tiny, [0u8; 3]);

    // An empty value deletes, unless APPEND_WRITE asks for a time-stamp refresh only.
    let empty = auth2_payload(&stamp(2026, 10, 7, 12, 0, 0), &cert, b"");
    assert_eq!(
        plan(&units, Some(previous), AUTH_ATTRIBUTES, &empty),
        Some(Plan::Delete)
    );
    assert_eq!(
        plan(
            &units,
            Some(previous),
            AUTH_ATTRIBUTES | auth::APPEND_WRITE,
            &empty
        ),
        Some(Plan::Append)
    );
}

#[test]
fn check_requires_one_descriptor_and_a_matching_attribute_word() {
    let units = name_units("MyOwnVariable");
    let cert = certificate();
    let payload = auth2_payload(&stamp(2026, 10, 7, 12, 0, 0), &cert, b"value");

    // Neither authentication attribute, both, or the deprecated one.
    for attributes in [
        auth::NON_VOLATILE | auth::BOOTSERVICE_ACCESS | auth::RUNTIME_ACCESS,
        AUTH_ATTRIBUTES | auth::ENHANCED_AUTHENTICATED_ACCESS,
        auth::NON_VOLATILE | auth::BOOTSERVICE_ACCESS | auth::AUTHENTICATED_WRITE_ACCESS,
    ] {
        assert_eq!(
            req(&units, None, attributes, &payload).err(),
            Some(Error::Descriptor),
            "attributes {attributes:#x}"
        );
    }

    // A reserved attribute bit is not a descriptor question.
    assert_eq!(
        req(&units, None, AUTH_ATTRIBUTES | 0x200, &payload).err(),
        Some(Error::Attributes)
    );

    // A descriptor that does not match the attributes: the payload is an AUTH_3 header.
    let time_stamp = stamp(2026, 10, 7, 12, 0, 0);
    let auth3 = auth3_payload(Kind3::TimeStamp, &time_stamp, &cert, &[], b"value");
    assert!(req(&units, None, AUTH_ATTRIBUTES, &auth3).is_err());

    // Stored attributes must match the submitted ones, APPEND_WRITE aside.
    let previous = stored(AUTH_ATTRIBUTES, b"stored", 2020);
    assert_eq!(
        refusal(
            &units,
            Some(previous),
            AUTH_ATTRIBUTES & !auth::RUNTIME_ACCESS,
            &payload
        ),
        Some(Error::AttributeChange)
    );
    assert_eq!(
        plan(&units, Some(previous), AUTH_ATTRIBUTES, &payload),
        Some(Plan::Replace)
    );
}

#[test]
fn check_refuses_the_all_zero_time_without_append_write() {
    let units = name_units("MyOwnVariable");
    let cert = certificate();
    let payload = auth2_payload(&[0u8; 16], &cert, b"value");

    assert_eq!(
        refusal(&units, None, AUTH_ATTRIBUTES, &payload),
        Some(Error::TimeStamp)
    );
    assert_eq!(
        plan(&units, None, AUTH_ATTRIBUTES | auth::APPEND_WRITE, &payload),
        Some(Plan::Replace)
    );
}

#[test]
fn a_test_verifier_accepts_the_matching_certificate_and_refuses_another() {
    let units = name_units("MyOwnVariable");
    let cert = certificate();
    let payload = auth2_payload(&stamp(2026, 10, 7, 12, 0, 0), &cert, b"value");
    let request = req(&units, None, AUTH_ATTRIBUTES, &payload).unwrap();

    let policy = TestPolicy {
        verifier: TestVerifier {
            marker: cert.clone(),
        },
    };
    assert_eq!(auth::check(&request), Ok(Plan::Replace));
    assert_eq!(policy.authorize(&request), Ok(()));

    // The wrong key: the same descriptor shape, a certificate the verifier does not hold.
    let other = vec![0x30, 0x82, 0x02, 0x00];
    let payload = auth2_payload(&stamp(2026, 10, 7, 12, 0, 0), &other, b"value");
    let request = req(&units, None, AUTH_ATTRIBUTES, &payload).unwrap();
    assert_eq!(auth::check(&request), Ok(Plan::Replace));
    assert_eq!(policy.authorize(&request), Err(Error::Signature));
}

#[test]
fn secure_boot_policy_none_publishes_setup_mode_and_refuses() {
    let policy = SecureBootPolicy::None;
    assert_eq!(policy.mode(), Mode::Setup);
    assert_eq!(policy.secure_boot(), 0);
    assert_eq!(policy.setup_mode(), 1);
    assert_eq!(policy.audit_mode(), 0);
    assert_eq!(policy.deployed_mode(), 0);
    for role in [Role::PlatformKey, Role::KeyExchangeKey, Role::Db, Role::Dbx] {
        assert!(!policy.enrolled(role));
        assert_eq!(policy.database(role), None);
    }

    let units = name_units("dbx");
    let cert = certificate();
    let payload = auth2_payload(&stamp(2026, 10, 7, 12, 0, 0), &cert, b"value");
    let request = req(&units, None, AUTH_ATTRIBUTES, &payload).unwrap();
    // The rules pass and the policy still refuses: authorization is not the rule set.
    assert_eq!(auth::check(&request), Ok(Plan::Replace));
    assert_eq!(policy.authorize(&request), Err(Error::Refused));
}

#[test]
fn the_crypto_stub_fails_closed() {
    let units = name_units("MyOwnVariable");
    let cert = certificate();
    let payload = auth2_payload(&stamp(2026, 10, 7, 12, 0, 0), &cert, b"value");
    let request = req(&units, None, AUTH_ATTRIBUTES, &payload).unwrap();
    assert_eq!(
        Pkcs7Verifier.verify(&request),
        Err(Error::Unsupported(Unsupported::Crypto))
    );
}

#[test]
fn roles_follow_the_names_and_guids_of_the_specification() {
    let cases: [(&str, [u8; 16], Role); 9] = [
        ("PK", auth::GLOBAL_VARIABLE_GUID, Role::PlatformKey),
        ("KEK", auth::GLOBAL_VARIABLE_GUID, Role::KeyExchangeKey),
        (
            "OsRecoveryOrder",
            auth::GLOBAL_VARIABLE_GUID,
            Role::OsRecovery,
        ),
        ("db", auth::IMAGE_SECURITY_DATABASE_GUID, Role::Db),
        ("dbx", auth::IMAGE_SECURITY_DATABASE_GUID, Role::Dbx),
        ("dbt", auth::IMAGE_SECURITY_DATABASE_GUID, Role::Dbt),
        ("dbr", auth::IMAGE_SECURITY_DATABASE_GUID, Role::Dbr),
        // The right name under the wrong GUID is private, and so is the right GUID under
        // the wrong name.
        ("PK", GUID, Role::Private),
        ("pk", auth::GLOBAL_VARIABLE_GUID, Role::Private),
    ];
    for (text, guid, role) in cases {
        let units = name_units(text);
        assert_eq!(Role::of(VariableName::Units(&units), &guid), role, "{text}");
    }

    // The wire form of the name gives the same answer as the units form.
    let units = name_units("dbx");
    let bytes = wire(&units);
    assert_eq!(
        Role::of(
            VariableName::Bytes(&bytes),
            &auth::IMAGE_SECURITY_DATABASE_GUID
        ),
        Role::Dbx
    );
}

#[test]
fn modes_follow_the_three_global_variables() {
    assert_eq!(Mode::of(1, 0, 0), Mode::Setup);
    assert_eq!(Mode::of(0, 0, 0), Mode::User);
    assert_eq!(Mode::of(0, 1, 0), Mode::Audit);
    assert_eq!(Mode::of(0, 0, 1), Mode::Deployed);
    assert_eq!(Mode::of(1, 1, 1), Mode::Deployed);
}

#[test]
fn time_orders_by_component_and_round_trips() {
    let earlier = Time::parse(&stamp(2026, 10, 7, 12, 0, 0)).unwrap();
    let later = Time::parse(&stamp(2026, 10, 7, 12, 0, 1)).unwrap();
    let next_day = Time::parse(&stamp(2026, 10, 8, 0, 0, 0)).unwrap();
    assert!(earlier < later);
    assert!(later < next_day);
    assert_eq!(earlier, Time::parse(&earlier.to_bytes()).unwrap());
    assert_eq!(Time::parse(&[0u8; 16]).unwrap(), Time::ZERO);
    assert!(Time::ZERO.is_unspecified());
    assert!(Time::ZERO.is_valid());
    assert!(!earlier.is_unspecified());
    assert!(
        !Time::parse(&stamp(2026, 13, 1, 0, 0, 0))
            .unwrap()
            .is_valid()
    );
    assert_eq!(Time::parse(&[0u8; 8]).err(), Some(Error::Truncated));
}

#[test]
fn authentication3_parses_the_timestamp_form_and_bounds_every_structure() {
    let cert = certificate();
    let time_stamp = stamp(2026, 10, 7, 12, 0, 0);
    let payload = auth3_payload(Kind3::TimeStamp, &time_stamp, &cert, &[], b"value");
    let descriptor = Authentication3::parse(&payload).unwrap();

    assert_eq!(descriptor.version(), 1);
    assert_eq!(descriptor.kind(), Kind3::TimeStamp);
    assert_eq!(descriptor.flags(), 0);
    assert_eq!(descriptor.secondary(), time_stamp.as_slice());
    assert_eq!(
        descriptor.time_stamp().map(Time::to_bytes),
        Some(time_stamp)
    );
    assert_eq!(descriptor.nonce(), None);
    assert_eq!(descriptor.new_certificate(), None);
    assert_eq!(descriptor.certificate(), cert.as_slice());
    assert_eq!(descriptor.value(&payload), b"value");
    assert_eq!(descriptor.len(), descriptor.metadata().len());
    assert_eq!(descriptor.len(), 10 + time_stamp.len() + 24 + cert.len());
    assert!(!descriptor.is_empty());

    // A version other than 1, an unknown type, and a reserved flag bit.
    let mut version = payload.clone();
    version[0] = 2;
    assert_eq!(Authentication3::parse(&version).err(), Some(Error::Invalid));
    let mut kind = payload.clone();
    kind[1] = 3;
    assert_eq!(Authentication3::parse(&kind).err(), Some(Error::Invalid));
    let mut flags = payload.clone();
    flags[6..10].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(Authentication3::parse(&flags).err(), Some(Error::Invalid));

    // MetadataSize below the primary descriptor, and beyond the payload.
    let mut small = payload.clone();
    small[2..6].copy_from_slice(&9u32.to_le_bytes());
    assert_eq!(Authentication3::parse(&small).err(), Some(Error::Length));
    let mut large = payload.clone();
    large[2..6].copy_from_slice(&4096u32.to_le_bytes());
    assert_eq!(Authentication3::parse(&large).err(), Some(Error::Truncated));

    // Trailing bytes inside the metadata are not allowed.
    let mut trailing = payload.clone();
    let metadata_size = u32::from_le_bytes(payload[2..6].try_into().unwrap());
    trailing[2..6].copy_from_slice(&(metadata_size + 4).to_le_bytes());
    assert_eq!(Authentication3::parse(&trailing).err(), Some(Error::Length));

    // Truncated payloads: inside the primary descriptor, and inside the secondary one.
    assert_eq!(
        Authentication3::parse(&payload[..9]).err(),
        Some(Error::Truncated)
    );
    assert_eq!(
        Authentication3::parse(&payload[..20]).err(),
        Some(Error::Truncated)
    );

    // The time stamp of an AUTH_3 descriptor is GMT in the same way.
    let mut pad = time_stamp;
    pad[15] = 1;
    let padded = auth3_payload(Kind3::TimeStamp, &pad, &cert, &[], b"value");
    assert_eq!(
        Authentication3::parse(&padded).err(),
        Some(Error::TimeStamp)
    );

    // A signing certificate that is not PKCS#7: the primary descriptor and the secondary
    // EFI_TIME are 26 bytes, then the WIN_CERTIFICATE header, then CertType.
    let mut auth3 = payload.clone();
    auth3[34..50].copy_from_slice(&[0x22; 16]);
    assert_eq!(
        Authentication3::parse(&auth3).err(),
        Some(Error::CertificateType)
    );
}

#[test]
fn authentication3_parses_the_nonce_form() {
    let cert = certificate();
    let mut secondary = Vec::new();
    secondary.extend_from_slice(&8u32.to_le_bytes());
    secondary.extend_from_slice(b"nonce123");
    let payload = auth3_payload(Kind3::Nonce, &secondary, &cert, &[], b"value");
    let descriptor = Authentication3::parse(&payload).unwrap();
    assert_eq!(descriptor.kind(), Kind3::Nonce);
    assert_eq!(descriptor.nonce(), Some(b"nonce123".as_slice()));
    assert_eq!(descriptor.time_stamp(), None);
    assert_eq!(descriptor.secondary(), secondary.as_slice());

    // A zero nonce size is refused; a nonce that runs past the metadata is truncated.
    let mut zero = secondary.clone();
    zero[..4].copy_from_slice(&0u32.to_le_bytes());
    let payload = auth3_payload(Kind3::Nonce, &zero, &cert, &[], b"value");
    assert_eq!(Authentication3::parse(&payload).err(), Some(Error::Invalid));
    let mut over = secondary.clone();
    over[..4].copy_from_slice(&64u32.to_le_bytes());
    let payload = auth3_payload(Kind3::Nonce, &over, &cert, &[], b"value");
    assert_eq!(
        Authentication3::parse(&payload).err(),
        Some(Error::Truncated)
    );

    // The enhanced descriptor has no APPEND_WRITE semantics.
    let units = name_units("MyOwnVariable");
    let payload = auth3_payload(Kind3::Nonce, &secondary, &cert, &[], b"value");
    assert_eq!(
        plan(&units, None, ENHANCED_ATTRIBUTES, &payload),
        Some(Plan::Replace)
    );
    assert_eq!(
        refusal(
            &units,
            None,
            ENHANCED_ATTRIBUTES | auth::APPEND_WRITE,
            &payload
        ),
        Some(Error::AppendWrite)
    );

    // The nonce form carries no time stamp, so there is no monotonicity rule to satisfy.
    let previous = Stored {
        attributes: ENHANCED_ATTRIBUTES,
        data: b"stored",
        time_stamp: None,
    };
    assert_eq!(
        plan(&units, Some(previous), ENHANCED_ATTRIBUTES, &payload),
        Some(Plan::Replace)
    );
}

#[test]
fn authentication3_signing_input_covers_secondary_value_and_new_certificate() {
    let cert = certificate();
    let new_cert = vec![0x30, 0x82, 0x03, 0x00];
    let time_stamp = stamp(2026, 10, 7, 12, 0, 0);
    let payload = auth3_payload(Kind3::TimeStamp, &time_stamp, &cert, &new_cert, b"value");
    let descriptor = Authentication3::parse(&payload).unwrap();
    assert_eq!(descriptor.flags(), auth::ENHANCED_AUTH_FLAG_UPDATE_CERT);
    assert_eq!(descriptor.new_certificate(), Some(new_cert.as_slice()));

    let units = name_units("MyOwnVariable");
    let request = req(&units, None, ENHANCED_ATTRIBUTES, &payload).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(&wire(&units));
    expected.extend_from_slice(&GUID);
    expected.extend_from_slice(&ENHANCED_ATTRIBUTES.to_le_bytes());
    expected.extend_from_slice(&time_stamp);
    expected.extend_from_slice(b"value");
    expected.extend_from_slice(&new_cert);

    let mut buffer = vec![0u8; request.signing_input().len()];
    assert_eq!(
        request.signing_input().copy_into(&mut buffer).unwrap(),
        expected.len()
    );
    assert_eq!(buffer, expected);

    // A nonce update serializes the *current* nonce after the value, before the NewCert.
    let mut with_nonce = Vec::new();
    with_nonce.extend_from_slice(&wire(&units));
    with_nonce.extend_from_slice(&GUID);
    with_nonce.extend_from_slice(&ENHANCED_ATTRIBUTES.to_le_bytes());
    with_nonce.extend_from_slice(&time_stamp);
    with_nonce.extend_from_slice(b"value");
    with_nonce.extend_from_slice(b"current!");
    with_nonce.extend_from_slice(&new_cert);

    let input = request.signing_input_with_nonce(b"current!");
    let mut buffer = vec![0u8; input.len()];
    assert_eq!(input.copy_into(&mut buffer).unwrap(), with_nonce.len());
    assert_eq!(buffer, with_nonce);
}

#[test]
fn parsing_and_checking_leave_the_payload_untouched() {
    // The parsers and `check` take shared references, so this is structural; the assertion
    // documents the guarantee that a refused write consumes nothing.
    let cert = certificate();
    let payload = auth2_payload(&stamp(2026, 10, 7, 12, 0, 0), &cert, b"value");
    let before = payload.clone();
    let units = name_units("MyOwnVariable");

    let request = req(&units, None, AUTH_ATTRIBUTES, &payload).unwrap();
    assert_eq!(auth::check(&request), Ok(Plan::Replace));
    assert_eq!(
        SecureBootPolicy::None.authorize(&request),
        Err(Error::Refused)
    );
    assert_eq!(payload, before);

    assert!(Authentication2::parse(&payload[..12]).is_err());
    assert_eq!(&payload[..12], &before[..12]);
}
