//! UEFI authenticated-variable descriptors, the signed-data digest input and the
//! policy/verifier traits a consumer authorizes a write with.
//!
//! Everything in this module is a pure function over caller-owned bytes: no I/O, no
//! allocation and no dependency, so a firmware, bootloader, kernel or host tool can all
//! parse a descriptor and rebuild the exact digest input a signature covers. This module
//! performs **no cryptography and no verification of its own** — it parses descriptors,
//! enforces the rules the specification fixes independently of any key material, and
//! hands the digest input to a [`Verifier`] the consumer supplies.
//!
//! # What is here
//!
//! - [`Authentication2`]: `EFI_VARIABLE_AUTHENTICATION_2`, the descriptor an
//!   `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS` payload begins with (UEFI 2.10
//!   §8.2.3 "Related Definitions", usage in §8.2.6). The section an earlier ticket called
//!   "§8.2.2" is §8.2.6 in UEFI 2.10; §8.2.2 is `GetNextVariableName()`.
//! - [`Authentication3`]: `EFI_VARIABLE_AUTHENTICATION_3`, the extensible descriptor
//!   `EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS` selects (UEFI 2.10 §8.2.5). Parsed for
//!   completeness of the format; nothing in this workspace uses it yet.
//! - [`Request`] plus [`check`]: the whole rule set that does not depend on key material —
//!   descriptor selection, the attribute word, time-stamp monotonicity and the
//!   `APPEND_WRITE` rules — returning the [`Plan`] the caller must execute.
//! - [`SigningInput`]: the byte-exact digest input of §8.2.6 step 2, `VariableName ||
//!   VendorGuid || Attributes || TimeStamp || Data`, with the name's terminating NUL
//!   excluded. [`SigningInput::feed`] streams it into a hash without a buffer;
//!   [`SigningInput::copy_into`] materializes it for tests and host tools.
//! - [`Verifier`], [`Policy`], [`KeyStore`], [`Role`] and [`Mode`]: the traits and the key
//!   roles of UEFI 2.10 §32.3, with [`SecureBootPolicy::None`] as this repository's
//!   official policy and [`Pkcs7Verifier`] as the owner-directed stub.
//!
//! # What is not here
//!
//! - **No cryptographic verifier.** [`Pkcs7Verifier`] is an explicit stub that returns
//!   [`Unsupported::Crypto`]: this crate has no dependencies and therefore cannot hash or
//!   check a PKCS#7 signature. Supplying the real verifier is the consumer's job.
//! - **No rollback anchor and no store write.** Persistence, freshness (the protected
//!   monotonic value) and the write path belong to the consumer: in this workspace, to
//!   the block-backed store design that keeps the raw descriptor and verifies it at load
//!   time. Nothing here touches a byte image.
//! - **No `EFI_VARIABLE_AUTHENTICATION`** (the counter-based, deprecated descriptor):
//!   [`check`] refuses a payload whose attributes select it.
//!
//! # Example
//!
//! ```
//! use efivar_store::auth::{self, Authentication2, Request, VariableName};
//!
//! let mut payload = Vec::new();
//! // EFI_TIME: 2024-01-01 00:00:00, always GMT, so every offset field is zero.
//! payload.extend_from_slice(&[0xe8, 0x07, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
//! payload.extend_from_slice(&25u32.to_le_bytes()); // dwLength: 8 + 16 + 1
//! payload.extend_from_slice(&0x0200u16.to_le_bytes()); // wRevision
//! payload.extend_from_slice(&0x0ef1u16.to_le_bytes()); // wCertificateType: EFI_GUID
//! payload.extend_from_slice(&auth::PKCS7_CERT_TYPE); // CertType
//! payload.push(0x30); // a one-byte CertData, opaque to this module
//! payload.extend_from_slice(b"value"); // the new variable content
//!
//! let descriptor = Authentication2::parse(&payload)?;
//! assert_eq!(descriptor.time_stamp().year, 2024);
//! assert_eq!(descriptor.value(&payload), b"value");
//!
//! let name: Vec<u16> = "LoaderEntryDefault".encode_utf16().collect();
//! let guid = [0x82, 0xb0, 0x67, 0x4a, 0x4c, 0x0a, 0xcf, 0x41, 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f];
//! let request = Request::parse(
//!     VariableName::Units(&name),
//!     &guid,
//!     auth::TIME_BASED_AUTHENTICATED_WRITE_ACCESS | auth::NON_VOLATILE | auth::BOOTSERVICE_ACCESS,
//!     None,
//!     &payload,
//! )?;
//! assert_eq!(request.signing_input().len(), 36 + 16 + 4 + 16 + 5);
//! # Ok::<(), efivar_store::auth::Error>(())
//! ```

use crate::Guid;

/// `EFI_VARIABLE_NON_VOLATILE`: retained across power cycles.
pub const NON_VOLATILE: u32 = 0x0000_0001;
/// `EFI_VARIABLE_BOOTSERVICE_ACCESS`: visible to boot services.
pub const BOOTSERVICE_ACCESS: u32 = 0x0000_0002;
/// `EFI_VARIABLE_RUNTIME_ACCESS`: visible after `ExitBootServices`.
pub const RUNTIME_ACCESS: u32 = 0x0000_0004;
/// `EFI_VARIABLE_HARDWARE_ERROR_RECORD` ("HR").
pub const HARDWARE_ERROR_RECORD: u32 = 0x0000_0008;
/// `EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS`: deprecated counter-based authentication.
pub const AUTHENTICATED_WRITE_ACCESS: u32 = 0x0000_0010;
/// `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS`: selects the
/// [`Authentication2`] descriptor.
pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 0x0000_0020;
/// `EFI_VARIABLE_APPEND_WRITE`: appends the submitted value instead of replacing.
pub const APPEND_WRITE: u32 = 0x0000_0040;
/// `EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS`: selects the [`Authentication3`]
/// descriptor.
pub const ENHANCED_AUTHENTICATED_ACCESS: u32 = 0x0000_0080;
/// The bits that make a variable authenticated: `0x10 | 0x20 | 0x80`. The byte-image
/// engine refuses a write whose attribute word carries any of them.
pub const AUTHENTICATED: u32 = 0x0000_00b0;

/// Every attribute bit UEFI 2.10 §8.2 defines. Bits above these are reserved.
const DEFINED_ATTRIBUTES: u32 = 0x0000_00ff;

/// `WIN_CERT_TYPE_EFI_GUID`, the only `wCertificateType` an authentication descriptor
/// accepts.
pub const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0ef1;
/// `WIN_CERT_REVISION_2_0`, the current `WIN_CERTIFICATE` revision.
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;

/// `EFI_CERT_TYPE_PKCS7_GUID` (`4aafd29d-68df-49ee-8aa9-347d375665a7`) in EFI on-disk
/// byte order: the only `CertType` UEFI 2.10 §8.2 accepts for an authentication
/// descriptor.
pub const PKCS7_CERT_TYPE: Guid = [
    0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7,
];

/// `EFI_IMAGE_SECURITY_DATABASE_GUID` (`d719b2cb-3d3a-4596-a3bc-dad00e67656f`), the vendor
/// GUID of the `db`, `dbx`, `dbt` and `dbr` secure boot databases.
pub const IMAGE_SECURITY_DATABASE_GUID: Guid = [
    0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f,
];

/// `EFI_GLOBAL_VARIABLE` (`8be4df61-93ca-11d2-aa0d-00e098032b8c`), the vendor GUID of `PK`,
/// `KEK` and the other architecturally defined variables.
pub const GLOBAL_VARIABLE_GUID: Guid = [
    0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
];

/// `EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE`: the secondary descriptor is an
/// `EFI_TIME`.
pub const AUTHENTICATION_3_TIMESTAMP_TYPE: u8 = 1;
/// `EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE`: the secondary descriptor is an
/// `EFI_VARIABLE_AUTHENTICATION_3_NONCE`.
pub const AUTHENTICATION_3_NONCE_TYPE: u8 = 2;
/// `EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT`: a `NewCert` structure precedes the
/// signing certificate.
pub const ENHANCED_AUTH_FLAG_UPDATE_CERT: u32 = 0x0000_0001;

/// Bytes of an `EFI_TIME` (`Year` `u16`, `Month`, `Day`, `Hour`, `Minute`, `Second`,
/// `Pad1`, `Nanosecond` `u32`, `TimeZone` `i16`, `Daylight`, `Pad2`).
const TIME_LEN: usize = 16;

/// Bytes of a `WIN_CERTIFICATE_UEFI_GUID` before its `CertData`: the 8-byte
/// `WIN_CERTIFICATE` header and `CertType`.
const WIN_CERTIFICATE_UEFI_GUID_HEADER: usize = 8 + 16;

/// The `EFI_TIME` value the specification reserves for "no time source": every component
/// set to zero, usable only together with `EFI_VARIABLE_APPEND_WRITE` (UEFI 2.10 §8.2.6
/// step 1 note).
pub const UNSPECIFIED_TIME: Time = Time {
    year: 0,
    month: 0,
    day: 0,
    hour: 0,
    minute: 0,
    second: 0,
    nanosecond: 0,
    time_zone: 0,
    daylight: 0,
};

/// Why a descriptor, a rule check or a signature check did not pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A descriptor, payload or caller buffer is shorter than the bytes it must hold.
    Truncated,
    /// A declared length is inconsistent with the bytes present, or a structure does not
    /// end where its own length fields say it does.
    Length,
    /// A field value is outside what the specification allows: an unknown descriptor
    /// version, an unknown type, a reserved flag bit, a certificate revision other than
    /// `0x0200`, an impossible calendar date.
    Invalid,
    /// A time-stamp rule failed: a `Pad`/`Nanosecond`/`TimeZone`/`Daylight` component is
    /// not zero, or the all-zero time is used without `EFI_VARIABLE_APPEND_WRITE`.
    TimeStamp,
    /// `AuthInfo.CertType` is not `EFI_CERT_TYPE_PKCS7_GUID`, or `wCertificateType` is
    /// not `WIN_CERT_TYPE_EFI_GUID`.
    CertificateType,
    /// The attribute word does not select exactly one supported descriptor: both
    /// authentication attributes set, neither set, or the deprecated counter-based
    /// `EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS`.
    Descriptor,
    /// An attribute bit outside the defined set (`0xff`) is set.
    Attributes,
    /// The update would change the attribute word of a variable that already exists,
    /// which the specification forbids.
    AttributeChange,
    /// The stored authenticated variable carries no time stamp, so monotonicity cannot be
    /// established. Fails closed.
    MissingTimeStamp,
    /// The update's time stamp is not later than the one already stored: a replay, or a
    /// signer whose clock went backwards.
    Stale,
    /// `EFI_VARIABLE_APPEND_WRITE` is set where the specification does not allow it.
    AppendWrite,
    /// A [`Verifier`] rejected the signature over the digest input.
    Signature,
    /// A [`Policy`] refuses this write. This is the refusal [`SecureBootPolicy::None`]
    /// returns, and the same refusal the byte-image engine reports as
    /// [`crate::Error::AuthenticatedWrite`].
    Refused,
    /// The requested primitive is not implemented in this build. Owner-directed stub, see
    /// [`Unsupported`].
    Unsupported(Unsupported),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for Error {}

/// The owner-directed stubs of this module.
///
/// This crate is dependency-free, so it implements no cryptography: a caller that needs a
/// real signature check supplies its own [`Verifier`]. Every stub returns
/// [`Error::Unsupported`] rather than pretending to succeed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unsupported {
    /// No hashing and no PKCS#7 signature check: see [`Pkcs7Verifier`].
    Crypto,
}

/// A variable name: UTF-16LE code units without the terminating NUL, in whichever form
/// the caller already holds.
///
/// A firmware that works from `StoreMut` has the units; a store image, a checkpoint or a
/// log record usually has the wire bytes. Both are accepted here so no caller has to
/// allocate or copy to reach the digest input. The wire form is exactly what
/// [`crate::Name::as_bytes`] yields and what this crate's records store.
///
/// Two values are equal when they name the same code-unit sequence, so the units and wire
/// forms of one name compare equal.
#[derive(Clone, Copy, Debug)]
pub enum VariableName<'a> {
    /// UTF-16LE code units.
    Units(&'a [u16]),
    /// UTF-16LE code units in wire byte order, without the terminating NUL. An odd
    /// trailing byte is not a code unit and is ignored.
    Bytes(&'a [u8]),
}

impl PartialEq for VariableName<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.units().eq(other.units())
    }
}

impl Eq for VariableName<'_> {}

impl<'a> VariableName<'a> {
    /// The number of UTF-16 code units.
    pub fn units_len(self) -> usize {
        match self {
            Self::Units(units) => units.len(),
            Self::Bytes(bytes) => bytes.len() / 2,
        }
    }

    /// The name's length in bytes: two per code unit.
    pub fn len(self) -> usize {
        self.units_len() * 2
    }

    /// Whether the name is empty. Never true for a variable that exists: the
    /// specification requires at least one character.
    pub fn is_empty(self) -> bool {
        self.units_len() == 0
    }

    /// The code units, in order.
    pub fn units(self) -> Units<'a> {
        Units {
            name: self,
            index: 0,
        }
    }

    /// Writes the UTF-16LE wire form into `out`, returning its length. `out` must be at
    /// least [`VariableName::len`] bytes or [`Error::Truncated`] is returned and nothing
    /// is written.
    pub fn write_bytes(self, out: &mut [u8]) -> Result<usize, Error> {
        let length = self.len();
        let target = out.get_mut(..length).ok_or(Error::Truncated)?;
        for (index, unit) in self.units().enumerate() {
            target[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
        Ok(length)
    }

    /// Whether the name equals `text`, which must be ASCII. Names are compared exactly
    /// and case-sensitively, as the specification defines them.
    pub fn ascii_eq(self, text: &str) -> bool {
        let mut units = self.units();
        for byte in text.bytes() {
            match units.next() {
                Some(unit) if unit == u16::from(byte) => {}
                _ => return false,
            }
        }
        units.next().is_none()
    }
}

impl<'a> From<&'a [u16]> for VariableName<'a> {
    fn from(units: &'a [u16]) -> Self {
        Self::Units(units)
    }
}

impl<'a> From<&'a [u8]> for VariableName<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self::Bytes(bytes)
    }
}

/// The code units of a [`VariableName`], in order.
#[derive(Clone, Copy, Debug)]
pub struct Units<'a> {
    name: VariableName<'a>,
    index: usize,
}

impl Iterator for Units<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        let unit = match self.name {
            VariableName::Units(units) => units.get(self.index).copied(),
            VariableName::Bytes(bytes) => bytes
                .get(self.index * 2..)
                .and_then(|tail| tail.get(..2))
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
        };
        self.index += usize::from(unit.is_some());
        unit
    }
}

/// An `EFI_TIME` (`UEFI 2.10` §8.3) as used in an authentication descriptor, in a
/// variable's authenticated record header and in a store's checkpoint.
///
/// The on-disk form is 16 bytes: `Year` `u16`, `Month`, `Day`, `Hour`, `Minute`,
/// `Second`, `Pad1`, `Nanosecond` `u32`, `TimeZone` `i16`, `Daylight`, `Pad2`. The pad
/// bytes are not exposed; the descriptor parsers require them to be zero, because an
/// authentication descriptor is always expressed in GMT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Time {
    /// 1900–9999.
    pub year: u16,
    /// 1–12.
    pub month: u8,
    /// 1–31.
    pub day: u8,
    /// 0–23.
    pub hour: u8,
    /// 0–59.
    pub minute: u8,
    /// 0–59.
    pub second: u8,
    /// 0–999,999,999. Always zero in an authentication descriptor.
    pub nanosecond: u32,
    /// Minutes from UTC, −1440–1440, or 2047 for "local time". Always zero in an
    /// authentication descriptor.
    pub time_zone: i16,
    /// 0 or 1. Always zero in an authentication descriptor.
    pub daylight: u8,
}

impl Time {
    /// The "no time source" value: every component zero.
    pub const ZERO: Time = UNSPECIFIED_TIME;

    /// Parses the 16-byte on-disk form. Bounds-checked. The `Pad` bytes are not exposed
    /// here; the descriptor parsers check them against the raw bytes, which they hold.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            year: u16_at(bytes, 0)?,
            month: byte_at(bytes, 2)?,
            day: byte_at(bytes, 3)?,
            hour: byte_at(bytes, 4)?,
            minute: byte_at(bytes, 5)?,
            second: byte_at(bytes, 6)?,
            nanosecond: u32_at(bytes, 8)?,
            time_zone: i16::from_le_bytes(bytes_at::<2>(bytes, 12)?),
            daylight: byte_at(bytes, 14)?,
        })
    }

    /// The 16-byte on-disk form, with both pad bytes zero.
    pub fn to_bytes(self) -> [u8; TIME_LEN] {
        let mut out = [0u8; TIME_LEN];
        out[0..2].copy_from_slice(&self.year.to_le_bytes());
        out[2] = self.month;
        out[3] = self.day;
        out[4] = self.hour;
        out[5] = self.minute;
        out[6] = self.second;
        out[8..12].copy_from_slice(&self.nanosecond.to_le_bytes());
        out[12..14].copy_from_slice(&self.time_zone.to_le_bytes());
        out[14] = self.daylight;
        out
    }

    /// Whether every exposed component is zero: the value §8.2.6 reserves for a platform
    /// with no reliable time source, valid only with `EFI_VARIABLE_APPEND_WRITE`.
    pub fn is_unspecified(self) -> bool {
        self.year == 0
            && self.month == 0
            && self.day == 0
            && self.hour == 0
            && self.minute == 0
            && self.second == 0
            && self.nanosecond == 0
            && self.time_zone == 0
            && self.daylight == 0
    }

    /// Whether the components are within the ranges `EFI_TIME` defines, or the value is
    /// [`Time::ZERO`]. A descriptor carrying anything else is malformed.
    pub fn is_valid(self) -> bool {
        if self.is_unspecified() {
            return true;
        }
        (1900..=9999).contains(&self.year)
            && (1..=12).contains(&self.month)
            && (1..=31).contains(&self.day)
            && self.hour < 24
            && self.minute < 60
            && self.second < 60
            && self.nanosecond < 1_000_000_000
            && (self.time_zone == 2047 || (-1440..=1440).contains(&self.time_zone))
            && self.daylight <= 1
    }

    /// The comparison key: fields in significance order. Authentication descriptors are
    /// always GMT with a zero `Nanosecond`, so comparing the fields is comparing the
    /// instants — the rule edk2's `AuthServiceInternalCompareTimeStamp` implements.
    fn key(self) -> (u16, u8, u8, u8, u8, u8, u32) {
        (
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.nanosecond,
        )
    }
}

impl Ord for Time {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

impl PartialOrd for Time {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A `WIN_CERTIFICATE_UEFI_GUID`: the certificate block the `_2` and `_3` descriptors both
/// carry.
#[derive(Clone, Copy, Debug)]
struct WinCertificate<'a> {
    certificate_type: Guid,
    certificate: &'a [u8],
    length: usize,
}

impl<'a> WinCertificate<'a> {
    /// Parses the certificate at `offset`, returning it; the caller has already validated
    /// every byte before `offset` and knows how many bytes remain.
    fn parse(bytes: &'a [u8], offset: usize) -> Result<Self, Error> {
        let length = usize::try_from(u32_at(bytes, offset)?).map_err(|_| Error::Length)?;
        if length < WIN_CERTIFICATE_UEFI_GUID_HEADER {
            return Err(Error::Length);
        }
        let end = offset.checked_add(length).ok_or(Error::Length)?;
        let block = bytes.get(offset..end).ok_or(Error::Truncated)?;
        if u16_at(block, 4)? != WIN_CERT_REVISION_2_0 {
            return Err(Error::Invalid);
        }
        if u16_at(block, 6)? != WIN_CERT_TYPE_EFI_GUID {
            return Err(Error::CertificateType);
        }
        let certificate_type = bytes_at::<16>(block, 8)?;
        let certificate = &block[WIN_CERTIFICATE_UEFI_GUID_HEADER..];
        if certificate.is_empty() {
            return Err(Error::Length);
        }
        Ok(Self {
            certificate_type,
            certificate,
            length,
        })
    }
}

/// `EFI_VARIABLE_AUTHENTICATION_2`: the descriptor an
/// `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS` payload begins with (UEFI 2.10
/// §8.2.3, §8.2.6).
///
/// Layout: `EFI_TIME` (16 bytes, GMT), then a `WIN_CERTIFICATE_UEFI_GUID` whose
/// `dwLength` counts itself. The descriptor is followed directly by the new variable
/// value; [`Authentication2::value`] returns it. The descriptor is not part of the
/// variable data and is not returned by `GetVariable`.
#[derive(Clone, Copy, Debug)]
pub struct Authentication2<'a> {
    time_stamp_bytes: &'a [u8],
    time_stamp: Time,
    certificate: WinCertificate<'a>,
    length: usize,
}

impl<'a> Authentication2<'a> {
    /// Bytes an `EFI_VARIABLE_AUTHENTICATION_2` needs before its `CertData`.
    pub const HEADER: usize = TIME_LEN + WIN_CERTIFICATE_UEFI_GUID_HEADER;

    /// Parses the descriptor at the start of `payload` and bounds every field against it.
    ///
    /// Refuses, before any consumer sees the data: a payload too short for the declared
    /// `dwLength`; a `dwLength` smaller than the certificate header; a revision other than
    /// `0x0200`; a `wCertificateType` other than `WIN_CERT_TYPE_EFI_GUID`; a `CertType`
    /// other than `EFI_CERT_TYPE_PKCS7_GUID`; an empty `CertData`; and a time stamp with a
    /// non-zero `Pad1`, `Nanosecond`, `TimeZone`, `Daylight` or `Pad2`, or with components
    /// outside the `EFI_TIME` ranges. This is exactly the gate edk2's
    /// `VerifyTimeBasedPayload` applies before it touches the payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, Error> {
        let time_stamp_bytes = payload.get(..TIME_LEN).ok_or(Error::Truncated)?;
        let time_stamp = Time::parse(time_stamp_bytes)?;
        // Pad1 and Pad2 are not part of `Time`; the raw bytes are checked here.
        if time_stamp_bytes[7] != 0 || time_stamp_bytes[15] != 0 {
            return Err(Error::TimeStamp);
        }
        if time_stamp.nanosecond != 0 || time_stamp.time_zone != 0 || time_stamp.daylight != 0 {
            return Err(Error::TimeStamp);
        }
        if !time_stamp.is_valid() {
            return Err(Error::TimeStamp);
        }
        let certificate = WinCertificate::parse(payload, TIME_LEN)?;
        if certificate.certificate_type != PKCS7_CERT_TYPE {
            return Err(Error::CertificateType);
        }
        Ok(Self {
            time_stamp_bytes,
            time_stamp,
            certificate,
            length: TIME_LEN + certificate.length,
        })
    }

    /// The descriptor's time stamp.
    pub fn time_stamp(self) -> Time {
        self.time_stamp
    }

    /// The descriptor's raw 16-byte `EFI_TIME`, byte for byte as the signature covers it.
    pub fn time_stamp_bytes(self) -> &'a [u8] {
        self.time_stamp_bytes
    }

    /// `AuthInfo.CertType`: always [`PKCS7_CERT_TYPE`] after a successful parse.
    pub fn certificate_type(self) -> Guid {
        self.certificate.certificate_type
    }

    /// `AuthInfo.CertData`: the DER-encoded PKCS#7 `SignedData`. This crate neither parses
    /// nor verifies it, and does not pad-strip it.
    pub fn certificate(self) -> &'a [u8] {
        self.certificate.certificate
    }

    /// Total descriptor bytes: `16 + dwLength`. This is where the new value starts.
    pub fn len(self) -> usize {
        self.length
    }

    /// Whether the descriptor is empty. Never true after a successful parse; present so a
    /// `len` never stands alone.
    pub fn is_empty(self) -> bool {
        self.length == 0
    }

    /// The new variable value: every byte of the payload after the descriptor.
    pub fn value(self, payload: &'a [u8]) -> &'a [u8] {
        &payload[self.length..]
    }
}

/// What immediately follows an [`Authentication3`] primary descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind3 {
    /// `EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE`: an `EFI_TIME`.
    TimeStamp,
    /// `EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE`: an `EFI_VARIABLE_AUTHENTICATION_3_NONCE`.
    Nonce,
}

/// `EFI_VARIABLE_AUTHENTICATION_3`: the extensible descriptor
/// `EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS` selects (UEFI 2.10 §8.2.3, §8.2.5).
///
/// Layout: a 10-byte primary descriptor (`Version`, `Type`, `MetadataSize`, `Flags`), then
/// the type-specific secondary descriptor, then an optional `NewCert` when
/// `Flags & EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT` is set, then the signing
/// certificate, then the new value. `MetadataSize` covers everything but the value.
#[derive(Clone, Copy, Debug)]
pub struct Authentication3<'a> {
    metadata: &'a [u8],
    secondary: &'a [u8],
    kind: Kind3,
    flags: u32,
    time_stamp: Option<Time>,
    nonce: Option<&'a [u8]>,
    new_certificate: Option<WinCertificate<'a>>,
    signing_certificate: WinCertificate<'a>,
}

impl<'a> Authentication3<'a> {
    /// Bytes of the primary descriptor, before the secondary descriptor.
    pub const HEADER: usize = 10;

    /// Parses the descriptor at the start of `payload` and bounds every structure against
    /// `MetadataSize` and against the payload.
    ///
    /// Refuses a version other than 1; a `Type` other than `TIMESTAMP_TYPE` or
    /// `NONCE_TYPE`; any reserved `Flags` bit; a `MetadataSize` smaller than the primary
    /// descriptor or larger than the payload; a truncated secondary descriptor; a
    /// zero-length nonce; a missing signing certificate; trailing bytes inside
    /// `MetadataSize` after the signing certificate; a non-zero `EFI_TIME` pad or offset
    /// component; and a certificate that is not `WIN_CERT_TYPE_EFI_GUID` with
    /// `EFI_CERT_TYPE_PKCS7_GUID`.
    pub fn parse(payload: &'a [u8]) -> Result<Self, Error> {
        let header = payload.get(..Self::HEADER).ok_or(Error::Truncated)?;
        if header[0] != 1 {
            return Err(Error::Invalid);
        }
        let kind = match header[1] {
            AUTHENTICATION_3_TIMESTAMP_TYPE => Kind3::TimeStamp,
            AUTHENTICATION_3_NONCE_TYPE => Kind3::Nonce,
            _ => return Err(Error::Invalid),
        };
        let metadata_size = usize::try_from(u32_at(header, 2)?).map_err(|_| Error::Length)?;
        let flags = u32_at(header, 6)?;
        if flags & !ENHANCED_AUTH_FLAG_UPDATE_CERT != 0 {
            return Err(Error::Invalid);
        }
        if metadata_size < Self::HEADER {
            return Err(Error::Length);
        }
        let metadata = payload.get(..metadata_size).ok_or(Error::Truncated)?;
        let rest = &metadata[Self::HEADER..];

        let (secondary_len, time_stamp, nonce) = match kind {
            Kind3::TimeStamp => {
                let secondary = rest.get(..TIME_LEN).ok_or(Error::Truncated)?;
                if secondary[7] != 0 || secondary[15] != 0 {
                    return Err(Error::TimeStamp);
                }
                let time = Time::parse(secondary)?;
                if time.nanosecond != 0 || time.time_zone != 0 || time.daylight != 0 {
                    return Err(Error::TimeStamp);
                }
                if !time.is_valid() {
                    return Err(Error::TimeStamp);
                }
                (TIME_LEN, Some(time), None)
            }
            Kind3::Nonce => {
                let size = usize::try_from(u32_at(rest, 0)?).map_err(|_| Error::Length)?;
                if size == 0 {
                    return Err(Error::Invalid);
                }
                let nonce = rest.get(4..4 + size).ok_or(Error::Truncated)?;
                (4 + size, None, Some(nonce))
            }
        };

        let mut offset = secondary_len;
        let new_certificate = if flags & ENHANCED_AUTH_FLAG_UPDATE_CERT != 0 {
            let certificate = WinCertificate::parse(rest, offset)?;
            if certificate.certificate_type != PKCS7_CERT_TYPE {
                return Err(Error::CertificateType);
            }
            offset += certificate.length;
            Some(certificate)
        } else {
            None
        };
        let signing_certificate = WinCertificate::parse(rest, offset)?;
        if signing_certificate.certificate_type != PKCS7_CERT_TYPE {
            return Err(Error::CertificateType);
        }
        offset += signing_certificate.length;
        if offset != rest.len() {
            return Err(Error::Length);
        }

        Ok(Self {
            metadata,
            secondary: &rest[..secondary_len],
            kind,
            flags,
            time_stamp,
            nonce,
            new_certificate,
            signing_certificate,
        })
    }

    /// The primary descriptor's `Version`; always 1 after a successful parse.
    pub fn version(self) -> u8 {
        1
    }

    /// The primary descriptor's `Type`.
    pub fn kind(self) -> Kind3 {
        self.kind
    }

    /// The primary descriptor's `Flags`.
    pub fn flags(self) -> u32 {
        self.flags
    }

    /// Every metadata byte: the primary descriptor, the secondary descriptor and both
    /// certificates. `MetadataSize` bytes.
    pub fn metadata(self) -> &'a [u8] {
        self.metadata
    }

    /// The secondary descriptor: an `EFI_TIME` for [`Kind3::TimeStamp`], an
    /// `EFI_VARIABLE_AUTHENTICATION_3_NONCE` (`NonceSize` then the nonce) for
    /// [`Kind3::Nonce`]. This is the "secondary descriptor" element of the §8.2.5 digest
    /// serialization.
    pub fn secondary(self) -> &'a [u8] {
        self.secondary
    }

    /// The secondary `EFI_TIME`, for [`Kind3::TimeStamp`].
    pub fn time_stamp(self) -> Option<Time> {
        self.time_stamp
    }

    /// The secondary nonce, without its `NonceSize` field, for [`Kind3::Nonce`].
    pub fn nonce(self) -> Option<&'a [u8]> {
        self.nonce
    }

    /// The `NewCert` `CertData` when `Flags` announced it: the certificate to install as
    /// the variable's new authority.
    pub fn new_certificate(self) -> Option<&'a [u8]> {
        self.new_certificate
            .map(|certificate| certificate.certificate)
    }

    /// The signing certificate's `CertData`: the PKCS#7 `SignedData` over the digest input.
    pub fn certificate(self) -> &'a [u8] {
        self.signing_certificate.certificate
    }

    /// `MetadataSize`: the descriptor plus every certificate, excluding the value. This is
    /// where the new value starts.
    pub fn len(self) -> usize {
        self.metadata.len()
    }

    /// Whether the descriptor is empty. Never true after a successful parse.
    pub fn is_empty(self) -> bool {
        self.metadata.is_empty()
    }

    /// The new variable value: every byte of the payload after the metadata.
    pub fn value(self, payload: &'a [u8]) -> &'a [u8] {
        &payload[self.metadata.len()..]
    }
}

/// The descriptor a payload begins with, selected by the attribute word.
#[derive(Clone, Copy, Debug)]
pub enum Descriptor<'a> {
    /// `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS`.
    Authentication2(Authentication2<'a>),
    /// `EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS`.
    Authentication3(Authentication3<'a>),
}

impl Descriptor<'_> {
    /// The time stamp the descriptor carries, when it carries one.
    pub fn time_stamp(self) -> Option<Time> {
        match self {
            Self::Authentication2(descriptor) => Some(descriptor.time_stamp()),
            Self::Authentication3(descriptor) => descriptor.time_stamp(),
        }
    }

    /// The descriptor's length in bytes, which is where the value starts.
    pub fn len(self) -> usize {
        match self {
            Self::Authentication2(descriptor) => descriptor.len(),
            Self::Authentication3(descriptor) => descriptor.len(),
        }
    }

    /// Whether the descriptor is empty. Never true after a successful parse.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// The variable a request updates, as the consumer currently holds it: the store's
/// checkpoint view, or the live variable in a running firmware.
#[derive(Clone, Copy, Debug)]
pub struct Stored<'a> {
    /// The stored attribute word. It never contains `EFI_VARIABLE_APPEND_WRITE`.
    pub attributes: u32,
    /// The stored value.
    pub data: &'a [u8],
    /// The time stamp recorded with a stored authenticated variable. `None` for a store
    /// that did not record one; [`check`] then fails closed.
    pub time_stamp: Option<Time>,
}

/// One authenticated `SetVariable` call: what was submitted, and what is stored.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The variable name, without the terminating NUL.
    pub name: VariableName<'a>,
    /// The vendor GUID in EFI on-disk byte order.
    pub guid: &'a Guid,
    /// The attribute word exactly as submitted, `EFI_VARIABLE_APPEND_WRITE` included.
    pub attributes: u32,
    /// The stored variable, when one exists.
    pub stored: Option<Stored<'a>>,
    /// The parsed authentication descriptor.
    pub descriptor: Descriptor<'a>,
    /// The new variable content: the payload after the descriptor.
    pub value: &'a [u8],
}

impl<'a> Request<'a> {
    /// Parses the descriptor the attribute word selects and splits the value off
    /// `payload`, which is `SetVariable`'s `Data` buffer: descriptor first, new value
    /// after.
    ///
    /// The descriptor must match the attributes: `TIME_BASED…` selects
    /// `EFI_VARIABLE_AUTHENTICATION_2`, `ENHANCED…` selects `_3`; both set, neither set,
    /// or the deprecated `EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS` is
    /// [`Error::Descriptor`]. This is a parse, not an authorization: run [`check`] and a
    /// [`Policy`] next.
    pub fn parse(
        name: VariableName<'a>,
        guid: &'a Guid,
        attributes: u32,
        stored: Option<Stored<'a>>,
        payload: &'a [u8],
    ) -> Result<Self, Error> {
        let descriptor = match selector(attributes)? {
            Selector::Authentication2 => {
                Descriptor::Authentication2(Authentication2::parse(payload)?)
            }
            Selector::Authentication3 => {
                Descriptor::Authentication3(Authentication3::parse(payload)?)
            }
        };
        let value = match descriptor {
            Descriptor::Authentication2(descriptor) => descriptor.value(payload),
            Descriptor::Authentication3(descriptor) => descriptor.value(payload),
        };
        Ok(Self {
            name,
            guid,
            attributes,
            stored,
            descriptor,
            value,
        })
    }

    /// The byte-exact digest input of UEFI 2.10 §8.2.6 step 2. For an
    /// `EFI_VARIABLE_AUTHENTICATION_3` update carrying a nonce, use
    /// [`Request::signing_input_with_nonce`]: the current nonce is serialized after the
    /// value.
    pub fn signing_input(&self) -> SigningInput<'_> {
        self.signing_input_with_nonce(&[])
    }

    /// [`Request::signing_input`], with the variable's *current* nonce serialized after the
    /// value as §8.2.5 step 3.c requires for a `NONCE_TYPE` update. The nonce in the
    /// descriptor is the new one and is not part of the input; a create passes `&[]`.
    pub fn signing_input_with_nonce<'b>(&'b self, current_nonce: &'b [u8]) -> SigningInput<'b> {
        match self.descriptor {
            Descriptor::Authentication2(descriptor) => SigningInput {
                name: self.name,
                guid: self.guid,
                attributes: self.attributes.to_le_bytes(),
                descriptor: descriptor.time_stamp_bytes(),
                value: self.value,
                nonce: current_nonce,
                certificate: None,
            },
            Descriptor::Authentication3(descriptor) => SigningInput {
                name: self.name,
                guid: self.guid,
                attributes: self.attributes.to_le_bytes(),
                descriptor: descriptor.secondary(),
                value: self.value,
                nonce: current_nonce,
                certificate: descriptor.new_certificate(),
            },
        }
    }

    /// What this request would do to the variable if it is authorized.
    pub fn plan(&self) -> Plan {
        plan(self)
    }

    /// The value this request would store if it is authorized: the submitted value, or the
    /// stored value followed by it when the plan appends. The caller performs the
    /// concatenation; this crate allocates nothing.
    pub fn stored_with_appended<'b>(&'b self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        let stored = match self.stored {
            Some(stored) => stored.data,
            None => &[],
        };
        let length = stored.len() + self.value.len();
        let target = out.get_mut(..length).ok_or(Error::Truncated)?;
        let (head, tail) = target.split_at_mut(stored.len());
        head.copy_from_slice(stored);
        tail.copy_from_slice(self.value);
        Ok(target)
    }
}

/// What an authorized request does to the variable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Plan {
    /// The value replaces the stored one (or creates the variable).
    Replace,
    /// The value is appended to the stored one. An empty value refreshes the stored time
    /// stamp without changing the data.
    Append,
    /// The variable is deleted: an authenticated update that carries no value.
    Delete,
}

/// The attribute-selected descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Selector {
    Authentication2,
    Authentication3,
}

/// Which descriptor the attribute word selects, or why it selects nothing valid.
fn selector(attributes: u32) -> Result<Selector, Error> {
    if attributes & !DEFINED_ATTRIBUTES != 0 {
        return Err(Error::Attributes);
    }
    if attributes & AUTHENTICATED_WRITE_ACCESS != 0 {
        return Err(Error::Descriptor);
    }
    let time_based = attributes & TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0;
    let enhanced = attributes & ENHANCED_AUTHENTICATED_ACCESS != 0;
    match (time_based, enhanced) {
        (true, false) => Ok(Selector::Authentication2),
        (false, true) => Ok(Selector::Authentication3),
        _ => Err(Error::Descriptor),
    }
}

/// The plan the attribute word and the stored variable imply, without the checks
/// [`check`] performs.
fn plan(request: &Request<'_>) -> Plan {
    let append = request.attributes & APPEND_WRITE != 0;
    if request.value.is_empty() {
        if append { Plan::Append } else { Plan::Delete }
    } else if append && request.stored.is_some() {
        Plan::Append
    } else {
        Plan::Replace
    }
}

/// Applies every authenticated-variable rule that does not depend on key material and
/// returns what the caller must do next. Pure: reads nothing, writes nothing.
///
/// In order:
///
/// 1. The attribute word must be one of the defined bits, must not select the deprecated
///    counter-based descriptor, and must select the descriptor the payload actually
///    begins with ([`Error::Attributes`], [`Error::Descriptor`]).
/// 2. `EFI_VARIABLE_APPEND_WRITE` with the enhanced descriptor is refused: the
///    specification defines appending for time-based authenticated updates
///    ([`Error::AppendWrite`]).
/// 3. When a variable is stored, the submitted attributes outside
///    `EFI_VARIABLE_APPEND_WRITE` must equal the stored ones — the specification returns
///    `EFI_INVALID_PARAMETER` for any other attribute change
///    ([`Error::AttributeChange`]).
/// 4. A time stamp must satisfy the §8.2.6 rules: strictly later than the stored one
///    unless `EFI_VARIABLE_APPEND_WRITE` is set ([`Error::Stale`]); the all-zero time is
///    usable only with `EFI_VARIABLE_APPEND_WRITE` ([`Error::TimeStamp`]); a stored
///    authenticated variable with no recorded time stamp fails closed
///    ([`Error::MissingTimeStamp`]).
/// 5. The plan: an empty value deletes, `EFI_VARIABLE_APPEND_WRITE` with a stored value
///    appends, everything else replaces.
///
/// This is the rule set a [`Verifier`] and a [`Policy`] decision are applied to, never a
/// substitute for them: `check` decides nothing about who signed anything.
pub fn check(request: &Request<'_>) -> Result<Plan, Error> {
    let selected = selector(request.attributes)?;
    let matches = matches!(
        (selected, request.descriptor),
        (Selector::Authentication2, Descriptor::Authentication2(_))
            | (Selector::Authentication3, Descriptor::Authentication3(_))
    );
    if !matches {
        return Err(Error::Descriptor);
    }
    let append = request.attributes & APPEND_WRITE != 0;
    if append && selected == Selector::Authentication3 {
        return Err(Error::AppendWrite);
    }
    match request.stored {
        Some(stored) if stored.attributes != request.attributes & !APPEND_WRITE => {
            return Err(Error::AttributeChange);
        }
        _ => {}
    }
    let time_stamp = match request.descriptor.time_stamp() {
        Some(time_stamp) => time_stamp,
        None => return Ok(plan(request)),
    };
    if time_stamp.is_unspecified() && !append {
        return Err(Error::TimeStamp);
    }
    if append {
        // §8.2.6 step 2: the time stamp is verified only without APPEND_WRITE, so an
        // appending update is not compared against the stored one at all.
        return Ok(plan(request));
    }
    let previous = match request.stored {
        Some(stored) => stored.time_stamp.ok_or(Error::MissingTimeStamp)?,
        None => return Ok(plan(request)),
    };
    if time_stamp <= previous {
        return Err(Error::Stale);
    }
    Ok(plan(request))
}

/// The exact digest input a signature covers.
///
/// UEFI 2.10 §8.2.6 step 2 defines it for `EFI_VARIABLE_AUTHENTICATION_2` as
/// `digest = hash (VariableName, VendorGuid, Attributes, TimeStamp,
/// DataNew_variable_content)`, with "The NULL character terminating the VariableName value
/// shall not be included in the hash computation". §8.2.5 step 3 defines the
/// `EFI_VARIABLE_AUTHENTICATION_3` serialization as `VariableName`, `VendorGuid`,
/// `Attributes` and the secondary descriptor, then the new value, then the current nonce
/// of a nonce update, then a `NewCert`. Both are built here, in one shape.
///
/// The input is a stream, not a buffer: [`SigningInput::feed`] pushes it into a hash
/// without allocating, and [`SigningInput::copy_into`] writes it into a caller buffer of
/// [`SigningInput::len`] bytes.
#[derive(Clone, Copy, Debug)]
pub struct SigningInput<'a> {
    name: VariableName<'a>,
    guid: &'a Guid,
    attributes: [u8; 4],
    descriptor: &'a [u8],
    value: &'a [u8],
    nonce: &'a [u8],
    certificate: Option<&'a [u8]>,
}

/// A sink for [`SigningInput::feed`]: a hash, or anything else that consumes bytes.
/// Implementing it for a real SHA-256 is a consumer's job; this crate has no dependency
/// that could.
pub trait DigestInput {
    /// Consumes the next chunk. Chunks are contiguous pieces of the digest input, in
    /// order; the name arrives two bytes at a time because it is stored as UTF-16.
    fn update(&mut self, chunk: &[u8]);
}

impl<'a> SigningInput<'a> {
    /// The name this input covers.
    pub fn name(self) -> VariableName<'a> {
        self.name
    }

    /// The vendor GUID this input covers.
    pub fn guid(self) -> &'a Guid {
        self.guid
    }

    /// The attribute word this input covers, as submitted.
    pub fn attributes(self) -> u32 {
        u32::from_le_bytes(self.attributes)
    }

    /// The value this input covers.
    pub fn value(self) -> &'a [u8] {
        self.value
    }

    /// Total bytes of the digest input.
    pub fn len(self) -> usize {
        self.name.len()
            + self.guid.len()
            + self.attributes.len()
            + self.descriptor.len()
            + self.value.len()
            + self.nonce.len()
            + self.certificate.map_or(0, <[u8]>::len)
    }

    /// Whether the digest input is empty. Never true: the vendor GUID and the attributes
    /// are always present.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Feeds the whole digest input to `digest`, in order, without a buffer.
    pub fn feed(self, digest: &mut impl DigestInput) {
        for unit in self.name.units() {
            digest.update(&unit.to_le_bytes());
        }
        digest.update(self.guid);
        digest.update(&self.attributes);
        digest.update(self.descriptor);
        digest.update(self.value);
        digest.update(self.nonce);
        if let Some(certificate) = self.certificate {
            digest.update(certificate);
        }
    }

    /// Copies the whole digest input into `out`, returning its length. `out` must be at
    /// least [`SigningInput::len`] bytes or [`Error::Truncated`] is returned and nothing
    /// is written.
    pub fn copy_into(self, out: &mut [u8]) -> Result<usize, Error> {
        // The whole length is checked before the first byte, so a refused copy cannot
        // leave a partial digest input behind.
        if out.len() < self.len() {
            return Err(Error::Truncated);
        }
        let mut offset = 0;
        for unit in self.name.units() {
            append(out, &mut offset, &unit.to_le_bytes())?;
        }
        append(out, &mut offset, self.guid)?;
        append(out, &mut offset, &self.attributes)?;
        append(out, &mut offset, self.descriptor)?;
        append(out, &mut offset, self.value)?;
        append(out, &mut offset, self.nonce)?;
        if let Some(certificate) = self.certificate {
            append(out, &mut offset, certificate)?;
        }
        Ok(offset)
    }
}

/// Appends `chunk` at `*offset`, refusing to write past the buffer.
fn append(out: &mut [u8], offset: &mut usize, chunk: &[u8]) -> Result<(), Error> {
    let end = offset.checked_add(chunk.len()).ok_or(Error::Truncated)?;
    let target = out.get_mut(*offset..end).ok_or(Error::Truncated)?;
    target.copy_from_slice(chunk);
    *offset = end;
    Ok(())
}

/// The secure boot role of a variable: which key database authorizes it (UEFI 2.10 §32.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// `PK` under [`GLOBAL_VARIABLE_GUID`]: the platform key, root of the hierarchy.
    PlatformKey,
    /// `KEK`: the key exchange key database.
    KeyExchangeKey,
    /// `db`: the authorized image signature database.
    Db,
    /// `dbx`: the forbidden image signature database.
    Dbx,
    /// `dbt`: the timestamp signature database.
    Dbt,
    /// `dbr`: the recovery signature database.
    Dbr,
    /// `OsRecoveryOrder` and the `OsRecovery####` variables.
    OsRecovery,
    /// Any other variable, including device-authentication databases and vendor
    /// variables: the specification's "Private Authenticated Variable".
    Private,
}

impl Role {
    /// The role a `(name, GUID)` pair has, by the names §32.3 defines. Names are matched
    /// exactly and case-sensitively; a name that merely resembles one is
    /// [`Role::Private`].
    pub fn of(name: VariableName<'_>, guid: &Guid) -> Role {
        if *guid == GLOBAL_VARIABLE_GUID {
            if name.ascii_eq("PK") {
                return Role::PlatformKey;
            }
            if name.ascii_eq("KEK") {
                return Role::KeyExchangeKey;
            }
            if name.ascii_eq("OsRecoveryOrder") {
                return Role::OsRecovery;
            }
        } else if *guid == IMAGE_SECURITY_DATABASE_GUID {
            if name.ascii_eq("db") {
                return Role::Db;
            }
            if name.ascii_eq("dbx") {
                return Role::Dbx;
            }
            if name.ascii_eq("dbt") {
                return Role::Dbt;
            }
            if name.ascii_eq("dbr") {
                return Role::Dbr;
            }
        }
        Role::Private
    }
}

/// The mutually exclusive secure boot modes of UEFI 2.10 §32.3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// `SetupMode == 1`, `AuditMode == 0`, `DeployedMode == 0`: no `PK` is enrolled and
    /// secure boot policy variables can be written without a signature.
    Setup,
    /// `SetupMode == 0`, `AuditMode == 0`, `DeployedMode == 0`.
    User,
    /// `DeployedMode == 1`.
    Deployed,
    /// `AuditMode == 1`.
    Audit,
}

impl Mode {
    /// The mode the `SetupMode`, `AuditMode` and `DeployedMode` variable values describe.
    pub fn of(setup_mode: u8, audit_mode: u8, deployed_mode: u8) -> Mode {
        if deployed_mode != 0 {
            Mode::Deployed
        } else if audit_mode != 0 {
            Mode::Audit
        } else if setup_mode != 0 {
            Mode::Setup
        } else {
            Mode::User
        }
    }
}

/// The key state an authorization works from: what is enrolled, and the database bytes
/// themselves.
///
/// Implemented by the consumer, because where keys live is the consumer's business — a
/// compiled-in root set, a checkpoint, a firmware variable, a TPM. This crate ships only
/// [`SecureBootPolicy::None`], which has no keys at all.
pub trait KeyStore {
    /// Whether any signature database is enrolled for `role`.
    fn enrolled(&self, role: Role) -> bool;

    /// The current `EFI_SIGNATURE_LIST` bytes of the variable that backs `role`, when the
    /// store holds it. `None` means "no key material", never "authorized".
    fn database(&self, role: Role) -> Option<&[u8]>;
}

/// Checks the signature a [`Request`] carries, over the bytes [`Request::signing_input`]
/// yields.
///
/// A real implementation needs a hash and a PKCS#7 verifier; this crate has neither, so
/// the only verifier it ships is the [`Pkcs7Verifier`] stub.
pub trait Verifier {
    /// Verifies the request's signature. [`Error::Signature`] means the check ran and
    /// failed; [`Error::Unsupported`] means no check was possible.
    fn verify(&self, request: &Request<'_>) -> Result<(), Error>;
}

/// Decides whether one authenticated update may be applied at all: signature, signer
/// identity, role, mode.
///
/// A policy is the authorization half of a write; [`check`] is the format and rule half,
/// and a caller runs both before touching storage. Implementations must not perform I/O,
/// allocate, or mutate anything: they are called to decide.
pub trait Policy {
    /// Authorizes `request`, or refuses it with an [`Error`]. [`Error::Refused`] is the
    /// ordinary refusal.
    fn authorize(&self, request: &Request<'_>) -> Result<(), Error>;
}

/// This repository's official policy: no Secure Boot, no keys, no authenticated write.
///
/// The platform state this describes is exactly what this workspace ships and documents:
/// Secure Boot is off (`SecureBoot == 0`), the platform is in setup mode (`SetupMode == 1`,
/// `AuditMode == 0`, `DeployedMode == 0`), no `PK`/`KEK`/`db`/`dbx` is enrolled by us, and
/// an authenticated write is refused before a byte is staged — the refusal the byte-image
/// engine already reports as [`crate::Error::AuthenticatedWrite`] when an attribute word
/// carries `0x10`/`0x20`/`0x80`.
///
/// It is a real implementation, not a stub: refusal is the intended behaviour. A consumer
/// that wants authenticated variables enables the deferred-verification container (which
/// keeps the raw descriptor and verifies it at load time) instead of weakening this
/// policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureBootPolicy {
    /// Setup mode, `SecureBoot == 0`, no keys enrolled, authenticated writes refused.
    None,
}

impl SecureBootPolicy {
    /// The secure boot mode this policy reports: always [`Mode::Setup`].
    pub fn mode(self) -> Mode {
        Mode::Setup
    }

    /// The `SecureBoot` variable value this policy publishes: 0.
    pub fn secure_boot(self) -> u8 {
        0
    }

    /// The `SetupMode` variable value this policy publishes: 1.
    pub fn setup_mode(self) -> u8 {
        1
    }

    /// The `AuditMode` variable value this policy publishes: 0.
    pub fn audit_mode(self) -> u8 {
        0
    }

    /// The `DeployedMode` variable value this policy publishes: 0.
    pub fn deployed_mode(self) -> u8 {
        0
    }
}

impl Policy for SecureBootPolicy {
    fn authorize(&self, _request: &Request<'_>) -> Result<(), Error> {
        match self {
            Self::None => Err(Error::Refused),
        }
    }
}

impl KeyStore for SecureBootPolicy {
    fn enrolled(&self, _role: Role) -> bool {
        false
    }

    fn database(&self, _role: Role) -> Option<&[u8]> {
        None
    }
}

/// The owner-directed crypto stub: no hash, no PKCS#7 check.
///
/// This crate is dependency-free, so it cannot verify a signature; a consumer that needs
/// verification (the deferred-verification replay at boot, or a host tool with a PKCS#7
/// library) implements [`Verifier`] itself. The stub returns [`Unsupported::Crypto`] so
/// that a caller which forgot to supply a verifier fails closed instead of accepting an
/// unchecked write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pkcs7Verifier;

impl Verifier for Pkcs7Verifier {
    fn verify(&self, _request: &Request<'_>) -> Result<(), Error> {
        Err(Error::Unsupported(Unsupported::Crypto))
    }
}

fn bytes_at<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], Error> {
    data.get(offset..)
        .and_then(|tail| tail.get(..N))
        .and_then(|span| span.try_into().ok())
        .ok_or(Error::Truncated)
}

fn byte_at(data: &[u8], offset: usize) -> Result<u8, Error> {
    data.get(offset).copied().ok_or(Error::Truncated)
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(bytes_at(data, offset)?))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(bytes_at(data, offset)?))
}
