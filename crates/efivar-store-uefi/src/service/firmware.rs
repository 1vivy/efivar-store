use crate::variables::{self, Error, Firmware, Variable};
use alloc::{vec, vec::Vec};
use core::{ptr, ptr::NonNull};
use r_efi::efi::{self, Status};

pub(crate) struct Original {
    pub(crate) table: NonNull<efi::RuntimeServices>,
    pub(crate) truncated: bool,
    pub(crate) policy: variables::Policy,
}
impl Original {
    pub(crate) fn services(&self) -> &'static efi::RuntimeServices {
        // SAFETY: this saved firmware-owned runtime table outlives Surfacer.
        unsafe { self.table.as_ref() }
    }
}

pub(crate) fn guid_bytes(guid: &efi::Guid) -> efivar_store::Guid {
    // SAFETY: EFI_GUID is exactly 16 initialized mixed-endian bytes.
    unsafe { ptr::read_unaligned(ptr::from_ref(guid).cast()) }
}
fn guid_value(bytes: &efivar_store::Guid) -> efi::Guid {
    // SAFETY: EFI_GUID permits every 16-byte representation.
    unsafe { ptr::read_unaligned(bytes.as_ptr().cast()) }
}

pub(crate) fn status(error: Error) -> Status {
    match error {
        Error::InvalidParameter => Status::INVALID_PARAMETER,
        Error::Unsupported => Status::UNSUPPORTED,
        Error::NotFound => Status::NOT_FOUND,
        Error::SecurityViolation => Status::SECURITY_VIOLATION,
        Error::WriteProtected => Status::WRITE_PROTECTED,
        Error::BufferTooSmall(_) => Status::BUFFER_TOO_SMALL,
        Error::OutOfResources => Status::OUT_OF_RESOURCES,
        Error::Device => Status::DEVICE_ERROR,
        Error::Corrupt => Status::COMPROMISED_DATA,
    }
}
fn error(status: Status) -> Error {
    if status == Status::NOT_FOUND {
        Error::NotFound
    } else if status == Status::INVALID_PARAMETER {
        Error::InvalidParameter
    } else if status == Status::UNSUPPORTED {
        Error::Unsupported
    } else {
        Error::Device
    }
}

impl Firmware for Original {
    fn get(&mut self, name: &[u16], guid: &efivar_store::Guid) -> Result<Variable, Error> {
        let mut name = name.to_vec();
        name.push(0);
        let mut guid = guid_value(guid);
        let mut attributes = 0;
        let mut size = 0;
        // SAFETY: standard size query; name/GUID/size/attributes are live.
        let result = unsafe {
            (self.services().get_variable)(
                name.as_mut_ptr(),
                &mut guid,
                &mut attributes,
                &mut size,
                ptr::null_mut(),
            )
        };
        if result != Status::BUFFER_TOO_SMALL && result.is_error() {
            return Err(error(result));
        }
        if size > variables::MAX_VALUE {
            return Err(Error::OutOfResources);
        }
        let mut data = vec![0; size];
        // SAFETY: allocation covers the advertised size, all outputs are live.
        let result = unsafe {
            (self.services().get_variable)(
                name.as_mut_ptr(),
                &mut guid,
                &mut attributes,
                &mut size,
                data.as_mut_ptr().cast(),
            )
        };
        if result.is_error() {
            return Err(error(result));
        }
        if size > data.len() {
            return Err(Error::Corrupt);
        }
        data.truncate(size);
        name.pop();
        Ok(Variable {
            name,
            guid: guid_bytes(&guid),
            attributes,
            data,
        })
    }
    fn set(
        &mut self,
        name: &[u16],
        guid: &efivar_store::Guid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        let mut name = name.to_vec();
        name.push(0);
        let mut guid = guid_value(guid);
        // SAFETY: inputs cover their advertised name and data lengths.
        let result = unsafe {
            (self.services().set_variable)(
                name.as_mut_ptr(),
                &mut guid,
                attributes,
                data.len(),
                data.as_ptr().cast_mut().cast(),
            )
        };
        if result.is_error() {
            Err(error(result))
        } else {
            Ok(())
        }
    }
    fn enumerate(&mut self) -> Result<Vec<Variable>, Error> {
        let mut name = vec![0_u16; variables::MAX_NAME];
        let mut guid = guid_value(&[0; 16]);
        let mut values = Vec::new();
        for _ in 0..4096 {
            let (result, size) = loop {
                let mut size = name.len() * 2;
                // SAFETY: name and GUID outputs span their advertised capacity.
                let result = unsafe {
                    (self.services().get_next_variable_name)(
                        &mut size,
                        name.as_mut_ptr(),
                        &mut guid,
                    )
                };
                if result != Status::BUFFER_TOO_SMALL {
                    break (result, size);
                }
                if size > 64 * 1024 {
                    return Err(Error::OutOfResources);
                }
                if size <= name.len() * 2 || !size.is_multiple_of(2) {
                    return Err(Error::Corrupt);
                }
                name.resize(size / 2, 0);
            };
            if result == Status::NOT_FOUND {
                return Ok(values);
            }
            if result.is_error() {
                return Err(error(result));
            }
            if size < 4 || size > name.len() * 2 || size % 2 != 0 || name[size / 2 - 1] != 0 {
                return Err(Error::Corrupt);
            }
            let key = &name[..size / 2 - 1];
            if key.is_empty()
                || key.contains(&0)
                || char::decode_utf16(key.iter().copied()).any(|c| c.is_err())
            {
                return Err(Error::Corrupt);
            }
            if values
                .iter()
                .any(|v: &Variable| v.guid == guid_bytes(&guid) && v.name == key)
            {
                return Err(Error::Corrupt);
            }
            values.push(Variable {
                name: key.to_vec(),
                guid: guid_bytes(&guid),
                attributes: 0,
                data: Vec::new(),
            });
        }
        Err(Error::OutOfResources)
    }

    fn list(&mut self) -> Result<Vec<Variable>, Error> {
        let mut name = [0_u16; variables::MAX_NAME];
        let mut guid = guid_value(&[0; 16]);
        let mut values = Vec::new();
        let mut bytes = 0;
        for _ in 0..256 {
            let mut size = core::mem::size_of_val(&name);
            // SAFETY: bounded live EFI enumeration outputs.
            let result = unsafe {
                (self.services().get_next_variable_name)(&mut size, name.as_mut_ptr(), &mut guid)
            };
            if result == Status::NOT_FOUND {
                return Ok(values);
            }
            if result.is_error()
                || size < 4
                || size > core::mem::size_of_val(&name)
                || size % 2 != 0
                || name[size / 2 - 1] != 0
            {
                self.truncated = true;
                return Ok(values);
            }
            let key = &name[..size / 2 - 1];
            let key_guid = guid_bytes(&guid);
            if matches!((self.policy)(&key_guid), variables::Route::Store { .. }) {
                continue;
            }
            match self.get(key, &key_guid) {
                Ok(v) if v.attributes & variables::RT != 0 => {
                    let length =
                        variables::index::RECORD + (v.name.len() + 1) * 2 + v.data.len() + 7;
                    if bytes + length <= 512 * 1024 {
                        bytes += length;
                        values.push(v);
                    } else {
                        self.truncated = true;
                    }
                }
                Ok(_) | Err(Error::NotFound) => {}
                Err(_) => {
                    self.truncated = true;
                }
            }
        }
        self.truncated = true;
        Ok(values)
    }
    fn truncated(&self) -> bool {
        self.truncated
    }
}
