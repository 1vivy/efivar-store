use efivar_store::efvs;
use efivar_store_ffi::*;
use std::{ptr, slice};
const NAME: [u8; 2] = [b'A', 0]; // One UTF-16LE unit, not a C string.

struct Store {
    ctx: Vec<usize>,
    image: Vec<u8>,
    scratch: Vec<u8>,
}
impl Store {
    fn new() -> Self {
        let mut image = vec![0; 16384];
        efvs::initialize_with_block(&mut image, 4096, 512).unwrap();
        let mut s = Self {
            ctx: vec![0; efvs_ctx_size().div_ceil(size_of::<usize>())],
            image,
            scratch: vec![0; 4096],
        };
        assert_eq!(s.load(), 0);
        s
    }
    fn ctx(&mut self) -> *mut u8 {
        self.ctx.as_mut_ptr().cast()
    }
    fn load(&mut self) -> usize {
        // SAFETY: Buffers are disjoint, aligned and live until Store drops.
        unsafe {
            efvs_load(
                self.ctx(),
                self.image.as_mut_ptr(),
                self.image.len(),
                self.scratch.as_mut_ptr(),
                self.scratch.len(),
            )
        }
    }
    fn set(&mut self, attr: u32, value: &[u8]) -> (usize, usize, usize) {
        let (mut start, mut end) = (0, 0);
        // SAFETY: Loaded context with live readable inputs and writable outputs.
        let status = unsafe {
            efvs_set(
                self.ctx(),
                NAME.as_ptr(),
                2,
                &[1; 16],
                attr,
                value.as_ptr(),
                value.len(),
                &mut start,
                &mut end,
            )
        };
        (status, start, end)
    }
    fn get(&mut self) -> (usize, u32, Vec<u8>) {
        let (mut attr, mut data, mut len) = (0, ptr::null(), 0);
        // SAFETY: Loaded context and valid inputs/outputs; returned view copied before mutation.
        let status = unsafe {
            efvs_get(
                self.ctx(),
                NAME.as_ptr(),
                2,
                &[1; 16],
                &mut attr,
                &mut data,
                &mut len,
            )
        };
        let value = if status == 0 {
            // SAFETY: Successful get returns a valid view until mutation.
            unsafe { slice::from_raw_parts(data, len).to_vec() }
        } else {
            vec![]
        };
        (status, attr, value)
    }
}
#[test]
fn roundtrip_append_delete_reload_and_iteration() {
    let mut s = Store::new();
    let before = s.image.clone();
    let (status, start, end) = s.set(7, b"first");
    assert_eq!(status, 0);
    assert_eq!(&before[..start], &s.image[..start]);
    assert_eq!(&before[end..], &s.image[end..]);
    assert_eq!(s.get(), (0, 7, b"first".to_vec()));
    assert_eq!(s.set(7, b"second").0, 0);
    assert_eq!(s.set(7 | efvs::ATTR_APPEND, b"!").0, 0);
    assert_eq!(s.load(), 0);
    assert_eq!(s.get(), (0, 7, b"second!".to_vec()));
    let (mut name, mut len, mut guid) = (ptr::null(), 0, [0; 16]);
    // SAFETY: All buffers are valid, and name is copied before any mutation.
    assert_eq!(
        // SAFETY: Loaded context and live input/output buffers.
        unsafe {
            efvs_next(
                s.ctx(),
                b"".as_ptr(),
                0,
                &[0; 16],
                &mut name,
                &mut len,
                &mut guid,
            )
        },
        0
    );
    // SAFETY: Successful next returns len readable bytes.
    assert_eq!(unsafe { slice::from_raw_parts(name, len) }, b"A\0");
    assert_eq!(guid, [1; 16]);
    assert_eq!(s.set(0, b"").0, 0);
    assert_eq!(s.load(), 0);
    assert_eq!(s.get().0, NOT_FOUND);
}
#[test]
fn policy_query_and_full_errors_do_not_write() {
    let mut s = Store::new();
    let before = s.image.clone();
    assert_eq!(s.set(3, b"x").0, (1usize << 63) | 8);
    assert_eq!(s.set(0x27, b"x").0, (1usize << 63) | 26);
    assert_eq!(s.image, before);
    let (mut cap, mut free, mut largest) = (0, 0, 0);
    // SAFETY: Loaded context and writable outputs.
    assert_eq!(
        // SAFETY: Loaded context and writable u64 outputs.
        unsafe { efvs_query(s.ctx(), 7, &mut cap, &mut free, &mut largest) },
        0
    );
    assert_eq!(cap, free);
    assert_eq!(largest, 4096 - efvs::CHECKPOINT_HEADER_SIZE as u64 - 50);
    loop {
        let before = s.image.clone();
        let status = s.set(7, &[9; 512]).0;
        if status != 0 {
            assert_eq!(status, (1usize << 63) | 9);
            assert_eq!(s.image, before);
            break;
        }
    }
}
#[test]
fn blank_refusal_and_torn_tail() {
    let mut s = Store::new();
    assert_eq!(s.set(7, b"first").0, 0);
    let (_, start, end) = s.set(7, b"second");
    s.image[end - 16..].fill(0);
    assert!(start < end);
    assert_eq!(s.load(), 0);
    assert_eq!(s.get(), (0, 7, b"first".to_vec()));
    let before = s.image.clone();
    assert_eq!(s.set(7, b"no").0, DEVICE);
    assert_eq!(s.image, before);
    s.image.fill(0);
    let before = s.image.clone();
    assert_ne!(s.load(), 0);
    assert_eq!(s.image, before);
}
