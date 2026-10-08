//! UEFI variable-service library linked into a boot application.
//! Boot-time construction uses `alloc`; copied runtime readers do not.
#![no_std]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod service;
pub mod variables;
pub use service::{VariableService, delete_durable, get, installed, set};
pub use variables::{Policy, Route};
