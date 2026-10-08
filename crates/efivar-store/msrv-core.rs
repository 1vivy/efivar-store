//! Compile-only root for the modules shared with Rust-for-Linux.
//! rustup run 1.82.0 rustc --edition 2021 --crate-type lib --crate-name core_check crates/efivar-store/msrv-core.rs
#![no_std]
pub type Guid = [u8; 16];
#[path = "src/auth.rs"]
pub mod auth;
#[path = "src/efvs/mod.rs"]
pub mod efvs;
#[path = "src/sha256.rs"]
pub mod sha256;
