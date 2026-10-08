//! Compile-only contract for embedding the engine in an edition-2021 kernel crate.
#![no_std]

#[allow(unused_attributes)]
#[path = "../src/lib.rs"]
mod engine;

pub use engine::*;
