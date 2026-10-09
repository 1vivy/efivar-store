// SPDX-License-Identifier: GPL-2.0-only
//! Compiler-runtime descriptor for a kernel-backed freestanding engine.
//!
//! This crate deliberately defines no helper functions. LLVM-lowered calls
//! must resolve to genuine kernel implementations through ordinary module
//! relocation/import admission. An unavailable helper is a link/admission
//! failure, never a panicking substitute or a successful no-op.
//!
//! Kbuild garbage-collects core's unused code before module admission. Only
//! helpers reachable from the actual EFI engine form the final import set.
#![allow(internal_features)]
#![feature(compiler_builtins)]
#![compiler_builtins]
#![no_builtins]
#![no_std]
