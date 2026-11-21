//! Compile the actual allocator snapshot tests as a module, preserving the
//! production module's pub(super) visibility and excluding privileged paths.
#![allow(dead_code)]

#[path = "../../kernel/frames.rs"]
mod frames;
