//! Compile the real allocator and DMA ownership code with external host
//! cases, preserving private allocator invariants and excluding privileged paths.
#![allow(dead_code)]

#[path = "../../kernel/frames.rs"]
mod frames;

#[path = "../../kernel/dma.rs"]
mod dma;
