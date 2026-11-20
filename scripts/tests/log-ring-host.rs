// Host harness: compile the exact no_std-compatible kernel modules without
// installing an IRQ handler, UART sink, or any mutable global kernel state.
#[path = "../../kernel/log_policy.rs"]
mod log_policy;
#[path = "../../kernel/log_ring.rs"]
mod log_ring;
