//! Multi-provider abstraction layer.
//!
//! Providers implement common collector trait objects so that the CLI and TUI
//! can drive collection without knowing the underlying cloud API.

#[cfg(feature = "gcp")]
pub mod gcp;
