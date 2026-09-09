//! Async Rust client for the JumpCloud REST API.
//!
//! # Quick start
//!
//! ```no_run
//! use jumpcloud_rs::JumpCloudClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = JumpCloudClient::new(
//!         "https://console.jumpcloud.com",
//!         "your-api-key",
//!         None, // Some("org-id") for MTP/MSP orgs
//!     )?;
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::JumpCloudClient;
pub use error::JumpCloudError;
