//! Async Rust client for the CrowdStrike Falcon REST API.
//!
//! # Quick start
//!
//! ```no_run
//! use crowdstrike_rs::CrowdStrikeClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = CrowdStrikeClient::new("https://api.crowdstrike.com", "client-id", "client-secret")?;
//!     let hosts = client.hosts().list_all().await?;
//!     println!("{} hosts", hosts.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::CrowdStrikeClient;
pub use error::CrowdStrikeError;
