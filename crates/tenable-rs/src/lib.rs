//! Async Rust client for the Tenable.io and Tenable.sc REST APIs.
//!
//! # Quick start
//!
//! ```no_run
//! use tenable_rs::TenableClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = TenableClient::tenable_io("access_key", "secret_key")?;
//!     let findings = client.vulns().export_all(None).await?;
//!     println!("{} vulnerabilities", findings.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;
mod export;

pub mod api;
pub mod types;

pub use client::TenableClient;
pub use error::TenableError;
