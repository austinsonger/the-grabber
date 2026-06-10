//! Async Rust client for the Okta REST API.
//!
//! # Quick start
//!
//! ```no_run
//! use okta_rs::OktaClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = OktaClient::new("https://acme.okta.com", "00ABC...")?;
//!     let users = client.users().list_all().await?;
//!     println!("{} users", users.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::OktaClient;
pub use error::OktaError;

#[doc(hidden)]
pub use client::next_link as __test_next_link;
