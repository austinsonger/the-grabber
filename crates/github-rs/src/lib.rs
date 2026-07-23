//! Async Rust client for the GitHub REST API.
//!
//! # Quick start
//!
//! ```no_run
//! use github_rs::GithubClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = GithubClient::new("https://api.github.com", "ghp_...", "my-org")?;
//!     let admins = client.members().list_by_role("admin").await?;
//!     println!("{} admins", admins.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::GithubClient;
pub use error::GithubError;

#[doc(hidden)]
pub use client::next_link as __test_next_link;
