//! Async Rust client for the Atlassian Jira Cloud REST API v3.
//!
//! Scope: projects and issues only.
//!
//! # Quick start
//!
//! ```no_run
//! use jira_rs::JiraClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = JiraClient::new(
//!         "https://acme.atlassian.net",
//!         "user@acme.com",
//!         "ATATT...",
//!     )?;
//!     let projects = client.projects().list_all().await?;
//!     println!("{} projects", projects.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::JiraClient;
pub use error::JiraError;
