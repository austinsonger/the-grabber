//! Async Rust client for Elastic Security: Kibana Detection Engine, Exception
//! Lists, and Cases REST APIs, plus direct Elasticsearch alert queries.
//!
//! # Quick start
//!
//! ```no_run
//! use elastic_rs::ElasticClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = ElasticClient::new(
//!         "https://my-deployment.kb.us-east-1.aws.found.io",
//!         "https://my-deployment.es.us-east-1.aws.found.io",
//!         "id:api_key",
//!     )?;
//!     let rules = client.rules().find_all().await?;
//!     println!("{} detection rules", rules.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::ElasticClient;
pub use error::ElasticError;
