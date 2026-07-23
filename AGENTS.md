# Agent Instructions & Guidelines

## 🤖 Context
You are working on **The Grabber**, an extensible AWS compliance evidence and inventory collector written in Rust.
It leverages the official AWS Rust SDKs, `tokio` for concurrent asynchronous execution, and `ratatui` for its terminal UI.
Your primary goal is to safely modify, expand, or debug this application while strictly adhering to established project patterns.

## 🚀 Build & Run Commands
- **Check (Fast)**: `cargo check`
- **Build**: `cargo build`
- **Run Development**: `cargo run -- [args]`
- **Linting**: `cargo clippy -- -D warnings` (Resolve all clippy warnings introduced by your changes)
- **Formatting**: `cargo fmt` (Run automatically, do not deviate from `rustfmt`)

## 🧪 Testing Commands
- **Run All Tests**: `cargo test`
- **Run Specific Test**: `cargo test <test_name>`
- **Run Module Tests**: `cargo test <module_name>::`
- **Run With Print Output**: `cargo test <test_name> -- --nocapture`

## 🛠️ Code Style & Conventions

### 1. Architecture & Structure
- Provider-scoped module tree. Every collector lives under `src/providers/<provider>/<service>.rs`, where `<provider>` is one of `aws`, `okta`, `jira`, `tenable`, `elastic`, `azure`, or `gcp`. Each provider has a `factory.rs` (implements `CloudProvider` / `ProviderFactory` from `src/providers/mod.rs`) that registers keys to concrete collectors.
- Cross-cutting orchestration lives under `src/runner/` (collector dispatch, multi-region, output paths). TUI code lives under `src/tui/`. POA&M lives under `src/poam/`. Inventory orchestration lives under `src/inventory_orchestrator/`.
- When you add a new AWS/Okta/Jira/Tenable collector: create `src/providers/<provider>/<name>.rs`, declare it in `src/providers/<provider>/mod.rs`, and register its key in that provider's `factory.rs`. Do **not** touch `main.rs` — new provider modules do not need to be declared there.
- When you add a new top-level provider: create `src/providers/<provider>/`, add it to `src/providers/mod.rs`, implement `ProviderFactory` in its `factory.rs`, and (if it should be feature-gated) wire the Cargo feature in the root `Cargo.toml`.

### 2. Error Handling (Strict Requirement)
- **Always** use the `anyhow` crate for error handling: `anyhow::Result`, `anyhow::Context`.
- **Never** use `unwrap()` or `expect()` in production code. Propagate errors elegantly using `?` and add meaningful context using `.context("Failed to retrieve [Resource]")?`.
- For early exits due to invalid state, use `anyhow::bail!("Clear error message")`.

### 3. Async & Concurrency
- `tokio` is the async runtime. 
- Avoid blocking the async executor. If you must perform CPU-bound/blocking IO work (like heavy ZIP compression or parsing), wrap it in `tokio::task::spawn_blocking`.
- When fetching bulk data from AWS, leverage concurrent streams where appropriate, but respect AWS API rate limits.

### 4. AWS SDK Usage
- Use the official `aws-sdk-*` and `aws-config` crates. Do not reinvent wrappers.
- Inject `&aws_config::SdkConfig` into collector functions rather than building clients internally whenever possible.
- **Pagination**: When querying AWS endpoints that return lists, you must handle pagination. Use the AWS SDK's built-in paginators (`.into_paginator().items().send()`).

### 5. Formatting & Imports
- **Imports Grouping**:
  1. Standard library (`std::*`)
  2. External dependencies (`anyhow`, `aws_sdk_*`, `tokio`, etc.)
  3. Internal crate modules (`crate::*`)
- Leave a blank line between each import group.

### 6. Structs & Serialization
- Ensure data structures that represent AWS resources or configuration state derive standard traits: `#[derive(Debug, Clone, Serialize, Deserialize)]`.
- Use `serde_json` for JSON operations and `csv` for CSV output operations.

### 7. Documentation
- Use module-level documentation (`//!`) at the top of new files to describe the module's scope and design.
- Use doc comments (`///`) for public functions and complex logic. Focus on the *why*, not just the *what*.

## 🎯 Agent Working Protocol
1. **Read Before You Write**: Use `read` and `glob` to examine adjacent modules. If you're building an `SqsCollector`, look at how `SnsCollector` or `S3Collector` is built first.
2. **Test Your Assumptions**: Run `cargo check` and `cargo test` after modifying code to catch compilation or logic errors locally.
3. **Plan for the TUI**: When writing a plan for new features, changes, or workflows, explicitly consider what needs to be added, updated, or surfaced in the terminal UI under `src/tui/`. Do not treat backend or collector work as complete planning unless the TUI impact has been reviewed.
4. **Paths**: Always use absolute paths when utilizing file system tools. Resolve relative logic against the project root.
5. **No Destructive Reverts**: Do not revert your own changes unless explicitly requested by the user, or if your changes broke the build. Fix forward instead.
