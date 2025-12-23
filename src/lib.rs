//! # magikrun
//!
//! **OCI-Compliant Container Runtime Abstraction Layer**
//!
//! This crate provides a pure OCI Runtime Spec compliant interface for
//! container operations across heterogeneous isolation backends. It handles
//! single-container operations only - pod semantics (shared namespaces,
//! pause containers) are delegated to the higher-level `magikpod` crate.
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                           magikrun                                  │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────────┐    │
//! │  │                    OciRuntime Trait                         │    │
//! │  │    create(id, bundle) → start(id) → kill(id) → delete(id)  │    │
//! │  │                         state(id)                           │    │
//! │  └─────────────────────────────────────────────────────────────┘    │
//! │                              │                                      │
//! │  ┌───────────────────────────┼───────────────────────────────┐      │
//! │  │                   Bundle Building                         │      │
//! │  │  OCI Image → Layers → Rootfs + config.json                │      │
//! │  │  Path traversal protection │ Size limits │ Whiteout files │      │
//! │  └───────────────────────────┼───────────────────────────────┘      │
//! │                              │                                      │
//! │  ┌───────────────────────────┼───────────────────────────────┐      │
//! │  │               Content-Addressed Storage                   │      │
//! │  │  Digest verification │ Deduplication │ Atomic writes      │      │
//! │  └───────────────────────────────────────────────────────────┘      │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                      Runtime Backends                               │
//! │  ┌──────────────┐  ┌───────────────┐  ┌──────────────┐              │
//! │  │ YoukiRuntime │  │ WasmtimeRuntime│  │  KrunRuntime │              │
//! │  │   (Linux)    │  │  (Cross-plat)  │  │   (MicroVM)  │              │
//! │  │  Namespaces  │  │   WASI + Fuel  │  │  KVM / HVF   │              │
//! │  │  Cgroups v2  │  │   256MB limit  │  │   4GB limit  │              │
//! │  └──────────────┘  └───────────────┘  └──────────────┘              │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # OCI Runtime Spec Compliance
//!
//! This crate implements the [OCI Runtime Spec](https://github.com/opencontainers/runtime-spec)
//! container lifecycle:
//!
//! ```text
//!                    ┌──────────────────────────────────────────────┐
//!                    │                                              │
//!                    ▼                                              │
//!   ┌─────────┐   create   ┌─────────┐   start   ┌─────────┐       │
//!   │ (none)  │ ─────────► │ Created │ ────────► │ Running │       │
//!   └─────────┘            └─────────┘           └────┬────┘       │
//!                               │                     │            │
//!                               │ delete              │ kill       │
//!                               │ (if created)        │            │
//!                               ▼                     ▼            │
//!                          ┌─────────┐           ┌─────────┐       │
//!                          │ Deleted │ ◄──────── │ Stopped │ ──────┘
//!                          └─────────┘  delete   └─────────┘
//! ```
//!
//! # Security Model
//!
//! The isolation hierarchy provides defense-in-depth:
//!
//! | Runtime   | Isolation Level | Attack Surface | Use Case              |
//! |-----------|-----------------|----------------|---------------------- |
//! | KrunRuntime | Hardware VM   | Minimal (VMM)  | Untrusted workloads   |
//! | YoukiRuntime| Namespaces    | Kernel syscalls| Multi-tenant pods     |
//! | WasmtimeRuntime | WASM sandbox | WASI only   | Portable plugins      |
//!
//! ## Key Security Properties
//!
//! - **Path Traversal Protection**: All tar extraction validates paths against
//!   `..` components and absolute paths (see [`bundle::extract_layers_to_rootfs`]).
//! - **Size Limits**: Bounded constants prevent resource exhaustion:
//!   - `MAX_LAYER_SIZE`: 512 MiB per layer
//!   - `MAX_ROOTFS_SIZE`: 4 GiB total
//!   - `MAX_WASM_MODULE_SIZE`: 256 MiB
//! - **Digest Verification**: Content-addressed storage verifies SHA-256 before
//!   storing blobs (see [`storage::BlobStore::put_blob`]).
//! - **Fuel Limits**: WASM execution bounded by `DEFAULT_WASM_FUEL` (1B ops).
//! - **Timeouts**: All network operations bounded by `IMAGE_PULL_TIMEOUT` (5 min).
//!
//! # No Pod Semantics
//!
//! This crate intentionally excludes pod-level concepts. Each container is
//! independent. For namespace sharing and pod orchestration, use `magikpod`
//! which builds bundles with namespace paths in `config.json`:
//!
//! ```json
//! {
//!   "linux": {
//!     "namespaces": [
//!       { "type": "pid" },
//!       { "type": "network", "path": "/proc/1234/ns/net" }
//!     ]
//!   }
//! }
//! ```
//!
//! # Feature Flags
//!
//! All runtime backends are compiled unconditionally with runtime availability
//! checks. This ensures consistent API surface across platforms.
//!
//! # Example
//!
//! ```rust,ignore
//! use magikrun::{Platform, RuntimeRegistry, BlobStore, pull_image, BundleBuilder};
//!
//! #[tokio::main]
//! async fn main() -> magikrun::Result<()> {
//!     // Detect platform and available runtimes
//!     let platform = Platform::detect();
//!     let registry = RuntimeRegistry::new(&platform)?;
//!
//!     // Pull image and build bundle
//!     let storage = std::sync::Arc::new(BlobStore::new()?);
//!     let image = pull_image("alpine:3.18", &storage).await?;
//!     let builder = BundleBuilder::new()?;
//!     // ... build and run container
//!     Ok(())
//! }
//! ```

pub mod bundle;
pub mod constants;
pub mod error;
pub mod platform;
pub mod registry;
pub mod runtime;
pub mod storage;

pub mod runtimes;

// Re-exports
pub use bundle::{Bundle, BundleBuilder, BundleFormat};
pub use constants::*;
pub use error::{Error, Result};
pub use platform::{Arch, Capability, Os, Platform};
pub use registry::{ImageHandle, RegistryClient, pull_image};
pub use runtime::{ContainerState, ContainerStatus, ExecOptions, ExecResult, OciRuntime, Signal};
pub use runtimes::{KrunRuntime, RuntimeRegistry, WasmtimeRuntime, WindowsRuntime, YoukiRuntime};
pub use storage::BlobStore;
