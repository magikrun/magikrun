//! # magik-oci
//!
//! OCI-compliant container runtime abstraction layer.
//!
//! This crate provides a pure OCI Runtime Spec compliant interface for
//! container operations. It does NOT include pod concepts - those belong
//! in the `magik-pod` crate.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         magik-oci                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  OciRuntime trait (create/start/kill/delete/state)              │
//! │  Bundle builder (OCI runtime bundle from image)                 │
//! │  Registry client (OCI Distribution)                             │
//! │  Blob storage (content-addressed)                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                      Runtime Backends                           │
//! │  ┌──────────┐  ┌───────────┐  ┌──────────┐                     │
//! │  │  youki   │  │ wasmtime  │  │   krun   │                     │
//! │  │ (Linux)  │  │  (WASM)   │  │ (microVM)│                     │
//! │  └──────────┘  └───────────┘  └──────────┘                     │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # OCI Runtime Spec Compliance
//!
//! This crate implements the OCI Runtime Spec lifecycle:
//!
//! ```text
//! create → start → (exec) → kill → delete
//! ```
//!
//! Each container is independent - pod semantics (shared namespaces,
//! pause containers) are handled by the higher-level `magik-pod` crate.

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
pub use platform::{Capability, Platform};
pub use registry::{pull_image, ImageHandle, RegistryClient};
pub use runtime::{
    ContainerState, ContainerStatus, ExecOptions, ExecResult, OciRuntime, Signal,
};
pub use storage::BlobStore;
