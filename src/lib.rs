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
//! │  │NativeRuntime │  │ WasmtimeRuntime│  │  KrunRuntime │              │
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
//! | NativeRuntime| Namespaces    | Kernel syscalls| Multi-tenant pods     |
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
//! use magikrun::{
//!     ImageService, BundleBuilder, OciContainerConfig,
//!     NativeRuntime, OciRuntime, Platform,
//! };
//!
//! #[tokio::main]
//! async fn main() -> magikrun::Result<()> {
//!     // CRI pattern: separate image service from runtime
//!     let image_service = ImageService::new()?;
//!     let bundle_builder = BundleBuilder::with_storage(image_service.storage().clone())?;
//!
//!     // Step 1: Pull image (CRI ImageService)
//!     let image = image_service.pull("alpine:3.18").await?;
//!
//!     // Step 2: Build bundle from image
//!     let bundle = bundle_builder.build_oci_bundle(&image, &OciContainerConfig {
//!         name: "my-container".to_string(),
//!         command: Some(vec!["/bin/sh".to_string()]),
//!         ..Default::default()
//!     })?;
//!
//!     // Step 3: Create and start container (CRI RuntimeService)
//!     let runtime = NativeRuntime::new();
//!     runtime.create("my-container", bundle.path()).await?;
//!     runtime.start("my-container").await?;
//!
//!     Ok(())
//! }
//! ```

// =============================================================================
// Internal Modules
// =============================================================================

mod bundle;
mod constants;
mod error;
mod platform;
mod registry;
mod runtimes;
mod storage;

// =============================================================================
// Facade Modules
// =============================================================================

/// Image facade - CRI ImageService pattern.
///
/// Provides: `ImageService`, `ImageHandle`, `BundleBuilder`, `Bundle`,
/// `OciContainerConfig`, `Platform`, `Error`, `Result`
pub mod image;

/// Runtime facade - CRI RuntimeService pattern.
///
/// Provides: `OciRuntime`, `ContainerState`, `ContainerStatus`, `Signal`,
/// `NativeRuntime`, `WasmtimeRuntime`, `KrunRuntime`, `WindowsRuntime`,
/// `RuntimeRegistry`, `Error`, `Result`
pub mod runtime;

/// Pod Runtime Interface (PRI) - atomic pod lifecycle.
///
/// Provides pod-first orchestration where pods are the atomic unit,
/// not containers. Unlike CRI's step-by-step model (RunPodSandbox →
/// CreateContainer → StartContainer), PRI deploys pods atomically:
///
/// ```text
/// run_pod(spec) → RUNNING | ERROR (nothing created)
/// ```
///
/// This module provides:
/// - `PodRuntime` trait: Atomic pod lifecycle operations
/// - `PodSpec`, `ContainerSpec`: Pod specification parsing (K8s-compatible)
/// - `PodHandle`, `PodStatus`, `PodPhase`: Runtime state types
/// - Runtime implementations: `NativePodRuntime`, `MicroVmPodRuntime`, `WasmPodRuntime`
///
/// ## Internal: TSI Protocol
///
/// The TSI (Transparent Socket Interface) for MicroVM communication is
/// internal to this module. It provides vsock-based exec/logs operations
/// for containers running inside VMs. Pod lifecycle is handled by vminit
/// reading baked specs - TSI only handles Day-2 operations.
pub mod pod;

/// Infra framework for infrastructure containers/inits.
///
/// Provides the core framework for the `vminit` binary and extensions
/// like workplane. Runs inside pods as the infra-container:
///
/// - **Native mode**: Infra-container holds namespaces for other containers to join
/// - **MicroVM mode**: Same code runs inside VM (vminit spawns containers)
///
/// This module provides:
/// - `Infra`: Core infra-container manager
/// - `InfraConfig`: Infrastructure configuration
/// - `InfraExtension`: Trait for extending infra behavior (implemented by workplane)
/// - `InfraEvent`: Container lifecycle events
/// - `InfraContext`: Context passed to extensions
///
/// ## Symmetric Design
///
/// The same infra-container code runs identically in both native and MicroVM
/// modes. The only difference is the outer environment (host vs VM).
pub mod infra;
