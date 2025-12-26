//! Pod runtime implementations.
//!
//! This module provides concrete implementations of the [`PodRuntime`] trait
//! for different isolation technologies.
//!
//! # Available Runtimes
//!
//! | Runtime | Runtime Class | Platform | Atomicity |
//! |---------|---------------|----------|-----------|
//! | [`NativePodRuntime`] | `pod-containers` | Linux | Emulated (rollback) |
//! | [`MicroVmPodRuntime`] | `pod-microvm` | Linux/macOS | Natural (VM boot) |
//! | [`WasmPodRuntime`] | `pod-wasm` | All | Natural (store) |
//!
//! # Isolation Hierarchy
//!
//! ```text
//! Security    ┌───────────────────────────────────┐
//!    ▲        │  MicroVmPodRuntime                │  VM-level isolation
//!    │        │  (libkrun: KVM/Hypervisor.framework)
//!    │        └───────────────────────────────────┘
//!    │        ┌───────────────────────────────────┐
//!    │        │  NativePodRuntime                 │  Namespace isolation
//!    │        │  (youki: namespaces + cgroups v2) │
//!    │        └───────────────────────────────────┘
//!    │        ┌───────────────────────────────────┐
//!    │        │  WasmPodRuntime                   │  WASM sandbox
//!    │        │  (wasmtime: capability-based)     │
//!    ▼        └───────────────────────────────────┘
//! Performance
//! ```
//!
//! # Atomic Pod Deployment
//!
//! All implementations guarantee atomic pod deployment:
//!
//! - **Success**: Pod is fully running with all containers started
//! - **Failure**: Nothing is created (automatic rollback)
//!
//! There are no intermediate states visible to the caller.

#[cfg(target_os = "linux")]
mod native;
mod wasm;
#[cfg(not(target_os = "windows"))]
mod microvm;

#[cfg(target_os = "linux")]
pub use native::NativePodRuntime;
pub use wasm::WasmPodRuntime;
#[cfg(not(target_os = "windows"))]
pub use microvm::MicroVmPodRuntime;
