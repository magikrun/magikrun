//! # TSI (Transparent Socket Interface) Module
//!
//! Provides vsock-based communication between the host pod runtime
//! and vminit running inside MicroVMs.
//!
//! ## Overview
//!
//! TSI enables Day-2 operations for containers inside VMs:
//! - **Exec sessions**: Run commands in container namespaces
//! - **Log streaming**: Container log access
//! - **Health checks**: Ping to verify vminit is running
//!
//! Pod lifecycle (create/start/stop/delete) is NOT part of TSI.
//! vminit reads the baked pod spec from the VM rootfs and spawns
//! containers at boot.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Host                                                           │
//! │  ┌─────────────────────┐                                        │
//! │  │  MicroVmPodRuntime  │                                        │
//! │  │  ┌───────────────┐  │                                        │
//! │  │  │  TsiClient    │──┼──┐                                     │
//! │  │  └───────────────┘  │  │ vsock (AF_VSOCK)                    │
//! │  └─────────────────────┘  │ CID:PORT (e.g., 3:1024)             │
//! │                           ▼                                     │
//! │  ┌─────────────────────────────────────────────────────────┐    │
//! │  │  MicroVM (libkrun)                                      │    │
//! │  │  ┌─────────────────────────────────────────────────┐    │    │
//! │  │  │  vminit (PID 1)                                 │    │    │
//! │  │  │  - Spawns containers from /containers/*/        │    │    │
//! │  │  │  - Listens on vsock CID_ANY:1024                │    │    │
//! │  │  │  - Handles: exec, logs, ping                    │    │    │
//! │  │  │  - Reaps zombies, forwards signals              │    │    │
//! │  │  └────────────────────┬────────────────────────────┘    │    │
//! │  │                       │ fork/exec/signal                │    │
//! │  │  ┌────────────────────▼────────────────────────────┐    │    │
//! │  │  │  Container processes                            │    │    │
//! │  │  └─────────────────────────────────────────────────┘    │    │
//! │  └─────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Protocol
//!
//! JSON-over-vsock with newline-delimited messages:
//!
//! ```json
//! // Request
//! {"action":"exec","container":"nginx","command":["sh"]}\n
//!
//! // Response (success)
//! {"status":"ok","data":{"type":"exec_session","session_id":"abc"}}\n
//!
//! // Response (error)
//! {"status":"error","code":"container_not_found","message":"..."}\n
//! ```
//!
//! See [`protocol`] module for all request/response types.
//!
//! ## Security Considerations
//!
//! - Container names are validated (max 63 chars) to prevent injection
//! - Command arguments are bounded in size and count
//! - Timeouts prevent hung connections from blocking
//! - vsock provides VM-level isolation (no network exposure)
//!
//! ## Modules
//!
//! - [`protocol`]: Request/response type definitions (platform-independent)
//! - [`client`]: Host-side async vsock client (Linux/macOS only)
//!
//! ## Status
//!
//! This module defines the TSI protocol and client for MicroVM Day-2 operations.
//! It is currently reserved for `MicroVmPodRuntime` integration. The types are
//! exported for future use when VM-based pod exec/logs are implemented.

// Allow unused items: TSI is infrastructure for MicroVM exec/logs operations.
// The types are defined and validated but MicroVmPodRuntime integration is pending.
// Removing would lose the security-validated protocol; suppressing is appropriate.
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod protocol;

#[cfg(not(target_os = "windows"))]
pub mod client;

// Re-export protocol types (always available)
pub use protocol::{
    ErrorCode, ErrorPayload, ExecRequest, LogsRequest, MAX_COMMAND_ARG_LEN, MAX_COMMAND_ARGS,
    MAX_CONTAINER_NAME_LEN, MAX_TAIL_LINES, OkPayload, Request, Response, ResponseData,
};

// Re-export client types (Linux/macOS only)
#[cfg(not(target_os = "windows"))]
pub use client::{DEFAULT_TIMEOUT, DEFAULT_VSOCK_PORT, TsiClient, TsiError, TsiResult};

/// Vsock CID for the host (CID 2 by convention).
///
/// Used by guest agents to connect back to the host if needed.
pub const VSOCK_CID_HOST: u32 = 2;

/// Vsock CID for any (used by guest to accept from any host).
///
/// When the guest agent binds with `CID_ANY`, it accepts connections
/// from any CID (typically the host at CID 2).
pub const VSOCK_CID_ANY: u32 = u32::MAX;
