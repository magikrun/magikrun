//! # Infra Module - Infra-Container Framework
//!
//! The infra-container is the first container in a pod that:
//! - Holds Linux namespaces (network, IPC, UTS) for other containers to join
//! - Runs workplane extensions (WDHT, Raft, mesh networking)
//! - Provides service discovery and self-healing capabilities
//!
//! ## Symmetric Design
//!
//! The infra-container runs **identically** in both native and MicroVM modes.
//! The only difference is the outer environment:
//!
//! ```text
//! Native Mode:                          MicroVM Mode:
//! ─────────────────────────             ─────────────────────────────────────
//!                                       
//! ┌─────────────────────────┐           ┌─────────────────────────────────────┐
//! │ Pod                     │           │ VM                                  │
//! │  ┌───────────────────┐  │           │  vminit (PID 1)                     │
//! │  │ infra-container   │  │           │  │                                  │
//! │  │  ┌─────────────┐  │  │           │  └─► spawns:                        │
//! │  │  │ workplane   │  │  │           │      ┌───────────────────────────┐  │
//! │  │  │ binary      │  │  │           │      │ Pod                       │  │
//! │  │  │ ────────────│  │  │           │      │  ┌───────────────────┐    │  │
//! │  │  │ Infra +     │  │  │           │      │  │ infra-container   │    │  │
//! │  │  │ Extensions  │  │  │           │      │  │  workplane binary │    │  │
//! │  │  └─────────────┘  │  │           │      │  │  (same as native) │    │  │
//! │  └───────────────────┘  │           │      │  └───────────────────┘    │  │
//! │  ┌───────────────────┐  │           │      │  ┌───────────────────┐    │  │
//! │  │ app-container     │  │           │      │  │ app-container     │    │  │
//! │  └───────────────────┘  │           │      │  └───────────────────┘    │  │
//! └─────────────────────────┘           │      └───────────────────────────┘  │
//!                                       └─────────────────────────────────────┘
//! ```
//!
//! ## Extension Model
//!
//! Extensions implement `InfraExtension` and hook into container lifecycle:
//!
//! ```rust,ignore
//! use magikrun::infra::{Infra, InfraExtension, InfraEvent};
//!
//! struct WorkplaneExtension {
//!     wdht_client: WdhtClient,
//!     raft: RaftNode,
//! }
//!
//! #[async_trait]
//! impl InfraExtension for WorkplaneExtension {
//!     fn name(&self) -> &str { "workplane" }
//!
//!     async fn on_start(&mut self, ctx: &InfraContext) -> Result<()> {
//!         self.wdht_client.connect().await?;
//!         self.raft.join_cluster().await?;
//!         Ok(())
//!     }
//!
//!     async fn on_event(&mut self, event: &InfraEvent) -> Result<()> {
//!         match event {
//!             InfraEvent::ContainerStarted { name, .. } => {
//!                 self.wdht_client.register_container(name).await?;
//!             }
//!             _ => {}
//!         }
//!         Ok(())
//!     }
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - Infra-container holds namespaces - app containers join, not create
//! - Extensions run in same process - compile-time only, no plugins
//! - Namespace isolation protects infra from app container compromise

mod extension;

pub use extension::{
    ExtensionError, ExtensionResult, Infra, InfraConfig, InfraContext, InfraError, InfraEvent,
    InfraExtension, InfraResult, MAX_EXTENSION_NAME_LEN, MAX_EXTENSIONS,
};

/// Infra version string.
pub const INFRA_VERSION: &str = env!("CARGO_PKG_VERSION");
