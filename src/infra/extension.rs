//! # Extension Framework for Infra-Container
//!
//! This module provides the extension interface for the infra-container.
//! Extensions hook into container lifecycle events and provide workplane
//! functionality like service discovery, consensus, and mesh networking.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

// ============================================================================
// CONSTANTS (No Magic Numbers)
// ============================================================================

/// Maximum number of extensions that can be registered.
pub const MAX_EXTENSIONS: usize = 16;

/// Maximum length of extension name.
pub const MAX_EXTENSION_NAME_LEN: usize = 64;

/// Default timeout for extension callbacks in seconds.
const EXTENSION_CALLBACK_TIMEOUT_SECS: u64 = 30;

/// Maximum number of containers that can be tracked.
const MAX_TRACKED_CONTAINERS: usize = 256;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Error type for extension operations.
#[derive(Debug, Error)]
pub enum ExtensionError {
    /// Extension with this name already registered.
    #[error("extension '{0}' already registered")]
    AlreadyRegistered(String),

    /// Extension name exceeds maximum length.
    #[error("extension name exceeds max length of {MAX_EXTENSION_NAME_LEN}")]
    NameTooLong,

    /// Too many extensions registered.
    #[error("too many extensions (max: {MAX_EXTENSIONS})")]
    TooManyExtensions,

    /// Extension callback failed.
    #[error("extension '{name}' callback '{callback}' failed: {message}")]
    CallbackFailed {
        name: String,
        callback: String,
        message: String,
    },

    /// Extension callback timed out.
    #[error("extension '{0}' callback timed out")]
    CallbackTimeout(String),

    /// Extension initialization failed.
    #[error("extension '{0}' failed to initialize: {1}")]
    InitializationFailed(String, String),
}

/// Result type for extension operations.
pub type ExtensionResult<T> = Result<T, ExtensionError>;

/// Error type for Infra operations.
#[derive(Debug, Error)]
pub enum InfraError {
    /// Extension error.
    #[error(transparent)]
    Extension(#[from] ExtensionError),

    /// Container not found.
    #[error("container '{0}' not found")]
    ContainerNotFound(String),

    /// Infra already running.
    #[error("infra already running")]
    AlreadyRunning,

    /// Infra not running.
    #[error("infra not running")]
    NotRunning,

    /// Shutdown requested.
    #[error("shutdown requested")]
    ShutdownRequested,

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for Infra operations.
pub type InfraResult<T> = Result<T, InfraError>;

// ============================================================================
// CONFIGURATION
// ============================================================================

/// Configuration for the Infra instance.
#[derive(Debug, Clone)]
pub struct InfraConfig {
    /// Pod unique identifier.
    pub pod_id: String,

    /// Pod name from manifest.
    pub pod_name: String,

    /// Pod namespace.
    pub namespace: String,

    /// Path to pod root (for logs, state).
    pub pod_root: PathBuf,

    /// Extensions to load (statically registered).
    pub extension_names: Vec<String>,
}

impl Default for InfraConfig {
    fn default() -> Self {
        Self {
            pod_id: String::new(),
            pod_name: String::new(),
            namespace: String::new(),
            pod_root: PathBuf::from("/run/magik/pods"),
            extension_names: Vec::new(),
        }
    }
}

// ============================================================================
// LIFECYCLE EVENTS
// ============================================================================

/// Status of a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerStatus {
    /// Container is being created.
    Creating,
    /// Container is created but not started.
    Created,
    /// Container is running.
    Running,
    /// Container is paused.
    Paused,
    /// Container has stopped.
    Stopped,
    /// Container has exited with code.
    Exited(i32),
}

/// Events dispatched to extensions during container lifecycle.
#[derive(Debug, Clone)]
pub enum InfraEvent {
    /// Infra is starting up.
    Starting,

    /// Infra is ready (all extensions initialized).
    Ready,

    /// Container is starting.
    ContainerStarting {
        /// Container name.
        name: String,
        /// Container ID.
        id: String,
    },

    /// Container has started.
    ContainerStarted {
        /// Container name.
        name: String,
        /// Container ID.
        id: String,
        /// Container PID.
        pid: u32,
    },

    /// Container status changed.
    ContainerStatusChanged {
        /// Container name.
        name: String,
        /// Container ID.
        id: String,
        /// Old status.
        old_status: ContainerStatus,
        /// New status.
        new_status: ContainerStatus,
    },

    /// Container has stopped.
    ContainerStopped {
        /// Container name.
        name: String,
        /// Container ID.
        id: String,
        /// Exit code.
        exit_code: i32,
    },

    /// Shutdown signal received.
    ShutdownRequested {
        /// Signal number.
        signal: i32,
    },

    /// Infra is shutting down.
    ShuttingDown,

    /// Custom event from an extension.
    Custom {
        /// Source extension name.
        source: String,
        /// Event type identifier.
        event_type: String,
        /// Event payload (JSON-encoded).
        payload: String,
    },
}

// ============================================================================
// EXTENSION CONTEXT
// ============================================================================

/// Context passed to extension callbacks.
///
/// Provides access to pod information and inter-extension communication.
#[derive(Debug, Clone)]
pub struct InfraContext {
    /// Pod unique identifier.
    pub pod_id: String,

    /// Pod name.
    pub pod_name: String,

    /// Pod namespace.
    pub namespace: String,

    /// Path to pod root.
    pub pod_root: PathBuf,

    /// Current tracked containers (name -> id).
    containers: Arc<RwLock<HashMap<String, String>>>,
}

impl InfraContext {
    /// Create a new context from config.
    fn new(config: &InfraConfig) -> Self {
        Self {
            pod_id: config.pod_id.clone(),
            pod_name: config.pod_name.clone(),
            namespace: config.namespace.clone(),
            pod_root: config.pod_root.clone(),
            containers: Arc::new(RwLock::new(HashMap::with_capacity(16))),
        }
    }

    /// Get list of running container names.
    pub async fn container_names(&self) -> Vec<String> {
        let containers = self.containers.read().await;
        containers.keys().cloned().collect()
    }

    /// Get container ID by name.
    pub async fn container_id(&self, name: &str) -> Option<String> {
        let containers = self.containers.read().await;
        containers.get(name).cloned()
    }

    /// Track a container.
    async fn track_container(&self, name: String, id: String) -> InfraResult<()> {
        let mut containers = self.containers.write().await;
        if containers.len() >= MAX_TRACKED_CONTAINERS {
            return Err(InfraError::Internal(format!(
                "too many tracked containers (max: {MAX_TRACKED_CONTAINERS})"
            )));
        }
        containers.insert(name, id);
        Ok(())
    }

    /// Untrack a container.
    async fn untrack_container(&self, name: &str) {
        let mut containers = self.containers.write().await;
        containers.remove(name);
    }
}

// ============================================================================
// EXTENSION TRAIT
// ============================================================================

/// Extension interface for the infra-container.
///
/// Extensions are registered at compile time and receive lifecycle events.
/// They run in the same process as the infra container.
///
/// # Implementation Notes
///
/// - Extensions MUST be `Send + Sync` for async compatibility.
/// - Callbacks MUST NOT block for extended periods.
/// - Extensions SHOULD use timeouts for any I/O operations.
/// - Extensions MUST handle shutdown gracefully.
#[async_trait]
pub trait InfraExtension: Send + Sync {
    /// Extension name (must be unique, max 64 chars).
    fn name(&self) -> &str;

    /// Called when the infra is starting.
    ///
    /// Extensions should initialize their state here.
    async fn on_start(&mut self, ctx: &InfraContext) -> ExtensionResult<()> {
        let _ = ctx;
        Ok(())
    }

    /// Called when the infra is ready (all extensions started).
    ///
    /// Extensions can start background tasks here.
    async fn on_ready(&mut self, ctx: &InfraContext) -> ExtensionResult<()> {
        let _ = ctx;
        Ok(())
    }

    /// Called for each lifecycle event.
    ///
    /// Extensions should handle events non-blocking.
    async fn on_event(&mut self, event: &InfraEvent, ctx: &InfraContext) -> ExtensionResult<()> {
        let _ = (event, ctx);
        Ok(())
    }

    /// Called when the infra is shutting down.
    ///
    /// Extensions should clean up resources here.
    async fn on_shutdown(&mut self, ctx: &InfraContext) -> ExtensionResult<()> {
        let _ = ctx;
        Ok(())
    }
}

// ============================================================================
// INFRA CORE
// ============================================================================

/// Infra-container core.
///
/// Manages extension lifecycle and dispatches events.
pub struct Infra {
    /// Configuration.
    config: InfraConfig,

    /// Context shared with extensions.
    context: InfraContext,

    /// Registered extensions.
    extensions: Vec<Box<dyn InfraExtension>>,

    /// Running state.
    running: bool,
}

impl Infra {
    /// Create a new Infra instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for this instance.
    ///
    /// # Returns
    ///
    /// A new `Infra` instance (not yet running).
    pub fn new(config: InfraConfig) -> Self {
        let context = InfraContext::new(&config);
        Self {
            config,
            context,
            extensions: Vec::with_capacity(MAX_EXTENSIONS),
            running: false,
        }
    }

    /// Register an extension.
    ///
    /// # Arguments
    ///
    /// * `extension` - Extension to register.
    ///
    /// # Errors
    ///
    /// Returns error if extension name is too long, already registered, or
    /// too many extensions.
    pub fn register<E: InfraExtension + 'static>(&mut self, extension: E) -> ExtensionResult<()> {
        let name = extension.name();

        // Validate name length
        if name.len() > MAX_EXTENSION_NAME_LEN {
            return Err(ExtensionError::NameTooLong);
        }

        // Check for duplicates
        if self.extensions.iter().any(|e| e.name() == name) {
            return Err(ExtensionError::AlreadyRegistered(name.to_string()));
        }

        // Check count limit
        if self.extensions.len() >= MAX_EXTENSIONS {
            return Err(ExtensionError::TooManyExtensions);
        }

        info!(extension = %name, "Registered extension");
        self.extensions.push(Box::new(extension));
        Ok(())
    }

    /// Start the infra and all extensions.
    ///
    /// # Errors
    ///
    /// Returns error if already running or extension initialization fails.
    #[instrument(skip(self), fields(pod_id = %self.config.pod_id))]
    pub async fn start(&mut self) -> InfraResult<()> {
        if self.running {
            return Err(InfraError::AlreadyRunning);
        }

        info!(
            pod_id = %self.config.pod_id,
            pod_name = %self.config.pod_name,
            namespace = %self.config.namespace,
            extensions = self.extensions.len(),
            "Starting infra"
        );

        // Dispatch Starting event first
        self.dispatch_event(InfraEvent::Starting).await;

        // Initialize extensions
        for extension in &mut self.extensions {
            let name = extension.name().to_string();
            debug!(extension = %name, "Initializing extension");

            let result = tokio::time::timeout(
                std::time::Duration::from_secs(EXTENSION_CALLBACK_TIMEOUT_SECS),
                extension.on_start(&self.context),
            )
            .await;

            match result {
                Ok(Ok(())) => {
                    info!(extension = %name, "Extension initialized");
                }
                Ok(Err(e)) => {
                    error!(extension = %name, error = %e, "Extension initialization failed");
                    return Err(InfraError::Extension(ExtensionError::InitializationFailed(
                        name,
                        e.to_string(),
                    )));
                }
                Err(_) => {
                    error!(extension = %name, "Extension initialization timed out");
                    return Err(InfraError::Extension(ExtensionError::CallbackTimeout(name)));
                }
            }
        }

        self.running = true;

        // Dispatch Ready event
        self.dispatch_event(InfraEvent::Ready).await;

        // Call on_ready for each extension
        for extension in &mut self.extensions {
            let name = extension.name().to_string();
            if let Err(e) = extension.on_ready(&self.context).await {
                warn!(extension = %name, error = %e, "Extension on_ready failed");
                // Non-fatal, continue
            }
        }

        info!("Infra started");
        Ok(())
    }

    /// Notify container started.
    ///
    /// Call this when a container in the pod has started.
    pub async fn notify_container_started(&mut self, name: &str, id: &str, pid: u32) {
        info!(container = %name, id = %id, pid = pid, "Container started");

        // Track container
        if let Err(e) = self
            .context
            .track_container(name.to_string(), id.to_string())
            .await
        {
            error!(error = %e, "Failed to track container");
        }

        // Dispatch event
        self.dispatch_event(InfraEvent::ContainerStarted {
            name: name.to_string(),
            id: id.to_string(),
            pid,
        })
        .await;
    }

    /// Notify container stopped.
    ///
    /// Call this when a container in the pod has stopped.
    pub async fn notify_container_stopped(&mut self, name: &str, id: &str, exit_code: i32) {
        info!(container = %name, id = %id, exit_code = exit_code, "Container stopped");

        // Untrack container
        self.context.untrack_container(name).await;

        // Dispatch event
        self.dispatch_event(InfraEvent::ContainerStopped {
            name: name.to_string(),
            id: id.to_string(),
            exit_code,
        })
        .await;
    }

    /// Request shutdown.
    ///
    /// Call this when a shutdown signal is received.
    pub async fn shutdown(&mut self, signal: i32) -> InfraResult<()> {
        if !self.running {
            return Err(InfraError::NotRunning);
        }

        info!(signal = signal, "Shutdown requested");

        // Dispatch shutdown requested event
        self.dispatch_event(InfraEvent::ShutdownRequested { signal })
            .await;
        self.dispatch_event(InfraEvent::ShuttingDown).await;

        // Shutdown extensions in reverse order
        for extension in self.extensions.iter_mut().rev() {
            let name = extension.name().to_string();
            debug!(extension = %name, "Shutting down extension");

            if let Err(e) = extension.on_shutdown(&self.context).await {
                warn!(extension = %name, error = %e, "Extension shutdown failed");
                // Continue with other extensions
            }
        }

        self.running = false;
        info!("Infra shutdown complete");
        Ok(())
    }

    /// Dispatch an event to all extensions.
    async fn dispatch_event(&mut self, event: InfraEvent) {
        debug!(event = ?event, "Dispatching event");

        for extension in &mut self.extensions {
            let name = extension.name().to_string();

            let result = tokio::time::timeout(
                std::time::Duration::from_secs(EXTENSION_CALLBACK_TIMEOUT_SECS),
                extension.on_event(&event, &self.context),
            )
            .await;

            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!(extension = %name, error = %e, "Extension event handler failed");
                }
                Err(_) => {
                    warn!(extension = %name, "Extension event handler timed out");
                }
            }
        }
    }

    /// Get the context for direct access.
    pub fn context(&self) -> &InfraContext {
        &self.context
    }

    /// Check if infra is running.
    pub fn is_running(&self) -> bool {
        self.running
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestExtension {
        name: String,
        start_count: Arc<AtomicUsize>,
        event_count: Arc<AtomicUsize>,
        shutdown_count: Arc<AtomicUsize>,
    }

    impl TestExtension {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                start_count: Arc::new(AtomicUsize::new(0)),
                event_count: Arc::new(AtomicUsize::new(0)),
                shutdown_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl InfraExtension for TestExtension {
        fn name(&self) -> &str {
            &self.name
        }

        async fn on_start(&mut self, _ctx: &InfraContext) -> ExtensionResult<()> {
            self.start_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn on_event(
            &mut self,
            _event: &InfraEvent,
            _ctx: &InfraContext,
        ) -> ExtensionResult<()> {
            self.event_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn on_shutdown(&mut self, _ctx: &InfraContext) -> ExtensionResult<()> {
            self.shutdown_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_extension_registration() {
        let config = InfraConfig {
            pod_id: "test-pod-123".to_string(),
            pod_name: "test-pod".to_string(),
            namespace: "default".to_string(),
            pod_root: PathBuf::from("/tmp/test"),
            extension_names: Vec::new(),
        };

        let mut infra = Infra::new(config);
        let ext = TestExtension::new("test-ext");

        assert!(infra.register(ext).is_ok());
    }

    #[tokio::test]
    async fn test_duplicate_extension_rejected() {
        let config = InfraConfig::default();
        let mut infra = Infra::new(config);

        infra.register(TestExtension::new("dup")).unwrap();

        let result = infra.register(TestExtension::new("dup"));
        assert!(matches!(result, Err(ExtensionError::AlreadyRegistered(_))));
    }

    #[tokio::test]
    async fn test_extension_lifecycle() {
        let config = InfraConfig {
            pod_id: "lifecycle-test".to_string(),
            pod_name: "lifecycle".to_string(),
            namespace: "default".to_string(),
            pod_root: PathBuf::from("/tmp/test"),
            extension_names: Vec::new(),
        };

        let mut infra = Infra::new(config);

        let start_count = Arc::new(AtomicUsize::new(0));
        let shutdown_count = Arc::new(AtomicUsize::new(0));

        struct CountingExt {
            start: Arc<AtomicUsize>,
            shutdown: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl InfraExtension for CountingExt {
            fn name(&self) -> &str {
                "counting"
            }

            async fn on_start(&mut self, _ctx: &InfraContext) -> ExtensionResult<()> {
                self.start.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            async fn on_shutdown(&mut self, _ctx: &InfraContext) -> ExtensionResult<()> {
                self.shutdown.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let ext = CountingExt {
            start: Arc::clone(&start_count),
            shutdown: Arc::clone(&shutdown_count),
        };

        infra.register(ext).unwrap();

        // Start
        infra.start().await.unwrap();
        assert_eq!(start_count.load(Ordering::SeqCst), 1);
        assert!(infra.is_running());

        // Shutdown
        infra.shutdown(15).await.unwrap();
        assert_eq!(shutdown_count.load(Ordering::SeqCst), 1);
        assert!(!infra.is_running());
    }

    #[tokio::test]
    async fn test_container_tracking() {
        let config = InfraConfig {
            pod_id: "track-test".to_string(),
            ..Default::default()
        };

        let mut infra = Infra::new(config);
        infra.start().await.unwrap();

        // Track container
        infra
            .notify_container_started("app", "container-123", 1234)
            .await;

        let names = infra.context().container_names().await;
        assert_eq!(names, vec!["app"]);

        let id = infra.context().container_id("app").await;
        assert_eq!(id, Some("container-123".to_string()));

        // Untrack container
        infra
            .notify_container_stopped("app", "container-123", 0)
            .await;

        let names = infra.context().container_names().await;
        assert!(names.is_empty());

        infra.shutdown(15).await.unwrap();
    }

    #[tokio::test]
    async fn test_name_too_long_rejected() {
        let config = InfraConfig::default();
        let mut infra = Infra::new(config);

        struct LongNameExt;

        #[async_trait]
        impl InfraExtension for LongNameExt {
            fn name(&self) -> &str {
                // 65 characters - over the limit
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        }

        let result = infra.register(LongNameExt);
        assert!(matches!(result, Err(ExtensionError::NameTooLong)));
    }
}
