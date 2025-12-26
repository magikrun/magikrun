//! TSI (Transparent Socket Interface) protocol definitions.
//!
//! This module defines the wire protocol for communication between
//! the host-side pod runtime and the guest vminit running inside MicroVMs.
//!
//! # Protocol Format
//!
//! - **Transport**: vsock (AF_VSOCK)
//! - **Encoding**: JSON
//! - **Framing**: Newline-delimited (each message ends with `\n`)
//!
//! # Request/Response Flow
//!
//! ```text
//! Host                             Guest (vminit)
//!   |                                 |
//!   |  {"action":"exec",...}\n        |
//!   |-------------------------------->|
//!   |                                 |
//!   |  {"status":"ok",...}\n          |
//!   |<--------------------------------|
//!   |                                 |
//! ```
//!
//! # Supported Actions
//!
//! TSI is minimal - only Day-2 operations that cross the vsock boundary.
//! Pod lifecycle (create/delete) is handled by vminit reading baked pod spec.
//!
//! | Action | Description |
//! |--------|-------------|
//! | `exec` | Execute command in container |
//! | `logs` | Stream container logs |
//! | `ping` | Check vminit availability |
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │ Host                                                             │
//! │  ┌─────────────────────┐                                         │
//! │  │  MicroVmPodRuntime  │                                         │
//! │  │  ┌───────────────┐  │                                         │
//! │  │  │  TsiClient    │──┼──┐                                      │
//! │  │  └───────────────┘  │  │ vsock (AF_VSOCK)                     │
//! │  └─────────────────────┘  │ CID:1024                             │
//! │                           ▼                                      │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  MicroVM (libkrun)                                         │  │
//! │  │  ┌──────────────────────────────────────────────────────┐  │  │
//! │  │  │  vminit (PID 1)                                      │  │  │
//! │  │  │  - Spawns containers from baked /containers/*/       │  │  │
//! │  │  │  - Handles TSI: exec, logs, ping                     │  │  │
//! │  │  │  - Zombie reaping, signal forwarding                 │  │  │
//! │  │  └──────────────────────────────────────────────────────┘  │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────────┘
//! ```

use serde::{Deserialize, Serialize};

// =============================================================================
// Constants
// =============================================================================

/// Maximum container name length.
pub const MAX_CONTAINER_NAME_LEN: usize = 63;

/// Maximum command argument length.
pub const MAX_COMMAND_ARG_LEN: usize = 4096;

/// Maximum number of command arguments.
pub const MAX_COMMAND_ARGS: usize = 256;

/// Maximum tail lines for logs.
pub const MAX_TAIL_LINES: u32 = 100_000;

// =============================================================================
// Request Types
// =============================================================================

/// Request from host to guest vminit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Request {
    /// Execute a command in a container.
    Exec(ExecRequest),

    /// Stream logs from a container.
    Logs(LogsRequest),

    /// Ping to check vminit health.
    Ping,
}

/// Execute a command in a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Container name (e.g., "infra", "app-nginx").
    pub container: String,
    /// Command to execute.
    pub command: Vec<String>,
    /// Attach stdin.
    pub stdin: bool,
    /// Attach stdout.
    pub stdout: bool,
    /// Attach stderr.
    pub stderr: bool,
    /// Allocate TTY.
    pub tty: bool,
}

/// Request container logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogsRequest {
    /// Container name.
    pub container: String,
    /// Follow logs (stream).
    pub follow: bool,
    /// Number of lines from tail (0 = all).
    pub tail_lines: u32,
    /// Include timestamps.
    pub timestamps: bool,
}

// =============================================================================
// Response Types
// =============================================================================

/// Response from guest vminit to host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// Success response.
    Ok(OkPayload),
    /// Error response.
    Error(ErrorPayload),
}

impl Response {
    /// Creates a success response with no data.
    #[must_use]
    pub fn ok() -> Self {
        Self::Ok(OkPayload { data: None })
    }

    /// Creates a success response with data.
    #[must_use]
    pub fn ok_with_data(data: ResponseData) -> Self {
        Self::Ok(OkPayload { data: Some(data) })
    }

    /// Creates an error response.
    #[must_use]
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error(ErrorPayload {
            code,
            message: message.into(),
        })
    }

    /// Returns true if this is a success response.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
}

/// Success payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkPayload {
    /// Optional response data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ResponseData>,
}

/// Response data variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseData {
    /// Pong response.
    Pong {
        /// vminit version string.
        version: String,
        /// Number of running containers.
        container_count: usize,
    },

    /// Exec session ID (for streaming exec).
    ExecSession {
        /// Session identifier for subsequent requests.
        session_id: String,
    },

    /// Log line.
    LogLine {
        /// Optional timestamp.
        timestamp: Option<String>,
        /// Log content.
        line: String,
    },
}

/// Error payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// Error code.
    pub code: ErrorCode,
    /// Human-readable message.
    pub message: String,
}

/// Error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Container not found.
    ContainerNotFound,
    /// Container not running.
    ContainerNotRunning,
    /// Exec failed.
    ExecFailed,
    /// Internal vminit error.
    Internal,
    /// Request timeout.
    Timeout,
    /// Invalid request format.
    InvalidRequest,
}

// =============================================================================
// Wire Format Helpers
// =============================================================================

impl Request {
    /// Serializes request to JSON line (with newline).
    ///
    /// # Errors
    ///
    /// Returns error if JSON serialization fails.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        let mut json = serde_json::to_string(self)?;
        json.push('\n');
        Ok(json)
    }

    /// Deserializes request from JSON.
    ///
    /// # Errors
    ///
    /// Returns error if JSON deserialization fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s.trim())
    }
}

impl Response {
    /// Serializes response to JSON line (with newline).
    ///
    /// # Errors
    ///
    /// Returns error if JSON serialization fails.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        let mut json = serde_json::to_string(self)?;
        json.push('\n');
        Ok(json)
    }

    /// Deserializes response from JSON.
    ///
    /// # Errors
    ///
    /// Returns error if JSON deserialization fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_serialization() {
        let resp = Response::ok();
        let json = resp.to_json_line().unwrap();
        assert!(json.contains("\"status\":\"ok\""));

        let resp = Response::error(ErrorCode::ContainerNotFound, "container 'foo' not found");
        let json = resp.to_json_line().unwrap();
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("\"code\":\"container_not_found\""));
    }

    #[test]
    fn test_ping_request() {
        let req = Request::Ping;
        let json = req.to_json_line().unwrap();
        assert!(json.contains("\"action\":\"ping\""));

        let parsed = Request::from_json(&json).unwrap();
        assert!(matches!(parsed, Request::Ping));
    }

    #[test]
    fn test_exec_request() {
        let req = Request::Exec(ExecRequest {
            container: "nginx".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "ls".to_string()],
            stdin: true,
            stdout: true,
            stderr: true,
            tty: true,
        });
        let json = req.to_json_line().unwrap();
        assert!(json.contains("\"action\":\"exec\""));
        assert!(json.contains("\"container\":\"nginx\""));
    }

    #[test]
    fn test_logs_request() {
        let req = Request::Logs(LogsRequest {
            container: "app".to_string(),
            follow: true,
            tail_lines: 100,
            timestamps: false,
        });
        let json = req.to_json_line().unwrap();
        assert!(json.contains("\"action\":\"logs\""));
        assert!(json.contains("\"container\":\"app\""));
        assert!(json.contains("\"follow\":true"));
    }

    #[test]
    fn test_pong_response() {
        let resp = Response::ok_with_data(ResponseData::Pong {
            version: "0.2.3".to_string(),
            container_count: 2,
        });
        let json = resp.to_json_line().unwrap();
        assert!(json.contains("\"type\":\"pong\""));
        assert!(json.contains("\"version\":\"0.2.3\""));
        assert!(json.contains("\"container_count\":2"));
    }
}
