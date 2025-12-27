//! Port forwarding utilities shared between pod runtimes.
//!
//! This module provides common types and functions for port mapping
//! extraction and validation used by both Native and MicroVM pod runtimes.

use crate::pod::ContainerSpec;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of port mappings per pod.
///
/// **Security**: Prevents resource exhaustion from pods with excessive port mappings.
/// 1024 ports is generous for legitimate use while bounding argument list size.
pub const MAX_PORT_MAPPINGS: usize = 1024;

// =============================================================================
// Protocol
// =============================================================================

/// Network protocol for port forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    /// TCP port forwarding.
    Tcp,
    /// UDP port forwarding.
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

// =============================================================================
// PortMapping
// =============================================================================

/// A single port mapping from host to container/VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortMapping {
    /// Protocol (TCP or UDP).
    pub protocol: Protocol,
    /// Port on the host to listen on.
    pub host_port: u16,
    /// Port inside the container/VM to forward to.
    pub container_port: u16,
}

impl PortMapping {
    /// Creates a TCP port mapping.
    #[must_use]
    pub const fn tcp(host_port: u16, container_port: u16) -> Self {
        Self {
            protocol: Protocol::Tcp,
            host_port,
            container_port,
        }
    }

    /// Creates a UDP port mapping.
    #[must_use]
    #[allow(dead_code)] // Used by tests and for API symmetry with tcp()
    pub const fn udp(host_port: u16, container_port: u16) -> Self {
        Self {
            protocol: Protocol::Udp,
            host_port,
            container_port,
        }
    }

    /// Returns pasta/passt argument format: "host_port:container_port".
    #[must_use]
    pub fn as_arg(self) -> String {
        format!("{}:{}", self.host_port, self.container_port)
    }
}

impl fmt::Display for PortMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}→{}",
            self.protocol, self.host_port, self.container_port
        )
    }
}

// =============================================================================
// Port Mapping Extraction
// =============================================================================

/// Result of port mapping extraction.
#[derive(Debug)]
pub struct PortMappingResult {
    /// Valid port mappings.
    pub mappings: Vec<PortMapping>,
    /// Number of invalid mappings skipped.
    pub skipped_invalid: usize,
    /// Number of duplicate mappings skipped.
    pub skipped_duplicates: usize,
    /// Whether the limit was reached.
    pub limit_reached: bool,
}

/// Extracts and validates port mappings from container specs.
///
/// # Port Resolution (K8s-compatible)
///
/// Only creates port mappings when `hostPort` is explicitly specified.
/// Ports without `hostPort` are skipped (K8s behavior: not exposed on host).
///
/// # Validation
///
/// - Skips mappings where `host_port` or `container_port` is 0
/// - Deduplicates by (host_port, protocol) - first mapping wins
/// - Enforces `MAX_PORT_MAPPINGS` limit
///
/// # Arguments
///
/// * `containers` - Container specifications to extract ports from
///
/// # Returns
///
/// A `PortMappingResult` containing valid mappings and statistics.
pub fn extract_port_mappings(containers: &[ContainerSpec]) -> PortMappingResult {
    let mut mappings = Vec::new();
    let mut seen: HashSet<(u16, Protocol)> = HashSet::new();
    let mut skipped_invalid = 0;
    let mut skipped_duplicates = 0;
    let mut limit_reached = false;

    'outer: for container in containers {
        for port in &container.ports {
            // K8s-strict: only map ports with explicit hostPort
            let Some(host_port) = port.host_port else {
                continue;
            };

            // Validate port values are non-zero
            if host_port == 0 || port.container_port == 0 {
                tracing::warn!(
                    container = %container.name,
                    host_port = host_port,
                    container_port = port.container_port,
                    "Skipping invalid port mapping: port 0 is not allowed"
                );
                skipped_invalid += 1;
                continue;
            }

            let protocol = match port.protocol.to_uppercase().as_str() {
                "UDP" => Protocol::Udp,
                _ => Protocol::Tcp,
            };

            // Check for duplicates (same host_port + protocol)
            let key = (host_port, protocol);
            if seen.contains(&key) {
                tracing::warn!(
                    container = %container.name,
                    host_port = host_port,
                    protocol = %protocol,
                    "Skipping duplicate port mapping"
                );
                skipped_duplicates += 1;
                continue;
            }

            // Check limit
            if mappings.len() >= MAX_PORT_MAPPINGS {
                tracing::warn!(
                    max = MAX_PORT_MAPPINGS,
                    "Maximum port mappings reached, ignoring remaining"
                );
                limit_reached = true;
                break 'outer;
            }

            seen.insert(key);
            mappings.push(PortMapping {
                protocol,
                host_port,
                container_port: port.container_port,
            });
        }
    }

    PortMappingResult {
        mappings,
        skipped_invalid,
        skipped_duplicates,
        limit_reached,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pod::ContainerPort;

    fn make_container(name: &str, ports: Vec<ContainerPort>) -> ContainerSpec {
        ContainerSpec {
            name: name.to_string(),
            image: "test:latest".to_string(),
            command: None,
            args: None,
            env: std::collections::HashMap::new(),
            working_dir: None,
            ports,
            volume_mounts: Vec::new(),
            resources: Default::default(),
        }
    }

    fn make_port(container_port: u16, host_port: Option<u16>, protocol: &str) -> ContainerPort {
        ContainerPort {
            name: None,
            container_port,
            host_port,
            protocol: protocol.to_string(),
        }
    }

    #[test]
    fn test_extract_skips_ports_without_host_port() {
        let containers = vec![make_container("test", vec![make_port(80, None, "TCP")])];
        let result = extract_port_mappings(&containers);
        assert!(result.mappings.is_empty());
    }

    #[test]
    fn test_extract_valid_tcp_port() {
        let containers = vec![make_container(
            "test",
            vec![make_port(80, Some(8080), "TCP")],
        )];
        let result = extract_port_mappings(&containers);
        assert_eq!(result.mappings.len(), 1);
        assert_eq!(result.mappings[0].host_port, 8080);
        assert_eq!(result.mappings[0].container_port, 80);
        assert_eq!(result.mappings[0].protocol, Protocol::Tcp);
    }

    #[test]
    fn test_extract_valid_udp_port() {
        let containers = vec![make_container(
            "test",
            vec![make_port(53, Some(5353), "UDP")],
        )];
        let result = extract_port_mappings(&containers);
        assert_eq!(result.mappings.len(), 1);
        assert_eq!(result.mappings[0].protocol, Protocol::Udp);
    }

    #[test]
    fn test_extract_skips_zero_ports() {
        let containers = vec![make_container(
            "test",
            vec![
                make_port(0, Some(8080), "TCP"),
                make_port(80, Some(0), "TCP"),
            ],
        )];
        let result = extract_port_mappings(&containers);
        assert!(result.mappings.is_empty());
        assert_eq!(result.skipped_invalid, 2);
    }

    #[test]
    fn test_extract_deduplicates() {
        let containers = vec![
            make_container("c1", vec![make_port(80, Some(8080), "TCP")]),
            make_container("c2", vec![make_port(81, Some(8080), "TCP")]), // Same host_port
        ];
        let result = extract_port_mappings(&containers);
        assert_eq!(result.mappings.len(), 1);
        assert_eq!(result.skipped_duplicates, 1);
        // First one wins
        assert_eq!(result.mappings[0].container_port, 80);
    }

    #[test]
    fn test_same_host_port_different_protocol_allowed() {
        let containers = vec![make_container(
            "test",
            vec![
                make_port(53, Some(5353), "TCP"),
                make_port(53, Some(5353), "UDP"),
            ],
        )];
        let result = extract_port_mappings(&containers);
        assert_eq!(result.mappings.len(), 2);
    }

    #[test]
    fn test_port_mapping_constructors() {
        // Test tcp() constructor
        let tcp_mapping = PortMapping::tcp(8080, 80);
        assert_eq!(tcp_mapping.protocol, Protocol::Tcp);
        assert_eq!(tcp_mapping.host_port, 8080);
        assert_eq!(tcp_mapping.container_port, 80);
        assert_eq!(tcp_mapping.as_arg(), "8080:80");

        // Test udp() constructor
        let udp_mapping = PortMapping::udp(5353, 53);
        assert_eq!(udp_mapping.protocol, Protocol::Udp);
        assert_eq!(udp_mapping.host_port, 5353);
        assert_eq!(udp_mapping.container_port, 53);
        assert_eq!(udp_mapping.as_arg(), "5353:53");
    }
}
