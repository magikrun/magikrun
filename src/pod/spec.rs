//! Pod specification types.
//!
//! This module provides Kubernetes-compatible pod manifest parsing
//! with comprehensive validation.
//!
//! # Supported Formats
//!
//! - **YAML**: Primary format, parsed via `serde_yaml`
//! - **JSON**: Also supported (YAML is a superset of JSON)

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Constants for Manifest Validation
// =============================================================================

/// Maximum size of a pod manifest in bytes (1 MiB).
pub const MAX_MANIFEST_SIZE: usize = 1024 * 1024;

/// Maximum number of pods per runtime instance.
pub const MAX_PODS: usize = 1024;

/// Maximum number of containers per pod.
pub const MAX_CONTAINERS_PER_POD: usize = 16;

/// Maximum number of volumes per pod.
pub const MAX_VOLUMES_PER_POD: usize = 64;

/// Maximum length for Kubernetes-compatible names (RFC 1123 DNS subdomain).
pub const MAX_NAME_LEN: usize = 253;

/// Maximum length for namespace names.
pub const MAX_NAMESPACE_LEN: usize = 63;

/// Maximum length for container names within a pod.
pub const MAX_CONTAINER_NAME_LEN: usize = 63;

/// Maximum length for pod IDs (UUID string = 36 chars).
pub const MAX_POD_ID_LEN: usize = 64;

/// Maximum number of environment variables per container.
pub const MAX_ENV_VARS_PER_CONTAINER: usize = 256;

/// Maximum length of an environment variable value (32 KiB).
pub const MAX_ENV_VALUE_LEN: usize = 32 * 1024;

/// Maximum number of labels per pod.
pub const MAX_LABELS_PER_POD: usize = 64;

/// Maximum number of annotations per pod.
pub const MAX_ANNOTATIONS_PER_POD: usize = 64;

/// Maximum length for label/annotation keys.
pub const MAX_LABEL_KEY_LEN: usize = 253;

/// Maximum length for label/annotation values.
pub const MAX_LABEL_VALUE_LEN: usize = 63 * 1024;

/// Maximum grace period for container termination (seconds).
pub const MAX_GRACE_PERIOD_SECS: u32 = 300;

/// Default grace period for container termination (seconds).
pub const DEFAULT_GRACE_PERIOD_SECS: u32 = 30;

// =============================================================================
// Validation Helpers
// =============================================================================

/// Validates a Kubernetes-compatible name (RFC 1123 DNS label).
fn validate_name(name: &str, max_len: usize) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidInput("name cannot be empty".to_string()));
    }

    if name.len() > max_len {
        return Err(Error::InvalidInput(format!(
            "name '{}' exceeds maximum length of {}",
            name, max_len
        )));
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Error::InvalidInput(format!(
            "name '{}' must contain only lowercase alphanumeric characters or '-'",
            name
        )));
    }

    if name.starts_with('-') || name.ends_with('-') {
        return Err(Error::InvalidInput(format!(
            "name '{}' cannot start or end with '-'",
            name
        )));
    }

    Ok(())
}

// =============================================================================
// Pod Specification
// =============================================================================

/// Pod specification.
///
/// Represents a parsed and validated Kubernetes Pod manifest.
/// This is the primary input type for pod creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSpec {
    /// Namespace (defaults to "default" if not specified).
    pub namespace: String,
    /// Pod name (RFC 1123 DNS label, unique within namespace).
    pub name: String,
    /// Resource kind (usually "Pod").
    pub kind: String,
    /// Labels for pod selection and organization.
    pub labels: HashMap<String, String>,
    /// Annotations for arbitrary metadata.
    pub annotations: HashMap<String, String>,
    /// Container specifications (at least one required).
    pub containers: Vec<ContainerSpec>,
    /// Init container specifications (run before main containers).
    pub init_containers: Vec<ContainerSpec>,
    /// Volume definitions for the pod.
    pub volumes: Vec<Volume>,
    /// Runtime class name (determines pod runtime).
    pub runtime_class_name: Option<String>,
    /// Override hostname for the pod.
    pub hostname: Option<String>,
}

impl PodSpec {
    /// Parses a pod spec from YAML bytes.
    ///
    /// # Errors
    ///
    /// - Size exceeds `MAX_MANIFEST_SIZE`
    /// - YAML parsing fails
    /// - Validation errors for names, counts, etc.
    pub fn from_yaml(yaml: &[u8]) -> Result<Self> {
        if yaml.len() > MAX_MANIFEST_SIZE {
            return Err(Error::InvalidInput(format!(
                "manifest size {} exceeds limit of {}",
                yaml.len(),
                MAX_MANIFEST_SIZE
            )));
        }

        let doc: serde_yaml::Value =
            serde_yaml::from_slice(yaml).map_err(|e| Error::InvalidInput(e.to_string()))?;

        Self::from_value(&doc)
    }

    /// Parses a pod spec from a `serde_yaml::Value`.
    pub fn from_value(doc: &serde_yaml::Value) -> Result<Self> {
        let metadata = doc.get("metadata");
        let kind = doc
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or("Pod")
            .to_string();

        let namespace = metadata
            .and_then(|m| m.get("namespace"))
            .and_then(|n| n.as_str())
            .unwrap_or("default")
            .to_string();
        validate_name(&namespace, MAX_NAMESPACE_LEN)?;

        let name = metadata
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .ok_or_else(|| Error::InvalidInput("missing metadata.name".to_string()))?
            .to_string();
        validate_name(&name, MAX_NAME_LEN)?;

        let labels = parse_string_map(
            metadata.and_then(|m| m.get("labels")),
            "label",
            MAX_LABELS_PER_POD,
        )?;

        let annotations = parse_string_map(
            metadata.and_then(|m| m.get("annotations")),
            "annotation",
            MAX_ANNOTATIONS_PER_POD,
        )?;

        let spec = doc.get("spec");

        let containers_seq = spec
            .and_then(|s| s.get("containers"))
            .and_then(|c| c.as_sequence())
            .ok_or_else(|| Error::InvalidInput("missing spec.containers".to_string()))?;

        if containers_seq.len() > MAX_CONTAINERS_PER_POD {
            return Err(Error::InvalidInput(format!(
                "too many containers: {} (max {})",
                containers_seq.len(),
                MAX_CONTAINERS_PER_POD
            )));
        }

        let containers: Vec<ContainerSpec> = containers_seq
            .iter()
            .map(ContainerSpec::from_value)
            .collect::<Result<Vec<_>>>()?;

        if containers.is_empty() {
            return Err(Error::InvalidInput(
                "at least one container required".to_string(),
            ));
        }

        let init_containers = parse_container_list(spec.and_then(|s| s.get("initContainers")))?;

        let volumes = parse_volume_list(spec.and_then(|s| s.get("volumes")))?;

        let runtime_class_name = spec
            .and_then(|s| s.get("runtimeClassName"))
            .and_then(|r| r.as_str())
            .map(String::from);

        let hostname = spec
            .and_then(|s| s.get("hostname"))
            .and_then(|h| h.as_str())
            .map(String::from);

        Ok(Self {
            namespace,
            name,
            kind,
            labels,
            annotations,
            containers,
            init_containers,
            volumes,
            runtime_class_name,
            hostname,
        })
    }
}

fn parse_string_map(
    value: Option<&serde_yaml::Value>,
    kind: &str,
    max_count: usize,
) -> Result<HashMap<String, String>> {
    let Some(mapping) = value.and_then(|v| v.as_mapping()) else {
        return Ok(HashMap::new());
    };

    if mapping.len() > max_count {
        return Err(Error::InvalidInput(format!(
            "too many {}s: {} (max {})",
            kind,
            mapping.len(),
            max_count
        )));
    }

    let mut result = HashMap::new();
    for (k, v) in mapping.iter() {
        let key = k
            .as_str()
            .ok_or_else(|| Error::InvalidInput(format!("{} key must be a string", kind)))?;
        let val = v
            .as_str()
            .ok_or_else(|| Error::InvalidInput(format!("{} value must be a string", kind)))?;

        if key.len() > MAX_LABEL_KEY_LEN {
            return Err(Error::InvalidInput(format!(
                "{} key '{}' exceeds max length {}",
                kind, key, MAX_LABEL_KEY_LEN
            )));
        }
        if val.len() > MAX_LABEL_VALUE_LEN {
            return Err(Error::InvalidInput(format!(
                "{} value for '{}' exceeds max length {}",
                kind, key, MAX_LABEL_VALUE_LEN
            )));
        }
        result.insert(key.to_string(), val.to_string());
    }
    Ok(result)
}

fn parse_container_list(value: Option<&serde_yaml::Value>) -> Result<Vec<ContainerSpec>> {
    let Some(seq) = value.and_then(|v| v.as_sequence()) else {
        return Ok(Vec::new());
    };

    if seq.len() > MAX_CONTAINERS_PER_POD {
        return Err(Error::InvalidInput(format!(
            "too many init containers: {} (max {})",
            seq.len(),
            MAX_CONTAINERS_PER_POD
        )));
    }

    seq.iter().map(ContainerSpec::from_value).collect()
}

fn parse_volume_list(value: Option<&serde_yaml::Value>) -> Result<Vec<Volume>> {
    let Some(seq) = value.and_then(|v| v.as_sequence()) else {
        return Ok(Vec::new());
    };

    if seq.len() > MAX_VOLUMES_PER_POD {
        return Err(Error::InvalidInput(format!(
            "too many volumes: {} (max {})",
            seq.len(),
            MAX_VOLUMES_PER_POD
        )));
    }

    seq.iter().map(Volume::from_value).collect()
}

// =============================================================================
// Container Specification
// =============================================================================

/// Container specification.
///
/// Represents a single container within a pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSpec {
    /// Container name (unique within pod, RFC 1123 label).
    pub name: String,
    /// Image reference (e.g., "nginx:1.25", "ghcr.io/user/app:v1").
    pub image: String,
    /// Override the image's default entrypoint.
    pub command: Option<Vec<String>>,
    /// Arguments to the entrypoint.
    pub args: Option<Vec<String>>,
    /// Environment variables (name → value).
    pub env: HashMap<String, String>,
    /// Working directory inside the container.
    pub working_dir: Option<String>,
    /// Exposed ports.
    pub ports: Vec<ContainerPort>,
    /// Volume mount points.
    pub volume_mounts: Vec<VolumeMount>,
    /// Resource limits and requests.
    pub resources: ResourceRequirements,
}

impl ContainerSpec {
    /// Parses from a YAML value.
    pub fn from_value(value: &serde_yaml::Value) -> Result<Self> {
        let name = value
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| Error::InvalidInput("missing container name".to_string()))?
            .to_string();
        validate_name(&name, MAX_CONTAINER_NAME_LEN)?;

        let image = value
            .get("image")
            .and_then(|i| i.as_str())
            .ok_or_else(|| Error::InvalidInput("missing container image".to_string()))?
            .to_string();

        let command = value
            .get("command")
            .and_then(|c| c.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });

        let args = value.get("args").and_then(|a| a.as_sequence()).map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });

        let env = parse_env_vars(value.get("env"), &name)?;

        let working_dir = value
            .get("workingDir")
            .and_then(|w| w.as_str())
            .map(String::from);

        let ports = parse_ports(value.get("ports"));
        let volume_mounts = parse_volume_mounts(value.get("volumeMounts"));
        let resources = parse_resources(value.get("resources"));

        Ok(Self {
            name,
            image,
            command,
            args,
            env,
            working_dir,
            ports,
            volume_mounts,
            resources,
        })
    }

    /// Returns true if this container uses a WASM image.
    pub fn is_wasm(&self) -> bool {
        self.image.ends_with(".wasm")
            || self.image.contains(":wasm")
            || self.image.contains("/wasm/")
    }
}

fn parse_env_vars(
    value: Option<&serde_yaml::Value>,
    container_name: &str,
) -> Result<HashMap<String, String>> {
    let Some(seq) = value.and_then(|v| v.as_sequence()) else {
        return Ok(HashMap::new());
    };

    if seq.len() > MAX_ENV_VARS_PER_CONTAINER {
        return Err(Error::InvalidInput(format!(
            "too many environment variables in container {}: {} (max {})",
            container_name,
            seq.len(),
            MAX_ENV_VARS_PER_CONTAINER
        )));
    }

    let mut map = HashMap::new();
    for item in seq {
        let env_name = item
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| Error::InvalidInput("missing env name".to_string()))?;
        let val = item.get("value").and_then(|v| v.as_str()).unwrap_or("");

        if val.len() > MAX_ENV_VALUE_LEN {
            return Err(Error::InvalidInput(format!(
                "env variable {} value exceeds limit of {} bytes",
                env_name, MAX_ENV_VALUE_LEN
            )));
        }

        map.insert(env_name.to_string(), val.to_string());
    }
    Ok(map)
}

fn parse_ports(value: Option<&serde_yaml::Value>) -> Vec<ContainerPort> {
    let Some(seq) = value.and_then(|v| v.as_sequence()) else {
        return Vec::new();
    };

    seq.iter()
        .filter_map(|p| {
            let container_port = p.get("containerPort")?.as_u64()? as u16;
            let protocol = p
                .get("protocol")
                .and_then(|pr| pr.as_str())
                .unwrap_or("TCP")
                .to_string();
            let name = p.get("name").and_then(|n| n.as_str()).map(String::from);
            let host_port = p
                .get("hostPort")
                .and_then(|hp| hp.as_u64())
                .map(|hp| hp as u16);
            Some(ContainerPort {
                name,
                container_port,
                protocol,
                host_port,
            })
        })
        .collect()
}

fn parse_volume_mounts(value: Option<&serde_yaml::Value>) -> Vec<VolumeMount> {
    let Some(seq) = value.and_then(|v| v.as_sequence()) else {
        return Vec::new();
    };

    seq.iter()
        .filter_map(|vm| {
            let name = vm.get("name")?.as_str()?.to_string();
            let mount_path = vm.get("mountPath")?.as_str()?.to_string();
            let read_only = vm
                .get("readOnly")
                .and_then(|r| r.as_bool())
                .unwrap_or(false);
            Some(VolumeMount {
                name,
                mount_path,
                read_only,
            })
        })
        .collect()
}

fn parse_resources(value: Option<&serde_yaml::Value>) -> ResourceRequirements {
    let Some(r) = value else {
        return ResourceRequirements::default();
    };

    let memory_bytes = r
        .get("limits")
        .or_else(|| r.get("requests"))
        .and_then(|l| l.get("memory"))
        .and_then(|m| m.as_str())
        .map(parse_memory_string)
        .unwrap_or(0);

    let cpu_shares = r
        .get("limits")
        .or_else(|| r.get("requests"))
        .and_then(|l| l.get("cpu"))
        .and_then(|c| c.as_str())
        .map(parse_cpu_string)
        .unwrap_or(0);

    ResourceRequirements {
        memory_bytes,
        cpu_shares,
    }
}

// =============================================================================
// Supporting Types
// =============================================================================

/// Container port definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerPort {
    /// Optional name for the port (for service discovery).
    pub name: Option<String>,
    /// Port number inside the container (1-65535).
    pub container_port: u16,
    /// Protocol (TCP or UDP, defaults to TCP).
    pub protocol: String,
    /// Optional host port to map to.
    pub host_port: Option<u16>,
}

/// Volume mount specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    /// Name of the volume to mount.
    pub name: String,
    /// Path inside the container to mount at.
    pub mount_path: String,
    /// If true, mount as read-only.
    pub read_only: bool,
}

/// Pod volume definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    /// Volume name (referenced by volume mounts).
    pub name: String,
    /// Volume source type.
    pub source: VolumeSource,
}

impl Volume {
    fn from_value(value: &serde_yaml::Value) -> Result<Self> {
        let name = value
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| Error::InvalidInput("volume missing 'name' field".to_string()))?
            .to_string();

        validate_name(&name, MAX_CONTAINER_NAME_LEN)?;

        let source = if value.get("emptyDir").is_some() {
            VolumeSource::EmptyDir
        } else if let Some(hp) = value.get("hostPath") {
            let path = hp
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| {
                    Error::InvalidInput(format!("hostPath volume '{}' missing 'path' field", name))
                })?
                .to_string();

            if path.contains("..") {
                return Err(Error::InvalidInput(format!(
                    "hostPath volume '{}' contains path traversal: {}",
                    name, path
                )));
            }

            if !path.starts_with('/') {
                return Err(Error::InvalidInput(format!(
                    "hostPath volume '{}' must be absolute path: {}",
                    name, path
                )));
            }

            VolumeSource::HostPath { path }
        } else if let Some(cm) = value.get("configMap") {
            let cm_name = cm
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| {
                    Error::InvalidInput(format!("configMap volume '{}' missing 'name' field", name))
                })?
                .to_string();
            VolumeSource::ConfigMap { name: cm_name }
        } else if let Some(secret) = value.get("secret") {
            let secret_name = secret
                .get("secretName")
                .and_then(|n| n.as_str())
                .ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "secret volume '{}' missing 'secretName' field",
                        name
                    ))
                })?
                .to_string();
            VolumeSource::Secret { name: secret_name }
        } else {
            VolumeSource::EmptyDir
        };

        Ok(Self { name, source })
    }
}

/// Volume source type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VolumeSource {
    /// Empty directory (ephemeral).
    EmptyDir,
    /// Host filesystem path.
    HostPath { path: String },
    /// ConfigMap reference.
    ConfigMap { name: String },
    /// Secret reference.
    Secret { name: String },
}

/// Resource requirements for a container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceRequirements {
    /// Memory limit in bytes.
    pub memory_bytes: u64,
    /// CPU shares (millicores, 1000 = 1 CPU).
    pub cpu_shares: u64,
}

// =============================================================================
// Resource Parsing Helpers
// =============================================================================

/// Parses Kubernetes memory strings to bytes.
fn parse_memory_string(s: &str) -> u64 {
    let s = s.trim();
    if let Some(val) = s.strip_suffix("Gi") {
        val.parse::<u64>()
            .unwrap_or(0)
            .saturating_mul(1024 * 1024 * 1024)
    } else if let Some(val) = s.strip_suffix("Mi") {
        val.parse::<u64>().unwrap_or(0).saturating_mul(1024 * 1024)
    } else if let Some(val) = s.strip_suffix("Ki") {
        val.parse::<u64>().unwrap_or(0).saturating_mul(1024)
    } else if let Some(val) = s.strip_suffix('G') {
        val.parse::<u64>()
            .unwrap_or(0)
            .saturating_mul(1_000_000_000)
    } else if let Some(val) = s.strip_suffix('M') {
        val.parse::<u64>().unwrap_or(0).saturating_mul(1_000_000)
    } else if let Some(val) = s.strip_suffix('K') {
        val.parse::<u64>().unwrap_or(0).saturating_mul(1_000)
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

/// Parses Kubernetes CPU strings to millicores.
fn parse_cpu_string(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    if let Some(val) = s.strip_suffix('m') {
        val.parse::<u64>().unwrap_or(0)
    } else if let Ok(cores) = s.parse::<f64>() {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let millicores = (cores * 1000.0) as u64;
        millicores
    } else {
        0
    }
}
