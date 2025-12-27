# magikrun

**Unified OCI Runtime for Containers, WebAssembly, and MicroVMs**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024_edition-orange.svg)]()
[![Crates.io](https://img.shields.io/crates/v/magikrun.svg)](https://crates.io/crates/magikrun)
[![Documentation](https://docs.rs/magikrun/badge.svg)](https://docs.rs/magikrun)

`magikrun` is a pure Rust OCI-compliant container runtime abstraction layer that provides:

- **OCI Runtime Spec compliance** for single-container operations (`create` → `start` → `kill` → `delete`)
- **Pod Runtime Interface (PRI)** for atomic pod deployment across heterogeneous isolation backends
- **Three isolation backends**: Native containers (Linux), MicroVMs (KVM/HVF), WebAssembly (cross-platform)
- **Security-first design** with comprehensive input validation, size limits, and timeout enforcement

## From CRI to PRI: Evolution of Container Interfaces

### The CRI Problem

Kubernetes introduced the **Container Runtime Interface (CRI)** to decouple from Docker. CRI treats pods as composite structures built step-by-step:

```
CRI Workflow:
─────────────────────────────────────────────────────────────────────
RunPodSandbox()           → Creates pause container + namespaces
CreateContainer(A)        → Prepares container A (not running)
StartContainer(A)         → Runs container A
CreateContainer(B)        → Prepares container B
StartContainer(B)         → Runs container B
...wait for user/health checks...
StopContainer(B)          → Graceful stop
StopContainer(A)          → Graceful stop  
RemoveContainer(B)        → Cleanup container B
RemoveContainer(A)        → Cleanup container A
StopPodSandbox()          → Stop pause container
RemovePodSandbox()        → Delete namespace holder
─────────────────────────────────────────────────────────────────────
             11+ API calls, intermediate failure states possible
```

**Problems with CRI:**
1. **Partial failure states**: What if `StartContainer(B)` fails after `A` is running?
2. **Complex rollback logic**: Kubelet must track and undo partial progress
3. **Race conditions**: Namespace sharing during step-by-step creation
4. **Overhead**: Multiple RPC round-trips per pod
5. **Impedance mismatch**: Pods are the scheduling unit, but CRI operates on containers

### The PRI Solution

**Pod Runtime Interface (PRI)** treats pods as the atomic unit of deployment:

```
PRI Workflow:
─────────────────────────────────────────────────────────────────────
run_pod(spec)             → RUNNING (all containers) or ERROR (nothing)
...pod lifecycle...
stop_pod(id, grace)       → Graceful shutdown
delete_pod(id)            → Complete cleanup
─────────────────────────────────────────────────────────────────────
             3 operations, no intermediate states
```

**PRI Properties:**
- **Atomic**: Either all containers start or none do (automatic rollback)
- **Stateless**: No orphaned resources on failure
- **Immutable**: Replace pods, don't repair them
- **Self-healing friendly**: Failed pod = delete + reschedule (simple!)

### Why Now?

Several factors make PRI the right approach today:

1. **MicroVMs**: Hardware VM isolation (KVM, Hypervisor.framework) provides natural atomicity—VM boot is all-or-nothing
2. **WASM**: WebAssembly runtimes create isolated stores atomically
3. **GitOps/Immutable Infrastructure**: Pods are cattle, not pets—replace don't repair
4. **Edge/IoT**: Simpler semantics reduce resource overhead
5. **Security**: Fewer intermediate states = smaller attack surface

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           magikrun                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                  Pod Runtime Interface (PRI)                  │  │
│  │        run_pod(spec) → stop_pod(id) → delete_pod(id)         │  │
│  │                                                               │  │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │  │
│  │   │ NativePod   │  │ MicroVmPod  │  │  WasmPod    │          │  │
│  │   │  Runtime    │  │  Runtime    │  │  Runtime    │          │  │
│  │   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │  │
│  │          │                │                │                  │  │
│  └──────────┼────────────────┼────────────────┼──────────────────┘  │
│             │ uses           │ uses           │ uses                │
│             ▼                ▼                ▼                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                  OCI Runtime (Single Container)               │  │
│  │         create(id, bundle) → start → kill → delete           │  │
│  │                                                               │  │
│  │   ┌──────────────┐ ┌──────────────┐ ┌───────────────────────┐ │  │
│  │   │NativeRuntime │ │  KrunRuntime │ │   WasmtimeRuntime     │ │  │
│  │   │   (youki)    │ │   (libkrun)  │ │     (wasmtime)        │ │  │
│  │   └──────────────┘ └──────────────┘ └───────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              │                                      │
│  ┌───────────────────────────┼───────────────────────────────────┐  │
│  │                   Image & Bundle Building                     │  │
│  │  OCI Registry → Layers → Rootfs + config.json                │  │
│  │  Path traversal │ Size limits │ TOCTOU-safe whiteouts        │  │
│  │  Symlink depth │ Hardlink validation │ Null-byte rejection   │  │
│  └───────────────────────────┼───────────────────────────────────┘  │
│                              │                                      │
│  ┌───────────────────────────┼───────────────────────────────────┐  │
│  │               Content-Addressed Storage                       │  │
│  │  SHA-256 verification │ Deduplication │ Atomic writes         │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Infra Framework                            │  │
│  │   Infra + InfraExtension (workplane, mesh, service discovery) │  │
│  │   Runs inside infra-container (same code: native & MicroVM)   │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Layer Relationships

| Layer | Uses | Purpose |
|-------|------|---------|
| **PRI (pod module)** | OCI Runtime | Atomic pod lifecycle with rollback |
| **OCI Runtime (runtime module)** | Bundle Builder, Storage | Single container lifecycle |
| **Image & Bundle (image module)** | Storage, Registry | Pull images, build OCI bundles |
| **Storage** | Filesystem | Content-addressed blob storage with SHA-256 verification |
| **Infra (infra module)** | — | Framework for infra-container binaries with extension model |
| **passt** | — | TCP/UDP/ICMP networking for MicroVMs |

## Module Structure

| Module | Description |
|--------|-------------|
| `image` | CRI ImageService pattern: pull images, build bundles (OciRuntime, Wasm, MicroVm) |
| `runtime` | OCI RuntimeService: single-container lifecycle (create/start/kill/delete/state) |
| `pod` | **PRI**: Atomic pod lifecycle with `PodRuntime` trait and exec/logs support |
| `infra` | Infra-container framework with extension model for workplane, mesh, service discovery |
| `passt` | MicroVM networking via passt (TCP forwarding, UDP for Korium, ICMP health probes) |

## OCI Runtimes (Single Container)

| Runtime | Platform | Backend | Isolation Level | Use Case |
|---------|----------|---------|-----------------|----------|
| `NativeRuntime` | Linux | youki (libcontainer/libcgroups) | Namespaces + cgroups v2 | Standard Linux containers |
| `KrunRuntime` | Linux/macOS | libkrun (krun-sys) | Hardware VM (KVM/HVF) | Untrusted workloads |
| `WasmtimeRuntime` | All | wasmtime + wasmtime-wasi | WASM sandbox + fuel limits | Portable plugins, edge |

These are the **building blocks** that PRI Pod Runtimes compose for atomic pod operations.

### OCI Runtime Operations

| Operation | Input | Effect |
|-----------|-------|--------|
| `create` | container ID, bundle path | Sets up container without starting |
| `start` | container ID | Executes the container process |
| `state` | container ID | Returns current container state |
| `kill` | container ID, signal | Sends signal to container process |
| `delete` | container ID | Removes container resources |

## Pod Runtimes (PRI)

| Runtime | Platform | Backend | Isolation | Atomicity |
|---------|----------|---------|-----------|-----------|
| `NativePodRuntime` | Linux | youki + pause | Namespaces + cgroups v2 | Emulated (rollback) |
| `MicroVmPodRuntime` | Linux/macOS | libkrun | Hardware VM (KVM/HVF) | Natural (VM boot) |
| `WasmPodRuntime` | All | wasmtime | WASM sandbox | Natural (store) |

### Atomicity Explained

**Native Pods** (emulated atomicity):
```
1. Create pause container (holds namespaces)
2. Start infra-container (joins namespaces)
3. Start app containers (join namespaces)
4. If any step fails → rollback all previous steps
5. Return success only when ALL running
```

**MicroVM Pods** (natural atomicity):
```
1. Build composite rootfs with all container images
2. Bake pod spec into VM filesystem
3. Boot VM (vminit spawns containers)
4. VM either boots completely or fails → nothing to clean up
```

**WASM Pods** (natural atomicity):
```
1. Create wasmtime Store (isolated memory)
2. Load all modules
3. Link and instantiate
4. If any fails → store is dropped, no leaks
```

## Bundle Formats

Different runtime backends require different bundle formats:

| Format | Contents | Runtime Backend | Use Case |
|--------|----------|-----------------|----------|
| `Bundle::OciRuntime` | `rootfs/` + `config.json` | `NativeRuntime` | Standard Linux containers |
| `Bundle::Wasm` | `module.wasm` + WASI config | `WasmtimeRuntime` | WebAssembly modules |
| `Bundle::MicroVm` | `rootfs/` + command/env | `KrunRuntime` | MicroVM guests |

The `BundleBuilder` automatically selects the appropriate format based on the target runtime.

## MicroVM Networking (passt)

MicroVMs use [passt](https://passt.top/) for TCP/UDP/ICMP networking:

```
┌─────────────────────────────────────────────────────────────────┐
│  Host                                                           │
│  ┌─────────────────────┐    ┌─────────────────────┐             │
│  │  MicroVmPodRuntime  │───▶│  passt              │             │
│  │  - Control channel  │    │  - TCP forwarding   │             │
│  │  - exec/logs        │    │  - UDP forwarding   │             │
│  └──────────┬──────────┘    │  - ICMP (ping)      │             │
│             │               └──────────┬──────────┘             │
│             ▼                          ▼                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  MicroVM (libkrun)                                       │   │
│  │  ┌────────────────────────────────────────────────────┐  │   │
│  │  │  vminit (PID 1) - Listens on TCP :1024             │  │   │
│  │  │  - Spawns containers from /containers/*/           │  │   │
│  │  │  - Control protocol: exec, logs, ping              │  │   │
│  │  └────────────────────────────────────────────────────┘  │   │
│  │  virtio-net (eth0) - Transparent TCP/UDP/ICMP            │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## The Infra-Container

Every pod has an **infra-container** that:
- Holds Linux namespaces (network, IPC, UTS) for other containers to join
- Runs workplane extensions (service discovery, Raft consensus, mesh)
- Provides the "pause" functionality but with active capabilities

### Extension Model

Extensions implement `InfraExtension` and hook into container lifecycle:

```rust
use magikrun::infra::{InfraExtension, InfraEvent, InfraContext};

struct WorkplaneExtension { /* ... */ }

#[async_trait]
impl InfraExtension for WorkplaneExtension {
    fn name(&self) -> &str { "workplane" }

    async fn on_start(&mut self, ctx: &InfraContext) -> ExtensionResult<()> {
        // Request Korium UDP port via passt
        ctx.request_udp_port(51820, 51820, self.name()).await?;
        Ok(())
    }

    async fn on_event(&mut self, event: &InfraEvent, ctx: &InfraContext) -> ExtensionResult<()> {
        match event {
            InfraEvent::ContainerStarted { name, .. } => { /* register container */ }
            _ => {}
        }
        Ok(())
    }
}
```

### Symmetric Design

The same infra-container code runs in both native and MicroVM modes:

```
Native Mode:                          MicroVM Mode:
─────────────────────────             ─────────────────────────────────────
                                      
┌─────────────────────────┐           ┌─────────────────────────────────────┐
│ Pod                     │           │ VM                                  │
│  ┌───────────────────┐  │           │  vminit (PID 1)                     │
│  │ infra-container   │  │           │  │ spawns containers                │
│  │  (workplane)      │  │           │  │ reaps zombies                    │
│  └───────────────────┘  │           │  │ forwards signals                 │
│  ┌───────────────────┐  │           │  │                                  │
│  │ app-container     │  │           │  ├─► infra-container (SAME CODE)    │
│  └───────────────────┘  │           │  └─► app-container                  │
└─────────────────────────┘           └─────────────────────────────────────┘
```

## Content-Addressed Storage

OCI layers are stored by cryptographic digest for deduplication and integrity:

```
~/.magikrun/blobs/
└── sha256/
    ├── ab/
    │   ├── abcd1234...  (blob content)
    │   └── ab9f8e7d...  (blob content)
    └── cd/
        └── cdef5678...  (blob content)
```

**Security properties:**
- **Digest verification**: Content hash verified before storage (prevents cache poisoning)
- **Atomic writes**: Temp file + rename pattern prevents partial/corrupted blobs
- **Path validation**: Only hexadecimal characters allowed in digests
- **Deduplication**: Same layer shared across images = one copy on disk

## Security Model

### Isolation Hierarchy (Defense-in-Depth)

```
┌───────────────────────────────────────────────────┐
│                  MicroVM                          │  ← Hardware VM boundary
│  ┌─────────────────────────────────────────────┐  │
│  │            Native Container                 │  │  ← Kernel namespace boundary
│  │  ┌───────────────────────────────────────┐  │  │
│  │  │              WASM                     │  │  │  ← Language sandbox boundary
│  │  └───────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────┘
```

| Runtime | Isolation Level | Attack Surface | Use Case |
|---------|-----------------|----------------|----------|
| `MicroVmPodRuntime` | Hardware VM | Minimal (VMM only) | Untrusted workloads |
| `NativePodRuntime` | Kernel namespaces | Kernel syscalls | Multi-tenant pods |
| `WasmPodRuntime` | WASM sandbox | WASI only | Portable plugins |

### Runtime Resource Limits

The `NativeRuntime` enforces resource limits at container creation time:

- **Container limit pre-check**: Rejects creation if `MAX_CONTAINERS` (1,024) already exist
- **Duplicate ID rejection**: Fails fast if container ID already exists
- **Container ID validation**: Validates ID length and character set before any state mutation

This ensures limit enforcement occurs **before** any resources are allocated, preventing
race conditions and resource leaks.

### Security Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_IMAGE_REF_LEN` | 512 bytes | Image reference length limit |
| `MAX_LAYER_SIZE` | 512 MiB | Per-layer compressed size limit |
| `MAX_ROOTFS_SIZE` | 4 GiB | Total extracted rootfs limit |
| `MAX_LAYERS` | 128 | Maximum layers per image |
| `MAX_FILES_PER_LAYER` | 100,000 | Inode exhaustion prevention |
| `MAX_MANIFEST_SIZE` | 1 MiB | Manifest parsing limit |
| `MAX_CONFIG_SIZE` | 1 MiB | Config blob parsing limit |
| `MAX_CONTAINERS` | 1,024 | Runtime container limit |
| `MAX_CONTAINER_ID_LEN` | 128 bytes | Container ID length limit |
| `MAX_WASM_MODULE_SIZE` | 256 MiB | WASM module size limit |
| `MAX_WASM_MEMORY_PAGES` | 65,536 | WASM memory limit (4 GiB) |
| `DEFAULT_WASM_FUEL` | 1B ops | WASM instruction limit |
| `MAX_VM_MEMORY_MIB` | 4,096 | MicroVM memory limit |
| `MAX_VCPUS` | 8 | MicroVM vCPU limit |
| `DEFAULT_MEMORY_BYTES` | 256 MiB | Default container memory |
| `MAX_MEMORY_BYTES` | 8 GiB | Maximum container memory |
| `IMAGE_PULL_TIMEOUT` | 300s | Network operation timeout |
| `CONTAINER_START_TIMEOUT` | 60s | Container start timeout |
| `DEFAULT_GRACE_PERIOD` | 30s | Shutdown grace period |
| `EXEC_TIMEOUT` | 300s | Exec command timeout |
| `MAX_INFLIGHT_BLOBS` | 256 | Concurrent download limit |

### Layer Extraction Security

OCI layer extraction enforces 8 security checks:

| Check | Protection |
|-------|------------|
| **Path traversal** | Rejects `..` components and absolute paths |
| **Symlink depth** | Max 40 levels with visited-path cycle detection |
| **Hardlink validation** | Same depth-tracking and path validation as symlinks |
| **Null-byte rejection** | Rejects paths containing `\0` |
| **Size limits** | `MAX_LAYER_SIZE`, `MAX_ROOTFS_SIZE`, `MAX_FILES_PER_LAYER` |
| **Whiteout handling** | TOCTOU-safe using `symlink_metadata()` |
| **File count limits** | `MAX_FILES_PER_LAYER` per layer |
| **Atomic extraction** | Failures don't leave partial state |

## Usage

### PRI (Recommended)

```rust
use magikrun::pod::{PodRuntime, PodSpec, NativePodRuntime};
use std::time::Duration;

#[tokio::main]
async fn main() -> magikrun::Result<()> {
    let runtime = NativePodRuntime::new()?;
    
    // Parse K8s-compatible pod manifest
    let spec = PodSpec::from_yaml(include_bytes!("pod.yaml"))?;
    
    // Atomic: either fully running or error (nothing created)
    let handle = runtime.run_pod(&spec).await?;
    println!("Pod {} running", handle.id);
    
    // Check status
    let status = runtime.pod_status(&handle.id).await?;
    println!("Phase: {:?}", status.phase);
    
    // Graceful stop with 30s grace period
    runtime.stop_pod(&handle.id, Duration::from_secs(30)).await?;
    runtime.delete_pod(&handle.id, false).await?;
    
    Ok(())
}
```

### OCI Runtime (Low-Level)

```rust
use magikrun::image::{ImageService, BundleBuilder, OciContainerConfig};
use magikrun::runtime::{NativeRuntime, OciRuntime};

#[tokio::main]
async fn main() -> magikrun::Result<()> {
    // CRI ImageService pattern
    let image_service = ImageService::new()?;
    let bundle_builder = BundleBuilder::with_storage(image_service.storage().clone())?;
    
    // Pull image
    let image = image_service.pull("alpine:3.18").await?;
    
    // Build OCI bundle
    let bundle = bundle_builder.build_oci_bundle(&image, &OciContainerConfig {
        name: "my-container".to_string(),
        command: Some(vec!["/bin/sh".to_string()]),
        ..Default::default()
    })?;
    
    // OCI lifecycle
    let runtime = NativeRuntime::new();
    runtime.create("my-container", bundle.path()).await?;
    runtime.start("my-container").await?;
    // ... later ...
    runtime.kill("my-container", magikrun::runtime::Signal::Term).await?;
    runtime.delete("my-container").await?;
    
    Ok(())
}
```

## Binaries

| Binary | Location | Purpose |
|--------|----------|---------|
| `magikrun` | Host | OCI runtime CLI, image management |
| `vminit` | VM `/init` | Minimal init for MicroVMs (PID 1, Linux only) |

### vminit

The `vminit` binary runs as PID 1 inside MicroVMs. It:
- Reads baked pod spec from `/pod/spec.json`
- Spawns containers using libcontainer
- Reaps zombie processes
- Forwards signals (SIGTERM, SIGINT) to containers
- Listens on TCP :1024 for control protocol (exec/logs/ping)

```bash
# Build static binary for VMs (requires vminit feature and Linux target)
cargo build --release --bin vminit --features vminit --target x86_64-unknown-linux-musl
```

## Platform Support

| Capability | Linux | macOS | Windows | Detection Method |
|------------|:-----:|:-----:|:-------:|------------------|
| Native containers | ✅ | ❌ | ❌ | `/proc/self/ns/pid` exists |
| Cgroups v2 | ✅ | ❌ | ❌ | `/sys/fs/cgroup/cgroup.controllers` |
| Seccomp | ✅ | ❌ | ❌ | `/proc/self/seccomp` or sysctl |
| MicroVMs (KVM) | ✅ | ❌ | ❌ | `/dev/kvm` accessible |
| MicroVMs (HVF) | ❌ | ✅ | ❌ | `kern.hv_support` sysctl |
| WASM | ✅ | ✅ | ✅ | Always available (pure Rust) |

### Platform Detection

Use `Platform::detect()` to discover available capabilities:

```rust
use magikrun::image::{Platform, Capability};

let platform = Platform::detect();
println!("OS: {:?}, Arch: {:?}", platform.os, platform.arch);
println!("OCI platform: {}", platform.oci_platform()); // e.g., "linux/amd64"

if platform.supports_native_containers() {
    println!("NativeRuntime available");
}
if platform.has_hypervisor() {
    println!("KrunRuntime available (hardware VM)");
}
// WASM is always available
assert!(platform.capabilities.contains(&Capability::WasmRuntime));
```

## Dependencies

### Core
- `tokio` (1.x) - Async runtime with rt-multi-thread, fs, process, sync, time
- `async-trait` (0.1) - Async trait definitions
- `serde` / `serde_json` / `serde_yaml` (0.9) - Serialization (YAML for K8s Pod manifests)
- `thiserror` (2.x) - Structured error handling
- `tracing` (0.1) - Structured logging and observability

### OCI
- `oci-spec` (0.8) - OCI image manifest types
- `oci-distribution` (0.11) - Registry client with digest verification

### Runtimes
- `libcontainer` / `libcgroups` (0.5) - youki container runtime, Linux only (RUSTSEC-2024-0437 fix)
- `wasmtime` / `wasmtime-wasi` (40) - WASM execution (RUSTSEC-2025-0118, RUSTSEC-2025-0046 fixes)
- `krun-sys` (1.10) - libkrun FFI bindings, Linux/macOS only

### Security
- `sha2` (0.10) / `hex` (0.4) - Content-addressed hashing with SHA-256 verification
- `flate2` (1.x) / `tar` (0.4) - Bounded layer extraction with size limits

### Utilities
- `uuid` (1.x, v7) - UUIDv7 generation for container IDs
- `chrono` (0.4) - Timestamps
- `dirs` (6.x) - Platform-appropriate path resolution
- `futures` (0.3) - Async utilities
- `libc` (0.2) - System interfaces

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `testing` | Exposes internal APIs for security testing (layer extraction) | Off |
| `vminit` | Builds the vminit binary (Linux only, requires additional deps) | Off |

## Testing

```bash
# Library tests only (fast)
cargo test --lib

# All tests including integration
cargo test

# Bundle security tests (path traversal, symlinks, hardlinks, etc.)
cargo test --features testing

# With verbose output
cargo test -- --nocapture
```

## OCI Spec Compliance

| Spec | Version | Notes |
|------|---------|-------|
| OCI Runtime Spec | 1.0.2 | Full lifecycle support (create/start/kill/delete/state) |
| OCI Image Spec | 1.0.2 | Multi-platform manifests, gzip/zstd layers |
| OCI Distribution Spec | — | Via `oci-distribution` crate |

## Error Handling

All operations return `magikrun::Result<T>` with structured error types:

| Category | Error Variants | Recovery Strategy |
|----------|----------------|-------------------|
| Container Lifecycle | `ContainerNotFound`, `CreateFailed`, `InvalidState` | Retry or cleanup |
| Image/Registry | `ImagePullFailed`, `PathTraversal`, `ImageTooLarge` | Check image ref, network |
| Bundle | `BundleBuildFailed`, `InvalidBundle` | Rebuild from image |
| Runtime | `RuntimeUnavailable`, `NotSupported` | Select different runtime |
| Storage | `BlobNotFound`, `DigestMismatch` | Check disk space, re-pull |
| Timeout | `Timeout` | Retry with backoff |

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
