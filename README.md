# magikrun

**OCI-Compliant Container Runtime Abstraction Layer**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024_edition-orange.svg)]()

`magikrun` provides a pure OCI Runtime Spec compliant interface for container operations across heterogeneous isolation backends. It handles single-container operations only—pod semantics (shared namespaces, pause containers) are delegated to the higher-level [`magikpod`](../magikpod) crate.

## Runtime Flavours Matrix

| Runtime           | Linux | macOS | Windows | Isolation Technology       | Bundle Format         |
|-------------------|:-----:|:-----:|:-------:|----------------------------|-----------------------|
| **YoukiRuntime**  |   ✅  |   ❌  |   ❌    | Namespaces + cgroups v2    | `Bundle::OciRuntime`  |
| **WasmtimeRuntime**|  ✅  |   ✅  |   ✅    | WASM sandbox + WASI        | `Bundle::Wasm`        |
| **KrunRuntime**   |   ✅  |   ✅  |   ❌    | MicroVM (KVM / HVF)        | `Bundle::MicroVm`     |

### At a Glance

| Aspect           | YoukiRuntime              | WasmtimeRuntime           | KrunRuntime                |
|------------------|---------------------------|---------------------------|----------------------------|
| **Use Case**     | Production containers     | Portable plugins          | Untrusted workloads        |
| **Isolation**    | Kernel namespaces         | Language-level sandbox    | Hardware VM boundary       |
| **Startup**      | ~50ms                     | ~5ms                      | ~100ms                     |
| **Memory**       | Shared with host (cgroup) | 4 GiB max (WASM pages)    | 4 GiB max (VM allocation)  |
| **CPU Limit**    | cgroups v2                | Fuel (1B ops default)     | vCPUs (8 max)              |
| **Networking**   | Native Linux netns        | WASI sockets (limited)    | virtio-net (full stack)    |
| **Filesystem**   | Native rootfs             | WASI preopens only        | virtio-fs                  |
| **Dependencies** | libcontainer/libcgroups   | Pure Rust (wasmtime)      | libkrun (FFI)              |

### Platform Detection

`magikrun` automatically detects available capabilities at runtime:

| Capability        | Detection Method                              | Required For      |
|-------------------|-----------------------------------------------|-------------------|
| Namespaces        | `/proc/self/ns/*` availability                | YoukiRuntime      |
| cgroups v2        | `/sys/fs/cgroup/cgroup.controllers` presence  | YoukiRuntime      |
| Seccomp           | `prctl(PR_GET_SECCOMP)` support               | YoukiRuntime      |
| KVM               | `/dev/kvm` device node                        | KrunRuntime       |
| Hypervisor.framework | `sysctl kern.hv_support`                   | KrunRuntime       |
| WASM Runtime      | Always available (compiled-in wasmtime)       | WasmtimeRuntime   |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           magikrun                                  │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    OciRuntime Trait                         │    │
│  │    create(id, bundle) → start(id) → kill(id) → delete(id)  │    │
│  │                         state(id)                           │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                      │
│  ┌───────────────────────────┼───────────────────────────────┐      │
│  │                   Bundle Building                         │      │
│  │  OCI Image → Layers → Rootfs + config.json                │      │
│  │  Path traversal protection │ Size limits │ Whiteout files │      │
│  └───────────────────────────┼───────────────────────────────┘      │
│                              │                                      │
│  ┌───────────────────────────┼───────────────────────────────┐      │
│  │               Content-Addressed Storage                   │      │
│  │  Digest verification │ Deduplication │ Atomic writes      │      │
│  └───────────────────────────────────────────────────────────┘      │
├─────────────────────────────────────────────────────────────────────┤
│                      Runtime Backends                               │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────┐              │
│  │ YoukiRuntime │  │WasmtimeRuntime│  │  KrunRuntime │              │
│  │   (Linux)    │  │  (Cross-plat) │  │   (MicroVM)  │              │
│  │  Namespaces  │  │  WASI + Fuel  │  │  KVM / HVF   │              │
│  │  Cgroups v2  │  │  256MB limit  │  │   4GB limit  │              │
│  └──────────────┘  └───────────────┘  └──────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

## OCI Runtime Spec Compliance

Implements the [OCI Runtime Spec](https://github.com/opencontainers/runtime-spec) container lifecycle:

```
                   ┌──────────────────────────────────────────────┐
                   │                                              │
                   ▼                                              │
  ┌─────────┐   create   ┌─────────┐   start   ┌─────────┐       │
  │ (none)  │ ─────────► │ Created │ ────────► │ Running │       │
  └─────────┘            └─────────┘           └────┬────┘       │
                              │                     │            │
                              │ delete              │ kill       │
                              │ (if created)        │            │
                              ▼                     ▼            │
                         ┌─────────┐           ┌─────────┐       │
                         │ Deleted │ ◄──────── │ Stopped │ ──────┘
                         └─────────┘  delete   └─────────┘
```

### Core Operations

| Operation | Input                 | Effect                              |
|-----------|-----------------------|-------------------------------------|
| `create`  | container ID, bundle  | Sets up container without starting  |
| `start`   | container ID          | Executes the container process      |
| `state`   | container ID          | Returns current container state     |
| `kill`    | container ID, signal  | Sends signal to container process   |
| `delete`  | container ID          | Removes container resources         |

## Runtime Backends

| Runtime           | Platform       | Isolation            | Use Case              |
|-------------------|----------------|----------------------|-----------------------|
| `YoukiRuntime`    | Linux only     | Namespaces + cgroups | Production containers |
| `WasmtimeRuntime` | Cross-platform | WASM sandbox         | Portable plugins      |
| `KrunRuntime`     | Linux/macOS    | Hardware VM (KVM/HVF)| Untrusted workloads   |

### Isolation Hierarchy

Defense-in-depth with layered isolation:

```
┌───────────────────────────────────────────────────┐
│                  KrunRuntime                      │  ← Hardware VM boundary
│  ┌─────────────────────────────────────────────┐  │
│  │              YoukiRuntime                   │  │  ← Kernel namespace boundary
│  │  ┌───────────────────────────────────────┐  │  │
│  │  │         WasmtimeRuntime               │  │  │  ← WASM sandbox boundary
│  │  │                                       │  │  │
│  │  └───────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────┘
```

## Security Model

### Key Security Properties

- **Path Traversal Protection**: All tar extraction validates paths against `..` components and absolute paths
- **Size Limits**: Bounded constants prevent resource exhaustion
- **Digest Verification**: Content-addressed storage verifies SHA-256 before storing blobs
- **Fuel Limits**: WASM execution bounded by instruction count
- **Timeouts**: All network operations bounded

### Security Constants

| Constant               | Value    | Purpose                          |
|------------------------|----------|----------------------------------|
| `MAX_LAYER_SIZE`       | 512 MiB  | Per-layer size limit             |
| `MAX_ROOTFS_SIZE`      | 4 GiB    | Total rootfs size limit          |
| `MAX_LAYERS`           | 128      | Maximum layers per image         |
| `MAX_WASM_MODULE_SIZE` | 256 MiB  | WASM module size limit           |
| `MAX_WASM_MEMORY_PAGES`| 65,536   | WASM memory limit (4 GiB)        |
| `DEFAULT_WASM_FUEL`    | 1B ops   | WASM instruction limit           |
| `MAX_VM_MEMORY_MIB`    | 4,096    | MicroVM memory limit             |
| `MAX_VCPUS`            | 8        | MicroVM vCPU limit               |
| `IMAGE_PULL_TIMEOUT`   | 300s     | Registry pull timeout            |
| `CONTAINER_START_TIMEOUT` | 60s   | Container start timeout          |

## Usage

### Add Dependency

```toml
[dependencies]
magikrun = "0.1"
```

### Example

```rust
use magikrun::{Platform, BlobStore, pull_image, BundleBuilder};
use magikrun::runtimes::RuntimeRegistry;

#[tokio::main]
async fn main() -> magikrun::Result<()> {
    // Detect platform and available runtimes
    let platform = Platform::detect();
    let registry = RuntimeRegistry::new(&platform)?;
    
    // List available runtimes
    for name in registry.available_runtimes() {
        println!("Available: {}", name);
    }

    // Pull image and store layers
    let storage = std::sync::Arc::new(BlobStore::new()?);
    let image = pull_image("alpine:3.18", &storage).await?;
    
    // Build OCI bundle
    let builder = BundleBuilder::new()?;
    let bundle = builder
        .image(&image)
        .storage(&storage)
        .build()
        .await?;
    
    // Get a runtime and run container
    if let Some(runtime) = registry.get("wasmtime") {
        runtime.create("my-container", &bundle).await?;
        runtime.start("my-container").await?;
        
        // Check state
        let state = runtime.state("my-container").await?;
        println!("Status: {:?}", state.status);
        
        // Cleanup
        runtime.kill("my-container", magikrun::Signal::Term).await?;
        runtime.delete("my-container").await?;
    }
    
    Ok(())
}
```

## No Pod Semantics

This crate intentionally excludes pod-level concepts. Each container is independent. For namespace sharing and pod orchestration, use [`magikpod`](../magikpod) which configures namespace paths in `config.json`:

```json
{
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "network", "path": "/proc/1234/ns/net" }
    ]
  }
}
```

## Bundle Formats

| Format              | Contents                        | Runtime           |
|---------------------|---------------------------------|-------------------|
| `Bundle::OciRuntime`| rootfs + config.json            | YoukiRuntime      |
| `Bundle::Wasm`      | .wasm module + WASI config      | WasmtimeRuntime   |
| `Bundle::MicroVm`   | rootfs + command/env            | KrunRuntime       |

## Platform Detection

```rust
use magikrun::{Platform, Capability};

let platform = Platform::detect();

// Check OS and architecture
println!("OS: {}, Arch: {}", platform.os, platform.arch);

// Check available capabilities
if platform.has_capability(Capability::Namespaces) {
    println!("Linux containers available");
}

if platform.has_capability(Capability::Hypervisor) {
    println!("MicroVM isolation available");
}

// WASM is always available
assert!(platform.has_capability(Capability::WasmRuntime));
```

## Content-Addressed Storage

The `BlobStore` provides secure, deduplicated storage for OCI layers:

```rust
use magikrun::BlobStore;
use sha2::{Sha256, Digest};

let store = BlobStore::new()?;

// Store with automatic verification
let data = b"layer content";
let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));
store.put_blob(&digest, data)?;

// Retrieve
let retrieved = store.get_blob(&digest)?;
assert_eq!(retrieved, data);

// Deduplication: same content = same digest = one copy on disk
```

### Storage Layout

```
~/.magik-oci/blobs/
└── sha256/
    ├── ab/
    │   ├── abcd1234...  (blob content)
    │   └── ab9f8e7d...  (blob content)
    └── cd/
        └── cdef5678...  (blob content)
```

## Testing

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test file
cargo test --test storage_tests
```

### Test Coverage

- **130 tests** covering:
  - Security-critical constants validation
  - Error message formatting
  - Platform detection logic
  - Container state serialization (OCI spec compliance)
  - Runtime registry and availability
  - Blob storage operations

## Dependencies

### Core
- `tokio` - Async runtime
- `async-trait` - Async trait definitions
- `serde` / `serde_json` - Serialization

### OCI
- `oci-spec` - OCI image manifest types
- `oci-distribution` - Registry client

### Runtimes
- `wasmtime` / `wasmtime-wasi` - WASM execution (v27)
- `krun-sys` - libkrun FFI bindings (v1.10)
- `libcontainer` / `libcgroups` - youki runtime (Linux, cgroups v2)

### Security
- `sha2` / `hex` - Content-addressed hashing
- `flate2` / `tar` - Layer extraction with bounds checking

## License

Apache-2.0. See [LICENSE](LICENSE) for details.

This project uses runtime backends (youki, wasmtime, libkrun) and OCI libraries that are also Apache-2.0 licensed.

## Related Projects

- [`magikpod`](../magikpod) - Pod-level orchestration with namespace sharing
- [`magik`](../magik) - Decentralized workload orchestration
- [`korium`](../korium) - P2P mesh networking
