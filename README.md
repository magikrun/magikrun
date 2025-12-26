# magikrun

**OCI-Compliant Container Runtime with Pod Runtime Interface (PRI)**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024_edition-orange.svg)]()
[![Crates.io](https://img.shields.io/crates/v/magikrun.svg)](https://crates.io/crates/magikrun)
[![Documentation](https://docs.rs/magikrun/badge.svg)](https://docs.rs/magikrun)

`magikrun` is a container runtime abstraction layer that provides both OCI Runtime Spec compliance and a novel **Pod Runtime Interface (PRI)** for atomic pod operations across heterogeneous isolation backends.

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
│  │  Path traversal protection │ Size limits │ Whiteout handling │  │
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
| **Storage** | Filesystem | Content-addressed blob storage |
| **Infra (infra module)** | — | Framework for infra-container binaries |

## Module Structure

| Module | Description |
|--------|-------------|
| `image` | CRI ImageService pattern: pull images, build bundles |
| `runtime` | OCI RuntimeService: single-container lifecycle (create/start/kill/delete) |
| `pod` | **PRI**: Atomic pod lifecycle with `PodRuntime` trait |
| `infra` | Infra-container framework for extensions (workplane, mesh) |

## OCI Runtimes (Single Container)

| Runtime | Platform | Backend | Use Case |
|---------|----------|---------|----------|
| `NativeRuntime` | Linux | youki (libcontainer) | Standard Linux containers |
| `KrunRuntime` | Linux/macOS | libkrun | MicroVM-isolated containers |
| `WasmtimeRuntime` | All | wasmtime | WASM/WASI workloads |
| `WindowsRuntime` | Windows | (stub) | Windows container support |

These are the **building blocks** that PRI Pod Runtimes compose for atomic pod operations.

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

## The Infra-Container

Every pod has an **infra-container** that:
- Holds Linux namespaces (network, IPC, UTS) for other containers to join
- Runs workplane extensions (service discovery, Raft consensus, mesh)
- Provides the "pause" functionality but with active capabilities

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

### Security Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_LAYER_SIZE` | 512 MiB | Per-layer extraction limit |
| `MAX_ROOTFS_SIZE` | 4 GiB | Total rootfs size limit |
| `MAX_LAYERS` | 128 | Maximum layers per image |
| `MAX_CONTAINERS_PER_POD` | 16 | Pod container limit |
| `MAX_WASM_MODULE_SIZE` | 256 MiB | WASM module limit |
| `DEFAULT_WASM_FUEL` | 1B ops | WASM instruction limit |
| `MAX_VM_MEMORY_MIB` | 4,096 | MicroVM memory limit |
| `MAX_VCPUS` | 8 | MicroVM vCPU limit |
| `IMAGE_PULL_TIMEOUT` | 300s | Registry timeout |

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
| `vminit` | VM `/init` | Minimal init for MicroVMs (PID 1) |

### vminit

The `vminit` binary runs as PID 1 inside MicroVMs. It:
- Reads baked pod spec from `/pod/spec.json`
- Spawns containers using libcontainer
- Reaps zombie processes
- Forwards signals (SIGTERM, SIGINT) to containers
- Handles TSI (exec/logs) requests via vsock

```bash
# Build static binary for VMs
cargo build --release --bin vminit --target x86_64-unknown-linux-musl
```

## Platform Support

| Capability | Linux | macOS | Windows | Detection |
|------------|:-----:|:-----:|:-------:|-----------|
| Native containers | ✅ | ❌ | ❌ | `/proc/self/ns/*` |
| MicroVMs | ✅ (KVM) | ✅ (HVF) | ❌ | `/dev/kvm` or `kern.hv_support` |
| WASM | ✅ | ✅ | ✅ | Always available |
| cgroups v2 | ✅ | ❌ | ❌ | `/sys/fs/cgroup/cgroup.controllers` |

## Dependencies

### Core
- `tokio` (1.x) - Async runtime
- `async-trait` - Async trait definitions
- `serde` / `serde_json` - Serialization

### OCI
- `oci-spec` (0.8) - OCI image manifest types
- `oci-distribution` (0.11) - Registry client

### Runtimes
- `libcontainer` / `libcgroups` (0.4) - youki container runtime
- `wasmtime` / `wasmtime-wasi` (27) - WASM execution
- `krun-sys` (1.10) - libkrun FFI bindings

### Security
- `sha2` / `hex` - Content-addressed hashing
- `flate2` / `tar` - Bounded layer extraction

## Testing

```bash
# Library tests only (fast)
cargo test --lib

# All tests including integration
cargo test

# With verbose output
cargo test -- --nocapture
```

## License

Apache-2.0. See [LICENSE](LICENSE) for details.

## Related Projects

- [`magikpod`](../magikpod) - Pod orchestration with K8s manifest support
- [`magik`](../magik) - Decentralized workload orchestration (machineplane + workplane)
- [`korium`](../korium) - P2P mesh networking (Kademlia DHT, GossipSub, QUIC/mTLS)
