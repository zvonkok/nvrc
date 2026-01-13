# NVRC Development Guide

**Read [ARCHITECTURE.md](ARCHITECTURE.md) first** to understand the security
model, threat landscape, and design rationale before making changes.

## Project Overview

NVRC is a minimal init process (PID 1) for ephemeral confidential VMs with
NVIDIA GPUs. It configures GPU resources, starts required daemons
(nvidia-persistenced, nv-hostengine, etc.), and hands off to kata-agent.

## Long-term Goal: no_std

The goal is to eventually run NVRC as `no_std`. We are slowly transitioning
by building `hardened_std` as our security-hardened std replacement. This
enables:

- Smaller binary size
- No libstd dependency (pure syscall interface)
- Reduced attack surface
- Better control over all system interactions

**no_std Transition Roadmap:**

1. [done] `hardened_std::fs` - File operations with path whitelisting
2. [done] `hardened_std::process` - Process execution with binary whitelisting
3. [done] `hardened_std::os::unix::net` - Unix sockets with path whitelisting
4. [done] Replace `std::sync::Once` with `once_cell` (no_std compatible)
5. [done] `hardened_std::fs::exists()` - Replace `std::path::Path::exists()`
6. [todo] Replace `std::panic` hook setup (may need custom impl)
7. [todo] Replace `std::os::fd::AsFd` (needed for nix poll integration)
8. [todo] Audit all dependencies for no_std compatibility

**Dependencies no_std status:**

- `anyhow` - yes, supports no_std (disable default features)
- `log` - yes, supports no_std
- `nix` - no, requires std (may need direct syscalls)
- `once_cell` - yes, supports no_std
- `rlimit` - needs investigation

## hardened_std

Security-hardened std replacement with whitelist-only access to filesystem,
processes, and sockets.

**Core Principles:**

- Fresh filesystem on every boot - if a path exists, it's an error (fail-fast)
- No `remove_file` - we setup clean state, not fix bad state
- Whitelist-only: paths, binaries, socket paths must be explicitly allowed
- Static arguments: `&'static str` only (no runtime injection)
- Minimal surface: implement only what NVRC actually needs
- Single-threaded: NVRC is PID 1 (init) with no threads - no thread::sleep, no
  mutexes, no thread-safe synchronization needed in production code

## Guidelines

1. **API Compatibility**: Keep std-compatible interfaces for easy exchange
2. **Tests**: Minimal meaningful coverage. Tests can use std.
3. **After completion**: Run `cargo fmt` and `cargo clippy`
