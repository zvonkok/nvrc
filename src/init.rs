// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

use crate::hash;

/// NVRC's init duties (mounts, module loads, daemon forks, the poweroff panic
/// hook) would wreck a normal host, so they must only run as PID 1. Anywhere
/// else (CI smoke test, dev shell) report identity and exit before the caller
/// touches anything.
pub fn as_pid1() {
    if running_as_init() {
        return;
    }
    // No logger on this path, so print to stdout rather than via the dropped
    // log macros; this is the CI smoke test's only observable output.
    println!("{}", hash::version_line());
    std::process::exit(0);
}

// Raw SYS_getpid syscall: stays on the pure-syscall path hardened_std targets,
// and needs no /proc (unmounted this early, mount::setup runs later).
fn running_as_init() -> bool {
    unsafe { libc::syscall(libc::SYS_getpid) == 1 }
}
