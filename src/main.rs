// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

//! NVRC init binary - minimal init process for GPU-enabled confidential VMs.
//!
//! This is a #![no_std] binary that uses hardened_std for all security-restricted
//! operations. On panic, the VM is powered off to prevent undefined state.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

/// Panic handler - powers off the VM on panic.
/// In a confidential VM, a panic could leave the system in an undefined state
/// with potential data exposure. Power-off ensures clean termination.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Write panic info to stderr via direct libc
    let prefix = b"NVRC panic: ";
    unsafe {
        libc::write(
            libc::STDERR_FILENO,
            prefix.as_ptr() as *const libc::c_void,
            prefix.len(),
        );
    }

    // Write location if available
    if let Some(location) = info.location() {
        let file = location.file();
        let line = location.line();

        unsafe {
            libc::write(
                libc::STDERR_FILENO,
                file.as_ptr() as *const libc::c_void,
                file.len(),
            );
            libc::write(libc::STDERR_FILENO, b":".as_ptr() as *const libc::c_void, 1);
        }

        // Format line number
        let mut line_buf = [0u8; 10];
        let line_str = hardened_std::panic::format_u32(line, &mut line_buf);
        unsafe {
            libc::write(
                libc::STDERR_FILENO,
                line_str.as_ptr() as *const libc::c_void,
                line_str.len(),
            );
            libc::write(libc::STDERR_FILENO, b"\n".as_ptr() as *const libc::c_void, 1);
        }
    }

    // Sync and power off
    hardened_std::panic::power_off()
}

/// Global allocator using libc malloc/free
struct LibcAllocator;

unsafe impl core::alloc::GlobalAlloc for LibcAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        libc::memalign(layout.align(), layout.size()) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        libc::free(ptr as *mut libc::c_void)
    }
}

#[global_allocator]
static ALLOCATOR: LibcAllocator = LibcAllocator;

mod daemon;
mod error;
mod execute;
mod kata_agent;
mod kernel_params;
mod kmsg;
mod lockdown;
#[macro_use]
mod macros;
mod modprobe;
mod mount;
mod nvrc;
mod smi;
mod syslog;
mod toolkit;

#[cfg(test)]
mod test_utils;

#[macro_use]
extern crate log;

use hardened_std::collections::HashMap;

use kata_agent::SYSLOG_POLL_FOREVER as POLL_FOREVER;
use nvrc::NVRC;
use toolkit::nvidia_ctk_cdi;

type ModeFn = fn(&mut NVRC);

/// VMs with GPU passthrough need driver setup, clock tuning,
/// and monitoring daemons before workloads can use the GPU.
fn mode_gpu(init: &mut NVRC) {
    must!(modprobe::load("nvidia"));
    must!(modprobe::load("nvidia-uvm"));

    must!(init.nvidia_smi_lmc());
    must!(init.nvidia_smi_lgc());
    must!(init.nvidia_smi_pl());

    must!(init.nvidia_persistenced());

    must!(init.nv_hostengine());
    must!(init.dcgm_exporter());
    must!(init.nv_fabricmanager());
    must!(nvidia_ctk_cdi());
    must!(init.nvidia_smi_srs());
    must!(init.check_daemons());
}

/// NVSwitch NVL4 mode for HGX H100/H200/H800 systems (third-gen NVSwitch).
/// Service VM mode for NVLink 4.0 topologies in shared virtualization.
/// Loads NVIDIA driver and starts fabric manager. GPUs are assigned to service VM.
/// Automatically enables fabricmanager regardless of kernel parameters.
fn mode_nvswitch_nvl4(init: &mut NVRC) {
    // Override kernel parameter: always enable fabricmanager for nvswitch mode
    init.fabricmanager_enabled = Some(true);

    must!(modprobe::load("nvidia"));
    must!(init.nv_fabricmanager());
    must!(init.check_daemons());
}

/// NVSwitch NVL5 mode for HGX B200/B300/B100 systems (fourth-gen NVSwitch).
/// Service VM mode for NVLink 5.0 topologies with CX7 bridge devices.
/// Does NOT load nvidia driver (GPUs not attached to service VM).
/// Loads ib_umad for InfiniBand MAD access to CX7 bridges.
/// FM automatically starts NVLSM (NVLink Subnet Manager) internally.
/// Requires kernel 5.17+ and /dev/infiniband/umadX devices.
fn mode_nvswitch_nvl5(init: &mut NVRC) {
    // Override kernel parameter: always enable fabricmanager for nvswitch mode
    init.fabricmanager_enabled = Some(true);

    // Load InfiniBand user MAD module for CX7 bridge device access
    must!(modprobe::load("ib_umad"));
    must!(init.nv_fabricmanager());
    must!(init.check_daemons());
}

/// Entry point - called by C runtime startup code
#[no_mangle]
pub extern "C" fn main(_argc: isize, _argv: *const *const u8) -> isize {
    // Dispatch table allows adding new modes without touching control flow.
    let modes: HashMap<&str, ModeFn> = HashMap::from([
        ("gpu", mode_gpu as ModeFn),
        ("cpu", (|_| {}) as ModeFn),
        ("nvswitch-nvl4", mode_nvswitch_nvl4 as ModeFn),
        ("nvswitch-nvl5", mode_nvswitch_nvl5 as ModeFn),
    ]);

    must!(lockdown::set_panic_hook());
    let mut init = NVRC::default();
    must!(mount::setup());
    must!(kmsg::kernlog_setup());
    must!(syslog::poll());
    must!(mount::readonly("/"));
    must!(init.process_kernel_params(None));

    // Kernel param nvrc.mode selects runtime behavior; GPU is the safe default
    // since most users expect full GPU functionality.
    let mode = init.mode.as_deref().unwrap_or("gpu");
    let setup = modes.get(mode).copied().unwrap_or(mode_gpu);
    setup(&mut init);

    must!(lockdown::disable_modules_loading());
    must!(kata_agent::fork_agent(POLL_FOREVER));
    0
}
