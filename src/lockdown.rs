// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

//! Lockdown primitives for confidential VM security.
//!
//! In production with #![no_std], the #[panic_handler] in main.rs handles
//! panics by powering off the VM. This module provides module loading lockdown.

use crate::error::{Context, Result};
use hardened_std::fs;

#[cfg(test)]
use hardened_std::panic as hardened_panic;

/// Placeholder for panic hook setup - actual handling done by #[panic_handler].
/// Returns Ok(()) for compatibility with existing call sites.
pub fn set_panic_hook() -> Result<()> {
    // In no_std mode, panic handling is done by #[panic_handler] in main.rs
    // This function exists for API compatibility during the transition
    Ok(())
}

/// Permanently disable kernel module loading for this boot.
/// Once all required GPU drivers are loaded, this prevents any further
/// module insertion—a security hardening measure for confidential VMs
/// that blocks potential kernel-level attacks via malicious modules.
/// This is a one-way operation: once set, it cannot be undone without reboot.
pub fn disable_modules_loading() -> Result<()> {
    const PATH: &str = "/proc/sys/kernel/modules_disabled";
    fs::write(PATH, b"1\n").context("disable module loading")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::require_root;

    #[test]
    #[ignore] // DANGEROUS: permanently disables module loading until reboot - only run in ephemeral VMs
    fn test_disable_modules_loading() {
        require_root();

        // This permanently disables module loading until reboot.
        // Only run on dedicated test runners!
        let result = disable_modules_loading();
        assert!(result.is_ok());

        // Verify it was set (use std::fs in tests to verify hardened_std wrote correctly)
        let content = std::fs::read_to_string("/proc/sys/kernel/modules_disabled").unwrap();
        assert_eq!(content.trim(), "1");
    }

    #[test]
    fn test_power_off_function_exists() {
        // Just verify power_off compiles - can't call it without rebooting!
        let _: fn() -> ! = hardened_panic::power_off;
    }

    #[test]
    fn test_set_panic_hook() {
        // In no_std mode, this is a no-op placeholder
        let result = set_panic_hook();
        assert!(result.is_ok());
    }
}
