// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

//! Panic handling for hardened environments
//!
//! Provides power-off function for VM shutdown using direct syscalls.
//! No std dependency - uses libc directly for all operations.

/// Format u32 to decimal string in provided buffer, returns slice with result.
/// Used for formatting line numbers in panic output.
pub fn format_u32(mut n: u32, buf: &mut [u8; 10]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[0..1];
    }

    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

/// Power off the VM immediately.
///
/// Uses the reboot syscall with LINUX_REBOOT_CMD_POWER_OFF.
/// This function never returns in production - it powers off the VM.
pub fn power_off() -> ! {
    // SAFETY: reboot() with POWER_OFF is safe - it cleanly shuts down the system
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }

    // Should never reach here, but if reboot fails somehow, loop forever
    loop {
        // SAFETY: pause() is always safe
        unsafe {
            libc::pause();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_u32() {
        let mut buf = [0u8; 10];

        assert_eq!(format_u32(0, &mut buf), b"0");
        assert_eq!(format_u32(1, &mut buf), b"1");
        assert_eq!(format_u32(42, &mut buf), b"42");
        assert_eq!(format_u32(12345, &mut buf), b"12345");
        assert_eq!(format_u32(4294967295, &mut buf), b"4294967295");
    }

    #[test]
    fn test_power_off_exists() {
        // Just verify it compiles - can't call it!
        let _: fn() -> ! = power_off;
    }
}
