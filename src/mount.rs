// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

//! Filesystem setup for the minimal init environment.

extern crate alloc;

use crate::anyhow;
use crate::error::{Context, Result};
use alloc::ffi::CString;
use alloc::format;
use hardened_std::fs;

/// Mount flags - subset of MS_* flags we actually use
mod flags {
    pub const MS_NOSUID: libc::c_ulong = 2;
    pub const MS_NODEV: libc::c_ulong = 4;
    pub const MS_NOEXEC: libc::c_ulong = 8;
    pub const MS_REMOUNT: libc::c_ulong = 32;
    pub const MS_RELATIME: libc::c_ulong = 1 << 21;
    pub const MS_RDONLY: libc::c_ulong = 1;
}

/// Mount a filesystem. Errors if mount fails.
fn mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    // Convert strings to C strings (null-terminated)
    let source_cstr = CString::new(source).unwrap();
    let target_cstr = CString::new(target).unwrap();
    let fstype_cstr = CString::new(fstype).unwrap();
    let data_cstr = data.map(|d| CString::new(d).unwrap());

    let data_ptr = data_cstr
        .as_ref()
        .map(|c| c.as_ptr() as *const libc::c_void)
        .unwrap_or(core::ptr::null());

    // SAFETY: mount() syscall with valid pointers
    let ret = unsafe {
        libc::mount(
            source_cstr.as_ptr(),
            target_cstr.as_ptr(),
            fstype_cstr.as_ptr(),
            flags,
            data_ptr,
        )
    };

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(anyhow!("mount {} on {}: errno {}", source, target, errno));
    }
    Ok(())
}

/// Remount a filesystem as read-only.
/// Security hardening: prevents writes to the root filesystem after init,
/// reducing attack surface in the confidential VM.
pub fn readonly(target: &str) -> Result<()> {
    let flags = flags::MS_NOSUID | flags::MS_NODEV | flags::MS_RDONLY | flags::MS_REMOUNT;

    let target_cstr = CString::new(target).unwrap();

    // SAFETY: mount() with MS_REMOUNT doesn't need source/fstype
    let ret = unsafe {
        libc::mount(
            core::ptr::null(),
            target_cstr.as_ptr(),
            core::ptr::null(),
            flags,
            core::ptr::null(),
        )
    };

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(anyhow!("remount {} readonly: errno {}", target, errno));
    }
    Ok(())
}

/// Check if a filesystem type is available in the kernel.
fn fs_available(filesystems: &str, fstype: &str) -> bool {
    filesystems.lines().any(|line| line.contains(fstype))
}

/// Mount optional filesystem if the fstype is available AND the target exists.
/// Used for securityfs and efivarfs that may not be present on all kernels.
fn mount_optional(
    filesystems: &str,
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
) -> Result<()> {
    if fs_available(filesystems, fstype) && fs::exists(target) {
        mount(source, target, fstype, flags, None)?;
    }
    Ok(())
}

// Previously, we manually created:
// 1. Device nodes with mknod():
//    - /dev/null (major 1, minor 3) - mode 0666
//    - /dev/zero (major 1, minor 5)
//    - /dev/random (major 1, minor 8)
//    - /dev/urandom (major 1, minor 9)
//
// 2. Symlinks with ln():
//    - /dev/core -> /proc/kcore
//    - /dev/fd -> /proc/self/fd
//    - /dev/stdin -> /proc/self/fd/0
//    - /dev/stdout -> /proc/self/fd/1
//    - /dev/stderr -> /proc/self/fd/2
//
// However, devtmpfs automatically creates these nodes when we mount it!
//
// How it works:
// 1. The kernel's mem driver (drivers/char/mem.c) calls device_create()
//    during kernel initialization for each standard character device
// 2. device_create() registers the device with devtmpfs
// 3. When we mount devtmpfs the kernel populates it with ALL registered
//    devices, including /dev/null, /dev/zero, etc.
// 4. Nodes are created with default permissions (e.g., /dev/null is 0666)
//
// Note: CONFIG_DEVTMPFS_MOUNT=y auto-mounts devtmpfs at boot for regular
// init systems, but in our case (kata with initrd), NVRC explicitly mounts
// devtmpfs below. Either way, the mount operation triggers node creation.
//
// References:
// - Kernel source: drivers/char/mem.c (mem driver registration)
// - Kernel source: drivers/base/devtmpfs.c (automatic node creation)
// - LWN article: https://lwn.net/Articles/330985/
//
// This is why we removed the device_nodes() function - it was redundant
// and caused "path already exists" errors with our fail-fast mknod().

/// Set up the minimal filesystem hierarchy required for GPU initialization.
/// Creates /proc, /dev, /sys, /run, /tmp mounts and essential device nodes.
pub fn setup() -> Result<()> {
    setup_at("")
}

/// Internal: setup with configurable root path (for testing with temp directories).
fn setup_at(root: &str) -> Result<()> {
    let common = flags::MS_NOSUID | flags::MS_NOEXEC | flags::MS_NODEV | flags::MS_RELATIME;

    mount("proc", &format!("{root}/proc"), "proc", common, None)?;

    let dev_flags = flags::MS_NOSUID | flags::MS_NOEXEC | flags::MS_RELATIME;
    mount(
        "dev",
        &format!("{root}/dev"),
        "devtmpfs",
        dev_flags,
        Some("mode=0755"),
    )?;

    mount("sysfs", &format!("{root}/sys"), "sysfs", common, None)?;
    mount(
        "run",
        &format!("{root}/run"),
        "tmpfs",
        common,
        Some("mode=0755"),
    )?;

    let tmp_flags = flags::MS_NOSUID | flags::MS_NODEV | flags::MS_RELATIME;
    mount("tmpfs", &format!("{root}/tmp"), "tmpfs", tmp_flags, None)?;

    // Read once for all optional mounts
    let filesystems = fs::read_to_string("/proc/filesystems").context("read /proc/filesystems")?;

    mount_optional(
        &filesystems,
        "securityfs",
        &format!("{root}/sys/kernel/security"),
        "securityfs",
        common,
    )?;
    mount_optional(
        &filesystems,
        "efivarfs",
        &format!("{root}/sys/firmware/efi/efivars"),
        "efivarfs",
        common,
    )?;

    // devtmpfs automatically creates:
    // 1. Standard device nodes: /dev/null, /dev/zero, /dev/random, /dev/urandom
    // 2. Standard symlinks: /dev/core -> /proc/kcore, /dev/fd -> /proc/self/fd,
    //    /dev/stdin -> /proc/self/fd/0, /dev/stdout -> /proc/self/fd/1, /dev/stderr -> /proc/self/fd/2
    // No need to manually create them with mknod() or ln()
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // === fs_available tests ===

    #[test]
    fn test_fs_available() {
        let filesystems = std::fs::read_to_string("/proc/filesystems").unwrap();
        assert!(fs_available(&filesystems, "proc"));
        assert!(fs_available(&filesystems, "sysfs"));
        assert!(fs_available(&filesystems, "tmpfs"));
        assert!(!fs_available(&filesystems, "nonexistent_fs"));
    }

    #[test]
    fn test_fs_available_empty() {
        assert!(!fs_available("", "proc"));
        assert!(!fs_available("", "tmpfs"));
    }

    // === mount_optional tests ===

    #[test]
    fn test_mount_optional_target_not_exists() {
        // When target path doesn't exist, should be no-op
        let filesystems = "nodev tmpfs\n";
        let result = mount_optional(filesystems, "tmpfs", "/nonexistent/path", "tmpfs", 0);
        assert!(result.is_ok());
    }

    // === Error path tests ===

    #[test]
    fn test_mount_fails_nonexistent_target() {
        let err = mount("tmpfs", "/nonexistent/mount/point", "tmpfs", 0, None).unwrap_err();
        assert!(
            err.to_string().contains("/nonexistent/mount/point"),
            "error should mention the path: {}",
            err
        );
    }

    #[test]
    fn test_readonly_fails_nonexistent() {
        let err = readonly("/nonexistent/path").unwrap_err();
        assert!(
            err.to_string().contains("/nonexistent/path"),
            "error should mention the path: {}",
            err
        );
    }

    // === setup_at() test with temp directory ===
    // Note: devtmpfs automatically creates both device nodes AND symlinks,
    // so there's no need to test proc_symlinks() separately

    #[test]
    fn test_setup_at_with_temp_root() {
        use crate::test_utils::require_root;
        use tempfile::TempDir;

        require_root();

        let tmpdir = TempDir::new().unwrap();
        let root = tmpdir.path().to_str().unwrap();

        // Create required directories
        // Note: Tests intentionally use std::fs rather than hardened_std::fs because:
        // 1. Tests run on host system with arbitrary temp paths (not in hardened_std whitelist)
        // 2. Tests need to access /proc/filesystems which requires broader std::fs::read_to_string
        // 3. Production code uses hardened_std::fs with strict path whitelisting
        for dir in ["proc", "dev", "sys", "run", "tmp"] {
            std::fs::create_dir_all(format!("{root}/{dir}")).unwrap();
        }

        // Cleanup function to ensure unmounting even on panic
        struct Cleanup<'a> {
            root: &'a str,
        }
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                // Unmount in reverse order (opposite of mount order)
                // Log failures but don't panic - cleanup is best-effort
                for dir in ["tmp", "run", "sys", "dev", "proc"] {
                    let path = format!("{}/{}", self.root, dir);
                    let path_cstr = std::ffi::CString::new(path.as_str()).unwrap();
                    // SAFETY: umount with valid path is safe
                    let ret = unsafe { libc::umount(path_cstr.as_ptr()) };
                    if ret < 0 {
                        // In tests, unmount failures are expected if mount never succeeded
                        // or if the test itself failed. Only log when debugging is enabled.
                        // Set MOUNT_TEST_DEBUG=1 to see cleanup warnings during test runs.
                        if std::env::var("MOUNT_TEST_DEBUG").is_ok() {
                            eprintln!("Warning: Failed to unmount {}", path);
                        }
                    }
                }
            }
        }
        let _cleanup = Cleanup { root };

        // Run setup_at with temp root
        let result = setup_at(root);
        assert!(result.is_ok(), "setup_at failed: {:?}", result);

        // Verify device nodes exist (created automatically by devtmpfs)
        assert!(Path::new(&format!("{root}/dev/null")).exists());
        assert!(Path::new(&format!("{root}/dev/zero")).exists());

        // Verify symlinks were created
        assert!(Path::new(&format!("{root}/dev/stdin")).is_symlink());
        assert!(Path::new(&format!("{root}/dev/stdout")).is_symlink());

        // Cleanup happens via Drop
    }
}
