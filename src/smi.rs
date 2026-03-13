//! nvidia-smi GPU configuration commands.
//!
//! These functions apply GPU settings via nvidia-smi before workloads run.
//! All are optional—if the kernel param isn't set, they return immediately.

use log::debug;
use std::fs;

use crate::daemon::FABRIC_MODE_FULL;
use crate::execute::foreground;
use crate::kmsg;
use crate::mode;
use crate::modprobe;
use crate::nvrc::NVRC;

const NVIDIA_SMI: &str = "/bin/nvidia-smi";

impl NVRC {
    /// Lock memory clocks to a specific frequency (MHz).
    /// Reduces memory clock jitter for latency-sensitive workloads.
    pub fn nvidia_smi_lmc(&self) {
        let Some(mhz) = self.nvidia_smi_lmc else {
            return;
        };
        foreground(NVIDIA_SMI, &["-lmc", &mhz.to_string()]);
    }

    /// Lock memory clocks (deferred) to a specific frequency (MHz).
    /// Reduces memory clock jitter for latency-sensitive workloads.
    /// Uses --lock-memory-clocks-deferred because -lmc is not yet supported.
    /// Performs a full driver reload cycle to activate the deferred setting.
    pub fn nvidia_smi_lmcd(&mut self) {
        let Some(mhz) = self.nvidia_smi_lmcd else {
            return;
        };

        // --lock-memory-clocks-deferred stores the setting in the
        // loaded driver and activates it on the *next* driver load.
        foreground(
            NVIDIA_SMI,
            &["--lock-memory-clocks-deferred", &mhz.to_string()],
        );
        self.driver_reload();
    }

    /// Full driver reload cycle: stop daemons, unload modules,
    /// FLR reset GPUs, reload modules, restart daemons.
    fn driver_reload(&mut self) {
        // Stop daemons that hold the driver open
        let mut reader = kmsg::open_kmsg("/dev/kmsg");
        self.stop_persistenced();
        if self.nvswitch == Some("nvl4") {
            self.stop_fabricmanager();
        }
        kmsg::wait_for_marker(&mut reader, "PID file closed", 30);

        // Unload driver modules (reverse dependency order).
        // nvidia-uvm and nvidia-modeset both hold refs on nvidia,
        // so they must be removed first.  Retry because the kernel
        // may still hold references briefly after persistenced exits
        // (UVM cleanup, GSP teardown).
        let interval = std::time::Duration::from_secs(1);
        modprobe::unload_retry("nvidia-uvm", 10, interval);
        modprobe::unload_retry("nvidia-modeset", 10, interval);
        modprobe::unload_retry("nvidia", 10, interval);

        // FLR reset all GPUs via sysfs (driver not needed)
        gpu_flr_reset_from("/sys/bus/pci/devices");

        // Reload driver modules (forward dependency order)
        modprobe::load("nvidia");
        modprobe::load("nvidia-modeset");
        modprobe::load("nvidia-uvm");

        // Restart daemons (fabric manager before persistenced)
        if self.nvswitch == Some("nvl4") {
            self.nv_fabricmanager(FABRIC_MODE_FULL, "greedy");
        }
        self.nvidia_persistenced();
    }

    /// Lock GPU core clocks to a specific frequency (MHz).
    /// Provides consistent performance by preventing dynamic frequency scaling.
    pub fn nvidia_smi_lgc(&self) {
        let Some(mhz) = self.nvidia_smi_lgc else {
            return;
        };
        foreground(NVIDIA_SMI, &["-lgc", &mhz.to_string()]);
    }

    /// Set GPU power limit in watts.
    /// Caps power consumption for thermal/power budget compliance.
    pub fn nvidia_smi_pl(&self) {
        let Some(watts) = self.nvidia_smi_pl else {
            return;
        };
        foreground(NVIDIA_SMI, &["-pl", &watts.to_string()]);
    }

    /// Set GPU Ready State after successful attestation.
    /// In Confidential Computing mode, GPUs default to NotReady and refuse
    /// workloads. After attestation verifies the GPU's integrity, we set
    /// the state to Ready so it can execute compute jobs.
    pub fn nvidia_smi_srs(&self) {
        let Some(ref state) = self.nvidia_smi_srs else {
            return;
        };
        foreground(NVIDIA_SMI, &["conf-compute", "-srs", state]);
    }
}

/// Perform PCI Function Level Reset (FLR) on all GPUs.
/// Writes "1" to /sys/bus/pci/devices/<BDF>/reset for each GPU.
/// Works without the driver loaded.
fn gpu_flr_reset_from(pci_path: &str) {
    for path in mode::gpu_paths_from(pci_path) {
        let reset_path = path.join("reset");
        debug!("FLR reset: {}", path.display());
        fs::write(&reset_path, "1").unwrap_or_else(|e| {
            panic!("FLR reset {}: {e}", reset_path.display());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::panic;
    use tempfile::TempDir;

    // When fields are None, functions return immediately (no nvidia-smi call)

    #[test]
    fn test_lmc_none() {
        let nvrc = NVRC::default();
        nvrc.nvidia_smi_lmc();
    }

    #[test]
    fn test_lgc_none() {
        let nvrc = NVRC::default();
        nvrc.nvidia_smi_lgc();
    }

    #[test]
    fn test_pl_none() {
        let nvrc = NVRC::default();
        nvrc.nvidia_smi_pl();
    }

    #[test]
    fn test_srs_none() {
        let nvrc = NVRC::default();
        nvrc.nvidia_smi_srs();
    }

    #[test]
    fn test_lmcd_none() {
        let mut nvrc = NVRC::default();
        nvrc.nvidia_smi_lmcd();
    }

    // When fields are Some, nvidia-smi is called (panics without NVIDIA hardware)

    #[test]
    fn test_lmcd_some_fails_without_nvidia_smi() {
        let mut nvrc = NVRC::default();
        nvrc.nvidia_smi_lmcd = Some(1000);
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            nvrc.nvidia_smi_lmcd();
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_lmc_some_fails_without_nvidia_smi() {
        let mut nvrc = NVRC::default();
        nvrc.nvidia_smi_lmc = Some(1000);
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            nvrc.nvidia_smi_lmc();
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_lgc_some_fails_without_nvidia_smi() {
        let mut nvrc = NVRC::default();
        nvrc.nvidia_smi_lgc = Some(1500);
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            nvrc.nvidia_smi_lgc();
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_pl_some_fails_without_nvidia_smi() {
        let mut nvrc = NVRC::default();
        nvrc.nvidia_smi_pl = Some(300);
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            nvrc.nvidia_smi_pl();
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_srs_some_fails_without_nvidia_smi() {
        let mut nvrc = NVRC::default();
        nvrc.nvidia_smi_srs = Some("1".into());
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            nvrc.nvidia_smi_srs();
        }));
        assert!(result.is_err());
    }

    // --- FLR reset tests ---

    fn create_pci_device(tmpdir: &TempDir, name: &str, vendor: &str, class: &str) {
        let dev = tmpdir.path().join(name);
        fs::create_dir_all(&dev).unwrap();
        fs::write(dev.join("vendor"), vendor).unwrap();
        fs::write(dev.join("class"), class).unwrap();
        fs::write(dev.join("reset"), "").unwrap();
    }

    #[test]
    fn test_gpu_flr_reset_single_gpu() {
        let tmpdir = TempDir::new().unwrap();
        create_pci_device(&tmpdir, "0000:41:00.0", "0x10de\n", "0x030200\n");
        gpu_flr_reset_from(tmpdir.path().to_str().unwrap());
        let content = fs::read_to_string(tmpdir.path().join("0000:41:00.0/reset")).unwrap();
        assert_eq!(content, "1");
    }

    #[test]
    fn test_gpu_flr_reset_multiple_gpus() {
        let tmpdir = TempDir::new().unwrap();
        create_pci_device(&tmpdir, "0000:41:00.0", "0x10de\n", "0x030200\n");
        create_pci_device(&tmpdir, "0000:42:00.0", "0x10de\n", "0x030000\n");
        gpu_flr_reset_from(tmpdir.path().to_str().unwrap());
        for bdf in ["0000:41:00.0", "0000:42:00.0"] {
            let content = fs::read_to_string(tmpdir.path().join(bdf).join("reset")).unwrap();
            assert_eq!(content, "1");
        }
    }

    #[test]
    fn test_gpu_flr_reset_skips_non_gpu() {
        let tmpdir = TempDir::new().unwrap();
        create_pci_device(&tmpdir, "0000:41:00.0", "0x10de\n", "0x030200\n");
        // NVIDIA audio device (class 0x0403)
        create_pci_device(&tmpdir, "0000:41:00.1", "0x10de\n", "0x040300\n");
        // Non-NVIDIA device
        create_pci_device(&tmpdir, "0000:00:02.0", "0x8086\n", "0x030000\n");
        gpu_flr_reset_from(tmpdir.path().to_str().unwrap());
        // Only the GPU should be reset
        let gpu = fs::read_to_string(tmpdir.path().join("0000:41:00.0/reset")).unwrap();
        assert_eq!(gpu, "1");
        let audio = fs::read_to_string(tmpdir.path().join("0000:41:00.1/reset")).unwrap();
        assert_eq!(audio, "");
        let intel = fs::read_to_string(tmpdir.path().join("0000:00:02.0/reset")).unwrap();
        assert_eq!(intel, "");
    }

    #[test]
    fn test_gpu_flr_reset_empty_dir() {
        let tmpdir = TempDir::new().unwrap();
        gpu_flr_reset_from(tmpdir.path().to_str().unwrap());
    }

    #[test]
    fn test_gpu_flr_reset_nonexistent_dir() {
        gpu_flr_reset_from("/nonexistent/path");
    }
}
