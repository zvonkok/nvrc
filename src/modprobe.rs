use crate::execute::foreground;
use crate::mode;

const MODPROBE: &str = "/sbin/modprobe";

/// Load a kernel module via modprobe.
/// For nvidia, automatically disables NVLink when only one GPU is present.
pub fn load(module: &str) {
    let mut args = vec![module];
    if module == "nvidia" && mode::gpu_paths_from("/sys/bus/pci/devices").len() == 1 {
        args.push("NVreg_NvLinkDisable=1");
    }
    foreground(MODPROBE, &args);
}

/// Unload a kernel module via modprobe -r.
pub fn unload(module: &str) {
    foreground(MODPROBE, &["-r", module]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::require_root;
    use serial_test::serial;
    use std::panic;

    // Kernel module loading must be serialized - parallel modprobe
    // calls can race and cause spurious failures.

    #[test]
    #[serial]
    fn test_load_loop() {
        require_root();
        load("loop");
    }

    #[test]
    #[serial]
    fn test_unload_loop() {
        require_root();
        load("loop");
        unload("loop");
    }

    #[test]
    #[serial]
    fn test_unload_nonexistent() {
        require_root();
        let result = panic::catch_unwind(|| {
            unload("nonexistent_module_xyz123");
        });
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn test_load_nonexistent() {
        require_root();
        let result = panic::catch_unwind(|| {
            load("nonexistent_module_xyz123");
        });
        assert!(result.is_err());
    }
}
