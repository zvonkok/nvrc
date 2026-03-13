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

/// Unload a kernel module with retries. The kernel may still hold
/// references briefly after userspace daemons exit (e.g. UVM cleanup
/// after nvidia-persistenced shutdown).
pub fn unload_retry(module: &str, retries: u32, interval: std::time::Duration) {
    let mod_name = module.replace('-', "_");
    let mod_path = format!("/sys/module/{mod_name}");
    let refcnt_path = format!("{mod_path}/refcnt");
    for attempt in 0..retries {
        if !std::path::Path::new(&mod_path).exists() {
            log::debug!("modprobe -r {module}: already unloaded");
            return;
        }
        let output = std::process::Command::new(MODPROBE)
            .args(["-r", module])
            .output();
        match output {
            Ok(o) if o.status.success() => return,
            Ok(o) if attempt + 1 < retries => {
                let diag = unload_diagnostics(&mod_path, &refcnt_path);
                let stderr = String::from_utf8_lossy(&o.stderr);
                log::debug!(
                    "modprobe -r {module}: retry {}/{retries} {diag} stderr={stderr}",
                    attempt + 1,
                );
                std::thread::sleep(interval);
            }
            Ok(o) => {
                let diag = unload_diagnostics(&mod_path, &refcnt_path);
                let stderr = String::from_utf8_lossy(&o.stderr);
                panic!(
                    "modprobe -r {module} failed after {retries} attempts {diag} stderr={stderr}",
                );
            }
            Err(e) => panic!("modprobe -r {module}: {e}"),
        }
    }
}

/// Gather diagnostic info when module unload fails:
/// refcnt, holder modules, and processes with open nvidia device fds.
fn unload_diagnostics(mod_path: &str, refcnt_path: &str) -> String {
    let refcnt = std::fs::read_to_string(refcnt_path).unwrap_or_default();
    let holders_path = format!("{mod_path}/holders");
    let holders: Vec<String> = std::fs::read_dir(&holders_path)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    // Check /proc/*/fd for open /dev/nvidia* files
    let mut users = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid = entry.file_name();
            let Some(pid_str) = pid.to_str() else {
                continue;
            };
            if !pid_str.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                continue;
            }
            let fd_dir = format!("/proc/{pid_str}/fd");
            if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                for fd in fds.flatten() {
                    if let Ok(target) = std::fs::read_link(fd.path()) {
                        let t = target.to_string_lossy();
                        if t.contains("/dev/nvidia") {
                            let comm = std::fs::read_to_string(format!("/proc/{pid_str}/comm"))
                                .unwrap_or_default();
                            users.push(format!("{}({})->{}", pid_str, comm.trim(), t));
                        }
                    }
                }
            }
        }
    }

    format!(
        "refcnt={} holders=[{}] users=[{}]",
        refcnt.trim(),
        holders.join(","),
        users.join(","),
    )
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
