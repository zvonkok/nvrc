// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

use anyhow::{anyhow, Context, Result};
use hardened_std::process::{Child, Command, Stdio};

use crate::kmsg::kmsg;

/// Run a command and block until completion. Output goes to kmsg so it appears
/// in dmesg/kernel log - the only reliable log destination in minimal VMs.
/// Used for setup commands that must succeed before continuing (nvidia-smi, modprobe).
pub fn foreground(command: &'static str, args: &[&str]) -> Result<()> {
    debug!("{} {}", command, args.join(" "));

    let kmsg_file = kmsg().context("Failed to open kmsg device")?;
    let mut cmd = Command::new(command);
    cmd.args(args).context("Invalid arguments")?;
    cmd.stdout(Stdio::from(
        kmsg_file.try_clone().context("Failed to clone kmsg file")?,
    ));
    cmd.stderr(Stdio::from(kmsg_file));

    let status = cmd.status().context("Failed to execute command")?;

    if !status.success() {
        return Err(anyhow!("{} failed ({})", command, status));
    }
    Ok(())
}

/// Spawn a daemon without waiting. Returns Child so caller can track it later.
/// Used for long-running services (nvidia-persistenced, fabricmanager) that run
/// alongside kata-agent. Output to kmsg for visibility in kernel log.
pub fn background(command: &'static str, args: &[&str]) -> Result<Child> {
    debug!("{} {}", command, args.join(" "));
    let kmsg_file = kmsg().context("Failed to open kmsg device")?;
    let mut cmd = Command::new(command);
    cmd.args(args).context("Invalid arguments")?;
    cmd.stdout(Stdio::from(
        kmsg_file.try_clone().context("Failed to clone kmsg file")?,
    ));
    cmd.stderr(Stdio::from(kmsg_file));

    cmd.spawn().context("Failed to spawn command")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== foreground tests ====================

    #[test]
    fn test_foreground_success() {
        let result = foreground("/bin/true", &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_foreground_failure_exit_code() {
        // Command runs but exits non-zero
        let result = foreground("/bin/false", &[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed"));
    }

    #[test]
    fn test_foreground_not_allowed() {
        // Command not in whitelist
        let result = foreground("/nonexistent/command", &[]);
        assert!(result.is_err());
        // Error chain: context("Failed to execute command") wraps "Binary not in allowed list"
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("not in allowed list"),
            "error should contain 'not in allowed list': {}",
            err
        );
    }

    #[test]
    fn test_foreground_with_args() {
        let result = foreground("/bin/sh", &["-c", "exit 0"]);
        assert!(result.is_ok());

        let result = foreground("/bin/sh", &["-c", "exit 42"]);
        assert!(result.is_err());
    }

    // ==================== background tests ====================

    #[test]
    fn test_background_spawns() {
        let result = background("/bin/sleep", &["0.01"]);
        assert!(result.is_ok());
        let mut child = result.unwrap();
        let status = child.wait().unwrap();
        assert!(status.success());
    }

    #[test]
    fn test_background_not_allowed() {
        // Command not in whitelist
        let result = background("/nonexistent/command", &[]);
        assert!(result.is_err());
        // Error chain: context("Failed to spawn command") wraps "Binary not in allowed list"
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("not in allowed list"),
            "error should mention 'not in allowed list': {}",
            err
        );
    }

    #[test]
    fn test_background_check_later() {
        let result = background("/bin/sh", &["-c", "exit 7"]);
        assert!(result.is_ok());
        let mut child = result.unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
        assert_eq!(status.code(), Some(7));
    }
}
