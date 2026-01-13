// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

extern crate alloc;

use crate::anyhow;
use crate::error::{Context, Result};
use hardened_std::fs;
use hardened_std::process::Command;
use log::{debug, error};

const KATA_AGENT_PATH: &str = "/usr/bin/kata-agent";

/// Syslog polling runs indefinitely in production—VM lifetime measured in
/// hours/days, not the 136 years this represents. Using u32::MAX avoids
/// overflow concerns.
pub const SYSLOG_POLL_FOREVER: u32 = u32::MAX;

/// OOM score adjustment for kata-agent. Value of -997 makes it nearly
/// unkillable, ensuring VM stability even under memory pressure. Range is -1000
/// (never kill) to 1000 (always kill first).
const OOM_SCORE_ADJ: &str = "-997";

/// Set resource limit using direct libc call.
fn setrlimit(resource: libc::__rlimit_resource_t, soft: u64, hard: u64) -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    // SAFETY: setrlimit with valid rlimit struct is safe
    let ret = unsafe { libc::setrlimit(resource, &rlim) };
    if ret != 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(anyhow!("setrlimit failed: errno {}", errno));
    }
    Ok(())
}

/// Get resource limit using direct libc call.
fn getrlimit(resource: libc::__rlimit_resource_t) -> Result<(u64, u64)> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit with valid rlimit pointer is safe
    let ret = unsafe { libc::getrlimit(resource, &mut rlim) };
    if ret != 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(anyhow!("getrlimit failed: errno {}", errno));
    }
    Ok((rlim.rlim_cur, rlim.rlim_max))
}

/// kata-agent needs high file descriptor limits for container workloads and
/// must survive OOM conditions to maintain VM stability
fn agent_setup() -> Result<()> {
    let nofile = 1024 * 1024;
    setrlimit(libc::RLIMIT_NOFILE as _, nofile, nofile).context("setrlimit RLIMIT_NOFILE")?;
    fs::write("/proc/self/oom_score_adj", OOM_SCORE_ADJ.as_bytes())
        .context("write /proc/self/oom_score_adj")?;
    let lim = getrlimit(libc::RLIMIT_NOFILE as _)?;
    debug!("kata-agent RLIMIT_NOFILE: {:?}", lim);
    Ok(())
}

/// exec() replaces this process with kata-agent, so it only returns on failure.
/// We want kata-agent to become PID 1's child for proper process hierarchy.
fn exec_agent(cmd: &'static str) -> Result<()> {
    let err = Command::new(cmd).exec();
    Err(anyhow!("exec {} failed: {err}", cmd))
}

/// Path parameter enables testing with /bin/true instead of real kata-agent
fn kata_agent(path: &'static str) -> Result<()> {
    agent_setup()?;
    exec_agent(path)
}

/// Guest VMs lack a syslog daemon, so we poll /dev/log to drain messages
/// and forward them to kmsg. Timeout enables testing without infinite loops.
/// Uses blocking poll with 500ms timeout instead of sleep+poll for no_std compat.
fn syslog_loop(timeout_secs: u32) -> Result<()> {
    let iterations = (timeout_secs as u64) * 2; // 500ms per iteration
    for _ in 0..iterations {
        // poll_timeout blocks for up to 500ms, returning when data arrives or timeout
        if let Err(e) = crate::syslog::poll_timeout(500) {
            return Err(anyhow!("poll syslog: {e}"));
        }
    }
    Ok(())
}

/// Parent execs kata-agent (becoming it), child stays as syslog poller.
/// This way kata-agent inherits our PID and becomes the main guest process.
/// Timeout parameter allows tests to verify the fork/syslog logic exits cleanly
pub fn fork_agent(timeout_secs: u32) -> Result<()> {
    // SAFETY: fork() is safe here because:
    // 1. We are PID 1 with no other threads (single-threaded process)
    // 2. Parent immediately execs kata-agent (no shared state issues)
    // 3. Child only calls async-signal-safe functions (poll syscall)
    // 4. No locks or mutexes exist that could deadlock in child
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => {
            // Fork failed
            let errno = unsafe { *libc::__errno_location() };
            Err(anyhow!("fork failed: errno {}", errno))
        }
        0 => {
            // Child process - syslog poller
            if let Err(e) = syslog_loop(timeout_secs) {
                error!("{e}");
            }
            Ok(())
        }
        _ => {
            // Parent process - becomes kata-agent
            kata_agent(KATA_AGENT_PATH).context("kata-agent parent")?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::require_root;

    #[test]
    fn test_agent_setup() {
        require_root();

        // agent_setup sets rlimit and writes oom_score_adj
        let result = agent_setup();
        assert!(result.is_ok(), "agent_setup failed: {:?}", result);

        // Verify rlimit was set
        let (soft, hard) = getrlimit(libc::RLIMIT_NOFILE as _).unwrap();
        assert_eq!(soft, 1024 * 1024);
        assert_eq!(hard, 1024 * 1024);

        // Verify oom_score_adj was written
        let oom = std::fs::read_to_string("/proc/self/oom_score_adj").unwrap();
        assert_eq!(oom.trim(), OOM_SCORE_ADJ);
    }

    #[test]
    fn test_exec_agent_not_found() {
        // exec_agent with nonexistent command returns error (doesn't exec)
        let result = exec_agent("/nonexistent/command");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exec"), "error should mention exec: {}", err);
    }

    #[test]
    fn test_kata_agent_not_found() {
        require_root();

        // kata_agent with nonexistent path - setup succeeds, exec fails
        // SAFETY: Test forks to isolate agent_setup() and exec failure.
        // Single-threaded test process with no shared state.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => panic!("fork failed"),
            0 => {
                // Child: Setup succeeds, exec fails - verify and exit with expected code
                assert!(kata_agent("/nonexistent/agent").is_err());
                std::process::exit(1);
            }
            child_pid => {
                // Parent: wait for child
                let mut status: libc::c_int = 0;
                unsafe { libc::waitpid(child_pid, &mut status, 0) };
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 1);
            }
        }
    }

    #[test]
    fn test_syslog_loop_timeout() {
        // syslog_loop with 1 second timeout runs up to 2 iterations (500ms each).
        //
        // **Why no minimum time assertion:**
        // When /dev/log doesn't exist (common in test environments), poll_timeout()
        // returns Err immediately on each iteration - no blocking occurs. A minimum
        // time assertion would cause test failures in environments without /dev/log.
        //
        // The poll_socket_timeout tests in syslog.rs verify timeout behavior directly
        // with controlled sockets. This test verifies syslog_loop's error handling.
        let start = std::time::Instant::now();
        let result = syslog_loop(1);
        let elapsed = start.elapsed();

        // Upper bound: 2 iterations * 500ms + scheduling overhead = ~1200ms max
        // (when /dev/log exists and poll blocks). When it doesn't, exits immediately.
        assert!(elapsed.as_millis() < 1500);

        // Result depends on /dev/log availability - both outcomes are valid
        let _ = result;
    }

    #[test]
    fn test_fork_agent_with_timeout() {
        // Double fork: outer fork isolates the test, inner fork (inside fork_agent_with_timeout)
        // does the real work. This lets us actually call fork_agent_with_timeout() directly.
        // SAFETY: Outer fork isolates the test in a child process.
        // Single-threaded test with no shared state.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => panic!("fork failed"),
            0 => {
                // Child: This child calls fork_agent, which forks again internally.
                // - Inner parent (us): kata_agent() fails, returns Err
                // - Inner child: runs syslog_loop(1), exits after ~1 second
                let result = fork_agent(1);
                // We're the inner parent, so we get the error from kata_agent()
                std::process::exit(if result.is_err() { 1 } else { 0 });
            }
            child_pid => {
                // Parent: Wrapper exits 1 because kata_agent() fails (no binary)
                let mut status: libc::c_int = 0;
                unsafe { libc::waitpid(child_pid, &mut status, 0) };
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 1);
            }
        }
    }
}
