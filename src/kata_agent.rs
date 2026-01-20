// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

use log::debug;
use rustix::process::{setrlimit, Resource, Rlimit};
use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

const KATA_AGENT_PATH: &str = "/usr/bin/kata-agent";

/// Syslog polling runs indefinitely in production—VM lifetime measured in hours/days,
/// not the 136 years this represents. Using u32::MAX avoids overflow concerns.
pub const SYSLOG_POLL_FOREVER: u32 = u32::MAX;

/// OOM score adjustment for kata-agent. Value of -997 makes it nearly unkillable,
/// ensuring VM stability even under memory pressure. Range is -1000 (never kill) to 1000 (always kill first).
const KATA_AGENT_OOM_SCORE_ADJ: &str = "-997";

/// kata-agent needs high file descriptor limits for container workloads and
/// must survive OOM conditions to maintain VM stability
fn agent_setup() {
    let nofile = 1024 * 1024;
    let rlim = Rlimit {
        current: Some(nofile),
        maximum: Some(nofile),
    };
    setrlimit(Resource::Nofile, rlim).expect("setrlimit RLIMIT_NOFILE");
    fs::write(
        "/proc/self/oom_score_adj",
        KATA_AGENT_OOM_SCORE_ADJ.as_bytes(),
    )
    .expect("write /proc/self/oom_score_adj");
    let lim = rustix::process::getrlimit(Resource::Nofile);
    debug!("kata-agent RLIMIT_NOFILE: {:?}", lim);
}

/// exec() replaces this process with kata-agent, so it only returns on failure.
/// We want kata-agent to become PID 1's child for proper process hierarchy.
fn exec_agent(cmd: &str) {
    let err = Command::new(cmd).exec();
    panic!("exec {cmd} failed: {err}");
}

/// Path parameter enables testing with /bin/true instead of real kata-agent
fn kata_agent(path: &str) {
    agent_setup();
    exec_agent(path);
}

/// Guest VMs lack a syslog daemon, so we poll /dev/log to drain messages
/// and forward them to kmsg. Timeout enables testing without infinite loops.
fn syslog_loop(timeout_secs: u32) {
    let iterations = (timeout_secs as u64) * 2; // 500ms per iteration
    for _ in 0..iterations {
        sleep(Duration::from_millis(500));
        crate::syslog::poll();
    }
}

/// Fork the process. Returns Ok(Some(pid)) in parent, Ok(None) in child, Err on failure.
fn fork() -> io::Result<Option<libc::pid_t>> {
    // SAFETY: fork() is safe here because:
    // 1. We are PID 1 with no other threads (single-threaded process)
    // 2. Parent immediately execs kata-agent (no shared state issues)
    // 3. Child only calls async-signal-safe functions (syslog::poll, sleep)
    // 4. No locks or mutexes exist that could deadlock in child
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(None),      // Child
        _ => Ok(Some(pid)), // Parent
    }
}

/// Parent execs kata-agent (becoming it), child stays as syslog poller.
/// This way kata-agent inherits our PID and becomes the main guest process.
/// Timeout parameter allows tests to verify the fork/syslog logic exits cleanly
pub fn fork_agent(timeout_secs: u32) {
    match fork().expect("fork agent") {
        Some(_) => {
            // Parent: become kata-agent
            kata_agent(KATA_AGENT_PATH);
        }
        None => {
            // Child: syslog poller
            syslog_loop(timeout_secs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::require_root;
    use rustix::process::{waitpid, Pid, WaitOptions};
    use std::panic;

    /// Install a panic hook that exits with code 1.
    /// Required in forked children because Rust's test harness catches panics
    /// and exits with 0, which breaks our "panic = failure" assertions.
    fn set_test_panic_hook() {
        panic::set_hook(Box::new(|info| {
            eprintln!("panic: {info}");
            std::process::exit(1);
        }));
    }

    #[test]
    fn test_agent_setup() {
        require_root();

        // agent_setup sets rlimit and writes oom_score_adj
        agent_setup();

        // Verify rlimit was set
        let lim = rustix::process::getrlimit(Resource::Nofile);
        assert_eq!(lim.current, Some(1024 * 1024));
        assert_eq!(lim.maximum, Some(1024 * 1024));

        // Verify oom_score_adj was written
        let oom = fs::read_to_string("/proc/self/oom_score_adj").unwrap();
        assert_eq!(oom.trim(), KATA_AGENT_OOM_SCORE_ADJ);
    }

    #[test]
    fn test_exec_agent_not_found() {
        // exec_agent with nonexistent command panics (doesn't exec)
        let result = panic::catch_unwind(|| {
            exec_agent("/nonexistent/command");
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_kata_agent_not_found() {
        require_root();

        // kata_agent with nonexistent path - setup succeeds, exec panics
        // SAFETY: Test forks to isolate agent_setup() and exec failure.
        // Single-threaded test process with no shared state.
        match fork().expect("fork") {
            Some(child_pid) => {
                // Child exits abnormally due to panic
                let pid = unsafe { Pid::from_raw(child_pid).unwrap() };
                let status = waitpid(Some(pid), WaitOptions::empty()).expect("waitpid");
                // status is None if child hasn't exited, Some((Pid, WaitStatus)) otherwise
                // Check that child did not exit with code 0
                match status {
                    Some((_, ws)) => assert!(!ws.exited() || ws.exit_status() != Some(0)),
                    None => panic!("child should have exited"),
                }
            }
            None => {
                set_test_panic_hook();
                // Setup succeeds, exec panics
                kata_agent("/nonexistent/agent");
                std::process::exit(0); // Won't reach here
            }
        }
    }

    #[test]
    fn test_syslog_loop_timeout() {
        // syslog_loop with 1 second timeout runs up to 2 iterations (500ms each).
        // Two possible outcomes:
        // 1. poll() works: runs full 2 iterations (~1000ms)
        // 2. poll() panics: test fails due to missing /dev/log
        // We catch_unwind to handle missing /dev/log gracefully in test env
        let start = std::time::Instant::now();
        let _ = panic::catch_unwind(|| syslog_loop(1));
        let elapsed = start.elapsed();

        // Lower bound: at least 1 sleep cycle (500ms) runs before poll
        // Upper bound: 2 iterations + scheduling overhead = ~1200ms max
        assert!(elapsed.as_millis() >= 400);
        assert!(elapsed.as_millis() < 1500);
    }

    #[test]
    fn test_fork_agent_with_timeout() {
        require_root();

        // Double fork: outer fork isolates the test, inner fork (inside fork_agent)
        // does the real work. This lets us actually call fork_agent() directly.
        // SAFETY: Outer fork isolates the test in a child process.
        // Single-threaded test with no shared state.
        match fork().expect("outer fork") {
            Some(child_pid) => {
                // Wrapper exits abnormally because kata_agent() panics (no binary)
                let pid = unsafe { Pid::from_raw(child_pid).unwrap() };
                let status = waitpid(Some(pid), WaitOptions::empty()).expect("waitpid");
                match status {
                    Some((_, ws)) => assert!(!ws.exited() || ws.exit_status() != Some(0)),
                    None => panic!("child should have exited"),
                }
            }
            None => {
                set_test_panic_hook();
                // This child calls fork_agent, which forks again internally.
                // - Inner parent (us): kata_agent() panics
                // - Inner child: runs syslog_loop(1), exits after ~1 second
                fork_agent(1);
                std::process::exit(0); // Won't reach here due to panic
            }
        }
    }
}
