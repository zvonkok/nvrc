// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

//! Minimal syslog sink for ephemeral init environments.
//!
//! Programs expect /dev/log to exist for logging. As a minimal init we provide
//! this socket and forward messages to the kernel log via trace!(). Severity
//! levels are stripped since all messages go to the same destination anyway.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use hardened_std::os::fd::AsFd;
use hardened_std::os::unix::net::UnixDatagram;
use hardened_std::{Error, Result};
use log::trace;
use once_cell::race::OnceBox;

/// Global syslog socket—lazily initialized on first poll().
static SYSLOG: OnceBox<UnixDatagram> = OnceBox::new();

const DEV_LOG: &str = "/dev/log";

/// Poll the global /dev/log socket, logging any message via trace!().
/// Lazily initializes /dev/log on first call. Non-blocking (timeout=0).
pub fn poll() -> Result<()> {
    poll_timeout(0)?;
    Ok(())
}

/// Poll with timeout (milliseconds). Blocks until data arrives or timeout.
/// Returns Ok(true) if a message was processed, Ok(false) on timeout.
///
/// **Timeout limits:** Negative values block indefinitely.
/// For production 500ms polling, this is not a concern.
pub fn poll_timeout(timeout_ms: i32) -> Result<bool> {
    let sock = SYSLOG.get_or_try_init(|| UnixDatagram::bind(DEV_LOG).map(Box::new))?;
    poll_socket_timeout(sock, timeout_ms)
}

/// Poll socket with timeout. Returns Ok(true) if message read, Ok(false) on timeout.
fn poll_socket_timeout(sock: &UnixDatagram, timeout_ms: i32) -> Result<bool> {
    let mut pfd = libc::pollfd {
        fd: sock.as_fd(),
        events: libc::POLLIN,
        revents: 0,
    };

    // SAFETY: poll() with valid pollfd struct is safe
    let count = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };

    if count < 0 {
        return Err(Error::Io(unsafe { *libc::__errno_location() }));
    }

    if count == 0 {
        return Ok(false);
    }

    if (pfd.revents & libc::POLLIN) == 0 {
        return Ok(false);
    }

    let mut buf = [0u8; 4096];
    let (len, _) = sock.recv_from(&mut buf)?;
    let msg = String::from_utf8_lossy(&buf[..len]);
    trace!("{}", strip_priority(msg.trim_end()));
    Ok(true)
}

/// Strip the syslog priority prefix <N> from a message.
/// Example: "<6>hello" → "hello"
fn strip_priority(msg: &str) -> &str {
    msg.strip_prefix('<')
        .and_then(|s| s.find('>').map(|i| &s[i + 1..]))
        .unwrap_or(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram as StdUnixDatagram;
    use tempfile::TempDir;

    /// Helper to bind a test socket
    fn bind_test(path: &str) -> Result<UnixDatagram> {
        UnixDatagram::bind(path)
    }

    // === strip_priority tests ===

    #[test]
    fn test_strip_priority() {
        assert_eq!(strip_priority("<6>test message"), "test message");
        assert_eq!(strip_priority("<13>another msg"), "another msg");
        assert_eq!(strip_priority("no prefix"), "no prefix");
        assert_eq!(strip_priority("<>empty"), "empty");
        assert_eq!(strip_priority("<6>"), "");
        assert_eq!(strip_priority(""), "");
        assert_eq!(strip_priority("<"), "<");
        assert_eq!(strip_priority("<6"), "<6");
    }

    // === bind tests ===

    #[test]
    fn test_bind_success() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.sock");
        assert!(bind_test(path.to_str().unwrap()).is_ok());
    }

    #[test]
    fn test_bind_disallowed_path() {
        let err = bind_test("/nonexistent/dir/test.sock").unwrap_err();
        assert!(matches!(err, Error::PathNotAllowed));
    }

    #[test]
    fn test_bind_already_exists() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.sock");
        let path_str = path.to_str().unwrap();
        let _sock1 = bind_test(path_str).unwrap();
        let err = bind_test(path_str).unwrap_err();
        assert!(matches!(err, Error::Io(libc::EADDRINUSE)));
    }

    // === poll_socket_timeout tests ===

    #[test]
    fn test_poll_no_data() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.sock");
        let sock = bind_test(path.to_str().unwrap()).unwrap();
        assert_eq!(poll_socket_timeout(&sock, 0).unwrap(), false);
    }

    #[test]
    fn test_poll_with_data() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.sock");
        let server = bind_test(path.to_str().unwrap()).unwrap();

        let client = StdUnixDatagram::unbound().unwrap();
        client.send_to(b"<6>hello world", &path).unwrap();

        assert!(poll_socket_timeout(&server, 100).unwrap());
    }

    #[test]
    fn test_poll_timeout_blocks() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("timeout.sock");
        let sock = bind_test(path.to_str().unwrap()).unwrap();

        let start = std::time::Instant::now();
        let result = poll_socket_timeout(&sock, 100).unwrap();
        let elapsed = start.elapsed();

        assert!(!result);
        assert!(elapsed.as_millis() >= 80);
        assert!(elapsed.as_millis() < 200);
    }

    #[test]
    fn test_poll_multiple_messages() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.sock");
        let server = bind_test(path.to_str().unwrap()).unwrap();

        let client = StdUnixDatagram::unbound().unwrap();
        client.send_to(b"<6>first", &path).unwrap();
        client.send_to(b"<6>second", &path).unwrap();

        // Drains one at a time
        assert!(poll_socket_timeout(&server, 0).unwrap());
        assert!(poll_socket_timeout(&server, 0).unwrap());
        assert!(!poll_socket_timeout(&server, 0).unwrap());
    }

    #[test]
    fn test_poll_public_api() {
        // Exercise public API - may fail if /dev/log already bound
        let _ = poll();
        let _ = poll_timeout(10);
    }
}
