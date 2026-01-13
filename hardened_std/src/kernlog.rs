// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

//! Minimal kernel log implementation for no_std environments.
//!
//! Writes log messages to /dev/kmsg (kernel ring buffer) which can be read via dmesg.
//! This replaces the `kernlog` crate with a minimal implementation using direct syscalls.

use core::fmt::{self, Write};

/// File descriptor for /dev/kmsg, set by init()
static mut KMSG_FD: i32 = -1;

/// Initialize the kernel logger by opening /dev/kmsg.
/// Must be called before any log macros will produce output.
///
/// Returns Ok(()) on success, Err on failure to open /dev/kmsg.
pub fn init() -> Result<(), i32> {
    // Path to kernel message buffer
    let path = b"/dev/kmsg\0";

    // SAFETY: open() with valid path is safe
    let fd = unsafe {
        libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_WRONLY | libc::O_CLOEXEC,
        )
    };

    if fd < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(errno);
    }

    // SAFETY: Single-threaded init, no race
    unsafe {
        KMSG_FD = fd;
    }

    // Set ourselves as the global logger
    // SAFETY: Single-threaded, called once at startup
    unsafe {
        let _ = log::set_logger_racy(&KMSG_LOGGER);
    }

    Ok(())
}

/// The global logger instance
static KMSG_LOGGER: KmsgLogger = KmsgLogger;

/// Minimal logger that writes to /dev/kmsg
struct KmsgLogger;

impl log::Log for KmsgLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        // Let log::max_level() handle filtering
        true
    }

    fn log(&self, record: &log::Record) {
        // SAFETY: Reading static set during init
        let fd = unsafe { KMSG_FD };
        if fd < 0 {
            return;
        }

        // Format: "<level>module: message\n"
        // Syslog priority levels for kernel:
        // 0=EMERG, 1=ALERT, 2=CRIT, 3=ERR, 4=WARN, 5=NOTICE, 6=INFO, 7=DEBUG
        let level = match record.level() {
            log::Level::Error => b'3',
            log::Level::Warn => b'4',
            log::Level::Info => b'6',
            log::Level::Debug => b'7',
            log::Level::Trace => b'7',
        };

        // Use a stack buffer to avoid allocation
        let mut buf = LogBuffer::new();

        // Write prefix with level
        let _ = buf.write_char('<');
        let _ = buf.write_char(level as char);
        let _ = buf.write_char('>');

        // Write module path if available
        if let Some(module) = record.module_path() {
            let _ = buf.write_str(module);
            let _ = buf.write_str(": ");
        }

        // Write the message
        let _ = write!(buf, "{}", record.args());
        let _ = buf.write_char('\n');

        // Write to /dev/kmsg
        // SAFETY: write() with valid fd and buffer is safe
        unsafe {
            libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
        }
    }

    fn flush(&self) {
        // /dev/kmsg doesn't need flushing
    }
}

/// Stack-allocated buffer for formatting log messages
struct LogBuffer {
    buf: [u8; 512],
    pos: usize,
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            buf: [0u8; 512],
            pos: 0,
        }
    }

    fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    fn len(&self) -> usize {
        self.pos
    }
}

impl Write for LogBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.pos;
        let to_write = bytes.len().min(remaining);

        if to_write > 0 {
            self.buf[self.pos..self.pos + to_write].copy_from_slice(&bytes[..to_write]);
            self.pos += to_write;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_buffer_write() {
        let mut buf = LogBuffer::new();
        write!(buf, "hello {}", 42).unwrap();
        assert_eq!(&buf.buf[..buf.pos], b"hello 42");
    }

    #[test]
    fn test_log_buffer_overflow() {
        let mut buf = LogBuffer::new();
        // Write more than buffer size - should truncate, not panic
        for _ in 0..100 {
            let _ = buf.write_str("0123456789");
        }
        assert_eq!(buf.pos, 512); // Capped at buffer size
    }

    #[test]
    fn test_init_returns_ok() {
        // init() should succeed if /dev/kmsg is accessible (requires root)
        // or fail gracefully if not
        let _ = init();
    }
}
