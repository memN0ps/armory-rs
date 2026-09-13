//! Bounded output through the standard Beacon API.

use core::fmt::{self, Write};

const CALLBACK_OUTPUT_UTF8: i32 = 0x20;
const OUTPUT_CAPACITY: usize = 2 * 1024;
const OUTPUT_LIMIT: usize = 64 * 1024;
const TRUNCATION_MARKER: &[u8] = b"[-] Output reached the 64 KiB safety limit\n";

#[cfg(not(test))]
unsafe extern "C" {
    fn BeaconOutput(kind: i32, data: *const u8, length: i32);
}

#[cfg(not(test))]
unsafe fn beacon_output(kind: i32, data: *const u8, length: i32) {
    unsafe { BeaconOutput(kind, data, length) };
}

#[cfg(test)]
unsafe fn beacon_output(_kind: i32, _data: *const u8, _length: i32) {}

pub struct Output {
    bytes: [u8; OUTPUT_CAPACITY],
    length: usize,
    emitted: usize,
    truncated: bool,
}

impl Output {
    pub const fn new() -> Self {
        Self {
            bytes: [0; OUTPUT_CAPACITY],
            length: 0,
            emitted: 0,
            truncated: false,
        }
    }

    pub fn line(&mut self, message: &str) {
        let _ = self.write_str(message);
        let _ = self.write_char('\n');
    }

    pub fn field(&mut self, name: &str, value: &str) {
        let _ = writeln!(self, "[*] {name:<16}: {value}");
    }

    pub fn error(&mut self, message: &str) {
        let _ = writeln!(self, "[-] {message}");
    }

    pub fn flush(&mut self) {
        self.emit();

        if self.truncated {
            unsafe {
                beacon_output(
                    CALLBACK_OUTPUT_UTF8,
                    TRUNCATION_MARKER.as_ptr(),
                    TRUNCATION_MARKER.len() as i32,
                );
            }
        }

        self.emitted = 0;
        self.truncated = false;
    }

    fn emit(&mut self) {
        if self.length == 0 {
            return;
        }

        // SAFETY: `bytes` remains live and immutable for the duration of this
        // call, and `length` never exceeds its fixed capacity or `i32::MAX`.
        unsafe {
            beacon_output(
                CALLBACK_OUTPUT_UTF8,
                self.bytes.as_ptr(),
                self.length as i32,
            );
        }

        self.emitted += self.length;
        self.length = 0;
    }
}

impl Write for Output {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let mut offset = 0;

        while offset < value.len() && !self.truncated {
            if self.length == OUTPUT_CAPACITY {
                self.emit();
            }

            let budget = OUTPUT_LIMIT.saturating_sub(self.emitted + self.length);

            if budget == 0 {
                self.truncated = true;
                break;
            }

            let available = OUTPUT_CAPACITY - self.length;
            let mut count = (value.len() - offset).min(available).min(budget);

            while count != 0 && !value.is_char_boundary(offset + count) {
                count -= 1;
            }

            if count == 0 {
                if self.length == 0 {
                    self.truncated = true;
                    break;
                }

                self.emit();
                continue;
            }

            // SAFETY: `count` is bounded by the remaining source bytes and
            // free destination capacity. The regions cannot overlap.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    value.as_ptr().add(offset),
                    self.bytes.as_mut_ptr().add(self.length),
                    count,
                );
            }

            self.length += count;
            offset += count;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_text_larger_than_one_chunk() {
        let mut output = Output::new();
        let value = "x".repeat(OUTPUT_CAPACITY + 1);

        assert!(output.write_str(&value).is_ok());
        assert_eq!(output.emitted + output.length, value.len());
        assert!(!output.truncated);
    }

    #[test]
    fn preserves_utf8_boundaries() {
        let mut output = Output::new();
        let value = "x".repeat(OUTPUT_CAPACITY - 1) + "\u{00e9}";

        assert!(output.write_str(&value).is_ok());
        assert_eq!(output.emitted + output.length, value.len());
        assert!(!output.truncated);
    }
}
