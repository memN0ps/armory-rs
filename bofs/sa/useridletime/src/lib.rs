//! # User Idle Time BOF
//!
//! Displays how long the current user has been idle (no keyboard/mouse input).
//!
//! ## MITRE ATT&CK
//! - T1082 - System Information Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use rustbof::{eprintln, println};
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

#[rustbof::main]
fn main() {
    unsafe {
        let mut lii: LASTINPUTINFO = core::mem::zeroed();
        lii.cbSize = core::mem::size_of::<LASTINPUTINFO>() as u32;

        if GetLastInputInfo(&mut lii) == 0 {
            eprintln!("Failed to retrieve last user idle time");
            return;
        }

        let tick_count = GetTickCount();
        let idle_secs = (tick_count.wrapping_sub(lii.dwTime)) / 1000;

        let seconds = idle_secs % 60;
        let minutes = (idle_secs / 60) % 60;
        let hours = (idle_secs / 3600) % 24;
        let days = idle_secs / 86400;

        println!(
            "Current User idle time: {} days, {} hours, {} minutes, {} seconds",
            days, hours, minutes, seconds
        );
    }
}
