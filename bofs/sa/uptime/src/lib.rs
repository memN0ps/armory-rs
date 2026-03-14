//! # Uptime BOF
//!
//! Displays system uptime, current local time, and boot time.
//!
//! ## MITRE ATT&CK
//! - T1082 - System Information Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use rustbof::println;
use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::SystemInformation::{GetLocalTime, GetTickCount64};
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToFileTime};

#[rustbof::main]
fn main() {
    unsafe {
        let ticks = GetTickCount64();
        let secs = ticks / 1000;
        let mins = secs / 60;
        let hrs = mins / 60;
        let days = hrs / 24;

        println!(
            "Uptime: {} days, {} hours, {} minutes, {} seconds",
            days,
            hrs % 24,
            mins % 60,
            secs % 60
        );

        let mut local_time: SYSTEMTIME = core::mem::zeroed();
        GetLocalTime(&mut local_time);
        println!(
            "Local time: {}-{:02}-{:02} {:02}:{:02}:{:02}",
            local_time.wYear,
            local_time.wMonth,
            local_time.wDay,
            local_time.wHour,
            local_time.wMinute,
            local_time.wSecond
        );

        let mut ft: FILETIME = core::mem::zeroed();
        SystemTimeToFileTime(&local_time, &mut ft);
        let mut ftime: u64 = (ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64;
        ftime -= ticks * 10_000; // Convert ms to 100ns intervals
        let boot_ft = FILETIME {
            dwLowDateTime: ftime as u32,
            dwHighDateTime: (ftime >> 32) as u32,
        };
        let mut boot_time: SYSTEMTIME = core::mem::zeroed();
        FileTimeToSystemTime(&boot_ft, &mut boot_time);
        println!(
            "Boot time: {}-{:02}-{:02} {:02}:{:02}:{:02}",
            boot_time.wYear,
            boot_time.wMonth,
            boot_time.wDay,
            boot_time.wHour,
            boot_time.wMinute,
            boot_time.wSecond
        );
    }
}
