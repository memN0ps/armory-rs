//! # Net Uptime BOF
//!
//! Displays the boot time of a remote computer using NetStatisticsGet.
//!
//! ## MITRE ATT&CK
//! - T1082 - System Information Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost). Uses wide string internally.

#![no_std]

use rustbof::data::DataParser;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;

unsafe extern "system" {
    fn NetStatisticsGet(
        server: *const u16,
        service: *const u16,
        level: u32,
        options: u32,
        buf: *mut *mut u8,
    ) -> u32;
    fn FileTimeToSystemTime(lpfiletime: *const FILETIME, lpsystemtime: *mut SYSTEMTIME) -> i32;
}

#[repr(C)]
struct StatWorkstation0 {
    statistics_start_time_low: u32,
    statistics_start_time_high: u32,
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname_str = parser.get_str();

    unsafe {
        let server_ptr = if hostname_str.is_empty() {
            core::ptr::null()
        } else {
            let wide = to_wide(hostname_str);
            let ptr = wide.as_ptr();
            core::mem::forget(wide);
            ptr
        };

        let service = to_wide("LanmanWorkstation");

        let mut output: *mut u8 = core::ptr::null_mut();
        let status = NetStatisticsGet(server_ptr, service.as_ptr(), 0, 0, &mut output);

        let display_host = if hostname_str.is_empty() {
            "localhost"
        } else {
            hostname_str
        };

        if status == 0 && !output.is_null() {
            let stats = &*(output as *const StatWorkstation0);

            let ft = FILETIME {
                dwLowDateTime: stats.statistics_start_time_low,
                dwHighDateTime: stats.statistics_start_time_high,
            };

            let mut st: SYSTEMTIME = core::mem::zeroed();
            FileTimeToSystemTime(&ft, &mut st);

            println!("ServerName:   {}", display_host);
            println!(
                "Boot time:    {}-{:02}-{:02} {:02}:{:02}:{:02}",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
            );
        } else {
            eprintln!("Unable to retrieve uptime remotely: {}", status);
        }

        if !output.is_null() {
            NetApiBufferFree(output as *mut _);
        }
    }
}
