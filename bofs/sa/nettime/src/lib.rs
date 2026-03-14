//! # Net Time BOF
//!
//! Displays the local time on a remote computer using NetRemoteTOD.
//!
//! ## MITRE ATT&CK
//! - T1124 - System Time Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost). Uses wide string internally.

#![no_std]

use rustbof::data::DataParser;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetRemoteTOD, TIME_OF_DAY_INFO,
};

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

        let mut tod: *mut u8 = core::ptr::null_mut();
        let status = NetRemoteTOD(server_ptr, &mut tod);

        let display_host = if hostname_str.is_empty() { "localhost" } else { hostname_str };

        if status == 0 {
            let info = &*(tod as *const TIME_OF_DAY_INFO);

            let elapsed = info.tod_elapsedt as i64;
            let tz_offset = info.tod_timezone as i64 * 60;
            let local_secs = elapsed - tz_offset;

            let secs_per_day: i64 = 86400;
            let total_days = local_secs / secs_per_day;
            let day_secs = (local_secs % secs_per_day) as u32;
            let hours = day_secs / 3600;
            let minutes = (day_secs % 3600) / 60;
            let seconds = day_secs % 60;

            let (year, month, day) = days_to_ymd(total_days);

            let tz_hours = -(info.tod_timezone as i32) / 60;
            println!(
                "Local time (GMT{:+03}:00) at {} is {:02}/{:02}/{:04} {:02}:{:02}:{:02}",
                tz_hours, display_host, month, day, year, hours, minutes, seconds
            );
        } else {
            eprintln!("Unable to retrieve time remotely: {}", status);
        }

        if !tod.is_null() {
            NetApiBufferFree(tod as *mut _);
        }
    }
}

fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    days += 719468; // days from 0000-03-01 to 1970-01-01
    let era = days / 146097;
    let doe = (days - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}
