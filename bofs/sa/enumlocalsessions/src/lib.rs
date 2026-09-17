//! # Enumerate Local Sessions BOF
//!
//! Enumerates all active and disconnected local sessions on the current host
//! using the Windows Terminal Services API (`WTSEnumerateSessionsA`).
//!
//! For each qualifying session, displays the session ID, window station name,
//! domain, and username.
//!
//! ## MITRE ATT&CK
//! - T1033 - System Owner/User Discovery
//!
//! ## Arguments
//! None.

#![no_std]
use core::ffi::CStr;
use core::ptr::null_mut;

use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_SESSION_INFOA, WTSActive, WTSDisconnected, WTSDomainName, WTSEnumerateSessionsA,
    WTSFreeMemory, WTSQuerySessionInformationA, WTSUserName, WTSWinStationName,
};

const WTS_CURRENT_SERVER_HANDLE: *mut core::ffi::c_void = core::ptr::null_mut();

#[rustbof::main]
fn main() {
    unsafe {
        let mut session_info: *mut WTS_SESSION_INFOA = null_mut();
        let mut count: u32 = 0;

        let result = WTSEnumerateSessionsA(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &mut session_info,
            &mut count,
        );

        if result == FALSE {
            eprintln!("WTSEnumerateSessionsA failed");
            return;
        }

        if session_info.is_null() || count == 0 {
            println!("No sessions found.");
            return;
        }

        let sessions = core::slice::from_raw_parts(session_info, count as usize);

        println!("Enumerating local sessions...\n");

        let mut active_count: u32 = 0;

        for session in sessions {
            let state = session.State;

            if state != WTSActive && state != WTSDisconnected {
                continue;
            }

            let session_id = session.SessionId;

            let username = query_session_string(session_id, WTSUserName);
            let domain = query_session_string(session_id, WTSDomainName);
            let station = query_session_string(session_id, WTSWinStationName);

            println!("  - [{}] {}: {}\\{}", session_id, station, domain, username);

            active_count += 1;
        }

        println!("\nTotal active/disconnected sessions: {}", active_count);

        WTSFreeMemory(session_info as *mut _);
    }
}

unsafe fn query_session_string(session_id: u32, info_class: i32) -> &'static str {
    unsafe {
        let mut buffer: *mut u8 = null_mut();
        let mut bytes_returned: u32 = 0;

        let result = WTSQuerySessionInformationA(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            info_class,
            &mut buffer,
            &mut bytes_returned,
        );

        if result == FALSE || buffer.is_null() {
            return "<unknown>";
        }

        let c_str = CStr::from_ptr(buffer as *const i8);
        let s = c_str.to_str().unwrap_or("<unknown>");

        if s.is_empty() {
            WTSFreeMemory(buffer as *mut _);
            return "<empty>";
        }

        let len = s.len();
        let mut copy = alloc::vec![0u8; len];
        core::ptr::copy_nonoverlapping(s.as_ptr(), copy.as_mut_ptr(), len);
        WTSFreeMemory(buffer as *mut _);

        let leaked = alloc::boxed::Box::leak(copy.into_boxed_slice());
        core::str::from_utf8_unchecked(leaked)
    }
}
