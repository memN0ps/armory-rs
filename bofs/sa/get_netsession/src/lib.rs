//! # Get Net Session BOF
//!
//! Enumerates network sessions on a local or remote computer using NetSessionEnum.
//!
//! ## MITRE ATT&CK
//! - T1049 - System Network Connections Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost). Uses wide string internally.

#![no_std]

use rustbof::data::DataParser;
use rustbof::str::{from_wide, to_wide};
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;

#[repr(C)]
struct SessionInfo10 {
    sesi10_cname: *mut u16,
    sesi10_username: *mut u16,
    sesi10_time: u32,
    sesi10_idle_time: u32,
}

unsafe extern "system" {
    fn NetSessionEnum(
        servername: *const u16,
        unc_client_name: *const u16,
        username: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32;
}

const NERR_SUCCESS: u32 = 0;
const ERROR_MORE_DATA: u32 = 234;
const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname_str = alloc::string::String::from(parser.get_str());

    unsafe {
        let server_ptr = if hostname_str.is_empty() {
            core::ptr::null()
        } else {
            let wide = to_wide(&hostname_str);
            let ptr = wide.as_ptr();
            core::mem::forget(wide);
            ptr
        };

        let display_host = if hostname_str.is_empty() {
            "localhost"
        } else {
            &hostname_str
        };

        println!("Network sessions at {}:\n", display_host);
        println!(
            "  {:<32} {:<24} {:<16} {}",
            "Client", "Username", "Time (s)", "Idle (s)"
        );
        println!(
            "  {:<32} {:<24} {:<16} {}",
            "------", "--------", "--------", "--------"
        );

        let mut resume_handle: u32 = 0;

        loop {
            let mut buf: *mut u8 = core::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;

            let status = NetSessionEnum(
                server_ptr,
                core::ptr::null(),
                core::ptr::null(),
                10,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            );

            if status != NERR_SUCCESS && status != ERROR_MORE_DATA {
                eprintln!("NetSessionEnum failed with error: {}", status);
                break;
            }

            if !buf.is_null() && entries_read > 0 {
                let entries = core::slice::from_raw_parts(
                    buf as *const SessionInfo10,
                    entries_read as usize,
                );

                for entry in entries {
                    let client = wide_ptr_to_str(entry.sesi10_cname);
                    let username = wide_ptr_to_str(entry.sesi10_username);

                    println!(
                        "  {:<32} {:<24} {:<16} {}",
                        client, username, entry.sesi10_time, entry.sesi10_idle_time
                    );
                }
            }

            if !buf.is_null() {
                NetApiBufferFree(buf as *mut _);
            }

            if status != ERROR_MORE_DATA {
                break;
            }
        }
    }
}

fn wide_ptr_to_str(ptr: *mut u16) -> alloc::string::String {
    if ptr.is_null() {
        return alloc::string::String::new();
    }
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        from_wide(core::slice::from_raw_parts(ptr, len))
    }
}
