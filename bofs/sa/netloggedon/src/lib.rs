//! # Net Logged On BOF
//!
//! Enumerates logged-on users on a local or remote computer using NetWkstaUserEnum.
//!
//! ## MITRE ATT&CK
//! - T1033 - System Owner/User Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost). Uses wide string internally.

#![no_std]

use rustbof::data::DataParser;
use rustbof::str::{from_wide, to_wide};
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;

#[repr(C)]
struct WkstaUserInfo1 {
    wkui1_username: *mut u16,
    wkui1_logon_domain: *mut u16,
    wkui1_oth_domains: *mut u16,
    wkui1_logon_server: *mut u16,
}

unsafe extern "system" {
    fn NetWkstaUserEnum(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resumehandle: *mut u32,
    ) -> u32;
}

const NERR_SUCCESS: u32 = 0;
const ERROR_MORE_DATA: u32 = 234;
const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;

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

        let display_host = if hostname_str.is_empty() {
            "localhost"
        } else {
            hostname_str
        };

        println!("Logged on users at {}:\n", display_host);
        println!(
            "  {:<24} {:<24} {:<24} {}",
            "Username", "Domain", "Oth Domains", "Logon Server"
        );
        println!(
            "  {:<24} {:<24} {:<24} {}",
            "--------", "------", "-----------", "------------"
        );

        let mut resume_handle: u32 = 0;

        loop {
            let mut buf: *mut u8 = core::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;

            let status = NetWkstaUserEnum(
                server_ptr,
                1,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            );

            if status != NERR_SUCCESS && status != ERROR_MORE_DATA {
                eprintln!("NetWkstaUserEnum failed with error: {}", status);
                break;
            }

            if !buf.is_null() && entries_read > 0 {
                let entries = core::slice::from_raw_parts(
                    buf as *const WkstaUserInfo1,
                    entries_read as usize,
                );

                for entry in entries {
                    let username = wide_ptr_to_str(entry.wkui1_username);
                    let domain = wide_ptr_to_str(entry.wkui1_logon_domain);
                    let oth_domains = wide_ptr_to_str(entry.wkui1_oth_domains);
                    let logon_server = wide_ptr_to_str(entry.wkui1_logon_server);

                    println!(
                        "  {:<24} {:<24} {:<24} {}",
                        username, domain, oth_domains, logon_server
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
