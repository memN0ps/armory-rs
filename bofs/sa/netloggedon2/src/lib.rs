//! # NetLoggedOn2 BOF (BOFHound variant)
//!
//! Lists logged-on users with JSON output for BOFHound ingestion.
//! Same functionality as netloggedon but outputs structured JSON.
//!
//! ## MITRE ATT&CK
//! - T1033 - System Owner/User Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::str::{from_wide, to_wide};
use rustbof::{eprintln, println};

#[repr(C)]
struct WkstaUserInfo1 {
    username: *mut u16,
    logon_domain: *mut u16,
    oth_domains: *mut u16,
    logon_server: *mut u16,
}

unsafe extern "system" {
    fn NetWkstaUserEnum(
        server: *const u16, level: u32, bufptr: *mut *mut u8,
        prefmaxlen: u32, entriesread: *mut u32, totalentries: *mut u32,
        resumehandle: *mut u32,
    ) -> u32;
    fn NetApiBufferFree(buffer: *mut core::ffi::c_void) -> u32;
}

const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;
const ERROR_MORE_DATA: u32 = 234;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());

    let server_wide = if hostname.is_empty() { None } else { Some(to_wide(&hostname)) };
    let server_ptr = server_wide.as_ref().map_or(core::ptr::null(), |w| w.as_ptr());
    let host_display = if hostname.is_empty() { "localhost" } else { &hostname };

    println!("{{\"host\":\"{}\",\"users\":[", host_display);

    unsafe {
        let mut resume: u32 = 0;
        let mut first = true;
        loop {
            let mut buf: *mut u8 = core::ptr::null_mut();
            let mut read: u32 = 0;
            let mut total: u32 = 0;
            let status = NetWkstaUserEnum(server_ptr, 1, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total, &mut resume);

            if status == 0 || status == ERROR_MORE_DATA {
                let entries = buf as *const WkstaUserInfo1;
                for i in 0..read as usize {
                    let e = &*entries.add(i);
                    if !first { println!(","); }
                    first = false;
                    println!("  {{\"username\":\"{}\",\"domain\":\"{}\",\"logon_server\":\"{}\"}}",
                        from_wide(core::slice::from_raw_parts(e.username, 256.min(wcslen(e.username)))),
                        from_wide(core::slice::from_raw_parts(e.logon_domain, 256.min(wcslen(e.logon_domain)))),
                        from_wide(core::slice::from_raw_parts(e.logon_server, 256.min(wcslen(e.logon_server)))),
                    );
                }
                NetApiBufferFree(buf as *mut _);
            } else {
                eprintln!("NetWkstaUserEnum failed: {}", status);
                break;
            }
            if status != ERROR_MORE_DATA { break; }
        }
    }

    println!("]}}");
}

fn wcslen(ptr: *mut u16) -> usize {
    if ptr.is_null() { return 0; }
    let mut len = 0;
    unsafe { while *ptr.add(len) != 0 { len += 1; } }
    len
}
