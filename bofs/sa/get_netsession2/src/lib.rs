//! # GetNetSession2 BOF (BOFHound variant)
//!
//! Enumerates network sessions with JSON output for BOFHound ingestion.
//!
//! ## MITRE ATT&CK
//! - T1049 - System Network Connections Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::str::{from_wide, to_wide};
use rustbof::{eprintln, println};

#[repr(C)]
struct SessionInfo10 {
    cname: *mut u16,
    username: *mut u16,
    time: u32,
    idle_time: u32,
}

unsafe extern "system" {
    fn NetSessionEnum(
        server: *const u16,
        client: *const u16,
        user: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume: *mut u32,
    ) -> u32;
    fn NetApiBufferFree(buffer: *mut core::ffi::c_void) -> u32;
}

const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());

    let server_wide = if hostname.is_empty() {
        None
    } else {
        Some(to_wide(&hostname))
    };
    let server_ptr = server_wide
        .as_ref()
        .map_or(core::ptr::null(), |w| w.as_ptr());

    println!(
        "{{\"host\":\"{}\",\"sessions\":[",
        if hostname.is_empty() {
            "localhost"
        } else {
            &hostname
        }
    );

    unsafe {
        let mut buf: *mut u8 = core::ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        let mut resume: u32 = 0;

        let status = NetSessionEnum(
            server_ptr,
            core::ptr::null(),
            core::ptr::null(),
            10,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
            &mut resume,
        );
        if status == 0 {
            let entries = buf as *const SessionInfo10;
            for i in 0..read as usize {
                let e = &*entries.add(i);
                let cname = from_wide(core::slice::from_raw_parts(e.cname, wcslen(e.cname)));
                let user = from_wide(core::slice::from_raw_parts(e.username, wcslen(e.username)));
                if i > 0 {
                    println!(",");
                }
                println!(
                    "  {{\"client\":\"{}\",\"user\":\"{}\",\"time\":{},\"idle\":{}}}",
                    cname, user, e.time, e.idle_time
                );
            }
            NetApiBufferFree(buf as *mut _);
        } else {
            eprintln!("NetSessionEnum failed: {}", status);
        }
    }

    println!("]}}");
}

fn wcslen(ptr: *mut u16) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let mut len = 0;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
    }
    len
}
