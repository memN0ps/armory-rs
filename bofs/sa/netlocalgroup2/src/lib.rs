//! # NetLocalGroup2 BOF (BOFHound variant)
//!
//! Enumerates local groups with JSON output for BOFHound ingestion.
//!
//! ## MITRE ATT&CK
//! - T1069.001 - Permission Groups Discovery: Local Groups
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::str::{from_wide, to_wide};
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::*;

#[repr(C)]
struct LocalGroupInfo1 {
    name: *mut u16,
    comment: *mut u16,
}

unsafe extern "system" {
    fn NetLocalGroupEnum(
        server: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resumehandle: *mut u32,
    ) -> u32;
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
        "{{\"host\":\"{}\",\"groups\":[",
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

        let status = NetLocalGroupEnum(
            server_ptr,
            1,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
            &mut resume,
        );
        if status == 0 {
            let entries = buf as *const LocalGroupInfo1;
            for i in 0..read as usize {
                let e = &*entries.add(i);
                let name = from_wide(core::slice::from_raw_parts(e.name, wcslen(e.name)));
                let comment = from_wide(core::slice::from_raw_parts(e.comment, wcslen(e.comment)));
                if i > 0 {
                    println!(",");
                }
                println!("  {{\"name\":\"{}\",\"comment\":\"{}\"}}", name, comment);
            }
            NetApiBufferFree(buf as *mut _);
        } else {
            eprintln!("NetLocalGroupEnum failed: {}", status);
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
