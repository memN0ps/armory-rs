//! # Registry Session Enumeration BOF
//!
//! Enumerates logged-on user SIDs by inspecting subkeys under HKEY_USERS
//! in the Windows registry. Filters for interactive user SIDs (S-1-5-21-*)
//! and excludes class subkeys (those containing an underscore). Supports
//! remote registry access via `RegConnectRegistryA` when a hostname is
//! provided.
//!
//! ## MITRE ATT&CK
//! - T1033 - System Owner/User Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).

#![no_std]

use alloc::string::String;
use alloc::vec;
use core::ffi::CStr;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::*;

const HKEY_USERS: *mut core::ffi::c_void = 0x80000003u32 as isize as *mut core::ffi::c_void;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());

    let target = if hostname.is_empty() {
        "localhost"
    } else {
        hostname.as_str()
    };

    println!(
        "Enumerating logged-on user SIDs from HKEY_USERS on {}",
        target
    );
    println!("{}", "=".repeat(60));

    unsafe {
        let root_key: *mut core::ffi::c_void = if hostname.is_empty() {
            HKEY_USERS
        } else {
            let host_cstr = rustbof::str::to_cstr(&hostname);
            let mut remote_key: *mut core::ffi::c_void = core::ptr::null_mut();
            let ret = RegConnectRegistryA(
                host_cstr.as_ptr() as *const u8,
                HKEY_USERS as HKEY,
                &mut remote_key as *mut *mut core::ffi::c_void as *mut HKEY,
            );
            if ret != 0 {
                eprintln!("RegConnectRegistryA failed: 0x{:X}", ret);
                return;
            }
            remote_key
        };

        let mut index: u32 = 0;
        let mut count: u32 = 0;

        loop {
            let mut name_buf = vec![0u8; 512];
            let mut name_len: u32 = name_buf.len() as u32;

            let ret = RegEnumKeyExA(
                root_key as HKEY,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );

            if ret == 259 {
                break;
            }
            if ret != 0 {
                eprintln!("RegEnumKeyExA failed at index {}: 0x{:X}", index, ret);
                break;
            }

            let subkey_name = CStr::from_ptr(name_buf.as_ptr() as *const i8)
                .to_str()
                .unwrap_or("(invalid)");

            if subkey_name.starts_with("S-1-5-21") {
                let mut has_underscore = false;
                for b in subkey_name.as_bytes() {
                    if *b == b'_' {
                        has_underscore = true;
                        break;
                    }
                }
                if !has_underscore {
                    println!("  [{}] {}", target, subkey_name);
                    count += 1;
                }
            }

            index += 1;
        }

        println!("");
        println!("Total logged-on user SIDs: {}", count);

        if !hostname.is_empty() {
            RegCloseKey(root_key as HKEY);
        }
    }
}
