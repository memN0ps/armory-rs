//! # Domain Information BOF
//!
//! Reports local join state and discovers one domain controller, forest name,
//! domain name, and AD site through documented NetAPI calls.
//!
//! ## MITRE ATT&CK
//! - T1016 - System Network Configuration Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::string::String;
use core::ffi::c_void;
use rustbof::{eprintln, println};

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct DomainControllerInfo {
    controller_name: *mut u16,
    controller_address: *mut u16,
    address_type: u32,
    domain_guid: Guid,
    domain_name: *mut u16,
    forest_name: *mut u16,
    flags: u32,
    controller_site_name: *mut u16,
    client_site_name: *mut u16,
}

unsafe extern "system" {
    fn NetGetJoinInformation(
        server: *const u16,
        name_buffer: *mut *mut u16,
        status: *mut u32,
    ) -> u32;
    fn DsGetDcNameW(
        computer_name: *const u16,
        domain_name: *const u16,
        domain_guid: *const Guid,
        site_name: *const u16,
        flags: u32,
        info: *mut *mut DomainControllerInfo,
    ) -> u32;
    fn NetApiBufferFree(buffer: *mut c_void) -> u32;
}

const DS_DIRECTORY_SERVICE_REQUIRED: u32 = 0x00000010;
const DS_RETURN_DNS_NAME: u32 = 0x40000000;
const MAX_UNITS: usize = 32768;

fn wide_pointer(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::from("<not available>");
    }
    unsafe {
        let mut length = 0usize;
        while length < MAX_UNITS && *pointer.add(length) != 0 {
            length += 1;
        }
        if length == MAX_UNITS {
            String::from("<value exceeds limit>")
        } else {
            String::from_utf16_lossy(core::slice::from_raw_parts(pointer, length))
        }
    }
}

fn join_label(status: u32) -> &'static str {
    match status {
        1 => "unjoined",
        2 => "workgroup",
        3 => "domain",
        _ => "unknown",
    }
}

#[rustbof::main]
fn main() {
    println!("Domain information");
    unsafe {
        let mut join_name = core::ptr::null_mut();
        let mut join_status = 0u32;
        let status = NetGetJoinInformation(core::ptr::null(), &mut join_name, &mut join_status);
        if status == 0 {
            println!("Join state: {}", join_label(join_status));
            println!("Join name: {}", wide_pointer(join_name));
            if !join_name.is_null() {
                NetApiBufferFree(join_name as *mut c_void);
            }
        } else {
            eprintln!("NetGetJoinInformation failed: 0x{:X}", status);
        }

        let mut info = core::ptr::null_mut();
        let status = DsGetDcNameW(
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
            &mut info,
        );
        if status == 0 && !info.is_null() {
            println!("Domain: {}", wide_pointer((*info).domain_name));
            println!("Forest: {}", wide_pointer((*info).forest_name));
            println!(
                "Domain controller: {}",
                wide_pointer((*info).controller_name)
            );
            println!(
                "Controller address: {}",
                wide_pointer((*info).controller_address)
            );
            println!(
                "Controller site: {}",
                wide_pointer((*info).controller_site_name)
            );
            println!("Client site: {}", wide_pointer((*info).client_site_name));
            NetApiBufferFree(info as *mut c_void);
        } else {
            eprintln!("DsGetDcNameW failed: 0x{:X}", status);
        }
    }
}
