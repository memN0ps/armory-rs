//! # Service Delete BOF
//!
//! Deletes a specified Windows service on a local or remote host by connecting
//! to the Service Control Manager (SCM), opening the target service, and
//! calling `DeleteService`.
//!
//! ## MITRE ATT&CK
//! - T1489 - Service Stop
//!
//! ## Arguments
//! - `str`: Target hostname (empty string for local machine).
//! - `str`: Service name to delete.

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{FALSE, GetLastError};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, DeleteService, OpenSCManagerA, OpenServiceA, SC_MANAGER_CONNECT,
};

const DELETE: u32 = 0x10000;

fn delete_service(hostname: *const u8, service_name: &core::ffi::CStr) -> u32 {
    unsafe {
        let sc_manager = OpenSCManagerA(hostname, core::ptr::null(), SC_MANAGER_CONNECT);
        if sc_manager.is_null() {
            let err = GetLastError();
            eprintln!("OpenSCManagerA failed ({:#X})", err);
            return err;
        }

        let sc_service = OpenServiceA(sc_manager, service_name.as_ptr() as *const u8, DELETE);
        if sc_service.is_null() {
            let err = GetLastError();
            eprintln!("OpenServiceA failed ({:#X})", err);
            CloseServiceHandle(sc_manager);
            return err;
        }

        if DeleteService(sc_service) == FALSE {
            let err = GetLastError();
            eprintln!("DeleteService failed ({:#X})", err);
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return err;
        }

        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
        0
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);

    let hostname = String::from(parser.get_str());
    let service_name = String::from(parser.get_str());

    let hostname_cstr = rustbof::str::to_cstr(&hostname);
    let service_cstr = rustbof::str::to_cstr(&service_name);

    println!("delete_service:");
    println!("  hostname:    {}", hostname);
    println!("  servicename: {}", service_name);

    let host_ptr = if hostname.is_empty() {
        core::ptr::null()
    } else {
        hostname_cstr.as_ptr() as *const u8
    };

    let result = delete_service(host_ptr, &service_cstr);
    if result != 0 {
        eprintln!("delete_service failed: {:#X}", result);
    } else {
        println!("SUCCESS.");
    }
}
