//! # Service Create BOF
//!
//! Creates a new Windows service on a local or remote host by connecting
//! to the Service Control Manager (SCM) and calling `CreateServiceA`.
//!
//! ## MITRE ATT&CK
//! - T1543.003 - Create or Modify System Process: Windows Service
//!
//! ## Arguments
//! - `str`: Target hostname (empty string for local machine).
//! - `str`: Service name.
//! - `str`: Display name.
//! - `str`: Binary path for the service executable.

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, CreateServiceA, OpenSCManagerA,
};

const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
const SERVICE_DEMAND_START: u32 = 3;
const SERVICE_ERROR_NORMAL: u32 = 1;

fn create_service(
    hostname: *const u8,
    service_name: &core::ffi::CStr,
    display_name: &core::ffi::CStr,
    bin_path: &core::ffi::CStr,
) -> u32 {
    unsafe {
        let sc_manager = OpenSCManagerA(hostname, core::ptr::null(), SC_MANAGER_CREATE_SERVICE);
        if sc_manager.is_null() {
            let err = GetLastError();
            eprintln!("OpenSCManagerA failed ({:#X})", err);
            return err;
        }

        let sc_service = CreateServiceA(
            sc_manager,
            service_name.as_ptr() as *const u8,
            display_name.as_ptr() as *const u8,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            bin_path.as_ptr() as *const u8,
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
        );
        if sc_service.is_null() {
            let err = GetLastError();
            eprintln!("CreateServiceA failed ({:#X})", err);
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
    let display_name = String::from(parser.get_str());
    let bin_path = String::from(parser.get_str());

    let hostname_cstr = rustbof::str::to_cstr(&hostname);
    let service_cstr = rustbof::str::to_cstr(&service_name);
    let display_cstr = rustbof::str::to_cstr(&display_name);
    let binpath_cstr = rustbof::str::to_cstr(&bin_path);

    println!("create_service:");
    println!("  hostname:    {}", hostname);
    println!("  servicename: {}", service_name);
    println!("  displayname: {}", display_name);
    println!("  binpath:     {}", bin_path);

    let host_ptr = if hostname.is_empty() {
        core::ptr::null()
    } else {
        hostname_cstr.as_ptr() as *const u8
    };

    let result = create_service(host_ptr, &service_cstr, &display_cstr, &binpath_cstr);
    if result != 0 {
        eprintln!("create_service failed: {:#X}", result);
    } else {
        println!("SUCCESS.");
    }
}
