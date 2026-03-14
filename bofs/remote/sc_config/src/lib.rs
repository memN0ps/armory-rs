//! # Service Config BOF
//!
//! Modifies a Windows service's configuration on a local or remote host by
//! connecting to the Service Control Manager (SCM), opening the target service,
//! and calling `ChangeServiceConfigA`.
//!
//! ## MITRE ATT&CK
//! - T1543.003 - Create or Modify System Process: Windows Service
//!
//! ## Arguments
//! - `str`: Target hostname (empty string for local machine).
//! - `str`: Service name.
//! - `str`: Binary path (empty string to leave unchanged).
//! - `int`: Start type (pass 0xFFFFFFFF / SERVICE_NO_CHANGE to leave unchanged).
//! - `int`: Error control (pass 0xFFFFFFFF / SERVICE_NO_CHANGE to leave unchanged).

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{GetLastError, FALSE};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigA, CloseServiceHandle, OpenSCManagerA, OpenServiceA, SC_MANAGER_CONNECT,
    SERVICE_CHANGE_CONFIG,
};

const SERVICE_NO_CHANGE: u32 = 0xFFFFFFFF;

fn config_service(
    hostname: *const u8,
    service_name: &core::ffi::CStr,
    bin_path: *const u8,
    start_type: u32,
    error_control: u32,
) -> u32 {
    unsafe {
        let sc_manager = OpenSCManagerA(hostname, core::ptr::null(), SC_MANAGER_CONNECT);
        if sc_manager.is_null() {
            let err = GetLastError();
            eprintln!("OpenSCManagerA failed ({:#X})", err);
            return err;
        }

        let sc_service = OpenServiceA(
            sc_manager,
            service_name.as_ptr() as *const u8,
            SERVICE_CHANGE_CONFIG,
        );
        if sc_service.is_null() {
            let err = GetLastError();
            eprintln!("OpenServiceA failed ({:#X})", err);
            CloseServiceHandle(sc_manager);
            return err;
        }

        if ChangeServiceConfigA(
            sc_service,
            SERVICE_NO_CHANGE,
            start_type,
            error_control,
            bin_path,
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
        ) == FALSE
        {
            let err = GetLastError();
            eprintln!("ChangeServiceConfigA failed ({:#X})", err);
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
    let bin_path = String::from(parser.get_str());
    let start_type = parser.get_int() as u32;
    let error_control = parser.get_int() as u32;

    let hostname_cstr = rustbof::str::to_cstr(&hostname);
    let service_cstr = rustbof::str::to_cstr(&service_name);
    let binpath_cstr = rustbof::str::to_cstr(&bin_path);

    println!("config_service:");
    println!("  hostname:     {}", hostname);
    println!("  servicename:  {}", service_name);
    println!("  binpath:      {}", bin_path);
    println!("  starttype:    {:#X}", start_type);
    println!("  errorcontrol: {:#X}", error_control);

    let host_ptr = if hostname.is_empty() {
        core::ptr::null()
    } else {
        hostname_cstr.as_ptr() as *const u8
    };

    let binpath_ptr = if bin_path.is_empty() {
        core::ptr::null()
    } else {
        binpath_cstr.as_ptr() as *const u8
    };

    let result = config_service(host_ptr, &service_cstr, binpath_ptr, start_type, error_control);
    if result != 0 {
        eprintln!("config_service failed: {:#X}", result);
    } else {
        println!("SUCCESS.");
    }
}
