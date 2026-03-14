//! # Service Start BOF
//!
//! Starts a specified Windows service on a local or remote host by connecting
//! to the Service Control Manager (SCM), opening the target service, and
//! issuing a start command via `StartServiceA`.
//!
//! ## MITRE ATT&CK
//! - T1569.002 - System Services: Service Execution
//!
//! ## Arguments
//! - `str`: Target hostname (empty string for local machine).
//! - `str`: Service name to start.

#![no_std]

use alloc::ffi::CString;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{GetLastError, FALSE};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerA, OpenServiceA, StartServiceA,
    SC_MANAGER_CONNECT, SERVICE_START,
};

fn start_service(hostname: *const u8, service_name: &CString) -> u32 {
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
            SERVICE_START,
        );
        if sc_service.is_null() {
            let err = GetLastError();
            eprintln!("OpenServiceA failed ({:#X})", err);
            CloseServiceHandle(sc_manager);
            return err;
        }

        let result = if StartServiceA(sc_service, 0, core::ptr::null()) == FALSE {
            let err = GetLastError();
            eprintln!("StartServiceA failed ({:#X})", err);
            err
        } else {
            0
        };

        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
        result
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);

    let hostname_cstr = rustbof::str::to_cstr(parser.get_str());
    let service_cstr = rustbof::str::to_cstr(parser.get_str());

    let hostname_str = hostname_cstr.to_str().unwrap_or("");
    let service_str = service_cstr.to_str().unwrap_or("");

    println!("start_service:");
    println!("  hostname:    {}", hostname_str);
    println!("  servicename: {}", service_str);

    let host_ptr = if hostname_str.is_empty() {
        core::ptr::null()
    } else {
        hostname_cstr.as_ptr() as *const u8
    };

    let result = start_service(host_ptr, &service_cstr);
    if result != 0 {
        eprintln!("start_service failed: {:#X}", result);
    } else {
        println!("SUCCESS.");
    }
}
