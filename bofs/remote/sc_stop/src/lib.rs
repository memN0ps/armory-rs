//! # Service Stop BOF
//!
//! Stops a specified Windows service on a local or remote host by connecting
//! to the Service Control Manager (SCM), opening the target service, querying
//! its current state, and issuing a stop command via `ControlService`.
//!
//! ## MITRE ATT&CK
//! - T1569.002 - System Services: Service Execution
//!
//! ## Arguments
//! - `str`: Target hostname (empty string for local machine).
//! - `str`: Service name to stop.

#![no_std]

use alloc::ffi::CString;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{GetLastError, FALSE};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerA, OpenServiceA,
    QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

fn stop_service(hostname: *const u8, service_name: &CString) -> u32 {
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
            SERVICE_STOP | SERVICE_QUERY_STATUS,
        );
        if sc_service.is_null() {
            let err = GetLastError();
            eprintln!("OpenServiceA failed ({:#X})", err);
            CloseServiceHandle(sc_manager);
            return err;
        }

        let mut ssp: SERVICE_STATUS_PROCESS = core::mem::zeroed();
        let mut bytes_needed: u32 = 0;
        if QueryServiceStatusEx(
            sc_service,
            SC_STATUS_PROCESS_INFO,
            &mut ssp as *mut SERVICE_STATUS_PROCESS as *mut u8,
            core::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        ) == FALSE
        {
            let err = GetLastError();
            eprintln!("QueryServiceStatusEx failed ({:#X})", err);
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return err;
        }

        if ssp.dwCurrentState == SERVICE_STOPPED {
            println!("Service is already stopped.");
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return 0;
        }

        if ssp.dwCurrentState == SERVICE_STOP_PENDING {
            println!("Service stop pending...");
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return 0;
        }

        let mut service_status: SERVICE_STATUS = core::mem::zeroed();
        let result = if ControlService(
            sc_service,
            SERVICE_CONTROL_STOP,
            &mut service_status,
        ) == FALSE
        {
            let err = GetLastError();
            eprintln!("ControlService failed ({:#X})", err);
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

    println!("stop_service:");
    println!("  hostname:    {}", hostname_str);
    println!("  servicename: {}", service_str);

    let host_ptr = if hostname_str.is_empty() {
        core::ptr::null()
    } else {
        hostname_cstr.as_ptr() as *const u8
    };

    let result = stop_service(host_ptr, &service_cstr);
    if result != 0 {
        eprintln!("stop_service failed: {:#X}", result);
    } else {
        println!("SUCCESS.");
    }
}
