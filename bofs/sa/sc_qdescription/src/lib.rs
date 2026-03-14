//! # Service Query Description BOF
//!
//! Queries the description of a specific Windows service using QueryServiceConfig2A
//! with SERVICE_CONFIG_DESCRIPTION.
//!
//! ## MITRE ATT&CK
//! - T1007 - System Service Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).
//! - `str`: Service name.

#![no_std]

use alloc::{string::String, vec};
use core::ffi::CStr;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::*;

const SERVICE_CONFIG_DESCRIPTION: u32 = 1;

#[repr(C)]
struct ServiceDescriptionA {
    lpDescription: *const u8,
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());
    let service_name = String::from(parser.get_str());

    if service_name.is_empty() {
        eprintln!("Service name is required");
        return;
    }

    let host_ptr = if hostname.is_empty() {
        core::ptr::null()
    } else {
        let cstr = rustbof::str::to_cstr(&hostname);
        let ptr = cstr.as_ptr() as *const u8;
        core::mem::forget(cstr);
        ptr
    };

    let svc_cstr = rustbof::str::to_cstr(&service_name);

    unsafe {
        let sc_manager = OpenSCManagerA(host_ptr, core::ptr::null(), SC_MANAGER_CONNECT);
        if sc_manager.is_null() {
            eprintln!("OpenSCManagerA failed: 0x{:X}", GetLastError());
            return;
        }

        let sc_service = OpenServiceA(
            sc_manager,
            svc_cstr.as_ptr() as *const u8,
            SERVICE_QUERY_CONFIG,
        );
        if sc_service.is_null() {
            eprintln!("OpenServiceA failed: 0x{:X}", GetLastError());
            CloseServiceHandle(sc_manager);
            return;
        }

        let mut needed: u32 = 0;
        QueryServiceConfig2A(
            sc_service,
            SERVICE_CONFIG_DESCRIPTION,
            core::ptr::null_mut(),
            0,
            &mut needed,
        );

        if needed == 0 {
            eprintln!("QueryServiceConfig2A failed to return size: 0x{:X}", GetLastError());
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return;
        }

        let mut buf = vec![0u8; needed as usize];
        if QueryServiceConfig2A(
            sc_service,
            SERVICE_CONFIG_DESCRIPTION,
            buf.as_mut_ptr(),
            needed,
            &mut needed,
        ) == 0
        {
            eprintln!("QueryServiceConfig2A failed: 0x{:X}", GetLastError());
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return;
        }

        let desc = &*(buf.as_ptr() as *const ServiceDescriptionA);

        println!("SERVICE_NAME: {}", service_name);
        if desc.lpDescription.is_null() {
            println!("\tDESCRIPTION: (none)");
        } else {
            let description = CStr::from_ptr(desc.lpDescription as *const i8)
                .to_str()
                .unwrap_or("(invalid)");
            println!("\tDESCRIPTION: {}", description);
        }

        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
    }
}
