//! # Service Description BOF
//!
//! Sets a service's description on a local or remote host by connecting
//! to the Service Control Manager (SCM), opening the target service, and
//! calling `ChangeServiceConfig2A` with `SERVICE_CONFIG_DESCRIPTION`.
//! ## MITRE ATT&CK
//! - T1543.003 - Create or Modify System Process: Windows Service
//!
//! ## Arguments
//! - `str`: Target hostname (empty string for local machine).
//! - `str`: Service name.
//! - `str`: New description for the service.

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerA, OpenServiceA, SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG,
};

const SERVICE_CONFIG_DESCRIPTION: u32 = 1;

unsafe extern "system" {
    fn ChangeServiceConfig2A(
        h_service: *mut core::ffi::c_void,
        dw_info_level: u32,
        lp_info: *const core::ffi::c_void,
    ) -> i32;
}

#[repr(C)]
struct ServiceDescriptionA {
    lp_description: *const u8,
}

fn set_service_description(
    hostname: *const u8,
    service_name: &core::ffi::CStr,
    description: &core::ffi::CStr,
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

        let desc = ServiceDescriptionA {
            lp_description: description.as_ptr() as *const u8,
        };

        if ChangeServiceConfig2A(
            sc_service,
            SERVICE_CONFIG_DESCRIPTION,
            &desc as *const ServiceDescriptionA as *const core::ffi::c_void,
        ) == 0
        {
            let err = GetLastError();
            eprintln!("ChangeServiceConfig2A failed ({:#X})", err);
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
    let description = String::from(parser.get_str());

    let hostname_cstr = rustbof::str::to_cstr(&hostname);
    let service_cstr = rustbof::str::to_cstr(&service_name);
    let desc_cstr = rustbof::str::to_cstr(&description);

    println!("set_service_description:");
    println!("  hostname:    {}", hostname);
    println!("  servicename: {}", service_name);
    println!("  description: {}", description);

    let host_ptr = if hostname.is_empty() {
        core::ptr::null()
    } else {
        hostname_cstr.as_ptr() as *const u8
    };

    let result = set_service_description(host_ptr, &service_cstr, &desc_cstr);
    if result != 0 {
        eprintln!("set_service_description failed: {:#X}", result);
    } else {
        println!("SUCCESS.");
    }
}
