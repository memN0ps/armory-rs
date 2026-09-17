//! # Service Query Configuration BOF
//!
//! Queries the configuration of a specific Windows service using QueryServiceConfigA.
//! Displays service type, start type, error control, binary path, load order group,
//! tag, display name, dependencies, and service start name.
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

#[repr(C)]
struct QueryServiceConfigA {
    dw_service_type: u32,
    dw_start_type: u32,
    dw_error_control: u32,
    lp_binary_path_name: *const u8,
    lp_load_order_group: *const u8,
    dw_tag_id: u32,
    lp_dependencies: *const u8,
    lp_service_start_name: *const u8,
    lp_display_name: *const u8,
}

fn service_type_str(t: u32) -> &'static str {
    match t {
        0x1 => "KERNEL_DRIVER",
        0x2 => "FILE_SYSTEM_DRIVER",
        0x10 => "WIN32_OWN_PROCESS",
        0x110 => "WIN32_OWN_PROCESS (Interactive)",
        0x20 => "WIN32_SHARE_PROCESS",
        0x120 => "WIN32_SHARE_PROCESS (Interactive)",
        0x50 => "USER_OWN_PROCESS",
        0xD0 => "USER_OWN_PROCESS (Instance)",
        0x60 => "USER_SHARE_PROCESS",
        0xE0 => "USER_SHARE_PROCESS (Instance)",
        _ => "UNKNOWN",
    }
}

fn start_type_str(s: u32) -> &'static str {
    match s {
        0 => "BOOT",
        1 => "SYSTEM",
        2 => "AUTO",
        3 => "DEMAND",
        4 => "DISABLED",
        _ => "UNKNOWN",
    }
}

fn error_control_str(e: u32) -> &'static str {
    match e {
        0 => "IGNORE",
        1 => "NORMAL",
        2 => "SEVERE",
        3 => "CRITICAL",
        _ => "UNKNOWN",
    }
}

unsafe fn read_cstr(ptr: *const u8) -> &'static str {
    unsafe {
        if ptr.is_null() {
            "(null)"
        } else {
            CStr::from_ptr(ptr as *const i8)
                .to_str()
                .unwrap_or("(invalid)")
        }
    }
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
        QueryServiceConfigA(
            sc_service,
            core::ptr::null_mut() as *mut QUERY_SERVICE_CONFIGW as *mut _,
            0,
            &mut needed,
        );

        if needed == 0 {
            eprintln!(
                "QueryServiceConfigA failed to return size: 0x{:X}",
                GetLastError()
            );
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return;
        }

        let mut buf = vec![0u8; needed as usize];
        if QueryServiceConfigA(
            sc_service,
            buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW as *mut _,
            needed,
            &mut needed,
        ) == 0
        {
            eprintln!("QueryServiceConfigA failed: 0x{:X}", GetLastError());
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return;
        }

        let config = &*(buf.as_ptr() as *const QueryServiceConfigA);

        println!("SERVICE_NAME: {}", service_name);
        println!(
            "\t{:<20} : {} {}",
            "TYPE",
            config.dw_service_type,
            service_type_str(config.dw_service_type)
        );
        println!(
            "\t{:<20} : {} {}",
            "START_TYPE",
            config.dw_start_type,
            start_type_str(config.dw_start_type)
        );
        println!(
            "\t{:<20} : {} {}",
            "ERROR_CONTROL",
            config.dw_error_control,
            error_control_str(config.dw_error_control)
        );
        println!(
            "\t{:<20} : {}",
            "BINARY_PATH_NAME",
            read_cstr(config.lp_binary_path_name)
        );
        println!(
            "\t{:<20} : {}",
            "LOAD_ORDER_GROUP",
            read_cstr(config.lp_load_order_group)
        );
        println!("\t{:<20} : {}", "TAG", config.dw_tag_id);
        println!(
            "\t{:<20} : {}",
            "DISPLAY_NAME",
            read_cstr(config.lp_display_name)
        );
        println!(
            "\t{:<20} : {}",
            "DEPENDENCIES",
            read_cstr(config.lp_dependencies)
        );
        println!(
            "\t{:<20} : {}",
            "SERVICE_START_NAME",
            read_cstr(config.lp_service_start_name)
        );

        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
    }
}
