//! # Service Query Failure Actions BOF
//!
//! Queries the failure actions configured for a specific Windows service using
//! QueryServiceConfig2A with SERVICE_CONFIG_FAILURE_ACTIONS (value 2).
//! Displays the reset period, reboot message, command, and each configured
//! failure action with its type and delay.
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

const SERVICE_CONFIG_FAILURE_ACTIONS: u32 = 2;

#[repr(C)]
struct ServiceFailureActionsA {
    dwResetPeriod: u32,
    lpRebootMsg: *const u8,
    lpCommand: *const u8,
    cActions: u32,
    lpsaActions: *const ScAction,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ScAction {
    r#type: u32,
    delay: u32,
}

fn action_type_str(t: u32) -> &'static str {
    match t {
        0 => "SC_ACTION_NONE",
        1 => "SC_ACTION_RESTART",
        2 => "SC_ACTION_REBOOT",
        3 => "SC_ACTION_RUN_COMMAND",
        _ => "UNKNOWN",
    }
}

unsafe fn read_cstr(ptr: *const u8) -> &'static str {
    if ptr.is_null() {
        "(null)"
    } else {
        CStr::from_ptr(ptr as *const i8)
            .to_str()
            .unwrap_or("(invalid)")
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
        QueryServiceConfig2A(
            sc_service,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            core::ptr::null_mut(),
            0,
            &mut needed,
        );

        if needed == 0 {
            eprintln!(
                "QueryServiceConfig2A failed to return size: 0x{:X}",
                GetLastError()
            );
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return;
        }

        let mut buf = vec![0u8; needed as usize];
        if QueryServiceConfig2A(
            sc_service,
            SERVICE_CONFIG_FAILURE_ACTIONS,
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

        let fa = &*(buf.as_ptr() as *const ServiceFailureActionsA);

        println!("SERVICE_NAME: {}", service_name);
        println!("\t{:<20} : {} seconds", "RESET_PERIOD", fa.dwResetPeriod);
        println!("\t{:<20} : {}", "REBOOT_MESSAGE", read_cstr(fa.lpRebootMsg));
        println!("\t{:<20} : {}", "COMMAND", read_cstr(fa.lpCommand));
        println!("\t{:<20} : {}", "NUM_ACTIONS", fa.cActions);

        if !fa.lpsaActions.is_null() && fa.cActions > 0 {
            let actions = core::slice::from_raw_parts(fa.lpsaActions, fa.cActions as usize);
            for (i, action) in actions.iter().enumerate() {
                println!(
                    "\tACTION[{}]             : {} (delay: {} ms)",
                    i,
                    action_type_str(action.r#type),
                    action.delay
                );
            }
        }

        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
    }
}
