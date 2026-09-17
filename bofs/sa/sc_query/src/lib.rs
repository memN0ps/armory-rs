//! # Service Query BOF
//!
//! Queries the status of a specific Windows service or enumerates all services.
//! Displays service type, state, PID, exit codes, and flags.
//!
//! ## MITRE ATT&CK
//! - T1007 - System Service Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).
//! - `str`: Service name (empty to enumerate all services).

#![no_std]

use alloc::{string::String, vec};
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::*;

fn service_type_str(t: u32) -> &'static str {
    match t {
        0x1 => "KERNEL_DRIVER",
        0x2 => "FILE_DRIVER",
        0x10 => "WIN32_OWN",
        0x110 => "WIN32_OWN Interactive",
        0x20 => "WIN32_SHARED",
        0x120 => "WIN32_SHARED Interactive",
        0x50 => "USER_OWN",
        0xD0 => "USER_OWN Instance",
        0x60 => "USER_SHARED",
        0xE0 => "USER_SHARED Instance",
        _ => "UNKNOWN",
    }
}

fn service_state_str(s: u32) -> &'static str {
    match s {
        1 => "STOPPED",
        2 => "START_PENDING",
        3 => "STOP_PENDING",
        4 => "RUNNING",
        5 => "CONTINUE_PENDING",
        6 => "PAUSE_PENDING",
        7 => "PAUSED",
        _ => "UNKNOWN",
    }
}

fn query_single_service(hostname: *const u8, service_name: &str) {
    unsafe {
        let sc_manager = OpenSCManagerA(hostname, core::ptr::null(), SC_MANAGER_CONNECT);
        if sc_manager.is_null() {
            eprintln!("OpenSCManagerA failed: 0x{:X}", GetLastError());
            return;
        }

        let svc_cstr = rustbof::str::to_cstr(service_name);
        let sc_service = OpenServiceA(
            sc_manager,
            svc_cstr.as_ptr() as *const u8,
            SERVICE_QUERY_STATUS,
        );
        if sc_service.is_null() {
            eprintln!("OpenServiceA failed: 0x{:X}", GetLastError());
            CloseServiceHandle(sc_manager);
            return;
        }

        let mut ssp: SERVICE_STATUS_PROCESS = core::mem::zeroed();
        let mut needed: u32 = 0;
        if QueryServiceStatusEx(
            sc_service,
            SC_STATUS_PROCESS_INFO,
            &mut ssp as *mut _ as *mut u8,
            core::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        ) == 0
        {
            eprintln!("QueryServiceStatusEx failed: 0x{:X}", GetLastError());
        } else {
            println!("SERVICE_NAME: {}", service_name);
            println!(
                "\t{:<20} : {} {}",
                "TYPE",
                ssp.dwServiceType,
                service_type_str(ssp.dwServiceType)
            );
            println!(
                "\t{:<20} : {} {}",
                "STATE",
                ssp.dwCurrentState,
                service_state_str(ssp.dwCurrentState)
            );
            println!("\t{:<20} : {}", "WIN32_EXIT_CODE", ssp.dwWin32ExitCode);
            println!(
                "\t{:<20} : {}",
                "SERVICE_EXIT_CODE", ssp.dwServiceSpecificExitCode
            );
            println!("\t{:<20} : {}", "CHECKPOINT", ssp.dwCheckPoint);
            println!("\t{:<20} : {}", "WAIT_HINT", ssp.dwWaitHint);
            println!("\t{:<20} : {}", "PID", ssp.dwProcessId);
            println!("\t{:<20} : {}", "Flags", ssp.dwServiceFlags);
        }

        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
    }
}

fn enumerate_all_services(hostname: *const u8) {
    unsafe {
        let sc_manager = OpenSCManagerA(
            hostname,
            core::ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        );
        if sc_manager.is_null() {
            eprintln!("OpenSCManagerA failed: 0x{:X}", GetLastError());
            return;
        }

        let mut needed: u32 = 0;
        let mut returned: u32 = 0;
        let mut resume: u32 = 0;
        EnumServicesStatusExA(
            sc_manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            core::ptr::null_mut(),
            0,
            &mut needed,
            &mut returned,
            &mut resume,
            core::ptr::null(),
        );

        if needed == 0 {
            eprintln!("EnumServicesStatusExA failed: 0x{:X}", GetLastError());
            CloseServiceHandle(sc_manager);
            return;
        }

        let mut buf = vec![0u8; needed as usize];
        resume = 0;
        if EnumServicesStatusExA(
            sc_manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buf.as_mut_ptr(),
            needed,
            &mut needed,
            &mut returned,
            &mut resume,
            core::ptr::null(),
        ) == 0
        {
            eprintln!("EnumServicesStatusExA failed: 0x{:X}", GetLastError());
            CloseServiceHandle(sc_manager);
            return;
        }

        let entries = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSA;
        for i in 0..returned as usize {
            let entry = &*entries.add(i);
            let name = core::ffi::CStr::from_ptr(entry.lpServiceName as *const i8)
                .to_str()
                .unwrap_or("?");
            let display = core::ffi::CStr::from_ptr(entry.lpDisplayName as *const i8)
                .to_str()
                .unwrap_or("?");
            let ssp = &entry.ServiceStatusProcess;

            println!(
                "{:<32} {:<40} {:<8} {:<20} PID:{}",
                name,
                display,
                service_state_str(ssp.dwCurrentState),
                service_type_str(ssp.dwServiceType),
                ssp.dwProcessId
            );
        }

        println!("\nTotal services: {}", returned);
        CloseServiceHandle(sc_manager);
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());
    let service_name = String::from(parser.get_str());

    let host_ptr = if hostname.is_empty() {
        core::ptr::null()
    } else {
        let cstr = rustbof::str::to_cstr(&hostname);
        let ptr = cstr.as_ptr() as *const u8;
        core::mem::forget(cstr);
        ptr
    };

    if service_name.is_empty() {
        enumerate_all_services(host_ptr);
    } else {
        query_single_service(host_ptr, &service_name);
    }
}
