//! # Sysmon Status BOF
//!
//! Reports Sysmon service and driver state, configured binary paths, and the
//! operational event-channel flag without invoking Sysmon itself.
//!
//! ## MITRE ATT&CK
//! - T1518.001 - Software Discovery: Security Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::vec;
use core::ffi::CStr;
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::{
    HKEY, KEY_READ, KEY_WOW64_64KEY, RegCloseKey, RegOpenKeyExA, RegQueryValueExA,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerA, OpenServiceA, QUERY_SERVICE_CONFIGA, QueryServiceConfigA,
    QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};

const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const REG_DWORD: u32 = 4;

fn service_state(name: &[u8], label: &str) -> bool {
    unsafe {
        let manager = OpenSCManagerA(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            eprintln!("{}: service manager open failed", label);
            return false;
        }

        let service = OpenServiceA(
            manager,
            name.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        );
        if service.is_null() {
            CloseServiceHandle(manager);
            return false;
        }

        let mut status: SERVICE_STATUS_PROCESS = core::mem::zeroed();
        let mut needed = 0u32;
        let ok = QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            core::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        );
        if ok == 0 {
            eprintln!("{}: status query failed", label);
        } else {
            let state = match status.dwCurrentState {
                1 => "stopped",
                2 => "start pending",
                3 => "stop pending",
                4 => "running",
                5 => "continue pending",
                6 => "pause pending",
                7 => "paused",
                _ => "unknown",
            };
            println!("{}: {}", label, state);
        }

        needed = 0;
        QueryServiceConfigA(service, core::ptr::null_mut(), 0, &mut needed);
        if needed > 0 {
            let mut buffer = vec![0u8; needed as usize];
            if QueryServiceConfigA(
                service,
                buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGA,
                needed,
                &mut needed,
            ) != 0
            {
                let config = &*(buffer.as_ptr() as *const QUERY_SERVICE_CONFIGA);
                if !config.lpBinaryPathName.is_null() {
                    let path = CStr::from_ptr(config.lpBinaryPathName as *const i8)
                        .to_str()
                        .unwrap_or("<invalid path>");
                    println!("  path: {}", path);
                }
            }
        }

        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        true
    }
}

fn channel_enabled() -> Result<Option<u32>, u32> {
    unsafe {
        let path = b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational\0";
        let mut key: HKEY = core::ptr::null_mut();
        let status = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE as HKEY,
            path.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        );
        if status != 0 {
            return Err(status);
        }

        let mut value = 0u32;
        let mut value_type = 0u32;
        let mut value_size = core::mem::size_of::<u32>() as u32;
        let status = RegQueryValueExA(
            key,
            c"Enabled".as_ptr() as *const u8,
            core::ptr::null(),
            &mut value_type,
            &mut value as *mut _ as *mut u8,
            &mut value_size,
        );
        RegCloseKey(key);

        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(status);
        }
        if value_type != REG_DWORD {
            return Ok(None);
        }

        Ok(Some(value))
    }
}

#[rustbof::main]
fn main() {
    println!("Sysmon status\n");

    let mut found = false;
    found |= service_state(b"Sysmon64\0", "Sysmon64 service");
    found |= service_state(b"Sysmon\0", "Sysmon service");
    found |= service_state(b"SysmonDrv\0", "Sysmon driver");

    if !found {
        println!("No standard Sysmon service name was found.");
    }

    match channel_enabled() {
        Ok(Some(0)) => println!("Operational event channel: disabled"),
        Ok(Some(_)) => println!("Operational event channel: enabled"),
        Ok(None) => println!("Operational event channel: state not specified"),
        Err(ERROR_FILE_NOT_FOUND) => println!("Operational event channel: not registered"),
        Err(status) => eprintln!("Operational event channel query failed: 0x{:X}", status),
    }
}
