//! # AppLocker Status BOF
//!
//! Reports Application Identity service state and the configured enforcement
//! mode and rule count for each AppLocker collection.
//!
//! ## MITRE ATT&CK
//! - T1518.001 - Software Discovery: Security Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::vec;
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::{
    HKEY, KEY_READ, KEY_WOW64_64KEY, RegCloseKey, RegEnumKeyExA, RegOpenKeyExA, RegQueryValueExA,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerA, OpenServiceA, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};

const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const REG_DWORD: u32 = 4;

struct Collection {
    name: &'static str,
    path: &'static [u8],
}

static COLLECTIONS: &[Collection] = &[
    Collection {
        name: "Executable",
        path: b"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Exe\0",
    },
    Collection {
        name: "Windows Installer",
        path: b"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Msi\0",
    },
    Collection {
        name: "Script",
        path: b"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Script\0",
    },
    Collection {
        name: "DLL",
        path: b"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Dll\0",
    },
    Collection {
        name: "Packaged app",
        path: b"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Appx\0",
    },
];

fn service_state() {
    unsafe {
        let manager = OpenSCManagerA(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            eprintln!("Application Identity service: service manager open failed");
            return;
        }

        let service = OpenServiceA(
            manager,
            c"AppIDSvc".as_ptr() as *const u8,
            SERVICE_QUERY_STATUS,
        );
        if service.is_null() {
            println!("Application Identity service: not available");
            CloseServiceHandle(manager);
            return;
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
            eprintln!("Application Identity service: status query failed");
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
            println!("Application Identity service: {}", state);
        }

        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
}

fn collection_state(collection: &Collection) -> Result<(Option<u32>, u32), u32> {
    unsafe {
        let mut key: HKEY = core::ptr::null_mut();
        let status = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE as HKEY,
            collection.path.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        );
        if status != 0 {
            return Err(status);
        }

        let mut mode = 0u32;
        let mut mode_type = 0u32;
        let mut mode_size = core::mem::size_of::<u32>() as u32;
        let mode_status = RegQueryValueExA(
            key,
            c"EnforcementMode".as_ptr() as *const u8,
            core::ptr::null(),
            &mut mode_type,
            &mut mode as *mut _ as *mut u8,
            &mut mode_size,
        );
        let configured_mode = if mode_status == 0 && mode_type == REG_DWORD {
            Some(mode)
        } else {
            None
        };

        let mut count = 0u32;
        loop {
            let mut name = vec![0u8; 260];
            let mut name_len = name.len() as u32;
            let status = RegEnumKeyExA(
                key,
                count,
                name.as_mut_ptr(),
                &mut name_len,
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );

            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != 0 {
                RegCloseKey(key);
                return Err(status);
            }
            count += 1;
        }

        RegCloseKey(key);
        Ok((configured_mode, count))
    }
}

fn mode_name(mode: Option<u32>) -> &'static str {
    match mode {
        Some(0) => "not configured",
        Some(1) => "enforced",
        Some(2) => "audit only",
        Some(_) => "unknown",
        None => "not specified",
    }
}

#[rustbof::main]
fn main() {
    println!("AppLocker configuration\n");
    service_state();
    println!();

    let mut configured = 0u32;
    for collection in COLLECTIONS {
        match collection_state(collection) {
            Ok((mode, count)) => {
                println!(
                    "{:<20} mode={:<16} rules={}",
                    collection.name,
                    mode_name(mode),
                    count
                );
                configured += 1;
            }
            Err(ERROR_FILE_NOT_FOUND) => println!(
                "{:<20} mode={:<16} rules=0",
                collection.name, "not configured"
            ),
            Err(status) => eprintln!("{} query failed: 0x{:X}", collection.name, status),
        }
    }

    println!("\nSummary: {} collection key(s) present", configured);
}
