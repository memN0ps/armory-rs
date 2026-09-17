//! # Windows Event Forwarding Status BOF
//!
//! Reports Windows Event Collector service state and enumerates local Windows
//! Event Forwarding subscription names through the documented WEC API.
//!
//! ## MITRE ATT&CK
//! - T1518.001 - Software Discovery: Security Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{string::String, vec};
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerA, OpenServiceA, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_ITEMS: u32 = 259;

type EcHandle = *mut core::ffi::c_void;
type EcOpenSubscriptionEnum = unsafe extern "system" fn(u32) -> EcHandle;
type EcEnumNextSubscription = unsafe extern "system" fn(EcHandle, u32, *mut u16, *mut u32) -> i32;
type EcClose = unsafe extern "system" fn(EcHandle) -> i32;

fn wide_to_string(buffer: &[u16]) -> String {
    let length = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

fn service_running() -> bool {
    unsafe {
        let manager = OpenSCManagerA(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            eprintln!("Windows Event Collector service: service manager open failed");
            return false;
        }

        let service = OpenServiceA(
            manager,
            c"Wecsvc".as_ptr() as *const u8,
            SERVICE_QUERY_STATUS,
        );
        if service.is_null() {
            println!("Windows Event Collector service: not available");
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
        let running = if ok == 0 {
            eprintln!("Windows Event Collector service: status query failed");
            false
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
            println!("Windows Event Collector service: {}", state);
            status.dwCurrentState == 4
        };

        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        running
    }
}

unsafe fn symbol(module: HMODULE, name: &[u8]) -> *const core::ffi::c_void {
    unsafe { GetProcAddress(module, name.as_ptr()).map_or(core::ptr::null(), |p| p as *const _) }
}

fn enumerate_subscriptions() {
    unsafe {
        let wecapi = LoadLibraryA(c"wecapi.dll".as_ptr() as *const u8);
        if wecapi.is_null() {
            eprintln!("  WEC API is unavailable");
            return;
        }

        let open_ptr = symbol(wecapi, b"EcOpenSubscriptionEnum\0");
        let next_ptr = symbol(wecapi, b"EcEnumNextSubscription\0");
        let close_ptr = symbol(wecapi, b"EcClose\0");
        if open_ptr.is_null() || next_ptr.is_null() || close_ptr.is_null() {
            eprintln!("  required WEC function is unavailable");
            FreeLibrary(wecapi);
            return;
        }

        let open: EcOpenSubscriptionEnum = core::mem::transmute(open_ptr);
        let next: EcEnumNextSubscription = core::mem::transmute(next_ptr);
        let close: EcClose = core::mem::transmute(close_ptr);

        let enumeration = open(0);
        if enumeration.is_null() {
            let error = GetLastError();
            eprintln!("  enumeration open failed: 0x{:X}", error);
            FreeLibrary(wecapi);
            return;
        }

        let mut count = 0u32;
        loop {
            let mut needed = 0u32;
            let ok = next(enumeration, 0, core::ptr::null_mut(), &mut needed);
            let error = if ok == 0 { GetLastError() } else { 0 };

            if error == ERROR_NO_MORE_ITEMS {
                break;
            }
            if error != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
                eprintln!("  enumeration failed: 0x{:X}", error);
                break;
            }

            let mut name = vec![0u16; needed as usize];
            if next(enumeration, needed, name.as_mut_ptr(), &mut needed) == 0 {
                eprintln!("  subscription query failed: 0x{:X}", GetLastError());
                break;
            }

            println!("  {}", wide_to_string(&name));
            count += 1;
        }

        if count == 0 {
            println!("  <none visible>");
        }
        println!("\nSummary: {} subscription(s)", count);

        close(enumeration);
        FreeLibrary(wecapi);
    }
}

#[rustbof::main]
fn main() {
    println!("Windows Event Forwarding configuration\n");
    if service_running() {
        println!("Subscriptions:");
        enumerate_subscriptions();
    } else {
        println!("Subscriptions: <unavailable while the collector service is stopped>");
    }
}
