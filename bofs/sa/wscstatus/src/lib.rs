//! # Windows Security Center Status BOF
//!
//! Queries aggregate Windows Security Center health for each documented
//! provider category. This reports the state seen by Security Center rather
//! than inferring protection from a process or service name.
//!
//! ## MITRE ATT&CK
//! - T1518.001 - Software Discovery: Security Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerA, OpenServiceA, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};

type WscGetSecurityProviderHealth = unsafe extern "system" fn(u32, *mut u32) -> i32;

static PROVIDERS: &[(&str, u32)] = &[
    ("Firewall", 0x01),
    ("Automatic updates", 0x02),
    ("Antivirus", 0x04),
    ("Antispyware", 0x08),
    ("Internet settings", 0x10),
    ("User Account Control", 0x20),
    ("Security Center service", 0x40),
];

fn health_name(health: u32) -> &'static str {
    match health {
        0 => "good",
        1 => "not monitored",
        2 => "poor",
        3 => "snooze",
        _ => "unknown",
    }
}

fn service_state() {
    unsafe {
        let manager = OpenSCManagerA(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            eprintln!("Security Center service: service manager open failed");
            return;
        }

        let service = OpenServiceA(
            manager,
            c"wscsvc".as_ptr() as *const u8,
            SERVICE_QUERY_STATUS,
        );
        if service.is_null() {
            println!("Security Center service: not available");
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
            eprintln!("Security Center service: status query failed");
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
            println!("Security Center service: {}", state);
        }

        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
}

unsafe fn symbol(module: HMODULE, name: &[u8]) -> *const core::ffi::c_void {
    unsafe { GetProcAddress(module, name.as_ptr()).map_or(core::ptr::null(), |p| p as *const _) }
}

fn provider_health() {
    unsafe {
        let module = LoadLibraryA(c"wscapi.dll".as_ptr() as *const u8);
        if module.is_null() {
            eprintln!("wscapi.dll is unavailable");
            return;
        }

        let function = symbol(module, b"WscGetSecurityProviderHealth\0");
        if function.is_null() {
            eprintln!("WscGetSecurityProviderHealth is unavailable");
            FreeLibrary(module);
            return;
        }

        let query: WscGetSecurityProviderHealth = core::mem::transmute(function);
        for &(name, provider) in PROVIDERS {
            let mut health = 0u32;
            let result = query(provider, &mut health);
            if result < 0 {
                eprintln!("{:<24} query failed: 0x{:08X}", name, result as u32);
            } else {
                println!("{:<24} {}", name, health_name(health));
            }
        }

        FreeLibrary(module);
    }
}

#[rustbof::main]
fn main() {
    println!("Windows Security Center health\n");
    service_state();
    println!();
    provider_health();
}
