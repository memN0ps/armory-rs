//! # Start WebClient BOF
//!
//! Starts the Windows WebClient service from a standard user context by
//! emitting its documented service-trigger ETW event, then verifies the
//! resulting service state.
//!
//! ## MITRE ATT&CK
//! - T1569.002 - System Services: Service Execution
//!
//! ## Arguments
//! None.

#![no_std]

use rustbof::{eprintln, println};
use windows_sys::{
    Win32::System::{
        Diagnostics::Etw::{EVENT_DESCRIPTOR, EventRegister, EventUnregister, EventWrite},
        Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
            SERVICE_STATUS_PROCESS,
        },
        Threading::Sleep,
    },
    core::GUID,
};

const WEBCLIENT_TRIGGER: GUID = GUID {
    data1: 0x22B6D684,
    data2: 0xFA63,
    data3: 0x4578,
    data4: [0x87, 0xC9, 0xEF, 0xFC, 0xBE, 0x66, 0x43, 0xC7],
};

fn service_running() -> Result<bool, u32> {
    let service_name = [
        'W' as u16, 'e' as u16, 'b' as u16, 'C' as u16, 'l' as u16, 'i' as u16, 'e' as u16,
        'n' as u16, 't' as u16, 0,
    ];

    unsafe {
        let manager = OpenSCManagerW(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return Err(windows_sys::Win32::Foundation::GetLastError());
        }

        let service = OpenServiceW(manager, service_name.as_ptr(), SERVICE_QUERY_STATUS);
        if service.is_null() {
            let error = windows_sys::Win32::Foundation::GetLastError();
            CloseServiceHandle(manager);
            return Err(error);
        }

        let mut status: SERVICE_STATUS_PROCESS = core::mem::zeroed();
        let mut needed = 0u32;
        let success = QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        );
        let error = if success == 0 {
            windows_sys::Win32::Foundation::GetLastError()
        } else {
            0
        };
        CloseServiceHandle(service);
        CloseServiceHandle(manager);

        if success == 0 {
            Err(error)
        } else {
            Ok(status.dwCurrentState == SERVICE_RUNNING)
        }
    }
}

fn trigger_service() -> Result<(), u32> {
    let mut registration = 0u64;
    let status = unsafe {
        EventRegister(
            &WEBCLIENT_TRIGGER,
            None,
            core::ptr::null(),
            &mut registration,
        )
    };
    if status != 0 {
        return Err(status);
    }

    let descriptor = EVENT_DESCRIPTOR {
        Id: 1,
        Version: 0,
        Channel: 0,
        Level: 4,
        Opcode: 0,
        Task: 0,
        Keyword: 0,
    };
    let result = unsafe { EventWrite(registration as i64, &descriptor, 0, core::ptr::null()) };
    unsafe { EventUnregister(registration as i64) };

    if result == 0 { Ok(()) } else { Err(result) }
}

#[rustbof::main]
fn main() {
    println!("WebClient service trigger");

    match service_running() {
        Ok(true) => {
            println!("[+] WebClient is already running.");
            return;
        }
        Ok(false) => println!("[*] WebClient is stopped. Emitting the service trigger."),
        Err(error) => eprintln!("[-] Initial service query failed: {}", error),
    }

    if let Err(error) = trigger_service() {
        eprintln!("[-] WebClient trigger failed: {}", error);
        return;
    }

    unsafe { Sleep(750) };
    match service_running() {
        Ok(true) => println!("[+] WebClient started and the running state was verified."),
        Ok(false) => eprintln!("[-] WebClient did not reach the running state."),
        Err(error) => eprintln!("[-] Final service query failed: {}", error),
    }
}
