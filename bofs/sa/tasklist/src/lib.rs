//! # Task List BOF
//!
//! Enumerates local processes with process ID, parent process ID, session, and
//! image name.
//!
//! ## MITRE ATT&CK
//! - T1057 - Process Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::string::String;
use rustbof::{eprintln, println};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        RemoteDesktop::ProcessIdToSessionId,
    },
};

fn image_name(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(value.len());

    String::from_utf16_lossy(&value[..length])
}

fn run() -> Result<u32, u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(unsafe { GetLastError() });
    }

    let mut entry: PROCESSENTRY32W = unsafe { core::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut count = 0u32;
    let mut current = unsafe { Process32FirstW(snapshot, &mut entry) };

    while current != 0 && count < 4096 {
        let mut session = 0u32;
        let session = if unsafe { ProcessIdToSessionId(entry.th32ProcessID, &mut session) } != 0 {
            session
        } else {
            u32::MAX
        };

        println!(
            "{:<7} {:<7} {:<7} {}",
            entry.th32ProcessID,
            entry.th32ParentProcessID,
            if session == u32::MAX { 0 } else { session },
            image_name(&entry.szExeFile)
        );
        count += 1;
        current = unsafe { Process32NextW(snapshot, &mut entry) };
    }

    unsafe { CloseHandle(snapshot) };

    Ok(count)
}

#[rustbof::main]
fn main() {
    println!("Process inventory\n");
    println!("{:<7} {:<7} {:<7} {}", "PID", "PPID", "Session", "Image");
    println!("{:-<7} {:-<7} {:-<7} {:-<32}", "", "", "", "");
    match run() {
        Ok(count) => println!("Processes: {}", count),
        Err(error) => eprintln!("Process snapshot failed: {}", error),
    }
}
