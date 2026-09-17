//! # Loaded Modules BOF
//!
//! Enumerates all loaded modules (DLLs) in a target process using
//! EnumProcessModulesEx and GetModuleFileNameExA. If PID 0 is specified,
//! the current process is used.
//!
//! ## Arguments
//! - `int`: Process identifier. Use `0` for the current process.
//!
//! ## MITRE ATT&CK
//! - T1057 - Process Discovery

#![no_std]

use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExA, LIST_MODULES_ALL,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

const MAX_MODULES: usize = 1024;

const MAX_PATH_LEN: usize = 260;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let pid = parser.get_int() as u32;

    let pid = if pid == 0 {
        unsafe { GetCurrentProcessId() }
    } else {
        pid
    };

    println!("Listing modules for PID: {}\n", pid);

    unsafe {
        let handle: HANDLE = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0, // FALSE
            pid,
        );

        if handle.is_null() {
            eprintln!("Failed to open process with PID: {}", pid);
            return;
        }

        let mut modules: [*mut core::ffi::c_void; MAX_MODULES] =
            [core::ptr::null_mut(); MAX_MODULES];
        let mut needed: u32 = 0;

        let success = EnumProcessModulesEx(
            handle,
            modules.as_mut_ptr() as *mut *mut core::ffi::c_void,
            (MAX_MODULES * core::mem::size_of::<*mut core::ffi::c_void>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        );

        if success == 0 {
            eprintln!("EnumProcessModulesEx failed for PID: {}", pid);
            CloseHandle(handle);
            return;
        }

        let count = needed as usize / core::mem::size_of::<*mut core::ffi::c_void>();

        println!("{:<6} {}", "#", "Module Path");
        println!("{:-<6} {:-<60}", "", "");

        for i in 0..count {
            let mut name_buf = [0u8; MAX_PATH_LEN];
            let len = GetModuleFileNameExA(
                handle,
                modules[i],
                name_buf.as_mut_ptr(),
                MAX_PATH_LEN as u32,
            );

            if len > 0 {
                let path = core::str::from_utf8(&name_buf[..len as usize]).unwrap_or("<invalid>");
                println!("{:<6} {}", i, path);
            }
        }

        println!("\nTotal modules: {}", count);

        CloseHandle(handle);
    }
}
