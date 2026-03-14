//! # Get Privilege BOF
//!
//! Enables a specified privilege on the current process or thread token.
//! Prefix privilege name with `~` to target the thread token (useful for
//! impersonated tokens) instead of the process token.
//!
//! ## MITRE ATT&CK
//! - T1134.002 - Access Token Manipulation: Create Process with Token
//!
//! ## Arguments
//! - `str`: Privilege name (e.g., `SeDebugPrivilege`, `~SeDebugPrivilege`).

#![no_std]

use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LUID, FALSE, ERROR_SUCCESS};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken};

unsafe extern "system" {
    fn OpenThreadToken(
        thread: *mut core::ffi::c_void,
        desired: u32,
        open_as_self: i32,
        token: *mut *mut core::ffi::c_void,
    ) -> i32;
}

fn set_privilege(priv_name: &str, use_thread: bool) -> u32 {
    unsafe {
        let mut token: *mut core::ffi::c_void = core::ptr::null_mut();
        if use_thread {
            if OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &mut token) == FALSE {
                return GetLastError();
            }
        } else {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == FALSE {
                return GetLastError();
            }
        }

        let mut luid: LUID = core::mem::zeroed();
        let name_cstr = rustbof::str::to_cstr(priv_name);
        if LookupPrivilegeValueA(core::ptr::null(), name_cstr.as_ptr() as *const u8, &mut luid) == FALSE {
            let err = GetLastError();
            CloseHandle(token);
            return err;
        }

        let mut tp: TOKEN_PRIVILEGES = core::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(
            token, FALSE, &tp,
            core::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            core::ptr::null_mut(), core::ptr::null_mut(),
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
    let priv_arg = parser.get_str();

    let (priv_name, use_thread) = if priv_arg.starts_with('~') {
        (&priv_arg[1..], true)
    } else {
        (priv_arg, false)
    };

    let status = set_privilege(priv_name, use_thread);
    if status != ERROR_SUCCESS {
        println!("Failed to activate priv {} : {}", priv_arg, status);
    } else {
        println!("SUCCESS: Activated priv {}.", priv_arg);
    }
}
