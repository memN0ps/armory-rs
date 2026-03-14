//! # Suspend/Resume Process BOF
//!
//! Suspends or resumes a target process by PID using the undocumented
//! `NtSuspendProcess` / `NtResumeProcess` NT APIs. Attempts to enable
//! `SeDebugPrivilege` first so that elevated processes can be targeted.
//!
//! ## MITRE ATT&CK
//! - T1106 - Native API
//!
//! ## Arguments
//! - `option` (short) - 0 = resume, 1 = suspend.
//! - `pid` (int) - Process ID of the target process.

#![no_std]

use core::ffi::c_void;
use core::ptr;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken};
const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
const STATUS_SUCCESS: i32 = 0;
unsafe extern "system" {
    fn NtSuspendProcess(process: *mut c_void) -> i32;
    fn NtResumeProcess(process: *mut c_void) -> i32;
}
fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token: HANDLE = core::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }

        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };

        let priv_name = b"SeDebugPrivilege\0";
        if LookupPrivilegeValueA(ptr::null(), priv_name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return false;
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let ok = AdjustTokenPrivileges(token, 0, &mut tp, 0, ptr::null_mut(), ptr::null_mut());
        CloseHandle(token);
        ok != 0
    }
}
#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let option = parser.get_short(); // 0 = resume, 1 = suspend
    let pid = parser.get_int() as u32;

    let action = if option == 1 { "Suspend" } else { "Resume" };
    println!("Attempting to {} process {} ...", action, pid);

    if enable_debug_privilege() {
        println!("SeDebugPrivilege enabled.");
    } else {
        println!("SeDebugPrivilege not available (non-fatal).");
    }

    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
        if handle.is_null() {
            eprintln!("OpenProcess failed for PID {}.", pid);
            return;
        }

        let status = if option == 1 {
            NtSuspendProcess(handle)
        } else {
            NtResumeProcess(handle)
        };

        if status == STATUS_SUCCESS {
            println!("Successfully {}ed process {}.", action.to_ascii_lowercase(), pid);
        } else {
            eprintln!("Nt{}Process failed with NTSTATUS: 0x{:08X}", action, status as u32);
        }

        CloseHandle(handle);
    }
}

trait AsciiLower {
    fn to_ascii_lowercase(&self) -> &str;
}

impl AsciiLower for str {
    fn to_ascii_lowercase(&self) -> &str {
        if self.as_bytes()[0] == b'S' {
            "suspend"
        } else {
            "resume"
        }
    }
}
