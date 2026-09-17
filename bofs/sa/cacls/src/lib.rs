//! # Cacls BOF
//!
//! Displays file or directory DACL permissions by resolving each ACE
//! to an account name and printing the associated access rights.
//!
//! ## MITRE ATT&CK
//! - T1222 - File and Directory Permissions Modification
//!
//! ## Arguments
//! - `str`: File or directory path to query.

#![no_std]

use alloc::format;
use rustbof::data::DataParser;
use rustbof::str::to_cstr;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoA, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, GetAce,
    GetAclInformation, LookupAccountSidA, SID_NAME_USE,
};

#[repr(C)]
struct AccessAllowedAce {
    header_type: u8,
    header_flags: u8,
    header_size: u16,
    mask: u32,
    sid_start: u32,
}

fn format_mask(mask: u32) -> alloc::string::String {
    let mut perms = alloc::string::String::new();

    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const GENERIC_EXECUTE: u32 = 0x20000000;
    const GENERIC_ALL: u32 = 0x10000000;
    const FILE_READ_DATA: u32 = 0x0001;
    const FILE_WRITE_DATA: u32 = 0x0002;
    const FILE_EXECUTE: u32 = 0x0020;
    const DELETE: u32 = 0x00010000;
    const READ_CONTROL: u32 = 0x00020000;
    const WRITE_DAC: u32 = 0x00040000;
    const WRITE_OWNER: u32 = 0x00080000;
    const SYNCHRONIZE: u32 = 0x00100000;

    if mask & GENERIC_ALL != 0 || mask == 0x001F01FF {
        return alloc::string::String::from("FULL_CONTROL");
    }

    if mask & (GENERIC_READ | FILE_READ_DATA | READ_CONTROL) != 0 {
        perms.push_str("READ ");
    }
    if mask & (GENERIC_WRITE | FILE_WRITE_DATA) != 0 {
        perms.push_str("WRITE ");
    }
    if mask & (GENERIC_EXECUTE | FILE_EXECUTE) != 0 {
        perms.push_str("EXECUTE ");
    }
    if mask & DELETE != 0 {
        perms.push_str("DELETE ");
    }
    if mask & WRITE_DAC != 0 {
        perms.push_str("WRITE_DAC ");
    }
    if mask & WRITE_OWNER != 0 {
        perms.push_str("WRITE_OWNER ");
    }
    if mask & SYNCHRONIZE != 0 {
        perms.push_str("SYNCHRONIZE ");
    }

    if perms.is_empty() {
        return format!("0x{:08X}", mask);
    }

    perms.truncate(perms.trim_end().len());
    perms
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let path = parser.get_str();
    let path_c = to_cstr(path);

    unsafe {
        let mut dacl: *mut ACL = core::ptr::null_mut();
        let mut sd: *mut core::ffi::c_void = core::ptr::null_mut();

        let result = GetNamedSecurityInfoA(
            path_c.as_ptr() as *const u8,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut dacl,
            core::ptr::null_mut(),
            &mut sd,
        );

        if result != ERROR_SUCCESS {
            eprintln!("GetNamedSecurityInfoA failed: {}", result);
            return;
        }

        if dacl.is_null() {
            println!("No DACL found for {}", path);
            LocalFree(sd);
            return;
        }

        let mut acl_info: ACL_SIZE_INFORMATION = core::mem::zeroed();
        if GetAclInformation(
            dacl,
            &mut acl_info as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
        {
            eprintln!("GetAclInformation failed");
            LocalFree(sd);
            return;
        }

        println!("Permissions for: {}", path);
        println!("{:<40} {}", "Account", "Access");
        println!("{}", "-".repeat(70));

        for i in 0..acl_info.AceCount {
            let mut ace_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
            if GetAce(dacl, i, &mut ace_ptr) == 0 {
                continue;
            }

            let ace = ace_ptr as *const AccessAllowedAce;
            let ace_type = (*ace).header_type;

            if ace_type > 1 {
                continue;
            }

            let mask = (*ace).mask;

            let sid = (ace as *const u8).add(8) as *const core::ffi::c_void;

            let mut name_buf = [0u8; 256];
            let mut name_len: u32 = 256;
            let mut domain_buf = [0u8; 256];
            let mut domain_len: u32 = 256;
            let mut sid_use: SID_NAME_USE = 0;

            let lookup_ok = LookupAccountSidA(
                core::ptr::null(),
                sid as *mut core::ffi::c_void,
                name_buf.as_mut_ptr(),
                &mut name_len,
                domain_buf.as_mut_ptr(),
                &mut domain_len,
                &mut sid_use,
            );

            let account = if lookup_ok != 0 {
                let domain = core::str::from_utf8(&domain_buf[..domain_len as usize]).unwrap_or("");
                let name = core::str::from_utf8(&name_buf[..name_len as usize]).unwrap_or("");
                if domain.is_empty() {
                    alloc::string::String::from(name)
                } else {
                    format!("{}\\{}", domain, name)
                }
            } else {
                alloc::string::String::from("(unknown)")
            };

            let ace_kind = if ace_type == 0 { "ALLOW" } else { "DENY" };
            let perms = format_mask(mask);

            println!("{:<40} {} {}", account, ace_kind, perms);
        }

        LocalFree(sd);
    }
}
