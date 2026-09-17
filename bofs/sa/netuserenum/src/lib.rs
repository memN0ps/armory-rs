//! # Net User Enum BOF
//!
//! Enumerates user accounts on a local or remote computer using NetUserEnum.
//! Supports filtering by account status: all users, locked, disabled, or active.
//! Optionally queries a domain controller via NetGetAnyDCName when targeting a domain.
//!
//! ## MITRE ATT&CK
//! - T1087.001 - Account Discovery: Local Account
//! - T1087.002 - Account Discovery: Domain Account
//!
//! ## Arguments
//! - `int`: usedomain - 0 for local, 1 for domain (queries a DC via NetGetAnyDCName)
//! - `int`: userfilter - 1=all, 2=locked, 3=disabled, 4=active

#![no_std]

use core::ffi::c_void;
use rustbof::data::DataParser;
use rustbof::str::from_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;

#[repr(C)]
struct UserInfo0 {
    usri0_name: *mut u16,
}

#[repr(C)]
struct UserInfo1 {
    usri1_name: *mut u16,
    usri1_password: *mut u16,
    usri1_password_age: u32,
    usri1_priv: u32,
    usri1_home_dir: *mut u16,
    usri1_comment: *mut u16,
    usri1_flags: u32,
    usri1_script_path: *mut u16,
}

unsafe extern "system" {
    fn NetUserEnum(
        servername: *const u16,
        level: u32,
        filter: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32;

    fn NetGetAnyDCName(servername: *const u16, domainname: *const u16, bufptr: *mut *mut u8)
    -> u32;
}

const FILTER_NORMAL_ACCOUNT: u32 = 0x0002;
const UF_LOCKOUT: u32 = 0x0010;
const UF_ACCOUNTDISABLE: u32 = 0x0002;
const NERR_SUCCESS: u32 = 0;
const ERROR_MORE_DATA: u32 = 234;
const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let usedomain = parser.get_int();
    let userfilter = parser.get_int();

    if !(1..=4).contains(&userfilter) {
        eprintln!(
            "Error: invalid userfilter {}. Use 1=all, 2=locked, 3=disabled, 4=active.",
            userfilter
        );
        return;
    }

    unsafe {
        let mut server_ptr: *const u16 = core::ptr::null();
        let mut dc_buf: *mut u8 = core::ptr::null_mut();

        if usedomain == 1 {
            let status = NetGetAnyDCName(core::ptr::null(), core::ptr::null(), &mut dc_buf);
            if status != NERR_SUCCESS {
                eprintln!("NetGetAnyDCName failed with error: {}", status);
                return;
            }
            server_ptr = dc_buf as *const u16;
            let dc_name = wide_ptr_to_str(server_ptr);
            println!("Domain Controller: {}\n", dc_name);
        }

        let filter_name = match userfilter {
            1 => "All Users",
            2 => "Locked Users",
            3 => "Disabled Users",
            4 => "Active Users",
            _ => "Unknown",
        };
        println!("User enumeration (filter: {}):\n", filter_name);

        if userfilter == 1 {
            enum_users_level0(server_ptr);
        } else {
            enum_users_level1(server_ptr, userfilter);
        }

        if !dc_buf.is_null() {
            NetApiBufferFree(dc_buf as *const c_void);
        }
    }
}

unsafe fn enum_users_level0(server_ptr: *const u16) {
    unsafe {
        println!("  {:<40}", "Username");
        println!("  {:<40}", "--------");

        let mut resume_handle: u32 = 0;
        let mut total_count: u32 = 0;

        loop {
            let mut buf: *mut u8 = core::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;

            let status = NetUserEnum(
                server_ptr,
                0,
                FILTER_NORMAL_ACCOUNT,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            );

            if status != NERR_SUCCESS && status != ERROR_MORE_DATA {
                eprintln!("NetUserEnum failed with error: {}", status);
                break;
            }

            if !buf.is_null() && entries_read > 0 {
                let entries =
                    core::slice::from_raw_parts(buf as *const UserInfo0, entries_read as usize);

                for entry in entries {
                    let name = wide_ptr_to_str(entry.usri0_name as *const u16);
                    println!("  {:<40}", name);
                }
                total_count += entries_read;
            }

            if !buf.is_null() {
                NetApiBufferFree(buf as *const c_void);
            }

            if status != ERROR_MORE_DATA {
                break;
            }
        }

        println!("\nTotal users: {}", total_count);
    }
}

unsafe fn enum_users_level1(server_ptr: *const u16, userfilter: i32) {
    unsafe {
        println!("  {:<40} {:<10}", "Username", "Flags");
        println!("  {:<40} {:<10}", "--------", "-----");

        let mut resume_handle: u32 = 0;
        let mut match_count: u32 = 0;

        loop {
            let mut buf: *mut u8 = core::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;

            let status = NetUserEnum(
                server_ptr,
                1,
                FILTER_NORMAL_ACCOUNT,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            );

            if status != NERR_SUCCESS && status != ERROR_MORE_DATA {
                eprintln!("NetUserEnum failed with error: {}", status);
                break;
            }

            if !buf.is_null() && entries_read > 0 {
                let entries =
                    core::slice::from_raw_parts(buf as *const UserInfo1, entries_read as usize);

                for entry in entries {
                    let flags = entry.usri1_flags;
                    let show = match userfilter {
                        2 => flags & UF_LOCKOUT != 0,
                        3 => flags & UF_ACCOUNTDISABLE != 0,
                        4 => flags & UF_LOCKOUT == 0 && flags & UF_ACCOUNTDISABLE == 0,
                        _ => false,
                    };

                    if show {
                        let name = wide_ptr_to_str(entry.usri1_name as *const u16);
                        println!("  {:<40} 0x{:08X}", name, flags);
                        match_count += 1;
                    }
                }
            }

            if !buf.is_null() {
                NetApiBufferFree(buf as *const c_void);
            }

            if status != ERROR_MORE_DATA {
                break;
            }
        }

        println!("\nMatching users: {}", match_count);
    }
}

fn wide_ptr_to_str(ptr: *const u16) -> alloc::string::String {
    if ptr.is_null() {
        return alloc::string::String::new();
    }
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        from_wide(core::slice::from_raw_parts(ptr, len))
    }
}
