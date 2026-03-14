//! # Net Shares BOF
//!
//! Enumerates network shares on a local or remote computer using NetShareEnum.
//! Supports both admin-level (SHARE_INFO_2) and user-level (SHARE_INFO_1) enumeration.
//!
//! ## MITRE ATT&CK
//! - T1135 - Network Share Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost). Uses wide string internally.
//! - `int`: Flag - 1 for admin level (SHARE_INFO_2), 0 for user level (SHARE_INFO_1).

#![no_std]

use rustbof::data::DataParser;
use rustbof::str::{from_wide, to_wide};
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;

#[repr(C)]
struct ShareInfo2 {
    shi2_netname: *mut u16,
    shi2_type: u32,
    shi2_remark: *mut u16,
    shi2_permissions: u32,
    shi2_max_uses: u32,
    shi2_current_uses: u32,
    shi2_path: *mut u16,
    shi2_passwd: *mut u16,
}

#[repr(C)]
struct ShareInfo1 {
    shi1_netname: *mut u16,
    shi1_type: u32,
    shi1_remark: *mut u16,
}

unsafe extern "system" {
    fn NetShareEnum(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32;
}

const NERR_SUCCESS: u32 = 0;
const ERROR_MORE_DATA: u32 = 234;
const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;

fn share_type_str(stype: u32) -> &'static str {
    match stype & 0x0FFFFFFF {
        0 => "Disk",
        1 => "Print",
        2 => "Device",
        3 => "IPC",
        _ => "Unknown",
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname_str = alloc::string::String::from(parser.get_str());
    let admin_flag = parser.get_int();

    unsafe {
        let server_ptr = if hostname_str.is_empty() {
            core::ptr::null()
        } else {
            let wide = to_wide(&hostname_str);
            let ptr = wide.as_ptr();
            core::mem::forget(wide);
            ptr
        };

        let display_host = if hostname_str.is_empty() {
            "localhost"
        } else {
            &hostname_str
        };

        if admin_flag != 0 {
            enum_shares_admin(server_ptr, display_host);
        } else {
            enum_shares_user(server_ptr, display_host);
        }
    }
}

unsafe fn enum_shares_admin(server_ptr: *const u16, display_host: &str) {
    println!("Share enumeration (admin) at {}:\n", display_host);
    println!(
        "  {:<20} {:<10} {:<32} {:<40} {}",
        "Name", "Type", "Remark", "Path", "Permissions"
    );
    println!(
        "  {:<20} {:<10} {:<32} {:<40} {}",
        "----", "----", "------", "----", "-----------"
    );

    let mut resume_handle: u32 = 0;

    loop {
        let mut buf: *mut u8 = core::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let status = NetShareEnum(
            server_ptr,
            2,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume_handle,
        );

        if status != NERR_SUCCESS && status != ERROR_MORE_DATA {
            eprintln!("NetShareEnum (level 2) failed with error: {}", status);
            break;
        }

        if !buf.is_null() && entries_read > 0 {
            let entries =
                core::slice::from_raw_parts(buf as *const ShareInfo2, entries_read as usize);

            for entry in entries {
                let name = wide_ptr_to_str(entry.shi2_netname);
                let stype = share_type_str(entry.shi2_type);
                let remark = wide_ptr_to_str(entry.shi2_remark);
                let path = wide_ptr_to_str(entry.shi2_path);
                let perms = entry.shi2_permissions;

                println!(
                    "  {:<20} {:<10} {:<32} {:<40} {}",
                    name, stype, remark, path, perms
                );
            }
        }

        if !buf.is_null() {
            NetApiBufferFree(buf as *mut _);
        }

        if status != ERROR_MORE_DATA {
            break;
        }
    }
}

unsafe fn enum_shares_user(server_ptr: *const u16, display_host: &str) {
    println!("Share enumeration (user) at {}:\n", display_host);
    println!(
        "  {:<20} {:<10} {}",
        "Name", "Type", "Remark"
    );
    println!(
        "  {:<20} {:<10} {}",
        "----", "----", "------"
    );

    let mut resume_handle: u32 = 0;

    loop {
        let mut buf: *mut u8 = core::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let status = NetShareEnum(
            server_ptr,
            1,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume_handle,
        );

        if status != NERR_SUCCESS && status != ERROR_MORE_DATA {
            eprintln!("NetShareEnum (level 1) failed with error: {}", status);
            break;
        }

        if !buf.is_null() && entries_read > 0 {
            let entries =
                core::slice::from_raw_parts(buf as *const ShareInfo1, entries_read as usize);

            for entry in entries {
                let name = wide_ptr_to_str(entry.shi1_netname);
                let stype = share_type_str(entry.shi1_type);
                let remark = wide_ptr_to_str(entry.shi1_remark);

                println!("  {:<20} {:<10} {}", name, stype, remark);
            }
        }

        if !buf.is_null() {
            NetApiBufferFree(buf as *mut _);
        }

        if status != ERROR_MORE_DATA {
            break;
        }
    }
}

fn wide_ptr_to_str(ptr: *mut u16) -> alloc::string::String {
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
