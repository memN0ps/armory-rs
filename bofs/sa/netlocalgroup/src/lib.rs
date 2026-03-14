//! Net Local Group Enumeration BOF
//!
//! Enumerates local groups on a system and optionally lists members of a
//! specific local group using the NetLocalGroupEnum and NetLocalGroupGetMembers
//! Windows API functions.
//!
//! ## MITRE ATT&CK
//!
//! T1069.001 - Permission Groups Discovery: Local Groups

#![no_std]

use alloc::vec::Vec;
use core::ffi::c_void;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetApiBufferFree, NetLocalGroupEnum, NetLocalGroupGetMembers,
};

#[repr(C)]
struct LocalGroupInfo1 {
    lgrpi1_name: *mut u16,
    lgrpi1_comment: *mut u16,
}

#[repr(C)]
struct LocalGroupMembersInfo1 {
    lgrmi1_sid: *mut c_void,
    lgrmi1_sidusage: u32,
    lgrmi1_name: *mut u16,
}

unsafe fn wide_ptr_to_string(ptr: *const u16) -> alloc::string::String {
    if ptr.is_null() {
        return alloc::string::String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(ptr, len);
    rustbof::str::from_wide(slice)
}

fn to_wide(s: &str) -> Vec<u16> {
    rustbof::str::to_wide(s)
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);

    let group_type = parser.get_short();
    let server_str = parser.get_str();
    let server_wide: Vec<u16>;
    let server_ptr: *const u16 = if server_str.is_empty() {
        core::ptr::null()
    } else {
        server_wide = to_wide(server_str);
        server_wide.as_ptr()
    };

    match group_type {
        0 => list_groups(server_ptr),
        1 => {
            let group_name = parser.get_str();
            if group_name.is_empty() {
                eprintln!("Error: group name is required for member listing");
                return;
            }
            let group_wide = to_wide(group_name);
            list_members(server_ptr, group_wide.as_ptr());
        }
        _ => {
            eprintln!("Error: invalid type {}. Use 0 for groups, 1 for members.", group_type);
        }
    }
}

fn list_groups(server: *const u16) {
    unsafe {
        let mut buf: *mut u8 = core::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        let mut resume_handle: usize = 0;

        println!("{:<40} {}", "Group Name", "Comment");
        println!("{:-<40} {:-<40}", "", "");

        loop {
            let status = NetLocalGroupEnum(
                server,
                1,
                &mut buf,
                u32::MAX,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            );

            if status != NERR_Success && status != ERROR_MORE_DATA {
                eprintln!("NetLocalGroupEnum failed with error: {}", status);
                return;
            }

            if !buf.is_null() {
                let info = buf as *const LocalGroupInfo1;
                for i in 0..entries_read as isize {
                    let entry = &*info.offset(i);
                    let name = wide_ptr_to_string(entry.lgrpi1_name);
                    let comment = wide_ptr_to_string(entry.lgrpi1_comment);
                    println!("{:<40} {}", name, comment);
                }
                NetApiBufferFree(buf as *const c_void);
                buf = core::ptr::null_mut();
            }

            if status != ERROR_MORE_DATA {
                break;
            }
        }

        println!("\nTotal groups: {}", total_entries);
    }
}

fn list_members(server: *const u16, group: *const u16) {
    unsafe {
        let mut buf: *mut u8 = core::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        let mut resume_handle: usize = 0;

        let group_name = wide_ptr_to_string(group);
        println!("Members of '{}':\n", group_name);
        println!("{:<50} {}", "Member Name", "SID Use");
        println!("{:-<50} {:-<10}", "", "");

        loop {
            let status = NetLocalGroupGetMembers(
                server,
                group,
                1,
                &mut buf,
                u32::MAX,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            );

            if status != NERR_Success && status != ERROR_MORE_DATA {
                eprintln!("NetLocalGroupGetMembers failed with error: {}", status);
                return;
            }

            if !buf.is_null() {
                let info = buf as *const LocalGroupMembersInfo1;
                for i in 0..entries_read as isize {
                    let entry = &*info.offset(i);
                    let name = wide_ptr_to_string(entry.lgrmi1_name);
                    let sid_use = sid_name_use_str(entry.lgrmi1_sidusage);
                    println!("{:<50} {}", name, sid_use);
                }
                NetApiBufferFree(buf as *const c_void);
                buf = core::ptr::null_mut();
            }

            if status != ERROR_MORE_DATA {
                break;
            }
        }

        println!("\nTotal members: {}", total_entries);
    }
}

fn sid_name_use_str(sid_use: u32) -> &'static str {
    match sid_use {
        1 => "User",
        2 => "Group",
        3 => "Domain",
        4 => "Alias",
        5 => "WellKnownGroup",
        6 => "DeletedAccount",
        7 => "Invalid",
        8 => "Unknown",
        _ => "Other",
    }
}
