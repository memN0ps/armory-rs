//! # Net Group BOF
//!
//! Lists domain groups and their members using NetQueryDisplayInformation
//! and NetGroupGetUsers Windows API functions.
//!
//! ## MITRE ATT&CK
//! - T1069.002 - Permission Groups Discovery: Domain Groups
//!
//! ## Arguments
//! - `short`: type - 0 to list groups, 1 to list members of a specific group
//! - `wstr`: server - target server (empty for local)
//! - `wstr`: groupname - group name (required when type=1)

#![no_std]

use core::ffi::c_void;
use rustbof::data::DataParser;
use rustbof::str::from_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;

#[repr(C)]
struct NetDisplayGroup {
    grpi3_name: *mut u16,
    grpi3_comment: *mut u16,
    grpi3_group_id: u32,
    grpi3_attributes: u32,
    grpi3_next_index: u32,
}

#[repr(C)]
struct GroupUsersInfo0 {
    grui0_name: *mut u16,
}

unsafe extern "system" {
    fn NetQueryDisplayInformation(
        servername: *const u16,
        level: u32,
        index: u32,
        entriesrequested: u32,
        prefmaxlen: u32,
        returnedentrycount: *mut u32,
        sortedbuffer: *mut *mut c_void,
    ) -> u32;

    fn NetGroupGetUsers(
        servername: *const u16,
        groupname: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resumehandle: *mut usize,
    ) -> u32;
}

const NERR_SUCCESS: u32 = 0;
const ERROR_MORE_DATA: u32 = 234;
const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);

    let group_type = parser.get_short();
    let server_str = alloc::string::String::from(parser.get_str());
    let server_wide: alloc::vec::Vec<u16>;
    let server_ptr: *const u16 = if server_str.is_empty() {
        core::ptr::null()
    } else {
        server_wide = rustbof::str::to_wide(&server_str);
        server_wide.as_ptr()
    };

    match group_type {
        0 => list_groups(server_ptr),
        1 => {
            let group_name = alloc::string::String::from(parser.get_str());
            if group_name.is_empty() {
                eprintln!("Error: group name is required for member listing");
                return;
            }
            let group_wide = rustbof::str::to_wide(&group_name);
            list_members(server_ptr, group_wide.as_ptr());
        }
        _ => {
            eprintln!(
                "Error: invalid type {}. Use 0 for groups, 1 for members.",
                group_type
            );
        }
    }
}

fn list_groups(server: *const u16) {
    unsafe {
        println!("{:<40} {:<40} {:<10} {}", "Group Name", "Comment", "Group ID", "Attributes");
        println!("{:-<40} {:-<40} {:-<10} {:-<10}", "", "", "", "");

        let mut index: u32 = 0;
        let mut total_count: u32 = 0;

        loop {
            let mut count: u32 = 0;
            let mut buf: *mut c_void = core::ptr::null_mut();

            let status = NetQueryDisplayInformation(
                server,
                3,
                index,
                100,
                MAX_PREFERRED_LENGTH,
                &mut count,
                &mut buf,
            );

            if status != NERR_SUCCESS && status != ERROR_MORE_DATA {
                eprintln!("NetQueryDisplayInformation failed with error: {}", status);
                break;
            }

            if !buf.is_null() && count > 0 {
                let entries =
                    core::slice::from_raw_parts(buf as *const NetDisplayGroup, count as usize);

                for entry in entries {
                    let name = wide_ptr_to_str(entry.grpi3_name);
                    let comment = wide_ptr_to_str(entry.grpi3_comment);
                    println!(
                        "{:<40} {:<40} {:<10} 0x{:08X}",
                        name, comment, entry.grpi3_group_id, entry.grpi3_attributes
                    );
                    index = entry.grpi3_next_index;
                }
                total_count += count;
            }

            NetApiBufferFree(buf as *const c_void);

            if status != ERROR_MORE_DATA {
                break;
            }
        }

        println!("\nTotal groups: {}", total_count);
    }
}

fn list_members(server: *const u16, group: *const u16) {
    unsafe {
        let group_name = wide_ptr_to_str(group);
        println!("Members of '{}':\n", group_name);
        println!("  {:<50}", "Member Name");
        println!("  {:-<50}", "");

        let mut resume_handle: usize = 0;
        let mut total_count: u32 = 0;

        loop {
            let mut buf: *mut u8 = core::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;

            let status = NetGroupGetUsers(
                server,
                group,
                0,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            );

            if status != NERR_SUCCESS && status != ERROR_MORE_DATA {
                eprintln!("NetGroupGetUsers failed with error: {}", status);
                break;
            }

            if !buf.is_null() && entries_read > 0 {
                let entries = core::slice::from_raw_parts(
                    buf as *const GroupUsersInfo0,
                    entries_read as usize,
                );

                for entry in entries {
                    let name = wide_ptr_to_str(entry.grui0_name);
                    println!("  {:<50}", name);
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

        println!("\nTotal members: {}", total_count);
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
