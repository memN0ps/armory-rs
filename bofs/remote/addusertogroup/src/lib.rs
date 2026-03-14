//! # Add User to Group BOF
//!
//! Adds a user to a local group using NetLocalGroupAddMembers.
//!
//! ## MITRE ATT&CK
//! - T1098 - Account Manipulation
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).
//! - `str`: Username to add.
//! - `str`: Group name to add user to.
//!

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};

#[repr(C)]
struct LocalGroupMembersInfo3 {
    lgrmi3_domainandname: *const u16,
}

unsafe extern "system" {
    fn NetLocalGroupAddMembers(
        servername: *const u16,
        groupname: *const u16,
        level: u32,
        buf: *const u8,
        totalentries: u32,
    ) -> u32;
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());
    let username = String::from(parser.get_str());
    let groupname = String::from(parser.get_str());

    let server_wide = if hostname.is_empty() {
        None
    } else {
        Some(to_wide(&hostname))
    };
    let user_wide = to_wide(&username);
    let group_wide = to_wide(&groupname);

    let server_ptr = server_wide
        .as_ref()
        .map_or(core::ptr::null(), |w| w.as_ptr());

    let member = LocalGroupMembersInfo3 {
        lgrmi3_domainandname: user_wide.as_ptr(),
    };

    println!("Adding user '{}' to group '{}' on '{}'...",
        username,
        groupname,
        if hostname.is_empty() { "localhost" } else { &hostname }
    );

    let status = unsafe {
        NetLocalGroupAddMembers(
            server_ptr,
            group_wide.as_ptr(),
            3, // Level 3 = by domain\username
            &member as *const _ as *const u8,
            1,
        )
    };

    if status == 0 {
        println!("SUCCESS: User '{}' added to group '{}'.", username, groupname);
    } else {
        eprintln!("NetLocalGroupAddMembers failed: {}", status);
    }
}
