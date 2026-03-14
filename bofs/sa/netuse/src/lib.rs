//! # Net Use BOF
//!
//! Maps or disconnects network drive connections using WNetAddConnection2A
//! and WNetCancelConnection2A.
//!
//! ## MITRE ATT&CK
//! - T1021.002 - Remote Services: SMB/Windows Admin Shares
//!
//! ## Arguments
//! - `str`: Share path (e.g., `\\server\share`).
//! - `str`: Username (empty for current user).
//! - `str`: Password (empty if using current creds).
//! - `short`: Action (0 = connect, 1 = disconnect).
//!

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::WNet::*;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let share = String::from(parser.get_str());
    let username = String::from(parser.get_str());
    let password = String::from(parser.get_str());
    let action = parser.get_short();

    if action == 1 {
        let share_cstr = rustbof::str::to_cstr(&share);
        let result = unsafe {
            WNetCancelConnection2A(share_cstr.as_ptr() as *const u8, 0, 1) // force=TRUE
        };
        if result == 0 {
            println!("SUCCESS: Disconnected from {}", share);
        } else {
            eprintln!("WNetCancelConnection2A failed: {}", result);
        }
    } else {
        let share_cstr = rustbof::str::to_cstr(&share);
        let user_cstr = if username.is_empty() {
            None
        } else {
            Some(rustbof::str::to_cstr(&username))
        };
        let pass_cstr = if password.is_empty() {
            None
        } else {
            Some(rustbof::str::to_cstr(&password))
        };

        let mut nr: NETRESOURCEA = unsafe { core::mem::zeroed() };
        nr.dwType = RESOURCETYPE_DISK;
        nr.lpRemoteName = share_cstr.as_ptr() as *mut u8;

        let user_ptr = user_cstr
            .as_ref()
            .map_or(core::ptr::null(), |c| c.as_ptr() as *const u8);
        let pass_ptr = pass_cstr
            .as_ref()
            .map_or(core::ptr::null(), |c| c.as_ptr() as *const u8);

        let result = unsafe { WNetAddConnection2A(&nr, pass_ptr, user_ptr, 0) };
        if result == 0 {
            println!("SUCCESS: Connected to {}", share);
        } else {
            eprintln!("WNetAddConnection2A failed: {}", result);
        }
    }
}
