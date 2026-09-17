//! # Net User BOF
//!
//! Gets detailed information for a specific user using NetUserGetInfo (level 2).
//!
//! ## MITRE ATT&CK
//! - T1087.002 - Account Discovery: Domain Account
//!
//! ## Arguments
//! - `str`: Username (required).
//! - `str`: Hostname (empty to query the domain controller).

#![no_std]

use rustbof::data::DataParser;
use rustbof::str::{from_wide, to_wide};
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;

#[repr(C)]
struct UserInfo2 {
    usri2_name: *mut u16,
    usri2_password: *mut u16,
    usri2_password_age: u32,
    usri2_priv: u32,
    usri2_home_dir: *mut u16,
    usri2_comment: *mut u16,
    usri2_flags: u32,
    usri2_script_path: *mut u16,
    usri2_auth_flags: u32,
    usri2_full_name: *mut u16,
    usri2_usr_comment: *mut u16,
    usri2_parms: *mut u16,
    usri2_workstations: *mut u16,
    usri2_last_logon: u32,
    usri2_last_logoff: u32,
    usri2_acct_expires: u32,
    usri2_max_storage: u32,
    usri2_units_per_week: u32,
    usri2_logon_hours: *mut u8,
    usri2_bad_pw_count: u32,
    usri2_num_logons: u32,
    usri2_logon_server: *mut u16,
    usri2_country_code: u32,
    usri2_code_page: u32,
}

unsafe extern "system" {
    fn NetUserGetInfo(
        servername: *const u16,
        username: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
    ) -> u32;
}

const NERR_SUCCESS: u32 = 0;

fn priv_str(priv_level: u32) -> &'static str {
    match priv_level {
        0 => "Guest",
        1 => "User",
        2 => "Admin",
        _ => "Unknown",
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let username_str = alloc::string::String::from(parser.get_str());
    let hostname_str = alloc::string::String::from(parser.get_str());

    if username_str.is_empty() {
        eprintln!("Error: username is required");
        return;
    }

    unsafe {
        let server_ptr = if hostname_str.is_empty() {
            core::ptr::null()
        } else {
            let wide = to_wide(&hostname_str);
            let ptr = wide.as_ptr();
            core::mem::forget(wide);
            ptr
        };

        let username_wide = to_wide(&username_str);

        let mut buf: *mut u8 = core::ptr::null_mut();

        let status = NetUserGetInfo(server_ptr, username_wide.as_ptr(), 2, &mut buf);

        if status != NERR_SUCCESS {
            eprintln!("NetUserGetInfo failed with error: {}", status);
            if !buf.is_null() {
                NetApiBufferFree(buf as *mut _);
            }
            return;
        }

        if buf.is_null() {
            eprintln!("NetUserGetInfo returned null buffer");
            return;
        }

        let info = &*(buf as *const UserInfo2);

        let name = wide_ptr_to_str(info.usri2_name);
        let full_name = wide_ptr_to_str(info.usri2_full_name);
        let comment = wide_ptr_to_str(info.usri2_comment);
        let home_dir = wide_ptr_to_str(info.usri2_home_dir);
        let script_path = wide_ptr_to_str(info.usri2_script_path);
        let logon_server = wide_ptr_to_str(info.usri2_logon_server);

        let display_host = if hostname_str.is_empty() {
            "domain controller"
        } else {
            &hostname_str
        };

        println!("User info for '{}' on {}:\n", username_str, display_host);
        println!("  {:<20} {}", "Name:", name);
        println!("  {:<20} {}", "Full Name:", full_name);
        println!("  {:<20} {}", "Comment:", comment);
        println!("  {:<20} {}", "Privilege:", priv_str(info.usri2_priv));
        println!("  {:<20} 0x{:08X}", "Flags:", info.usri2_flags);
        println!("  {:<20} {}", "Home Dir:", home_dir);
        println!("  {:<20} {}", "Script Path:", script_path);
        println!("  {:<20} {}", "Last Logon:", info.usri2_last_logon);
        println!("  {:<20} {}", "Bad PW Count:", info.usri2_bad_pw_count);
        println!("  {:<20} {}", "Num Logons:", info.usri2_num_logons);
        println!("  {:<20} {}", "Logon Server:", logon_server);

        NetApiBufferFree(buf as *mut _);
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
