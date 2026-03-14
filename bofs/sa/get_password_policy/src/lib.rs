//! # Get Password Policy BOF
//!
//! Retrieves the domain password policy and account lockout settings using
//! NetUserModalsGet. Queries level 0 for password requirements and level 3
//! for lockout configuration.
//!
//! ## MITRE ATT&CK
//! - T1201 - Password Policy Discovery
//!
//! ## Arguments
//! - `wstr`: server - target server (empty for local)

#![no_std]

use core::ffi::c_void;
use rustbof::data::DataParser;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;

#[repr(C)]
struct UserModalsInfo0 {
    usrmod0_min_passwd_len: u32,
    usrmod0_max_passwd_age: u32,
    usrmod0_min_passwd_age: u32,
    usrmod0_force_logoff: u32,
    usrmod0_password_hist_len: u32,
}

#[repr(C)]
struct UserModalsInfo3 {
    usrmod3_lockout_duration: u32,
    usrmod3_lockout_observation_window: u32,
    usrmod3_lockout_threshold: u32,
}

unsafe extern "system" {
    fn NetUserModalsGet(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
    ) -> u32;
}

const NERR_SUCCESS: u32 = 0;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let server_str = alloc::string::String::from(parser.get_str());

    let server_wide: alloc::vec::Vec<u16>;
    let server_ptr: *const u16 = if server_str.is_empty() {
        core::ptr::null()
    } else {
        server_wide = to_wide(&server_str);
        server_wide.as_ptr()
    };

    let display_host = if server_str.is_empty() {
        "localhost"
    } else {
        &server_str
    };

    println!("Password policy for {}:\n", display_host);

    unsafe {
        let mut buf: *mut u8 = core::ptr::null_mut();
        let status = NetUserModalsGet(server_ptr, 0, &mut buf);

        if status != NERR_SUCCESS {
            eprintln!("NetUserModalsGet (level 0) failed with error: {}", status);
        } else if !buf.is_null() {
            let info = &*(buf as *const UserModalsInfo0);

            println!("  Minimum password length:  {}", info.usrmod0_min_passwd_len);

            let max_age_days = if info.usrmod0_max_passwd_age == 0xFFFFFFFF {
                println!("  Maximum password age:     Never expires");
                0
            } else {
                let days = info.usrmod0_max_passwd_age / 86400;
                println!("  Maximum password age:     {} days", days);
                days
            };

            let min_age_days = info.usrmod0_min_passwd_age / 86400;
            println!("  Minimum password age:     {} days", min_age_days);

            if info.usrmod0_force_logoff == 0xFFFFFFFF {
                println!("  Force logoff:             Never");
            } else {
                let logoff_minutes = info.usrmod0_force_logoff / 60;
                println!("  Force logoff:             {} minutes", logoff_minutes);
            }

            println!("  Password history length:  {}", info.usrmod0_password_hist_len);

            NetApiBufferFree(buf as *const c_void);
        }

        let mut buf3: *mut u8 = core::ptr::null_mut();
        let status3 = NetUserModalsGet(server_ptr, 3, &mut buf3);

        if status3 != NERR_SUCCESS {
            eprintln!("\nNetUserModalsGet (level 3) failed with error: {}", status3);
        } else if !buf3.is_null() {
            let info3 = &*(buf3 as *const UserModalsInfo3);

            println!("\n  Lockout threshold:        {}", info3.usrmod3_lockout_threshold);

            let duration_minutes = info3.usrmod3_lockout_duration / 60;
            let window_minutes = info3.usrmod3_lockout_observation_window / 60;

            println!("  Lockout duration:         {} minutes", duration_minutes);
            println!("  Lockout observation:      {} minutes", window_minutes);

            NetApiBufferFree(buf3 as *const c_void);
        }
    }
}
