//! # Spawn As BOF
//!
//! Spawns a process as another user using `CreateProcessWithLogonW`.
//! ## MITRE ATT&CK
//! - T1134.002 - Access Token Manipulation: Create Process with Token
//!
//! ## Arguments
//! - `str`: Username.
//! - `str`: Password.
//! - `str`: Domain.
//! - `str`: Command line to execute.

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::str::to_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};

const LOGON_WITH_PROFILE: u32 = 0x00000001;

const CREATE_NO_WINDOW: u32 = 0x08000000;

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    std_input: *mut core::ffi::c_void,
    std_output: *mut core::ffi::c_void,
    std_error: *mut core::ffi::c_void,
}

#[repr(C)]
struct ProcessInformation {
    h_process: *mut core::ffi::c_void,
    h_thread: *mut core::ffi::c_void,
    dw_process_id: u32,
    dw_thread_id: u32,
}

unsafe extern "system" {
    fn CreateProcessWithLogonW(
        lp_username: *const u16,
        lp_domain: *const u16,
        lp_password: *const u16,
        dw_logon_flags: u32,
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        dw_creation_flags: u32,
        lp_environment: *mut core::ffi::c_void,
        lp_current_directory: *const u16,
        lp_startup_info: *const StartupInfoW,
        lp_process_information: *mut ProcessInformation,
    ) -> i32;
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let username = String::from(parser.get_str());
    let password = String::from(parser.get_str());
    let domain = String::from(parser.get_str());
    let command = String::from(parser.get_str());

    println!("shspawnas:");
    println!("  username: {}", username);
    println!("  domain:   {}", domain);
    println!("  command:  {}", command);

    let user_wide = to_wide(&username);
    let pass_wide = to_wide(&password);
    let domain_wide = to_wide(&domain);
    let mut cmd_wide = to_wide(&command);

    let si: StartupInfoW = unsafe {
        let mut si: StartupInfoW = core::mem::zeroed();
        si.cb = core::mem::size_of::<StartupInfoW>() as u32;
        si
    };
    let mut pi: ProcessInformation = unsafe { core::mem::zeroed() };

    let result = unsafe {
        CreateProcessWithLogonW(
            user_wide.as_ptr(),
            domain_wide.as_ptr(),
            pass_wide.as_ptr(),
            LOGON_WITH_PROFILE,
            core::ptr::null(),
            cmd_wide.as_mut_ptr(),
            CREATE_NO_WINDOW,
            core::ptr::null_mut(),
            core::ptr::null(),
            &si,
            &mut pi,
        )
    };

    if result == 0 {
        let err = unsafe { GetLastError() };
        eprintln!("CreateProcessWithLogonW failed ({:#X})", err);
        return;
    }

    println!("Process spawned successfully (PID: {})", pi.dw_process_id);

    unsafe {
        CloseHandle(pi.h_process);
        CloseHandle(pi.h_thread);
    }

    println!("SUCCESS.");
}
