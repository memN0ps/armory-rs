//! # Service Failure Actions BOF
//!
//! Sets service failure recovery actions on a local or remote host by
//! connecting to the Service Control Manager (SCM), opening the target
//! service, and calling `ChangeServiceConfig2A` with
//! `SERVICE_CONFIG_FAILURE_ACTIONS`.
//! ## MITRE ATT&CK
//! - T1543.003 - Create or Modify System Process: Windows Service
//!
//! ## Arguments
//! - `str`: Target hostname (empty string for local machine).
//! - `str`: Service name.
//! - `int`: Reset period in seconds.
//! - `int`: Action 1 type (0=NONE, 1=RESTART, 2=REBOOT, 3=RUN_COMMAND).
//! - `int`: Delay 1 in milliseconds.
//! - `int`: Action 2 type (0=NONE, 1=RESTART, 2=REBOOT, 3=RUN_COMMAND).
//! - `int`: Delay 2 in milliseconds.

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerA, OpenServiceA, SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const SERVICE_CONFIG_FAILURE_ACTIONS: u32 = 2;

unsafe extern "system" {
    fn ChangeServiceConfig2A(
        h_service: *mut core::ffi::c_void,
        dw_info_level: u32,
        lp_info: *const core::ffi::c_void,
    ) -> i32;
}

#[repr(C)]
struct ScAction {
    action_type: u32,
    delay: u32,
}

#[repr(C)]
struct ServiceFailureActionsA {
    dw_reset_period: u32,
    lp_reboot_msg: *const u8,
    lp_command: *const u8,
    c_actions: u32,
    lp_sa_actions: *const ScAction,
}

fn enable_shutdown_privilege() {
    unsafe {
        let mut token: *mut core::ffi::c_void = core::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == FALSE {
            return;
        }

        let priv_name = b"SeShutdownPrivilege\0";
        let mut luid: LUID = core::mem::zeroed();
        if LookupPrivilegeValueA(
            core::ptr::null(),
            priv_name.as_ptr(),
            &mut luid,
        ) == FALSE
        {
            CloseHandle(token);
            return;
        }

        let mut tp: TOKEN_PRIVILEGES = core::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(
            token,
            FALSE,
            &tp,
            core::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        CloseHandle(token);
    }
}

fn config_failure(
    hostname: *const u8,
    service_name: &core::ffi::CStr,
    reset_period: u32,
    actions: &[ScAction],
) -> u32 {
    unsafe {
        let sc_manager = OpenSCManagerA(hostname, core::ptr::null(), SC_MANAGER_CONNECT);
        if sc_manager.is_null() {
            let err = GetLastError();
            eprintln!("OpenSCManagerA failed ({:#X})", err);
            return err;
        }

        let sc_service = OpenServiceA(
            sc_manager,
            service_name.as_ptr() as *const u8,
            SERVICE_CHANGE_CONFIG,
        );
        if sc_service.is_null() {
            let err = GetLastError();
            eprintln!("OpenServiceA failed ({:#X})", err);
            CloseServiceHandle(sc_manager);
            return err;
        }

        enable_shutdown_privilege();

        let failure_actions = ServiceFailureActionsA {
            dw_reset_period: reset_period,
            lp_reboot_msg: core::ptr::null(),
            lp_command: core::ptr::null(),
            c_actions: actions.len() as u32,
            lp_sa_actions: actions.as_ptr(),
        };

        if ChangeServiceConfig2A(
            sc_service,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            &failure_actions as *const ServiceFailureActionsA as *const core::ffi::c_void,
        ) == 0
        {
            let err = GetLastError();
            eprintln!("ChangeServiceConfig2A failed ({:#X})", err);
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return err;
        }

        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
        0
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);

    let hostname = String::from(parser.get_str());
    let service_name = String::from(parser.get_str());
    let reset_period = parser.get_int() as u32;
    let action1_type = parser.get_int() as u32;
    let delay1 = parser.get_int() as u32;
    let action2_type = parser.get_int() as u32;
    let delay2 = parser.get_int() as u32;

    let hostname_cstr = rustbof::str::to_cstr(&hostname);
    let service_cstr = rustbof::str::to_cstr(&service_name);

    println!("config_failure:");
    println!("  hostname:     {}", hostname);
    println!("  servicename:  {}", service_name);
    println!("  resetperiod:  {} seconds", reset_period);
    println!("  action1:      type={} delay={}ms", action1_type, delay1);
    println!("  action2:      type={} delay={}ms", action2_type, delay2);

    let host_ptr = if hostname.is_empty() {
        core::ptr::null()
    } else {
        hostname_cstr.as_ptr() as *const u8
    };

    let actions = [
        ScAction {
            action_type: action1_type,
            delay: delay1,
        },
        ScAction {
            action_type: action2_type,
            delay: delay2,
        },
    ];

    let result = config_failure(host_ptr, &service_cstr, reset_period, &actions);
    if result != 0 {
        eprintln!("config_failure failed: {:#X}", result);
    } else {
        println!("SUCCESS.");
    }
}
