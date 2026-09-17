//! # Get Session Info BOF
//!
//! Retrieves logon session information for the current process token
//! using `LsaGetLogonSessionData`. Displays user name, authentication
//! package, logon type, session ID, logon server, DNS domain, UPN,
//! profile path, home directory, logon time, and password last set.
//!
//! ## MITRE ATT&CK
//! - T1033 - System Owner/User Discovery
//!
//! ## Arguments
//! None.

#![no_std]
use alloc::string::String;
use core::ptr::null_mut;

use rustbof::str::from_wide;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenStatistics};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Luid {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
struct SecurityLogonSessionData {
    size: u32,
    logon_id: Luid,
    user_name: UnicodeString,
    logon_domain: UnicodeString,
    authentication_package: UnicodeString,
    logon_type: u32,
    session: u32,
    sid: *mut core::ffi::c_void,
    logon_time: i64,
    logon_server: UnicodeString,
    dns_domain_name: UnicodeString,
    upn: UnicodeString,
}

#[repr(C)]
struct TokenStatisticsData {
    token_id: Luid,
    authentication_id: Luid,
    _padding: [u8; 200],
}

#[repr(C)]
struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}
unsafe extern "system" {
    fn LsaGetLogonSessionData(
        logon_id: *mut Luid,
        ppLogonSessionData: *mut *mut SecurityLogonSessionData,
    ) -> NTSTATUS;

    fn LsaFreeReturnBuffer(buffer: *mut core::ffi::c_void) -> NTSTATUS;

    fn FileTimeToSystemTime(lpFileTime: *const i64, lpSystemTime: *mut SystemTime) -> i32;
}
unsafe fn unicode_string_to_string(us: &UnicodeString) -> String {
    unsafe {
        if us.buffer.is_null() || us.length == 0 {
            return String::new();
        }
        let len = (us.length as usize) / 2;
        let slice = core::slice::from_raw_parts(us.buffer, len);
        from_wide(slice)
    }
}

fn filetime_to_string(ft: i64) -> String {
    if ft == 0 {
        return String::from("N/A");
    }

    let mut st = SystemTime {
        year: 0,
        month: 0,
        day_of_week: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
        milliseconds: 0,
    };

    let result = unsafe { FileTimeToSystemTime(&ft, &mut st) };
    if result == 0 {
        return String::from("N/A");
    }

    alloc::format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.year,
        st.month,
        st.day,
        st.hour,
        st.minute,
        st.second
    )
}

fn logon_type_str(logon_type: u32) -> &'static str {
    match logon_type {
        0 => "Undefined (0)",
        2 => "Interactive (2)",
        3 => "Network (3)",
        4 => "Batch (4)",
        5 => "Service (5)",
        7 => "Unlock (7)",
        8 => "NetworkCleartext (8)",
        9 => "NewCredentials (9)",
        10 => "RemoteInteractive (10)",
        11 => "CachedInteractive (11)",
        _ => "Unknown",
    }
}
#[rustbof::main]
fn main() {
    unsafe {
        let mut token: HANDLE = core::ptr::null_mut();
        let result = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token);
        if result == 0 {
            eprintln!("OpenProcessToken failed");
            return;
        }

        let mut stats: TokenStatisticsData = core::mem::zeroed();
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token,
            TokenStatistics,
            &mut stats as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<TokenStatisticsData>() as u32,
            &mut return_length,
        );

        if result == 0 {
            eprintln!("GetTokenInformation failed");
            CloseHandle(token);
            return;
        }

        CloseHandle(token);

        let mut auth_id = stats.authentication_id;
        let mut session_data: *mut SecurityLogonSessionData = null_mut();

        let status = LsaGetLogonSessionData(&mut auth_id, &mut session_data);
        if status != 0 {
            eprintln!(
                "LsaGetLogonSessionData failed with NTSTATUS: 0x{:08X}",
                status as u32
            );
            return;
        }

        if session_data.is_null() {
            eprintln!("LsaGetLogonSessionData returned null");
            return;
        }

        let data = &*session_data;

        println!("LOGON SESSION INFORMATION");
        println!("=========================\n");

        let user_name = unicode_string_to_string(&data.user_name);
        let logon_domain = unicode_string_to_string(&data.logon_domain);
        let auth_package = unicode_string_to_string(&data.authentication_package);
        let logon_server = unicode_string_to_string(&data.logon_server);
        let dns_domain = unicode_string_to_string(&data.dns_domain_name);
        let upn = unicode_string_to_string(&data.upn);

        let display_user = if logon_domain.is_empty() {
            user_name.clone()
        } else {
            alloc::format!("{}\\{}", logon_domain, user_name)
        };

        println!("  UserName              : {}", display_user);
        println!("  AuthenticationPackage : {}", auth_package);
        println!(
            "  LogonType             : {}",
            logon_type_str(data.logon_type)
        );
        println!("  Session               : {}", data.session);
        println!("  LogonServer           : {}", logon_server);
        println!("  DnsDomainName         : {}", dns_domain);
        println!("  UPN                   : {}", upn);
        println!(
            "  LogonTime             : {}",
            filetime_to_string(data.logon_time)
        );

        LsaFreeReturnBuffer(session_data as *mut core::ffi::c_void);
    }
}
