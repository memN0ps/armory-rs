//! # Process Token Inventory BOF
//!
//! Enumerates accessible process primary tokens and reports the owning account,
//! integrity level, and elevation state. It requests query-only handles.
//!
//! ## MITRE ATT&CK
//! - T1057 - Process Discovery
//! - T1033 - System Owner/User Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{format, string::String, vec};
use rustbof::println;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountSidW,
    TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenElevation,
    TokenIntegrityLevel, TokenUser,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

fn wide_to_string(buffer: &[u16]) -> String {
    let length = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

fn token_information(token: *mut core::ffi::c_void, class: i32) -> Option<alloc::vec::Vec<u8>> {
    unsafe {
        let mut needed = 0u32;
        GetTokenInformation(token, class, core::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return None;
        }

        let mut buffer = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr() as *mut core::ffi::c_void,
            needed,
            &mut needed,
        ) == 0
        {
            return None;
        }

        Some(buffer)
    }
}

fn account_name(token: *mut core::ffi::c_void) -> String {
    let Some(buffer) = token_information(token, TokenUser) else {
        return String::from("<unknown>");
    };

    unsafe {
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut name = vec![0u16; 256];
        let mut domain = vec![0u16; 256];
        let mut name_size = name.len() as u32;
        let mut domain_size = domain.len() as u32;
        let mut sid_type = 0i32;

        if LookupAccountSidW(
            core::ptr::null(),
            user.User.Sid,
            name.as_mut_ptr(),
            &mut name_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut sid_type,
        ) == 0
        {
            return String::from("<unresolved>");
        }

        let name = wide_to_string(&name);
        let domain = wide_to_string(&domain);
        if domain.is_empty() {
            name
        } else {
            format!("{}\\{}", domain, name)
        }
    }
}

fn integrity_name(token: *mut core::ffi::c_void) -> &'static str {
    let Some(buffer) = token_information(token, TokenIntegrityLevel) else {
        return "unknown";
    };

    unsafe {
        let label = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let count = *GetSidSubAuthorityCount(label.Label.Sid) as u32;
        if count == 0 {
            return "unknown";
        }
        let rid = *GetSidSubAuthority(label.Label.Sid, count - 1);
        match rid {
            0x0000..=0x0FFF => "untrusted",
            0x1000..=0x1FFF => "low",
            0x2000..=0x20FF => "medium",
            0x2100..=0x2FFF => "medium plus",
            0x3000..=0x3FFF => "high",
            0x4000..=0x4FFF => "system",
            0x5000..=0x5FFF => "protected",
            _ => "unknown",
        }
    }
}

fn elevation_name(token: *mut core::ffi::c_void) -> &'static str {
    let Some(buffer) = token_information(token, TokenElevation) else {
        return "unknown";
    };

    unsafe {
        let elevation = &*(buffer.as_ptr() as *const TOKEN_ELEVATION);
        if elevation.TokenIsElevated != 0 {
            "yes"
        } else {
            "no"
        }
    }
}

fn enumerate_processes() {
    const MAX_ROWS: u32 = 256;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            println!("Process snapshot failed.");
            return;
        }

        let mut entry: PROCESSENTRY32W = core::mem::zeroed();
        entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot, &mut entry) == 0 {
            println!("No process information was returned.");
            CloseHandle(snapshot);
            return;
        }

        println!(
            "{:<7} {:<28} {:<28} {:<12} {}",
            "PID", "Image", "Account", "Integrity", "Elevated"
        );
        println!("{:-<7} {:-<28} {:-<28} {:-<12} {:-<8}", "", "", "", "", "");

        let mut visible = 0u32;
        let mut denied = 0u32;
        let mut truncated = false;
        loop {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
            if process.is_null() {
                denied += 1;
            } else {
                let mut token = core::ptr::null_mut();
                if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                    denied += 1;
                } else {
                    println!(
                        "{:<7} {:<28.28} {:<28.28} {:<12} {}",
                        entry.th32ProcessID,
                        wide_to_string(&entry.szExeFile),
                        account_name(token),
                        integrity_name(token),
                        elevation_name(token)
                    );
                    visible += 1;
                    CloseHandle(token);
                }
                CloseHandle(process);
            }

            if visible >= MAX_ROWS {
                truncated = true;
                break;
            }

            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }

        CloseHandle(snapshot);
        println!(
            "\nVisible tokens: {} | access denied: {}{}",
            visible,
            denied,
            if truncated {
                " | row limit reached"
            } else {
                ""
            }
        );
    }
}

#[rustbof::main]
fn main() {
    println!("Process token inventory\n");
    enumerate_processes();
}
