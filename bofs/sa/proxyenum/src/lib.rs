//! # Proxy Enumeration BOF
//!
//! Reports machine WinHTTP proxy settings, the current user's WinINet proxy
//! and automatic-configuration state, and common proxy environment variables.
//!
//! ## MITRE ATT&CK
//! - T1016 - System Network Configuration Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{string::String, vec};
use rustbof::{eprintln, println};

#[repr(C)]
struct WinHttpProxyInfo {
    access_type: u32,
    proxy: *mut u16,
    proxy_bypass: *mut u16,
}

#[repr(C)]
struct WinHttpCurrentUserIeProxyConfig {
    auto_detect: i32,
    auto_config_url: *mut u16,
    proxy: *mut u16,
    proxy_bypass: *mut u16,
}

unsafe extern "system" {
    fn WinHttpGetDefaultProxyConfiguration(proxy_info: *mut WinHttpProxyInfo) -> i32;
    fn WinHttpGetIEProxyConfigForCurrentUser(
        proxy_config: *mut WinHttpCurrentUserIeProxyConfig,
    ) -> i32;
    fn GlobalFree(memory: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    fn GetEnvironmentVariableA(name: *const u8, buffer: *mut u8, size: u32) -> u32;
    fn GetLastError() -> u32;
}

fn wide_to_string(value: *const u16) -> String {
    if value.is_null() {
        return String::from("<not set>");
    }

    unsafe {
        let mut length = 0usize;
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(core::slice::from_raw_parts(value, length))
    }
}

unsafe fn free_wide(value: *mut u16) {
    if !value.is_null() {
        unsafe {
            GlobalFree(value as *mut core::ffi::c_void);
        }
    }
}

fn environment_value(name: &[u8]) -> Option<String> {
    unsafe {
        let needed = GetEnvironmentVariableA(name.as_ptr(), core::ptr::null_mut(), 0);
        if needed == 0 {
            return None;
        }

        let mut value = vec![0u8; needed as usize];
        let written = GetEnvironmentVariableA(name.as_ptr(), value.as_mut_ptr(), needed);
        if written == 0 || written >= needed {
            return None;
        }

        value.truncate(written as usize);
        Some(String::from_utf8_lossy(&value).into_owned())
    }
}

#[rustbof::main]
fn main() {
    println!("Proxy configuration\n");

    unsafe {
        let mut machine: WinHttpProxyInfo = core::mem::zeroed();
        if WinHttpGetDefaultProxyConfiguration(&mut machine) == 0 {
            eprintln!("WinHTTP machine proxy query failed: 0x{:X}", GetLastError());
        } else {
            let mode = match machine.access_type {
                1 => "direct",
                3 => "named proxy",
                4 => "automatic proxy",
                _ => "unknown",
            };
            println!("WinHTTP machine mode:   {}", mode);
            println!("WinHTTP proxy:          {}", wide_to_string(machine.proxy));
            println!(
                "WinHTTP bypass:         {}",
                wide_to_string(machine.proxy_bypass)
            );
            free_wide(machine.proxy);
            free_wide(machine.proxy_bypass);
        }

        println!();
        let mut user: WinHttpCurrentUserIeProxyConfig = core::mem::zeroed();
        if WinHttpGetIEProxyConfigForCurrentUser(&mut user) == 0 {
            eprintln!(
                "WinINet current-user proxy query failed: 0x{:X}",
                GetLastError()
            );
        } else {
            println!(
                "WinINet auto-detect:    {}",
                if user.auto_detect != 0 {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "WinINet PAC URL:        {}",
                wide_to_string(user.auto_config_url)
            );
            println!("WinINet proxy:          {}", wide_to_string(user.proxy));
            println!(
                "WinINet bypass:         {}",
                wide_to_string(user.proxy_bypass)
            );
            free_wide(user.auto_config_url);
            free_wide(user.proxy);
            free_wide(user.proxy_bypass);
        }
    }

    println!("\nEnvironment:");
    for &(label, name) in &[
        ("HTTP_PROXY", b"HTTP_PROXY\0".as_slice()),
        ("HTTPS_PROXY", b"HTTPS_PROXY\0".as_slice()),
        ("ALL_PROXY", b"ALL_PROXY\0".as_slice()),
        ("NO_PROXY", b"NO_PROXY\0".as_slice()),
    ] {
        println!(
            "{:<12} {}",
            label,
            environment_value(name).unwrap_or_else(|| String::from("<not set>"))
        );
    }
}
