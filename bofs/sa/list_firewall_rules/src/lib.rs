//! # List Firewall Rules BOF
//!
//! Enumerates Windows Firewall rules by reading directly from the registry
//! at `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`.
//! Each value contains a pipe-delimited firewall rule string. Parses and displays
//! Action, Direction, Protocol, Local Port, Remote Port, Application, and Name.
//!
//! ## MITRE ATT&CK
//! - T1518 - Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::vec;
use core::ffi::CStr;
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::*;

const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;

fn parse_and_print_rule(rule: &str) {
    let mut action = "";
    let mut dir = "";
    let mut protocol = "";
    let mut lport = "";
    let mut rport = "";
    let mut app = "";
    let mut name = "";

    for segment in rule.split('|') {
        if let Some(val) = segment.strip_prefix("Action=") {
            action = val;
        } else if let Some(val) = segment.strip_prefix("Dir=") {
            dir = val;
        } else if let Some(val) = segment.strip_prefix("Protocol=") {
            protocol = val;
        } else if let Some(val) = segment.strip_prefix("LPort=") {
            lport = val;
        } else if let Some(val) = segment.strip_prefix("RPort=") {
            rport = val;
        } else if let Some(val) = segment.strip_prefix("App=") {
            app = val;
        } else if let Some(val) = segment.strip_prefix("Name=") {
            name = val;
        }
    }

    println!(
        "  {:<30} Action={:<6} Dir={:<4} Proto={:<4} LPort={:<10} RPort={:<10} App={}",
        name, action, dir, protocol, lport, rport, app
    );
}

#[rustbof::main]
fn main() {
    let subkey = b"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\0";

    unsafe {
        let mut hkey: isize = 0;
        let ret = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE as HKEY,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey as *mut isize as *mut HKEY,
        );
        if ret != 0 {
            eprintln!("RegOpenKeyExA failed: 0x{:X}", ret);
            return;
        }

        println!("Windows Firewall Rules (from registry):");
        println!("{}", "-".repeat(120));

        let mut index: u32 = 0;
        let mut count: u32 = 0;

        loop {
            let mut name_buf = vec![0u8; 512];
            let mut name_len: u32 = name_buf.len() as u32;
            let mut value_type: u32 = 0;
            let mut data_buf = vec![0u8; 4096];
            let mut data_len: u32 = data_buf.len() as u32;

            let ret = RegEnumValueA(
                hkey as HKEY,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                core::ptr::null(),
                &mut value_type,
                data_buf.as_mut_ptr(),
                &mut data_len,
            );

            if ret == 259 {
                break;
            }
            if ret != 0 {
                eprintln!("RegEnumValueA failed at index {}: 0x{:X}", index, ret);
                break;
            }

            if value_type == 1 && data_len > 0 {
                let rule_str = CStr::from_ptr(data_buf.as_ptr() as *const i8)
                    .to_str()
                    .unwrap_or("");
                if !rule_str.is_empty() {
                    parse_and_print_rule(rule_str);
                    count += 1;
                }
            }

            index += 1;
        }

        println!("{}", "-".repeat(120));
        println!("Total firewall rules: {}", count);

        RegCloseKey(hkey as HKEY);
    }
}
