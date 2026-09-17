//! # Attack Surface Reduction Status BOF
//!
//! Enumerates locally configured and policy-backed Attack Surface Reduction
//! rules and exclusions without changing Microsoft Defender settings.
//!
//! ## MITRE ATT&CK
//! - T1518.001 - Software Discovery: Security Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::vec;
use core::ffi::CStr;
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::{
    HKEY, KEY_READ, KEY_WOW64_64KEY, RegCloseKey, RegEnumValueA, RegOpenKeyExA,
};

const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

struct RuleSource {
    label: &'static str,
    rules: &'static [u8],
    exclusions: &'static [u8],
}

static SOURCES: &[RuleSource] = &[
    RuleSource {
        label: "Local preference",
        rules: b"SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules\0",
        exclusions: b"SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\ASROnlyExclusions\0",
    },
    RuleSource {
        label: "Policy",
        rules: b"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules\0",
        exclusions: b"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\ASROnlyExclusions\0",
    },
];

fn state_name(value: &str) -> &'static str {
    match value {
        "0" => "disabled",
        "1" => "block",
        "2" => "audit",
        "6" => "warn",
        _ => "unknown",
    }
}

fn string_value(data: &[u8]) -> &str {
    if data.is_empty() {
        return "";
    }

    unsafe {
        CStr::from_ptr(data.as_ptr() as *const i8)
            .to_str()
            .unwrap_or("<invalid utf-8>")
    }
}

fn enumerate_values(path: &[u8], rules: bool) -> Result<u32, u32> {
    unsafe {
        let mut key: HKEY = core::ptr::null_mut();
        let status = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE as HKEY,
            path.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        );
        if status != 0 {
            return Err(status);
        }

        let mut count = 0u32;
        let mut index = 0u32;

        loop {
            let mut name = vec![0u8; 1024];
            let mut name_len = name.len() as u32;
            let mut data = vec![0u8; 8192];
            let mut data_len = data.len() as u32;
            let mut value_type = 0u32;

            let status = RegEnumValueA(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                core::ptr::null(),
                &mut value_type,
                data.as_mut_ptr(),
                &mut data_len,
            );

            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != 0 {
                RegCloseKey(key);
                return Err(status);
            }

            name[name_len as usize] = 0;
            data.truncate(data_len as usize);
            let name = CStr::from_ptr(name.as_ptr() as *const i8)
                .to_str()
                .unwrap_or("<invalid name>");

            if rules {
                let value = match value_type {
                    REG_SZ => string_value(&data),
                    REG_DWORD if data.len() >= 4 => {
                        match u32::from_le_bytes([data[0], data[1], data[2], data[3]]) {
                            0 => "0",
                            1 => "1",
                            2 => "2",
                            6 => "6",
                            _ => "?",
                        }
                    }
                    _ => "?",
                };
                println!("  {} = {} ({})", name, value, state_name(value));
            } else {
                println!("  {}", name);
            }

            count += 1;
            index += 1;
        }

        RegCloseKey(key);
        Ok(count)
    }
}

#[rustbof::main]
fn main() {
    println!("Attack Surface Reduction configuration\n");

    let mut total_rules = 0u32;
    let mut total_exclusions = 0u32;

    for source in SOURCES {
        println!("{} rules:", source.label);
        match enumerate_values(source.rules, true) {
            Ok(0) => println!("  <none configured>"),
            Ok(count) => total_rules += count,
            Err(ERROR_FILE_NOT_FOUND) => println!("  <key not present>"),
            Err(status) => eprintln!("  query failed: 0x{:X}", status),
        }

        println!("{} exclusions:", source.label);
        match enumerate_values(source.exclusions, false) {
            Ok(0) => println!("  <none configured>"),
            Ok(count) => total_exclusions += count,
            Err(ERROR_FILE_NOT_FOUND) => println!("  <key not present>"),
            Err(status) => eprintln!("  query failed: 0x{:X}", status),
        }

        println!();
    }

    println!(
        "Summary: {} configured rule value(s), {} exclusion value(s)",
        total_rules, total_exclusions
    );
}
