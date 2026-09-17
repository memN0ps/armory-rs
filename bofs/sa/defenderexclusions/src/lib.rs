//! # Microsoft Defender Exclusion Inventory BOF
//!
//! Enumerates configured path, process, extension, and IP-address exclusions.
//! Registry configuration is reported as configuration evidence, not proof that
//! an exclusion is currently effective.
//!
//! ## MITRE ATT&CK
//! - T1518.001 - Security Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::string::String;
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegEnumValueW, RegOpenKeyExW,
};

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const MAX_ENTRIES: u32 = 128;

const ROOT: &str = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\";
const CATEGORIES: [(&str, &str); 4] = [
    ("Paths", "Path"),
    ("Processes", "Process"),
    ("Extensions", "Extension"),
    ("IpAddresses", "IP address"),
];

fn wide_z(value: &str) -> alloc::vec::Vec<u16> {
    let mut result: alloc::vec::Vec<u16> = value.encode_utf16().collect();
    result.push(0);
    result
}

fn enumerate_category(key_name: &str, label: &str) -> Result<(u32, bool), u32> {
    let full_name = alloc::format!("{}{}", ROOT, key_name);
    let full_name = wide_z(&full_name);
    let mut key: HKEY = core::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            full_name.as_ptr(),
            0,
            KEY_READ,
            &mut key,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok((0, false));
    }
    if status != 0 {
        return Err(status);
    }

    println!("{} exclusions:", label);
    let mut count = 0u32;
    let mut index = 0u32;
    let mut truncated = false;
    loop {
        if count == MAX_ENTRIES {
            truncated = true;
            break;
        }

        let mut name = [0u16; 1024];
        let mut name_len = name.len() as u32;
        let status = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status == ERROR_MORE_DATA {
            println!("  <entry omitted: name exceeds 1023 UTF-16 units>");
            index += 1;
            count += 1;
            continue;
        }
        if status != 0 {
            unsafe { RegCloseKey(key) };
            return Err(status);
        }

        let value = String::from_utf16_lossy(&name[..name_len as usize]);
        println!("  {}", value);
        index += 1;
        count += 1;
    }

    if count == 0 {
        println!("  <none configured>");
    }
    println!();
    unsafe { RegCloseKey(key) };
    Ok((count, truncated))
}

#[rustbof::main]
fn main() {
    println!("Microsoft Defender exclusion inventory");
    println!("Configured registry state only; effective protection may differ.\n");

    let mut total = 0u32;
    let mut truncated = false;
    for (key_name, label) in CATEGORIES {
        match enumerate_category(key_name, label) {
            Ok((count, category_truncated)) => {
                total += count;
                truncated |= category_truncated;
            }
            Err(status) => eprintln!("{} exclusions failed: 0x{:X}", label, status),
        }
    }

    println!(
        "Configured exclusions shown: {}{}",
        total,
        if truncated {
            " | row limit reached"
        } else {
            ""
        }
    );
}
