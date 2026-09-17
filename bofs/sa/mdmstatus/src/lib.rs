//! # MDM Enrollment Status BOF
//!
//! Enumerates local Windows MDM enrollment records. A record proves that
//! enrollment data exists; it does not by itself prove that the management
//! channel is currently healthy.
//!
//! ## MITRE ATT&CK
//! - T1012 - Query Registry
//! - T1518 - Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{string::String, vec};
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::{
    HKEY, KEY_READ, KEY_WOW64_64KEY, RegCloseKey, RegEnumKeyExA, RegOpenKeyExA, RegQueryValueExA,
};

const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const MAX_RECORDS: u32 = 64;

const ENROLLMENTS: &[u8] = b"SOFTWARE\\Microsoft\\Enrollments\0";

fn query_string(key: HKEY, name: &[u8]) -> Option<String> {
    unsafe {
        let mut value_type = 0u32;
        let mut size = 0u32;
        if RegQueryValueExA(
            key,
            name.as_ptr(),
            core::ptr::null(),
            &mut value_type,
            core::ptr::null_mut(),
            &mut size,
        ) != 0
            || value_type != REG_SZ
            || size == 0
            || size > 4096
        {
            return None;
        }

        let mut buffer = vec![0u8; size as usize + 1];
        if RegQueryValueExA(
            key,
            name.as_ptr(),
            core::ptr::null(),
            &mut value_type,
            buffer.as_mut_ptr(),
            &mut size,
        ) != 0
        {
            return None;
        }

        let length = buffer.iter().position(|&byte| byte == 0)?;
        let value = core::str::from_utf8(&buffer[..length]).ok()?;
        Some(String::from(value))
    }
}

fn query_dword(key: HKEY, name: &[u8]) -> Option<u32> {
    unsafe {
        let mut value_type = 0u32;
        let mut size = 4u32;
        let mut value = 0u32;
        if RegQueryValueExA(
            key,
            name.as_ptr(),
            core::ptr::null(),
            &mut value_type,
            &mut value as *mut u32 as *mut u8,
            &mut size,
        ) == 0
            && value_type == REG_DWORD
            && size == 4
        {
            Some(value)
        } else {
            None
        }
    }
}

fn print_record(root: HKEY, subkey: &str) -> bool {
    let mut path = String::from(subkey);
    path.push('\0');

    unsafe {
        let mut key: HKEY = core::ptr::null_mut();
        if RegOpenKeyExA(root, path.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut key) != 0 {
            return false;
        }

        let provider = query_string(key, b"ProviderID\0");
        if provider.is_none() {
            RegCloseKey(key);
            return false;
        }

        println!("{}", subkey);
        println!(
            "  provider:   {}",
            provider.as_deref().unwrap_or("<unknown>")
        );
        if let Some(value) = query_string(key, b"UPN\0") {
            println!("  account:    {}", value);
        }
        if let Some(value) = query_string(key, b"AADTenantID\0") {
            println!("  tenant:     {}", value);
        }
        if let Some(value) = query_string(key, b"DiscoveryServiceFullURL\0") {
            println!("  discovery:  {}", value);
        }
        if let Some(value) = query_dword(key, b"EnrollmentType\0") {
            println!("  type:       {}", value);
        }
        if let Some(value) = query_dword(key, b"EnrollmentState\0") {
            println!("  state:      {}", value);
        }
        println!();

        RegCloseKey(key);
        true
    }
}

fn enumerate_enrollments() -> Result<(u32, bool), u32> {
    unsafe {
        let mut root: HKEY = core::ptr::null_mut();
        let status = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE as HKEY,
            ENROLLMENTS.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut root,
        );
        if status != 0 {
            return Err(status);
        }

        let mut index = 0u32;
        let mut records = 0u32;
        let mut truncated = false;
        loop {
            if index >= 256 || records >= MAX_RECORDS {
                truncated = true;
                break;
            }

            let mut name = vec![0u8; 512];
            let mut length = (name.len() - 1) as u32;
            let status = RegEnumKeyExA(
                root,
                index,
                name.as_mut_ptr(),
                &mut length,
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != 0 {
                RegCloseKey(root);
                return Err(status);
            }

            if let Ok(subkey) = core::str::from_utf8(&name[..length as usize]) {
                if print_record(root, subkey) {
                    records += 1;
                }
            }
            index += 1;
        }

        RegCloseKey(root);
        Ok((records, truncated))
    }
}

#[rustbof::main]
fn main() {
    println!("MDM enrollment records\n");

    match enumerate_enrollments() {
        Ok((0, _)) => println!("No MDM provider records found."),
        Ok((count, truncated)) => println!(
            "Records: {}{}",
            count,
            if truncated { " | limit reached" } else { "" }
        ),
        Err(ERROR_FILE_NOT_FOUND) => println!("No MDM enrollment registry exists."),
        Err(status) => eprintln!("Enrollment query failed: 0x{:X}", status),
    }
}
