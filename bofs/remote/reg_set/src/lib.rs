//! # Registry Set Value BOF
//!
//! Sets a registry value using RegSetValueExA. Supports remote registry access
//! via RegConnectRegistryA when a hostname is provided. Creates the key if it
//! does not already exist using RegCreateKeyExA.
//!
//! ## MITRE ATT&CK
//! - T1112 - Modify Registry
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).
//! - `int`: Hive ID (0=HKCR, 1=HKCU, 2=HKLM, 3=HKU).
//! - `str`: Registry path (subkey).
//! - `str`: Value name.
//! - `str`: Type string ("REG_SZ", "REG_DWORD", "REG_EXPAND_SZ", "REG_BINARY", "REG_QWORD").
//! - `str`: Value data (string for SZ types, decimal for DWORD/QWORD, hex for BINARY).

#![no_std]

use alloc::{string::String, vec::Vec};
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::*;

const HKEY_CLASSES_ROOT: isize = 0x80000000u32 as isize;
const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;
const HKEY_USERS: isize = 0x80000003u32 as isize;

const REG_TYPE_SZ: u32 = 1;
const REG_TYPE_EXPAND_SZ: u32 = 2;
const REG_TYPE_BINARY: u32 = 3;
const REG_TYPE_DWORD: u32 = 4;
const REG_TYPE_QWORD: u32 = 11;

fn hive_from_id(id: i32) -> Option<isize> {
    match id {
        0 => Some(HKEY_CLASSES_ROOT),
        1 => Some(HKEY_CURRENT_USER),
        2 => Some(HKEY_LOCAL_MACHINE),
        3 => Some(HKEY_USERS),
        _ => None,
    }
}

fn hive_name(id: i32) -> &'static str {
    match id {
        0 => "HKEY_CLASSES_ROOT",
        1 => "HKEY_CURRENT_USER",
        2 => "HKEY_LOCAL_MACHINE",
        3 => "HKEY_USERS",
        _ => "UNKNOWN",
    }
}

fn type_from_str(s: &str) -> Option<u32> {
    match s {
        "REG_SZ" => Some(REG_TYPE_SZ),
        "REG_EXPAND_SZ" => Some(REG_TYPE_EXPAND_SZ),
        "REG_BINARY" => Some(REG_TYPE_BINARY),
        "REG_DWORD" => Some(REG_TYPE_DWORD),
        "REG_QWORD" => Some(REG_TYPE_QWORD),
        _ => None,
    }
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn parse_u32(s: &str) -> Option<u32> {
    let mut result: u32 = 0;
    for &b in s.as_bytes() {
        if b < b'0' || b > b'9' {
            return None;
        }
        result = result.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(result)
}

fn parse_u64(s: &str) -> Option<u64> {
    let mut result: u64 = 0;
    for &b in s.as_bytes() {
        if b < b'0' || b > b'9' {
            return None;
        }
        result = result.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(result)
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());
    let hive_id = parser.get_int();
    let path = String::from(parser.get_str());
    let value_name = String::from(parser.get_str());
    let type_str = String::from(parser.get_str());
    let value_data = String::from(parser.get_str());

    let hive = match hive_from_id(hive_id) {
        Some(h) => h,
        None => {
            eprintln!("Invalid hive ID: {} (use 0=HKCR, 1=HKCU, 2=HKLM, 3=HKU)", hive_id);
            return;
        }
    };

    if path.is_empty() {
        eprintln!("Registry path is required");
        return;
    }

    if value_name.is_empty() {
        eprintln!("Value name is required");
        return;
    }

    let reg_type = match type_from_str(&type_str) {
        Some(t) => t,
        None => {
            eprintln!("Invalid type: {} (use REG_SZ, REG_DWORD, REG_EXPAND_SZ, REG_BINARY, REG_QWORD)", type_str);
            return;
        }
    };

    let path_cstr = rustbof::str::to_cstr(&path);
    let name_cstr = rustbof::str::to_cstr(&value_name);

    unsafe {
        let root_key: isize = if hostname.is_empty() {
            hive
        } else {
            let host_cstr = rustbof::str::to_cstr(&hostname);
            let mut remote_key: isize = 0;
            let ret = RegConnectRegistryA(
                host_cstr.as_ptr() as *const u8,
                hive as HKEY,
                &mut remote_key as *mut isize as *mut HKEY,
            );
            if ret != 0 {
                eprintln!("RegConnectRegistryA failed: 0x{:X}", ret);
                return;
            }
            remote_key
        };

        let mut hkey: isize = 0;
        let mut disposition: u32 = 0;
        let ret = RegCreateKeyExA(
            root_key as HKEY,
            path_cstr.as_ptr() as *const u8,
            0,
            core::ptr::null(),
            0, // REG_OPTION_NON_VOLATILE
            KEY_WRITE,
            core::ptr::null(),
            &mut hkey as *mut isize as *mut HKEY,
            &mut disposition,
        );
        if ret != 0 {
            eprintln!(
                "RegCreateKeyExA failed on {}\\{}: 0x{:X}",
                hive_name(hive_id),
                path,
                ret
            );
            if !hostname.is_empty() {
                RegCloseKey(root_key as HKEY);
            }
            return;
        }

        let data_result: Option<Vec<u8>> = match reg_type {
            REG_TYPE_SZ | REG_TYPE_EXPAND_SZ => {
                let mut bytes = Vec::from(value_data.as_bytes());
                bytes.push(0);
                Some(bytes)
            }
            REG_TYPE_DWORD => {
                match parse_u32(&value_data) {
                    Some(val) => Some(Vec::from(val.to_le_bytes().as_slice())),
                    None => None,
                }
            }
            REG_TYPE_QWORD => {
                match parse_u64(&value_data) {
                    Some(val) => Some(Vec::from(val.to_le_bytes().as_slice())),
                    None => None,
                }
            }
            REG_TYPE_BINARY => hex_to_bytes(&value_data),
            _ => None,
        };

        let data = match data_result {
            Some(d) => d,
            None => {
                eprintln!("Failed to parse value '{}' for type {}", value_data, type_str);
                RegCloseKey(hkey as HKEY);
                if !hostname.is_empty() {
                    RegCloseKey(root_key as HKEY);
                }
                return;
            }
        };

        let ret = RegSetValueExA(
            hkey as HKEY,
            name_cstr.as_ptr() as *const u8,
            0,
            reg_type,
            data.as_ptr(),
            data.len() as u32,
        );
        if ret != 0 {
            eprintln!(
                "RegSetValueExA failed for '{}' on {}\\{}: 0x{:X}",
                value_name,
                hive_name(hive_id),
                path,
                ret
            );
        } else {
            let disp_str = if disposition == 1 { "created" } else { "opened" };
            println!(
                "SUCCESS: Set {} = '{}' ({}) on {}\\{} (key {})",
                value_name,
                value_data,
                type_str,
                hive_name(hive_id),
                path,
                disp_str
            );
        }

        RegCloseKey(hkey as HKEY);
        if !hostname.is_empty() {
            RegCloseKey(root_key as HKEY);
        }
    }
}
