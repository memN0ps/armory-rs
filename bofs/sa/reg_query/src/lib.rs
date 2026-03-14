//! # Registry Query BOF
//!
//! Queries the Windows registry for a specific value or enumerates values and
//! subkeys under a given registry path. Supports remote registry access via
//! RegConnectRegistryA when a hostname is provided.
//!
//! ## MITRE ATT&CK
//! - T1012 - Query Registry
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost).
//! - `int`: Hive ID (0=HKCR, 1=HKCU, 2=HKLM, 3=HKU).
//! - `str`: Registry path (subkey).
//! - `str`: Key/value name (empty to enumerate).
//! - `int`: Recursive flag (unused in initial port, reserved).

#![no_std]

use alloc::{string::String, vec};
use core::ffi::CStr;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Registry::*;

const HKEY_CLASSES_ROOT: isize = 0x80000000u32 as isize;
const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;
const HKEY_USERS: isize = 0x80000003u32 as isize;

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

fn reg_type_str(t: u32) -> &'static str {
    match t {
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_BINARY => "REG_BINARY",
        REG_DWORD => "REG_DWORD",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_QWORD => "REG_QWORD",
        _ => "UNKNOWN",
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

fn hive_from_id(id: i32) -> Option<isize> {
    match id {
        0 => Some(HKEY_CLASSES_ROOT),
        1 => Some(HKEY_CURRENT_USER),
        2 => Some(HKEY_LOCAL_MACHINE),
        3 => Some(HKEY_USERS),
        _ => None,
    }
}

unsafe fn print_value(name: &str, value_type: u32, data: &[u8]) {
    match value_type {
        REG_SZ | REG_EXPAND_SZ => {
            if data.is_empty() {
                println!("\t{} ({}) : (empty)", name, reg_type_str(value_type));
            } else {
                let s = CStr::from_ptr(data.as_ptr() as *const i8)
                    .to_str()
                    .unwrap_or("(invalid)");
                println!("\t{} ({}) : {}", name, reg_type_str(value_type), s);
            }
        }
        REG_DWORD => {
            if data.len() >= 4 {
                let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                println!("\t{} ({}) : 0x{:X} ({})", name, reg_type_str(value_type), val, val);
            } else {
                println!("\t{} ({}) : (invalid size)", name, reg_type_str(value_type));
            }
        }
        REG_QWORD => {
            if data.len() >= 8 {
                let val = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                ]);
                println!("\t{} ({}) : 0x{:X} ({})", name, reg_type_str(value_type), val, val);
            } else {
                println!("\t{} ({}) : (invalid size)", name, reg_type_str(value_type));
            }
        }
        REG_MULTI_SZ => {
            println!("\t{} ({}) :", name, reg_type_str(value_type));
            let mut offset = 0;
            while offset < data.len() {
                let s = CStr::from_ptr(data[offset..].as_ptr() as *const i8);
                let bytes = s.to_bytes();
                if bytes.is_empty() {
                    break;
                }
                let val = s.to_str().unwrap_or("(invalid)");
                println!("\t\t{}", val);
                offset += bytes.len() + 1;
            }
        }
        REG_BINARY | _ => {
            println!("\t{} ({}) : ({} bytes)", name, reg_type_str(value_type), data.len());
        }
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());
    let hive_id = parser.get_int();
    let path = String::from(parser.get_str());
    let key_name = String::from(parser.get_str());
    let _recursive = parser.get_int();

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

        let mut hkey: isize = 0;
        let ret = RegOpenKeyExA(
            root_key as HKEY,
            path_cstr.as_ptr() as *const u8,
            0,
            KEY_READ,
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

        println!("{}\\{}", hive_name(hive_id), path);

        if !key_name.is_empty() {
            let key_cstr = rustbof::str::to_cstr(&key_name);
            let mut value_type: u32 = 0;
            let mut data_size: u32 = 0;

            let ret = RegQueryValueExA(
                hkey as HKEY,
                key_cstr.as_ptr() as *const u8,
                core::ptr::null(),
                &mut value_type,
                core::ptr::null_mut(),
                &mut data_size,
            );
            if ret != 0 {
                eprintln!("RegQueryValueExA failed to get size for '{}': 0x{:X}", key_name, ret);
                RegCloseKey(hkey as HKEY);
                if !hostname.is_empty() {
                    RegCloseKey(root_key as HKEY);
                }
                return;
            }

            let mut data = vec![0u8; data_size as usize];
            let ret = RegQueryValueExA(
                hkey as HKEY,
                key_cstr.as_ptr() as *const u8,
                core::ptr::null(),
                &mut value_type,
                data.as_mut_ptr(),
                &mut data_size,
            );
            if ret != 0 {
                eprintln!("RegQueryValueExA failed for '{}': 0x{:X}", key_name, ret);
                RegCloseKey(hkey as HKEY);
                if !hostname.is_empty() {
                    RegCloseKey(root_key as HKEY);
                }
                return;
            }

            data.truncate(data_size as usize);
            print_value(&key_name, value_type, &data);
        } else {
            println!("  Values:");
            let mut index: u32 = 0;
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

                let val_name = CStr::from_ptr(name_buf.as_ptr() as *const i8)
                    .to_str()
                    .unwrap_or("(invalid)");

                data_buf.truncate(data_len as usize);
                print_value(val_name, value_type, &data_buf);

                index += 1;
            }

            println!("  Subkeys:");
            index = 0;
            loop {
                let mut name_buf = vec![0u8; 512];
                let mut name_len: u32 = name_buf.len() as u32;

                let ret = RegEnumKeyExA(
                    hkey as HKEY,
                    index,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                );

                if ret == 259 {
                    break;
                }
                if ret != 0 {
                    eprintln!("RegEnumKeyExA failed at index {}: 0x{:X}", index, ret);
                    break;
                }

                let subkey_name = CStr::from_ptr(name_buf.as_ptr() as *const i8)
                    .to_str()
                    .unwrap_or("(invalid)");
                println!("\t{}", subkey_name);

                index += 1;
            }
        }

        RegCloseKey(hkey as HKEY);
        if !hostname.is_empty() {
            RegCloseKey(root_key as HKEY);
        }
    }
}
