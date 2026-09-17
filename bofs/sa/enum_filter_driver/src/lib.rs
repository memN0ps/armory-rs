//! # Enumerate Filter Drivers BOF
//!
//! Enumerates minifilter drivers by scanning the registry for services
//! that have an "Instances" subkey with "Altitude" values. Filter drivers
//! (e.g., antivirus file system filters) register at specific altitudes.
//!
//! ## MITRE ATT&CK
//! - T1518.001 - Software Discovery: Security Software Discovery
//!
//! ## Arguments
//! - `str`: Hostname (empty for localhost, or remote hostname for remote registry).

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows_sys::Win32::System::Registry::*;

const SERVICE_KEY: &[u8] = b"SYSTEM\\CurrentControlSet\\Services\0";
const INSTANCES_KEY: &[u8] = b"Instances\0";
const ALTITUDE_VALUE: &[u8] = b"Altitude\0";

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let hostname = String::from(parser.get_str());

    unsafe {
        let mut root_key: HKEY = core::ptr::null_mut();

        if hostname.is_empty() {
            let status = RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                SERVICE_KEY.as_ptr(),
                0,
                KEY_READ,
                &mut root_key,
            );
            if status != 0u32 {
                eprintln!("RegOpenKeyExA failed: {}", status);
                return;
            }
        } else {
            let host_cstr = rustbof::str::to_cstr(&hostname);
            let mut remote_key: HKEY = core::ptr::null_mut();
            let status = RegConnectRegistryA(
                host_cstr.as_ptr() as *const u8,
                HKEY_LOCAL_MACHINE,
                &mut remote_key,
            );
            if status != 0u32 {
                eprintln!("RegConnectRegistryA failed: {}", status);
                return;
            }
            let status =
                RegOpenKeyExA(remote_key, SERVICE_KEY.as_ptr(), 0, KEY_READ, &mut root_key);
            if status != 0u32 {
                eprintln!("RegOpenKeyExA failed: {}", status);
                RegCloseKey(remote_key);
                return;
            }
        }

        println!("{:<40} {:<15} {}", "Filter Driver", "Instance", "Altitude");
        println!("{:-<40} {:-<15} {:-<10}", "", "", "");

        let mut svc_index: u32 = 0;
        let mut svc_name = [0u8; 260];
        let mut count: u32 = 0;

        loop {
            let mut name_len: u32 = 260;
            let status = RegEnumKeyExA(
                root_key,
                svc_index,
                svc_name.as_mut_ptr(),
                &mut name_len,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != 0u32 {
                svc_index += 1;
                continue;
            }

            let mut svc_key: HKEY = core::ptr::null_mut();
            if RegOpenKeyExA(root_key, svc_name.as_ptr(), 0, KEY_READ, &mut svc_key) == 0 {
                let mut inst_key: HKEY = core::ptr::null_mut();
                if RegOpenKeyExA(svc_key, INSTANCES_KEY.as_ptr(), 0, KEY_READ, &mut inst_key) == 0 {
                    let mut inst_index: u32 = 0;
                    let mut inst_name = [0u8; 260];
                    loop {
                        let mut inst_name_len: u32 = 260;
                        let s = RegEnumKeyExA(
                            inst_key,
                            inst_index,
                            inst_name.as_mut_ptr(),
                            &mut inst_name_len,
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                        );
                        if s == ERROR_NO_MORE_ITEMS {
                            break;
                        }
                        if s != 0 {
                            inst_index += 1;
                            continue;
                        }

                        let mut inst_subkey: HKEY = core::ptr::null_mut();
                        if RegOpenKeyExA(
                            inst_key,
                            inst_name.as_ptr(),
                            0,
                            KEY_READ,
                            &mut inst_subkey,
                        ) == 0
                        {
                            let mut alt_buf = [0u8; 260];
                            let mut alt_len: u32 = 260;
                            let mut alt_type: u32 = 0;
                            if RegQueryValueExA(
                                inst_subkey,
                                ALTITUDE_VALUE.as_ptr(),
                                core::ptr::null_mut(),
                                &mut alt_type,
                                alt_buf.as_mut_ptr(),
                                &mut alt_len,
                            ) == 0
                            {
                                let svc_str = cstr(&svc_name);
                                let inst_str = cstr(&inst_name);
                                let alt_str = cstr(&alt_buf);
                                println!("{:<40} {:<15} {}", svc_str, inst_str, alt_str);
                                count += 1;
                            }
                            RegCloseKey(inst_subkey);
                        }
                        inst_index += 1;
                    }
                    RegCloseKey(inst_key);
                }
                RegCloseKey(svc_key);
            }
            svc_index += 1;
        }

        println!("\nTotal filter drivers found: {}", count);
        RegCloseKey(root_key);
    }
}

fn cstr(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..len]).unwrap_or("")
}
