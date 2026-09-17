//! # Installed Application Count BOF
//!
//! Counts unique uninstall entries across the current-user and both
//! local-machine registry views without printing application names.
//!
//! ## MITRE ATT&CK
//! - T1518 - Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{string::String, vec::Vec};
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    REG_EXPAND_SZ, REG_SZ, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
};

const ERROR_NO_MORE_ITEMS: u32 = 259;
const MAX_SUBKEYS: u32 = 4096;
const MAX_APPLICATIONS: usize = 2048;
const UNINSTALL: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

fn wide_z(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn display_name(key: HKEY) -> Option<String> {
    let name = wide_z("DisplayName");
    let mut value_type = 0u32;
    let mut buffer = [0u16; 1024];
    let mut bytes = (buffer.len() * core::mem::size_of::<u16>()) as u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null(),
            &mut value_type,
            buffer.as_mut_ptr() as *mut u8,
            &mut bytes,
        )
    };
    if status != 0 || (value_type != REG_SZ && value_type != REG_EXPAND_SZ) {
        return None;
    }

    let units = core::cmp::min(bytes as usize / 2, buffer.len());
    let length = buffer[..units]
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units);
    if length == 0 {
        None
    } else {
        Some(String::from_utf16_lossy(&buffer[..length]))
    }
}

fn add_unique(applications: &mut Vec<String>, name: String) {
    if applications.len() < MAX_APPLICATIONS
        && !applications
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&name))
    {
        applications.push(name);
    }
}

fn enumerate_view(root: HKEY, view: u32, applications: &mut Vec<String>) -> Result<u32, u32> {
    let path = wide_z(UNINSTALL);
    let mut uninstall: HKEY = core::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_READ | view, &mut uninstall) };
    if status != 0 {
        return Err(status);
    }

    let mut examined = 0u32;
    while examined < MAX_SUBKEYS && applications.len() < MAX_APPLICATIONS {
        let mut subkey_name = [0u16; 512];
        let mut name_length = subkey_name.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                uninstall,
                examined,
                subkey_name.as_mut_ptr(),
                &mut name_length,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        examined += 1;
        if status != 0 || name_length as usize >= subkey_name.len() {
            continue;
        }

        subkey_name[name_length as usize] = 0;
        let mut entry: HKEY = core::ptr::null_mut();
        if unsafe {
            RegOpenKeyExW(
                uninstall,
                subkey_name.as_ptr(),
                0,
                KEY_READ | view,
                &mut entry,
            )
        } == 0
        {
            if let Some(name) = display_name(entry) {
                add_unique(applications, name);
            }
            unsafe { RegCloseKey(entry) };
        }
    }

    unsafe { RegCloseKey(uninstall) };
    Ok(examined)
}

#[rustbof::main]
fn main() {
    let mut applications = Vec::new();
    let views = [
        ("Local Machine 64-bit", HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
        ("Local Machine 32-bit", HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
        ("Current User", HKEY_CURRENT_USER, 0),
    ];

    println!("Installed application count");
    for (label, root, view) in views {
        match enumerate_view(root, view, &mut applications) {
            Ok(examined) => println!("{}: {} uninstall entries examined", label, examined),
            Err(status) => eprintln!("{} enumeration failed: 0x{:X}", label, status),
        }
    }
    println!("Unique named applications: {}", applications.len());
    if applications.len() == MAX_APPLICATIONS {
        println!("Application limit reached.");
    }
}
