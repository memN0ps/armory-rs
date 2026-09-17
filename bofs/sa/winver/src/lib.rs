//! # Windows Version BOF
//!
//! Reports the native Windows version, build, update build revision, product
//! name, display version, and installation type.
//!
//! ## MITRE ATT&CK
//! - T1082 - System Information Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{string::String, vec};
use rustbof::{eprintln, println};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_SZ, RegCloseKey,
    RegOpenKeyExW, RegQueryValueExW,
};

#[repr(C)]
struct OsVersionInfo {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack: [u16; 128],
    service_pack_major: u16,
    service_pack_minor: u16,
    suite_mask: u16,
    product_type: u8,
    reserved: u8,
}

unsafe extern "system" {
    fn RtlGetVersion(version: *mut OsVersionInfo) -> i32;
}

const CURRENT_VERSION: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

fn wide_z(value: &str) -> alloc::vec::Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn query_string(key: HKEY, name: &str) -> Option<String> {
    let name = wide_z(name);
    let mut value_type = 0u32;
    let mut size = 0u32;
    if unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null(),
            &mut value_type,
            core::ptr::null_mut(),
            &mut size,
        )
    } != 0
        || (value_type != REG_SZ && value_type != REG_EXPAND_SZ)
        || size == 0
        || size > 32 * 1024
    {
        return None;
    }

    let mut buffer = vec![0u16; (size as usize + 1) / 2];
    if unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null(),
            &mut value_type,
            buffer.as_mut_ptr() as *mut u8,
            &mut size,
        )
    } != 0
    {
        return None;
    }
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..length]))
}

fn query_dword(key: HKEY, name: &str) -> Option<u32> {
    let name = wide_z(name);
    let mut value_type = 0u32;
    let mut value = 0u32;
    let mut size = core::mem::size_of::<u32>() as u32;
    if unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null(),
            &mut value_type,
            &mut value as *mut u32 as *mut u8,
            &mut size,
        )
    } == 0
        && value_type == REG_DWORD
        && size == 4
    {
        Some(value)
    } else {
        None
    }
}

#[rustbof::main]
fn main() {
    let mut version: OsVersionInfo = unsafe { core::mem::zeroed() };
    version.size = core::mem::size_of::<OsVersionInfo>() as u32;
    let version_status = unsafe { RtlGetVersion(&mut version) };

    let path = wide_z(CURRENT_VERSION);
    let mut key: HKEY = core::ptr::null_mut();
    let registry_status =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };

    println!("Windows version");
    if version_status >= 0 {
        println!(
            "Native version: {}.{}.{}",
            version.major, version.minor, version.build
        );
    } else {
        eprintln!("RtlGetVersion failed: 0x{:08X}", version_status as u32);
    }

    if registry_status == 0 {
        let build = query_string(key, "CurrentBuildNumber")
            .unwrap_or_else(|| alloc::format!("{}", version.build));
        let ubr = query_dword(key, "UBR").unwrap_or(0);
        println!("Build and revision: {}.{}", build, ubr);
        let product =
            query_string(key, "ProductName").unwrap_or_else(|| String::from("<not available>"));
        if version.major == 10 && version.build >= 22_000 && product.starts_with("Windows 10") {
            println!("Product: Windows 11{}", &product[10..]);
            println!("Registry product label: {}", product);
        } else {
            println!("Product: {}", product);
        }
        println!(
            "Display version: {}",
            query_string(key, "DisplayVersion").unwrap_or_else(|| String::from("<not available>"))
        );
        println!(
            "Installation type: {}",
            query_string(key, "InstallationType")
                .unwrap_or_else(|| String::from("<not available>"))
        );
        unsafe { RegCloseKey(key) };
    } else {
        eprintln!(
            "CurrentVersion registry query failed: 0x{:X}",
            registry_status
        );
    }
}
