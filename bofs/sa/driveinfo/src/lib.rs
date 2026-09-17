//! # Drive Information BOF
//!
//! Enumerates logical drives with drive type, volume label, file system,
//! serial number, capacity, and available space.
//!
//! ## MITRE ATT&CK
//! - T1120 - Peripheral Device Discovery
//! - T1083 - File and Directory Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{format, string::String, vec};
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW,
};
use windows_sys::Win32::System::WindowsProgramming::{
    DRIVE_CDROM, DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE,
    DRIVE_UNKNOWN,
};

fn wide_to_string(buffer: &[u16]) -> String {
    let length = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

fn drive_type_name(value: u32) -> &'static str {
    match value {
        DRIVE_UNKNOWN => "unknown",
        DRIVE_NO_ROOT_DIR => "invalid",
        DRIVE_REMOVABLE => "removable",
        DRIVE_FIXED => "fixed",
        DRIVE_REMOTE => "remote",
        DRIVE_CDROM => "optical",
        DRIVE_RAMDISK => "ramdisk",
        _ => "unknown",
    }
}

fn byte_size(value: u64) -> String {
    const GIB: u64 = 1_073_741_824;
    const MIB: u64 = 1_048_576;

    if value >= GIB {
        let whole = value / GIB;
        let decimal = (value % GIB) * 10 / GIB;
        format!("{}.{} GiB", whole, decimal)
    } else {
        format!("{} MiB", value / MIB)
    }
}

fn print_drive(root: &[u16]) {
    unsafe {
        let root_name = wide_to_string(root);
        let drive_type = drive_type_name(GetDriveTypeW(root.as_ptr()));

        let mut volume_name = [0u16; 261];
        let mut file_system = [0u16; 261];
        let mut serial = 0u32;
        let mut maximum_component = 0u32;
        let mut flags = 0u32;
        let volume_ok = GetVolumeInformationW(
            root.as_ptr(),
            volume_name.as_mut_ptr(),
            volume_name.len() as u32,
            &mut serial,
            &mut maximum_component,
            &mut flags,
            file_system.as_mut_ptr(),
            file_system.len() as u32,
        );

        let mut available = 0u64;
        let mut total = 0u64;
        let mut total_free = 0u64;
        let space_ok =
            GetDiskFreeSpaceExW(root.as_ptr(), &mut available, &mut total, &mut total_free);

        println!("{} [{}]", root_name, drive_type);
        if volume_ok != 0 {
            let label = wide_to_string(&volume_name);
            println!(
                "  label:       {}",
                if label.is_empty() { "<none>" } else { &label }
            );
            println!("  file system: {}", wide_to_string(&file_system));
            println!(
                "  serial:      {:04X}-{:04X}",
                serial >> 16,
                serial & 0xFFFF
            );
        } else {
            println!("  volume:      unavailable (0x{:X})", GetLastError());
        }

        if space_ok != 0 {
            println!("  capacity:    {}", byte_size(total));
            println!("  available:   {}", byte_size(available));
        } else {
            println!("  space:       unavailable");
        }
        println!();
    }
}

#[rustbof::main]
fn main() {
    unsafe {
        let required = GetLogicalDriveStringsW(0, core::ptr::null_mut());
        if required == 0 {
            eprintln!("GetLogicalDriveStringsW failed: 0x{:X}", GetLastError());
        } else {
            let mut buffer = vec![0u16; required as usize + 1];
            let written = GetLogicalDriveStringsW(buffer.len() as u32, buffer.as_mut_ptr());
            if written == 0 || written > buffer.len() as u32 {
                eprintln!("GetLogicalDriveStringsW failed: 0x{:X}", GetLastError());
            } else {
                println!("Logical drives\n");
                let mut offset = 0usize;
                let mut count = 0u32;
                while offset < written as usize && buffer[offset] != 0 {
                    let length = buffer[offset..].iter().position(|&c| c == 0).unwrap_or(0);
                    if length == 0 {
                        break;
                    }
                    print_drive(&buffer[offset..offset + length + 1]);
                    offset += length + 1;
                    count += 1;
                }
                println!("Total drives: {}", count);
            }
        }
    }
}
