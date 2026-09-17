//! # VSS Enumeration BOF
//!
//! Enumerates Volume Shadow Copies by probing well-known shadow copy device
//! paths (\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN). This avoids
//! COM/WMI dependencies and works by directly testing for the existence of
//! shadow copy volumes using CreateFileA.
//!
//! ## MITRE ATT&CK
//! - T1003.003 - OS Credential Dumping: NTDS
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::format;
use alloc::string::String;
use rustbof::println;
const GENERIC_READ: u32 = 0x80000000;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
const INVALID_HANDLE_VALUE: isize = -1;

const MAX_SHADOW_COPIES: u32 = 100;
#[repr(C)]
struct Win32FindDataA {
    file_attributes: u32,
    creation_time: [u32; 2],
    last_access_time: [u32; 2],
    last_write_time: [u32; 2],
    file_size_high: u32,
    file_size_low: u32,
    reserved0: u32,
    reserved1: u32,
    file_name: [u8; 260],
    alternate_file_name: [u8; 14],
}

#[repr(C)]
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time: [u32; 2],
    last_access_time: [u32; 2],
    last_write_time: [u32; 2],
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}
unsafe extern "system" {
    fn CreateFileA(
        file_name: *const u8,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *mut core::ffi::c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: *mut core::ffi::c_void,
    ) -> isize;

    fn GetFileInformationByHandle(
        file: isize,
        file_information: *mut ByHandleFileInformation,
    ) -> i32;

    fn CloseHandle(handle: isize) -> i32;

    fn FindFirstFileA(file_name: *const u8, find_data: *mut Win32FindDataA) -> isize;

    fn FindNextFileA(find_handle: isize, find_data: *mut Win32FindDataA) -> i32;

    fn FindClose(find_handle: isize) -> i32;
}
fn cstr_from_buf(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..len]).unwrap_or("(invalid)")
}

fn filetime_to_date(ft: [u32; 2]) -> String {
    let ticks = ((ft[1] as u64) << 32) | ft[0] as u64;
    if ticks == 0 {
        return String::from("(unknown)");
    }

    let secs_since_1601 = ticks / 10_000_000;

    const EPOCH_DIFF: u64 = 11_644_473_600;
    if secs_since_1601 < EPOCH_DIFF {
        return String::from("(pre-epoch)");
    }

    let unix_secs = secs_since_1601 - EPOCH_DIFF;

    let days = unix_secs / 86400;
    let remaining_secs = unix_secs % 86400;
    let hours = remaining_secs / 3600;
    let minutes = (remaining_secs % 3600) / 60;
    let seconds = remaining_secs % 60;

    let mut y = 1970u64;
    let mut d = days;
    loop {
        let days_in_year = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        y += 1;
    }

    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut m = 0u64;
    for i in 0..12 {
        if d < month_days[i] {
            m = i as u64 + 1;
            break;
        }
        d -= month_days[i];
    }
    if m == 0 {
        m = 12;
    }

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        m,
        d + 1,
        hours,
        minutes,
        seconds
    )
}
#[rustbof::main]
fn main() {
    println!("=== Volume Shadow Copy Enumeration ===\n");

    let mut found_count: u32 = 0;

    unsafe {
        for i in 1..=MAX_SHADOW_COPIES {
            let path = format!("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{}\0", i);

            let handle = CreateFileA(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                core::ptr::null_mut(),
            );

            if handle == INVALID_HANDLE_VALUE {
                continue;
            }

            found_count += 1;
            println!(
                "  [Shadow Copy {}] HarddiskVolumeShadowCopy{}",
                found_count, i
            );

            let mut info: ByHandleFileInformation = core::mem::zeroed();
            if GetFileInformationByHandle(handle, &mut info) != 0 {
                println!(
                    "    Created:       {}",
                    filetime_to_date(info.creation_time)
                );
                println!("    Volume Serial: 0x{:08X}", info.volume_serial_number);
            }

            let search_path = format!(
                "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{}\\*\0",
                i
            );

            let mut find_data: Win32FindDataA = core::mem::zeroed();
            let find_handle = FindFirstFileA(search_path.as_ptr(), &mut find_data);

            if find_handle != INVALID_HANDLE_VALUE {
                let mut dir_count: u32 = 0;
                let mut file_count: u32 = 0;

                loop {
                    let name = cstr_from_buf(&find_data.file_name);
                    if name != "." && name != ".." {
                        if find_data.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                            dir_count += 1;
                        } else {
                            file_count += 1;
                        }
                    }

                    if FindNextFileA(find_handle, &mut find_data) == 0 {
                        break;
                    }
                }

                println!(
                    "    Root Contents: {} dirs, {} files",
                    dir_count, file_count
                );
                FindClose(find_handle);
            } else {
                println!("    Root Contents: (access denied or empty)");
            }

            let device_path = format!("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{}", i);
            println!("    Device Path:   {}", device_path);
            println!();

            CloseHandle(handle);
        }
    }

    if found_count == 0 {
        println!("  No volume shadow copies found.");
        println!(
            "  (Probed HarddiskVolumeShadowCopy1 through HarddiskVolumeShadowCopy{})",
            MAX_SHADOW_COPIES
        );
    } else {
        println!("Total shadow copies found: {}", found_count);
    }

    println!("\n=== VSS Enumeration Complete ===");
}
