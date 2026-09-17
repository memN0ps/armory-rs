//! # Dir BOF
//!
//! Lists directory contents with file sizes and timestamps.
//!
//! ## MITRE ATT&CK
//! - T1083 - File and Directory Discovery
//!
//! ## Arguments
//! - `str`: Directory path to list.

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Time::FileTimeToSystemTime;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let path = parser.get_str();

    let mut path_buf = String::from(path);
    if path_buf.ends_with('\\') || path_buf.ends_with(':') {
        path_buf.push('*');
    } else if !path_buf.contains('*') {
        path_buf.push_str("\\*");
    }
    path_buf.push('\0');

    list_dir(&path_buf);
}

fn list_dir(path: &str) {
    unsafe {
        let mut fd: WIN32_FIND_DATAA = core::mem::zeroed();
        let handle = FindFirstFileA(path.as_ptr(), &mut fd);

        if handle == INVALID_HANDLE_VALUE {
            eprintln!(
                "Couldn't open {}: Error {}",
                path.trim_end_matches('\0'),
                GetLastError()
            );
            return;
        }

        let display_path = path.trim_end_matches('\0');
        println!("Contents of {}:", display_path);

        let mut n_files: u32 = 0;
        let mut n_dirs: u32 = 0;
        let mut total_size: u64 = 0;

        loop {
            let mut st: SYSTEMTIME = core::mem::zeroed();
            FileTimeToSystemTime(&fd.ftLastWriteTime, &mut st);

            let name_bytes = core::slice::from_raw_parts(fd.cFileName.as_ptr() as *const u8, 260);
            let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(260);
            let name = core::str::from_utf8(&name_bytes[..name_len]).unwrap_or("");

            if fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                if fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    println!(
                        "\t{:02}/{:02}/{:04} {:02}:{:02}{:>16} {}",
                        st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, "<junction>", name
                    );
                } else {
                    println!(
                        "\t{:02}/{:02}/{:04} {:02}:{:02}{:>16} {}",
                        st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, "<dir>", name
                    );
                }
                n_dirs += 1;
            } else {
                let file_size = ((fd.nFileSizeHigh as u64) << 32) | fd.nFileSizeLow as u64;
                println!(
                    "\t{:02}/{:02}/{:04} {:02}:{:02}{:>16} {}",
                    st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, file_size, name
                );
                n_files += 1;
                total_size += file_size;
            }

            if FindNextFileA(handle, &mut fd) == 0 {
                break;
            }
        }

        let err = GetLastError();
        if err != ERROR_NO_MORE_FILES {
            eprintln!("Error fetching files: {}", err);
        }

        println!(
            "\t{:>32} Total File Size for {} File(s)",
            total_size, n_files
        );
        println!("\t{:>55} Dir(s)", n_dirs);

        FindClose(handle);
    }
}
