//! # Find Loaded Module BOF
//!
//! Searches all running processes for a specific loaded module (DLL).
//! Enumerates processes via CreateToolhelp32Snapshot and checks each
//! process's module list for a case-insensitive match.
//!
//! ## MITRE ATT&CK
//! - T1057 - Process Discovery
//!
//! ## Arguments
//! - `str`: Module name to search for (e.g., `ntdll.dll`, `amsi.dll`).
//! - `str`: Process name filter (optional, empty for all processes).

#![no_std]

use alloc::string::String;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;

fn contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    for i in 0..=(h.len() - n.len()) {
        let mut found = true;
        for j in 0..n.len() {
            if !h[i + j].eq_ignore_ascii_case(&n[j]) {
                found = false;
                break;
            }
        }
        if found {
            return true;
        }
    }
    false
}

fn cstr_from_i8(buf: &[i8]) -> &str {
    let bytes = unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..len]).unwrap_or("")
}

fn check_process_modules(pid: u32, mod_search: &str) -> bool {
    unsafe {
        let mut modinfo: MODULEENTRY32 = core::mem::zeroed();
        modinfo.dwSize = core::mem::size_of::<MODULEENTRY32>() as u32;

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return false;
        }

        let mut found = false;
        if Module32First(snap, &mut modinfo) != 0 {
            loop {
                let path = cstr_from_i8(&modinfo.szExePath);
                if contains_ci(path, mod_search) {
                    println!("{}", path);
                    found = true;
                }
                if Module32Next(snap, &mut modinfo) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snap);
        found
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let mod_search = String::from(parser.get_str());
    let proc_filter = String::from(parser.get_str());
    let proc_filter = if proc_filter.is_empty() {
        None
    } else {
        Some(proc_filter)
    };

    unsafe {
        let mut procinfo: PROCESSENTRY32 = core::mem::zeroed();
        procinfo.dwSize = core::mem::size_of::<PROCESSENTRY32>() as u32;

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            eprintln!("Unable to list processes: {}", GetLastError());
            return;
        }

        let mut count: u32 = 0;
        if Process32First(snap, &mut procinfo) != 0 {
            loop {
                let exe_name = cstr_from_i8(&procinfo.szExeFile);

                let matches = match &proc_filter {
                    Some(filter) => contains_ci(exe_name, filter),
                    None => true,
                };

                if matches && check_process_modules(procinfo.th32ProcessID, &mod_search) {
                    println!("{:<10} : {}", procinfo.th32ProcessID, exe_name);
                    count += 1;
                }

                if Process32Next(snap, &mut procinfo) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snap);

        if count == 0 {
            println!(
                "Enumerated all processes but didn't find module '{}'",
                mod_search
            );
        }
    }
}
