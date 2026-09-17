//! # List DNS Cache BOF
//!
//! Enumerates the local DNS resolver cache entries.
//!
//! ## MITRE ATT&CK
//! - T1018 - Remote System Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use rustbof::println;

#[repr(C)]
struct DnsCacheEntry {
    next: *mut DnsCacheEntry,
    name: *mut u16, // Wide string DNS name
    wtype: u16,     // DNS record type
    data_length: u16,
    flags: u32,
}

unsafe extern "system" {
    fn DnsGetCacheDataTable(entry: *mut *mut DnsCacheEntry) -> i32;
    fn DnsFree(data: *mut core::ffi::c_void, free_type: i32);
}

const DNS_FREE_FLAT: i32 = 0;

#[rustbof::main]
fn main() {
    unsafe {
        let mut entry: *mut DnsCacheEntry = core::ptr::null_mut();
        DnsGetCacheDataTable(&mut entry);

        let head = entry;
        if entry.is_null() || (*entry).next.is_null() {
            println!("No DNS cache entries found");
            if !head.is_null() {
                DnsFree(head as *mut _, DNS_FREE_FLAT);
            }
            return;
        }

        entry = (*entry).next;
        while !entry.is_null() {
            let e = &*entry;
            if !e.name.is_null() {
                let mut len = 0usize;
                while *e.name.add(len) != 0 {
                    len += 1;
                }
                let name_slice = core::slice::from_raw_parts(e.name, len);
                let name = alloc::string::String::from_utf16_lossy(name_slice);
                println!("Cache record: {}   | TYPE {}", name, e.wtype);
            }

            let prev = entry;
            entry = e.next;
            DnsFree(prev as *mut _, DNS_FREE_FLAT);
        }

        if !head.is_null() {
            DnsFree(head as *mut _, DNS_FREE_FLAT);
        }
    }
}
