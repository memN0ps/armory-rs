//! # NSLookup BOF
//!
//! Performs DNS queries for a domain name using DnsQuery_A.
//! Supports specifying a custom DNS server and record type.
//!
//! ## MITRE ATT&CK
//! - T1018 - Remote System Discovery
//!
//! ## Arguments
//! - `str`: Domain name to query.
//! - `short`: DNS record type (1=A, 5=CNAME, 28=AAAA, etc.).
//! - `str`: DNS server IP (empty for system default).

#![no_std]

use alloc::format;
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::Dns::*;

#[repr(C)]
struct Ip4Array {
    addr_count: u32,
    addr_array: [u32; 1],
}

unsafe extern "system" {
    fn inet_addr(cp: *const u8) -> u32;
}

fn format_ipv4(addr: u32) -> alloc::string::String {
    format!(
        "{}.{}.{}.{}",
        addr & 0xFF,
        (addr >> 8) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 24) & 0xFF
    )
}

fn dns_type_name(wtype: u16) -> &'static str {
    match wtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        _ => "OTHER",
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let domain = alloc::string::String::from(parser.get_str());
    let record_type = parser.get_short() as u16;
    let dns_server = alloc::string::String::from(parser.get_str());

    unsafe {
        let mut records: *mut DNS_RECORDA = core::ptr::null_mut();
        let options = DNS_QUERY_WIRE_ONLY;

        let mut srv_list = Ip4Array {
            addr_count: 0,
            addr_array: [0],
        };
        let srv_ptr = if !dns_server.is_empty() {
            let cstr = rustbof::str::to_cstr(&dns_server);
            srv_list.addr_array[0] = inet_addr(cstr.as_ptr() as *const u8);
            srv_list.addr_count = 1;
            &srv_list as *const Ip4Array as *mut core::ffi::c_void
        } else {
            core::ptr::null_mut()
        };

        let domain_cstr = rustbof::str::to_cstr(&domain);
        let status = DnsQuery_A(
            domain_cstr.as_ptr() as *const u8,
            record_type,
            options as u32,
            srv_ptr,
            &mut records as *mut *mut DNS_RECORDA as *mut *mut _,
            core::ptr::null_mut(),
        );

        if status != 0 || records.is_null() {
            eprintln!("DNS query for '{}' failed (status: {})", domain, status);
            return;
        }

        println!("DNS query results for '{}' (type {}):", domain, dns_type_name(record_type));

        let mut current = records;
        while !current.is_null() {
            let rec = &*current;
            let rec_type = rec.wType;

            match rec_type {
                1 => {
                    let ip = rec.Data.A.IpAddress;
                    println!("  {} (A): {}", domain, format_ipv4(ip));
                }
                5 => {
                    let name_ptr = rec.Data.CNAME.pNameHost;
                    if !name_ptr.is_null() {
                        let cname = core::ffi::CStr::from_ptr(name_ptr as *const i8)
                            .to_str()
                            .unwrap_or("?");
                        println!("  {} (CNAME): {}", domain, cname);
                    }
                }
                _ => {
                    println!("  {} ({}): <data>", domain, dns_type_name(rec_type));
                }
            }

            current = rec.pNext;
        }

        DnsFree(records as *mut _, DnsFreeRecordList);
    }
}
