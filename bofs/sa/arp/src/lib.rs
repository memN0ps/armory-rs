//! # ARP Cache BOF
//!
//! Lists the local IPv4 ARP cache with interface indexes, MAC addresses, and
//! entry types.
//!
//! ## Arguments
//! - None.
//!
//! ## MITRE ATT&CK
//! - T1016 - System Network Configuration Discovery

#![no_std]

use alloc::format;
use alloc::vec;
use rustbof::{eprintln, println};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetIpNetTable, MIB_IPNETROW_LH, MIB_IPNETTABLE,
};

fn arp_type_str(t: u32) -> &'static str {
    match t {
        1 => "other",
        2 => "invalid",
        3 => "dynamic",
        4 => "static",
        _ => "unknown",
    }
}

fn ip_str(addr: u32) -> alloc::string::String {
    format!(
        "{}.{}.{}.{}",
        addr & 0xFF,
        (addr >> 8) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 24) & 0xFF
    )
}

#[rustbof::main]
fn main() {
    unsafe {
        let mut size: u32 = 0;
        GetIpNetTable(core::ptr::null_mut(), &mut size, 1);
        if size == 0 {
            println!("No ARP entries found.");
            return;
        }

        let mut buffer = vec![0u8; size as usize];
        let table = buffer.as_mut_ptr() as *mut MIB_IPNETTABLE;
        if GetIpNetTable(table, &mut size, 1) != 0 {
            eprintln!("GetIpNetTable failed");
            return;
        }

        let num = (*table).dwNumEntries as usize;
        let first = &(*table).table[0] as *const MIB_IPNETROW_LH;
        let row_size = core::mem::size_of::<MIB_IPNETROW_LH>();

        let mut last_if: u32 = 0;
        for i in 0..num {
            let row = &*((first as *const u8).add(i * row_size) as *const MIB_IPNETROW_LH);
            if last_if != row.dwIndex {
                last_if = row.dwIndex;
                println!("\nInterface  --- 0x{:X}", row.dwIndex);
                println!(
                    "{:<24}{:<24}{:<24}",
                    "Internet Address", "Physical Address", "Type"
                );
            }

            let ip = ip_str(row.dwAddr);
            let mac = if row.dwPhysAddrLen == 6 {
                format!(
                    "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
                    row.bPhysAddr[0],
                    row.bPhysAddr[1],
                    row.bPhysAddr[2],
                    row.bPhysAddr[3],
                    row.bPhysAddr[4],
                    row.bPhysAddr[5]
                )
            } else {
                alloc::string::String::new()
            };

            println!(
                "{:<24}{:<24}{:<24}",
                ip,
                mac,
                arp_type_str(row.Anonymous.dwType)
            );
        }
    }
}
