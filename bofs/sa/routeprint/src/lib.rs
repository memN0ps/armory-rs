//! # Routing Table BOF
//!
//! Lists local network interfaces and the IPv4 routing table.
//!
//! ## Arguments
//! - None.
//!
//! ## MITRE ATT&CK
//! - T1016 - System Network Configuration Discovery

#![no_std]

use alloc::format;
use alloc::vec;
use rustbof::str::from_cstr;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersInfo, GetIpForwardTable, IP_ADAPTER_INFO, MIB_IPFORWARDROW, MIB_IPFORWARDTABLE,
};

fn ip_str(a: u32) -> alloc::string::String {
    format!(
        "{}.{}.{}.{}",
        a & 0xFF,
        (a >> 8) & 0xFF,
        (a >> 16) & 0xFF,
        (a >> 24) & 0xFF
    )
}

#[rustbof::main]
fn main() {
    unsafe {
        let mut adapt_len: u32 = 0;
        if GetAdaptersInfo(core::ptr::null_mut(), &mut adapt_len) != ERROR_BUFFER_OVERFLOW {
            eprintln!("Failed to get adapter buffer size");
            return;
        }
        let mut adapt_buf = vec![0u8; adapt_len as usize];
        let adapters = adapt_buf.as_mut_ptr() as *mut IP_ADAPTER_INFO;

        let mut fwd_len: u32 = 0;
        GetIpForwardTable(core::ptr::null_mut(), &mut fwd_len, 1);
        if fwd_len == 0 {
            eprintln!("Failed to get forward table size");
            return;
        }
        let mut fwd_buf = vec![0u8; fwd_len as usize];
        let fwd_table = fwd_buf.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;

        if GetAdaptersInfo(adapters, &mut adapt_len) != 0 {
            eprintln!("GetAdaptersInfo failed");
            return;
        }
        if GetIpForwardTable(fwd_table, &mut fwd_len, 1) != 0 {
            eprintln!("GetIpForwardTable failed");
            return;
        }

        println!("===========================================================================");
        println!("Interface List");
        let mut cur = adapters;
        while !cur.is_null() {
            let a = &*cur;
            println!(
                "0x{} ........................... {}",
                a.Index,
                from_cstr(&a.Description)
            );
            cur = a.Next;
        }
        println!("===========================================================================");

        let def_gw = from_cstr(&(*adapters).GatewayList.IpAddress.String);

        println!("===========================================================================");
        println!("Active Routes:");
        println!(
            "{:<27}{:<17}{:<14}{:<11}{:<10}",
            "Network Destination", "Netmask", "Gateway", "Interface", "Metric"
        );

        let num = (*fwd_table).dwNumEntries as usize;
        let first = &(*fwd_table).table[0] as *const MIB_IPFORWARDROW;
        let row_sz = core::mem::size_of::<MIB_IPFORWARDROW>();
        for i in 0..num {
            let r = &*((first as *const u8).add(i * row_sz) as *const MIB_IPFORWARDROW);
            println!(
                "{:>17}{:>17}{:>17}{:>16}{:>9}",
                ip_str(r.dwForwardDest),
                ip_str(r.dwForwardMask),
                ip_str(r.dwForwardNextHop),
                r.dwForwardIfIndex,
                r.dwForwardMetric1
            );
        }
        println!("Default Gateway:{:>18}", def_gw);
        println!("===========================================================================");
        println!("Persistent Routes:");
    }
}
