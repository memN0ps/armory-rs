#![no_std]

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::null_mut;

use rustbof::str::from_cstr;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FIXED_INFO_W2KSP1, GetAdaptersInfo, GetNetworkParams,
    IF_TYPE_IEEE80211, IP_ADAPTER_INFO, MIB_IF_TYPE_ETHERNET,
    MIB_IF_TYPE_FDDI, MIB_IF_TYPE_LOOPBACK, MIB_IF_TYPE_PPP,
    MIB_IF_TYPE_SLIP, MIB_IF_TYPE_TOKENRING,
};

#[rustbof::main]
fn main() {
    println!("Windows IP Configuration\n");
    if let Err(e) = show_network_params() {
        eprintln!("GetNetworkParams Failed With Error: {e}");
    }

    if let Err(e) = show_adapters() {
        eprintln!("GetAdaptersInfo Failed With Error: {e}");
    }
}

fn show_network_params() -> Result<(), u32> {
    unsafe {
        let mut buf_len = 0u32;
        let status = GetNetworkParams(null_mut(), &mut buf_len);
        if status != ERROR_BUFFER_OVERFLOW {
            return Err(status);
        }

        let mut buffer = vec![0u8; buf_len as usize];
        let info = buffer.as_mut_ptr() as *mut FIXED_INFO_W2KSP1;
        let status = GetNetworkParams(info, &mut buf_len);
        if status != ERROR_SUCCESS {
            return Err(status);
        }

        let info = &*info;
        let mut rows: Vec<(&str, String)> = Vec::new();

        rows.push(("Host Name", from_cstr(&info.HostName).into()));
        rows.push(("Primary Dns Suffix", from_cstr(&info.DomainName).into()));

        let ip = from_cstr(&info.DnsServerList.IpAddress.String);
        if !ip.is_empty() {
            rows.push(("DNS Servers", ip.into()));
            let mut next = info.DnsServerList.Next;
            while !next.is_null() {
                rows.push(("", from_cstr(&(*next).IpAddress.String).into()));
                next = (*next).Next;
            }
        }

        print_rows(&rows);
        Ok(())
    }
}

fn show_adapters() -> Result<(), u32> {
    unsafe {
        let mut buf_len = (size_of::<IP_ADAPTER_INFO>() * 16) as u32;
        let mut buffer = vec![0u8; buf_len as usize];
        let adapters = buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;

        let status = GetAdaptersInfo(adapters, &mut buf_len);
        if status != ERROR_SUCCESS {
            return Err(status);
        }

        let mut current = adapters;
        while !current.is_null() {
            let a = &*current;
            let tipo = match a.Type {
                MIB_IF_TYPE_ETHERNET => "Ethernet",
                MIB_IF_TYPE_TOKENRING => "Token Ring",
                MIB_IF_TYPE_FDDI => "FDDI",
                MIB_IF_TYPE_PPP => "PPP",
                MIB_IF_TYPE_LOOPBACK => "Loopback",
                MIB_IF_TYPE_SLIP => "SLIP",
                IF_TYPE_IEEE80211 => "Wireless",
                _ => "Unknown",
            };

            let m = &a.Address;
            let mut rows: Vec<(&str, String)> = Vec::new();

            rows.push(("Physical Address", format!(
                "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )));

            rows.push(("DHCP Enabled", (if a.DhcpEnabled != 0 { "Yes" } else { "No" }).into()));

            let ip = from_cstr(&a.IpAddressList.IpAddress.String);
            if !ip.is_empty() {
                rows.push(("IPv4 Address", ip.into()));
                rows.push(("Subnet Mask", from_cstr(&a.IpAddressList.IpMask.String).into()));
            }

            let gw = from_cstr(&a.GatewayList.IpAddress.String);
            if !gw.is_empty() {
                rows.push(("Default Gateway", gw.into()));
            }

            if a.DhcpEnabled != 0 {
                let dhcp = from_cstr(&a.DhcpServer.IpAddress.String);
                if !dhcp.is_empty() {
                    rows.push(("DHCP Server", dhcp.into()));
                }
            }

            println!("\n{} adapter {}:\n", tipo, from_cstr(&a.Description));
            print_rows(&rows);

            current = a.Next;
        }

        Ok(())
    }
}

fn print_rows(rows: &[(&str, String)]) {
    const WIDTH: usize = 34;
    for (label, value) in rows {
        if label.is_empty() {
            println!("   {: <WIDTH$}   {}", "", value);
        } else {
            let remaining = WIDTH - label.len();
            let pad = format!("{}{}", " ".repeat(remaining % 2), ". ".repeat(remaining / 2));
            println!("   {}{} : {}", label, pad, value);
        }
    }
}
