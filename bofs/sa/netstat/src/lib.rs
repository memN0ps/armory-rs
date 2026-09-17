//! # Network Connections BOF
//!
//! Lists selected local TCP and UDP connection tables with owning process
//! identifiers.
//!
//! ## Arguments
//! - `int`: Bit mask: `0x0001` TCPv4, `0x0010` TCPv6, `0x0100` UDPv4, and
//!   `0x1000` UDPv6.
//!
//! ## MITRE ATT&CK
//! - T1049 - System Network Connections Discovery

#![no_std]

use alloc::{format, vec};
use rustbof::data::DataParser;
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::NetworkManagement::IpHelper::*;

const AF4: u32 = 2;
const AF6: u32 = 23;

fn tcp_state_str(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTENING",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "???",
    }
}

fn ip4_str(addr: u32) -> alloc::string::String {
    format!(
        "{}.{}.{}.{}",
        addr & 0xFF,
        (addr >> 8) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 24) & 0xFF
    )
}

fn port(p: u32) -> u16 {
    (p as u16).swap_bytes()
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let choices = parser.get_int() as u32;

    println!("Active Connections\n");
    println!(
        "  {:<6} {:<48} {:<48} {:<13} {}",
        "Proto", "Local Address", "Foreign Address", "State", "PID"
    );

    if choices & 0x0001 != 0 {
        show_tcp4();
    }
    if choices & 0x0010 != 0 {
        show_tcp6();
    }
    if choices & 0x0100 != 0 {
        show_udp4();
    }
    if choices & 0x1000 != 0 {
        show_udp6();
    }
}

fn show_tcp4() {
    unsafe {
        let mut size: u32 = 0;
        if GetExtendedTcpTable(
            core::ptr::null_mut(),
            &mut size,
            1,
            AF4,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ) != ERROR_INSUFFICIENT_BUFFER
        {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        let table = buf.as_mut_ptr() as *mut MIB_TCPTABLE_OWNER_PID;
        if GetExtendedTcpTable(table as _, &mut size, 1, AF4, TCP_TABLE_OWNER_PID_ALL, 0) != 0 {
            eprintln!("Failed to get TCP4 endpoints table.");
            return;
        }

        let num = (*table).dwNumEntries as usize;
        let first = &(*table).table[0] as *const MIB_TCPROW_OWNER_PID;
        let rsz = core::mem::size_of::<MIB_TCPROW_OWNER_PID>();
        for i in 0..num {
            let row = &*((first as *const u8).add(i * rsz) as *const MIB_TCPROW_OWNER_PID);
            let local = format!("{}:{}", ip4_str(row.dwLocalAddr), port(row.dwLocalPort));
            let remote = if row.dwState == MIB_TCP_STATE_LISTEN as u32 {
                alloc::string::String::from("*:*")
            } else {
                format!("{}:{}", ip4_str(row.dwRemoteAddr), port(row.dwRemotePort))
            };
            println!(
                "  {:<6} {:<48} {:<48} {:<13} {}",
                "TCP",
                local,
                remote,
                tcp_state_str(row.dwState),
                row.dwOwningPid
            );
        }
    }
}

fn show_tcp6() {
    unsafe {
        let mut size: u32 = 0;
        if GetExtendedTcpTable(
            core::ptr::null_mut(),
            &mut size,
            1,
            AF6,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ) != ERROR_INSUFFICIENT_BUFFER
        {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        let table = buf.as_mut_ptr() as *mut MIB_TCP6TABLE_OWNER_PID;
        if GetExtendedTcpTable(table as _, &mut size, 1, AF6, TCP_TABLE_OWNER_PID_ALL, 0) != 0 {
            return;
        }

        let num = (*table).dwNumEntries as usize;
        let first = &(*table).table[0] as *const MIB_TCP6ROW_OWNER_PID;
        let rsz = core::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
        for i in 0..num {
            let row = &*((first as *const u8).add(i * rsz) as *const MIB_TCP6ROW_OWNER_PID);
            let a = row.ucLocalAddr;
            let local = format!(
                "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]:{}",
                u16::from_be_bytes([a[0], a[1]]),
                u16::from_be_bytes([a[2], a[3]]),
                u16::from_be_bytes([a[4], a[5]]),
                u16::from_be_bytes([a[6], a[7]]),
                u16::from_be_bytes([a[8], a[9]]),
                u16::from_be_bytes([a[10], a[11]]),
                u16::from_be_bytes([a[12], a[13]]),
                u16::from_be_bytes([a[14], a[15]]),
                port(row.dwLocalPort)
            );
            let remote = if row.dwState == MIB_TCP_STATE_LISTEN as u32 {
                alloc::string::String::from("*:*")
            } else {
                let r = row.ucRemoteAddr;
                format!(
                    "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]:{}",
                    u16::from_be_bytes([r[0], r[1]]),
                    u16::from_be_bytes([r[2], r[3]]),
                    u16::from_be_bytes([r[4], r[5]]),
                    u16::from_be_bytes([r[6], r[7]]),
                    u16::from_be_bytes([r[8], r[9]]),
                    u16::from_be_bytes([r[10], r[11]]),
                    u16::from_be_bytes([r[12], r[13]]),
                    u16::from_be_bytes([r[14], r[15]]),
                    port(row.dwRemotePort)
                )
            };
            println!(
                "  {:<6} {:<48} {:<48} {:<13} {}",
                "TCP6",
                local,
                remote,
                tcp_state_str(row.dwState),
                row.dwOwningPid
            );
        }
    }
}

fn show_udp4() {
    unsafe {
        let mut size: u32 = 0;
        if GetExtendedUdpTable(
            core::ptr::null_mut(),
            &mut size,
            1,
            AF4,
            UDP_TABLE_OWNER_PID,
            0,
        ) != ERROR_INSUFFICIENT_BUFFER
        {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        let table = buf.as_mut_ptr() as *mut MIB_UDPTABLE_OWNER_PID;
        if GetExtendedUdpTable(table as _, &mut size, 1, AF4, UDP_TABLE_OWNER_PID, 0) != 0 {
            return;
        }

        let num = (*table).dwNumEntries as usize;
        let first = &(*table).table[0] as *const MIB_UDPROW_OWNER_PID;
        let rsz = core::mem::size_of::<MIB_UDPROW_OWNER_PID>();
        for i in 0..num {
            let row = &*((first as *const u8).add(i * rsz) as *const MIB_UDPROW_OWNER_PID);
            let local = format!("{}:{}", ip4_str(row.dwLocalAddr), port(row.dwLocalPort));
            println!(
                "  {:<6} {:<48} {:<48} {:<13} {}",
                "UDP", local, "*:*", "", row.dwOwningPid
            );
        }
    }
}

fn show_udp6() {
    unsafe {
        let mut size: u32 = 0;
        if GetExtendedUdpTable(
            core::ptr::null_mut(),
            &mut size,
            1,
            AF6,
            UDP_TABLE_OWNER_PID,
            0,
        ) != ERROR_INSUFFICIENT_BUFFER
        {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        let table = buf.as_mut_ptr() as *mut MIB_UDP6TABLE_OWNER_PID;
        if GetExtendedUdpTable(table as _, &mut size, 1, AF6, UDP_TABLE_OWNER_PID, 0) != 0 {
            return;
        }

        let num = (*table).dwNumEntries as usize;
        let first = &(*table).table[0] as *const MIB_UDP6ROW_OWNER_PID;
        let rsz = core::mem::size_of::<MIB_UDP6ROW_OWNER_PID>();
        for i in 0..num {
            let row = &*((first as *const u8).add(i * rsz) as *const MIB_UDP6ROW_OWNER_PID);
            let a = row.ucLocalAddr;
            let local = format!(
                "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]:{}",
                u16::from_be_bytes([a[0], a[1]]),
                u16::from_be_bytes([a[2], a[3]]),
                u16::from_be_bytes([a[4], a[5]]),
                u16::from_be_bytes([a[6], a[7]]),
                u16::from_be_bytes([a[8], a[9]]),
                u16::from_be_bytes([a[10], a[11]]),
                u16::from_be_bytes([a[12], a[13]]),
                u16::from_be_bytes([a[14], a[15]]),
                port(row.dwLocalPort)
            );
            println!(
                "  {:<6} {:<48} {:<48} {:<13} {}",
                "UDP6", local, "*:*", "", row.dwOwningPid
            );
        }
    }
}
