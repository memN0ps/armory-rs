//! # NetBIOS Name Service Scanner BOF
//!
//! Sends a bounded NBSTAT query to one IPv4 address or a CIDR containing at
//! most 64 addresses. It reports returned NetBIOS names and MAC addresses.
//!
//! ## MITRE ATT&CK
//! - T1018 - Remote System Discovery
//! - T1049 - System Network Connections Discovery
//!
//! ## Arguments
//! `nbtscan <ipv4-or-cidr> <timeout_ms 50-5000>`

#![no_std]

use alloc::{string::String, vec::Vec};
use core::ffi::{c_char, c_void};
use rustbof::{eprintln, println};

type Socket = usize;

#[repr(C)]
struct WsaData {
    version: u16,
    high_version: u16,
    description: [u8; 257],
    system_status: [u8; 129],
    max_sockets: u16,
    max_udp_datagram: u16,
    vendor_info: *mut c_char,
}

#[repr(C)]
struct SockAddrIn {
    family: u16,
    port: u16,
    address: u32,
    zero: [u8; 8],
}

unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut WsaData) -> i32;
    fn WSACleanup() -> i32;
    fn WSAGetLastError() -> i32;
    fn socket(family: i32, socket_type: i32, protocol: i32) -> Socket;
    fn closesocket(socket: Socket) -> i32;
    fn setsockopt(
        socket: Socket,
        level: i32,
        option: i32,
        value: *const c_char,
        length: i32,
    ) -> i32;
    fn sendto(
        socket: Socket,
        buffer: *const c_char,
        length: i32,
        flags: i32,
        address: *const c_void,
        address_length: i32,
    ) -> i32;
    fn recvfrom(
        socket: Socket,
        buffer: *mut c_char,
        length: i32,
        flags: i32,
        address: *mut c_void,
        address_length: *mut i32,
    ) -> i32;
}

const AF_INET: i32 = 2;
const SOCK_DGRAM: i32 = 2;
const IPPROTO_UDP: i32 = 17;
const SOL_SOCKET: i32 = 0xffff;
const SO_RCVTIMEO: i32 = 0x1006;
const INVALID_SOCKET: Socket = !0usize;
const MAX_TARGETS: u32 = 64;

struct PackedArgs<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> PackedArgs<'a> {
    fn new(buffer: &'a [u8]) -> Option<Self> {
        if buffer.len() < 4 {
            return None;
        }
        let declared = u32::from_le_bytes(buffer[..4].try_into().ok()?) as usize;
        (declared == buffer.len() - 4).then_some(Self { buffer, offset: 4 })
    }

    fn string(&mut self, maximum: usize) -> Option<&'a str> {
        let end = self.offset.checked_add(4)?;
        let length =
            u32::from_le_bytes(self.buffer.get(self.offset..end)?.try_into().ok()?) as usize;
        self.offset = end;
        if length <= 1 || length > maximum + 1 {
            return None;
        }
        let end = self.offset.checked_add(length)?;
        let bytes = self.buffer.get(self.offset..end)?;
        self.offset = end;
        if bytes.last().copied() != Some(0) || bytes[..length - 1].contains(&0) {
            return None;
        }
        core::str::from_utf8(&bytes[..length - 1]).ok()
    }

    fn integer(&mut self) -> Option<i32> {
        let end = self.offset.checked_add(4)?;
        let value = i32::from_le_bytes(self.buffer.get(self.offset..end)?.try_into().ok()?);
        self.offset = end;
        Some(value)
    }

    fn finished(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

fn parse_ipv4(value: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut count = 0usize;
    for component in value.split('.') {
        if count >= 4 || component.is_empty() {
            return None;
        }
        octets[count] = component.parse::<u8>().ok()?;
        count += 1;
    }
    (count == 4).then_some(octets)
}

fn targets(value: &str) -> Option<Vec<[u8; 4]>> {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, prefix.parse::<u8>().ok()?),
        None => (value, 32),
    };
    if !(26..=32).contains(&prefix) {
        return None;
    }

    let address = parse_ipv4(address)?;
    let numeric = u32::from_be_bytes(address);
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let first = numeric & mask;
    let count = 1u32 << (32 - prefix);
    if count > MAX_TARGETS {
        return None;
    }

    let mut result = Vec::with_capacity(count as usize);
    for offset in 0..count {
        result.push(first.wrapping_add(offset).to_be_bytes());
    }
    Some(result)
}

fn query(transaction: u16) -> [u8; 50] {
    let mut packet = [0u8; 50];
    packet[..2].copy_from_slice(&transaction.to_be_bytes());
    packet[4..6].copy_from_slice(&1u16.to_be_bytes());
    packet[12] = 32;

    let mut raw_name = [0u8; 16];
    raw_name[0] = b'*';
    for (index, byte) in raw_name.iter().enumerate() {
        packet[13 + index * 2] = b'A' + (byte >> 4);
        packet[14 + index * 2] = b'A' + (byte & 0x0f);
    }
    packet[45] = 0;
    packet[46..48].copy_from_slice(&0x21u16.to_be_bytes());
    packet[48..50].copy_from_slice(&1u16.to_be_bytes());
    packet
}

fn skip_name(buffer: &[u8], mut offset: usize) -> Option<usize> {
    if buffer.get(offset).copied()? & 0xc0 == 0xc0 {
        return offset.checked_add(2).filter(|end| *end <= buffer.len());
    }

    loop {
        let length = *buffer.get(offset)? as usize;
        offset = offset.checked_add(1)?;
        if length == 0 {
            return Some(offset);
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        offset = offset.checked_add(length)?;
        if offset > buffer.len() {
            return None;
        }
    }
}

fn read_u16(buffer: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        buffer.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn trim_name(value: &[u8]) -> String {
    let end = value
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != 0)
        .map(|index| index + 1)
        .unwrap_or(0);
    String::from_utf8_lossy(&value[..end]).into_owned()
}

fn parse_response(buffer: &[u8], transaction: u16) -> Option<(Vec<String>, [u8; 6])> {
    if buffer.len() < 12 || read_u16(buffer, 0)? != transaction || read_u16(buffer, 6)? == 0 {
        return None;
    }

    let questions = read_u16(buffer, 4)?;
    let answers = read_u16(buffer, 6)?;
    let mut offset = 12usize;
    for _ in 0..questions {
        offset = skip_name(buffer, offset)?.checked_add(4)?;
        if offset > buffer.len() {
            return None;
        }
    }

    for _ in 0..answers {
        offset = skip_name(buffer, offset)?;
        let record_type = read_u16(buffer, offset)?;
        let data_length = read_u16(buffer, offset.checked_add(8)?)? as usize;
        let data_start = offset.checked_add(10)?;
        let data_end = data_start.checked_add(data_length)?;
        let data = buffer.get(data_start..data_end)?;
        offset = data_end;
        if record_type != 0x21 || data.is_empty() {
            continue;
        }

        let count = data[0] as usize;
        let names_end = 1usize.checked_add(count.checked_mul(18)?)?;
        if names_end.checked_add(6)? > data.len() || count > 64 {
            return None;
        }

        let mut names = Vec::with_capacity(count);
        for index in 0..count {
            let start = 1 + index * 18;
            let name = trim_name(data.get(start..start + 15)?);
            let suffix = data[start + 15];
            let flags = read_u16(data, start + 16)?;
            names.push(alloc::format!(
                "{}<{:02X}> {}",
                if name.is_empty() {
                    "<empty>"
                } else {
                    name.as_str()
                },
                suffix,
                if flags & 0x8000 != 0 {
                    "group"
                } else {
                    "unique"
                }
            ));
        }

        let mut mac = [0u8; 6];
        mac.copy_from_slice(&data[names_end..names_end + 6]);
        return Some((names, mac));
    }
    None
}

fn scan(targets: &[[u8; 4]], timeout: i32) -> Result<(u32, u32), i32> {
    let mut data: WsaData = unsafe { core::mem::zeroed() };
    let startup = unsafe { WSAStartup(0x0202, &mut data) };
    if startup != 0 {
        return Err(startup);
    }

    let socket = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) };
    if socket == INVALID_SOCKET {
        let error = unsafe { WSAGetLastError() };
        unsafe { WSACleanup() };
        return Err(error);
    }
    if unsafe {
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout as *const i32 as *const c_char,
            core::mem::size_of::<i32>() as i32,
        )
    } != 0
    {
        let error = unsafe { WSAGetLastError() };
        unsafe {
            closesocket(socket);
            WSACleanup();
        }
        return Err(error);
    }

    let mut responses = 0u32;
    let mut errors = 0u32;
    for (index, octets) in targets.iter().enumerate() {
        let transaction = 0x4e42u16.wrapping_add(index as u16);
        let packet = query(transaction);
        let address = SockAddrIn {
            family: AF_INET as u16,
            port: 137u16.to_be(),
            address: u32::from_ne_bytes(*octets),
            zero: [0u8; 8],
        };
        let sent = unsafe {
            sendto(
                socket,
                packet.as_ptr() as *const c_char,
                packet.len() as i32,
                0,
                &address as *const SockAddrIn as *const c_void,
                core::mem::size_of::<SockAddrIn>() as i32,
            )
        };
        if sent != packet.len() as i32 {
            errors += 1;
            continue;
        }

        let mut response = [0u8; 2048];
        let received = unsafe {
            recvfrom(
                socket,
                response.as_mut_ptr() as *mut c_char,
                response.len() as i32,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if received <= 0 {
            continue;
        }

        if let Some((names, mac)) = parse_response(&response[..received as usize], transaction) {
            responses += 1;
            println!(
                "{}.{}.{}.{} | mac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                octets[0],
                octets[1],
                octets[2],
                octets[3],
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
            for name in names {
                println!("  {}", name);
            }
        } else {
            errors += 1;
        }
    }

    unsafe {
        closesocket(socket);
        WSACleanup();
    }
    Ok((responses, errors))
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let parsed = if args.is_null() || len == 0 {
        None
    } else {
        let buffer = unsafe { core::slice::from_raw_parts(args, len) };
        PackedArgs::new(buffer).and_then(|mut parser| {
            let target = parser.string(64)?;
            let timeout = parser.integer()?;
            parser.finished().then_some((target, timeout))
        })
    };

    match parsed {
        None => eprintln!("Usage: nbtscan <ipv4-or-cidr> <timeout_ms 50-5000>"),
        Some((_target, timeout)) if !(50..=5000).contains(&timeout) => {
            eprintln!("Timeout must be between 50 and 5000 milliseconds")
        }
        Some((target, timeout)) => match targets(target) {
            None => eprintln!("Target must be IPv4 or a CIDR between /26 and /32"),
            Some(targets) => {
                println!(
                    "NetBIOS name scan | target={} | addresses={} | timeout={}ms",
                    target,
                    targets.len(),
                    timeout
                );
                match scan(&targets, timeout) {
                    Ok((responses, errors)) => println!(
                        "Scan complete | checked={} | responses={} | parse/send errors={}",
                        targets.len(),
                        responses,
                        errors
                    ),
                    Err(error) => eprintln!("Winsock setup failed: {}", error),
                }
            }
        },
    }
}
