//! # Bounded TCP Port Scan BOF
//!
//! Checks a bounded list of TCP ports on one IPv4 address with non-blocking
//! connect and an explicit per-port timeout. It performs no banner grabbing.
//!
//! ## MITRE ATT&CK
//! - T1046 - Network Service Discovery
//!
//! ## Arguments
//! Two packed strings followed by one packed int: IPv4 address, comma-separated
//! ports or top20, and timeout in milliseconds from 1 through 5000.

#![no_std]

use alloc::vec::Vec;
use rustbof::{eprintln, println};

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const SOL_SOCKET: i32 = 0xFFFF;
const SO_ERROR: i32 = 0x1007;
const INVALID_SOCKET: usize = usize::MAX;
const SOCKET_ERROR: i32 = -1;
const FIONBIO: i32 = 0x8004667Eu32 as i32;
const WSAEWOULDBLOCK: i32 = 10035;
const INADDR_NONE: u32 = u32::MAX;
const TOP20: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 636, 1433, 3306, 3389, 5985, 5986,
    8080,
];

#[repr(C)]
struct SockAddrIn {
    family: i16,
    port: u16,
    address: u32,
    zero: [u8; 8],
}

#[repr(C)]
struct Timeval {
    seconds: i32,
    microseconds: i32,
}

#[repr(C)]
struct FdSet {
    count: u32,
    sockets: [usize; 64],
}

unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut [u8; 408]) -> i32;
    fn WSACleanup() -> i32;
    fn WSAGetLastError() -> i32;
    fn socket(family: i32, socket_type: i32, protocol: i32) -> usize;
    fn connect(socket: usize, address: *const SockAddrIn, length: i32) -> i32;
    fn closesocket(socket: usize) -> i32;
    fn ioctlsocket(socket: usize, command: i32, argument: *mut u32) -> i32;
    fn select(
        ignored: i32,
        read: *mut FdSet,
        write: *mut FdSet,
        except: *mut FdSet,
        timeout: *const Timeval,
    ) -> i32;
    fn getsockopt(socket: usize, level: i32, option: i32, value: *mut u8, length: *mut i32) -> i32;
    fn inet_addr(address: *const u8) -> u32;
    fn htons(value: u16) -> u16;
}

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
        let header = self.offset.checked_add(4)?;
        let size =
            u32::from_le_bytes(self.buffer.get(self.offset..header)?.try_into().ok()?) as usize;
        self.offset = header;
        if size <= 1 || size > maximum + 1 {
            return None;
        }
        let end = self.offset.checked_add(size)?;
        let value = self.buffer.get(self.offset..end)?;
        self.offset = end;
        if value.last().copied() != Some(0) || value[..size - 1].contains(&0) {
            return None;
        }
        core::str::from_utf8(&value[..size - 1]).ok()
    }

    fn integer(&mut self) -> Option<i32> {
        let end = self.offset.checked_add(4)?;
        let value = i32::from_le_bytes(self.buffer.get(self.offset..end)?.try_into().ok()?);
        self.offset = end;
        Some(value)
    }

    fn done(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

fn parse_ports(value: &str) -> Option<Vec<u16>> {
    if value.eq_ignore_ascii_case("top20") {
        return Some(TOP20.to_vec());
    }
    let mut ports = Vec::new();
    for component in value.split(',') {
        let component = component.trim();
        if component.is_empty() {
            return None;
        }
        if let Some((first, last)) = component.split_once('-') {
            let first = first.trim().parse::<u16>().ok()?;
            let last = last.trim().parse::<u16>().ok()?;
            if first == 0 || first > last || last - first > 255 {
                return None;
            }
            for port in first..=last {
                if !ports.contains(&port) {
                    ports.push(port);
                }
                if ports.len() > 256 {
                    return None;
                }
            }
        } else {
            let port = component.parse::<u16>().ok()?;
            if port == 0 {
                return None;
            }
            if !ports.contains(&port) {
                ports.push(port);
            }
            if ports.len() > 256 {
                return None;
            }
        }
    }
    (!ports.is_empty()).then_some(ports)
}

fn probe(address: u32, port: u16, timeout_ms: i32) -> Result<bool, i32> {
    unsafe {
        let handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if handle == INVALID_SOCKET {
            return Err(WSAGetLastError());
        }
        let mut nonblocking = 1u32;
        if ioctlsocket(handle, FIONBIO, &mut nonblocking) == SOCKET_ERROR {
            let status = WSAGetLastError();
            closesocket(handle);
            return Err(status);
        }
        let socket_address = SockAddrIn {
            family: AF_INET as i16,
            port: htons(port),
            address,
            zero: [0; 8],
        };
        let connected = connect(
            handle,
            &socket_address,
            core::mem::size_of::<SockAddrIn>() as i32,
        );
        if connected == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK {
            closesocket(handle);
            return Ok(false);
        }
        let mut write = FdSet {
            count: 1,
            sockets: [0; 64],
        };
        let mut except = FdSet {
            count: 1,
            sockets: [0; 64],
        };
        write.sockets[0] = handle;
        except.sockets[0] = handle;
        let timeout = Timeval {
            seconds: timeout_ms / 1000,
            microseconds: (timeout_ms % 1000) * 1000,
        };
        let selected = select(0, core::ptr::null_mut(), &mut write, &mut except, &timeout);
        let mut error = 0i32;
        let mut size = core::mem::size_of::<i32>() as i32;
        let option = getsockopt(
            handle,
            SOL_SOCKET,
            SO_ERROR,
            &mut error as *mut _ as *mut u8,
            &mut size,
        );
        closesocket(handle);
        if selected == SOCKET_ERROR {
            Err(WSAGetLastError())
        } else if selected == 0 || option == SOCKET_ERROR {
            Ok(false)
        } else {
            Ok(error == 0)
        }
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let parsed = if args.is_null() || len == 0 {
        None
    } else {
        let buffer = unsafe { core::slice::from_raw_parts(args, len) };
        PackedArgs::new(buffer).and_then(|mut parser| {
            let host = parser.string(64)?;
            let ports = parser.string(2048)?;
            let timeout = parser.integer()?;
            parser.done().then_some((host, ports, timeout))
        })
    };

    match parsed {
        Some((host, ports, timeout)) if (1..=5000).contains(&timeout) => match parse_ports(ports) {
            Some(ports) => {
                let mut host_buffer = [0u8; 65];
                host_buffer[..host.len()].copy_from_slice(host.as_bytes());
                let address = unsafe { inet_addr(host_buffer.as_ptr()) };
                if address == INADDR_NONE {
                    eprintln!("IPv4 address is invalid. Hostname resolution is not performed.");
                } else {
                    let mut wsa = [0u8; 408];
                    let startup = unsafe { WSAStartup(0x0202, &mut wsa) };
                    if startup != 0 {
                        eprintln!("WSAStartup failed: {}", startup);
                    } else {
                        println!(
                            "TCP scan | target={} | ports={} | timeout={}ms",
                            host,
                            ports.len(),
                            timeout
                        );
                        let mut open = 0usize;
                        let mut errors = 0usize;
                        for port in &ports {
                            match probe(address, *port, timeout) {
                                Ok(true) => {
                                    println!("tcp/{} open", port);
                                    open += 1;
                                }
                                Ok(false) => {}
                                Err(_) => errors += 1,
                            }
                        }
                        println!(
                            "Scan complete | checked={} | open={} | errors={}",
                            ports.len(),
                            open,
                            errors
                        );
                        unsafe { WSACleanup() };
                    }
                }
            }
            None => eprintln!(
                "Ports must be top20, a comma list, or bounded ranges (maximum 256 ports)."
            ),
        },
        _ => eprintln!("Usage: portscan <ipv4> <top20|ports> <timeout_ms 1-5000>"),
    }
}
