//! # Probe BOF
//!
//! Checks if a TCP port is open on a target host by attempting a non-blocking
//! connect with a configurable timeout.
//!
//! ## MITRE ATT&CK
//! - T1046 - Network Service Discovery
//!
//! ## Arguments
//! - `host` (str) - Target IP address (e.g. "10.0.0.1").
//! - `port` (int) - TCP port number to probe.
//! - `timeout` (int) - Connection timeout in milliseconds.

#![no_std]

use rustbof::data::DataParser;
use rustbof::{eprintln, println};
const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const INVALID_SOCKET: usize = usize::MAX;
const SOCKET_ERROR: i32 = -1;
const FIONBIO: i32 = 0x8004_667E_u32 as i32;
const WSAEWOULDBLOCK: i32 = 10035;
const INADDR_NONE: u32 = 0xFFFF_FFFF;
#[repr(C)]
struct SockAddrIn {
    sin_family: i16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
struct Timeval {
    tv_sec: i32,
    tv_usec: i32,
}

const FD_SETSIZE: usize = 64;

#[repr(C)]
struct FdSet {
    fd_count: u32,
    fd_array: [usize; FD_SETSIZE],
}

impl FdSet {
    fn new() -> Self {
        Self {
            fd_count: 0,
            fd_array: [0; FD_SETSIZE],
        }
    }

    fn set(&mut self, fd: usize) {
        if (self.fd_count as usize) < FD_SETSIZE {
            self.fd_array[self.fd_count as usize] = fd;
            self.fd_count += 1;
        }
    }

    fn is_set(&self, fd: usize) -> bool {
        for i in 0..self.fd_count as usize {
            if self.fd_array[i] == fd {
                return true;
            }
        }
        false
    }
}
unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut [u8; 408]) -> i32;
    fn WSACleanup() -> i32;
    fn WSAGetLastError() -> i32;
    fn socket(af: i32, socket_type: i32, protocol: i32) -> usize;
    fn connect(s: usize, name: *const SockAddrIn, namelen: i32) -> i32;
    fn closesocket(s: usize) -> i32;
    fn ioctlsocket(s: usize, cmd: i32, argp: *mut u32) -> i32;
    fn select(
        nfds: i32,
        readfds: *mut FdSet,
        writefds: *mut FdSet,
        exceptfds: *mut FdSet,
        timeout: *const Timeval,
    ) -> i32;
    fn inet_addr(cp: *const u8) -> u32;
    fn htons(hostshort: u16) -> u16;
}
#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let mut parser = DataParser::new(args, len);
    let host = alloc::string::String::from(parser.get_str());
    let port = parser.get_int() as u16;
    let timeout_ms = parser.get_int();

    println!("Probing {}:{} (timeout {}ms)...", host, port, timeout_ms);

    unsafe {
        let mut wsa_data = [0u8; 408];
        let ret = WSAStartup(0x0202, &mut wsa_data);
        if ret != 0 {
            eprintln!("WSAStartup failed: {}", ret);
            return;
        }

        let sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if sock == INVALID_SOCKET {
            eprintln!("socket() failed: {}", WSAGetLastError());
            WSACleanup();
            return;
        }

        let host_bytes = host.as_bytes();
        let mut host_buf = [0u8; 256];
        let copy_len = if host_bytes.len() < 255 {
            host_bytes.len()
        } else {
            255
        };
        host_buf[..copy_len].copy_from_slice(&host_bytes[..copy_len]);
        host_buf[copy_len] = 0;

        let addr = inet_addr(host_buf.as_ptr());
        if addr == INADDR_NONE {
            eprintln!("Invalid IP address: {}", host);
            closesocket(sock);
            WSACleanup();
            return;
        }

        let mut mode: u32 = 1;
        if ioctlsocket(sock, FIONBIO, &mut mode) == SOCKET_ERROR {
            eprintln!("ioctlsocket() failed: {}", WSAGetLastError());
            closesocket(sock);
            WSACleanup();
            return;
        }

        let sa = SockAddrIn {
            sin_family: AF_INET as i16,
            sin_port: htons(port),
            sin_addr: addr,
            sin_zero: [0u8; 8],
        };

        let ret = connect(sock, &sa, core::mem::size_of::<SockAddrIn>() as i32);
        if ret == SOCKET_ERROR {
            let err = WSAGetLastError();
            if err != WSAEWOULDBLOCK {
                eprintln!("connect() failed: {}", err);
                closesocket(sock);
                WSACleanup();
                return;
            }
        }

        let mut write_fds = FdSet::new();
        write_fds.set(sock);
        let mut except_fds = FdSet::new();
        except_fds.set(sock);

        let tv = Timeval {
            tv_sec: timeout_ms / 1000,
            tv_usec: (timeout_ms % 1000) * 1000,
        };

        let sel = select(
            0, // ignored on Windows
            core::ptr::null_mut(),
            &mut write_fds,
            &mut except_fds,
            &tv,
        );

        if sel > 0 && write_fds.is_set(sock) && !except_fds.is_set(sock) {
            println!("{}:{} is OPEN", host, port);
        } else if sel == 0 {
            println!("{}:{} is CLOSED (timeout)", host, port);
        } else {
            println!("{}:{} is CLOSED", host, port);
        }

        closesocket(sock);
        WSACleanup();
    }
}
