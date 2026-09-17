//! # Remote Workstation Information BOF
//!
//! Queries a named Windows host through NetWkstaGetInfo and reports its
//! workstation version, platform, computer name, workgroup, and LAN root.
//!
//! ## MITRE ATT&CK
//! - T1018 - Remote System Discovery
//!
//! ## Arguments
//! - `str`: Remote hostname or UNC server name.

#![no_std]

use alloc::{string::String, vec::Vec};
use core::ffi::c_void;
use rustbof::{eprintln, println};

#[repr(C)]
struct WorkstationInfo101 {
    platform_id: u32,
    computer_name: *mut u16,
    language_group: *mut u16,
    version_major: u32,
    version_minor: u32,
    lan_root: *mut u16,
}

unsafe extern "system" {
    fn NetWkstaGetInfo(server: *const u16, level: u32, buffer: *mut *mut u8) -> u32;
    fn NetApiBufferFree(buffer: *mut c_void) -> u32;
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
        if declared != buffer.len() - 4 {
            return None;
        }
        Some(Self { buffer, offset: 4 })
    }

    fn read_string(&mut self) -> Option<&'a str> {
        let length_end = self.offset.checked_add(4)?;
        let length =
            u32::from_le_bytes(self.buffer.get(self.offset..length_end)?.try_into().ok()?) as usize;
        self.offset = length_end;
        if length <= 1 || length > 512 {
            return None;
        }
        let value_end = self.offset.checked_add(length)?;
        let value = self.buffer.get(self.offset..value_end)?;
        self.offset = value_end;
        if value.last().copied() != Some(0) || value[..length - 1].contains(&0) {
            return None;
        }
        core::str::from_utf8(&value[..length - 1]).ok()
    }

    fn finished(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

fn wide_z(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn wide_pointer(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::from("<not available>");
    }
    unsafe {
        let mut length = 0usize;
        while length < 32768 && *pointer.add(length) != 0 {
            length += 1;
        }
        if length == 32768 {
            String::from("<value exceeds limit>")
        } else {
            String::from_utf16_lossy(core::slice::from_raw_parts(pointer, length))
        }
    }
}

fn query(hostname: &str) -> Result<(), u32> {
    let server = wide_z(hostname);
    let mut buffer = core::ptr::null_mut();
    let status = unsafe { NetWkstaGetInfo(server.as_ptr(), 101, &mut buffer) };
    if status != 0 || buffer.is_null() {
        return Err(status);
    }

    unsafe {
        let info = &*(buffer as *const WorkstationInfo101);
        println!("Computer: {}", wide_pointer(info.computer_name));
        println!("Workgroup/domain: {}", wide_pointer(info.language_group));
        println!("Version: {}.{}", info.version_major, info.version_minor);
        println!("Platform ID: {}", info.platform_id);
        println!("LAN root: {}", wide_pointer(info.lan_root));
        NetApiBufferFree(buffer as *mut c_void);
    }
    Ok(())
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let hostname = if args.is_null() || len == 0 {
        None
    } else {
        let bytes = unsafe { core::slice::from_raw_parts(args, len) };
        PackedArgs::new(bytes).and_then(|mut parser| {
            let value = parser.read_string()?;
            parser.finished().then_some(value)
        })
    };

    match hostname {
        None => eprintln!("Usage: smbinfo <hostname>"),
        Some(hostname) => {
            println!("Remote workstation information: {}", hostname);
            if let Err(status) = query(hostname) {
                eprintln!("NetWkstaGetInfo failed: 0x{:X}", status);
            }
        }
    }
}
