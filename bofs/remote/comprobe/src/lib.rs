//! # COM Activation Probe BOF
//!
//! Tests whether one exact CLSID can be activated with an optional interface
//! identifier and an explicit activation context. The object is immediately
//! released. COM activation can load a DLL or start a local COM server.
//!
//! ## MITRE ATT&CK
//! - T1218 - System Binary Proxy Execution
//!
//! ## Arguments
//! Three packed strings: CLSID, IID or empty for IUnknown, and inproc, local,
//! or both.

#![no_std]

use core::ffi::c_void;
use rustbof::{eprintln, println};

type HResult = i32;

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, concurrency: u32) -> HResult;
    fn CoCreateInstance(
        class_id: *const Guid,
        outer: *mut c_void,
        context: u32,
        interface_id: *const Guid,
        object: *mut *mut c_void,
    ) -> HResult;
    fn CoUninitialize();
}

const S_OK: HResult = 0;
const S_FALSE: HResult = 1;
const RPC_E_CHANGED_MODE: HResult = 0x80010106u32 as i32;
const COINIT_MULTITHREADED: u32 = 0;
const CLSCTX_INPROC_SERVER: u32 = 1;
const CLSCTX_LOCAL_SERVER: u32 = 4;
const IID_IUNKNOWN: Guid = Guid {
    data1: 0,
    data2: 0,
    data3: 0,
    data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
};

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

    fn string(&mut self, maximum: usize, empty: bool) -> Option<&'a str> {
        let header = self.offset.checked_add(4)?;
        let size =
            u32::from_le_bytes(self.buffer.get(self.offset..header)?.try_into().ok()?) as usize;
        self.offset = header;
        if size == 0 || size > maximum + 1 {
            return None;
        }
        let end = self.offset.checked_add(size)?;
        let bytes = self.buffer.get(self.offset..end)?;
        self.offset = end;
        if bytes.last().copied() != Some(0) || bytes[..size - 1].contains(&0) {
            return None;
        }
        let value = core::str::from_utf8(&bytes[..size - 1]).ok()?;
        (empty || !value.is_empty()).then_some(value)
    }

    fn done(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

unsafe fn release(object: *mut c_void) {
    if !object.is_null() {
        type Release = unsafe extern "system" fn(*mut c_void) -> u32;
        let table = unsafe { *(object as *mut *mut *mut c_void) };
        let function: Release = unsafe { core::mem::transmute(*table.add(2)) };
        unsafe { function(object) };
    }
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn parse_guid(value: &str) -> Option<Guid> {
    let value = value.strip_prefix('{').unwrap_or(value);
    let value = value.strip_suffix('}').unwrap_or(value);
    if value.len() != 36 {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return None;
    }
    let mut raw = [0u8; 16];
    let mut output = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'-' {
            index += 1;
            continue;
        }
        if output >= raw.len() || index + 1 >= bytes.len() {
            return None;
        }
        raw[output] = (hex(bytes[index])? << 4) | hex(bytes[index + 1])?;
        output += 1;
        index += 2;
    }
    (output == 16).then_some(Guid {
        data1: u32::from_be_bytes(raw[0..4].try_into().ok()?),
        data2: u16::from_be_bytes(raw[4..6].try_into().ok()?),
        data3: u16::from_be_bytes(raw[6..8].try_into().ok()?),
        data4: raw[8..16].try_into().ok()?,
    })
}

fn activate(class_id: &Guid, interface_id: &Guid, context: u32) -> HResult {
    let mut object = core::ptr::null_mut();
    let status = unsafe {
        CoCreateInstance(
            class_id,
            core::ptr::null_mut(),
            context,
            interface_id,
            &mut object,
        )
    };
    if status >= 0 && !object.is_null() {
        unsafe { release(object) };
    }
    status
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let parsed = if args.is_null() || len == 0 {
        None
    } else {
        let buffer = unsafe { core::slice::from_raw_parts(args, len) };
        PackedArgs::new(buffer).and_then(|mut parser| {
            let class = parser.string(40, false)?;
            let interface = parser.string(40, true)?;
            let context = parser.string(8, false)?;
            parser.done().then_some((class, interface, context))
        })
    };

    match parsed {
        None => eprintln!("Usage: comprobe <clsid> <iid_or_empty> <inproc|local|both>"),
        Some((class, interface, context)) => match (
            parse_guid(class),
            if interface.is_empty() {
                Some(IID_IUNKNOWN)
            } else {
                parse_guid(interface)
            },
        ) {
            (Some(class_id), Some(interface_id))
                if context.eq_ignore_ascii_case("inproc")
                    || context.eq_ignore_ascii_case("local")
                    || context.eq_ignore_ascii_case("both") =>
            {
                let initialized =
                    unsafe { CoInitializeEx(core::ptr::null_mut(), COINIT_MULTITHREADED) };
                let uninitialize = initialized == S_OK || initialized == S_FALSE;
                if initialized < 0 && initialized != RPC_E_CHANGED_MODE {
                    eprintln!("CoInitializeEx failed: 0x{:08X}", initialized as u32);
                } else {
                    println!(
                        "COM activation probe | CLSID={} | IID={}",
                        class,
                        if interface.is_empty() {
                            "IUnknown"
                        } else {
                            interface
                        }
                    );
                    if context.eq_ignore_ascii_case("inproc")
                        || context.eq_ignore_ascii_case("both")
                    {
                        let status = activate(&class_id, &interface_id, CLSCTX_INPROC_SERVER);
                        println!(
                            "in-process: {} (0x{:08X})",
                            if status >= 0 { "success" } else { "failed" },
                            status as u32
                        );
                    }
                    if context.eq_ignore_ascii_case("local") || context.eq_ignore_ascii_case("both")
                    {
                        let status = activate(&class_id, &interface_id, CLSCTX_LOCAL_SERVER);
                        println!(
                            "local-server: {} (0x{:08X})",
                            if status >= 0 { "success" } else { "failed" },
                            status as u32
                        );
                    }
                    if uninitialize {
                        unsafe { CoUninitialize() };
                    }
                }
            }
            _ => eprintln!("Usage: comprobe <clsid> <iid_or_empty> <inproc|local|both>"),
        },
    }
}
