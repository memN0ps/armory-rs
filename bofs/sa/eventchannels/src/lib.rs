//! # Windows Event Channel Inventory BOF
//!
//! Enumerates local Windows Event Log channel names and configured enabled
//! state. An optional case-insensitive substring limits the output.
//!
//! ## MITRE ATT&CK
//! - T1518.001 - Security Software Discovery
//!
//! ## Arguments
//! - Optional `str`: Channel-name filter. Empty or absent lists all channels.

#![no_std]

use alloc::{string::String, vec};
use core::ffi::c_void;
use rustbof::{eprintln, println};

type EvtHandle = *mut c_void;

#[repr(C)]
struct EvtVariant {
    data: u64,
    count: u32,
    value_type: u32,
}

unsafe extern "system" {
    fn GetLastError() -> u32;
    fn EvtOpenChannelEnum(session: EvtHandle, flags: u32) -> EvtHandle;
    fn EvtNextChannelPath(
        channel_enum: EvtHandle,
        channel_path_size: u32,
        channel_path: *mut u16,
        channel_path_used: *mut u32,
    ) -> i32;
    fn EvtOpenChannelConfig(session: EvtHandle, channel_path: *const u16, flags: u32) -> EvtHandle;
    fn EvtGetChannelConfigProperty(
        channel_config: EvtHandle,
        property_id: u32,
        flags: u32,
        property_value_buffer_size: u32,
        property_value_buffer: *mut EvtVariant,
        property_value_buffer_used: *mut u32,
    ) -> i32;
    fn EvtClose(object: EvtHandle) -> i32;
}

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const EVT_CHANNEL_CONFIG_ENABLED: u32 = 0;
const MAX_CHANNELS_EXAMINED: u32 = 2048;
const MAX_CHANNELS_SHOWN: u32 = 128;
const MAX_CHANNEL_UNITS: u32 = 32768;

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
        if length == 0 {
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

fn optional_filter(args: *mut u8, len: usize) -> Result<String, ()> {
    if args.is_null() || len == 0 {
        return Ok(String::new());
    }
    let buffer = unsafe { core::slice::from_raw_parts(args, len) };
    let mut parser = PackedArgs::new(buffer).ok_or(())?;
    let filter = parser.read_string().ok_or(())?;
    if !parser.finished() || filter.len() > 256 {
        return Err(());
    }
    Ok(String::from(filter))
}

fn contains_case_insensitive(value: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn channel_enabled(path: &[u16]) -> Option<bool> {
    unsafe {
        let config = EvtOpenChannelConfig(core::ptr::null_mut(), path.as_ptr(), 0);
        if config.is_null() {
            return None;
        }
        let mut value: EvtVariant = core::mem::zeroed();
        let mut used = 0u32;
        let success = EvtGetChannelConfigProperty(
            config,
            EVT_CHANNEL_CONFIG_ENABLED,
            0,
            core::mem::size_of::<EvtVariant>() as u32,
            &mut value,
            &mut used,
        );
        EvtClose(config);
        if success == 0 || used > core::mem::size_of::<EvtVariant>() as u32 {
            None
        } else {
            Some(value.data != 0)
        }
    }
}

fn enumerate(filter: &str) -> Result<(u32, u32, bool), (&'static str, u32)> {
    unsafe {
        let handle = EvtOpenChannelEnum(core::ptr::null_mut(), 0);
        if handle.is_null() {
            return Err(("EvtOpenChannelEnum", GetLastError()));
        }

        let mut examined = 0u32;
        let mut shown = 0u32;
        let mut truncated = false;
        loop {
            if examined == MAX_CHANNELS_EXAMINED {
                truncated = true;
                break;
            }
            let mut required = 0u32;
            let first = EvtNextChannelPath(handle, 0, core::ptr::null_mut(), &mut required);
            if first == 0 {
                let status = GetLastError();
                if status == ERROR_NO_MORE_ITEMS {
                    break;
                }
                if status != ERROR_INSUFFICIENT_BUFFER
                    || required == 0
                    || required > MAX_CHANNEL_UNITS
                {
                    EvtClose(handle);
                    return Err(("EvtNextChannelPath(size)", status));
                }
            }

            let mut path = vec![0u16; required as usize];
            if EvtNextChannelPath(handle, required, path.as_mut_ptr(), &mut required) == 0 {
                let status = GetLastError();
                EvtClose(handle);
                return Err(("EvtNextChannelPath", status));
            }
            examined += 1;
            let length = path
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(path.len());
            let name = String::from_utf16_lossy(&path[..length]);
            if contains_case_insensitive(&name, filter) {
                if shown < MAX_CHANNELS_SHOWN {
                    let state = match channel_enabled(&path) {
                        Some(true) => "enabled",
                        Some(false) => "disabled",
                        None => "state unavailable",
                    };
                    println!("{:<9} {}", state, name);
                    shown += 1;
                } else {
                    truncated = true;
                }
            }
        }

        EvtClose(handle);
        Ok((examined, shown, truncated))
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    match optional_filter(args, len) {
        Err(()) => eprintln!("Usage: eventchannels [name_filter]"),
        Ok(filter) => {
            println!("Windows Event Log channel inventory");
            println!(
                "Filter: {}\n",
                if filter.is_empty() {
                    "<none>"
                } else {
                    filter.as_str()
                }
            );
            match enumerate(&filter) {
                Ok((examined, shown, truncated)) => println!(
                    "\nChannels examined: {} | shown: {}{}",
                    examined,
                    shown,
                    if truncated {
                        " | output limit reached"
                    } else {
                        ""
                    }
                ),
                Err((stage, status)) => eprintln!("{} failed: 0x{:X}", stage, status),
            }
        }
    }
}
