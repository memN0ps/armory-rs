//! # Recent Windows Logon Events BOF
//!
//! Reads a bounded newest-first set of Security events 4624, 4625, and 4672
//! through Windows Event Log. Security-log access normally requires elevation.
//!
//! ## MITRE ATT&CK
//! - T1033 - System Owner/User Discovery
//! - T1087.001 - Account Discovery: Local Account
//!
//! ## Arguments
//! Optional packed int: maximum events from 1 through 256. Default is 64.

#![no_std]

use alloc::{string::String, vec};
use core::ffi::c_void;
use rustbof::{eprintln, println};

type EvtHandle = *mut c_void;

unsafe extern "system" {
    fn GetLastError() -> u32;
    fn EvtQuery(session: EvtHandle, path: *const u16, query: *const u16, flags: u32) -> EvtHandle;
    fn EvtNext(
        result: EvtHandle,
        event_count: u32,
        events: *mut EvtHandle,
        timeout: u32,
        flags: u32,
        returned: *mut u32,
    ) -> i32;
    fn EvtRender(
        context: EvtHandle,
        fragment: EvtHandle,
        flags: u32,
        buffer_size: u32,
        buffer: *mut c_void,
        buffer_used: *mut u32,
        property_count: *mut u32,
    ) -> i32;
    fn EvtClose(object: EvtHandle) -> i32;
}

const EVT_QUERY_CHANNEL_PATH: u32 = 1;
const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
const EVT_RENDER_EVENT_XML: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const MAX_XML_BYTES: u32 = 64 * 1024;

fn wide(value: &str) -> alloc::vec::Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn limit(args: *mut u8, len: usize) -> Option<u32> {
    if args.is_null() || len == 0 {
        return Some(64);
    }
    let buffer = unsafe { core::slice::from_raw_parts(args, len) };
    if buffer.len() != 8 || u32::from_le_bytes(buffer[..4].try_into().ok()?) != 4 {
        return None;
    }
    let value = i32::from_le_bytes(buffer[4..8].try_into().ok()?);
    (1..=256).contains(&value).then_some(value as u32)
}

fn between<'a>(value: &'a str, first: &str, second: &str) -> Option<&'a str> {
    let start = value.find(first)?.checked_add(first.len())?;
    let end = value[start..].find(second)?.checked_add(start)?;
    Some(&value[start..end])
}

fn event_id(xml: &str) -> &str {
    between(xml, "<EventID", "</EventID>")
        .and_then(|value| value.rsplit_once('>').map(|(_, id)| id))
        .unwrap_or("unknown")
}

fn data<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let mut marker = String::from("<Data Name='");
    marker.push_str(name);
    marker.push_str("'>");
    if let Some(value) = between(xml, &marker, "</Data>") {
        return Some(value);
    }
    marker.clear();
    marker.push_str("<Data Name=\"");
    marker.push_str(name);
    marker.push_str("\">");
    between(xml, &marker, "</Data>")
}

fn render(event: EvtHandle) -> Result<String, u32> {
    unsafe {
        let mut needed = 0u32;
        let mut count = 0u32;
        if EvtRender(
            core::ptr::null_mut(),
            event,
            EVT_RENDER_EVENT_XML,
            0,
            core::ptr::null_mut(),
            &mut needed,
            &mut count,
        ) != 0
        {
            return Err(13);
        }
        let status = GetLastError();
        if status != ERROR_INSUFFICIENT_BUFFER || !(2..=MAX_XML_BYTES).contains(&needed) {
            return Err(status);
        }
        let mut buffer = vec![0u8; needed as usize];
        if EvtRender(
            core::ptr::null_mut(),
            event,
            EVT_RENDER_EVENT_XML,
            needed,
            buffer.as_mut_ptr() as *mut c_void,
            &mut needed,
            &mut count,
        ) == 0
        {
            return Err(GetLastError());
        }
        let units = core::slice::from_raw_parts(buffer.as_ptr() as *const u16, needed as usize / 2);
        let length = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        Ok(String::from_utf16_lossy(&units[..length]))
    }
}

fn enumerate(maximum: u32) -> Result<(u32, u32, u32), (&'static str, u32)> {
    let path = wide("Security");
    let xpath = wide("*[System[(EventID=4624 or EventID=4625 or EventID=4672)]]");
    unsafe {
        let query = EvtQuery(
            core::ptr::null_mut(),
            path.as_ptr(),
            xpath.as_ptr(),
            EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION,
        );
        if query.is_null() {
            return Err(("EvtQuery(Security)", GetLastError()));
        }
        let mut examined = 0u32;
        let mut shown = 0u32;
        let mut skipped = 0u32;
        while examined < maximum {
            let mut event = core::ptr::null_mut();
            let mut returned = 0u32;
            if EvtNext(query, 1, &mut event, 0, 0, &mut returned) == 0 {
                let status = GetLastError();
                if status == ERROR_NO_MORE_ITEMS {
                    break;
                }
                EvtClose(query);
                return Err(("EvtNext", status));
            }
            examined += 1;
            match render(event) {
                Ok(xml) => {
                    let user = data(&xml, "TargetUserName").unwrap_or("-");
                    let domain = data(&xml, "TargetDomainName").unwrap_or("-");
                    let workstation = data(&xml, "WorkstationName").unwrap_or("-");
                    let address = data(&xml, "IpAddress").unwrap_or("-");
                    let logon_type = data(&xml, "LogonType").unwrap_or("-");
                    println!(
                        "event={} | account={}\\{} | type={} | workstation={} | address={}",
                        event_id(&xml),
                        domain,
                        user,
                        logon_type,
                        workstation,
                        address
                    );
                    shown += 1;
                }
                Err(_) => skipped += 1,
            }
            EvtClose(event);
        }
        EvtClose(query);
        Ok((examined, shown, skipped))
    }
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    match limit(args, len) {
        None => eprintln!("Usage: wevtlogons [max_events 1-256]"),
        Some(maximum) => {
            println!("Recent Windows Security logon events | limit={}\n", maximum);
            match enumerate(maximum) {
                Ok((examined, shown, skipped)) => println!(
                    "\nEvents examined: {} | shown: {} | render skips: {}",
                    examined, shown, skipped
                ),
                Err((stage, status)) => eprintln!("{} failed: 0x{:X}", stage, status),
            }
        }
    }
}
