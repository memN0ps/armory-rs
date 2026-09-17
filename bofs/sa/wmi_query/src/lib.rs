//! # WMI Query BOF
//!
//! Executes a bounded WQL query against a local or remote WMI namespace and
//! prints the returned non-system properties.
//!
//! ## MITRE ATT&CK
//! - T1047 - Windows Management Instrumentation
//!
//! ## Arguments
//! - `str`: Hostname, or an empty string for localhost.
//! - `str`: WMI namespace, for example `root\cimv2`.
//! - `str`: WQL query, for example `SELECT Caption FROM Win32_OperatingSystem`.

#![no_std]

mod wmi;

use alloc::{format, string::String};
use rustbof::{eprintln, print, println};
use wmi::{Session, Value, WmiError};

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

    fn string(&mut self) -> Option<&'a str> {
        let prefix_end = self.offset.checked_add(4)?;
        let length =
            u32::from_le_bytes(self.buffer.get(self.offset..prefix_end)?.try_into().ok()?) as usize;
        if length == 0 {
            return None;
        }
        let end = prefix_end.checked_add(length)?;
        let bytes = self.buffer.get(prefix_end..end)?;
        if bytes.last().copied() != Some(0) || bytes[..length - 1].contains(&0) {
            return None;
        }
        self.offset = end;
        core::str::from_utf8(&bytes[..length - 1]).ok()
    }

    fn finished(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

fn print_value(value: &Value) {
    match value {
        Value::Empty => println!("<null>"),
        Value::Text(value) => println!("{}", value),
        Value::Signed(value) => println!("{}", value),
        Value::Unsigned(value) => println!("{}", value),
        Value::Boolean(value) => println!("{}", if *value { "true" } else { "false" }),
        Value::Unsupported(kind) => println!("<variant type {}>", kind),
    }
}

fn print_error(error: WmiError) {
    eprintln!("{} failed: 0x{:08X}", error.stage, error.code as u32);
}

fn run(hostname: &str, namespace: &str, query_text: &str) -> Result<(), WmiError> {
    let target_namespace = if hostname.is_empty() {
        String::from(namespace)
    } else {
        format!(
            "\\\\{}\\{}",
            hostname,
            namespace.trim_start_matches(['\\', '/'])
        )
    };

    let session = Session::connect(&target_namespace)?;
    let mut query = session.query(query_text)?;
    let mut rows = 0u32;

    while rows < 64 {
        let Some(object) = query.next(5000)? else {
            break;
        };
        rows += 1;
        println!("[{}]", rows);
        let mut shown = 0u32;
        object.enumerate(|name, value| {
            if shown < 16 {
                print!("  {}: ", name);
                print_value(value);
                shown += 1;
            }
        })?;
        if shown == 16 {
            println!("  <property output limit reached>");
        }
        println!();
    }

    println!(
        "Rows: {}{}",
        rows,
        if rows == 64 {
            " | row limit reached"
        } else {
            ""
        }
    );
    Ok(())
}

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let parsed = if args.is_null() || len == 0 {
        None
    } else {
        // SAFETY: The BOF ABI supplies a readable `len`-byte argument buffer
        // for this call. PackedArgs validates every field before using it.
        let buffer = unsafe { core::slice::from_raw_parts(args, len) };
        PackedArgs::new(buffer).and_then(|mut parser| {
            let hostname = parser.string()?;
            let namespace = parser.string()?;
            let query = parser.string()?;
            parser.finished().then_some((hostname, namespace, query))
        })
    };

    match parsed {
        Some((hostname, namespace, query))
            if hostname.len() <= 256
                && !namespace.is_empty()
                && namespace.len() <= 512
                && !query.is_empty()
                && query.len() <= 8192 =>
        {
            println!(
                "WMI query: {} | {}\n",
                if hostname.is_empty() {
                    "localhost"
                } else {
                    hostname
                },
                namespace
            );
            if let Err(error) = run(hostname, namespace, query) {
                print_error(error);
            }
        }
        _ => {
            eprintln!("Usage: wmi_query <hostname-or-empty> <namespace> <WQL query>");
        }
    }
}
