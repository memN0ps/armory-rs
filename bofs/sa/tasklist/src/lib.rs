//! # Task List BOF
//!
//! Enumerates running processes. Intended to use WMI Win32_Process for detailed
//! process information including command lines and owner. Falls back to a stub
//! pending COM IWbemLocator vtable FFI implementation.
//!
//! ## MITRE ATT&CK
//! - T1057 - Process Discovery
//!
//! ## Arguments
//! None.
//!
//! ## Status
//! Stub implementation. Full process enumeration via WMI Win32_Process requires
//! COM vtable FFI definitions for IWbemLocator and IWbemServices interfaces.

#![no_std]

use rustbof::println;

#[rustbof::main]
fn main() {
    println!("BOF loaded: tasklist");
    println!("Process enumeration via WMI Win32_Process - coming soon");
    println!();
    println!("  - WMI query: SELECT * FROM Win32_Process");
    println!("  - Display: PID, Name, PPID, CommandLine, Owner, SessionId");
    println!("  - Support remote host via WMI connection");
    println!("  - CSV-formatted output for easy parsing");
    println!();
    println!("Requires COM IWbemLocator vtable FFI (shared with wmi_query BOF).");
    println!("See wmi_query BOF for COM interface details.");
    println!();
    println!("Alternative: Use the existing 'listmods' BOF for module enumeration,");
    println!("or 'ProcessListHandles' BOF for handle enumeration.");
}
