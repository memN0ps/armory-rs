//! # AMSI and ETW Presence BOF
//!
//! Reports whether AMSI is loaded in the current process and whether selected
//! AMSI and ETW exports are present. It does not inspect code bytes or patch
//! either interface.
//!
//! ## MITRE ATT&CK
//! - T1518.001 - Security Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use core::ffi::c_void;
use rustbof::println;

unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}

fn wide_z(value: &str) -> alloc::vec::Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn export_present(module: *mut c_void, name: &[u8]) -> bool {
    !module.is_null() && !unsafe { GetProcAddress(module, name.as_ptr()) }.is_null()
}

#[rustbof::main]
fn main() {
    let amsi = unsafe { GetModuleHandleW(wide_z("amsi.dll").as_ptr()) };
    let ntdll = unsafe { GetModuleHandleW(wide_z("ntdll.dll").as_ptr()) };

    println!("AMSI and ETW presence in the current process");
    println!(
        "AMSI module loaded: {}",
        if amsi.is_null() { "no" } else { "yes" }
    );
    println!(
        "AmsiScanBuffer export: {}",
        if export_present(amsi, b"AmsiScanBuffer\0") {
            "present"
        } else {
            "absent"
        }
    );
    println!(
        "AmsiScanString export: {}",
        if export_present(amsi, b"AmsiScanString\0") {
            "present"
        } else {
            "absent"
        }
    );
    println!(
        "EtwEventWrite export: {}",
        if export_present(ntdll, b"EtwEventWrite\0") {
            "present"
        } else {
            "absent"
        }
    );
    println!(
        "EtwEventWriteFull export: {}",
        if export_present(ntdll, b"EtwEventWriteFull\0") {
            "present"
        } else {
            "absent"
        }
    );
    println!("No code bytes were read or changed.");
}
