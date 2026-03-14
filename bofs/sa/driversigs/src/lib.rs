//! # Driver Signatures BOF
//!
//! Enumerates kernel-mode driver services and checks their binary paths
//! against known EDR/AV vendor signatures. Helps identify security
//! products on the target system.
//!
//! ## MITRE ATT&CK
//! - T1518.001 - Software Discovery: Security Software Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{string::String, vec};
use rustbof::{eprintln, println};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::*;

const VENDOR_SIGS: &[(&str, &str)] = &[
    ("carbon", "Carbon Black"),
    ("crowdstrike", "CrowdStrike"),
    ("cylance", "Cylance"),
    ("endgame", "Endgame"),
    ("fireeye", "FireEye/Trellix"),
    ("mandiant", "Mandiant"),
    ("mcafee", "McAfee"),
    ("sentinel", "SentinelOne"),
    ("symantec", "Symantec/Broadcom"),
    ("tanium", "Tanium"),
    ("palo", "Palo Alto"),
    ("cortex", "Cortex XDR"),
    ("sophos", "Sophos"),
    ("kaspersky", "Kaspersky"),
    ("eset", "ESET"),
    ("bitdefender", "Bitdefender"),
    ("malwarebytes", "Malwarebytes"),
    ("trend", "Trend Micro"),
    ("defender", "Windows Defender"),
    ("elastic", "Elastic"),
];

fn contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    for i in 0..=(h.len() - n.len()) {
        let mut found = true;
        for j in 0..n.len() {
            if h[i + j].to_ascii_lowercase() != n[j].to_ascii_lowercase() {
                found = false;
                break;
            }
        }
        if found {
            return true;
        }
    }
    false
}

fn check_vendor(name: &str) -> Option<&'static str> {
    for &(sig, vendor) in VENDOR_SIGS {
        if contains_ci(name, sig) {
            return Some(vendor);
        }
    }
    None
}

#[rustbof::main]
fn main() {
    unsafe {
        let sc_manager = OpenSCManagerA(
            core::ptr::null(),
            core::ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        );
        if sc_manager.is_null() {
            eprintln!("OpenSCManagerA failed: 0x{:X}", GetLastError());
            return;
        }

        let mut needed: u32 = 0;
        let mut returned: u32 = 0;
        let mut resume: u32 = 0;
        EnumServicesStatusExA(
            sc_manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            core::ptr::null_mut(),
            0,
            &mut needed,
            &mut returned,
            &mut resume,
            core::ptr::null(),
        );

        if needed == 0 {
            eprintln!("No driver services found or access denied.");
            CloseServiceHandle(sc_manager);
            return;
        }

        let mut buf = vec![0u8; needed as usize];
        resume = 0;
        if EnumServicesStatusExA(
            sc_manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            buf.as_mut_ptr(),
            needed,
            &mut needed,
            &mut returned,
            &mut resume,
            core::ptr::null(),
        ) == 0
        {
            eprintln!("EnumServicesStatusExA failed: 0x{:X}", GetLastError());
            CloseServiceHandle(sc_manager);
            return;
        }

        println!("{:<40} {:<10} {}", "Service Name", "State", "Vendor Match");
        println!("{:-<40} {:-<10} {:-<20}", "", "", "");

        let entries = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSA;
        let mut edr_count: u32 = 0;

        for i in 0..returned as usize {
            let entry = &*entries.add(i);
            let name = core::ffi::CStr::from_ptr(entry.lpServiceName as *const i8)
                .to_str()
                .unwrap_or("?");
            let display = core::ffi::CStr::from_ptr(entry.lpDisplayName as *const i8)
                .to_str()
                .unwrap_or("?");
            let state = match entry.ServiceStatusProcess.dwCurrentState {
                4 => "RUNNING",
                1 => "STOPPED",
                _ => "OTHER",
            };

            if let Some(vendor) = check_vendor(name).or_else(|| check_vendor(display)) {
                println!("{:<40} {:<10} [!] {}", name, state, vendor);
                edr_count += 1;
            }
        }

        if edr_count == 0 {
            println!("\nNo known EDR/AV driver signatures detected.");
        } else {
            println!("\n{} potential EDR/AV driver(s) detected.", edr_count);
        }

        println!("\nTotal driver services enumerated: {}", returned);
        CloseServiceHandle(sc_manager);
    }
}
