//! # Power and Chassis State BOF
//!
//! Reports AC and battery state, then classifies the chassis using SMBIOS Type
//! 3 data with a battery-presence fallback.
//!
//! ## MITRE ATT&CK
//! - T1082 - System Information Discovery
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::vec;
use core::ffi::c_void;
use rustbof::{eprintln, println};

#[repr(C)]
struct SystemPowerStatus {
    ac_line_status: u8,
    battery_flag: u8,
    battery_life_percent: u8,
    system_status_flag: u8,
    battery_life_time: u32,
    battery_full_life_time: u32,
}

unsafe extern "system" {
    fn GetLastError() -> u32;
    fn GetSystemPowerStatus(status: *mut SystemPowerStatus) -> i32;
    fn GetSystemFirmwareTable(
        provider_signature: u32,
        table_id: u32,
        buffer: *mut c_void,
        buffer_size: u32,
    ) -> u32;
}

const RSMB: u32 = 0x52534D42;
const MAX_FIRMWARE_BYTES: u32 = 1024 * 1024;

fn chassis_label(chassis_type: u8) -> &'static str {
    match chassis_type & 0x7F {
        8 => "portable",
        9 => "laptop",
        10 => "notebook",
        11 => "handheld",
        14 => "subnotebook",
        30 => "tablet",
        31 => "convertible",
        32 => "detachable",
        3 | 4 | 5 | 6 | 7 | 13 | 15 | 16 | 24 | 35 => "desktop/workstation",
        17 | 18 | 19 | 20 | 23 | 28 | 29 | 33 => "server/enclosure",
        34 => "embedded",
        _ => "unknown",
    }
}

fn smbios_chassis() -> Result<Option<u8>, u32> {
    unsafe {
        let required = GetSystemFirmwareTable(RSMB, 0, core::ptr::null_mut(), 0);
        if !(8..=MAX_FIRMWARE_BYTES).contains(&required) {
            return Err(GetLastError());
        }
        let mut buffer = vec![0u8; required as usize];
        let written = GetSystemFirmwareTable(RSMB, 0, buffer.as_mut_ptr() as *mut c_void, required);
        if written < 8 || written > required {
            return Err(GetLastError());
        }
        buffer.truncate(written as usize);

        let table_length = u32::from_le_bytes(buffer[4..8].try_into().unwrap_or([0; 4])) as usize;
        if table_length > buffer.len() - 8 {
            return Err(13);
        }
        let table = &buffer[8..8 + table_length];
        let mut offset = 0usize;
        while offset + 4 <= table.len() {
            let structure_type = table[offset];
            let formatted_length = table[offset + 1] as usize;
            if formatted_length < 4 || offset + formatted_length > table.len() {
                return Err(13);
            }
            if structure_type == 3 && formatted_length > 5 {
                return Ok(Some(table[offset + 5]));
            }
            if structure_type == 127 {
                break;
            }

            let mut next = offset + formatted_length;
            while next + 1 < table.len() && (table[next] != 0 || table[next + 1] != 0) {
                next += 1;
            }
            if next + 1 >= table.len() {
                break;
            }
            offset = next + 2;
        }
        Ok(None)
    }
}

fn ac_label(value: u8) -> &'static str {
    match value {
        0 => "offline",
        1 => "online",
        _ => "unknown",
    }
}

#[rustbof::main]
fn main() {
    let mut status: SystemPowerStatus = unsafe { core::mem::zeroed() };
    if unsafe { GetSystemPowerStatus(&mut status) } == 0 {
        eprintln!("GetSystemPowerStatus failed: 0x{:X}", unsafe {
            GetLastError()
        });
    } else {
        let battery_present = status.battery_flag != 128 && status.battery_flag & 128 == 0;
        println!("Power and chassis state");
        println!("AC power: {}", ac_label(status.ac_line_status));
        println!(
            "Battery present: {}",
            if battery_present { "yes" } else { "no" }
        );
        if battery_present && status.battery_life_percent <= 100 {
            println!("Battery charge: {}%", status.battery_life_percent);
        }

        match smbios_chassis() {
            Ok(Some(chassis_type)) => println!(
                "Chassis: {} (SMBIOS type {})",
                chassis_label(chassis_type),
                chassis_type & 0x7F
            ),
            Ok(None) => println!(
                "Chassis: {} (battery fallback)",
                if battery_present {
                    "portable"
                } else {
                    "unknown"
                }
            ),
            Err(error) => eprintln!("SMBIOS query failed: 0x{:X}", error),
        }
    }
}
