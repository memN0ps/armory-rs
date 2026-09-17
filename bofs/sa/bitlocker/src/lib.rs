//! # BitLocker Status BOF
//!
//! Reads the local BitLocker volume snapshot exposed by the Microsoft Volume
//! Encryption WMI provider. It does not change encryption or key protectors.
//!
//! ## MITRE ATT&CK
//! - T1082 - System Information Discovery
//!
//! ## Arguments
//! None.

#![no_std]

mod wmi;

use rustbof::{eprintln, println};
use wmi::{Object, Session, Value, WmiError};

const NAMESPACE: &str = "root\\CIMV2\\Security\\MicrosoftVolumeEncryption";
const QUERY: &str = "SELECT DriveLetter,DeviceID,ProtectionStatus,ConversionStatus,EncryptionMethod,IsVolumeInitializedForProtection,VolumeType FROM Win32_EncryptableVolume";

fn text<'a>(value: &'a Value, fallback: &'a str) -> &'a str {
    match value {
        Value::Text(value) if !value.is_empty() => value,
        _ => fallback,
    }
}

fn number(value: &Value) -> Option<u32> {
    match value {
        Value::Unsigned(value) => u32::try_from(*value).ok(),
        Value::Signed(value) => u32::try_from(*value).ok(),
        _ => None,
    }
}

fn protection(value: Option<u32>) -> &'static str {
    match value {
        Some(0) => "off",
        Some(1) => "on",
        Some(2) => "unknown",
        _ => "not reported",
    }
}

fn conversion(value: Option<u32>) -> &'static str {
    match value {
        Some(0) => "fully decrypted",
        Some(1) => "fully encrypted",
        Some(2) => "encryption in progress",
        Some(3) => "decryption in progress",
        Some(4) => "encryption paused",
        Some(5) => "decryption paused",
        _ => "not reported",
    }
}

fn encryption(value: Option<u32>) -> &'static str {
    match value {
        Some(0) => "not encrypted",
        Some(1) => "AES 128 with diffuser",
        Some(2) => "AES 256 with diffuser",
        Some(3) => "AES 128",
        Some(4) => "AES 256",
        Some(5) => "hardware encryption",
        Some(6) => "XTS-AES 128",
        Some(7) => "XTS-AES 256",
        _ => "not reported",
    }
}

fn volume_type(value: Option<u32>) -> &'static str {
    match value {
        Some(0) => "operating system",
        Some(1) => "fixed data",
        Some(2) => "removable data",
        _ => "not reported",
    }
}

fn print_volume(object: &Object, index: u32) -> Result<(), WmiError> {
    let drive = object.get("DriveLetter")?;
    let device = object.get("DeviceID")?;
    let protection_state = object.get("ProtectionStatus")?;
    let conversion_state = object.get("ConversionStatus")?;
    let encryption_method = object.get("EncryptionMethod")?;
    let initialized = object.get("IsVolumeInitializedForProtection")?;
    let kind = object.get("VolumeType")?;

    println!("[{}] {}", index, text(&drive, "<no drive letter>"));
    println!("  device:      {}", text(&device, "<not reported>"));
    println!("  protection:  {}", protection(number(&protection_state)));
    println!("  conversion:  {}", conversion(number(&conversion_state)));
    println!("  encryption:  {}", encryption(number(&encryption_method)));
    println!("  volume type: {}", volume_type(number(&kind)));
    println!("  initialized: {}\n", match initialized {
        Value::Boolean(value) => {
            if value { "yes" } else { "no" }
        }
        _ => "not reported",
    });
    Ok(())
}

fn run() -> Result<u32, WmiError> {
    let session = Session::connect(NAMESPACE)?;
    let mut query = session.query(QUERY)?;
    let mut count = 0u32;
    while count < 32 {
        let Some(object) = query.next(5000)? else {
            break;
        };
        count += 1;
        print_volume(&object, count)?;
    }
    Ok(count)
}

#[rustbof::main]
fn main() {
    println!("BitLocker volume status\n");
    match run() {
        Ok(0) => println!("No encryptable volumes were returned."),
        Ok(count) => println!(
            "Volumes: {}{}",
            count,
            if count == 32 {
                " | row limit reached"
            } else {
                ""
            }
        ),
        Err(error) => eprintln!("{} failed: 0x{:08X}", error.stage, error.code as u32),
    }
}
